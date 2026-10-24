# VaultSync Threat Model

This document identifies security boundaries, adversaries, potential threats, defensive mitigations, and residual risks for the VaultSync ecosystem.

---

## 1. Trust Boundaries and System Assets

### High-Value Assets
1. **Master Password**: Client-only secret known solely to the human user.
2. **Vault Encryption Key (VEK)**: 256-bit symmetric key that decrypts vault records.
3. **Plaintext Vault Entries**: Passwords, usernames, TOTP secrets, notes, and URLs.
4. **Session Tokens / API Credentials**: Ephemeral tokens authorizing sync API interactions.

### Trust Zones
- **Zone 0: Client Secure Memory**: Ephemeral RAM on Fedora desktop and Android where plaintext secrets reside during unlocked state.
- **Zone 1: Client Persistent Storage**: Local encrypted SQLite/Room storage on client devices.
- **Zone 2: Transport Layer**: Private VPN mesh (WireGuard / Tailscale) encapsulated over IP.
- **Zone 3: Server Boundary**: Backend hosting database and synchronization daemon.

---

## 2. Threat Analysis and Mitigations

### 2.1 Stolen Server Database
- **Threat**: An attacker compromises the Linux host running the VaultSync backend, obtaining a full SQL database dump.
- **Mitigation**:
  - The server stores **zero plaintext vault data**.
  - Vault records are stored as AEAD ciphertext blobs encrypted with the client's VEK.
  - The VEK is stored wrapped (encrypted) with a KEK derived via Argon2id from the user's master password on the client.
  - Server authentication uses an independent **Account Password** ($P_{\text{account}}$) verified against a server-side Argon2id hash (`account_password_hash`).
  - **Zero Master Password Verifiers in Auth Tables**: The server authentication tables contain zero hashes or verifiers derived from $P_{\text{vault}}$. An attacker testing candidate master passwords against `account_password_hash` receives zero verification signals.
  - Even if an attacker recovers $P_{\text{account}}$, they cannot unwrap the vault key or decrypt vault records.
- **Limitations & Offline Attack Reality**:
  - The attacker can observe sync metadata: number of records, ciphertext sizes, record UUIDs, revision numbers, and sync timestamps.
  - **Offline Attack Oracle on Wrapped Vault Key**: The stolen database contains `kdf_salt` and `wrapped_vault_key`. Because `wrapped_vault_key` uses AES-256-GCM, its 16-byte authentication tag acts as an inherent offline verification oracle. An attacker can iterate candidate master passwords offline through Argon2id and test `unwrap_vault_key()`. Protection against this dictionary attack relies strictly on the memory-hard work factor of Argon2id ($64\text{ MiB}, t=3, p=4$) and master password passphrase entropy, NOT on the absence of a verification oracle.

### 2.2 Network Interception
- **Threat**: Man-in-the-middle (MitM) adversary intercepts network traffic between Android phone and Fedora desktop.
- **Mitigation**:
  - Network transport is encapsulated within private WireGuard / Tailscale overlay network with mutual public-key cryptographic authentication.
  - All HTTP sync traffic uses HTTPS / TLS over the VPN tunnel, providing double-layer encryption in transit.
  - Payloads are end-to-end encrypted before transmission; even if TLS and VPN were both broken, payloads remain unreadable.
- **Limitations**: Traffic analysis can determine request frequencies and payload sizes.

### 2.3 Weak Master Passwords and Offline Guessing
- **Threat**: An attacker with a captured database dump attempts dictionary attacks against wrapped VEKs.
- **Mitigation**:
  - Key derivation uses **Argon2id** with memory-hard parameters conforming to RFC 9106 (e.g., minimum 64 MiB memory, $\ge 3$ iterations, 4 parallel lanes).
  - Client enforces strong master password entropy checks upon creation.
- **Limitations**: A severely weak master password (e.g. "password123") remains susceptible to high-budget offline dictionary attacks if the ciphertext is acquired.

### 2.4 Unauthorized API Access
- **Threat**: An unauthorized party attempts to query the sync API to pull or push vault records.
- **Mitigation**:
  - API endpoints require authenticated bearer tokens or HMAC-signed session credentials.
  - Multi-tenant isolation: database queries strictly filter by authenticated user ID; accessing another user's record ID returns 404/403.
  - Service binds to `127.0.0.1` or the private VPN IP interface, not the public internet (`0.0.0.0`).
- **Limitations**: If a client device session token is compromised, an attacker can access encrypted blobs (though cannot decrypt them without the master password).

### 2.5 Lost or Stolen Devices
- **Threat**: The Android phone or Fedora laptop is stolen while unlocked or locked.
- **Mitigation**:
  - **Android**: VEK is wrapped in memory or protected via Android Keystore hardware-backed keys, unlocked only via BiometricPrompt or master password. Auto-locks upon backgrounding.
  - **Fedora**: Configurable auto-lock timer, memory wiping on lock, secure local storage encrypted at rest.
  - **Remote Revocation**: The server allows revoking active device sessions, blocking future sync operations.
- **Limitations**: If a device is seized in an actively unlocked state with live memory access (cold-boot or forensic memory dump), keys in volatile RAM may be extracted.

### 2.6 Malicious or Compromised Clients
- **Threat**: A compromised client uploads corrupted data, malicious blobs, or oversized payloads to exhaust server disk space.
- **Mitigation**:
  - Strict Pydantic payload validation limits blob sizes and schema compliance (maximum 2 MiB per record).
  - Rate limiting per session and per IP.
  - Atomic optimistic concurrency and mandatory expected revision on deletion prevent stale or concurrent overwrites.
- **Limitations**:
  - VaultSync implements a **latest-state synchronization model**, NOT an immutable audit ledger or point-in-time recovery system. Intermediate record revisions are overwritten by subsequent updates; the database does not maintain historical versions or durable rollback history.
  - A compromised client possessing the vault master password has legitimate cryptographic access to write valid ciphertext to the vault or tombstone records.

### 2.7 Concurrent Updates, Replays, and Rollback Boundaries
- **Threat**: Two devices modify the same record offline, or an attacker attempts to replay older synchronization requests.
- **Mitigation**:
  - Monotonic account-level sync cursors and atomic per-record revision increments.
  - Atomic database-level conditional writes (`WHERE revision = expected_revision AND is_deleted = false`) reject stale updates with `409 Conflict`.
  - Mandatory `expected_revision` parameter on `DELETE` ensures deletions cannot destroy newer revisions.
  - Durable tombstones ensure deleted records propagate consistently to offline clients during incremental catch-up sync.
- **Limitations & Cryptographic Boundaries**:
  - Record-level Authenticated Additional Data (AAD) binds ciphertext strictly to its `record_id`, preventing cross-record relocation. However, **AAD alone does not prevent an untrusted server from replaying an earlier valid ciphertext for that same record ID**; freshness verification depends on client-side revision checks.
  - True concurrent edits to the same item require user resolution rather than automatic field-level merging, as the server cannot inspect fields within the opaque ciphertext.

### 2.8 Corrupted Ciphertext and Invalid Input
- **Threat**: Bit rot, storage faults, or tampering produces altered ciphertext.
- **Mitigation**:
  - Authenticated encryption (AEAD: AES-256-GCM / XChaCha20-Poly1305) cryptographically detects any single-bit modification of ciphertext or associated authenticated data (AAD).
  - Clients fail immediately with a cryptographic error; never parse or trust unauthenticated payloads.
- **Limitations**: Corrupted records cannot be decrypted and require restoration from backup.

### 2.9 Backup Theft and Recovery Failures
- **Threat**: An offline backup archive is stolen from external storage, or database records cannot be restored due to loss of key material.
- **Current Architecture & Mitigation**:
  - The server database backup is a raw snapshot of `vaultsync.db`. Because the database contains only AES-256-GCM ciphertexts and wrapped keys, raw backup snapshots contain zero plaintext vault data.
  - *Planned Feature*: Dedicated encrypted client JSON export protected under an independent export key. *(Not implemented in current release)*.
- **Recovery Reality & Limitations**:
  - VaultSync contains **no recovery-key or recovery-phrase mechanism**.
  - Administrative server scripts (`admin_reset`) can reset account credentials, but **cannot decrypt or recover vault records**.
  - Loss of the Vault Master Password results in **permanent, mathematically irreversible data loss by design**. Users must manually safeguard their master password offline.

### 2.10 Accidental Exposure Through Logs, Crash Reports, Git, or Config
- **Threat**: Secrets, passwords, or keys leak into logs, commit history, or error traces.
- **Mitigation**:
  - Strict `.gitignore` rules blocking `.env`, `*.db`, `*.key`, and secret artifacts.
  - Structured logging filters that forbid dumping request bodies or decrypted contents.
  - Sanitized exception handlers that return generic error messages to clients while logging safe tracebacks.
  - Synthetic dummy credentials only in automated test suites and documentation.

---

## 3. Phase 3 Backend and Session Security Controls

### 3.1 Token Verifiers Instead of Plaintext Tokens
- **Threat**: Attacker acquires a server database dump containing active session records.
- **Mitigation**: The `sessions` table persists only `token_hash = SHA-256(session_token)`. The raw bearer token is never written to disk, preventing session hijacking from static database dumps.

### 3.2 Cross-Account Record Isolation
- **Threat**: User B guesses or acquires a record UUID belonging to User A and attempts to read or mutate it.
- **Mitigation**: Every record query strictly checks `account_id == current_user.id`. Access attempts to unowned records return generic `404 Not Found`, denying unauthorized access while concealing record existence.

### 3.3 Optimistic Concurrency and Conflict Avoidance
- **Threat**: Stale client modifies a record, overwriting newer changes made by another device.
- **Mitigation**: `PUT /api/v1/records/{record_id}` requires `expected_revision`. Stale updates return `409 Conflict`, requiring the client to fetch the current revision and fork or resolve.

### 3.4 Rate Limiting on Authentication Endpoints
- **Threat**: Automated brute-force credential guessing against `/api/v1/auth/login`.
- **Mitigation**: Sliding-window rate limiter tracks failed attempts per IP and username, triggering `429 Too Many Requests` when thresholds are exceeded.

---

## 4. Phase 3.1 Security Review Findings

### 4.1 Stolen Database Enables Offline Master Password Guessing
- **Vulnerability**: In a single-password derivation scheme where `auth_secret = HKDF(Argon2id(P, salt), "auth")` and `auth_hash = Argon2id(auth_secret)` are stored on the server:
  An attacker with a stolen database dump has `salt` and `auth_hash`. The attacker can test candidate passwords $P'$ by evaluating the derivation forward and checking `verify_auth_secret(auth_hash, auth_secret')`.
  Even though HKDF is one-way, `auth_hash` serves as an offline verification oracle!
  Once cracked, the attacker immediately computes $\text{KEK} = \text{HKDF}(M, \text{"kek"})$ and unwraps the vault encryption key, compromising all records.
- **Two-Credential Architecture (Implemented in Phase 3.2)**:
  - Separate Account Password ($P_{\text{account}}$) from Vault Master Password ($P_{\text{vault}}$).
  - The server only validates $P_{\text{account}}$ via `account_password_hash`. The server authentication system contains zero master password verifiers.
  - An account password breach reveals zero information about $P_{\text{vault}}$.
  - *Note on Threat Boundaries*: A stolen database dump still contains `wrapped_vault_key`, whose AES-256-GCM authentication tag serves as an offline oracle for $P_{\text{vault}}$ guesses. The two-credential architecture protects against server-side authentication stuffing and server operator compromise, while offline dictionary attack defense on the wrapped key relies strictly on Argon2id work factor ($64\text{ MiB}, t=3, p=4$) and master passphrase entropy.
- **PAKE Alternative**: OPAQUE (RFC 9807) was evaluated; while theoretically preventing offline attacks for single passwords, the current absence of mature, audited cross-language libraries in Python and Kotlin makes it inappropriate for this phase.

### 4.2 Multi-Worker and Multi-IP Abuse Limits
- **Vulnerability**: Pure in-memory rate limiting without process sharing allows rotating IPs to bypass single-user limits, and multiple Uvicorn workers to dilute enforcement.
- **Mitigation**: Dual-axis rate limiting (IP and username tracked separately). For production deployment, a database-backed rate limit table (`auth_rate_limits`) or shared persistent cache provides cluster-wide abuse prevention.

---

## 5. Phase 5 Comprehensive Security Audit & Remediation

### 5.1 Login Timing Oracle & Username Enumeration Mitigation
- **Weakness**: When `/api/v1/auth/login` received a non-existent username, it aborted immediately in $<1\text{ ms}$, whereas valid accounts ran server-side Argon2id taking $\approx 50\text{--}100\text{ ms}$. This latency difference enabled remote adversaries to enumerate registered usernames.
- **Remediation**: The authentication service maintains a pre-computed valid Argon2id hash (`DUMMY_PASSWORD_HASH`). When an account lookup yields no active user, the server executes `verify_password(DUMMY_PASSWORD_HASH, req.account_password)`, equalizing verification latency and eliminating the timing oracle.

### 5.2 Public Salt Retrieval & Password Change Abuse Controls
- **Weakness**: `/api/v1/auth/salt` was unauthenticated and completely un-rate-limited, enabling dictionary scanners to probe account existence. Furthermore, `PUT /api/v1/auth/password` lacked attempt tracking on current password verification.
- **Remediation**: Both endpoints now enforce dual-axis rate limiting (tracking IP and user identifiers). Failed lookups on `/salt` record abuse events and trigger `429 Too Many Requests` after threshold violations.

### 5.3 Username Normalization in Rate Limit Keys
- **Weakness**: Rate limiting tracked raw username strings, allowing attackers to bypass attempt counters by alternating case (`alice` vs `Alice` vs `ALICE`) or adding leading/trailing whitespace.
- **Remediation**: All authentication and salt rate limit keys normalize usernames via `username.strip().lower()`.

### 5.4 Unbounded Request Body Size / Memory Exhaustion (DoS)
- **Weakness**: While `settings.max_payload_size_bytes` (2 MiB) was configured, it was never enforced by server middleware. Large payloads could consume server buffers and trigger memory exhaustion.
- **Remediation**: Added `PayloadSizeLimitMiddleware` rejecting requests exceeding 2 MiB with `HTTP 413 Payload Too Large`.

### 5.5 Defense-in-Depth HTTP Security Headers
- **Weakness**: Responses lacked modern browser isolation headers (Content Security Policy, Cross-Origin Opener Policy, Cross-Origin Resource Policy).
- **Remediation**: Enhanced `SecurityHeadersMiddleware` to inject:
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store, max-age=0`

### 5.6 Client Memory Wiping & Key Buffer Zeroization
- **Weakness**: `clear_key_material(key)` checked for `key._raw`, but `VaultKey` in `vaultsync_server.crypto.vault_keys` stores key material in `key._key`. Consequently, locking the vault failed to zeroize the underlying mutable `bytearray`.
- **Remediation**: `clear_key_material` now invokes `key.clear()` and explicitly overwrites `key._key` with zeros, clearing the buffer.

### 5.7 Credential Exposure in Representations & Logging
- **Weakness**: `VaultItem` defaulted to standard Pydantic `repr`, printing plaintext passwords and confidential notes in string representations, debug logs, and unhandled exception traces.
- **Remediation**: Added `repr=False` to `password` and `notes` fields in `VaultItem`. Plaintext secrets remain accessible in memory and in `to_secret_json()`, but will never appear in `repr(item)` or string logs.

### 5.8 Session Token Clearance on Authentication Errors
- **Weakness**: When desktop operations received HTTP 401 Unauthorized, `VaultSession` cleared `self.session_token = None` but did not notify the underlying `ApiClient`, leaving the invalid/stale bearer token attached to outgoing headers.
- **Remediation**: Centralized 401 handling into `_handle_auth_failure()`, ensuring `self.api.set_session_token(None)` is invoked on all auth failures and logouts.

### 5.9 Client Configuration File Permissions
- **Weakness**: Configuration files and directories were created with default umask permissions, potentially allowing other local users on a multi-user Linux machine to inspect configuration metadata.
- **Remediation**: Client now explicitly enforces POSIX `0700` directory and `0600` file permissions on `~/.config/vaultsync`.

