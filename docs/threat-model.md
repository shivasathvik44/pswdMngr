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
  - The VEK is stored wrapped (encrypted) with a KEK derived via Argon2id from the user's master password.
  - Server authentication credentials (e.g. hashed passwords or tokens) use a separate derivation pathway (`Argon2id(master_password, auth_salt)`) from encryption keys (`Argon2id(master_password, enc_salt)`). Compromising the server hash does not reveal the encryption key.
- **Limitations**: The attacker can observe sync metadata: number of records, ciphertext sizes, record UUIDs, revision numbers, and sync timestamps.

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
  - Strict Pydantic payload validation limits blob sizes and schema compliance.
  - Rate limiting per session and per IP.
  - Server maintains immutable revision history / version cursors so rollbacks can recover from malicious deletions.
- **Limitations**: A compromised client possessing the master password has legitimate cryptographic access to write valid ciphertext to the vault.

### 2.7 Concurrent Updates and Replayed Sync Requests
- **Threat**: Two devices modify the same record offline, or an attacker replays older synchronization requests.
- **Mitigation**:
  - Version cursors and monotonic record revision numbers.
  - Optimistic locking and conflict detection: updates require matching expected base revision.
  - Tombstones with revision tracking prevent deleted records from resurrecting on delayed sync.
  - Replayed requests are rejected idempotently using deterministic client mutation UUIDs.
- **Limitations**: True concurrent edits require user resolution (forking into a conflict record) rather than automated field-level merging, as the server cannot read fields inside ciphertext.

### 2.8 Corrupted Ciphertext and Invalid Input
- **Threat**: Bit rot, storage faults, or tampering produces altered ciphertext.
- **Mitigation**:
  - Authenticated encryption (AEAD: AES-256-GCM / XChaCha20-Poly1305) cryptographically detects any single-bit modification of ciphertext or associated authenticated data (AAD).
  - Clients fail immediately with a cryptographic error; never parse or trust unauthenticated payloads.
- **Limitations**: Corrupted records cannot be decrypted and require restoration from backup.

### 2.9 Backup Theft and Recovery Failures
- **Threat**: An offline backup archive is stolen from external storage, or a backup cannot be restored due to missing key parameters.
- **Mitigation**:
  - Backup exports are encrypted with a dedicated backup key derived from the master password and a distinct salt, or a separate recovery passphrase.
  - Backups include self-contained cryptographic headers (salt, Argon2 parameters, cipher version, MAC tag).
- **Limitations**: Loss of both master password and recovery key results in permanent, irrecoverable data loss by design.

### 2.10 Accidental Exposure Through Logs, Crash Reports, Git, or Config
- **Threat**: Secrets, passwords, or keys leak into logs, commit history, or error traces.
- **Mitigation**:
  - Strict `.gitignore` rules blocking `.env`, `*.db`, `*.key`, and secret artifacts.
  - Structured logging filters that forbid dumping request bodies or decrypted contents.
  - Sanitized exception handlers that return generic error messages to clients while logging safe tracebacks.
  - Synthetic dummy credentials only in automated test suites and documentation.
