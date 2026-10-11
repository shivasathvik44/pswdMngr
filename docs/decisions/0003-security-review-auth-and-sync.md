# ADR 0003: Security Review Findings — Auth Secret Derivation and Sync Concurrency

## Status
Accepted (Security Review & Architecture Recommendation)

## Context
During Phase 3.1, a security review was conducted on the authentication flow, rate limiting implementation, and incremental synchronization mechanics implemented in Phase 3.

## Findings and Decisions

### 1. Offline Master-Password Guessing Vulnerability
- **Finding**: In the initial Phase 3 design, `auth_secret` was derived directly from the master password using HKDF domain separation (`auth_secret = HKDF-Expand(Argon2id(P, salt), "vaultsync:auth:v1")`), and stored as `auth_hash = Argon2id(auth_secret)` in the `accounts` table.
- **Vulnerability**: While HKDF is a one-way function, an attacker with a server database dump possesses both `kdf_salt` and `auth_hash`. The attacker can execute a forward offline dictionary attack:
  $$\text{Candidate } P' \to \text{Argon2id}(P', \text{salt}) \to \text{HKDF} \to \text{auth\_secret}' \to \text{Argon2id verify against } \text{auth\_hash}$$
  Once verified, the attacker immediately derives $\text{KEK} = \text{HKDF-Expand}(M', \text{"vaultsync:kek:v1"})$ and unwraps `wrapped_vault_key`, decrypting the entire vault offline without network interaction.
- **Decision & Recommendation**:
  - The single-password model with server-side hash verification is fundamentally vulnerable to offline attacks upon database breach.
  - **Proposed Architecture**: Adopt a Two-Credential Model:
    1. **Account Password** ($P_{\text{account}}$): Used strictly for server authentication (`POST /api/v1/auth/login`).
    2. **Vault Master Password** ($P_{\text{vault}}$) + optional client Secret Key: Used strictly on the client for KEK derivation and local vault decryption.
    3. The server never receives or stores any verifier derived from $P_{\text{vault}}$.
  - **PAKE Evaluation**: OPAQUE (RFC 9807) was evaluated. While mathematically robust against offline dictionary attacks for single passwords, the lack of mature, stable cross-language libraries in Python and Kotlin (without complex NDK bindings) makes OPAQUE overly complex and brittle for this project at present.

### 2. Abuse Controls and Rate Limiting
- **Finding**: Rate limiting using compound key `auth:{username}:{ip}` permitted distributed brute force across rotating IPs against a single target user, and credential spraying across multiple usernames from a single IP. Furthermore, in-memory state does not persist across process restarts or multiple worker processes.
- **Decision**:
  - Implement dual-axis rate limiting tracking both `auth:ip:{ip}` and `auth:user:{username}` independently.
  - Reset user failure counters upon successful authentication.
  - Document database-backed rate limiting (`auth_rate_limits` table in SQLite/Postgres) as the recommended production mechanism to support multiple Uvicorn workers without requiring external Redis infrastructure.

### 3. Incremental Synchronization and Concurrency
- **Finding**: Concurrent mutations on the same account could race on `account.sync_cursor` without explicit database row locks, potentially leading to duplicate cursors or out-of-order commit windows where clients miss intermediate updates.
- **Decision**:
  - Enforce `select(Account).where(Account.id == account.id).with_for_update()` during cursor allocation in `create_record`, `update_record`, and `delete_record`.
  - Enforce deterministic secondary ordering: `order_by(EncryptedRecord.sync_cursor.asc(), EncryptedRecord.id.asc())`.
  - Verified deterministically in `test_sync_pagination_during_concurrent_mutations`.
