# ADR 0004: Two-Credential Security Architecture and Migration

## Status
Accepted and Implemented (Phase 3.2)

## Context
In Phase 3.1, a security review identified a critical flaw in the initial Phase 3 design:
The server stored an Argon2id hash of an `auth_secret` that was derived from the user's vault master password via HKDF (`auth_secret = HKDF-Expand(Argon2id(P_vault, salt), "vaultsync:auth:v1")`).

While HKDF domain separation ensures computational independence when inputs are high-entropy, an attacker obtaining a stolen server database dump possesses both `kdf_salt` and `auth_hash`. The attacker could run an offline dictionary attack:
$$\text{Candidate } P' \to \text{Argon2id}(P', \text{salt}) \to \text{HKDF} \to \text{verify against } \text{auth\_hash}$$
Once verified, the attacker immediately gained the true vault master password, derived the Key-Encryption Key ($\text{KEK}$), unwrapped the Vault Encryption Key ($\text{VEK}$), and decrypted all confidential records without network interaction or server detection.

## Decision

We have migrated VaultSync to an explicit **Two-Credential Security Architecture**:

### 1. Account Password ($P_{\text{account}}$)
- **Role**: Used exclusively for server account authentication (`POST /api/v1/auth/login`).
- **Storage**: The server verifies $P_{\text{account}}$ against a server-side Argon2id hash (`account_password_hash`) stored in the `accounts` table.
- **Independence**: Never used to derive the vault encryption key, KEK, or master secret. Never combined with or derived from the vault master password.
- **Transport**: Transmitted only over authenticated TLS (or loopback during local development). Never logged, cached in server files, or embedded in URLs.

### 2. Vault Master Password ($P_{\text{vault}}$)
- **Role**: Kept strictly client-side to derive the Key-Encryption Key ($\text{KEK}$) using RFC 9106 Argon2id ($64\text{ MiB}, t=3, p=4$) and a unique public salt.
- **Zero-Knowledge Guarantee**: Never transmitted to the server under any condition (registration, login, password changes, or recovery).
- **Zero Verifiers**: The server database stores zero authentication verifiers or hashes derived from $P_{\text{vault}}$.
- **Stolen Database Security**: A stolen database dump provides the attacker with zero verifiers to test offline guesses against $P_{\text{vault}}$ in the authentication tables. Testing candidate master passwords against `account_password_hash` will never match because the values are mathematically uncorrelated.

### 3. Account Password Changes (`PUT /api/v1/auth/password`)
- Requires active authenticated session and verification of the current account password.
- Updates only `account_password_hash`.
- Invalidates all other active sessions for the account.
- Leaves `kdf_salt`, `wrapped_vault_key`, and all encrypted records in the database completely untouched and identical byte-for-byte.

### 4. Vault Master Password Changes (`PUT /api/v1/auth/vault-key`)
- Handled entirely client-side: the client derives a new $\text{KEK}$ from the new master password and a fresh public salt, then re-wraps the existing 256-bit $\text{VEK}$.
- The client uploads the updated `WrappedKeyEnvelope` and fresh `kdf_salt`.
- The server stores the updated envelope and salt.
- Encrypted records do not require re-encryption because the underlying 256-bit $\text{VEK}$ is unchanged.
- The account password and `account_password_hash` remain unchanged.

### 5. Account Recovery and Master Password Loss Semantics
- **Account Password Lost**: Reset via administrative CLI (`python -m vaultsync_server.scripts.admin_reset`) or authenticated recovery flow. This updates `account_password_hash` only. It does not decrypt or alter the vault.
- **Vault Master Password Lost**: Encrypted records are **permanently irrecoverable**. The server cannot restore vault access, and no false "master password reset" feature exists.

### 6. Database Migration (`0002_two_credential_architecture.py`)
- Replaces legacy `auth_hash` with `account_password_hash`.
- Existing accounts created under Phase 3 have their legacy `auth_hash` dropped and are flagged with `requires_password_migration = True`.
- Added `auth_rate_limits` table for robust database-backed sliding-window rate limiting across multi-worker Uvicorn processes.
