# VaultSync Backup, Disaster Recovery, and Migration Guide

---

## 1. Backup Strategy

Because VaultSync operates on a strict zero-knowledge architecture, reliable and tested backup mechanisms are essential.

### Types of Backups
1. **Encrypted Client Export**: An encrypted archive containing all plaintext items encrypted with an independent backup key derived from the master password or a dedicated recovery passphrase. Stored securely offline.
2. **Server Database Backup**: A raw snapshot of the server's SQLite or PostgreSQL database. Because the server database contains only wrapped keys and ciphertext blobs, the database backup is itself safe against casual observation, though still considered sensitive metadata.

---

## 2. Recovery Scenarios

### Scenario A: Lost or Destroyed Device
- **Prerequisite**: User possesses both their Account Password and Vault Master Password.
- **Procedure**:
  1. Set up VaultSync on a replacement device (Fedora laptop or Android phone).
  2. Connect to the private Tailscale / WireGuard network.
  3. Log in to the VaultSync server using the **Account Password** (`POST /api/v1/auth/login`).
  4. The server delivers the public salt and wrapped vault key envelope (`WrappedKeyEnvelope`).
  5. The client computes the KEK locally from the **Vault Master Password** and unwraps the VEK.
  6. The client synchronizes and decrypts all vault entries.
  7. The user revokes the lost device's session via `DELETE /api/v1/sessions/{id}`.

### Scenario B: Forgotten Server Account Password
- **Prerequisite**: User has administrative access to the server host.
- **Semantics**:
  - The server account password can be administratively reset using the recovery CLI. To prevent password leakage into the Linux process table (`ps aux`, `/proc/<pid>/cmdline`) or shell history (CWE-214), passwords are never accepted as command-line arguments:
    ```bash
    # Interactive mode with masked double confirmation (recommended):
    python -m vaultsync_server.scripts.admin_reset --username alice

    # Non-interactive / piped stdin mode (for scripts and CI):
    echo -n "NewSecureAccountPassword2026!" | python -m vaultsync_server.scripts.admin_reset --username alice --password-stdin
    ```
  - **Security Guarantee**:
    - Updates only `account_password_hash` with Argon2id.
    - Revokes all existing active sessions.
    - **Never decrypts, alters, or destroys encrypted vault contents, wrapped keys, or public salts.**
    - Does NOT grant access to the vault without the Vault Master Password.

### Scenario C: Lost Vault Master Password
- **Impact**: **Permanently Irrecoverable by Design.**
- **Statement**: Because the server never receives or stores the master password, KEK, or unencrypted VEK, there is **zero backdoor**, zero administrative override, and zero mathematical possibility of decrypting vault contents without the master password or an existing unencrypted backup.
- **Anti-Pattern Rejection**: The server intentionally does not offer a "master password reset" feature, as such a feature would be mathematically dishonest and falsely imply that encrypted data could be recovered without the encryption key.
- **Mitigation**: Users are prompted during vault initialization to safely store an emergency recovery kit offline (e.g. printed paper in a physical fireproof safe).

### Scenario D: Complete Server Failure / Loss
- **Prerequisite**: Client devices retain their local encrypted cache, or an offsite database snapshot exists.
- **Procedure**:
  1. Provision a new server instance.
  2. Restore the database file from backup, or initialize a clean server database via Alembic migrations.
  3. Re-establish WireGuard / Tailscale connectivity.
  4. Client devices re-authenticate and synchronize the vault state.

---

## 3. Legacy Migration (Phase 3 to Phase 3.2)

### Why Migration is Necessary
In the initial Phase 3 prototype, server authentication used an `auth_secret` derived from the master password. Security review (Phase 3.1) revealed this enabled offline dictionary attacks against stolen database dumps.

Phase 3.2 migrated the schema to the **Two-Credential Model** via Alembic revision `0002_two_credential_architecture.py`.

### Migration Behavior
- The legacy `auth_hash` column is dropped.
- Existing accounts have `requires_password_migration` set to `1` (true).
- Attempted logins with legacy credentials return `403 Forbidden` (`detail: "Account requires password migration"`).

### How to Complete Migration
For local development and self-hosted instances, execute the administrative reset script to establish an independent account password:

```bash
# Interactive mode (prompts for new password with confirmation):
python -m vaultsync_server.scripts.admin_reset --username <username>

# Automation / piped mode:
echo -n "<new_account_password>" | python -m vaultsync_server.scripts.admin_reset --username <username> --password-stdin
```

This clears the `requires_password_migration` flag and sets the new `account_password_hash`. The user can then immediately log in with `<new_account_password>` and unlock their vault using their unchanged Vault Master Password.
