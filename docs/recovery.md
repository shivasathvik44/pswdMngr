# VaultSync Database Backup, Disaster Recovery, and Operational Guide

This document provides a practical, step-by-step guide for operators backing up, verifying, and recovering a deployed VaultSync server database.

> [!CAUTION]
> **Repository Safety Constraint:**
> These instructions are intended for operational deployments. Never execute backup, copy, query, or restore commands against the development baseline database at `/home/capslock/PDMG/vaultsync.db`.

---

## 1. Architecture & Threat Model Overview

VaultSync operates on a strict **Zero-Knowledge Architecture**:
- The server stores **only opaque ciphertexts**:
  - `account_password_hash` (Argon2id verifier for account authentication)
  - `encrypted_vault_key` (AES-256-GCM wrapped representation of the 256-bit vault key)
  - `key_derivation_salt` (public 16-byte KDF salt)
  - `records` table (AES-256-GCM encrypted blobs, authenticated nonces, tags, and record IDs)
- **Plaintext Zero-Knowledge**: The server database never contains plaintext passwords, decrypted vault items, or unencrypted keys.
- **Metadata Protection**: An attacker who obtains an unencrypted database snapshot cannot decrypt vault records without the client's Vault Master Passphrase, but could observe user account names, creation dates, sync timestamps, and record count/size distributions. Therefore, backups **must still be encrypted at rest and restricted by strict filesystem permissions**.

---

## 2. Safe Database Backup Procedures (SQLite)

When VaultSync uses SQLite in production (typically with Write-Ahead Logging / WAL enabled), raw file copying (`cp live.db backup.db`) while the server is running can produce a corrupted or torn snapshot if a write transaction is committed mid-copy.

Operators must use one of the two consistent methods described below.

### Method A: Live Online Backup via SQLite CLI (Recommended)

The official SQLite `.backup` command leverages SQLite's online backup API. It acquires the necessary shared locks, streams a point-in-time consistent snapshot across WAL frames, and never locks out readers or concurrent transactions.

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Define deployment paths (adjust to your deployment locations)
DB_PATH="/var/lib/vaultsync/vaultsync.db"
BACKUP_DIR="/var/backups/vaultsync"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/vaultsync-backup-${TIMESTAMP}.db"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

# 2. Perform atomic, consistent online backup
sqlite3 "${DB_PATH}" ".backup '${BACKUP_FILE}'"

# 3. Restrict permissions immediately
chmod 600 "${BACKUP_FILE}"

echo "Live backup completed: ${BACKUP_FILE}"
```

### Method B: Offline Cold Backup (Service Paused)

If preferred during maintenance windows, stop the service to flush WAL journals back into the main database file before copying:

```bash
# 1. Stop the VaultSync systemd service
sudo systemctl stop vaultsync

# 2. Copy the database file
cp /var/lib/vaultsync/vaultsync.db /var/backups/vaultsync/vaultsync-offline-$(date +%F).db

# 3. Restart the service
sudo systemctl start vaultsync
```

---

## 3. Protecting Backups: Encryption at Rest & Access Control

Backup archives must be protected against unauthorized access.

### 1. Filesystem Permissions
Ensure backup files and directories are owned exclusively by the dedicated service user or root, with `0600` file permissions:

```bash
chmod 600 /var/backups/vaultsync/*.db
chown vaultsync:vaultsync /var/backups/vaultsync/*.db
```

### 2. Encryption at Rest with GPG or Age
Before transferring backups to offsite storage or retention buckets, encrypt the snapshot:

```bash
# Using age (recommended for modern systems):
age -r "age1userpublickeyexample..." -o "${BACKUP_FILE}.age" "${BACKUP_FILE}"
rm -f "${BACKUP_FILE}"

# Or using GPG symmetric encryption:
gpg --batch --yes --symmetric --cipher-algo AES256 --output "${BACKUP_FILE}.gpg" "${BACKUP_FILE}"
rm -f "${BACKUP_FILE}"
```

---

## 4. Disaster Recovery & Safe Restoration Drill

> [!IMPORTANT]
> **Never restore a backup directly into a production service without verifying it in an isolated staging location first.**

### Step 1: Decrypt and Isolate the Restored Database
Always restore into a sandbox or temporary directory:

```bash
RESTORE_DIR=$(mktemp -d /tmp/vaultsync-restore-XXXXXX)
cd "${RESTORE_DIR}"

# Decrypt the backup archive
gpg --decrypt /var/backups/vaultsync/vaultsync-backup-20261022.db.gpg > test_restore.db
chmod 600 test_restore.db
```

### Step 2: Perform Low-Level SQLite Integrity Checks
Verify that the database file is structurally sound and free from corruption:

```bash
# Check SQLite B-tree structural integrity
sqlite3 test_restore.db "PRAGMA integrity_check;"
# Output MUST be: ok

# Check SQLite foreign key relationships
sqlite3 test_restore.db "PRAGMA foreign_key_check;"
# Output MUST be empty (no violations)
```

### Step 3: Verify Schema and Migration Status
Verify that the restored database is compatible with the latest Alembic schema:

```bash
# Check migration head status against the restored test database
VAULTSYNC_DATABASE_URL="sqlite:///${RESTORE_DIR}/test_restore.db" \
  alembic -c server/alembic.ini current
```

### Step 4: Verify with a Sandboxed Ephemeral Server
Launch a local ephemeral server on a high test port (e.g. 8888) to verify that the application can read the restored records and authenticate:

```bash
VAULTSYNC_DATABASE_URL="sqlite:///${RESTORE_DIR}/test_restore.db" \
VAULTSYNC_HOST="127.0.0.1" \
VAULTSYNC_PORT="8888" \
python3 -m uvicorn vaultsync_server.main:app
```

In another terminal, test service health:
```bash
curl -s http://127.0.0.1:8888/health
# Should return {"status":"healthy", ...}
```

### Step 5: Replace the Live Production Database
Once verified:

```bash
# 1. Stop live service
sudo systemctl stop vaultsync

# 2. Archive the broken/replaced database for post-mortem analysis
mv /var/lib/vaultsync/vaultsync.db /var/lib/vaultsync/vaultsync-pre-restore-$(date +%s).db.bak

# 3. Move the verified test database into production path
mv "${RESTORE_DIR}/test_restore.db" /var/lib/vaultsync/vaultsync.db
chown vaultsync:vaultsync /var/lib/vaultsync/vaultsync.db
chmod 600 /var/lib/vaultsync/vaultsync.db

# 4. Clean up temporary directory
rm -rf "${RESTORE_DIR}"

# 5. Start the live service
sudo systemctl start vaultsync
```

---

## 5. Recovery Scenarios and Feature Matrix

| Scenario | Supported Today | Mechanism / Tool | Does it Recover Vault Records? |
| :--- | :--- | :--- | :--- |
| **Lost / Replaced Device** | **Yes** | Log in with Account Password, unlock with Master Password | **Yes** |
| **Forgotten Account Password** | **Yes** | Server CLI: `python -m vaultsync_server.scripts.admin_reset` | **No** (restores login only; requires Master Password to unlock) |
| **Master Password Rotation** | **Yes** | Settings GUI / `rotate_vault_master_password()` | **N/A** (re-wraps existing VEK while vault is already unlocked) |
| **Forgotten Master Password** | **No** | **None (Irrecoverable by Design)** | **No (Permanent data loss)** |
| **Recovery Key / Recovery Phrase** | **No** | **Not implemented in codebase** | **N/A** |

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
- **Prerequisite**: Operator has shell access to the server host.
- **Semantics**:
  - The server account password can be administratively reset using the recovery CLI. Passwords are never accepted as command-line arguments to prevent leakage into `ps aux` or shell histories:
    ```bash
    # Interactive mode with masked confirmation (recommended):
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
- **Statement**: Because the server never receives or stores the master password, KEK, or unencrypted VEK, there is **zero backdoor**, zero administrative override, and zero mathematical possibility of decrypting vault contents without the master password.
- **Absence of Recovery Keys**: There is **no recovery-key or recovery-phrase mechanism implemented** in the VaultSync codebase. The server intentionally does not offer a "master password reset" feature, as such a feature would be mathematically dishonest and falsely imply that encrypted data could be recovered without the encryption key.
- **Operational Recommendation**: Users must manually safeguard their Vault Master Password (e.g. written on physical paper stored in a fireproof safe). If the master password is lost, all vault contents are permanently lost.

### Scenario D: Live Master Password Rotation
- **Prerequisite**: The vault must be currently UNLOCKED in the client application.
- **Procedure**:
  - The user enters a new master password in Settings.
  - The client re-wraps the in-memory VEK under a newly derived KEK with a fresh salt and transmits the new `WrappedKeyEnvelope` to `PUT /api/v1/auth/vault-key`.
  - Individual encrypted records do NOT need re-encryption because the raw VEK is preserved.

### Scenario E: Complete Server Failure / Loss
- **Prerequisite**: Client devices retain their local encrypted cache, or an offsite database snapshot exists.
- **Procedure**:
  1. Provision a new server instance.
  2. Restore the database file from backup, or initialize a clean server database via Alembic migrations.
  3. Re-establish WireGuard / Tailscale connectivity.
  4. Client devices re-authenticate and synchronize the vault state.
