# VaultSync Backup and Disaster Recovery

---

## 1. Backup Strategy

Because VaultSync operates on a zero-knowledge, self-hosted architecture without centralized recovery portals, reliable and tested backup mechanisms are critical.

### Types of Backups
1. **Encrypted Client Export**: An encrypted archive containing all plaintext items encrypted with an independent backup key derived from the master password or a dedicated recovery key.
2. **Server Database Backup**: A raw snapshot of the server's SQLite or PostgreSQL database. Because the server database contains only wrapped keys and ciphertexts, the database backup is itself safe against casual observation, though still considered sensitive metadata.

---

## 2. Recovery Scenarios

### Scenario A: Lost or Destroyed Device
- **Prerequisite**: User has access to their Master Password.
- **Procedure**:
  1. Set up VaultSync on a replacement device (Fedora laptop or Android phone).
  2. Connect to the private Tailscale / WireGuard network.
  3. Enroll the new device with the VaultSync server using account credentials.
  4. The server delivers the salt and wrapped VEK (`WVEK`).
  5. The client computes the KEK from the Master Password and unwraps the VEK.
  6. The client synchronizes and decrypts all vault entries.
  7. The user revokes the lost device's session via the device management interface.

### Scenario B: Complete Server Failure / Loss
- **Prerequisite**: Client devices retain their local encrypted cache, or an offsite database backup exists.
- **Procedure**:
  1. Provision a new server instance.
  2. Restore the database file from backup, or initialize a clean server and let an authorized client push the existing vault.
  3. Re-establish WireGuard / Tailscale connectivity.

### Scenario C: Lost Master Password
- **Impact**: Irrecoverable by design. Because the server does not store the master password, KEK, or VEK, there is no backdoor or administrative reset.
- **Mitigation**: Users are prompted during vault initialization to safely store an emergency recovery kit offline (e.g. printed paper in a physical safe).
