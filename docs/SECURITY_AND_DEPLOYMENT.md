# VaultSync Security and Production Deployment Guide

This document defines the security architecture, production deployment requirements, operational hardening, and known runtime limitations for the **VaultSync** ecosystem.

> [!WARNING]
> **Production Deployment Requirement:**
> The VaultSync backend server is an ASGI application (FastAPI / Uvicorn) designed to bind strictly to `127.0.0.1` (localhost) or an isolated mesh overlay network (Tailscale / WireGuard). **Never expose the backend server directly to the public internet without an authenticated, TLS-terminating reverse proxy.**

---

## 1. Network Architecture & Reverse Proxy Configuration

### 1.1 Reverse Proxy Necessity
FastAPI / Uvicorn serves application logic but is not designed to operate as a front-line internet gateway. A dedicated reverse proxy (such as Nginx, Caddy, or HAProxy) is required in production to provide:
1. **TLS Termination & Cipher Suite Enforcement**: HTTP/2, TLS 1.3, and modern forward-secret cipher suites.
2. **Slowloris & Slow Request Protection**: Mitigating slow-client connection pool exhaustion.
3. **Request Buffering & Payload Boundaries**: Enforcing HTTP body size limits before data reaches Python memory.
4. **Trusted Proxy Header Normalization**: Providing verified client IP and protocol metadata.

### 1.2 Example Nginx Configuration

```nginx
# /etc/nginx/sites-available/vaultsync.conf
upstream vaultsync_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name vault.example.internal;

    # TLS Certificates (e.g. Let's Encrypt or Tailscale HTTPS)
    ssl_certificate /etc/ssl/certs/vaultsync.crt;
    ssl_certificate_key /etc/ssl/private/vaultsync.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # Payload limits (must align with VAULTSYNC_MAX_PAYLOAD_SIZE_BYTES = 2 MiB)
    client_max_body_size 2M;

    location / {
        proxy_pass http://vaultsync_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

### 1.3 Example Caddy Configuration

```caddy
# /etc/caddy/Caddyfile
vault.example.internal {
    tls /etc/ssl/certs/vaultsync.crt /etc/ssl/private/vaultsync.key

    request_body {
        max_size 2MB
    }

    reverse_proxy 127.0.0.1:8000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

---

## 2. HSTS & Trusted Reverse Proxy Behavior

The VaultSync backend includes built-in security middleware (`vaultsync_server.main`) that evaluates transport security:

1. **HSTS Header Emission**:
   - The `Strict-Transport-Security` header is emitted **only** when `request.url.scheme == "https"` or when the request arrives over an approved reverse proxy forwarding `X-Forwarded-Proto: https`.
2. **Untrusted Header Prevention**:
   - To prevent untrusted clients from spoofing forwarded headers, the server checks `request.client.host` against `settings.trusted_proxies`.
   - Default: `["127.0.0.1", "::1"]`.
   - In containerized or multi-tier topologies, operators must configure `VAULTSYNC_TRUSTED_PROXIES` with the CIDR or IP addresses of upstream proxy nodes:
     ```bash
     VAULTSYNC_TRUSTED_PROXIES='["127.0.0.1", "10.0.0.2"]'
     ```

---

## 3. Production Secret Management

### 3.1 Server Master Secret Key (`VAULTSYNC_SERVER_SECRET_KEY`)
The server uses a dedicated master secret key for internal server-side cryptographic operations, most notably deriving deterministic synthetic salts for `/api/v1/auth/salt`.

- **Security Requirements in Production**:
  - `VAULTSYNC_ENVIRONMENT=production` enforces strict validation.
  - Must be **at least 32 characters** of high-entropy randomness.
  - Must not equal default strings (`vaultsync-development-secret-key-change-in-production-min32bytes`, `secret`, `changeme`).
  - If missing or insecure, the backend fails closed and aborts startup immediately with a `ValueError`.
- **Key Generation**:
  ```bash
  # Generate a 64-character hex string (32 bytes entropy):
  openssl rand -hex 32
  # Or via Python secrets module:
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
- **Injection Best Practices**:
  - Do not check `.env` files into source control.
  - On systemd-managed Linux hosts, use systemd credential management:
    ```ini
    # /etc/systemd/system/vaultsync.service
    [Service]
    EnvironmentFile=/etc/vaultsync/vaultsync.env
    # Or using systemd credentials:
    LoadCredential=server_secret_key:/etc/vaultsync/secret.key
    ```
  - Ensure the secret file is owned by `vaultsync:vaultsync` with permissions `0400` or `0600`.

---

## 4. Authentication, Sessions & Rate Limiting

### 4.1 Two-Credential Architecture
VaultSync strictly separates server authentication from vault encryption:
- **Account Password ($P_{\text{account}}$)**:
  - Transmitted to `/api/v1/auth/login` or `/api/v1/auth/register` over TLS.
  - Hashed server-side using Argon2id (`time_cost=3, memory_cost=64MB, parallelism=4`) with a unique account salt.
  - Grants an opaque Bearer session token.
  - Does **not** grant access to vault records.
- **Vault Master Passphrase ($P_{\text{vault}}$)**:
  - Exists strictly on client devices and is **never transmitted to the server**.
  - Derives the Key Encryption Key (KEK) client-side to unwrap the Vault Encryption Key (VEK).

### 4.2 Session Tokens & Revocation
- **Bearer Tokens**: Generated via `secrets.token_urlsafe(32)` (256 bits entropy).
- **Database Storage**: The server never stores plaintext session tokens. Tokens are stored as SHA-256 hashes (`token_hash`) in the `sessions` table.
- **Expiration Policy**: Controlled by `VAULTSYNC_SESSION_EXPIRY_HOURS` (default: 168 hours / 7 days).
- **Activity Throttling**: To prevent SQLite write contention during frequent sync polling, updates to `last_used_at` are throttled by `session_last_used_update_interval_seconds` (default: 300 seconds).
- **Immediate Revocation**: Calling `POST /api/v1/auth/logout` or `DELETE /api/v1/sessions/{id}` sets `revoked_at` in the database, immediately invalidating the session.

### 4.3 Rate Limiting & IPv6 Subnet Normalization
Abuse control is enforced across authentication endpoints (`/register`, `/login`, `/salt`, `/password`):
- **Limits**: Configured via `VAULTSYNC_RATE_LIMIT_MAX_ATTEMPTS` (default: 10) and `VAULTSYNC_RATE_LIMIT_WINDOW_SECONDS` (default: 60s).
- **Compound Database Indexing**: Backed by `auth_rate_limits` table with compound index `ix_auth_rate_limits_id_time` on `(identifier, attempt_time)` for fast sliding-window evaluation.
- **IP Extraction**: Transport peer IP (`request.client.host`) is used directly to prevent header-spoofing by unauthenticated clients.
- **IPv6 Normalization**:
  - IPv6 client addresses are grouped and normalized to a `/64` CIDR block (`normalize_client_ip`).
  - This prevents attackers from evading rate limits by rapidly cycling IPv6 interface identifiers within an ISP-allocated `/64` prefix.
  - IPv4-mapped IPv6 addresses (e.g. `::ffff:192.0.2.1`) are unwrapped to canonical IPv4.

---

## 5. Encrypted Record Storage & Zero-Knowledge Boundary

### 5.1 Opaque Record Envelopes
The server database stores only cryptographic envelopes:
- `record_id`: UUIDv4 identifier
- `ciphertext`: AES-256-GCM encrypted payload bytes (base64-encoded)
- `nonce`: 12-byte random initialization vector
- `tag`: 16-byte GCM authentication tag
- `version`: Optimistic concurrency integer counter
- `sync_cursor`: Monotonically increasing sync ordering cursor
- `is_deleted`: Tombstone boolean flag

### 5.2 Associated Authenticated Data (AAD)
Every record encryption binds the item's `record_id` as Associated Authenticated Data:
$$\text{AAD} = \text{UTF-8}(\text{record\_id})$$
This cryptographic binding guarantees that ciphertext envelopes cannot be swapped, re-associated with another record, or replayed under a different ID without causing an immediate GCM authentication tag failure.

### 5.3 Monotonic Sync Cursor Allocation (SEC-01)
To ensure multi-client synchronization integrity, record creation and update transactions execute inside an `exclusive_transaction()` context. Cursors are incremented monotonically under SQLite `BEGIN EXCLUSIVE` locking, preventing duplicate cursors or cursor gaps during concurrent writes.

---

## 6. Logging & Sensitive Data Handling

1. **Zero Secret Logging**:
   - The application logging pipeline explicitly forbids logging raw passwords, bearer tokens, KEKs, VEKs, or decrypted vault item fields.
   - Pydantic models automatically redact sensitive fields in string representations (`repr`).
2. **Safe Error Handling**:
   - Authentication errors return generic HTTP 401 or 400 responses without indicating whether a username exists or whether a password was incorrect.
   - Database and internal tracebacks are caught by global exception handlers and masked from HTTP clients.
3. **Log Sanitization**:
   - Production logs should be directed to `systemd-journald` or a local file with restricted permissions (`0640`).

---

## 7. Client Memory Security & Runtime Limitations

Both the Fedora Desktop (Python) and Android (Kotlin) clients implement memory hygiene procedures, but operators must understand platform limitations:

### 7.1 Implemented In-Memory Controls
- **`clear_key_material()`**: Uses native memory operations (`ctypes.memset`) to zero out mutable `bytearray` buffers holding decrypted keys and secret materials upon vault lock or logout.
- **Inactivity Auto-Lock**: Desktop and Android applications monitor user interaction events and automatically lock the vault after a configurable timeout (default: 5 minutes).
- **Clipboard Clearing**: Decrypted credentials copied to the clipboard are scheduled for automated clearing after 30 seconds, verifying that the clipboard still contains the copied value before wiping.

### 7.2 Inherent Runtime Limitations
- **Garbage Collection & Immutability**:
  - Python and JVM environments utilize managed memory with generational garbage collection.
  - Immutable objects (such as Python `str` or Java `java.lang.String`) cannot be reliably zeroized in place by application code. Transient copies created during string parsing, JSON decoding, or Qt widget rendering may persist in heap space until reclaimed by garbage collection.
- **OS Paging & Memory Dumps**:
  - If the host system swaps process memory to an unencrypted swap partition, sensitive memory pages could be written to disk.
  - Operating system core dumps (`ulimit -c`) could capture process memory if an unhandled crash occurs.

### 7.3 Operational Mitigations
1. **Full Disk Encryption (FDE)**: Always enable LUKS (Linux) or device encryption (Android) to ensure swap files and core dumps are encrypted at rest.
2. **Disable Core Dumps**: In production environments, disable core dumps via systemd (`LimitCORE=0`) or `/etc/security/limits.conf`.
3. **Host Integrity**: Ensure client workstations run updated operating systems free of malware, keyloggers, or unauthorized root access.

---

## 8. Operational Responsibilities & Incident Response

### 8.1 Maintenance Checklist
- **System Updates**: Regularly update OS packages, Python runtime, and virtual environment dependencies.
- **Database Backup Drills**: Execute periodic backup and restoration drills as documented in [`docs/recovery.md`](recovery.md).
- **Session Pruning**: For high-volume deployments, configure a periodic maintenance job to prune expired or revoked sessions:
  ```sql
  DELETE FROM sessions WHERE revoked_at IS NOT NULL OR expires_at < CURRENT_TIMESTAMP;
  ```

### 8.2 Incident Response Procedures
- **Stolen or Compromised Client Device**:
  1. Immediately log into VaultSync from another authorized client or administrative terminal.
  2. Revoke the lost device's session (`POST /api/v1/auth/logout` or delete from `sessions`).
  3. Rotate the **Vault Master Passphrase** from an unlocked trusted client to re-wrap the VEK with a new salt and master password.
  4. Change the **Account Password**.
- **Compromised Server Host**:
  1. Immediately take the server offline (`systemctl stop vaultsync`).
  2. Audit server logs and database snapshots for unauthorized changes.
  3. Because the server stores only ciphertext blobs, an attacker cannot decrypt vault contents without the client master passphrase.
  4. Restore the database snapshot to a clean, isolated host, deploy a newly generated `VAULTSYNC_SERVER_SECRET_KEY`, and instruct all users to rotate their Account Passwords and Master Passphrases.
