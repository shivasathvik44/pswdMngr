# VaultSync Sync API Specification

Version: `1.2.0` (Phase 3.2 Two-Credential Implementation)  
Base URL: `/api/v1`

---

## 1. Authentication and Credential Separation

VaultSync enforces strict cryptographic credential separation between client-side vault encryption and server authentication:

1. **Vault Master Password ($P_{\text{vault}}$)**:
   - Exists strictly on client devices and is **never** transmitted to the server under any circumstance.
   - Derives the Key-Encryption Key ($\text{KEK}$) locally using Argon2id ($64\text{ MiB}, t=3, p=4$) and the public salt.
   - Wraps the 256-bit Vault Encryption Key ($\text{VEK}$) via AES-256-GCM.
2. **Account Password ($P_{\text{account}}$)**:
   - Independent credential used exclusively for server account authentication.
   - Transmitted over authenticated TLS (or loopback during local development).
   - Never used as input to any vault encryption key derivation.
3. **Server Password Storage**:
   - The server verifies $P_{\text{account}}$ using Argon2id with server-side parameters ($32\text{ MiB}, t=2, p=2$).
   - The database stores only `account_password_hash` for server authentication. Zero verifiers derived from $P_{\text{vault}}$ are stored in authentication tables.
   - Note: The encrypted `wrapped_vault_key` contains an AES-256-GCM authentication tag that acts as an inherent offline verification oracle if the database is dumped; master password protection from offline guessing relies strictly on client-side Argon2id ($64\text{ MiB}, t=3, p=4$) and passphrase entropy.
4. **Session Bearer Tokens**:
   - Issued upon successful login (`POST /api/v1/auth/login`).
   - High-entropy CSPRNG tokens (`secrets.token_urlsafe(32)`).
   - Only the constant-length SHA-256 verifier (`token_hash`) is stored in the database.
   - Header: `Authorization: Bearer <token>`
   - Default expiration: 7 days ($168$ hours), revoked immediately upon logout, password change, or remote device wipe.
5. **Abuse Control & Rate Limiting**:
   - Dual-axis sliding-window rate limiting on IP (`auth:ip:{ip}`) and username (`auth:user:{username}`).
   - Multi-worker persistence via `auth_rate_limits` table in database.

---

## 2. API Endpoints Overview

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Service health status | No |
| `GET` | `/api/v1/health` | Versioned service health | No |
| `POST` | `/api/v1/auth/register` | Register new account with account password and public salt | No |
| `POST` | `/api/v1/auth/login` | Authenticate with account password and issue session | No |
| `POST` | `/api/v1/auth/logout` | Revoke current calling session | Yes |
| `PUT` | `/api/v1/auth/password` | Change account password (invalidates other sessions) | Yes |
| `GET` | `/api/v1/auth/salt` | Fetch user public KDF salt | No |
| `PUT` | `/api/v1/auth/vault-key` | Upload/update wrapped vault key envelope and salt | Yes |
| `GET` | `/api/v1/sessions` | List active sessions for account | Yes |
| `DELETE`| `/api/v1/sessions/{id}` | Revoke specific device session | Yes |
| `DELETE`| `/api/v1/sessions` | Revoke all sessions for account | Yes |
| `POST` | `/api/v1/records` | Create new encrypted record | Yes |
| `GET` | `/api/v1/records/{id}` | Fetch single encrypted record by record_id | Yes |
| `PUT` | `/api/v1/records/{id}` | Update encrypted record (optimistic concurrency) | Yes |
| `DELETE`| `/api/v1/records/{id}` | Tombstone record for deletion propagation | Yes |
| `GET` | `/api/v1/sync` | Incremental sync cursor with pagination | Yes |

---

## 3. Endpoint Specifications

### 3.1 Authentication

#### `POST /api/v1/auth/register`
- **Request Body**:
  ```json
  {
    "username": "alice",
    "account_password": "SecureAccountPassword2026!",
    "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg==",
    "wrapped_vault_key": "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"kdf\":{...},\"nonce\":\"...\",\"ciphertext\":\"...\"}"
  }
  ```
- **Validation**:
  - `account_password`: $\ge 8$ chars, $\le 256$ chars.
  - `kdf_salt`: Valid base64 encoding of exactly 16 bytes.
  - `wrapped_vault_key`: If provided, strictly validated against `WrappedKeyEnvelope` schema.
- **Response 201 Created**:
  ```json
  {
    "account_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "username": "alice",
    "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg==",
    "created_at": "2026-10-11T00:38:00+00:00"
  }
  ```
- **Error Responses**:
  - `400 Bad Request`: Malformed `kdf_salt` or invalid `wrapped_vault_key` envelope.
  - `409 Conflict`: Username already registered.
  - `429 Too Many Requests`: Registration rate limit exceeded.

#### `POST /api/v1/auth/login`
- **Request Body**:
  ```json
  {
    "username": "alice",
    "account_password": "SecureAccountPassword2026!",
    "device_name": "Fedora Workstation",
    "device_id": "laptop-fedora-uuid"
  }
  ```
- **Response 200 OK**:
  ```json
  {
    "session_token": "<urlsafe_bearer_token>",
    "session_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
    "account_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "expires_at": "2026-10-18T00:38:00+00:00",
    "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg==",
    "wrapped_vault_key": "<json_string_wrapped_key_envelope_or_null>"
  }
  ```
- **Error Responses**:
  - `401 Unauthorized`: Invalid credentials.
  - `403 Forbidden`: Account requires legacy password migration.
  - `429 Too Many Requests`: Failed attempt limit exceeded (dual-axis rate limiter).

#### `PUT /api/v1/auth/password`
- **Headers**: `Authorization: Bearer <session_token>`
- **Request Body**:
  ```json
  {
    "current_password": "OldAccountPassword2026!",
    "new_password": "NewSecureAccountPassword2027!"
  }
  ```
- **Semantics**:
  - Verifies current account password against stored hash.
  - Updates `account_password_hash` with Argon2id.
  - Clears `requires_password_migration` flag.
  - Revokes all other active sessions for the account.
  - Leaves `wrapped_vault_key`, `kdf_salt`, and all encrypted records completely intact.
- **Response 200 OK**:
  ```json
  {
    "status": "ok",
    "message": "Account password updated successfully"
  }
  ```
- **Error Responses**:
  - `401 Unauthorized`: Current account password incorrect or invalid session.

#### `PUT /api/v1/auth/vault-key`
- **Headers**: `Authorization: Bearer <session_token>`
- **Request Body**:
  ```json
  {
    "wrapped_vault_key": "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"kdf\":{...},\"nonce\":\"...\",\"ciphertext\":\"...\"}",
    "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg=="
  }
  ```
- **Semantics**:
  - Used during master password rotation.
  - Validates `WrappedKeyEnvelope` structure and optional fresh public `kdf_salt`.
  - Replaces stored envelope and salt.
  - Encrypted records do not require re-encryption because the underlying VEK is preserved.
  - Account password and `account_password_hash` are unchanged.
- **Response 200 OK**:
  ```json
  {
    "status": "ok",
    "message": "Wrapped vault key updated successfully"
  }
  ```

#### `GET /api/v1/auth/salt?username=alice`
- **Response 200 OK**:
  ```json
  {
    "username": "alice",
    "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg=="
  }
  ```
- **Error Responses**:
  - `404 Not Found`: Account does not exist.

---

## 3.2 Session Management

#### `GET /api/v1/sessions`
- **Headers**: `Authorization: Bearer <session_token>`
- **Response 200 OK**:
  ```json
  [
    {
      "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "device_name": "Fedora Workstation",
      "device_id": "laptop-fedora-uuid",
      "created_at": "2026-10-11T00:38:00+00:00",
      "expires_at": "2026-10-18T00:38:00+00:00",
      "last_used_at": "2026-10-11T00:40:00+00:00",
      "is_current": true
    }
  ]
  ```

#### `DELETE /api/v1/sessions/{session_id}`
- **Headers**: `Authorization: Bearer <session_token>`
- **Response 200 OK**: `{"status": "ok", "message": "Session successfully revoked"}`

---

## 3.3 Encrypted Records & Concurrency Control

#### `POST /api/v1/records`
- **Request Body**:
  ```json
  {
    "record_id": "d3b07384-d113-4674-8b6a-939e144a14d5",
    "ciphertext_payload": "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"record_id\":\"d3b07384-d113-4674-8b6a-939e144a14d5\",\"nonce\":\"...\",\"ciphertext\":\"...\"}"
  }
  ```
- **Response 201 Created**:
  ```json
  {
    "record_id": "d3b07384-d113-4674-8b6a-939e144a14d5",
    "ciphertext_payload": "...",
    "revision": 1,
    "sync_cursor": 1,
    "is_deleted": false,
    "created_at": "2026-10-11T00:40:00+00:00",
    "updated_at": "2026-10-11T00:40:00+00:00"
  }
  ```

#### `PUT /api/v1/records/{record_id}`
- **Optimistic Concurrency**: Requires client to supply `expected_revision`. If `expected_revision != record.revision`, the server rejects the update with `409 Conflict`.
- **Request Body**:
  ```json
  {
    "expected_revision": 1,
    "ciphertext_payload": "..."
  }
  ```
- **Response 200 OK**:
  ```json
  {
    "record_id": "d3b07384-d113-4674-8b6a-939e144a14d5",
    "ciphertext_payload": "...",
    "revision": 2,
    "sync_cursor": 2,
    "is_deleted": false,
    "created_at": "2026-10-11T00:40:00+00:00",
    "updated_at": "2026-10-11T00:42:00+00:00"
  }
  ```
- **Error Response 409 Conflict**:
  ```json
  {
    "detail": "Conflict: expected revision 1, but current revision is 2"
  }
  ```

#### `DELETE /api/v1/records/{record_id}?expected_revision=2`
- **Tombstone Semantics**: Does not physically drop the row. Sets `is_deleted = true`, purges `ciphertext_payload = ""`, increments `revision = revision + 1`, and increments `sync_cursor`.
- **Response 200 OK**:
  ```json
  {
    "record_id": "d3b07384-d113-4674-8b6a-939e144a14d5",
    "revision": 3,
    "sync_cursor": 3,
    "is_deleted": true
  }
  ```

---

## 3.4 Synchronization Cursor & Pagination

#### `GET /api/v1/sync?since_cursor=0&limit=100`
- **Query Parameters**:
  - `since_cursor` (int, default 0): The client's last observed sync cursor. Returns all modifications with `sync_cursor > since_cursor`.
  - `limit` (int, default 100, max 500): Maximum records per batch.
- **Response 200 OK**:
  ```json
  {
    "items": [
      {
        "record_id": "rec-1",
        "ciphertext_payload": "...",
        "revision": 1,
        "sync_cursor": 1,
        "is_deleted": false,
        "created_at": "2026-10-11T00:40:00+00:00",
        "updated_at": "2026-10-11T00:40:00+00:00"
      },
      {
        "record_id": "rec-2",
        "ciphertext_payload": "",
        "revision": 2,
        "sync_cursor": 2,
        "is_deleted": true,
        "created_at": "2026-10-11T00:40:00+00:00",
        "updated_at": "2026-10-11T00:41:00+00:00"
      }
    ],
    "server_cursor": 2,
    "next_cursor": 2,
    "has_more": false
  }
  ```

---

## 4. Metadata Observable by the Server

Because VaultSync treats records as opaque encrypted blobs, the server cannot read vault contents. However, the server does observe:
1. **Account Metadata**: Username, registration timestamp, last active timestamp.
2. **Device Metadata**: Device name (e.g. "Pixel 8"), optional device UUID, IP address, and active session count.
3. **Record Metadata**: Client-generated record UUIDs, ciphertext byte sizes (bounded to 2 MiB), revision numbers, and modification timestamps.
4. **Traffic Timing**: Synchronization request frequency and polling intervals.
