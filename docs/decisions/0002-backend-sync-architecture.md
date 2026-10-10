# ADR 0002: Backend Persistence, Session Verification, and Synchronization Architecture

## Status
Accepted

## Context
Phase 3 requires establishing persistent storage, device sessions, and encrypted vault record synchronization while strictly maintaining the zero-knowledge security boundary established in Phases 1 and 2. The server must never receive the vault master password or plaintext vault encryption keys, and must prevent concurrent edit collisions and cross-account data leaks.

## Decision
1. **Credential Separation**:
   - The master password derives a Master Secret via Argon2id.
   - HKDF-Expand with `b"vaultsync:kek:v1"` derives the Key Encryption Key (client-only).
   - HKDF-Expand with `b"vaultsync:auth:v1"` derives the `auth_secret` sent to the server.
   - The server stores only an Argon2id hash of `auth_secret` (`auth_hash`), preventing server database breaches from revealing the vault encryption key.
2. **Session Verification via Token Hashing**:
   - Device login generates high-entropy URL-safe bearer tokens (`secrets.token_urlsafe(32)`).
   - Only the SHA-256 verifier (`token_hash`) is stored in the database.
   - Sessions are validated for expiration and revocation on every request.
3. **Database & Migrations**:
   - Implemented using SQLAlchemy 2.0 ORM with SQLite for development and compatibility with PostgreSQL.
   - Database schema is managed strictly via versioned Alembic migrations (`alembic/versions/`).
4. **Optimistic Concurrency Control**:
   - Record updates require matching `expected_revision`.
   - Stale updates return `409 Conflict`, preserving existing data and enabling client-driven conflict resolution.
5. **Incremental Synchronization & Tombstones**:
   - Deletions create tombstones (`is_deleted = true`) and immediately purge ciphertext payloads.
   - Account-level monotonic `sync_cursor` enables efficient resumption and pagination (`GET /api/v1/sync`).

## Consequences
- The server has zero visibility into vault contents or plaintext keys.
- Token theft from static database dumps is eliminated.
- Clients must handle HTTP 409 conflicts explicitly.
