# VaultSync Cryptographic Protocol Specification

Status: **Design Draft (Scheduled for Phase 2 Implementation)**

---

## 1. Cryptographic Primitives

- **Key Derivation Function (KDF)**: Argon2id (RFC 9106)
  - Memory Cost: 64 MiB ($m = 65536$)
  - Time Cost: 3 iterations ($t = 3$)
  - Parallelism: 4 lanes ($p = 4$)
  - Salt: Cryptographically secure random 16 bytes ($128$ bits minimum)
- **Authenticated Encryption with Associated Data (AEAD)**: AES-256-GCM or XChaCha20-Poly1305
  - Key Size: 256 bits (32 bytes)
  - Nonce: Unique 96-bit (AES-GCM) or 192-bit (XChaCha20-Poly1305) randomly generated per encryption operation. Nonces must never be repeated.
  - Tag: 128-bit authentication tag.

---

## 2. Key Hierarchy

```
Master Password (User)
       │
       ├───> [Argon2id + Salt_enc] ───> Key Encryption Key (KEK, 256-bit)
       │                                     │
       │                                     ▼ [AEAD Encrypt]
       │                                Wrapped Vault Encryption Key (WVEK)
       │                                     ▲
       │                                     │ [Random CSPRNG]
       │                                Vault Encryption Key (VEK, 256-bit)
       │                                     │
       │                                     ▼ [AEAD Encrypt]
       │                                Vault Record Ciphertexts
       │
       └───> [Argon2id + Salt_auth] ──> Server Authentication Key / Hash
```

1. **Vault Encryption Key (VEK)**: Generated once per vault using a cryptographically secure random number generator (`os.urandom(32)` / `SecureRandom`).
2. **Key Encryption Key (KEK)**: Derived locally on each unlock. Used solely to wrap and unwrap the VEK.
3. **Server Authentication Hash**: Derived with an independent salt so that a server database breach does not assist offline cracking of vault ciphertexts.

---

## 3. Wire Format for Encrypted Records (Draft)

Encrypted records will use a versioned binary or JSON envelope:

```json
{
  "version": 1,
  "record_id": "uuid4-string",
  "nonce": "base64-encoded-nonce",
  "ciphertext": "base64-encoded-ciphertext-and-tag",
  "associated_data": "base64-encoded-aad"
}
```

*Detailed test vectors and protocol tests will be implemented in Phase 2.*
