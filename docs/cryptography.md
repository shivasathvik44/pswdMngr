# VaultSync Cryptographic Protocol Specification

Version: `1.0.0` (Phase 2 Prototype)  
Status: **Active Protocol Specification**

---

## 1. Cryptographic Primitives and Constants

| Primitive | Specification | Rationale & Parameter Constraints |
| :--- | :--- | :--- |
| **KDF** | Argon2id (RFC 9106) | Hybrid mode resistant to both GPU/ASIC trade-offs and side-channel timing attacks. Memory: 64 MiB ($65,536$ KiB), Iterations ($t$): 3, Parallelism ($p$): 4. |
| **Salt** | 16 bytes (128 bits) CSPRNG | Generated uniquely per user/vault via OS cryptographically secure random source (`os.urandom(16)`). |
| **Domain Separation** | HKDF-SHA256 (RFC 5869) | Derives independent cryptographic keys from the single Argon2id master secret using distinct context labels. |
| **AEAD Cipher** | AES-256-GCM | NIST-approved authenticated encryption providing confidentiality and integrity with hardware acceleration across x86_64 and ARM64. |
| **Cipher Key Size** | 256 bits (32 bytes) | Cryptographically secure random generation (`os.urandom(32)`). |
| **Nonce (IV)** | 96 bits (12 bytes) CSPRNG | Freshly generated via CSPRNG per encryption operation. Nonces are never repeated for a given key. |
| **Authentication Tag** | 128 bits (16 bytes) | Appended directly to ciphertext; verified in constant time by the AEAD primitive before any plaintext is returned. |

---

## 2. Master Password Normalization and Handling

- **Normalization**: To ensure consistency across different operating systems, keyboards, and input methods, passwords must be normalized to **Unicode Normalization Form C (NFC)** using standard Unicode normalization:
  $$\text{normalized\_password} = \text{unicodedata.normalize}('NFC', \text{password})$$
- **Encoding**: Normalized strings are encoded strictly as **UTF-8** byte sequences.
- **Constraints**:
  - Minimum length: 8 characters (clients recommend $\ge 14$ characters).
  - Maximum length: 1,024 characters (defensive bound against algorithmic complexity / denial of service).
- **Prohibitions**: The master password is never transmitted across the network, never written to disk, never included in logs or telemetry, and never used directly as an encryption key.

---

## 3. Two-Credential Security Architecture

To eliminate offline dictionary attacks against the vault master password in the event of a server database compromise, VaultSync enforces complete cryptographic credential separation between server account authentication and client-side vault encryption:

```
[CREDENTIAL 1: SERVER AUTHENTICATION]
Client Account Password (P_account)
         │  (Sent over authenticated TLS)
         ▼
FastAPI Backend Server
         │
         ▼
Argon2id Hash (account_password_hash stored in Database)
(Never derived from or related to the Vault Master Password)


[CREDENTIAL 2: CLIENT-SIDE VAULT ENCRYPTION]
Client Vault Master Password (P_vault)
         │  (NEVER sent to the server under any circumstance)
         ▼
Argon2id (Public Salt, m=65536, t=3, p=4, len=32)
         │
         ▼
Key Encryption Key (KEK, 32B via HKDF-Expand info="vaultsync:kek:v1")
         │
         ▼ [AES-256-GCM Encrypt with AAD]
Wrapped Vault Encryption Key (WVEK Envelope stored on server)
         ▲
         │
Vault Encryption Key (VEK, 32B CSPRNG, client memory only)
         │
         ▼ [AES-256-GCM Encrypt with Record AAD]
Encrypted Record Envelopes (Ciphertext + 16B Tag stored on server)
```

### Security Properties of Credential Separation:
1. **Zero Server Knowledge of Master Password**: The server never receives $P_{\text{vault}}$, the KEK, or the unencrypted VEK.
2. **Zero Verifiers in Authentication Tables**: The server database stores no hash or verifier computed from $P_{\text{vault}}$ in any authentication table. The server authenticates users solely via $P_{\text{account}}$ and `account_password_hash`.
3. **Account Password Compromise Isolation**: An attacker who compromises the server, intercepts network traffic, or recovers $P_{\text{account}}$ gains zero information about $P_{\text{vault}}$ and cannot unwrap the vault encryption key.
4. **Offline Master-Password Guessing Reality & Boundaries**:
   - A stolen database dump containing `wrapped_vault_key` and `kdf_salt` **does permit offline master-password guessing**.
   - Specifically, `wrapped_vault_key` contains an AES-256-GCM ciphertext and a 16-byte authentication tag. This authentication tag **inherently acts as an offline verification oracle**: candidate master passwords can be derived through Argon2id and tested against `unwrap_vault_key()`. Decryption fails with `InvalidTag` for incorrect guesses and succeeds for the true password.
   - **Protection Boundary**: The Two-Credential architecture does *not* prevent offline guessing on `wrapped_vault_key` from a full database dump; rather, protection against offline dictionary attacks relies entirely on the memory-hard work factor of Argon2id ($64\text{ MiB}, t=3, p=4$ in production, RFC 9106) and client-enforced passphrase entropy.
5. **Historical Note (Phase 3.1 Review)**: In the legacy Phase 3 prototype, `auth_secret` was derived from $P_{\text{vault}}$ using HKDF (`auth_secret = HKDF-Expand(Argon2id(P_vault, salt), "vaultsync:auth:v1")`) and stored as `auth_hash = Argon2id(auth_secret)`. As proved in Phase 3.1, this provided an attacker with an online/offline server authentication verification oracle directly tied to the master password. That approach was formally deprecated and replaced by the Two-Credential architecture in Phase 3.2.

---

## 4. Vault Encryption Key (VEK) Lifecycle

1. **Generation**: Generated on the client device during initial vault creation using a 256-bit CSPRNG (`os.urandom(32)`).
2. **Wrapping**: Wrapped by the KEK using AES-256-GCM.
   - **Associated Data (AAD)**: Deterministically computed as:
     `b"vaultsync:key-wrap:v1:" + str(version).encode("utf-8") + b":" + kdf_algorithm.encode("utf-8")`
   - Nonce: Unique 12 bytes.
3. **Unwrapping**:
   - Vault master password is entered by the user on the client device.
   - KEK is derived via Argon2id + HKDF-SHA256 using the envelope's salt and parameters.
   - AES-256-GCM verifies the 16-byte authentication tag against the wrapped key ciphertext and the deterministic AAD.
   - If verification succeeds, the 32-byte VEK is loaded into volatile client memory. If verification fails, a generic `DecryptionFailedError` is raised.
4. **Vault Master Password Rotation (`PUT /api/v1/auth/vault-key`)**:
   - Handled entirely on the client without modifying encrypted vault records.
   - A fresh public salt is generated. A new KEK is derived from the new master password.
   - The existing VEK is re-wrapped with the new KEK, creating a new `WrappedKeyEnvelope`.
   - The client uploads the new `WrappedKeyEnvelope` and fresh `kdf_salt` to `PUT /api/v1/auth/vault-key`.
   - Existing encrypted records remain completely decryptable with the new master password because the underlying 256-bit VEK is preserved.
   - The account password and server `account_password_hash` are unaffected.
5. **Vault Key Rotation**:
   - A new VEK is generated on the client.
   - All existing vault items are decrypted with the old VEK and re-encrypted with the new VEK.
   - The new VEK is wrapped with the current KEK and committed to the server.

---

## 5. Serialized Envelopes Specification

All encrypted envelopes are serialized as canonical JSON structures with Base64 encoding (RFC 4648 without line breaks) for binary byte arrays.

### 5.1 Wrapped Vault Key Envelope (`WrappedKeyEnvelope`)

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": {
    "algorithm": "Argon2id",
    "memory_cost": 65536,
    "time_cost": 3,
    "parallelism": 4,
    "salt": "<Base64 encoded 16-byte salt>"
  },
  "nonce": "<Base64 encoded 12-byte nonce>",
  "ciphertext": "<Base64 encoded 32-byte VEK ciphertext + 16-byte tag (48 bytes total)>"
}
```

### 5.2 Encrypted Record Envelope (`EncryptedRecordEnvelope`)

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "record_id": "<UUIDv4 string>",
  "nonce": "<Base64 encoded 12-byte nonce>",
  "ciphertext": "<Base64 encoded plaintext ciphertext + 16-byte tag>"
}
```

### 5.3 Authenticated Associated Data (AAD) Binding

To prevent **ciphertext relocation attacks** (where an attacker moves ciphertext from one record to another without decrypting it):
- Record encryption strictly binds the `record_id` and protocol version into the AEAD Associated Data:
  $$\text{AAD}_{\text{record}} = \text{b"vaultsync:record:v1:"} \mathbin{\Vert} \text{record\_id.encode('utf-8')}$$
- Decryption calculates $\text{AAD}_{\text{record}}$ from the envelope's `record_id`. If an adversary alters the `record_id` or swaps ciphertexts, the authentication tag verification fails.

---

## 6. Defensive Bounds and Validation Rules

Before initiating computationally intensive KDF or cryptographic allocations, inputs are validated against strict defensive bounds:

| Property | Minimum | Maximum | Defensive Rationale |
| :--- | :--- | :--- | :--- |
| **Version** | `1` | `1` | Strictly reject unsupported/unknown protocol versions. |
| **Algorithm** | `"AES-256-GCM"` | `"AES-256-GCM"` | Prevent downgrade or unexpected cipher fallback. |
| **KDF Algorithm** | `"Argon2id"` | `"Argon2id"` | Prevent unsupported KDF selection. |
| **Argon2 Memory** | $16,384$ KiB (16 MiB) | $524,288$ KiB (512 MiB) | Prevent memory exhaustion DoS while guaranteeing strength. |
| **Argon2 Iterations**| $1$ | $10$ | Prevent CPU starvation DoS. |
| **Argon2 Parallelism**| $1$ | $16$ | Bound thread allocations. |
| **Salt Length** | $16$ bytes | $16$ bytes | Reject short or oversized salts. |
| **Nonce Length** | $12$ bytes | $12$ bytes | Exactly 96 bits for standard AES-GCM. |
| **Tag Length** | $16$ bytes | $16$ bytes | Appended to ciphertext (minimum ciphertext length = 16 bytes). |
| **Record Plaintext Size** | $1$ byte | $1,048,576$ bytes (1 MiB) | Bound maximum record size to prevent memory bloat. |

---

## 7. Error Handling and Side-Channel Protection

- **Unified Failure Classes**: All cryptographic errors inherit from `CryptoError`.
- **Indistinguishable Decryption Failures**: When unwrapping a key or decrypting a record, invalid tags, bad nonces, altered AAD, or incorrect passwords all produce `DecryptionFailedError`. The system never reveals whether the failure was due to an incorrect password, modified ciphertext, or corrupted tag.
- **Safe Diagnostics**: Classes holding key material implement custom `__repr__` and `__str__` returning redacted placeholders (`<VaultKey: [REDACTED]>`).
- **No Secret Leakage**: Exception messages contain generic structural information and never log passwords, keys, or plaintext data.

---

## 8. Memory Security Limitations in Python

Python is a high-level language with automatic garbage collection and immutable strings. When building secure applications in Python, the following inherent limitations are documented:
1. **String Immutability**: In CPython, `str` and `bytes` objects are immutable. Once created in memory, they cannot be explicitly overwritten in user-space Python and persist until garbage collected.
2. **Memory Compaction & Copies**: CPython's memory allocator (`pymalloc`) and garbage collector may duplicate or move memory pages containing secrets without zeroization.
3. **Mitigations in VaultSync**:
   - Wherever raw mutable buffers are managed, `bytearray` instances are explicitly cleared via `bytearray.clear()` or zero-filled after use.
   - Plaintext records and derived keys are only held in memory during the unlocked session duration.
   - For high-assurance environments, OS-level protections (e.g. swap disablement / `mlock` where available, full-disk encryption like LUKS) are recommended.

---

## 9. Migration and Future Protocol Versioning

- Each envelope includes an explicit `version` integer (starting at `1`).
- When introducing a new cipher (e.g., Post-Quantum hybrid KDF or XChaCha20-Poly1305), a new version number (e.g., `2`) will be specified.
- Clients will support reading version $N$ and $N+1$, performing rolling re-encryption during normal unlock cycles.
