# Shared Cryptographic Test Vectors

This directory will store golden cross-language test vectors (JSON) generated in Phase 2 to verify cryptographic interoperability between the Python cryptography engine and the Kotlin Android crypto engine:
- Argon2id key derivation inputs and expected derived KEKs.
- AEAD (AES-256-GCM / XChaCha20-Poly1305) plaintexts, keys, nonces, AAD, and resulting ciphertexts.
- Malformed and corrupted ciphertext fixtures for negative security testing.
