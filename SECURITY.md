# Security Policy for VaultSync

## Security Philosophy

VaultSync is designed under a **Zero-Knowledge, Defense-in-Depth** security philosophy:

1. **Zero Knowledge Server**: The sync server stores only encrypted payloads (ciphertext), wrapped cryptographic keys, and minimal synchronization metadata. The server never receives, logs, or processes plaintext vault contents or the master key.
2. **End-to-End Cryptography**: Cryptographic operations occur strictly on client devices (Android and Fedora Linux desktop). Key derivation utilizes Argon2id, and authenticated encryption uses audited constructions (AES-256-GCM / XChaCha20-Poly1305).
3. **Private Transport by Design**: The sync server is designed to bind to local loopback (`127.0.0.1`) and be accessed across machines via encrypted mesh overlays (such as Tailscale or WireGuard), precluding exposure to the public internet.
4. **No Custom Cryptography**: All cryptographic implementations strictly rely on vetted, standardized industry libraries.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of VaultSync seriously. If you discover a vulnerability or potential security risk:

1. **Do NOT open a public issue.**
2. Send an encrypted email or private security advisory describing:
   - Type of vulnerability (e.g., cryptographic flaw, sync replay, injection).
   - Component affected (Server, Desktop, Android, Shared protocol).
   - Step-by-step reproduction instructions or proof-of-concept.
   - Potential impact.
3. We will acknowledge receipt within 48 hours and work on a remediation before coordinated public disclosure.

## Security Practices for Development and Deployment

- **Synthetic Credentials Only**: Never commit live passwords, real recovery keys, production certificates, or database dumps to this repository.
- **Structured Logging**: Application logs must never contain user vault payloads, secrets, tokens, or plaintext metadata.
- **Fail Closed**: Any cryptographic tampering, nonce reuse, or corrupted authentication tag must result in immediate decryption termination and security alerting.
