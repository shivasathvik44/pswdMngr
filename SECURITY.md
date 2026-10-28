# Security Policy for VaultSync

## Security Philosophy

VaultSync is designed under a **Zero-Knowledge, Two-Credential, Defense-in-Depth** security philosophy:

1. **Zero-Knowledge Server**: The sync server receives and stores only opaque encrypted payloads (AES-256-GCM ciphertext), wrapped cryptographic keys, public salts, and minimal synchronization metadata. The server never receives, logs, or processes plaintext vault records or the Vault Master Passphrase.
2. **Two-Credential Separation**: The Account Password ($P_{\text{account}}$) authenticates the client session to the server, while the Vault Master Passphrase ($P_{\text{vault}}$) is never transmitted and strictly derives the Key Encryption Key (KEK) on client devices to unwrap the Vault Encryption Key (VEK).
3. **End-to-End Cryptography**: Cryptographic operations occur strictly on client devices (Android and Fedora Linux desktop). Key derivation utilizes Argon2id ($m=64\text{MB}, t=3, p=4$), and record encryption uses authenticated AES-256-GCM with item-bound Associated Authenticated Data (AAD).
4. **Private Transport by Design**: The backend server is designed to bind to local loopback (`127.0.0.1`) behind an authenticating TLS reverse proxy or an encrypted mesh overlay (such as Tailscale or WireGuard), precluding exposure of the raw application server to the public internet.
5. **No Custom Cryptography**: All cryptographic implementations strictly rely on standardized, vetted industry libraries (`cryptography`, `argon2-cffi`, `BouncyCastle`).

For comprehensive security architecture, dependency management, and deployment instructions, see [`docs/SECURITY_AND_DEPLOYMENT.md`](docs/SECURITY_AND_DEPLOYMENT.md), [`docs/security/dependency-management.md`](docs/security/dependency-management.md), and [`docs/threat-model.md`](docs/threat-model.md).

## Supported Versions

| Version | Supported | Notes |
| ------- | :---: | --- |
| 0.1.x   | :white_check_mark: | Current active release branch |

## Reporting a Vulnerability

We take the security of VaultSync seriously. If you discover a vulnerability or potential security risk:

1. **Do NOT open a public issue.**
2. Send an encrypted email or private security advisory describing:
   - Type of vulnerability (e.g., cryptographic flaw, sync replay, injection, memory disclosure).
   - Component affected (Server, Desktop, Android, Shared protocol).
   - Step-by-step reproduction instructions or proof-of-concept using synthetic credentials.
   - Potential impact and threat model context.
3. We will acknowledge receipt within 48 hours and work on a remediation before coordinated public disclosure.

## Security Practices for Development and Deployment

- **Synthetic Credentials Only**: Never commit live passwords, real recovery keys, production certificates, or database dumps to this repository.
- **Fail Closed**: Any cryptographic tampering, nonce reuse, or corrupted authentication tag must terminate decryption immediately.
- **Structured Logging**: Application logs must never contain user vault payloads, secrets, tokens, or plaintext metadata.
- **Production Secret Validation**: In production environments, `VAULTSYNC_SERVER_SECRET_KEY` must be at least 32 characters of high-entropy randomness, and insecure default keys or databases are rejected at startup.
- **Dependency Vulnerability Scanning**: Direct and transitive dependencies across backend, desktop, Android, and CI workflows are continuously audited. Scanner execution errors and expired vulnerability exceptions fail closed in CI.

## Dependency Monitoring & Vulnerability Remediation

VaultSync enforces explicit remediation targets upon confirmation of a vulnerability:

| Severity | Target SLA |
|---|---|
| **Critical** | Triage within 24 hours; mitigate or remediate within 72 hours |
| **High** | Triage within 3 business days; remediate within 7 calendar days |
| **Medium** | Triage within 14 calendar days; remediate within 30 calendar days |
| **Low** | Review within 30 calendar days; remediate within 90 calendar days |

Temporary risk acceptance is governed by the [Dependency Management & Exception Policy](docs/security/dependency-management.md). Exceptions require documented compensating controls, a named owner, a maximum 90-day time bound, and registration in [`docs/security/vulnerability-exceptions.json`](docs/security/vulnerability-exceptions.json). Expired exceptions automatically fail CI.
