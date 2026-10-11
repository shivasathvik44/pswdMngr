# VaultSync

> **Status:** Under active development. VaultSync is a personal password manager for securely storing and synchronizing credentials across trusted devices.

[![Tests](https://github.com/vaultsync/vaultsync/actions/workflows/tests.yml/badge.svg)](https://github.com/vaultsync/vaultsync/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)

**VaultSync** is an open-source, self-hosted, end-to-end encrypted personal password manager that synchronizes an Android mobile device and a Fedora Linux desktop over a private VPN (Tailscale or WireGuard) — with zero reliance on commercial cloud platforms or Docker containers.

---

## Key Highlights

- **Zero-Knowledge Security**: The server stores only ciphertext blobs, user salts, and wrapped cryptographic keys. Master passwords and vault contents are never exposed to the server or network.
- **Two-Credential Architecture**: Complete mathematical separation between the server Account Password ($P_{\text{account}}$) and client Vault Master Password ($P_{\text{vault}}$). Server authentication tables contain zero master password verifiers, ensuring account compromise never reveals vault keys.
- **Private Mesh Connectivity**: Designed specifically for private network overlays (Tailscale or WireGuard) with secure loopback/VPN bindings (`127.0.0.1`).
- **Offline-First Synchronization**: Full offline read/write access with version cursors, optimistic concurrency conflict detection, and deletion tombstones.
- **Session Protection**: Bearer tokens are stored in the database strictly as SHA-256 verifier hashes, preventing session hijacking from static database dumps.
- **Abuse Control**: Dual-axis rate limiting across IP addresses and usernames, backed by database tracking for multi-worker support.
- **Native Dual Clients**:
  - **Fedora Linux Desktop**: Fast, responsive GUI written in Python and PySide6 with auto-lock and secure memory management.
  - **Android Mobile**: Native Kotlin application with Jetpack Compose, Android Keystore protection, biometric unlock, and native Android Autofill integration.
- **Audited Cryptographic Primitives**: Standardized Argon2id key derivation and AES-256-GCM authenticated encryption.
- **Transparent & Self-Hosted**: Operates directly on standard Linux distributions without requiring Docker or third-party cloud infrastructure.

---

## Repository Structure

```
vaultsync/
├── README.md                 # Project overview and instructions
├── SECURITY.md               # Security policy and vulnerability disclosure
├── CONTRIBUTING.md           # Contribution guidelines and standards
├── LICENSE                   # MIT License
├── .gitignore                # Git ignore rules for secrets, DBs, and builds
├── docs/                     # Architectural and security documentation
│   ├── architecture.md       # System design, ER diagrams, and Mermaid flows
│   ├── threat-model.md       # Comprehensive threat modeling
│   ├── cryptography.md       # Protocol specification and cryptographic algorithms
│   ├── api-spec.md           # Complete sync API specification
│   ├── recovery.md           # Backup and disaster recovery procedures
│   └── decisions/            # Architecture Decision Records (ADRs)
├── server/                   # FastAPI backend synchronization service
│   ├── alembic.ini           # Database migration configuration
│   ├── alembic/              # Versioned database migration scripts
│   ├── pyproject.toml        # Backend dependencies and metadata
│   ├── src/vaultsync_server/ # Server application source (API, Crypto, DB, Services)
│   └── tests/                # Automated pytest suite (Crypto, Health, Backend, Two-Credential)
├── desktop/                  # Fedora desktop client (PySide6)
│   ├── pyproject.toml        # Desktop client dependencies
│   ├── src/vaultsync_desktop/# Desktop GUI application source
│   └── tests/                # Desktop client tests
├── android/                  # Android mobile client (Kotlin / Jetpack Compose)
│   ├── settings.gradle.kts   # Gradle settings
│   └── app/                  # Android application module
├── shared/                   # Cross-platform shared definitions
│   ├── api-schema/           # Canonical API schemas
│   └── test-vectors/         # Cross-language cryptographic test vectors & Kotlin spec
└── .github/                  # GitHub Actions CI/CD workflows
    └── workflows/
        └── tests.yml         # Automated CI test runner
```

---

## Quick Start (Backend and Migrations)

### Prerequisites

- Linux (Fedora 39+ recommended)
- Python 3.12+ (tested on Python 3.14)
- Git

### Installation & Environment Setup

```bash
# Clone repository
git clone https://github.com/vaultsync/vaultsync.git
cd vaultsync

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and server package
pip install -e "server[dev]"
```

### Database Migrations

Apply database schema migrations via Alembic:

```bash
alembic -c server/alembic.ini upgrade head
```

### Administrative Account Reset and Migration

To reset an account password or migrate a legacy account without touching vault contents:

```bash
# Interactive mode (prompts for new password with confirmation):
python -m vaultsync_server.scripts.admin_reset --username alice

# Automation / piped mode:
echo -n "NewSecurePassword2026!" | python -m vaultsync_server.scripts.admin_reset --username alice --password-stdin
```

### Running the Automated Test Suite

```bash
# Run all tests (Crypto, Health, Database, Sync, Rate Limiting, Two-Credential)
pytest server/tests -v
```

### Starting the Local Development Server

```bash
# Start backend strictly on 127.0.0.1:8000
python3 -m uvicorn vaultsync_server.main:app --host 127.0.0.1 --port 8000
```

Verify service health:
```bash
curl -s http://127.0.0.1:8000/health
# Output: {"status":"ok","version":"0.1.0","environment":"development","timestamp":"..."}
```

---

## Project Roadmap

- [x] **Phase 1: Foundation**: Repository setup, FastAPI health API, automated tests, architecture design, and threat model.
- [x] **Phase 2: Cryptographic Prototype**: Key wrapping, Argon2id derivation, authenticated encryption, and cross-language test vectors.
- [x] **Phase 3: Secure Backend Synchronization**: Database persistence (SQLAlchemy/Alembic), session verification, optimistic concurrency control, and tombstone synchronization.
- [x] **Phase 3.1: Security Review**: Offline master-password cracking vulnerability proof, dual-axis rate limiting, and sync transaction boundaries.
- [x] **Phase 3.2: Two-Credential Security Migration**: Complete credential separation ($P_{\text{account}}$ vs $P_{\text{vault}}$), Alembic migration 0002, password change and admin recovery, and 100% security regression testing.
- [ ] **Phase 4: Fedora Desktop Client**: PySide6 GUI, local encrypted cache, password generator, and sync worker.
- [ ] **Phase 5: Android Mobile Client**: Compose UI, Android Keystore, biometric authentication, Room DB, and Autofill service.
- [ ] **Phase 6: Integration & Hardening**: End-to-end sync over Tailscale/WireGuard, systemd hardening, backup/restore verification, and security verification.
