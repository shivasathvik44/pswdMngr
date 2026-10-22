# VaultSync Release Readiness Checklist

This document tracks the verification status of VaultSync features, security controls, and operational readiness across all platform components.

Each item is categorized into one of five verification tiers:
- `[x]` **Verified by Automated Tests**: Validated by automated unit, integration, or end-to-end tests against real runtimes and ephemeral databases.
- `[s]` **Reviewed Statically**: Verified by source code, architecture, or configuration inspection; passing static checks without live runtime validation.
- `[ ]` **Requires Deployment Testing**: Requires operational deployment verification (e.g. reverse proxy, systemd, live TLS).
- `[ ]` **Requires Physical Android Testing**: Requires installation and testing on real physical Android hardware (biometrics, StrongBox, camera, Doze mode).
- `[ ]` **Not Implemented / Planned Future**: Features acknowledged as unbuilt or future roadmap items.

---

## 1. Cryptography & Security Boundaries

| Check / Requirement | Status | Verification Tier | Notes / Evidence |
|---|:---:|---|---|
| Two-Credential model separation ($P_{\text{account}}$ vs $P_{\text{vault}}$) | `[x]` | Verified by Automated Tests | 15 tests in `test_two_credentials.py` |
| Client-side Argon2id key derivation ($m=64\text{MB}, t=3, p=4$) | `[x]` | Verified by Automated Tests | Verified against golden vectors in `test_client_crypto.py` |
| AES-256-GCM record encryption with fresh 96-bit random IVs | `[x]` | Verified by Automated Tests | Verified in `test_client_crypto.py` and `test_cross_platform_android_interop.py` |
| Associated Authenticated Data (AAD) binding to `record_id` | `[x]` | Verified by Automated Tests | Tampered envelopes rejected in `test_cross_platform_android_interop.py` |
| Cross-platform Python <-> Kotlin crypto interoperability | `[x]` | Verified by Automated Tests | 8 tests in `test_cross_platform_android_interop.py` |
| Zero-knowledge server boundary (server never sees plaintext or master key) | `[x]` | Verified by Automated Tests | Verified across all backend integration tests |
| Client-side memory zeroization (`clear_key_material` via `ctypes.memset`) | `[x]` | Verified by Automated Tests | 8 tests in `test_desktop_security_phase5.py` |
| Synthetic salt derivation preventing username enumeration (SEC-02) | `[x]` | Verified by Automated Tests | Verified in `test_remediation_phase8_4_2.py` |
| Production secret validation fail-closed enforcement | `[x]` | Verified by Automated Tests | `Settings(environment="production")` fails closed if secret < 32 chars |
| Protected baseline DB decoupled from default dev startup | `[x]` | Verified by Automated Tests | `config.py` defaults to `vaultsync_dev.db`; rejects `vaultsync.db` in prod |
| Absence of committed secrets, private keys, or credentials | `[s]` | Reviewed Statically | Audited repository root, server, desktop, android, and shared |

---

## 2. Backend & Server Operations

| Check / Requirement | Status | Verification Tier | Notes / Evidence |
|---|:---:|---|---|
| Atomic sync cursor allocation and gapless rollback (SEC-01) | `[x]` | Verified by Automated Tests | Concurrent worker tests in `test_remediation_phase8_4_2.py` |
| Sliding-window authentication rate limiting (`auth_rate_limits` table) | `[x]` | Verified by Automated Tests | Verified with compound index in `test_remediation_phase8_4_3.py` |
| IPv6 client subnet normalization (`/64` aggregation) | `[x]` | Verified by Automated Tests | Prevents IPv6 rotating prefix abuse |
| Bearer session token hashing (SHA-256 verifier storage) | `[x]` | Verified by Automated Tests | Verified in `test_security_audit_phase5.py` |
| Immediate session revocation on logout | `[x]` | Verified by Automated Tests | Verified in `test_remediation_phase8_4_3.py` |
| Strict security headers (CSP, X-Frame-Options, X-Content-Type-Options) | `[x]` | Verified by Automated Tests | Verified in `test_security_audit_phase5.py` |
| HSTS emission gated on HTTPS or verified `trusted_proxies` | `[x]` | Verified by Automated Tests | Verified in `test_security_audit_phase5.py` |
| Max request payload limit enforcement (2 MiB) | `[x]` | Verified by Automated Tests | Verified in `test_security_audit_phase5.py` |
| Production reverse proxy TLS termination (Nginx / Caddy) | `[ ]` | Requires Deployment Testing | Requires live reverse proxy with TLS certificates |
| systemd service unit lifecycle & restart behavior | `[ ]` | Requires Deployment Testing | Requires execution under Linux init system |
| Database backup and recovery drill on live server | `[ ]` | Requires Deployment Testing | Follow runbook in `docs/recovery.md` |
| Periodic session cleanup cron job | `[ ]` | Requires Deployment Testing | Scheduled pruning of expired tokens |

---

## 3. Desktop Application (Fedora / PySide6)

| Check / Requirement | Status | Verification Tier | Notes / Evidence |
|---|:---:|---|---|
| Headless Qt UI navigation and screen lifecycle | `[x]` | Verified by Automated Tests | 19 tests in `test_ui_screens.py` |
| Desktop client <-> Live FastAPI backend integration | `[x]` | Verified by Automated Tests | 13 tests in `test_integration_backend.py` |
| Vault session lifecycle, search filtering, and CRUD operations | `[x]` | Verified by Automated Tests | 9 tests in `test_vault_session.py` |
| Desktop end-to-end usability and conflict handling | `[x]` | Verified by Automated Tests | 13 tests in `test_desktop_usability_phase6.py` |
| Inactivity auto-lock timer event filter | `[x]` | Verified by Automated Tests | Verified in `test_ui_screens.py` and `test_vault_session.py` |
| Clipboard auto-wipe with content match validation | `[x]` | Verified by Automated Tests | Verified in `test_ui_screens.py` |
| Masked secret fields with show/hide toggle and entropy meter | `[x]` | Verified by Automated Tests | Verified in `test_ui_screens.py` |
| OS Secret Service / GNOME Keyring token storage | `[s]` | Reviewed Statically | Fallback to memory verified; live keyring requires desktop session |
| Live Wayland / X11 interactive user session validation | `[ ]` | Requires Deployment Testing | Interactive manual verification on Fedora workstation |

---

## 4. Android Mobile Client (Kotlin / Compose)

| Check / Requirement | Status | Verification Tier | Notes / Evidence |
|---|:---:|---|---|
| Android API client compatibility with FastAPI routes & schemas | `[s]` | Reviewed Statically | Routes, models, and headers inspected in `ApiClient.kt` |
| Android Keystore AES-256-GCM token storage implementation | `[s]` | Reviewed Statically | Inspected in `KeyStoreManager.kt` |
| Room encrypted envelope schema and DAO queries | `[s]` | Reviewed Statically | Inspected in Room entities and `VaultDao.kt` |
| Network security configuration forbidding cleartext HTTP | `[s]` | Reviewed Statically | Inspected in `network_security_config.xml` |
| Staging APK compilation, ZIP integrity, and signature verification | `[x]` | Verified by Automated Tests | Phase 8.3.2 staging build verified (SHA-256 matching baseline) |
| Physical device installation & launch without ANR freezes | `[ ]` | Requires Physical Android Testing | DEFERRED: Requires physical Android phone |
| Hardware-backed BiometricPrompt (fingerprint / face unlock) | `[ ]` | Requires Physical Android Testing | DEFERRED: Requires physical Android biometric sensor |
| StrongBox TEE hardware key backing validation | `[ ]` | Requires Physical Android Testing | DEFERRED: Requires device with StrongBox hardware |
| Android Autofill framework integration in third-party apps | `[ ]` | Requires Physical Android Testing | DEFERRED: Autofill service requires OS integration |
| Background WorkManager synchronization under Android Doze mode | `[ ]` | Requires Physical Android Testing | DEFERRED: Requires battery optimization testing |

---

## 5. Unimplemented / Future Roadmap Items

| Feature / Capability | Status | Notes |
|---|:---:|---|
| Client-side offline encrypted backup export/import | `[ ]` | Planned Future (Phase 11+) |
| Emergency Recovery Phrase / Paper Key | `[ ]` | Irrecoverable by design; no recovery phrases implemented |
| Multi-region database active-active clustering | `[ ]` | Planned Future (Single-master SQLite/Postgres today) |
| Browser extensions (Firefox / Chrome) | `[ ]` | Planned Future |
| Hardware security key (FIDO2 / WebAuthn) support | `[ ]` | Planned Future |
