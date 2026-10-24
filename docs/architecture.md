# VaultSync Architecture

VaultSync is a self-hosted, end-to-end encrypted password management ecosystem built for seamless, private synchronization between an Android mobile device and a Fedora Linux desktop workstation over a private VPN mesh (Tailscale or WireGuard).

```mermaid
flowchart TD
    subgraph ClientFedora["Fedora Desktop Client (PySide6 / Python)"]
        FedoraUI["Desktop GUI (PySide6)"]
        FedoraCrypto["Client Crypto Engine (Argon2id + AES-256-GCM)"]
        FedoraStore["Local Encrypted SQLite Cache"]
        FedoraSync["Sync Engine (HTTPX)"]
        FedoraUI --> FedoraCrypto
        FedoraCrypto --> FedoraStore
        FedoraCrypto --> FedoraSync
    end

    subgraph ClientAndroid["Android Mobile Client (Kotlin / Compose)"]
        AndroidUI["Jetpack Compose UI & Autofill Service"]
        AndroidCrypto["Client Crypto Engine (Android Keystore + Argon2id + AES-256-GCM)"]
        AndroidStore["Local Encrypted Room Database"]
        AndroidSync["Sync Worker (WorkManager + Retrofit/OkHttp)"]
        AndroidUI --> AndroidCrypto
        AndroidCrypto --> AndroidStore
        AndroidCrypto --> AndroidSync
    end

    subgraph PrivateNetwork["Encrypted Overlay Network (Tailscale / WireGuard)"]
        direction LR
        VPN["Encrypted WireGuard / Tailscale Tunnel"]
    end

    subgraph Server["VaultSync Backend Server (FastAPI / Python)"]
        ServerAPI["FastAPI API Gateway (127.0.0.1 / VPN Interface)"]
        AuthModule["Server Authentication & Session Tracker"]
        SyncModule["Zero-Knowledge Sync & Conflict Resolver"]
        ServerDB["Storage Engine (SQLite / PostgreSQL)<br/>(Encrypted Blobs Only)"]
        
        ServerAPI --> AuthModule
        ServerAPI --> SyncModule
        SyncModule --> ServerDB
    end

    FedoraSync <-->|E2EE HTTPS over VPN| VPN
    AndroidSync <-->|E2EE HTTPS over VPN| VPN
    VPN <--> ServerAPI
```

---

## Core Architectural Pillars

### 1. Zero-Knowledge Cryptographic Model & Two-Credential Architecture
The backend synchronization server operates strictly on a **zero-knowledge principle** with complete credential separation:
- **Account Password ($P_{\text{account}}$)**: Sent over TLS to authenticate against the server API; verified against a server-side Argon2id hash (`account_password_hash`). Never used in vault key derivation.
- **Vault Master Password ($P_{\text{vault}}$)**: Exists strictly on client devices and is **never** transmitted across the network under any circumstance.
- **Vault Encryption Key (VEK)**: A 256-bit symmetric key generated randomly on client initialization. The VEK encrypts all vault items.
- **Key-Encryption Key (KEK)**: Derived locally from the master password using Argon2id ($64\text{ MiB}, t=3, p=4$) with a unique per-user salt. The KEK wraps (encrypts) the VEK using authenticated encryption (AES-256-GCM).
- **Server Storage**: The server stores only the user's public salt, the wrapped VEK ciphertext (`WrappedKeyEnvelope`), and opaque encrypted record payloads.

### 2. Private Network Mesh Transport
Rather than exposing the sync API to the public internet or relying on commercial third-party cloud hosting:
- The server binds locally to loopback or a virtual network interface (WireGuard / Tailscale IP).
- Device-to-device communication traverses an authenticated, encrypted VPN mesh.
- Host firewall rules (`nftables`/`firewalld`) enforce isolation, permitting traffic exclusively through the VPN interface.

### 3. Offline-First Synchronization & Conflict Resolution
Clients maintain an active local replica of encrypted items:
- Full offline read and write capabilities.
- Local mutations append to an offline change log.
- Upon connectivity restoration, sync workers exchange changes using **version cursors** and **tombstones** for deleted records.
- If two devices modify the same record concurrently, deterministic conflict detection creates a conflict branch or prompts the user, preventing silent data loss.

### 4. Cross-Platform Interoperability
- A canonical, versioned record schema and wire protocol ensure perfect cryptographic parity between Python (desktop) and Kotlin (Android).
- Standardized test vectors guarantee that records encrypted on Android can be decrypted on Linux and vice versa.

---

## Backend Persistence and Database Architecture (Phase 3.2)

The backend persistence layer is built with **SQLAlchemy 2.0** and versioned using **Alembic** migrations. It supports SQLite for local development and can be pointed to PostgreSQL in multi-user deployments.

```mermaid
erDiagram
    ACCOUNTS ||--o{ SESSIONS : "owns"
    ACCOUNTS ||--o{ ENCRYPTED_RECORDS : "owns"

    ACCOUNTS {
        UUID id PK
        string username UK
        string account_password_hash
        string kdf_salt
        text wrapped_vault_key
        bigint sync_cursor
        boolean is_active
        boolean requires_password_migration
        datetime created_at
        datetime updated_at
    }

    SESSIONS {
        UUID id PK
        UUID account_id FK
        string device_name
        string device_id
        string token_hash UK
        datetime created_at
        datetime expires_at
        datetime revoked_at
        datetime last_used_at
    }

    ENCRYPTED_RECORDS {
        UUID id PK
        string record_id
        UUID account_id FK
        text ciphertext_payload
        integer revision
        bigint sync_cursor
        boolean is_deleted
        datetime created_at
        datetime updated_at
    }

    AUTH_RATE_LIMITS {
        int id PK
        string identifier
        float attempt_time
    }
```

### 1. Account Entity (`accounts`)
- Stores account identity, the server-side Argon2id hash of `account_password`, the public KDF salt, and the wrapped vault key envelope.
- Tracks `vault_key_version` to enforce version locking and step-up auth on key envelope replacements.
- Manages an account-level monotonic `sync_cursor` incremented on every record mutation.
- Tracks `requires_password_migration` flag for legacy accounts.

### 2. Session Entity (`sessions`)
- Represents an active device session.
- **Security Control**: Only stores `token_hash = SHA-256(raw_bearer_token)`. The plaintext token exists only on the client device.
- Validates expiration (`expires_at`) and revocation (`revoked_at`) on every request.

### 3. Encrypted Records Entity (`encrypted_records`)
- Stores client-encrypted `EncryptedRecordEnvelope` JSON blobs.
- Enforces multi-tenant isolation via compound unique constraint `(account_id, record_id)`.
- **Atomic Optimistic Concurrency**: Enforces database-level conditional updates using `expected_revision`. Competing writes are rejected atomically without cursor drift.
- **Tombstones & Latest-State Synchronization**: Record deletions set `is_deleted = true`, purge `ciphertext_payload = ""`, and increment `revision` and `sync_cursor`. VaultSync provides a **latest-state synchronization model**, NOT an immutable event history or point-in-time recovery ledger; previous record states are overwritten.

---

## Desktop Client Architecture (Phase 4)

The Fedora Linux desktop client is implemented in Python 3.12+ and PySide6 (Qt 6.12+), adhering strictly to zero-knowledge guarantees:

```mermaid
flowchart TD
    subgraph GUI["PySide6 UI Thread (Main)"]
        MainWindow["MainWindow (Navigation & ActivityFilter)"]
        Screens["Screens (Server, Register, Login, Vault, Settings)"]
        Widgets["Widgets (PasswordEdit, PassphraseStrengthBar)"]
        MainWindow --> Screens
        Screens --> Widgets
    end

    subgraph AsyncBridge["Async Bridge (Dedicated Worker Thread)"]
        Dispatcher["AsyncDispatcher (Dedicated asyncio loop)"]
        APICall["vaultsync_desktop.api_client.ApiClient"]
    end

    subgraph Core["Local Core & Security"]
        Session["VaultSession (In-Memory Key & Records)"]
        Crypto["vaultsync_desktop.crypto (Argon2id + AES-256-GCM)"]
        Keyring["TokenStorage (FreeDesktop Secret Service / Keyring)"]
        Config["AppConfig (~/.config/vaultsync/config.json)"]
    end

    subgraph Backend["Remote/Local Backend"]
        FastAPI["VaultSync FastAPI Backend (Loopback or HTTPS)"]
    end

    MainWindow -->|User Actions| Session
    Session -->|Async Tasks| Dispatcher
    Dispatcher -->|Network IO| APICall
    APICall -->|HTTPX Client| FastAPI
    Session -->|Key Derivation / Decryption| Crypto
    Session -->|Session Token Storage| Keyring
    MainWindow -->|Preferences| Config
    Dispatcher -.->|Qt Signals (sig_success, sig_error)| GUI
```

### Key Components

1. **`AsyncDispatcher` & Non-blocking GUI Execution**:
   - Heavy network I/O and CPU-bound Argon2id operations run off the Qt GUI thread using a dedicated background asyncio thread.
   - Qt signals (`sig_success`, `sig_error`, `sig_finally`) marshal results back to the main thread, keeping the desktop UI responsive at 60 FPS without frame drops.

2. **Session & Token Storage (`TokenStorage`)**:
   - Session tokens are stored in the FreeDesktop Secret Service / GNOME Keyring via Python `keyring` (`service_name="vaultsync"`).
   - If no system keyring service is detected, fallback to volatile memory occurs with an explicit user notification.

3. **Inactivity Monitoring & Auto-Lock**:
   - `MainWindow` installs an application-level `ActivityFilter` intercepting all mouse and keyboard events.
   - A timer periodically monitors inactivity. If idle duration exceeds the configured timeout (default: 5 minutes), `VaultSession.lock()` is triggered automatically.

4. **Key Zeroization & Memory Limitations**:
   - On vault lock, the raw 256-bit VEK and decrypted plaintext records are zeroed out in memory via `ctypes.memset` / `bytearray` zeroization.
   - Python runtime memory limitations (garbage collection copies, immutable string internals) are explicitly documented; users requiring kernel-enforced memory bounds are guided accordingly.
