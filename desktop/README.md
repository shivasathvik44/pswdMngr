# VaultSync Desktop Client

Native Linux desktop client for **VaultSync**, built with Python 3.12+ and PySide6 (Qt for Python). Optimized for Fedora Workstation (GNOME) and Wayland/X11 compositors (including Hyprland).

---

## Security Architecture & Guarantees

The VaultSync desktop client implements zero-knowledge, end-to-end encrypted synchronization adhering strictly to the VaultSync Two-Credential specification.

### 1. Two-Credential Isolation
- **Account Password ($P_{\text{account}}$)**:
  - Transmitted to the server solely over TLS (or loopback HTTP during development) to authenticate session tokens (`/auth/login`, `/auth/register`).
  - Never used to derive encryption keys.
- **Vault Master Password ($P_{\text{vault}}$)**:
  - **Never leaves the desktop client**. It is never transmitted across the network, never stored in configuration files, and never logged.
  - Used strictly client-side to derive the Key Encryption Key (KEK) using Argon2id ($m=64\text{ MiB}, t=3, p=4$) and HKDF.
  - Used to unwrap the 256-bit random Vault Encryption Key (VEK).

### 2. Transport & URL Security
- **Loopback HTTP**: Allowed strictly for `127.0.0.1` and `localhost` (to support local development and point-to-point WireGuard/Tailscale localhost port forwards).
- **Remote HTTPS**: Enforced for all non-loopback addresses. Attempting to connect to an unencrypted remote HTTP address raises an explicit `ValidationError` before any socket connection is attempted.

### 3. Session & Key Management
- **Session Token Persistence**: Stored securely in the OS Secret Service / GNOME Keyring via Python `keyring` (`service_name="vaultsync"`). If the system Secret Service daemon is unavailable, the client falls back to volatile in-memory storage with an explicit warning.
- **Auto-Lock & Inactivity Timer**: The application monitors user interaction (mouse movements, key presses) via a Qt `QObject` event filter (`ActivityFilter`). After the configured inactivity period (default: 5 minutes), the vault automatically locks.
- **Memory Security Disclosures**:
  - Upon vault locking or logout, decrypted records and VEK byte buffers are wiped using `clear_key_material()` (`ctypes.memset`).
  - *Limitation*: As a Python runtime application, immutable strings, intermediate bytecode representations, and garbage collector movement may leave residual traces in unzeroed process memory. Users requiring absolute memory zeroization guarantees must use OS-level memory encryption or dedicated C/Rust binaries.

### 4. Passphrase Strength & Offline Cracking Awareness
- Interactive passphrase strength meter calculates Shannon entropy and estimates crack resistance.
- Emphasizes multi-word passphrases (Diceware style, 4+ words, $\ge 60$ bits entropy).
- Warns users that an attacker with access to the server database obtains the public KDF salt and wrapped VEK ciphertext, enabling offline dictionary attacks against weak master passwords.

---

## Installation & Setup on Fedora Linux

### Prerequisites
- Fedora 39+ (Workstation / GNOME or Hyprland)
- Python 3.12+ (tested through Python 3.14)
- System libraries:
  ```bash
  sudo dnf install -y python3-devel libxcb xcb-util-cursor
  ```

### Virtual Environment Setup

From the repository root (`/home/capslock/PDMG`):

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install server package (shared crypto backend)
pip install -e "server[dev]"

# Install desktop client package with PySide6 and testing tools
pip install -e "desktop[dev]"
```

---

## Running the Application

### 1. Launch with Local Development Server

Ensure your local VaultSync backend is running:
```bash
# Terminal 1: Backend
uvicorn vaultsync_server.main:app --host 127.0.0.1 --port 8000
```

Launch the desktop client:
```bash
# Terminal 2: Desktop Client
vaultsync-desktop --server http://127.0.0.1:8000
```
Or via Python module:
```bash
python -m vaultsync_desktop.main --server http://127.0.0.1:8000
```

### 2. Available CLI Arguments
- `--server <URL>`: Pre-fill backend server URL (must be `http://127.0.0.1:*`, `http://localhost:*`, or `https://*`).
- `--debug`: Enable verbose diagnostic logging to stdout.

---

## User Workflows

1. **Server Connection**: Enter server address. The client performs an initial `/health` check.
2. **Registration**:
   - Provide username, account password, and master passphrase.
   - Client generates a cryptographically secure 256-bit random VEK, derives the KEK client-side with Argon2id, wraps the VEK with AES-256-GCM, and uploads only the wrapped envelope and salt.
3. **Login & Vault Unlock**:
   - Step 1: Authenticate with username and account password to obtain a bearer session token.
   - Step 2: Unlock local vault by providing the vault master password to decrypt the wrapped VEK.
   - *Legacy Accounts*: If the server returns HTTP 403 Migration Required (Phase 3.1 legacy account), the client displays a clear migration dialogue directing the user to run the administrative reset CLI.
4. **Vault Management**:
   - Real-time search across titles, usernames, URLs, and notes.
   - View, add, edit, and delete credentials.
   - Optimistic concurrency control: if an item was modified remotely, saving raises a conflict notice preventing silent overwrites.
   - Sensitive field clipboard copy with automatic 30-second wipe (only clears if clipboard contents still match copied value).
5. **Settings & Rotation**:
   - Change Account Password: Sends current and new account passwords to `/auth/change-password`.
   - Rotate Vault Master Password: Re-wraps the existing VEK with a new master password and uploads the new envelope to `/vault/keys` without needing to re-encrypt any existing vault records.
   - Configure auto-lock timeout.

---

## Testing

The desktop client includes a comprehensive automated test suite with `pytest` and `pytest-qt` operating headlessly:

```bash
# Run desktop tests offscreen
QT_QPA_PLATFORM=offscreen pytest desktop/tests -v

# Run entire combined test suite (server + desktop: 75 tests)
QT_QPA_PLATFORM=offscreen pytest --import-mode=importlib server/tests desktop/tests -v
```
