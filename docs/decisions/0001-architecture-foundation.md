# ADR 0001: Architecture Foundation and Zero-Knowledge Protocol Baseline

## Status
Accepted

## Context
VaultSync requires a reliable, secure architecture for personal password synchronization between an Android phone and a Fedora Linux desktop without relying on third-party cloud hosting or Docker containers. The threat model requires zero-knowledge guarantees: the sync backend must never see plaintext credentials, encryption keys, or unencrypted metadata.

## Decision
1. **Repository Layout**: A unified multi-component repository containing `server/`, `desktop/`, `android/`, `shared/`, and `docs/`.
2. **Backend Framework**: Python 3.12+ with FastAPI and Uvicorn. FastAPI provides asynchronous request handling, OpenAPI documentation generation, and strict schema validation via Pydantic.
3. **Network Transport**: Private mesh networking via Tailscale or WireGuard overlays. By default, the development server binds strictly to `127.0.0.1` to prevent inadvertent public exposure.
4. **Zero-Knowledge Separation**: Separate authentication secrets from vault encryption keys. Server authentication uses a distinct key-derivation pathway from the client-side vault encryption key (VEK).
5. **No Docker Requirement**: Direct execution using native Python virtual environments and Linux system packages to maintain low footprint and high inspectability.

## Consequences
- Requires maintaining client cryptographic implementations across both Python (PySide6 desktop) and Kotlin (Android Jetpack Compose).
- Requires canonical cross-language test vectors to ensure interoperability.
- Server-side conflict resolution must operate blindly on encrypted revisions, version cursors, and tombstones without field-level inspection.
