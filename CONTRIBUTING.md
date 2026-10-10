# Contributing to VaultSync

Thank you for contributing to VaultSync! We welcome contributions that maintain our high standards of security, code quality, and maintainability.

## Development Principles

1. **Security First**: VaultSync is an end-to-end encrypted password manager. Any proposed changes to cryptographic primitives, protocol serialization, or key management must include detailed threat modeling and cross-language test vectors.
2. **Explicit Typings & Tests**: All code must include strict type annotations (Python type hints, Kotlin static typing) and comprehensive automated tests (including positive, malformed, and adversarial test cases).
3. **Reproducibility**: Changes must run without requiring paid cloud infrastructure or external proprietary dependencies.
4. **Zero Knowledge Enforcement**: Ensure no server changes introduce any mechanism where plaintext passwords or keys are accepted or logged.

## Local Development Workflow

### Server Setup (Python 3.12+)

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and server package in editable mode
pip install -e server[dev]

# Run automated tests
pytest server/tests
```

### Code Style and Standards

- **Python**: Follow PEP 8 guidelines, enforce type hints with `mypy` / Pydantic, and write clear docstrings.
- **Commit Messages**: Write concise, descriptive commit messages following the Conventional Commits specification (e.g. `feat(server): add health endpoint`, `test(server): add security headers check`).

## Submitting Pull Requests

1. Create a feature branch from `main`.
2. Ensure all unit and integration tests pass locally.
3. Submit a Pull Request describing what changes were made, the rationale, and testing evidence.
