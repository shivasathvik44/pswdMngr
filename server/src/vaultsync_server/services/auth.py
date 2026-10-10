"""Authentication, token hashing, and rate limiting service."""

import hashlib
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from vaultsync_server.config import settings

# Server-side Argon2id hasher for authenticating the client's auth_secret
# Note: Memory and iterations are chosen for server-side verification resilience
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=32768,  # 32 MiB server side
    parallelism=2,
    hash_len=32,
)


def hash_auth_secret(auth_secret: str) -> str:
    """Hash the client's derived auth_secret for persistent storage.
    
    The server never processes or stores the master password or KEK.
    """
    return _hasher.hash(auth_secret)


def verify_auth_secret(auth_hash: str, auth_secret: str) -> bool:
    """Verify incoming client auth_secret against stored Argon2id hash."""
    try:
        return _hasher.verify(auth_hash, auth_secret)
    except (VerifyMismatchError, Exception):
        return False


def generate_session_token() -> tuple[str, str]:
    """Generate a high-entropy session bearer token and its SHA-256 verifier.
    
    Returns:
        (raw_token, token_hash)
        The raw_token is returned to the client and never stored.
        The token_hash is stored in the database.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    return raw_token, token_hash


def hash_token(token: str) -> str:
    """Compute constant-length SHA-256 verifier hex string for a session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class InMemoryRateLimiter:
    """Sliding-window rate limiter for abuse control on authentication endpoints."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._attempts: dict[str, list[float]] = {}

    def is_rate_limited(self, identifier: str) -> bool:
        """Check if the given identifier (IP or username) has exceeded the threshold."""
        now = time.time()
        with self._lock:
            history = self._attempts.get(identifier, [])
            # Prune attempts outside the sliding window
            cutoff = now - self.window_seconds
            valid_history = [t for t in history if t > cutoff]
            self._attempts[identifier] = valid_history
            return len(valid_history) >= self.max_attempts

    def record_failure(self, identifier: str) -> None:
        """Record a failed authentication attempt."""
        now = time.time()
        with self._lock:
            history = self._attempts.setdefault(identifier, [])
            history.append(now)

    def reset(self, identifier: str) -> None:
        """Reset attempts on successful authentication."""
        with self._lock:
            self._attempts.pop(identifier, None)


rate_limiter = InMemoryRateLimiter(
    max_attempts=settings.rate_limit_max_attempts,
    window_seconds=settings.rate_limit_window_seconds,
)
