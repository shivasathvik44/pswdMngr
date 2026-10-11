"""Authentication, password hashing, token hashing, and rate limiting service.

Implements the Two-Credential security architecture:
Server verifies and hashes only the account password.
Vault master password never reaches the server.
"""

import hashlib
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.config import settings
from vaultsync_server.db.models import AuthRateLimit

# Server-side Argon2id hasher for account passwords
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=32768,  # 32 MiB server-side memory
    parallelism=2,
    hash_len=32,
)


def hash_password(password: str) -> str:
    """Hash the account password using Argon2id for secure database persistence."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify incoming account password against stored Argon2id hash in constant time."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, Exception):
        return False


# Aliases for transition compatibility
hash_auth_secret = hash_password
verify_auth_secret = verify_password


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

    def clear(self) -> None:
        """Clear all in-memory rate limiting state."""
        with self._lock:
            self._attempts.clear()


class DatabaseRateLimiter:
    """Database-backed sliding-window rate limiter for multi-worker deployments.
    
    Persists attempt timestamps in SQLite/PostgreSQL without external Redis dependencies.
    """

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    def is_rate_limited(self, db: DbSession, identifier: str) -> bool:
        """Check whether attempt count within window exceeds threshold."""
        cutoff = time.time() - self.window_seconds
        stmt = (
            select(func.count(AuthRateLimit.id))
            .where(
                AuthRateLimit.identifier == identifier,
                AuthRateLimit.attempt_time > cutoff,
            )
        )
        count = db.execute(stmt).scalar_one()
        return count >= self.max_attempts

    def record_failure(self, db: DbSession, identifier: str) -> None:
        """Record a failed authentication event."""
        now = time.time()
        event = AuthRateLimit(identifier=identifier, attempt_time=now)
        db.add(event)
        db.commit()

    def reset(self, db: DbSession, identifier: str) -> None:
        """Remove failure events for identifier upon successful authentication."""
        stmt = delete(AuthRateLimit).where(AuthRateLimit.identifier == identifier)
        db.execute(stmt)
        db.commit()

    def prune_expired(self, db: DbSession) -> int:
        """Prune attempts older than the rate limiting window."""
        cutoff = time.time() - self.window_seconds
        stmt = delete(AuthRateLimit).where(AuthRateLimit.attempt_time <= cutoff)
        result = db.execute(stmt)
        db.commit()
        return result.rowcount or 0


rate_limiter = InMemoryRateLimiter(
    max_attempts=settings.rate_limit_max_attempts,
    window_seconds=settings.rate_limit_window_seconds,
)

db_rate_limiter = DatabaseRateLimiter(
    max_attempts=settings.rate_limit_max_attempts,
    window_seconds=settings.rate_limit_window_seconds,
)
