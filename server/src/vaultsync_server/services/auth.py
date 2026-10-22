"""Authentication, password hashing, token hashing, and rate limiting service.

Implements the Two-Credential security architecture:
Server verifies and hashes only the account password.
Vault master password never reaches the server.
"""

import hashlib
import ipaddress
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.config import settings
from vaultsync_server.db.models import AuthRateLimit, Session

# Server-side Argon2id hasher for account passwords
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=32768,  # 32 MiB server-side memory
    parallelism=2,
    hash_len=32,
)

# Precomputed valid Argon2id hash used to prevent timing attacks / username enumeration on login
DUMMY_PASSWORD_HASH: Final[str] = _hasher.hash("vaultsync-dummy-constant-time-padding-secret")


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


def normalize_client_ip(ip_str: str | None) -> str:
    """Normalize client IP address for rate-limiting bucket aggregation.

    Security design:
    - IPv4: normalized to standard canonical representation (/32).
    - IPv6: normalized to /64 subnet prefix (e.g. 2001:db8:abcd:12::/64) to prevent
      rate-limit bypass via ephemeral IPv6 interface identifier rotation within
      subscriber allocations.
    - IPv4-mapped IPv6 (::ffff:192.0.2.1): unwrapped to canonical IPv4.
    - Malformed or absent input: safely returns 'unknown'.
    """
    if not ip_str or not isinstance(ip_str, str):
        return "unknown"

    cleaned = ip_str.strip()
    # Strip brackets and ports if present, e.g. [2001:db8::1]:8080 or 192.0.2.1:8000
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:cleaned.index("]")]
    elif ":" in cleaned and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]

    try:
        ip = ipaddress.ip_address(cleaned)
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped:
                return str(ip.ipv4_mapped)
            return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
        return str(ip)
    except ValueError:
        return "unknown"


def get_client_ip(request: Request) -> str:
    """Extract and normalize client IP from request for abuse control.

    Security note on proxies:
    Direct transport peer (request.client.host) is used as the authoritative source
    to prevent spoofing via unverified X-Forwarded-For headers from untrusted clients.
    """
    raw_ip = request.client.host if request.client else None
    return normalize_client_ip(raw_ip)


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
        self._last_prune_time: float = 0.0

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
        """Record a failed authentication event and prune expired events at bounded intervals."""
        now = time.time()
        # Bounded periodic pruning: execute at most once per window_seconds to prevent excessive write locks
        if now - self._last_prune_time >= self.window_seconds:
            cutoff = now - self.window_seconds
            try:
                db.execute(
                    delete(AuthRateLimit)
                    .where(AuthRateLimit.attempt_time <= cutoff)
                    .execution_options(synchronize_session=False)
                )
                self._last_prune_time = now
            except Exception:
                pass

        event = AuthRateLimit(identifier=identifier, attempt_time=now)
        db.add(event)
        db.commit()

    def reset(self, db: DbSession, identifier: str) -> None:
        """Remove failure events for identifier upon successful authentication."""
        stmt = (
            delete(AuthRateLimit)
            .where(AuthRateLimit.identifier == identifier)
            .execution_options(synchronize_session=False)
        )
        db.execute(stmt)
        db.commit()

    def prune_expired(self, db: DbSession) -> int:
        """Prune attempts older than the rate limiting window."""
        cutoff = time.time() - self.window_seconds
        stmt = (
            delete(AuthRateLimit)
            .where(AuthRateLimit.attempt_time <= cutoff)
            .execution_options(synchronize_session=False)
        )
        result = db.execute(stmt)
        db.commit()
        return result.rowcount or 0

    def reset_all(self, db: DbSession) -> int:
        """Clear all rate limit attempt logs across all identifiers (for testing and administrative reset)."""
        stmt = delete(AuthRateLimit).execution_options(synchronize_session=False)
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


def cleanup_inactive_sessions(
    db: DbSession,
    before: datetime | None = None,
    limit: int | None = None,
) -> int:
    """Explicit, bounded deletion of expired or revoked session records.

    Safety constraints:
    - Deletes ONLY rows where revoked_at is not NULL or expires_at <= cutoff.
    - Active, unexpired sessions are never touched.
    - Operates as an explicit, bounded operation suitable for scheduled maintenance
      or administrative invocation; does not run implicitly on hot request paths.

    Args:
        db: Active SQLAlchemy database session.
        before: Reference UTC cutoff timestamp (defaults to current UTC time).
        limit: Optional maximum rows to prune in a single operation.

    Returns:
        Number of deleted session records.
    """
    cutoff = before or datetime.now(timezone.utc)
    condition = (Session.revoked_at.is_not(None)) | (Session.expires_at <= cutoff)

    if limit is not None and limit > 0:
        subq = (
            select(Session.id)
            .where(condition)
            .limit(limit)
            .scalar_subquery()
        )
        stmt = delete(Session).where(Session.id.in_(subq)).execution_options(synchronize_session=False)
    else:
        stmt = delete(Session).where(condition).execution_options(synchronize_session=False)

    result = db.execute(stmt)
    db.commit()
    return result.rowcount or 0
