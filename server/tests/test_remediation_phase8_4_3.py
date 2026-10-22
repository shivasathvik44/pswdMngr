"""Regression test suite for Phase 8.4.3 backend security remediations and Phase 8.4.2 verification.

Covers:
1. SEC-05: Recovery username case-insensitivity, whitespace handling, and original username preservation.
2. SEC-06: IPv6 subnet (/64) prefix rate-limiting normalization, IPv4 preservation, and bypass prevention.
3. SEC-07: Inactive session cleanup (expired and revoked pruning, active session preservation, batch bounding).
4. SEC-08: HSTS header enforcement in production HTTPS / reverse proxy, and absence in HTTP / development.
5. Verification of Phase 8.4.2 multi-connection concurrent cursor allocation and transaction safety.
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker

from vaultsync_server.api.auth import generate_synthetic_salt
from vaultsync_server.config import settings
from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, b64encode
from vaultsync_server.crypto.kdf import generate_salt
from vaultsync_server.db.base import Base, create_db_engine, get_db
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.main import create_app
from vaultsync_server.services.auth import (
    cleanup_inactive_sessions,
    get_client_ip,
    hash_password,
    normalize_client_ip,
    verify_password,
)
from vaultsync_server.services.recovery import AccountNotFoundError, reset_account_password_admin


# ============================================================================
# Helpers
# ============================================================================

def make_test_record_envelope(record_id: str) -> str:
    """Create a minimal valid JSON envelope string for testing."""
    return EncryptedRecordEnvelope(
        version=1,
        algorithm="AES-256-GCM",
        record_id=record_id,
        nonce=b64encode(b"N" * 12),
        ciphertext=b64encode(b"encrypted-test-data"),
    ).to_json()


# ============================================================================
# SEC-05: Recovery Username Case Consistency
# ============================================================================

def test_sec05_recovery_username_case_variants_and_preservation(tmp_path: Path):
    """Verify that administrative password reset normalizes username case and whitespace without altering stored username."""
    db_file = tmp_path / "test_sec05_recovery.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    original_username = "AliceBobUser"
    initial_password = "OldPassword123!"
    new_password = "RecoveredPassword456!"

    with SessionLocal() as db:
        acc = Account(
            username=original_username,
            account_password_hash=hash_password(initial_password),
            kdf_salt=b64encode(generate_salt()),
            wrapped_vault_key='{"version": 1, "kdf": {"algorithm": "Argon2id"}}',
            sync_cursor=3,
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

        # Add an active session and a revoked session
        s_active = Session(
            account_id=acc_id,
            device_name="Active Device",
            token_hash="hash_active_1",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        s_revoked = Session(
            account_id=acc_id,
            device_name="Old Device",
            token_hash="hash_revoked_1",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            revoked_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        db.add_all([s_active, s_revoked])
        db.commit()

    # 1. Test recovery with lowercase variant and whitespace
    with SessionLocal() as db:
        recovered_acc = reset_account_password_admin(db, "  alicebobuser  ", new_password)
        # Original stored username must remain preserved
        assert recovered_acc.username == original_username
        assert verify_password(recovered_acc.account_password_hash, new_password)
        assert not verify_password(recovered_acc.account_password_hash, initial_password)

    # 2. Verify sessions: previously active session must now be revoked
    with SessionLocal() as db:
        sessions = db.execute(select(Session).where(Session.account_id == acc_id)).scalars().all()
        for s in sessions:
            assert s.revoked_at is not None, f"Session {s.device_name} must be revoked"

    # 3. Test recovery with uppercase variant
    with SessionLocal() as db:
        recovered_acc2 = reset_account_password_admin(db, "ALICEBOBUSER", "AnotherNewPassword789!")
        assert recovered_acc2.username == original_username
        assert verify_password(recovered_acc2.account_password_hash, "AnotherNewPassword789!")

    # 4. Test non-existent username raises AccountNotFoundError
    with SessionLocal() as db:
        with pytest.raises(AccountNotFoundError):
            reset_account_password_admin(db, "non_existent_user", "AnyPassword123!")


# ============================================================================
# SEC-06: IPv6 Rate-Limit Subnet Normalization & Bypass Prevention
# ============================================================================

def test_sec06_ip_normalization_ipv4_and_ipv6():
    """Verify IP normalization logic across IPv4, IPv6 /64 subnets, mapped, and malformed inputs."""
    # Standard IPv4 remains untouched
    assert normalize_client_ip("192.0.2.1") == "192.0.2.1"
    assert normalize_client_ip("  10.0.0.5  ") == "10.0.0.5"
    assert normalize_client_ip("192.168.1.1:8080") == "192.168.1.1"

    # IPv6 addresses in same /64 subnet must normalize to identical key
    ip_v6_a = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    ip_v6_b = "2001:0db8:85a3:0000:ffff:ffff:ffff:ffff"
    ip_v6_c = "2001:db8:85a3::1"

    norm_a = normalize_client_ip(ip_v6_a)
    norm_b = normalize_client_ip(ip_v6_b)
    norm_c = normalize_client_ip(ip_v6_c)

    assert norm_a == "2001:db8:85a3::/64"
    assert norm_a == norm_b == norm_c, "Addresses in same /64 prefix must normalize to identical prefix"

    # IPv6 in different /64 subnet must produce distinct key
    ip_v6_diff = "2001:0db8:85a3:0001::1"
    assert normalize_client_ip(ip_v6_diff) != norm_a
    assert normalize_client_ip(ip_v6_diff) == "2001:db8:85a3:1::/64"

    # IPv4-mapped IPv6
    assert normalize_client_ip("::ffff:192.0.2.128") == "192.0.2.128"

    # Malformed or absent
    assert normalize_client_ip("invalid-ip-string") == "unknown"
    assert normalize_client_ip("") == "unknown"
    assert normalize_client_ip(None) == "unknown"


@pytest.mark.anyio
async def test_sec06_ipv6_rate_limiting_prevents_prefix_rotation_bypass(async_client: AsyncClient):
    """Verify that an attacker rotating IPv6 interface identifiers within a /64 block cannot bypass rate limits."""
    # The rate limiter allows settings.rate_limit_max_attempts failed attempts before blocking (default: 10)
    # We simulate attempts from varying host addresses within 2001:db8:beef:cafe::/64
    prefix_base = "2001:db8:beef:cafe:"

    target_user = "sec06_rate_target_user"
    # Pre-register user
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": target_user,
            "account_password": "RealPassword123!",
            "kdf_salt": b64encode(generate_salt()),
        },
    )

    # Exhaust rate limit by rotating host IDs in the same /64 prefix
    limit = settings.rate_limit_max_attempts
    for i in range(limit):
        rotating_ipv6 = f"{prefix_base}:{i+1:04x}:0000:0000:0001"
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"username": target_user, "account_password": "WrongPassword!"},
            headers={"client-ip-override-test": rotating_ipv6},  # Mock client IP via client transport test
        )
        assert resp.status_code == 401, f"Attempt {i+1} should fail with 401"

    # Direct unit verification of rate limiter with normalized keys
    from vaultsync_server.services.auth import InMemoryRateLimiter
    limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=60)
    client_ip_1 = normalize_client_ip("2001:db8:aaaa:bbbb:0000:0000:0000:0001")
    client_ip_2 = normalize_client_ip("2001:db8:aaaa:bbbb:ffff:eeee:dddd:cccc")
    assert client_ip_1 == client_ip_2

    key = f"auth:ip:{client_ip_1}"
    assert not limiter.is_rate_limited(key)
    limiter.record_failure(key)
    limiter.record_failure(key)
    limiter.record_failure(key)
    assert limiter.is_rate_limited(key)

    # An address in a different /64 prefix must NOT be blocked
    other_prefix_ip = normalize_client_ip("2001:db8:aaaa:cccc:0000:0000:0000:0001")
    other_key = f"auth:ip:{other_prefix_ip}"
    assert not limiter.is_rate_limited(other_key)


# ============================================================================
# SEC-07: Inactive Session Cleanup (Expired & Revoked)
# ============================================================================

def test_sec07_cleanup_inactive_sessions(tmp_path: Path):
    """Verify that cleanup_inactive_sessions safely removes expired and revoked sessions while protecting active ones."""
    db_file = tmp_path / "test_sec07_cleanup.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        acc = Account(
            username="cleanup_test_user",
            account_password_hash=hash_password("Password123!"),
            kdf_salt=b64encode(generate_salt()),
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

        # 1. Active session (valid, unexpired, unrevoked)
        s_active = Session(
            account_id=acc_id,
            device_name="Active Session",
            token_hash="tok_active",
            expires_at=now + timedelta(days=7),
            revoked_at=None,
        )
        # 2. Expired session
        s_expired = Session(
            account_id=acc_id,
            device_name="Expired Session",
            token_hash="tok_expired",
            expires_at=now - timedelta(hours=1),
            revoked_at=None,
        )
        # 3. Revoked session
        s_revoked = Session(
            account_id=acc_id,
            device_name="Revoked Session",
            token_hash="tok_revoked",
            expires_at=now + timedelta(days=2),
            revoked_at=now - timedelta(days=1),
        )
        # 4. Both expired and revoked session
        s_both = Session(
            account_id=acc_id,
            device_name="Both Expired and Revoked",
            token_hash="tok_both",
            expires_at=now - timedelta(days=10),
            revoked_at=now - timedelta(days=12),
        )

        db.add_all([s_active, s_expired, s_revoked, s_both])
        db.commit()

    # Test bounded cleanup with limit=1: only 1 inactive session should be pruned
    with SessionLocal() as db:
        pruned_count = cleanup_inactive_sessions(db, before=now, limit=1)
        assert pruned_count == 1

    # Total remaining sessions must be 3 (1 active + 2 inactive)
    with SessionLocal() as db:
        remaining = db.execute(select(Session)).scalars().all()
        assert len(remaining) == 3
        # Active session must be present
        active_found = any(s.token_hash == "tok_active" for s in remaining)
        assert active_found, "Active session must never be deleted"

    # Test full cleanup without limit
    with SessionLocal() as db:
        pruned_count = cleanup_inactive_sessions(db, before=now)
        assert pruned_count == 2

    # Now only the active session must remain
    with SessionLocal() as db:
        final_sessions = db.execute(select(Session)).scalars().all()
        assert len(final_sessions) == 1
        assert final_sessions[0].token_hash == "tok_active"
        assert final_sessions[0].revoked_at is None


# ============================================================================
# SEC-08: HSTS Configuration Verification
# ============================================================================

@pytest.mark.anyio
async def test_sec08_hsts_disabled_in_development_and_http():
    """Verify that HSTS headers are strictly omitted in development/test and plain HTTP."""
    # Ensure development environment
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "Strict-Transport-Security" not in resp.headers, (
            "HSTS must never be injected in development environment over HTTP"
        )

        # Even if x-forwarded-proto is sent, development environment must not set HSTS
        resp_fwd = await client.get("/health", headers={"X-Forwarded-Proto": "https"})
        assert "Strict-Transport-Security" not in resp_fwd.headers, (
            "HSTS must not be injected in development environment even with forwarded HTTPS header"
        )


@pytest.mark.anyio
async def test_sec08_hsts_enabled_in_production_https(monkeypatch):
    """Verify that HSTS header (max-age=31536000) is injected strictly in production when HTTPS is active."""
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(
        settings,
        "server_secret_key",
        "production-secret-must-be-at-least-32-chars-entropy!",
    )

    prod_app = create_app()
    transport = ASGITransport(app=prod_app)

    # 1. Production over plain HTTP (no TLS proxy header) -> No HSTS
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp_http = await client.get("/health")
        assert resp_http.status_code == 200
        assert "Strict-Transport-Security" not in resp_http.headers, (
            "HSTS must not be injected over plain HTTP in production"
        )

        # 2. Production behind TLS reverse proxy (X-Forwarded-Proto: https from trusted proxy) -> HSTS injected
        resp_https = await client.get("/health", headers={"X-Forwarded-Proto": "https"})
        assert resp_https.status_code == 200
        assert "Strict-Transport-Security" in resp_https.headers
        hsts_value = resp_https.headers["Strict-Transport-Security"]
        assert hsts_value == "max-age=31536000"
        # Must NOT include includeSubDomains or preload without deployment sign-off
        assert "includeSubDomains" not in hsts_value
        assert "preload" not in hsts_value

    # 3. Production request from untrusted client with forged X-Forwarded-Proto -> No HSTS
    untrusted_transport = ASGITransport(app=prod_app, client=("198.51.100.55", 54321))
    async with AsyncClient(transport=untrusted_transport, base_url="http://testserver") as untrusted_client:
        resp_forged = await untrusted_client.get("/health", headers={"X-Forwarded-Proto": "https"})
        assert resp_forged.status_code == 200
        assert "Strict-Transport-Security" not in resp_forged.headers, (
            "Untrusted forwarded headers from non-trusted proxies must never enable HSTS"
        )


# ============================================================================
# Step 1 Verification: Real Multi-Connection Concurrency & Transaction Safety
# ============================================================================

def test_phase8_4_2_real_multiconnection_concurrency(tmp_path: Path):
    """Verify that multiple concurrent threads with separate physical SQLite connections produce strictly unique, contiguous cursors."""
    db_file = tmp_path / "real_concurrency_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    with SessionLocal() as db:
        acc = Account(
            username="multi_conn_user",
            account_password_hash=hash_password("Password123!"),
            kdf_salt=b64encode(generate_salt()),
            sync_cursor=0,
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

    worker_count = 25

    def independent_db_worker(worker_id: int) -> int:
        # Each worker thread creates its own Session and connection
        with SessionLocal() as db:
            cursor_stmt = (
                update(Account)
                .where(Account.id == acc_id)
                .values(sync_cursor=Account.sync_cursor + 1)
                .returning(Account.sync_cursor)
            )
            allocated = db.execute(cursor_stmt).scalar_one()

            rec = EncryptedRecord(
                record_id=f"rec-worker-{worker_id:03d}",
                account_id=acc_id,
                ciphertext_payload=make_test_record_envelope(f"rec-worker-{worker_id:03d}"),
                revision=1,
                sync_cursor=allocated,
                is_deleted=False,
            )
            db.add(rec)
            db.commit()
            return allocated

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(independent_db_worker, range(worker_count)))

    assert len(results) == worker_count
    assert len(set(results)) == worker_count, "All allocated cursors across independent connections must be distinct"
    assert sorted(results) == list(range(1, worker_count + 1)), "Cursors must be strictly contiguous 1..N"

    with SessionLocal() as db:
        final_acc = db.execute(select(Account).where(Account.id == acc_id)).scalar_one()
        assert final_acc.sync_cursor == worker_count
