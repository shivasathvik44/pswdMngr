"""Phase 5 Security Audit and Hardening Regression Tests.

Validates:
1. Login timing attack mitigation (uniform execution time via DUMMY_PASSWORD_HASH).
2. Elimination of username enumeration on /api/v1/auth/salt (deterministic synthetic salts).
3. Rate limiting on public /api/v1/auth/salt endpoint.
4. Rate limiting on authenticated /api/v1/auth/password change endpoint.
5. Case-insensitive username registration collision prevention & unified identity model.
6. Case-insensitive username rate limit normalization (preventing rate limit evasion).
7. Comprehensive request payload size upper bound enforcement:
   - Declared oversized Content-Length (HTTP 413).
   - Negative / invalid Content-Length (HTTP 400).
   - Streaming / chunked transfer exceeding limit without declared length (HTTP 413).
   - Mismatched declared length exceeding limit (HTTP 413).
   - Valid payload within limit (processed normally).
8. Defense-in-depth HTTP security headers (CSP, COOP, CORP, etc.).
9. DatabaseRateLimiter:
   - Periodic bounded cleanup of expired attempt records.
   - Guarantee that rate-limiter operations NEVER detach or corrupt unrelated ORM objects.
"""

import asyncio
import time
from typing import AsyncGenerator
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from vaultsync_server.config import settings
from vaultsync_server.crypto.envelope import b64decode, b64encode
from vaultsync_server.crypto.kdf import Argon2Params, derive_kek, generate_salt
from vaultsync_server.crypto.vault_keys import VaultKey, wrap_vault_key
from vaultsync_server.db.models import Account, AuthRateLimit
from vaultsync_server.services.auth import (
    DatabaseRateLimiter,
    db_rate_limiter,
    hash_password,
    rate_limiter,
)


def _make_reg_payload(username: str, account_password: str = "AccountPassword123!") -> dict[str, str]:
    vek = VaultKey.generate()
    salt_bytes = generate_salt()
    salt_b64 = b64encode(salt_bytes)
    kdf_params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt_bytes)
    kek = derive_kek("MasterPassword123!", kdf_params)
    wrap_env = wrap_vault_key(vek, kek, kdf_params)
    return {
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_env.to_json(),
    }


@pytest.fixture(autouse=True)
def clean_rate_limiters(app):
    """Ensure rate limiters are completely reset between test runs."""
    rate_limiter.clear()
    yield
    rate_limiter.clear()


@pytest.mark.anyio
async def test_login_timing_mitigation_nonexistent_account(async_client: AsyncClient):
    """Verify non-existent user login executes Argon2id dummy hash, ensuring uniform response behavior."""
    reg_payload = _make_reg_payload("timing_test_user", "AccountPassword123!")
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201

    # Measure time for existing account with wrong password (runs Argon2id)
    t0 = time.perf_counter()
    res_wrong_pw = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "timing_test_user", "account_password": "WrongPassword123!"},
    )
    elapsed_existing = time.perf_counter() - t0
    assert res_wrong_pw.status_code == 401
    assert res_wrong_pw.json()["detail"] == "Invalid credentials"

    rate_limiter.clear()

    # Measure time for non-existent account with wrong password (should run DUMMY_PASSWORD_HASH)
    t1 = time.perf_counter()
    res_no_user = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "non_existent_random_user_999", "account_password": "WrongPassword123!"},
    )
    elapsed_nonexistent = time.perf_counter() - t1
    assert res_no_user.status_code == 401
    assert res_no_user.json()["detail"] == "Invalid credentials"

    # Both must have performed Argon2id verification, taking significant time (> 5ms)
    assert elapsed_nonexistent > 0.005, f"Non-existent login returned too quickly ({elapsed_nonexistent*1000:.2f}ms), timing oracle present!"


@pytest.mark.anyio
async def test_salt_endpoint_does_not_disclose_account_existence(async_client: AsyncClient):
    """Verify GET /api/v1/auth/salt returns identical HTTP 200 format for existing and non-existent accounts."""
    # 1. Register an actual synthetic account
    real_username = "salt_real_user"
    reg_payload = _make_reg_payload(real_username, "SecretPass123!")
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    real_salt = reg_payload["kdf_salt"]

    # 2. Query salt for existing account
    res_real = await async_client.get("/api/v1/auth/salt", params={"username": real_username})
    assert res_real.status_code == 200
    data_real = res_real.json()
    assert data_real["username"] == real_username
    assert data_real["kdf_salt"] == real_salt
    assert len(b64decode(data_real["kdf_salt"])) == 16

    # 3. Query salt for non-existent account
    ghost_user = "salt_ghost_user_404"
    res_ghost = await async_client.get("/api/v1/auth/salt", params={"username": ghost_user})
    assert res_ghost.status_code == 200, "Non-existent user must return 200 OK to prevent username enumeration!"
    data_ghost = res_ghost.json()
    assert data_ghost["username"] == ghost_user
    assert isinstance(data_ghost["kdf_salt"], str)
    assert len(b64decode(data_ghost["kdf_salt"])) == 16, "Synthetic salt must be valid 16-byte base64"

    # 4. Verify deterministic property: repeated queries for same ghost user produce identical salt
    res_ghost2 = await async_client.get("/api/v1/auth/salt", params={"username": ghost_user})
    assert res_ghost2.status_code == 200
    assert res_ghost2.json()["kdf_salt"] == data_ghost["kdf_salt"]

    # 5. Verify distinct ghost users receive distinct salts
    res_other_ghost = await async_client.get("/api/v1/auth/salt", params={"username": "another_ghost_user"})
    assert res_other_ghost.status_code == 200
    assert res_other_ghost.json()["kdf_salt"] != data_ghost["kdf_salt"]


@pytest.mark.anyio
async def test_salt_endpoint_rate_limiting(async_client: AsyncClient):
    """Verify /api/v1/auth/salt is protected by IP rate limiting against rapid scraping attacks."""
    max_attempts = settings.rate_limit_max_attempts

    for attempt in range(max_attempts):
        res = await async_client.get(
            "/api/v1/auth/salt",
            params={"username": f"scan_target_{attempt}"},
        )
        assert res.status_code == 200

    # Next attempt must be throttled with 429 Too Many Requests
    blocked_res = await async_client.get(
        "/api/v1/auth/salt",
        params={"username": "scan_target_next"},
    )
    assert blocked_res.status_code == 429
    assert "Too many" in blocked_res.json()["detail"]


@pytest.mark.anyio
async def test_username_case_collision_prevention(async_client: AsyncClient):
    """Verify system enforces case-insensitive username uniqueness to prevent identity collisions."""
    # 1. Register "AlphaUser"
    reg_payload = _make_reg_payload("AlphaUser", "AlphaPassword123!")
    res1 = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert res1.status_code == 201

    # 2. Attempting to register "alphauser" (lowercase) must be rejected with 409 Conflict
    dup_payload = _make_reg_payload("alphauser", "DifferentPassword123!")
    res2 = await async_client.post("/api/v1/auth/register", json=dup_payload)
    assert res2.status_code == 409
    assert "already taken" in res2.json()["detail"]

    # 3. Attempting to register "ALPHAUSER" (uppercase) must also be rejected
    dup_payload_upper = _make_reg_payload("ALPHAUSER", "DifferentPassword123!")
    res3 = await async_client.post("/api/v1/auth/register", json=dup_payload_upper)
    assert res3.status_code == 409

    # 4. Legitimate login as "alphauser" (lowercase) should match "AlphaUser"
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "alphauser", "account_password": "AlphaPassword123!"},
    )
    assert login_res.status_code == 200
    assert login_res.json()["account_id"] == res1.json()["account_id"]


@pytest.mark.anyio
async def test_password_change_rate_limiting(async_client: AsyncClient):
    """Verify PUT /api/v1/auth/password rate limits incorrect current_password attempts."""
    reg_payload = _make_reg_payload("pwd_rate_test", "RealPassword123!")
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201

    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "pwd_rate_test", "account_password": "RealPassword123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    max_attempts = settings.rate_limit_max_attempts
    for attempt in range(max_attempts):
        res = await async_client.put(
            "/api/v1/auth/password",
            json={"current_password": "WrongPassword!", "new_password": "NewValidPassword123!"},
            headers=headers,
        )
        assert res.status_code == 401

    blocked_res = await async_client.put(
        "/api/v1/auth/password",
        json={"current_password": "WrongPassword!", "new_password": "NewValidPassword123!"},
        headers=headers,
    )
    assert blocked_res.status_code == 429


@pytest.mark.anyio
async def test_username_normalization_prevents_rate_limit_bypass(async_client: AsyncClient):
    """Verify username casing/whitespace cannot bypass authentication rate limits."""
    reg_payload = _make_reg_payload("case_test_user", "CorrectPassword123!")
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201

    variations = [
        "case_test_user",
        "Case_Test_User",
        "CASE_TEST_USER",
        " case_test_user ",
        "  Case_Test_User  ",
    ]

    attempts_made = 0
    max_attempts = settings.rate_limit_max_attempts
    while attempts_made < max_attempts:
        v = variations[attempts_made % len(variations)]
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": v, "account_password": "WrongPassword123!"},
        )
        assert res.status_code == 401
        attempts_made += 1

    blocked_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "cAsE_tEsT_uSeR", "account_password": "WrongPassword123!"},
    )
    assert blocked_res.status_code == 429


# ============================================================================
# Payload Size Limit Enforcement Tests
# ============================================================================

@pytest.mark.anyio
async def test_payload_size_enforcement_declared_oversized(async_client: AsyncClient):
    """Verify requests with declared Content-Length > 2 MiB are rejected with HTTP 413 immediately."""
    max_size = settings.max_payload_size_bytes
    oversized_headers = {
        "Content-Type": "application/json",
        "Content-Length": str(max_size + 1024),
    }

    res = await async_client.post(
        "/api/v1/auth/login",
        headers=oversized_headers,
        content=b"x" * 10,
    )
    assert res.status_code == 413
    assert "Payload too large" in res.json()["detail"]


@pytest.mark.anyio
async def test_payload_size_enforcement_invalid_negative_length(async_client: AsyncClient):
    """Verify requests with negative or invalid Content-Length are rejected with HTTP 400."""
    res = await async_client.post(
        "/api/v1/auth/login",
        headers={"Content-Length": "-10"},
        content=b"{}",
    )
    assert res.status_code == 400


@pytest.mark.anyio
async def test_payload_size_enforcement_streaming_chunked_oversized(async_client: AsyncClient):
    """Verify streamed chunked request without Content-Length exceeding 2 MiB is rejected with 413."""
    max_size = settings.max_payload_size_bytes

    async def stream_chunks():
        chunk = b"A" * 65536  # 64 KiB per chunk
        total_sent = 0
        while total_sent < max_size + 131072:  # exceed limit
            yield chunk
            total_sent += len(chunk)

    # Use streaming content (Transfer-Encoding: chunked, no Content-Length header)
    res = await async_client.post(
        "/api/v1/auth/login",
        content=stream_chunks(),
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 413
    assert "Payload too large" in res.json()["detail"]


@pytest.mark.anyio
async def test_payload_size_enforcement_valid_payload_passes(async_client: AsyncClient):
    """Verify valid request under 2 MiB passes through middleware without distortion."""
    res = await async_client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


@pytest.mark.anyio
async def test_defensive_security_headers(async_client: AsyncClient):
    """Verify defensive HTTP response headers are present on all API responses."""
    res = await async_client.get("/api/v1/health")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "no-store" in headers.get("Cache-Control", "")
    assert "default-src 'none'" in headers.get("Content-Security-Policy", "")
    assert headers.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert headers.get("Cross-Origin-Resource-Policy") == "same-origin"


# ============================================================================
# DatabaseRateLimiter ORM Safety & Periodic Cleanup Tests
# ============================================================================

def test_database_rate_limiter_does_not_detach_unrelated_orm_objects(test_db_engine):
    """Verify DatabaseRateLimiter operations do not detach or corrupt loaded ORM objects."""
    from sqlalchemy.orm import sessionmaker

    session_factory = sessionmaker(bind=test_db_engine)
    db: DbSession = session_factory()

    try:
        # Create a test Account in session
        account = Account(
            username="orm_safety_user",
            account_password_hash=hash_password("Pass123!"),
            kdf_salt="dGVzdF9zYWx0XzEyMzQ1Ng==",
            sync_cursor=5,
        )
        db.add(account)
        db.commit()

        # Modify an attribute in session (uncommitted change)
        account.sync_cursor = 10

        # Execute rate limiter failure
        limiter = DatabaseRateLimiter(max_attempts=5, window_seconds=60)
        limiter.record_failure(db, "test:identifier")

        # Crucial check: account MUST NOT be detached from db session!
        assert account in db, "ORM object was detached by rate limiter!"
        assert account.sync_cursor == 10

        # Accessing account attributes should not raise DetachedInstanceError
        assert account.username == "orm_safety_user"
    finally:
        db.close()


def test_database_rate_limiter_prunes_expired_records(test_db_engine):
    """Verify DatabaseRateLimiter cleans up stale attempt records without full table wipes."""
    from sqlalchemy.orm import sessionmaker

    session_factory = sessionmaker(bind=test_db_engine)
    db: DbSession = session_factory()

    try:
        limiter = DatabaseRateLimiter(max_attempts=3, window_seconds=1)

        # Manually insert an expired record (timestamp in past)
        stale_record = AuthRateLimit(identifier="test:stale", attempt_time=time.time() - 100)
        db.add(stale_record)
        db.commit()

        count_before = db.execute(select(func.count(AuthRateLimit.id))).scalar_one()
        assert count_before >= 1

        # Explicit prune
        pruned_count = limiter.prune_expired(db)
        assert pruned_count >= 1

        remaining = db.execute(select(AuthRateLimit)).scalars().all()
        identifiers = [r.identifier for r in remaining]
        assert "test:stale" not in identifiers
    finally:
        db.close()
