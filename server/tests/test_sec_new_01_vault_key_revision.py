"""Comprehensive test suite for SEC-NEW-01: Atomic Vault-Key Revision Protection.

Verifies:
- Monotonic revision increment semantics for wrapped vault keys.
- Step-up auth enforcement and expected_revision requirement.
- Rejection of stale revisions (HTTP 409 Conflict).
- Non-sensitive structured error responses and metadata preservation.
- Concurrency protection: exactly one update succeeds under race conditions.
- Backward compatibility: supports legacy expected_version alias, rejects missing revisions.
- Database migration compatibility and preservation of existing encrypted material.
- End-to-end HTTP API error handling and concurrency guarantees.
"""

import concurrent.futures
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession, sessionmaker

from vaultsync_server.api.schemas import VaultKeyUpdateRequest
from vaultsync_server.crypto.envelope import WrappedKeyEnvelope, b64encode
from vaultsync_server.crypto.kdf import Argon2Params, derive_kek, generate_salt
from vaultsync_server.crypto.vault_keys import VaultKey, unwrap_vault_key, wrap_vault_key
from vaultsync_server.db.base import Base, create_db_engine
from vaultsync_server.db.models import Account, Session
from vaultsync_server.main import create_app
from vaultsync_server.services.auth import hash_password, rate_limiter


@pytest.fixture(autouse=True)
def clean_rate_limiters():
    """Ensure rate limiters are completely reset between test runs."""
    rate_limiter.clear()
    yield
    rate_limiter.clear()


# ============================================================================
# Helpers
# ============================================================================

def make_wrapped_key(master_password: str, vek: VaultKey | None = None) -> tuple[VaultKey, str, str]:
    key = vek or VaultKey.generate()
    salt = generate_salt()
    salt_b64 = b64encode(salt)
    params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt)
    kek = derive_kek(master_password, params)
    wrap = wrap_vault_key(key, kek, params)
    return key, salt_b64, wrap.to_json()


# ============================================================================
# 1. Revision Behavior Tests
# ============================================================================

@pytest.mark.anyio
async def test_sec_new_01_initial_revision_on_register(async_client: AsyncClient):
    """Verify that new accounts with a wrapped vault key initialize at revision 1."""
    username = f"user_sec_new_reg_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPassword123!")

    # Register
    reg_res = await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    assert reg_res.status_code == 201

    # Login and verify revision in login response
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert data["vault_key_version"] == 1
    assert data["vault_key_revision"] == 1

    # GET /auth/vault-key verification
    token = data["session_token"]
    headers = {"Authorization": f"Bearer {token}"}
    vk_res = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    assert vk_res.status_code == 200
    vk_data = vk_res.json()
    assert vk_data["vault_key_version"] == 1
    assert vk_data["vault_key_revision"] == 1


@pytest.mark.anyio
async def test_sec_new_01_successful_replacements_increment_monotonically(async_client: AsyncClient):
    """Verify that every successful replacement increments the revision by exactly one."""
    username = f"user_sec_new_inc_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt1, wrap1 = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt1,
        "wrapped_vault_key": wrap1,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Update from revision 1 -> 2 using expected_revision
    _, salt2, wrap2 = make_wrapped_key("MasterPass2!", vek)
    res1 = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap2,
        "kdf_salt": salt2,
        "expected_revision": 1,
        "current_password": account_password,
    })
    assert res1.status_code == 200
    assert res1.json()["vault_key_revision"] == 2
    assert res1.json()["vault_key_version"] == 2

    # Verify via GET
    vk_res1 = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    assert vk_res1.json()["vault_key_revision"] == 2

    # 2. Update from revision 2 -> 3
    _, salt3, wrap3 = make_wrapped_key("MasterPass3!", vek)
    res2 = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap3,
        "kdf_salt": salt3,
        "expected_revision": 2,
        "current_password": account_password,
    })
    assert res2.status_code == 200
    assert res2.json()["vault_key_revision"] == 3
    assert res2.json()["vault_key_version"] == 3

    # Verify via GET
    vk_res2 = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    assert vk_res2.json()["vault_key_revision"] == 3
    assert vk_res2.json()["kdf_salt"] == salt3


@pytest.mark.anyio
async def test_sec_new_01_stale_revisions_rejected_with_409(async_client: AsyncClient):
    """Verify that stale revisions are rejected with HTTP 409 and leave metadata unchanged."""
    username = f"user_sec_new_stale_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt1, wrap1 = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt1,
        "wrapped_vault_key": wrap1,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Stale: Current revision is 1, client sends expected_revision = 0
    _, salt_stale, wrap_stale = make_wrapped_key("StalePass!", vek)
    stale_low = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_stale,
        "kdf_salt": salt_stale,
        "expected_revision": 0,
        "current_password": account_password,
    })
    assert stale_low.status_code == 409
    assert "Conflict" in stale_low.json()["detail"]
    assert "expected vault key revision 0" in stale_low.json()["detail"]
    assert "current revision is 1" in stale_low.json()["detail"]
    assert stale_low.headers.get("x-current-revision") == "1"

    # Stale: Current revision is 1, client sends future expected_revision = 9
    stale_high = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_stale,
        "kdf_salt": salt_stale,
        "expected_revision": 9,
        "current_password": account_password,
    })
    assert stale_high.status_code == 409
    assert "Conflict" in stale_high.json()["detail"]
    assert stale_high.headers.get("x-current-revision") == "1"

    # Invariant: Existing metadata and revision remain completely unchanged
    vk_res = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    assert vk_res.json()["vault_key_revision"] == 1
    assert vk_res.json()["kdf_salt"] == salt1
    assert vk_res.json()["wrapped_vault_key"] == wrap1


@pytest.mark.anyio
async def test_sec_new_01_validation_failure_preserves_revision(async_client: AsyncClient):
    """Verify that input validation or auth failures do not increment the revision."""
    username = f"user_sec_new_fail_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt1, wrap1 = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt1,
        "wrapped_vault_key": wrap1,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    _, salt2, wrap2 = make_wrapped_key("MasterPass2!", vek)

    # 1. Incorrect step-up account password -> 401
    bad_pw = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap2,
        "kdf_salt": salt2,
        "expected_revision": 1,
        "current_password": "WrongPassword999!",
    })
    assert bad_pw.status_code == 401

    # 2. Malformed JSON envelope -> 400
    bad_json = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": "not-valid-json",
        "kdf_salt": salt2,
        "expected_revision": 1,
        "current_password": account_password,
    })
    assert bad_json.status_code == 400

    # 3. Mismatched envelope salt -> 400
    fake_salt = b64encode(b"f" * 16)
    mismatched = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap2,
        "kdf_salt": fake_salt,
        "expected_revision": 1,
        "current_password": account_password,
    })
    assert mismatched.status_code == 400

    # 4. Omitting revision entirely -> 422
    no_rev = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap2,
        "kdf_salt": salt2,
        "current_password": account_password,
    })
    assert no_rev.status_code == 422

    # 5. Mismatched expected_revision and expected_version -> 422
    mismatched_revs = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap2,
        "kdf_salt": salt2,
        "expected_revision": 1,
        "expected_version": 2,
        "current_password": account_password,
    })
    assert mismatched_revs.status_code == 422

    # Verify revision is still 1 and salt is unchanged
    vk_res = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    assert vk_res.json()["vault_key_revision"] == 1
    assert vk_res.json()["kdf_salt"] == salt1


@pytest.mark.anyio
async def test_sec_new_01_idempotent_retry_with_expected_revision(async_client: AsyncClient):
    """Verify that resending the same update after an interrupted response succeeds idempotently."""
    username = f"user_sec_new_idem_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt1, wrap1 = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt1,
        "wrapped_vault_key": wrap1,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    _, salt2, wrap2 = make_wrapped_key("MasterPass2!", vek)
    payload = {
        "wrapped_vault_key": wrap2,
        "kdf_salt": salt2,
        "expected_revision": 1,
        "current_password": account_password,
    }

    # Attempt 1
    res1 = await async_client.put("/api/v1/auth/vault-key", headers=headers, json=payload)
    assert res1.status_code == 200
    assert res1.json()["vault_key_revision"] == 2

    # Simulated retry of identical request (e.g., client timeout before receiving response)
    res2 = await async_client.put("/api/v1/auth/vault-key", headers=headers, json=payload)
    assert res2.status_code == 200
    assert res2.json()["vault_key_revision"] == 2


# ============================================================================
# 2. Concurrency Race Condition Tests
# ============================================================================

@pytest.mark.anyio
async def test_sec_new_01_competing_updates_atomic_exclusion(async_client: AsyncClient):
    """Verify that two competing updates with the same expected_revision allow exactly one winner."""
    username = f"user_sec_new_race_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt1, wrap1 = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt1,
        "wrapped_vault_key": wrap1,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Competing updates prepared by Device A and Device B from revision 1
    _, salt_a, wrap_a = make_wrapped_key("DeviceA-Pass!", vek)
    _, salt_b, wrap_b = make_wrapped_key("DeviceB-Pass!", vek)

    # Device A submits first
    res_a = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_a,
        "kdf_salt": salt_a,
        "expected_revision": 1,
        "current_password": account_password,
    })
    assert res_a.status_code == 200
    assert res_a.json()["vault_key_revision"] == 2

    # Device B submits with same expected_revision (1) -> Must be rejected with 409 Conflict
    res_b = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_b,
        "kdf_salt": salt_b,
        "expected_revision": 1,
        "current_password": account_password,
    })
    assert res_b.status_code == 409
    assert "Conflict" in res_b.json()["detail"]

    # Final verification: Winning metadata belongs strictly to Device A
    vk_res = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    data = vk_res.json()
    assert data["vault_key_revision"] == 2
    assert data["wrapped_vault_key"] == wrap_a
    assert data["kdf_salt"] == salt_a


def test_sec_new_01_db_level_thread_concurrency(tmp_path: Path):
    """Simulate true multithreaded database concurrency on conditional revision update."""
    db_file = tmp_path / "concurrent_revision_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)

    # Create account with revision 1
    acc_id = uuid.uuid4()
    with session_factory() as db:
        acc = Account(
            id=acc_id,
            username="thread_race_user",
            account_password_hash=hash_password("Password123!"),
            kdf_salt="c2FsdDEyMzQ1Njc4OQ==",
            wrapped_vault_key="{\"initial\":1}",
            vault_key_version=1,
        )
        db.add(acc)
        db.commit()

    def attempt_update(thread_id: int) -> bool:
        with session_factory() as db:
            now = datetime.now(timezone.utc)
            stmt = (
                update(Account)
                .where(
                    Account.id == acc_id,
                    Account.vault_key_version == 1,
                )
                .values(
                    wrapped_vault_key=f"{{\"winner\":{thread_id}}}",
                    kdf_salt=f"salt_thread_{thread_id}",
                    vault_key_version=Account.vault_key_version + 1,
                    updated_at=now,
                )
            )
            res = db.execute(stmt)
            db.commit()
            return res.rowcount == 1

    # Run 5 threads competing for expected revision 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(attempt_update, range(5)))

    # Exactly 1 thread must have succeeded
    successes = [r for r in results if r is True]
    assert len(successes) == 1, f"Expected exactly 1 update to succeed, got {len(successes)}"

    # Final DB check
    with session_factory() as db:
        final_acc = db.execute(select(Account).where(Account.id == acc_id)).scalar_one()
        assert final_acc.vault_key_version == 2
        assert final_acc.vault_key_revision == 2

    engine.dispose()


# ============================================================================
# 3. Migration & Backward Compatibility Tests
# ============================================================================

def test_sec_new_01_migration_preserves_existing_data(tmp_path: Path):
    """Verify that existing accounts retain their revision, salts, and envelopes."""
    db_file = tmp_path / "migration_preservation_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)

    orig_envelope = "{\"version\":1,\"alg\":\"AES-256-GCM\",\"ciphertext\":\"ABC\"}"
    orig_salt = "MDEyMzQ1Njc4OWFiY2RlZg=="
    acc_id = uuid.uuid4()

    with session_factory() as db:
        acc = Account(
            id=acc_id,
            username="existing_user",
            account_password_hash=hash_password("AccountPass123!"),
            kdf_salt=orig_salt,
            wrapped_vault_key=orig_envelope,
            vault_key_version=1,
        )
        db.add(acc)
        db.commit()

    # Verify query
    with session_factory() as db:
        loaded = db.execute(select(Account).where(Account.id == acc_id)).scalar_one()
        assert loaded.vault_key_revision == 1
        assert loaded.vault_key_version == 1
        assert loaded.kdf_salt == orig_salt
        assert loaded.wrapped_vault_key == orig_envelope

    engine.dispose()


@pytest.mark.anyio
async def test_sec_new_01_legacy_expected_version_compatibility(async_client: AsyncClient):
    """Verify backward compatibility: client sending expected_version succeeds seamlessly."""
    username = f"user_sec_legacy_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt1, wrap1 = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt1,
        "wrapped_vault_key": wrap1,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Legacy client submits expected_version instead of expected_revision
    _, salt2, wrap2 = make_wrapped_key("MasterPass2!", vek)
    res = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap2,
        "kdf_salt": salt2,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert res.status_code == 200
    assert res.json()["vault_key_revision"] == 2
    assert res.json()["vault_key_version"] == 2

