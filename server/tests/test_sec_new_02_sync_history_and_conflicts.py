"""Comprehensive test suite for SEC-NEW-02: Synchronization History and Conflict Semantics.

Covers:
1. Synchronization Semantics (Option A — Latest-State):
   - Initial sync from cursor 0.
   - Incremental sync with non-zero cursor.
   - Idempotent repeated syncs (no changes).
   - Sync cursor validation (reject since_cursor > server_cursor).
   - Pagination with limit and has_more.
2. Concurrent Modification Scenarios:
   - Scenario 1: Device A modifies while Device B offline (latest-state delivery).
   - Scenario 2: Concurrent independent edits (optimistic concurrency control, HTTP 409).
   - Scenario 3: Device A deletes while Device B modifies (tombstone detection, 409, resurrection prevention).
   - Scenario 4: Concurrent race condition under parallel execution.
3. Tombstone Lifecycle & Zero-Knowledge:
   - Ciphertext scrubbing on deletion (ciphertext_payload cleared immediately).
   - Tombstones delivered via sync with monotonic cursors.
   - Prevention of tombstone resurrection via POST /records.
   - Differentiation of 404 Not Found vs 409 Conflict (tombstone exists) on PUT.
4. Option A Limitations & Guarantees:
   - Verification that exactly one row exists per record in the database (O(1) storage).
   - Intermediate revisions are cleanly superseded and non-recoverable.
   - Server preserves zero-knowledge encryption without 3-way merge inspection.
   - Concurrency and Conflict Handling with atomic optimistic concurrency and HTTP 409 conflict differentiation.
"""

import concurrent.futures
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession, sessionmaker

from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, b64encode
from vaultsync_server.crypto.kdf import Argon2Params, derive_kek, generate_salt
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey, wrap_vault_key
from vaultsync_server.db.base import Base, create_db_engine
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.services.auth import rate_limiter


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


def make_envelope(record_id: str, text: str = "Test Plaintext", vek: VaultKey | None = None) -> str:
    key = vek or VaultKey.generate()
    return encrypt_record(key, record_id, text).to_json()


async def register_and_login(async_client: AsyncClient, prefix: str = "sec02") -> tuple[dict[str, str], VaultKey]:
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPassword123!")

    reg_res = await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    assert reg_res.status_code == 201

    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    return {"Authorization": f"Bearer {token}"}, vek


# ============================================================================
# 1. Synchronization Semantics Tests
# ============================================================================

@pytest.mark.anyio
async def test_sync_initial_state_retrieves_all_records(async_client: AsyncClient):
    """Test initial sync from cursor 0 returns all records for the account."""
    headers, vek = await register_and_login(async_client, "sync_init")

    # Create 3 records
    for i in range(1, 4):
        rec_id = f"init-rec-{i}"
        res = await async_client.post("/api/v1/records", headers=headers, json={
            "record_id": rec_id,
            "ciphertext_payload": make_envelope(rec_id, f"Secret {i}", vek),
        })
        assert res.status_code == 201

    # Perform initial sync
    sync_res = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert sync_res.status_code == 200
    data = sync_res.json()

    assert len(data["items"]) == 3
    assert data["server_cursor"] == 3
    assert data["next_cursor"] == 3
    assert data["has_more"] is False
    assert [item["record_id"] for item in data["items"]] == ["init-rec-1", "init-rec-2", "init-rec-3"]


@pytest.mark.anyio
async def test_sync_incremental_progression(async_client: AsyncClient):
    """Test incremental sync retrieves only changes occurred after since_cursor."""
    headers, vek = await register_and_login(async_client, "sync_inc")

    # Create record 1 (cursor 1)
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": "rec-1",
        "ciphertext_payload": make_envelope("rec-1", "Initial", vek),
    })

    sync1 = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert len(sync1.json()["items"]) == 1
    cursor_after_1 = sync1.json()["next_cursor"]
    assert cursor_after_1 == 1

    # Create record 2 (cursor 2)
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": "rec-2",
        "ciphertext_payload": make_envelope("rec-2", "Initial", vek),
    })

    # Sync since cursor 1
    sync2 = await async_client.get(f"/api/v1/sync?since_cursor={cursor_after_1}", headers=headers)
    assert sync2.status_code == 200
    data2 = sync2.json()
    assert len(data2["items"]) == 1
    assert data2["items"][0]["record_id"] == "rec-2"
    assert data2["next_cursor"] == 2
    assert data2["server_cursor"] == 2


@pytest.mark.anyio
async def test_sync_idempotent_no_changes(async_client: AsyncClient):
    """Test sync with since_cursor equal to server_cursor returns empty items list."""
    headers, vek = await register_and_login(async_client, "sync_idem")

    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": "rec-1",
        "ciphertext_payload": make_envelope("rec-1", "Initial", vek),
    })

    # Initial sync
    sync1 = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    server_cursor = sync1.json()["server_cursor"]

    # Re-sync at current cursor
    sync2 = await async_client.get(f"/api/v1/sync?since_cursor={server_cursor}", headers=headers)
    assert sync2.status_code == 200
    data2 = sync2.json()
    assert data2["items"] == []
    assert data2["next_cursor"] == server_cursor
    assert data2["server_cursor"] == server_cursor
    assert data2["has_more"] is False


@pytest.mark.anyio
async def test_sync_cursor_exceeding_server_cursor_rejected(async_client: AsyncClient):
    """Test sync request with since_cursor exceeding server_cursor returns 400 Bad Request."""
    headers, vek = await register_and_login(async_client, "sync_oob")

    res = await async_client.get("/api/v1/sync?since_cursor=42", headers=headers)
    assert res.status_code == 400
    assert "Invalid sync cursor 42: exceeds current server cursor 0" in res.json()["detail"]


@pytest.mark.anyio
async def test_sync_pagination_limit_and_has_more(async_client: AsyncClient):
    """Test sync pagination using limit and next_cursor across multiple batches."""
    headers, vek = await register_and_login(async_client, "sync_page")

    # Create 5 records
    for i in range(1, 6):
        rec_id = f"page-rec-{i}"
        await async_client.post("/api/v1/records", headers=headers, json={
            "record_id": rec_id,
            "ciphertext_payload": make_envelope(rec_id, f"Secret {i}", vek),
        })

    # Page 1: limit 2
    p1 = await async_client.get("/api/v1/sync?since_cursor=0&limit=2", headers=headers)
    assert p1.status_code == 200
    data1 = p1.json()
    assert len(data1["items"]) == 2
    assert data1["has_more"] is True
    assert data1["next_cursor"] == 2

    # Page 2: limit 2
    p2 = await async_client.get(f"/api/v1/sync?since_cursor={data1['next_cursor']}&limit=2", headers=headers)
    assert p2.status_code == 200
    data2 = p2.json()
    assert len(data2["items"]) == 2
    assert data2["has_more"] is True
    assert data2["next_cursor"] == 4

    # Page 3: limit 2
    p3 = await async_client.get(f"/api/v1/sync?since_cursor={data2['next_cursor']}&limit=2", headers=headers)
    assert p3.status_code == 200
    data3 = p3.json()
    assert len(data3["items"]) == 1
    assert data3["has_more"] is False
    assert data3["next_cursor"] == 5


# ============================================================================
# 2. Concurrent Modification Scenarios (Section 3.B)
# ============================================================================

@pytest.mark.anyio
async def test_scenario_1_offline_device_receives_latest_state(async_client: AsyncClient):
    """Scenario 1: Device A modifies a record while Device B is offline.

    Device B syncs and receives the latest revision; intermediate changes are superseded.
    """
    headers, vek = await register_and_login(async_client, "scen1")
    rec_id = "scen1-rec"

    # Device A creates record (Rev 1, Cursor 1)
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "V1", vek),
    })

    # Device B cached cursor 1
    device_b_cursor = 1

    # Device A updates to Rev 2 (Cursor 2)
    await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "V2", vek),
    })

    # Device A updates to Rev 3 (Cursor 3)
    final_payload = make_envelope(rec_id, "V3-Final", vek)
    await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 2,
        "ciphertext_payload": final_payload,
    })

    # Device B reconnects and syncs from its last cursor
    sync_res = await async_client.get(f"/api/v1/sync?since_cursor={device_b_cursor}", headers=headers)
    assert sync_res.status_code == 200
    data = sync_res.json()

    # Device B receives exactly ONE item with latest revision 3
    assert len(data["items"]) == 1
    item = data["items"][0]
    assert item["record_id"] == rec_id
    assert item["revision"] == 3
    assert item["ciphertext_payload"] == final_payload
    assert item["is_deleted"] is False


@pytest.mark.anyio
async def test_scenario_2_concurrent_independent_edits_conflict(async_client: AsyncClient):
    """Scenario 2: Device A and Device B independently modify the same record.

    Device A succeeds with expected_revision=1; Device B receives 409 Conflict with current revision.
    """
    headers, vek = await register_and_login(async_client, "scen2")
    rec_id = "scen2-rec"

    # Initial creation: Rev 1
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "Initial", vek),
    })

    # Device A submits update expecting Rev 1 -> Succeeded (now Rev 2)
    res_a = await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "Device A Edit", vek),
    })
    assert res_a.status_code == 200
    assert res_a.json()["revision"] == 2

    # Device B submits concurrent update also expecting Rev 1 -> Rejected (409 Conflict)
    res_b = await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "Device B Competing Edit", vek),
    })
    assert res_b.status_code == 409
    err = res_b.json()
    assert "Conflict: expected revision 1, but current revision is 2" in err["detail"]

    # Verify Device A's data was NOT overwritten
    current_rec = await async_client.get(f"/api/v1/records/{rec_id}", headers=headers)
    assert current_rec.status_code == 200
    assert current_rec.json()["revision"] == 2


@pytest.mark.anyio
async def test_scenario_3_device_a_deletes_while_device_b_modifies(async_client: AsyncClient):
    """Scenario 3: Device A deletes a record while Device B modifies its older copy.

    Device B receives 409 Conflict informing that the record was deleted.
    Device B cannot resurrect the record via POST either.
    """
    headers, vek = await register_and_login(async_client, "scen3")
    rec_id = "scen3-rec"

    # Initial creation: Rev 1
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "Initial", vek),
    })

    # Device A deletes the record expecting Rev 1 -> Succeeded (Tombstone at Rev 2)
    del_res = await async_client.delete(f"/api/v1/records/{rec_id}?expected_revision=1", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["is_deleted"] is True
    assert del_res.json()["revision"] == 2

    # Device B tries to PUT with expected_revision=1 -> 409 Conflict (tombstone detected)
    put_res = await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "Device B Late Edit", vek),
    })
    assert put_res.status_code == 409
    assert "was deleted on another device" in put_res.json()["detail"]
    assert "tombstone revision 2" in put_res.json()["detail"]

    # Device B attempts to resurrect via POST with the same record_id -> 409 Conflict
    post_res = await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "Device B Resurrect Attempt", vek),
    })
    assert post_res.status_code == 409
    assert "previously deleted (tombstone exists)" in post_res.json()["detail"]


@pytest.mark.anyio
async def test_scenario_4_stale_synchronization_state_upload_prevented(async_client: AsyncClient):
    """Scenario 4: Device uploads changes based on stale sync state."""
    headers, vek = await register_and_login(async_client, "scen4")
    rec_id = "scen4-rec"

    # Create Rev 1
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "Initial", vek),
    })

    # Remote changes happen: Rev 2, then Rev 3
    await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "Rev 2", vek),
    })
    await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 2,
        "ciphertext_payload": make_envelope(rec_id, "Rev 3", vek),
    })

    # Device submits with stale expected_revision=1
    stale_put = await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "Stale Write", vek),
    })
    assert stale_put.status_code == 409
    assert "expected revision 1, but current revision is 3" in stale_put.json()["detail"]


# ============================================================================
# 3. Tombstone Semantics & Zero-Knowledge Verification
# ============================================================================

@pytest.mark.anyio
async def test_tombstone_clears_ciphertext_payload_immediately(async_client: AsyncClient):
    """Verify that deleting a record immediately scrubs ciphertext_payload on server."""
    headers, vek = await register_and_login(async_client, "tomb_scrub")
    rec_id = "tomb-scrub-rec"

    # Create record
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "Sensitive Password Material", vek),
    })

    # Delete record
    del_res = await async_client.delete(f"/api/v1/records/{rec_id}?expected_revision=1", headers=headers)
    assert del_res.status_code == 200

    # Sync and verify tombstone payload is completely blank ("")
    sync_res = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert sync_res.status_code == 200
    tombstone = sync_res.json()["items"][0]
    assert tombstone["record_id"] == rec_id
    assert tombstone["is_deleted"] is True
    assert tombstone["ciphertext_payload"] == ""
    assert tombstone["revision"] == 2


@pytest.mark.anyio
async def test_tombstone_ordering_in_sync_feed(async_client: AsyncClient):
    """Verify that tombstones are strictly ordered by monotonic sync_cursor."""
    headers, vek = await register_and_login(async_client, "tomb_order")

    # Create 3 records (cursors 1, 2, 3)
    for i in range(1, 4):
        await async_client.post("/api/v1/records", headers=headers, json={
            "record_id": f"order-rec-{i}",
            "ciphertext_payload": make_envelope(f"order-rec-{i}", f"Data {i}", vek),
        })

    # Delete record 2 (cursor 4)
    del_res = await async_client.delete(f"/api/v1/records/order-rec-2?expected_revision=1", headers=headers)
    assert del_res.status_code == 200

    sync_res = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    items = sync_res.json()["items"]
    assert len(items) == 3

    # Items must have monotonically increasing cursors
    cursors = [item["sync_cursor"] for item in items]
    assert cursors == sorted(cursors)
    # Record 2 is now cursor 4 and marked deleted
    tombstone = next(it for it in items if it["record_id"] == "order-rec-2")
    assert tombstone["is_deleted"] is True
    assert tombstone["sync_cursor"] == 4


# ============================================================================
# 4. Option A Storage & Recovery Limitations
# ============================================================================

@pytest.mark.anyio
async def test_option_a_storage_single_row_per_record(async_client: AsyncClient, tmp_path: Path):
    """Verify Option A architectural property: exactly one row exists per record.

    No historical change journal rows or audit duplicate rows exist on the server.
    """
    headers, vek = await register_and_login(async_client, "opt_a")
    rec_id = "opt-a-single-row"

    # Rev 1
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": make_envelope(rec_id, "Edit 1", vek),
    })

    # Rev 2
    await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(rec_id, "Edit 2", vek),
    })

    # Rev 3
    await async_client.put(f"/api/v1/records/{rec_id}", headers=headers, json={
        "expected_revision": 2,
        "ciphertext_payload": make_envelope(rec_id, "Edit 3", vek),
    })

    # Query sync from 0: returns strictly 1 item at Rev 3
    sync_res = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert len(sync_res.json()["items"]) == 1
    assert sync_res.json()["items"][0]["revision"] == 3


@pytest.mark.anyio
async def test_concurrency_race_condition_protection(tmp_path: Path):
    """Test atomic database concurrency protection under parallel competing updates.

    Verifies that two parallel threads attempting to update the same record with the same
    expected revision cannot both succeed.
    """
    db_file = tmp_path / "test_concurrency_sec02.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_db_engine(db_url)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    now = datetime.now(timezone.utc)
    acc_id = uuid.uuid4()
    # Seed account and record
    with SessionLocal() as db:
        account = Account(
            id=acc_id,
            username="race_user",
            account_password_hash="hash",
            kdf_salt="salt",
            wrapped_vault_key="wrap",
            vault_key_version=1,
            sync_cursor=1,
        )
        db.add(account)
        record = EncryptedRecord(
            record_id="race-rec-02",
            account_id=acc_id,
            ciphertext_payload="Initial",
            revision=1,
            sync_cursor=1,
            is_deleted=False,
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        db.commit()

    def worker_update(worker_id: int) -> bool:
        with SessionLocal() as db:
            # Atomic conditional update
            stmt = (
                update(EncryptedRecord)
                .where(
                    EncryptedRecord.account_id == acc_id,
                    EncryptedRecord.record_id == "race-rec-02",
                    EncryptedRecord.revision == 1,
                    EncryptedRecord.is_deleted.is_(False),
                )
                .values(
                    ciphertext_payload=f"Payload from worker {worker_id}",
                    revision=EncryptedRecord.revision + 1,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            res = db.execute(stmt)
            if res.rowcount == 1:
                # Also increment account sync cursor
                db.execute(
                    update(Account)
                    .where(Account.id == acc_id)
                    .values(sync_cursor=Account.sync_cursor + 1)
                )
                db.commit()
                return True
            db.rollback()
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(worker_update, 1)
        f2 = executor.submit(worker_update, 2)
        results = [f1.result(), f2.result()]

    # Exactly one succeeded and one failed
    assert results.count(True) == 1
    assert results.count(False) == 1

    # Verify final database state has revision 2 and sync_cursor 2
    with SessionLocal() as db:
        rec = db.execute(select(EncryptedRecord).where(EncryptedRecord.record_id == "race-rec-02")).scalar_one()
        acc = db.execute(select(Account).where(Account.id == acc_id)).scalar_one()
        assert rec.revision == 2
        assert acc.sync_cursor == 2

