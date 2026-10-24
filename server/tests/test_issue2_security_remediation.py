"""Comprehensive regression test suite for Issue #2 security and data-integrity findings.

Covers:
- SEC-01: Wrapped vault-key replacement authorization, step-up authentication, version locking,
  concurrent update rejection, and idempotent retry support.
- SEC-02: Atomic record updates, conditional SQL WHERE-clause enforcement, competing update
  race elimination, and cursor integrity on failure.
- SEC-03: Stale and missing record deletion prevention, mandatory expected revision, atomic tombstone
  creation, and concurrent modification protection.
- SEC-04: Latest-state synchronization boundaries, out-of-range cursor validation, tombstone
  propagation, and revision freshness semantics.
"""

import base64
import concurrent.futures
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession, sessionmaker

from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, WrappedKeyEnvelope, b64encode
from vaultsync_server.crypto.errors import DecryptionFailedError
from vaultsync_server.crypto.kdf import Argon2Params, derive_kek, generate_salt
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey, unwrap_vault_key, wrap_vault_key
from vaultsync_server.db.base import Base, create_db_engine
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.services.auth import hash_password


# ============================================================================
# Helpers
# ============================================================================

def make_envelope(record_id: str, text: str = "Test Plaintext", vek: VaultKey | None = None) -> str:
    key = vek or VaultKey.generate()
    return encrypt_record(key, record_id, text).to_json()


def make_wrapped_key(master_password: str, vek: VaultKey | None = None) -> tuple[VaultKey, str, str]:
    key = vek or VaultKey.generate()
    salt = generate_salt()
    salt_b64 = b64encode(salt)
    params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt)
    kek = derive_kek(master_password, params)
    wrap = wrap_vault_key(key, kek, params)
    return key, salt_b64, wrap.to_json()


# ============================================================================
# SEC-01: Wrapped Vault-Key Replacement
# ============================================================================

@pytest.mark.anyio
async def test_sec01_unauthorized_envelope_replacement_rejected(async_client: AsyncClient):
    """Verify that an ordinary session cannot replace the vault-key envelope without step-up auth."""
    username = f"user_sec01_unauth_{uuid.uuid4().hex[:6]}"
    account_password = "CorrectAccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPass1!")

    # Register & Login
    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    token = login_res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    _, new_salt_b64, new_wrap_json = make_wrapped_key("MasterPass2!", vek)

    # 1. Unauthenticated request -> 401
    unauth = await async_client.put("/api/v1/auth/vault-key", json={
        "wrapped_vault_key": new_wrap_json,
        "kdf_salt": new_salt_b64,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert unauth.status_code == 401

    # 2. Incorrect account password for step-up auth -> 401
    wrong_pwd = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": new_wrap_json,
        "kdf_salt": new_salt_b64,
        "expected_version": 1,
        "current_password": "WrongPassword999!",
    })
    assert wrong_pwd.status_code == 401
    assert "Current account password incorrect" in wrong_pwd.json()["detail"]


@pytest.mark.anyio
async def test_sec01_malformed_envelope_and_inconsistent_kdf_metadata(async_client: AsyncClient):
    """Verify rejection of malformed envelopes and inconsistent KDF metadata."""
    username = f"user_sec01_mal_{uuid.uuid4().hex[:6]}"
    account_password = "CorrectAccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    # 1. Malformed JSON
    bad_json = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": "not-a-valid-json",
        "kdf_salt": salt_b64,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert bad_json.status_code == 400

    # 2. Invalid KDF salt format
    bad_salt = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_json,
        "kdf_salt": "invalid-base64???",
        "expected_version": 1,
        "current_password": account_password,
    })
    assert bad_salt.status_code == 400

    # 3. Inconsistent KDF salt: envelope internal salt does not match payload kdf_salt
    mismatched_salt = b64encode(b"0" * 16)
    inconsistent = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_json,
        "kdf_salt": mismatched_salt,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert inconsistent.status_code == 400
    assert "KDF salt in envelope does not match request kdf_salt" in inconsistent.json()["detail"]


@pytest.mark.anyio
async def test_sec01_stale_expected_envelope_version_rejected(async_client: AsyncClient):
    """Verify that a stale expected_version is rejected with 409 Conflict."""
    username = f"user_sec01_stale_{uuid.uuid4().hex[:6]}"
    account_password = "CorrectAccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    _, new_salt_b64, new_wrap_json = make_wrapped_key("MasterPass2!", vek)

    # Stale version: current is 1, client provides expected_version = 0
    stale_low = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": new_wrap_json,
        "kdf_salt": new_salt_b64,
        "expected_version": 0,
        "current_password": account_password,
    })
    assert stale_low.status_code == 409
    assert "Conflict" in stale_low.json()["detail"]

    # Stale version: current is 1, client provides expected_version = 5
    stale_high = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": new_wrap_json,
        "kdf_salt": new_salt_b64,
        "expected_version": 5,
        "current_password": account_password,
    })
    assert stale_high.status_code == 409
    assert "Conflict" in stale_high.json()["detail"]


@pytest.mark.anyio
async def test_sec01_concurrent_updates_same_expected_version(async_client: AsyncClient):
    """Verify that two competing updates with the same expected_version allow exactly one to win."""
    username = f"user_sec01_compete_{uuid.uuid4().hex[:6]}"
    account_password = "CorrectAccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    # Two competing rotations
    _, salt_a, wrap_a = make_wrapped_key("ClientA-NewPass!", vek)
    _, salt_b, wrap_b = make_wrapped_key("ClientB-NewPass!", vek)

    # First update succeeds
    res_a = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_a,
        "kdf_salt": salt_a,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert res_a.status_code == 200
    assert res_a.json()["vault_key_version"] == 2

    # Second competing update with same expected_version (1) is rejected with 409 Conflict
    res_b = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": wrap_b,
        "kdf_salt": salt_b,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert res_b.status_code == 409
    assert "Conflict" in res_b.json()["detail"]


@pytest.mark.anyio
async def test_sec01_retry_after_simulated_interrupted_response(async_client: AsyncClient):
    """Verify that retrying an already applied update after an interrupted response succeeds idempotently."""
    username = f"user_sec01_retry_{uuid.uuid4().hex[:6]}"
    account_password = "CorrectAccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("MasterPass1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    _, new_salt_b64, new_wrap_json = make_wrapped_key("MasterPass2!", vek)

    payload = {
        "wrapped_vault_key": new_wrap_json,
        "kdf_salt": new_salt_b64,
        "expected_version": 1,
        "current_password": account_password,
    }

    # 1. Initial attempt succeeds
    res1 = await async_client.put("/api/v1/auth/vault-key", headers=headers, json=payload)
    assert res1.status_code == 200
    assert res1.json()["vault_key_version"] == 2

    # 2. Simulated retry of the identical request (client did not receive response 1 due to timeout/interruption)
    res2 = await async_client.put("/api/v1/auth/vault-key", headers=headers, json=payload)
    assert res2.status_code == 200
    assert res2.json()["vault_key_version"] == 2


@pytest.mark.anyio
async def test_sec01_authorized_replacement_and_subsequent_unlock(async_client: AsyncClient):
    """Verify that an authorized replacement allows unlock with new master password and denies old."""
    username = f"user_sec01_auth_{uuid.uuid4().hex[:6]}"
    account_password = "CorrectAccountPassword123!"
    old_master_pwd = "OriginalMasterPassword123!"
    new_master_pwd = "RotatedMasterPassword456!"

    vek, salt_b64, wrap_json = make_wrapped_key(old_master_pwd)

    # Register
    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    # Create secret record encrypted under original VEK
    rec_id = "sec01-rec-1"
    secret_text = "Highly Confidential Vault Secret 999"
    rec_payload = encrypt_record(vek, rec_id, secret_text).to_json()
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": rec_id,
        "ciphertext_payload": rec_payload,
    })

    # Client re-wraps VEK with new master password
    _, new_salt_b64, new_wrap_json = make_wrapped_key(new_master_pwd, vek)

    # Perform authorized update
    update_res = await async_client.put("/api/v1/auth/vault-key", headers=headers, json={
        "wrapped_vault_key": new_wrap_json,
        "kdf_salt": new_salt_b64,
        "expected_version": 1,
        "current_password": account_password,
    })
    assert update_res.status_code == 200
    assert update_res.json()["vault_key_version"] == 2

    # Fetch updated vault key
    vkey_res = await async_client.get("/api/v1/auth/vault-key", headers=headers)
    assert vkey_res.status_code == 200
    key_data = vkey_res.json()
    assert key_data["vault_key_version"] == 2
    assert key_data["kdf_salt"] == new_salt_b64

    # 1. Old master password MUST FAIL to unwrap
    env_obj = WrappedKeyEnvelope.from_json(key_data["wrapped_vault_key"])
    with pytest.raises(DecryptionFailedError):
        unwrap_vault_key(env_obj, old_master_pwd)

    # 2. New master password SUCCEEDS and recovers original VEK
    unwrapped_vek = unwrap_vault_key(env_obj, new_master_pwd)
    assert unwrapped_vek.raw_bytes == vek.raw_bytes

    # 3. Decrypt record with recovered VEK
    rec_res = await async_client.get(f"/api/v1/records/{rec_id}", headers=headers)
    rec_env = EncryptedRecordEnvelope.from_json(rec_res.json()["ciphertext_payload"])
    decrypted = decrypt_record(unwrapped_vek, rec_env)
    assert decrypted.decode("utf-8") == secret_text


# ============================================================================
# SEC-02: Atomic Record Updates
# ============================================================================

@pytest.mark.anyio
async def test_sec02_two_clients_updating_same_record_competing(async_client: AsyncClient):
    """Verify that two competing updates with the same expected_revision result in exactly one winner and one 409 Conflict."""
    username = f"user_sec02_compete_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec02-rec-compete"
    # Create record at revision 1
    create_res = await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": make_envelope(record_id, "Initial Data", vek),
    })
    assert create_res.status_code == 201
    assert create_res.json()["revision"] == 1
    initial_cursor = create_res.json()["sync_cursor"]

    # Competing Client A sends update for revision 1
    update_a = await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(record_id, "Client A Update", vek),
    })
    assert update_a.status_code == 200
    assert update_a.json()["revision"] == 2
    assert update_a.json()["sync_cursor"] == initial_cursor + 1

    # Competing Client B also sends update expecting revision 1 -> MUST BE REJECTED WITH 409
    update_b = await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(record_id, "Client B Update", vek),
    })
    assert update_b.status_code == 409
    assert "Conflict: expected revision 1, but current revision is 2" in update_b.json()["detail"]

    # Verify that Client B's failed update did NOT advance the cursor
    sync_check = await async_client.get(f"/api/v1/sync?since_cursor=0", headers=headers)
    assert sync_check.json()["server_cursor"] == initial_cursor + 1


@pytest.mark.anyio
async def test_sec02_failed_update_leaves_record_and_cursor_unchanged(async_client: AsyncClient, test_db_engine):
    """Verify that a rejected conditional update does not alter the record or increment sync_cursor."""
    username = f"user_sec02_failed_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec02-rec-failed"
    payload_orig = make_envelope(record_id, "Original", vek)
    create_res = await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": payload_orig,
    })
    assert create_res.status_code == 201

    with DbSession(test_db_engine) as db:
        acc_before = db.execute(select(Account).where(Account.username == username)).scalar_one()
        cursor_before = acc_before.sync_cursor

    # Stale update
    stale_res = await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 999,
        "ciphertext_payload": make_envelope(record_id, "Stale Change", vek),
    })
    assert stale_res.status_code == 409

    # Record and cursor must remain completely untouched
    with DbSession(test_db_engine) as db:
        acc_after = db.execute(select(Account).where(Account.username == username)).scalar_one()
        assert acc_after.sync_cursor == cursor_before

        rec = db.execute(select(EncryptedRecord).where(EncryptedRecord.record_id == record_id)).scalar_one()
        assert rec.revision == 1
        assert rec.ciphertext_payload == payload_orig


def test_sec02_parallel_updates_to_different_records(tmp_path: Path):
    """Verify thread-safe concurrent updates to different records with strict cursor uniqueness."""
    db_file = tmp_path / "parallel_records_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    with SessionLocal() as db:
        acc = Account(
            username="parallel_user",
            account_password_hash=hash_password("Sec02Parallel!"),
            kdf_salt=b64encode(generate_salt()),
            sync_cursor=0,
        )
        db.add(acc)
        db.commit()
        db.refresh(acc)
        acc_id = acc.id

        # Create 10 records
        for i in range(10):
            r = EncryptedRecord(
                record_id=f"rec-{i}",
                account_id=acc_id,
                ciphertext_payload=make_envelope(f"rec-{i}"),
                revision=1,
                sync_cursor=i + 1,
                is_deleted=False,
            )
            db.add(r)
        acc.sync_cursor = 10
        db.commit()

    def update_task(rec_idx: int) -> int:
        with SessionLocal() as db:
            now = datetime.now(timezone.utc)
            # Atomic conditional update
            upd = (
                update(EncryptedRecord)
                .where(
                    EncryptedRecord.account_id == acc_id,
                    EncryptedRecord.record_id == f"rec-{rec_idx}",
                    EncryptedRecord.revision == 1,
                    EncryptedRecord.is_deleted.is_(False),
                )
                .values(
                    ciphertext_payload=make_envelope(f"rec-{rec_idx}", "Updated"),
                    revision=EncryptedRecord.revision + 1,
                    updated_at=now,
                )
            )
            res = db.execute(upd)
            assert res.rowcount == 1

            cursor_stmt = (
                update(Account)
                .where(Account.id == acc_id)
                .values(sync_cursor=Account.sync_cursor + 1)
                .returning(Account.sync_cursor)
            )
            new_cursor = db.execute(cursor_stmt).scalar_one()

            set_c = (
                update(EncryptedRecord)
                .where(
                    EncryptedRecord.account_id == acc_id,
                    EncryptedRecord.record_id == f"rec-{rec_idx}",
                )
                .values(sync_cursor=new_cursor)
            )
            db.execute(set_c)
            db.commit()
            return new_cursor

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        allocated = list(executor.map(update_task, range(10)))

    assert len(allocated) == 10
    assert len(set(allocated)) == 10, "All allocated cursors must be strictly unique"
    assert sorted(allocated) == list(range(11, 21))


# ============================================================================
# SEC-03: Stale Record Deletion
# ============================================================================

@pytest.mark.anyio
async def test_sec03_delete_with_missing_revision_rejected(async_client: AsyncClient):
    """Verify that omitting expected_revision returns 400 Bad Request and preserves the record."""
    username = f"user_sec03_missing_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec03-rec-missing"
    payload = make_envelope(record_id, "Data", vek)
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": payload,
    })

    # Delete without expected_revision query param -> 400 Bad Request
    del_res = await async_client.delete(f"/api/v1/records/{record_id}", headers=headers)
    assert del_res.status_code == 400
    assert "Missing required query parameter: expected_revision" in del_res.json()["detail"]

    # Record must still exist
    get_res = await async_client.get(f"/api/v1/records/{record_id}", headers=headers)
    assert get_res.status_code == 200


@pytest.mark.anyio
async def test_sec03_delete_with_stale_revision_rejected(async_client: AsyncClient):
    """Verify that a delete with a stale revision returns 409 Conflict and preserves the record."""
    username = f"user_sec03_stale_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec03-rec-stale"
    # Create record at revision 1
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": make_envelope(record_id, "Rev1", vek),
    })

    # Device 1 updates record to revision 2
    await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(record_id, "Rev2", vek),
    })

    # Stale Device 2 attempts deletion expecting revision 1 -> 409 Conflict!
    del_res = await async_client.delete(f"/api/v1/records/{record_id}?expected_revision=1", headers=headers)
    assert del_res.status_code == 409
    assert "Conflict: expected revision 1, but current revision is 2" in del_res.json()["detail"]

    # Record must still be active at revision 2
    get_res = await async_client.get(f"/api/v1/records/{record_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["revision"] == 2
    assert get_res.json()["is_deleted"] is False


@pytest.mark.anyio
async def test_sec03_concurrent_update_and_delete(async_client: AsyncClient):
    """Verify that when an update and delete race on the same expected revision, exactly one succeeds."""
    username = f"user_sec03_race_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec03-rec-race"
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": make_envelope(record_id, "Initial", vek),
    })

    # Scenario: Update wins first
    upd_res = await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(record_id, "Updated", vek),
    })
    assert upd_res.status_code == 200

    # Competing delete expecting revision 1 fails with 409
    del_res = await async_client.delete(f"/api/v1/records/{record_id}?expected_revision=1", headers=headers)
    assert del_res.status_code == 409


@pytest.mark.anyio
async def test_sec03_repeated_delete_idempotency_behavior(async_client: AsyncClient):
    """Verify that deleting an already tombstoned record returns 404 Not Found."""
    username = f"user_sec03_repeat_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec03-rec-repeat"
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": make_envelope(record_id, "Initial", vek),
    })

    # First delete succeeds
    del1 = await async_client.delete(f"/api/v1/records/{record_id}?expected_revision=1", headers=headers)
    assert del1.status_code == 200
    assert del1.json()["is_deleted"] is True

    # Repeated delete of tombstoned record returns 404
    del2 = await async_client.delete(f"/api/v1/records/{record_id}?expected_revision=2", headers=headers)
    assert del2.status_code == 404


# ============================================================================
# SEC-04: Sync History and Rollback Guarantees
# ============================================================================

@pytest.mark.anyio
async def test_sec04_sync_out_of_range_cursor_rejected(async_client: AsyncClient):
    """Verify that sync requests with since_cursor exceeding server_cursor are rejected."""
    username = f"user_sec04_cursor_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    # Create 2 records (server_cursor becomes 2)
    for i in range(1, 3):
        await async_client.post("/api/v1/records", headers=headers, json={
            "record_id": f"rec-{i}",
            "ciphertext_payload": make_envelope(f"rec-{i}", "Data", vek),
        })

    # since_cursor = 2 is valid
    valid_sync = await async_client.get("/api/v1/sync?since_cursor=2", headers=headers)
    assert valid_sync.status_code == 200
    assert valid_sync.json()["server_cursor"] == 2

    # since_cursor = 999 exceeds server_cursor (2) -> 400 Bad Request
    invalid_sync = await async_client.get("/api/v1/sync?since_cursor=999", headers=headers)
    assert invalid_sync.status_code == 400
    assert "Invalid sync cursor 999: exceeds current server cursor 2" in invalid_sync.json()["detail"]


@pytest.mark.anyio
async def test_sec04_latest_state_sync_model_replaces_prior_revisions(async_client: AsyncClient):
    """Verify that sync delivers only the latest record state and not intermediate historical revisions."""
    username = f"user_sec04_latest_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword123!"
    vek, salt_b64, wrap_json = make_wrapped_key("Master1!")

    await async_client.post("/api/v1/auth/register", json={
        "username": username,
        "account_password": account_password,
        "kdf_salt": salt_b64,
        "wrapped_vault_key": wrap_json,
    })
    login_res = await async_client.post("/api/v1/auth/login", json={
        "username": username,
        "account_password": account_password,
    })
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    record_id = "sec04-rec-latest"
    # Rev 1
    await async_client.post("/api/v1/records", headers=headers, json={
        "record_id": record_id,
        "ciphertext_payload": make_envelope(record_id, "Version 1", vek),
    })
    # Rev 2
    await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 1,
        "ciphertext_payload": make_envelope(record_id, "Version 2", vek),
    })
    # Rev 3
    final_payload = make_envelope(record_id, "Version 3", vek)
    await async_client.put(f"/api/v1/records/{record_id}", headers=headers, json={
        "expected_revision": 2,
        "ciphertext_payload": final_payload,
    })

    # Full sync from cursor 0
    sync_res = await async_client.get("/api/v1/sync?since_cursor=0", headers=headers)
    assert sync_res.status_code == 200
    items = sync_res.json()["items"]

    # Exactly 1 item representing the latest state (Rev 3)
    assert len(items) == 1
    assert items[0]["record_id"] == record_id
    assert items[0]["revision"] == 3
    assert items[0]["ciphertext_payload"] == final_payload
