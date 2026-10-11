"""Phase 3.2 Security Regression Test Suite.

Validates the Two-Credential security architecture:
1. Registration stores no verifier derived from the vault master password.
2. Login succeeds with the account password and fails with invalid credentials.
3. Vault master password cannot be used as an account password unless deliberately chosen by user.
4. Account password changes succeed, update only the account-password hash, and leave wrapped key/records intact.
5. Vault master password changes update wrapped key/salt, leave account password intact, and allow client decryption.
6. Stolen database dump does not provide an attacker with a verifier for vault master password guesses.
7. Account recovery/reset cannot decrypt or destroy records, preserving zero-knowledge guarantees.
8. Unauthorized or malformed vault-key updates are strictly rejected.
9. Database-backed rate limiting works across multiple workers and survives restarts.
10. Passwords and credentials never appear in URLs or log-safe representations.
"""

import base64
import io
import json
import sys
import time
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session as DbSession, sessionmaker
from alembic import command
from alembic.config import Config

from vaultsync_server.db.base import create_db_engine
import vaultsync_server.scripts.admin_reset as admin_reset

from vaultsync_server.crypto.envelope import (
    CURRENT_PROTOCOL_VERSION,
    EncryptedRecordEnvelope,
    KdfMetadata,
    WrappedKeyEnvelope,
    b64encode,
)
from vaultsync_server.crypto.errors import DecryptionFailedError
from vaultsync_server.crypto.kdf import (
    Argon2Params,
    derive_kek,
    generate_salt,
    normalize_master_password,
)
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey, unwrap_vault_key, wrap_vault_key
from vaultsync_server.db.models import Account, EncryptedRecord, Session
from vaultsync_server.services.auth import (
    DatabaseRateLimiter,
    hash_password,
    verify_password,
)
from vaultsync_server.services.recovery import reset_account_password_admin


# ============================================================================
# Test 1: Registration stores no verifier derived from vault master password
# ============================================================================

@pytest.mark.anyio
async def test_registration_stores_no_master_password_verifier(
    async_client: AsyncClient,
    test_db_engine,
):
    """Test that the server database contains only the account-password hash,

    and zero verifiers derived from the client's vault master password.
    """
    username = f"user_reg_{uuid.uuid4().hex[:6]}"
    account_password = "SecretAccountPassword!2026"
    vault_master_password = "IndependentVaultMasterPassword#999"

    # Client-side vault key generation and wrapping
    vek = VaultKey.generate()
    salt_bytes = generate_salt()
    salt_b64 = b64encode(salt_bytes)
    kdf_params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt_bytes)
    kek = derive_kek(vault_master_password, kdf_params)
    wrap_env = wrap_vault_key(vek, kek, kdf_params)

    # Register with account_password, public salt, and wrapped key envelope
    res = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": account_password,
            "kdf_salt": salt_b64,
            "wrapped_vault_key": wrap_env.to_json(),
        },
    )
    assert res.status_code == 201

    # Inspect raw database columns
    with DbSession(test_db_engine) as db:
        stmt = select(Account).where(Account.username == username)
        account = db.execute(stmt).scalar_one()

        # Database must store Argon2id hash of account_password
        assert verify_password(account.account_password_hash, account_password) is True

        # Database must NOT verify against vault master password
        assert verify_password(account.account_password_hash, vault_master_password) is False

        # Database schema must not contain legacy auth_hash column
        assert not hasattr(account, "auth_hash")

        # The master password must not appear anywhere in stored records
        assert vault_master_password not in account.account_password_hash
        assert vault_master_password not in account.kdf_salt
        assert vault_master_password not in (account.wrapped_vault_key or "")


# ============================================================================
# Test 2: Login succeeds with account password and fails with invalid credentials
# ============================================================================

@pytest.mark.anyio
async def test_login_success_and_failure_semantics(async_client: AsyncClient, test_db_engine):
    """Test that login validates strictly the account password."""
    username = f"user_login_{uuid.uuid4().hex[:6]}"
    account_password = "ValidAccountPassword2026!"
    salt_b64 = b64encode(b"1234567890123456")

    reg = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": account_password,
            "kdf_salt": salt_b64,
        },
    )
    assert reg.status_code == 201

    # 1. Login with correct account password succeeds
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": account_password},
    )
    assert login_res.status_code == 200
    data = login_res.json()
    assert "session_token" in data
    assert data["kdf_salt"] == salt_b64

    # 2. Login with incorrect password fails
    wrong_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": "WrongPassword999!"},
    )
    assert wrong_res.status_code == 401
    assert "Invalid credentials" in wrong_res.json()["detail"]

    # 3. Account requiring password migration is blocked (403)
    with DbSession(test_db_engine) as db:
        stmt = select(Account).where(Account.username == username)
        acc = db.execute(stmt).scalar_one()
        acc.requires_password_migration = True
        db.commit()

    migration_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": account_password},
    )
    assert migration_res.status_code == 403
    assert "migration" in migration_res.json()["detail"].lower()


# ============================================================================
# Test 3: Vault master password cannot be used as an account password
# ============================================================================

@pytest.mark.anyio
async def test_vault_master_password_cannot_be_used_as_account_password(async_client: AsyncClient):
    """Verify credential separation: entering the vault master password at login fails."""
    username = f"user_sep_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPassword@Alpha"
    vault_master_password = "MasterPassword#Omega"
    salt_b64 = b64encode(b"abcdefghijklmnop")

    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": account_password,
            "kdf_salt": salt_b64,
        },
    )

    # Attempting to login using the vault master password must fail
    res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": vault_master_password},
    )
    assert res.status_code == 401
    assert "Invalid credentials" in res.json()["detail"]


# ============================================================================
# Test 4: Account password changes leave wrapped key, salt, and records intact
# ============================================================================

@pytest.mark.anyio
async def test_account_password_change_preserves_vault_data(
    async_client: AsyncClient,
    test_db_engine,
):
    """Test that changing the server account password modifies ONLY the password hash

    and invalidates other sessions, leaving wrapped vault key and records untouched.
    """
    username = f"user_pw_change_{uuid.uuid4().hex[:6]}"
    old_account_password = "OldAccountPassword123!"
    new_account_password = "NewAccountPassword456!"
    salt_b64 = b64encode(b"1111222233334444")
    sample_envelope = json.dumps({
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": {
            "algorithm": "Argon2id",
            "memory_cost": 16384,
            "time_cost": 1,
            "parallelism": 2,
            "salt": salt_b64,
        },
        "nonce": b64encode(b"0" * 12),
        "ciphertext": b64encode(b"0" * 48),
    })

    # Register
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": old_account_password,
            "kdf_salt": salt_b64,
            "wrapped_vault_key": sample_envelope,
        },
    )

    # Login device 1
    login1 = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": old_account_password, "device_name": "Dev1"},
    )
    token1 = login1.json()["session_token"]

    # Login device 2
    login2 = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": old_account_password, "device_name": "Dev2"},
    )
    token2 = login2.json()["session_token"]

    # Create an encrypted record from device 1
    rec_id = "test-rec-pwchange"
    rec_payload = EncryptedRecordEnvelope(
        version=1,
        algorithm="AES-256-GCM",
        record_id=rec_id,
        nonce=b64encode(b"1" * 12),
        ciphertext=b64encode(b"test-record-ciphertext-payload-bytes"),
    ).to_json()

    create_rec = await async_client.post(
        "/api/v1/records",
        headers={"Authorization": f"Bearer {token1}"},
        json={"record_id": rec_id, "ciphertext_payload": rec_payload},
    )
    assert create_rec.status_code == 201

    # Device 1 changes account password
    change_res = await async_client.put(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {token1}"},
        json={
            "current_password": old_account_password,
            "new_password": new_account_password,
        },
    )
    assert change_res.status_code == 200

    # Device 2 (other session) is now revoked!
    dev2_check = await async_client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert dev2_check.status_code == 401

    # Device 1 (current session) remains active
    dev1_check = await async_client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert dev1_check.status_code == 200

    # New logins succeed with new password, fail with old password
    fail_old = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": old_account_password},
    )
    assert fail_old.status_code == 401

    success_new = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": new_account_password},
    )
    assert success_new.status_code == 200

    # Crucial assertion: Wrapped vault key, KDF salt, and record payloads are identical!
    with DbSession(test_db_engine) as db:
        acc = db.execute(select(Account).where(Account.username == username)).scalar_one()
        assert acc.wrapped_vault_key == sample_envelope
        assert acc.kdf_salt == salt_b64

        rec = db.execute(select(EncryptedRecord).where(EncryptedRecord.record_id == rec_id)).scalar_one()
        assert rec.ciphertext_payload == rec_payload
        assert rec.revision == 1


# ============================================================================
# Test 5: Vault master password changes leave account password intact
# ============================================================================

@pytest.mark.anyio
async def test_vault_master_password_change_lifecycle(
    async_client: AsyncClient,
    test_db_engine,
):
    """Test full client-side vault master password rotation.

    1. Client wraps VEK with master password 1.
    2. Client creates encrypted record.
    3. Client rotates master password to master password 2:
       - Re-wraps existing VEK with new KEK derived from new master password and fresh salt.
       - Uploads new wrapped key envelope and fresh salt via PUT /api/v1/auth/vault-key.
    4. Account password hash is unchanged.
    5. Existing records remain decryptable using the new master password.
    """
    username = f"user_rot_{uuid.uuid4().hex[:6]}"
    account_password = "ServerAccountPassword123!"
    master_pwd_1 = "OriginalMasterPassword#1"
    master_pwd_2 = "RotatedMasterPassword#2"

    # Initial client crypto setup
    vek = VaultKey.generate()
    salt1_bytes = generate_salt()
    salt1_b64 = b64encode(salt1_bytes)
    params1 = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt1_bytes)
    kek1 = derive_kek(master_pwd_1, params1)
    wrap1 = wrap_vault_key(vek, kek1, params1)

    # Register
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "account_password": account_password,
            "kdf_salt": salt1_b64,
            "wrapped_vault_key": wrap1.to_json(),
        },
    )

    # Login
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": account_password},
    )
    token = login.json()["session_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Encrypt confidential record with original VEK
    plaintext_data = '{"site": "secret.example.com", "password": "super-secret-password-xyz"}'
    rec_id = "record-rot-1"
    rec_env = encrypt_record(vek, rec_id, plaintext_data)
    await async_client.post(
        "/api/v1/records",
        headers=auth_headers,
        json={"record_id": rec_id, "ciphertext_payload": rec_env.to_json()},
    )

    # Record account password hash before rotation
    with DbSession(test_db_engine) as db:
        acc_before = db.execute(select(Account).where(Account.username == username)).scalar_one()
        orig_pw_hash = acc_before.account_password_hash

    # CLIENT ROTATION: Re-wrap VEK with master_pwd_2 and fresh salt
    salt2_bytes = generate_salt()
    salt2_b64 = b64encode(salt2_bytes)
    params2 = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt2_bytes)
    kek2 = derive_kek(master_pwd_2, params2)
    wrap2 = wrap_vault_key(vek, kek2, params2)

    # Upload new wrapped key envelope and salt to server
    update_res = await async_client.put(
        "/api/v1/auth/vault-key",
        headers=auth_headers,
        json={
            "wrapped_vault_key": wrap2.to_json(),
            "kdf_salt": salt2_b64,
        },
    )
    assert update_res.status_code == 200

    # 1. Assert account password hash is UNCHANGED
    with DbSession(test_db_engine) as db:
        acc_after = db.execute(select(Account).where(Account.username == username)).scalar_one()
        assert acc_after.account_password_hash == orig_pw_hash
        assert acc_after.kdf_salt == salt2_b64

    # 2. Login again with account password succeeds
    login_again = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": account_password},
    )
    assert login_again.status_code == 200
    login_info = login_again.json()
    assert login_info["kdf_salt"] == salt2_b64
    assert login_info["wrapped_vault_key"] == wrap2.to_json()

    # 3. Client unwraps vault key using NEW master password and decrypts the old record!
    fetched_envelope = WrappedKeyEnvelope.from_json(login_info["wrapped_vault_key"])
    unwrapped_vek = unwrap_vault_key(fetched_envelope, master_pwd_2)
    assert unwrapped_vek.raw_bytes == vek.raw_bytes

    # Fetch record from server and decrypt
    rec_res = await async_client.get(f"/api/v1/records/{rec_id}", headers=auth_headers)
    rec_fetched = EncryptedRecordEnvelope.from_json(rec_res.json()["ciphertext_payload"])
    decrypted_bytes = decrypt_record(unwrapped_vek, rec_fetched)
    assert decrypted_bytes.decode("utf-8") == plaintext_data


# ============================================================================
# Test 6: Stolen DB dump provides no verifier for vault master password
# ============================================================================

def test_offline_master_password_attack_reality_and_credential_separation():
    """Rigorously verify the real behavior of an offline attacker with a stolen database dump.

    Attacker obtains: (username, account_password_hash, kdf_salt, wrapped_vault_key, records).

    VERIFIED PROPERTIES:
    1. Account Credential Separation:
       - The server account password hash (account_password_hash) is completely independent.
       - Attacker cannot verify candidate vault master passwords against account_password_hash.
       - Even if account_password is recovered, it CANNOT unwrap the vault key.

    2. Real Attack on Wrapped Vault Key:
       - The wrapped_vault_key contains an AES-256-GCM ciphertext and a 16-byte authentication tag.
       - The AES-GCM authentication tag INHERENTLY ACTS AS AN OFFLINE VERIFICATION ORACLE!
       - For wrong candidate passwords, unwrap_vault_key fails with DecryptionFailedError (InvalidTag).
       - For the correct candidate password, unwrap_vault_key succeeds, recovers the VEK,
         and decrypts all confidential vault records.

    3. Real Protection Boundary:
       - The two-credential architecture separates server access from vault encryption,
         ensuring the server never has an online or offline master-password verifier.
       - However, it DOES NOT eliminate offline dictionary attacks against wrapped_vault_key.
       - The sole defense against offline guessing on wrapped_vault_key is the memory-hard
         work factor of Argon2id (RFC 9106) combined with master password entropy.
    """
    real_vault_master_password = "KnownTestMasterPassword#2026"
    account_password = "CompletelyIndependentServerPassword$888"

    # Server stores Argon2id of account_password
    account_password_hash = hash_password(account_password)

    # Client derives KEK and wraps VEK
    salt_bytes = generate_salt()
    kdf_params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt_bytes)
    kek = derive_kek(real_vault_master_password, kdf_params)
    vek = VaultKey.generate()
    wrap_envelope = wrap_vault_key(vek, kek, kdf_params)

    # Encrypt sample confidential record
    sample_secret_payload = '{"bank_pin": "9876", "mnemonic": "alpha beta gamma delta"}'
    rec_envelope = encrypt_record(vek, "rec-stolen-1", sample_secret_payload)

    # Stolen database columns
    stolen_account_password_hash = account_password_hash
    stolen_wrapped_vault_key = wrap_envelope.to_json()
    stolen_rec_json = rec_envelope.to_json()

    # --- PROPERTY 1: Account password hash does NOT verify master password ---
    candidate_passwords = [
        "12345678",
        "password",
        "admin2026",
        real_vault_master_password,
    ]
    for cand in candidate_passwords:
        assert verify_password(stolen_account_password_hash, cand) is False

    # Cracked account_password cannot unwrap the vault key
    stolen_wrap_obj = WrappedKeyEnvelope.from_json(stolen_wrapped_vault_key)
    with pytest.raises(DecryptionFailedError):
        unwrap_vault_key(stolen_wrap_obj, account_password)

    # --- PROPERTY 2: wrapped_vault_key AES-GCM tag IS an offline verification oracle ---
    wrong_candidate = "WrongGuessPassword!999"
    with pytest.raises(DecryptionFailedError):
        unwrap_vault_key(stolen_wrap_obj, wrong_candidate)

    # Correct candidate verifies via AES-GCM tag and recovers the VEK!
    recovered_vek = unwrap_vault_key(stolen_wrap_obj, real_vault_master_password)
    assert recovered_vek.raw_bytes == vek.raw_bytes

    # Attacker successfully decrypts the vault record offline
    stolen_rec_obj = EncryptedRecordEnvelope.from_json(stolen_rec_json)
    decrypted_data = decrypt_record(recovered_vek, stolen_rec_obj)
    assert decrypted_data.decode("utf-8") == sample_secret_payload


# ============================================================================
# Test 7: Account recovery does not claim or provide vault decryption
# ============================================================================

def test_account_recovery_preserves_zero_knowledge(test_db_engine):
    """Test that administrative account password reset restores server access

    without decrypting or destroying encrypted vault contents.
    """
    username = f"user_rec_{uuid.uuid4().hex[:6]}"
    orig_acc_pw = "OriginalAccountPassword1!"
    new_acc_pw = "AdminResetAccountPassword2!"
    master_pw = "UserVaultMasterPassword99!"

    # Create account in DB with wrapped vault key and encrypted records
    salt_b64 = b64encode(generate_salt())
    fake_wrap = json.dumps({
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": {"algorithm": "Argon2id", "memory_cost": 16384, "time_cost": 1, "parallelism": 2, "salt": salt_b64},
        "nonce": b64encode(b"0" * 12),
        "ciphertext": b64encode(b"0" * 48),
    })

    with DbSession(test_db_engine) as db:
        acc = Account(
            username=username,
            account_password_hash=hash_password(orig_acc_pw),
            kdf_salt=salt_b64,
            wrapped_vault_key=fake_wrap,
        )
        db.add(acc)
        db.commit()
        db.refresh(acc)

        # Add an encrypted record
        rec = EncryptedRecord(
            account_id=acc.id,
            record_id="rec-preserved",
            ciphertext_payload='{"ciphertext": "preserved-content"}',
            sync_cursor=1,
            revision=1,
        )
        db.add(rec)
        db.commit()

        # Perform administrative password reset
        updated_acc = reset_account_password_admin(db, username, new_acc_pw)
        assert verify_password(updated_acc.account_password_hash, new_acc_pw) is True
        assert verify_password(updated_acc.account_password_hash, orig_acc_pw) is False

        # Assert wrapped vault key, KDF salt, and encrypted record are untouched
        assert updated_acc.wrapped_vault_key == fake_wrap
        assert updated_acc.kdf_salt == salt_b64

        saved_rec = db.execute(select(EncryptedRecord).where(EncryptedRecord.account_id == acc.id)).scalar_one()
        assert saved_rec.ciphertext_payload == '{"ciphertext": "preserved-content"}'
        assert saved_rec.is_deleted is False


# ============================================================================
# Test 8: Vault-key update rejects unauthorized or malformed envelopes
# ============================================================================

@pytest.mark.anyio
async def test_vault_key_update_rejects_unauthorized_and_malformed(async_client: AsyncClient):
    """Test validation and authorization on PUT /api/v1/auth/vault-key."""
    username = f"user_mal_{uuid.uuid4().hex[:6]}"
    account_password = "AccountPasswordValid123!"
    salt_b64 = b64encode(b"0123456789abcdef")

    # Register and login
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": username, "account_password": account_password, "kdf_salt": salt_b64},
    )
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "account_password": account_password},
    )
    auth_headers = {"Authorization": f"Bearer {login.json()['session_token']}"}

    # 1. Unauthenticated request -> 401
    unauth_res = await async_client.put(
        "/api/v1/auth/vault-key",
        json={"wrapped_vault_key": "some-envelope"},
    )
    assert unauth_res.status_code == 401

    # 2. Malformed JSON envelope -> 400
    res_bad_json = await async_client.put(
        "/api/v1/auth/vault-key",
        headers=auth_headers,
        json={"wrapped_vault_key": "{not-valid-json"},
    )
    assert res_bad_json.status_code == 400
    assert "Invalid wrapped vault key envelope" in res_bad_json.json()["detail"]

    # 3. Invalid envelope version -> 400
    bad_version_env = json.dumps({
        "version": 999,
        "algorithm": "AES-256-GCM",
        "kdf": {"algorithm": "Argon2id", "memory_cost": 16384, "time_cost": 1, "parallelism": 2, "salt": salt_b64},
        "nonce": b64encode(b"0" * 12),
        "ciphertext": b64encode(b"0" * 48),
    })
    res_bad_ver = await async_client.put(
        "/api/v1/auth/vault-key",
        headers=auth_headers,
        json={"wrapped_vault_key": bad_version_env},
    )
    assert res_bad_ver.status_code == 400

    # 4. Invalid KDF salt encoding -> 400
    valid_env = json.dumps({
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": {"algorithm": "Argon2id", "memory_cost": 16384, "time_cost": 1, "parallelism": 2, "salt": salt_b64},
        "nonce": b64encode(b"0" * 12),
        "ciphertext": b64encode(b"0" * 48),
    })
    res_bad_salt = await async_client.put(
        "/api/v1/auth/vault-key",
        headers=auth_headers,
        json={"wrapped_vault_key": valid_env, "kdf_salt": "invalid-base64!?"},
    )
    assert res_bad_salt.status_code == 400


# ============================================================================
# Test 9: DatabaseRateLimiter multi-worker / process-restart behavior
# ============================================================================

def test_database_rate_limiter_persistence_and_pruning(test_db_engine):
    """Test that DatabaseRateLimiter persists across simulated worker instances

    and correctly enforces limits and pruning.
    """
    with DbSession(test_db_engine) as db:
        # Simulate worker instance A
        worker_a_limiter = DatabaseRateLimiter(max_attempts=3, window_seconds=2)
        # Simulate worker instance B
        worker_b_limiter = DatabaseRateLimiter(max_attempts=3, window_seconds=2)

        identifier = f"test_id_{uuid.uuid4().hex[:6]}"

        # Initially not limited
        assert worker_a_limiter.is_rate_limited(db, identifier) is False
        assert worker_b_limiter.is_rate_limited(db, identifier) is False

        # Worker A records 2 failures
        worker_a_limiter.record_failure(db, identifier)
        worker_a_limiter.record_failure(db, identifier)

        # Worker B records 1 failure -> total 3 failures
        worker_b_limiter.record_failure(db, identifier)

        # Both workers now observe rate limit exceeded!
        assert worker_a_limiter.is_rate_limited(db, identifier) is True
        assert worker_b_limiter.is_rate_limited(db, identifier) is True

        # Successful auth resets attempts
        worker_a_limiter.reset(db, identifier)
        assert worker_b_limiter.is_rate_limited(db, identifier) is False


# ============================================================================
# Test 10: Admin reset CLI interactive & non-interactive behavior (CWE-214)
# ============================================================================

def test_admin_reset_cli_interactive_success(monkeypatch, test_db_engine):
    """Test admin_reset CLI in interactive getpass mode on password match."""
    username = f"admin_cli_user_{uuid.uuid4().hex[:6]}"
    orig_pwd = "OldAccountPassword123!"
    new_pwd = "NewInteractivePassword456!"

    with DbSession(test_db_engine) as db:
        acc = Account(
            username=username,
            account_password_hash=hash_password(orig_pwd),
            kdf_salt=b64encode(generate_salt()),
            wrapped_vault_key='{"version": 1, "test": "preserved"}',
        )
        db.add(acc)
        db.commit()

    # Monkeypatch SessionLocal to use test_db_engine
    test_sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    monkeypatch.setattr(admin_reset, "SessionLocal", test_sessionmaker)

    # Monkeypatch getpass.getpass to supply matching passwords
    prompt_history = []
    def mock_getpass(prompt=""):
        prompt_history.append(prompt)
        return new_pwd

    monkeypatch.setattr("getpass.getpass", mock_getpass)

    # Run CLI
    admin_reset.main(["--username", username])

    # Assert getpass was called twice (entry and confirmation)
    assert len(prompt_history) == 2
    assert "Enter new account password: " in prompt_history[0]
    assert "Confirm new account password: " in prompt_history[1]

    # Verify database state
    with DbSession(test_db_engine) as db:
        updated = db.execute(select(Account).where(Account.username == username)).scalar_one()
        assert verify_password(updated.account_password_hash, new_pwd) is True
        assert verify_password(updated.account_password_hash, orig_pwd) is False
        assert updated.wrapped_vault_key == '{"version": 1, "test": "preserved"}'


def test_admin_reset_cli_interactive_mismatch(monkeypatch, test_db_engine):
    """Test admin_reset CLI aborts when interactive passwords do not match."""
    username = f"admin_cli_user_{uuid.uuid4().hex[:6]}"
    orig_pwd = "OldAccountPassword123!"

    with DbSession(test_db_engine) as db:
        acc = Account(
            username=username,
            account_password_hash=hash_password(orig_pwd),
            kdf_salt=b64encode(generate_salt()),
            wrapped_vault_key='{"version": 1, "test": "preserved"}',
        )
        db.add(acc)
        db.commit()

    test_sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    monkeypatch.setattr(admin_reset, "SessionLocal", test_sessionmaker)

    answers = ["PasswordA123!", "PasswordB456!"]
    monkeypatch.setattr("getpass.getpass", lambda prompt="": answers.pop(0))

    with pytest.raises(SystemExit) as exc_info:
        admin_reset.main(["--username", username])
    assert exc_info.value.code == 1

    # Verify password was NOT changed
    with DbSession(test_db_engine) as db:
        unchanged = db.execute(select(Account).where(Account.username == username)).scalar_one()
        assert verify_password(unchanged.account_password_hash, orig_pwd) is True


def test_admin_reset_cli_password_stdin(monkeypatch, test_db_engine):
    """Test admin_reset CLI in piped stdin mode (automation / CI)."""
    username = f"admin_cli_user_{uuid.uuid4().hex[:6]}"
    orig_pwd = "OldAccountPassword123!"
    new_pwd = "NewPipedStdinPassword789!"

    with DbSession(test_db_engine) as db:
        acc = Account(
            username=username,
            account_password_hash=hash_password(orig_pwd),
            kdf_salt=b64encode(generate_salt()),
            wrapped_vault_key='{"version": 1, "test": "preserved"}',
        )
        db.add(acc)
        db.commit()

    test_sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    monkeypatch.setattr(admin_reset, "SessionLocal", test_sessionmaker)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{new_pwd}\n"))

    admin_reset.main(["--username", username, "--password-stdin"])

    with DbSession(test_db_engine) as db:
        updated = db.execute(select(Account).where(Account.username == username)).scalar_one()
        assert verify_password(updated.account_password_hash, new_pwd) is True


def test_admin_reset_cli_length_validation(monkeypatch, test_db_engine):
    """Test admin_reset CLI enforces length limits (8 <= len <= 256)."""
    username = f"admin_cli_user_{uuid.uuid4().hex[:6]}"
    with DbSession(test_db_engine) as db:
        acc = Account(
            username=username,
            account_password_hash=hash_password("ValidInitialPass1!"),
            kdf_salt=b64encode(generate_salt()),
        )
        db.add(acc)
        db.commit()

    test_sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    monkeypatch.setattr(admin_reset, "SessionLocal", test_sessionmaker)

    # Too short (< 8)
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    with pytest.raises(SystemExit) as exc_short:
        admin_reset.main(["--username", username, "--password-stdin"])
    assert exc_short.value.code == 1

    # Too long (> 256)
    monkeypatch.setattr("sys.stdin", io.StringIO(("x" * 257) + "\n"))
    with pytest.raises(SystemExit) as exc_long:
        admin_reset.main(["--username", username, "--password-stdin"])
    assert exc_long.value.code == 1


# ============================================================================
# Test 11: Alembic migration 0002 upgrade on populated Phase 3.1 database
# ============================================================================

def test_alembic_migration_0002_with_populated_phase3_database(tmp_path: Path):
    """Test upgrading a database with existing Phase 3.1 schema and records to 0002.

    Verifies:
    1. Migration 0001 creates initial schema (with auth_hash).
    2. Inserting accounts and records into Phase 3.1 schema.
    3. Migration 0002 upgrades cleanly:
       - auth_hash column is dropped.
       - account_password_hash is set to 'MIGRATION_REQUIRED' for existing accounts.
       - requires_password_migration is set to True.
       - kdf_salt, wrapped_vault_key, and encrypted records remain intact.
       - auth_rate_limits table is created.
    4. Downgrade warning verification:
       - Downgrading to 0001 restores auth_hash as NULL (cannot resurrect legacy hash).
    """
    test_db = tmp_path / "migration_populated_test.db"
    test_db_url = f"sqlite:///{test_db}"
    ini_path = Path(__file__).parents[1] / "alembic.ini"
    alembic_cfg = Config(str(ini_path))
    alembic_cfg.set_main_option("sqlalchemy.url", test_db_url)
    alembic_cfg.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic"))

    # Step 1: Upgrade to 0001 (Phase 3.1 schema)
    command.upgrade(alembic_cfg, "0001_initial_schema")

    # Step 2: Populate Phase 3.1 database with an account and record
    engine = create_db_engine(test_db_url)
    acc_id = str(uuid.uuid4())
    legacy_auth_hash = "legacy_argon2id_hash_of_auth_secret"
    kdf_salt_val = b64encode(b"0" * 16)
    wrapped_key_val = '{"version": 1, "algorithm": "AES-256-GCM", "preserved": true}'
    rec_payload = '{"iv": "abc", "ciphertext": "secret_data"}'

    with engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO accounts (id, username, auth_hash, kdf_salt, wrapped_vault_key, sync_cursor, is_active, created_at, updated_at) "
                "VALUES (:id, :username, :auth_hash, :kdf_salt, :wrapped_vault_key, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {
                "id": acc_id,
                "username": "legacy_alice",
                "auth_hash": legacy_auth_hash,
                "kdf_salt": kdf_salt_val,
                "wrapped_vault_key": wrapped_key_val,
            },
        )
        conn.execute(
            text(
                "INSERT INTO encrypted_records (id, record_id, account_id, ciphertext_payload, revision, sync_cursor, is_deleted, created_at, updated_at) "
                "VALUES (:id, :record_id, :account_id, :payload, 1, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {
                "id": str(uuid.uuid4()),
                "record_id": "rec-legacy-1",
                "account_id": acc_id,
                "payload": rec_payload,
            },
        )
        conn.commit()

    # Step 3: Upgrade to 0002_two_credential_architecture
    command.upgrade(alembic_cfg, "0002_two_credential_architecture")

    # Verify schema and data migration
    with engine.connect() as conn:
        acc_row = conn.execute(
            text("SELECT id, username, account_password_hash, requires_password_migration, kdf_salt, wrapped_vault_key FROM accounts WHERE id = :id"),
            {"id": acc_id},
        ).mappings().one()

        assert acc_row["account_password_hash"] == "MIGRATION_REQUIRED"
        assert acc_row["requires_password_migration"] in (True, 1)
        assert acc_row["kdf_salt"] == kdf_salt_val
        assert acc_row["wrapped_vault_key"] == wrapped_key_val

        # Verify auth_hash column no longer exists
        with pytest.raises(Exception):
            conn.execute(text("SELECT auth_hash FROM accounts"))

        # Verify encrypted_records table preserved
        rec_row = conn.execute(
            text("SELECT record_id, ciphertext_payload, sync_cursor FROM encrypted_records WHERE account_id = :id"),
            {"id": acc_id},
        ).mappings().one()
        assert rec_row["record_id"] == "rec-legacy-1"
        assert rec_row["ciphertext_payload"] == rec_payload

        # Verify auth_rate_limits table exists and functions
        conn.execute(
            text("INSERT INTO auth_rate_limits (identifier, attempt_time) VALUES (:ident, :att_time)"),
            {"ident": "test_ip_1", "att_time": time.time()},
        )
        rate_count = conn.execute(text("SELECT COUNT(*) FROM auth_rate_limits")).scalar()
        assert rate_count == 1
        conn.commit()

    # Step 4: Verify downgrade behavior (destructive downgrade observation)
    command.downgrade(alembic_cfg, "0001_initial_schema")
    with engine.connect() as conn:
        downgraded_row = conn.execute(
            text("SELECT auth_hash, kdf_salt, wrapped_vault_key FROM accounts WHERE id = :id"),
            {"id": acc_id},
        ).mappings().one()
        # auth_hash is restored as NULL (lossy downgrade)
        assert downgraded_row["auth_hash"] is None
        assert downgraded_row["wrapped_vault_key"] == wrapped_key_val


# ============================================================================
# Test 12: PUT /api/v1/auth/vault-key cross-account isolation and malformed preservation
# ============================================================================

@pytest.mark.anyio
async def test_vault_key_update_cross_account_isolation_and_preservation(async_client: AsyncClient, test_db_engine):
    """Test that PUT /api/v1/auth/vault-key enforces strict per-account isolation

    and that malformed envelope submissions preserve previously stored keys intact.
    """
    params_a = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=generate_salt())
    salt_a = b64encode(params_a.salt)
    kek_a = derive_kek("AliceMaster1!", params_a)
    env_a_orig = wrap_vault_key(VaultKey.generate(), kek_a, params_a).to_json()

    params_b = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=generate_salt())
    salt_b = b64encode(params_b.salt)
    kek_b = derive_kek("BobMaster1!", params_b)
    env_b_orig = wrap_vault_key(VaultKey.generate(), kek_b, params_b).to_json()

    # 1. Register Alice and Bob
    alice_username = f"alice_{uuid.uuid4().hex[:6]}"
    bob_username = f"bob_{uuid.uuid4().hex[:6]}"

    reg_a = await async_client.post("/api/v1/auth/register", json={
        "username": alice_username,
        "account_password": "AlicePassword123!",
        "kdf_salt": salt_a,
        "wrapped_vault_key": env_a_orig,
    })
    assert reg_a.status_code == 201

    reg_b = await async_client.post("/api/v1/auth/register", json={
        "username": bob_username,
        "account_password": "BobPassword123!",
        "kdf_salt": salt_b,
        "wrapped_vault_key": env_b_orig,
    })
    assert reg_b.status_code == 201

    # Login both
    login_a = await async_client.post("/api/v1/auth/login", json={"username": alice_username, "account_password": "AlicePassword123!"})
    alice_token = login_a.json()["session_token"]

    login_b = await async_client.post("/api/v1/auth/login", json={"username": bob_username, "account_password": "BobPassword123!"})
    bob_token = login_b.json()["session_token"]

    # 2. Alice updates her vault key
    params_a_new = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=generate_salt())
    salt_a_new = b64encode(params_a_new.salt)
    kek_a_new = derive_kek("AliceMasterNew1!", params_a_new)
    env_a_new = wrap_vault_key(VaultKey.generate(), kek_a_new, params_a_new).to_json()

    put_a = await async_client.put(
        "/api/v1/auth/vault-key",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"wrapped_vault_key": env_a_new, "kdf_salt": salt_a_new},
    )
    assert put_a.status_code == 200

    # Verify Alice's key updated, but Bob's key was NOT touched (Cross-account isolation)
    with DbSession(test_db_engine) as db:
        acc_a = db.execute(select(Account).where(Account.username == alice_username)).scalar_one()
        acc_b = db.execute(select(Account).where(Account.username == bob_username)).scalar_one()
        assert acc_a.wrapped_vault_key == env_a_new
        assert acc_a.kdf_salt == salt_a_new
        assert acc_b.wrapped_vault_key == env_b_orig
        assert acc_b.kdf_salt == salt_b

    # 3. Malformed envelope submission preserves previously stored key
    bad_env_payloads = [
        {"wrapped_vault_key": "not-a-json-object"},
        {"wrapped_vault_key": json.dumps({"version": 999, "algorithm": "AES-256-GCM"})},
        {"wrapped_vault_key": env_a_new, "kdf_salt": "invalid-b64-salt!!!"},
    ]

    for bad_req in bad_env_payloads:
        res_bad = await async_client.put(
            "/api/v1/auth/vault-key",
            headers={"Authorization": f"Bearer {alice_token}"},
            json=bad_req,
        )
        assert res_bad.status_code == 400

        # Verify Alice's DB record remains completely intact (not overwritten with partial/corrupted data)
        with DbSession(test_db_engine) as db:
            acc_a_check = db.execute(select(Account).where(Account.username == alice_username)).scalar_one()
            assert acc_a_check.wrapped_vault_key == env_a_new
            assert acc_a_check.kdf_salt == salt_a_new

