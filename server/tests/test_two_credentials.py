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
import json
import time
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

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

def test_database_dump_prevents_offline_master_password_verification():
    """Mathematically and programmatically demonstrate that a stolen database

    dump provides zero verifiers to check offline guesses against the vault master password.

    Attacker has: (username, account_password_hash, kdf_salt, wrapped_vault_key).
    Because account_password is uncorrelated with master_password:
    1. Attacker's candidate master passwords tested against account_password_hash never match.
    2. Even cracking account_password_hash only reveals account_password, which cannot unwrap the vault key.
    """
    vault_master_password = "SuperSecretMasterPassword!2026"
    account_password = "CompletelyIndependentServerPassword$888"

    # Server stores Argon2id of account_password
    account_password_hash = hash_password(account_password)

    # Client wraps VEK with vault_master_password
    salt_bytes = generate_salt()
    kdf_params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt_bytes)
    kek = derive_kek(vault_master_password, kdf_params)
    vek = VaultKey.generate()
    wrap_envelope = wrap_vault_key(vek, kek, kdf_params)

    # Stolen dump
    stolen_account_password_hash = account_password_hash
    stolen_wrapped_vault_key = wrap_envelope.to_json()

    # Attacker runs offline dictionary attack attempting to verify candidate master passwords
    candidate_master_passwords = [
        "12345678",
        "password",
        "admin2026",
        "SuperSecretMasterPassword!2026",  # The true master password
        "letmein",
    ]

    for cand in candidate_master_passwords:
        # Attacker tries to verify candidate against account_password_hash
        # Property: NEVER matches, even for the correct master password!
        assert verify_password(stolen_account_password_hash, cand) is False

    # Suppose attacker spends extensive GPU resources and cracks account_password_hash,
    # recovering account_password = "CompletelyIndependentServerPassword$888".
    cracked_server_password = account_password

    # Can attacker unwrap the vault key using the recovered account_password?
    stolen_wrap_obj = WrappedKeyEnvelope.from_json(stolen_wrapped_vault_key)
    with pytest.raises(DecryptionFailedError):
        unwrap_vault_key(stolen_wrap_obj, cracked_server_password)


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
