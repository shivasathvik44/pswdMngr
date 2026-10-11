"""Security review test suite validating Phase 3.1 security findings.

Covers:
1. Proof-of-concept demonstrating offline master-password guessing from a stolen database dump.
2. Abuse control verification (IP spraying, distributed user brute-forcing, resets).
3. Concurrency, ordering, pagination, and deletion propagation during active sync.
"""

import base64
import json
import time
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient

from vaultsync_server.crypto.envelope import EncryptedRecordEnvelope, WrappedKeyEnvelope
from vaultsync_server.crypto.kdf import (
    Argon2Params,
    DOMAIN_AUTH_V1,
    DOMAIN_KEK_V1,
    derive_auth_secret,
    derive_kek,
    derive_master_secret,
    expand_key,
    generate_salt,
    normalize_master_password,
)
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey, unwrap_vault_key, wrap_vault_key
from vaultsync_server.services.auth import InMemoryRateLimiter, verify_auth_secret


# ============================================================================
# 1. Issue 1: Proof of Offline Master-Password Guessing Attack
# ============================================================================

def test_offline_master_password_guessing_vulnerability():
    """Demonstrate that an attacker with a database dump can crack the master password offline.
    
    Proof Scenario:
    1. User initializes vault with master password P = "CorrectHorseStaple99!".
    2. Client derives KEK and auth_secret via HKDF.
    3. Server stores auth_hash = Argon2id(auth_secret) and wrapped_vault_key.
    4. Attacker obtains the database dump: (kdf_salt, auth_hash, wrapped_vault_key).
    5. Attacker iterates offline through candidate passwords without network access.
    6. For each candidate, attacker computes Argon2id(cand, salt) -> HKDF -> auth_secret.
    7. Attacker verifies against auth_hash.
    8. Once matched, the attacker immediately has KEK and decrypts all records!
    """
    # 1. Normal client registration and vault setup
    real_master_password = "CorrectHorseStaple99!"
    kdf_salt = generate_salt()
    params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=kdf_salt)

    # Client derivation
    pwd_bytes = normalize_master_password(real_master_password)
    master_secret = derive_master_secret(pwd_bytes, params)
    kek = expand_key(master_secret, DOMAIN_KEK_V1)
    auth_secret = expand_key(master_secret, DOMAIN_AUTH_V1).hex()

    # Client generates VEK and encrypts sample record
    vek = VaultKey.generate()
    wrap_envelope = wrap_vault_key(vek, kek, params)
    record_id = "test-secret-doc-uuid"
    sample_plaintext = '{"credit_card": "4111-2222-3333-4444", "cvv": "123"}'
    record_envelope = encrypt_record(vek, record_id, sample_plaintext)

    # Server hashes auth_secret and stores row
    from vaultsync_server.services.auth import hash_auth_secret
    server_auth_hash = hash_auth_secret(auth_secret)

    # -------------------------------------------------------------------------
    # ATTACKER PERSPECTIVE: Attacker dumps database
    # Stolen database columns:
    stolen_salt = kdf_salt
    stolen_auth_hash = server_auth_hash
    stolen_wrapped_key = wrap_envelope.to_json()
    stolen_record_envelope = record_envelope.to_json()

    # Attacker runs offline dictionary attack
    candidate_passwords = [
        "12345678",
        "password123",
        "admin2026!",
        "CorrectHorseStaple99!",  # Correct password in dictionary
        "winteriscoming",
    ]

    cracked_password = None
    cracked_master_secret = None

    for candidate in candidate_passwords:
        # Offline computation: candidate -> Argon2id -> HKDF auth_secret
        cand_bytes = normalize_master_password(candidate)
        cand_params = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=stolen_salt)
        cand_secret = derive_master_secret(cand_bytes, cand_params)
        cand_auth_secret = expand_key(cand_secret, DOMAIN_AUTH_V1).hex()

        # Offline verification against stolen database hash
        if verify_auth_secret(stolen_auth_hash, cand_auth_secret):
            cracked_password = candidate
            cracked_master_secret = cand_secret
            break

    # ASSERTION: Attacker successfully identified the exact master password!
    assert cracked_password == real_master_password
    assert cracked_master_secret is not None

    # ATTACKER EXPLOITATION: Recover KEK, unwrap VEK, decrypt confidential records
    cracked_kek = expand_key(cracked_master_secret, DOMAIN_KEK_V1)
    stolen_wrap_obj = WrappedKeyEnvelope.from_json(stolen_wrapped_key)
    unwrapped_vek = unwrap_vault_key(stolen_wrap_obj, cracked_password)

    stolen_rec_obj = EncryptedRecordEnvelope.from_json(stolen_record_envelope)
    decrypted_bytes = decrypt_record(unwrapped_vek, stolen_rec_obj)

    # ASSERTION: Attacker has fully decrypted confidential vault data offline!
    assert decrypted_bytes.decode("utf-8") == sample_plaintext


# ============================================================================
# 2. Issue 2: Abuse Control & Rate Limiter Tests
# ============================================================================

def test_rate_limiter_dual_axis_and_reset():
    """Verify rate limiter blocks both single-IP spraying and distributed user brute-forcing."""
    limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=60)

    # Axis 1: Distributed attack against single user from multiple IPs
    user = "alice"
    assert limiter.is_rate_limited(f"auth:user:{user}") is False

    for i in range(3):
        ip = f"10.0.0.{i+1}"
        limiter.record_failure(f"auth:ip:{ip}")
        limiter.record_failure(f"auth:user:{user}")

    # 4th attempt from a NEW IP (10.0.0.99) against 'alice' should be rate limited by user axis!
    assert limiter.is_rate_limited(f"auth:user:{user}") is True

    # Axis 2: Single IP spraying across multiple usernames
    bad_ip = "192.168.1.100"
    assert limiter.is_rate_limited(f"auth:ip:{bad_ip}") is False

    for i in range(3):
        target = f"user_{i}"
        limiter.record_failure(f"auth:ip:{bad_ip}")
        limiter.record_failure(f"auth:user:{target}")

    # 4th attempt from bad_ip against a fresh target should be rate limited by IP axis!
    assert limiter.is_rate_limited(f"auth:ip:{bad_ip}") is True

    # Reset behavior: Successful login resets user counter
    limiter.reset(f"auth:user:{user}")
    assert limiter.is_rate_limited(f"auth:user:{user}") is False


@pytest.mark.anyio
async def test_api_rate_limiting_integration(async_client: AsyncClient):
    """Test HTTP 429 response when failed attempts exceed threshold."""
    # Register victim user
    username = f"ratelimit_victim_{uuid.uuid4().hex[:6]}"
    salt = base64.b64encode(b"0123456789abcdef").decode("ascii")
    await async_client.post(
        "/api/v1/auth/register",
        json={"username": username, "auth_secret": "correct_secret_123456", "kdf_salt": salt},
    )

    # Perform 10 failed login attempts
    for _ in range(10):
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": username, "auth_secret": "wrong_secret_123456"},
        )
        assert res.status_code == 401

    # 11th attempt must trigger HTTP 429
    throttled_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "auth_secret": "wrong_secret_123456"},
    )
    assert throttled_res.status_code == 429
    assert "Too many failed login attempts" in throttled_res.json()["detail"]

    # Reset rate limiter so subsequent tests in the session are not affected
    from vaultsync_server.services.auth import rate_limiter
    rate_limiter._attempts.clear()


# ============================================================================
# 3. Issue 3: Incremental Sync Concurrency, Ordering & Pagination Tests
# ============================================================================

@pytest.mark.anyio
async def test_sync_pagination_during_concurrent_mutations(async_client: AsyncClient):
    """Test that mutations occurring during pagination do not skip records or break order."""
    vek = VaultKey.generate()
    username = f"sync_test_user_{uuid.uuid4().hex[:6]}"
    salt = base64.b64encode(b"0123456789abcdef").decode("ascii")
    auth_secret = "sync_auth_secret_token_123"

    await async_client.post(
        "/api/v1/auth/register",
        json={"username": username, "auth_secret": auth_secret, "kdf_salt": salt},
    )
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": username, "auth_secret": auth_secret},
    )
    headers = {"Authorization": f"Bearer {login_res.json()['session_token']}"}

    # Helper
    def make_payload(rid: str, text: str) -> str:
        return encrypt_record(vek, rid, text).to_json()

    # Step 1: Create 6 initial records (rec-1 to rec-6)
    for i in range(1, 7):
        rid = f"rec-{i}"
        await async_client.post(
            "/api/v1/records",
            headers=headers,
            json={"record_id": rid, "ciphertext_payload": make_payload(rid, f"Data {i}")},
        )

    # Step 2: Client starts paginated sync: Page 1 with limit=3
    page1 = await async_client.get("/api/v1/sync?since_cursor=0&limit=3", headers=headers)
    assert page1.status_code == 200
    p1_data = page1.json()
    assert len(p1_data["items"]) == 3
    assert p1_data["has_more"] is True
    assert [item["record_id"] for item in p1_data["items"]] == ["rec-1", "rec-2", "rec-3"]
    p1_cursor = p1_data["next_cursor"]
    assert p1_cursor == 3

    # Step 3: Concurrent mutation while client was reading Page 1!
    # Update rec-2 (moves its sync_cursor from 2 to 7)
    await async_client.put(
        "/api/v1/records/rec-2",
        headers=headers,
        json={"expected_revision": 1, "ciphertext_payload": make_payload("rec-2", "Updated Data 2")},
    )
    # Delete rec-4 (tombstones it, moves its sync_cursor from 4 to 8)
    await async_client.delete("/api/v1/records/rec-4", headers=headers)
    # Insert new rec-7 (sync_cursor 9)
    await async_client.post(
        "/api/v1/records",
        headers=headers,
        json={"record_id": "rec-7", "ciphertext_payload": make_payload("rec-7", "Data 7")},
    )

    # Step 4: Client resumes pagination from p1_cursor (since_cursor=3) with limit=3
    page2 = await async_client.get(f"/api/v1/sync?since_cursor={p1_cursor}&limit=3", headers=headers)
    assert page2.status_code == 200
    p2_data = page2.json()
    # At cursor > 3: rec-5 (cur 5), rec-6 (cur 6), rec-2 (cur 7)
    assert len(p2_data["items"]) == 3
    assert p2_data["has_more"] is True
    assert [item["record_id"] for item in p2_data["items"]] == ["rec-5", "rec-6", "rec-2"]
    p2_cursor = p2_data["next_cursor"]
    assert p2_cursor == 7

    # Step 5: Client fetches Page 3 from p2_cursor (since_cursor=7)
    page3 = await async_client.get(f"/api/v1/sync?since_cursor={p2_cursor}&limit=3", headers=headers)
    assert page3.status_code == 200
    p3_data = page3.json()
    # At cursor > 7: rec-4 (tombstone, cur 8), rec-7 (cur 9)
    assert len(p3_data["items"]) == 2
    assert p3_data["has_more"] is False
    assert [item["record_id"] for item in p3_data["items"]] == ["rec-4", "rec-7"]
    
    # Verify tombstone has purged ciphertext
    tombstone_item = p3_data["items"][0]
    assert tombstone_item["record_id"] == "rec-4"
    assert tombstone_item["is_deleted"] is True
    assert tombstone_item["ciphertext_payload"] == ""

    # Step 6: Verify total consistency: All updates committed during sync were observed!
    all_observed_ids = (
        [item["record_id"] for item in p1_data["items"]]
        + [item["record_id"] for item in p2_data["items"]]
        + [item["record_id"] for item in p3_data["items"]]
    )
    # rec-2 was observed in p1 and re-observed with new revision in p2
    assert "rec-1" in all_observed_ids
    assert "rec-2" in all_observed_ids
    assert "rec-3" in all_observed_ids
    assert "rec-4" in all_observed_ids
    assert "rec-5" in all_observed_ids
    assert "rec-6" in all_observed_ids
    assert "rec-7" in all_observed_ids
