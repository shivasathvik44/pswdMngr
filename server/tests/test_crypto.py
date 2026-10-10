"""Comprehensive automated test suite for VaultSync cryptographic prototype.

Tests all key derivation, authenticated encryption, tampering detection,
defensive bounds, redaction, and cross-language golden test vectors.
"""

import json
import os
from pathlib import Path

import pytest

from vaultsync_server.crypto.envelope import (
    EncryptedRecordEnvelope,
    WrappedKeyEnvelope,
    b64decode,
    b64encode,
)
from vaultsync_server.crypto.errors import (
    CryptoError,
    DecryptionFailedError,
    InputSizeExceededError,
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
)
from vaultsync_server.crypto.kdf import (
    Argon2Params,
    DOMAIN_AUTH_V1,
    DOMAIN_KEK_V1,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    derive_auth_secret,
    derive_kek,
    derive_master_secret,
    expand_key,
    generate_salt,
    normalize_master_password,
)
from vaultsync_server.crypto.records import (
    decrypt_record,
    encrypt_record,
)
from vaultsync_server.crypto.vault_keys import (
    VaultKey,
    rewrap_vault_key,
    unwrap_vault_key,
    wrap_vault_key,
)


@pytest.fixture
def sample_salt() -> bytes:
    """Fixture providing a deterministic 16-byte salt for repeatable tests."""
    return b"0123456789abcdef"


@pytest.fixture
def fast_params(sample_salt: bytes) -> Argon2Params:
    """Fixture providing fast Argon2 parameters for quick unit test execution."""
    # Uses 16 MiB and 1 iteration for high-speed test execution
    return Argon2Params(
        memory_cost=16384,
        time_cost=1,
        parallelism=2,
        salt=sample_salt,
    )


# 1. Successful key derivation with the same inputs
def test_key_derivation_deterministic(fast_params: Argon2Params):
    password = "CorrectHorseBatteryStaple1!"
    kek1 = derive_kek(password, fast_params)
    kek2 = derive_kek(password, fast_params)
    assert kek1 == kek2
    assert len(kek1) == 32


# 2. Different salts produce different derived keys
def test_different_salts_produce_different_keys():
    password = "CorrectHorseBatteryStaple1!"
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert salt1 != salt2

    params1 = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt1)
    params2 = Argon2Params(memory_cost=16384, time_cost=1, parallelism=2, salt=salt2)

    kek1 = derive_kek(password, params1)
    kek2 = derive_kek(password, params2)
    assert kek1 != kek2


# 3. Domain separation between KEK and Auth secret
def test_domain_separation_produces_distinct_keys(fast_params: Argon2Params):
    password = "CorrectHorseBatteryStaple1!"
    kek = derive_kek(password, fast_params)
    auth_secret = derive_auth_secret(password, fast_params)
    assert kek != auth_secret
    assert len(kek) == 32
    assert len(auth_secret) == 32


# 4. Successful vault-key wrapping and unwrapping
def test_vault_key_wrapping_and_unwrapping(fast_params: Argon2Params):
    password = "MyMasterPassword2026!"
    original_key = VaultKey.generate()

    kek = derive_kek(password, fast_params)
    envelope = wrap_vault_key(original_key, kek, fast_params)

    # Unwrap using the master password
    unwrapped_key = unwrap_vault_key(envelope, password)
    assert unwrapped_key.raw_bytes == original_key.raw_bytes


# 5. Wrong master password fails to unwrap the key
def test_wrong_master_password_fails_unwrapping(fast_params: Argon2Params):
    correct_password = "CorrectPassword123!"
    wrong_password = "WrongPassword456!"

    original_key = VaultKey.generate()
    kek = derive_kek(correct_password, fast_params)
    envelope = wrap_vault_key(original_key, kek, fast_params)

    with pytest.raises(DecryptionFailedError) as exc_info:
        unwrap_vault_key(envelope, wrong_password)
    
    # Assert safe exception message
    assert "Decryption failed" in str(exc_info.value)


# 6. Successful record encryption and decryption
def test_record_encryption_and_decryption():
    vault_key = VaultKey.generate()
    record_id = "test-record-uuid-1"
    plaintext = '{"username": "user@example.com", "secret": "s3cr3tP@ss"}'

    envelope = encrypt_record(vault_key, record_id, plaintext)
    assert envelope.record_id == record_id
    assert envelope.version == 1
    assert envelope.algorithm == "AES-256-GCM"

    decrypted_bytes = decrypt_record(vault_key, envelope)
    assert decrypted_bytes.decode("utf-8") == plaintext


# 7. Ciphertext modification rejected
def test_ciphertext_tampering_rejected():
    vault_key = VaultKey.generate()
    record_id = "test-record-uuid-2"
    plaintext = "Sensitive vault field data"

    envelope = encrypt_record(vault_key, record_id, plaintext)
    raw_ct = bytearray(b64decode(envelope.ciphertext))
    
    # Flip a single bit in the ciphertext payload
    raw_ct[0] ^= 0x01
    tampered_envelope = EncryptedRecordEnvelope(
        record_id=record_id,
        nonce=envelope.nonce,
        ciphertext=b64encode(raw_ct),
    )

    with pytest.raises(DecryptionFailedError):
        decrypt_record(vault_key, tampered_envelope)


# 8. Nonce modification rejected
def test_nonce_tampering_rejected():
    vault_key = VaultKey.generate()
    record_id = "test-record-uuid-3"
    plaintext = "Confidential note"

    envelope = encrypt_record(vault_key, record_id, plaintext)
    raw_nonce = bytearray(b64decode(envelope.nonce))
    raw_nonce[0] ^= 0x01

    tampered_envelope = EncryptedRecordEnvelope(
        record_id=record_id,
        nonce=b64encode(raw_nonce),
        ciphertext=envelope.ciphertext,
    )

    with pytest.raises(DecryptionFailedError):
        decrypt_record(vault_key, tampered_envelope)


# 9. Associated data modification rejected (record_id relocation attack)
def test_record_id_relocation_rejected():
    vault_key = VaultKey.generate()
    record_id_1 = "record-uuid-alice"
    record_id_2 = "record-uuid-bob"
    plaintext = "Alice secret payload"

    # Encrypt for Alice
    envelope = encrypt_record(vault_key, record_id_1, plaintext)

    # Attacker relocates ciphertext to Bob's record ID without re-encrypting
    relocated_envelope = EncryptedRecordEnvelope(
        record_id=record_id_2,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
    )

    with pytest.raises(DecryptionFailedError):
        decrypt_record(vault_key, relocated_envelope)


# 10. Truncated and malformed envelopes rejected
def test_truncated_ciphertext_rejected():
    vault_key = VaultKey.generate()
    record_id = "test-record-uuid-4"
    envelope = encrypt_record(vault_key, record_id, "Plaintext payload")
    
    # 1. Truncation below minimum tag size (16 bytes) -> rejected at envelope parsing
    severely_truncated_json = json.dumps({
        "version": 1,
        "algorithm": "AES-256-GCM",
        "record_id": record_id,
        "nonce": envelope.nonce,
        "ciphertext": b64encode(b"short"),  # only 5 bytes
    })
    with pytest.raises(MalformedEnvelopeError):
        EncryptedRecordEnvelope.from_json(severely_truncated_json)

    # 2. Truncation of authentication tag -> rejected at AEAD decryption
    raw_ct = b64decode(envelope.ciphertext)
    truncated_tag_env = EncryptedRecordEnvelope(
        record_id=record_id,
        nonce=envelope.nonce,
        ciphertext=b64encode(raw_ct[:-8]),  # tag partially truncated
    )
    with pytest.raises(DecryptionFailedError):
        decrypt_record(vault_key, truncated_tag_env)


def test_malformed_json_rejected():
    with pytest.raises(MalformedEnvelopeError):
        EncryptedRecordEnvelope.from_json("{broken json")

    with pytest.raises(MalformedEnvelopeError):
        WrappedKeyEnvelope.from_json("not a json string at all")


# 11. Unsupported versions and algorithms rejected
def test_unsupported_version_rejected():
    json_payload = json.dumps({
        "version": 2,  # unsupported future version
        "algorithm": "AES-256-GCM",
        "record_id": "rec-1",
        "nonce": b64encode(os.urandom(12)),
        "ciphertext": b64encode(os.urandom(32)),
    })
    with pytest.raises(UnsupportedVersionError):
        EncryptedRecordEnvelope.from_json(json_payload)


def test_unsupported_algorithm_rejected():
    json_payload = json.dumps({
        "version": 1,
        "algorithm": "DES-EDE3-CBC",  # unsupported algorithm
        "record_id": "rec-1",
        "nonce": b64encode(os.urandom(12)),
        "ciphertext": b64encode(os.urandom(32)),
    })
    with pytest.raises(UnsupportedAlgorithmError):
        EncryptedRecordEnvelope.from_json(json_payload)


# 12. Oversized inputs and unreasonable KDF parameters rejected
def test_oversized_password_rejected():
    oversized_password = "A" * (MAX_PASSWORD_LENGTH + 1)
    with pytest.raises(InputSizeExceededError):
        normalize_master_password(oversized_password)


def test_short_password_rejected():
    with pytest.raises(InvalidParameterError):
        normalize_master_password("short")


def test_unreasonable_kdf_parameters_rejected(sample_salt: bytes):
    # Too much memory (> 512 MiB)
    with pytest.raises(InvalidParameterError):
        Argon2Params(memory_cost=1048576, salt=sample_salt)

    # Too little memory (< 16 MiB)
    with pytest.raises(InvalidParameterError):
        Argon2Params(memory_cost=4096, salt=sample_salt)

    # Excessive time cost (> 10)
    with pytest.raises(InvalidParameterError):
        Argon2Params(time_cost=20, salt=sample_salt)

    # Invalid salt length
    with pytest.raises(InvalidParameterError):
        Argon2Params(salt=b"too_short")


# 13. Repeated encryption produces distinct nonces
def test_repeated_encryption_unique_nonces():
    vault_key = VaultKey.generate()
    record_id = "test-record-uuid-5"
    plaintext = "Repeat encryption data test"

    envelope1 = encrypt_record(vault_key, record_id, plaintext)
    envelope2 = encrypt_record(vault_key, record_id, plaintext)

    assert envelope1.nonce != envelope2.nonce
    assert envelope1.ciphertext != envelope2.ciphertext


# 14. Plaintext passwords and vault keys never appear in serialized envelopes
def test_secrets_redacted_and_not_serialized(fast_params: Argon2Params):
    password = "SuperSecretMasterPassword99!"
    vault_key = VaultKey.generate()

    # Verify VaultKey repr and str are redacted
    assert repr(vault_key) == "<VaultKey: [REDACTED]>"
    assert str(vault_key) == "<VaultKey: [REDACTED]>"

    kek = derive_kek(password, fast_params)
    envelope = wrap_vault_key(vault_key, kek, fast_params)
    serialized = envelope.to_json()

    # Ensure secret string and raw key bytes do not appear in serialized JSON
    assert password not in serialized
    assert vault_key.raw_bytes.hex() not in serialized


# 15. Error messages do not disclose secret values
def test_error_messages_do_not_leak_secrets(fast_params: Argon2Params):
    secret_password = "SensitiveUserSecretValue123!"
    vault_key = VaultKey.generate()
    kek = derive_kek(secret_password, fast_params)
    envelope = wrap_vault_key(vault_key, kek, fast_params)

    try:
        unwrap_vault_key(envelope, "IncorrectGuessedPassword1!")
    except DecryptionFailedError as exc:
        err_msg = str(exc)
        assert secret_password not in err_msg
        assert "IncorrectGuessedPassword1!" not in err_msg


# 16. Rewrapping key upon master password change
def test_rewrap_vault_key_on_password_change(fast_params: Argon2Params):
    old_password = "OldMasterPassword123!"
    new_password = "NewMasterPassword456!"
    vault_key = VaultKey.generate()

    # Wrap with old password
    kek_old = derive_kek(old_password, fast_params)
    old_envelope = wrap_vault_key(vault_key, kek_old, fast_params)

    # Unwrap and rewrap with new password
    unwrapped = unwrap_vault_key(old_envelope, old_password)
    new_params = Argon2Params(
        memory_cost=fast_params.memory_cost,
        time_cost=fast_params.time_cost,
        parallelism=fast_params.parallelism,
        salt=generate_salt(),
    )
    new_envelope = rewrap_vault_key(unwrapped, new_password, new_params)

    # Verify old password now fails on new envelope
    with pytest.raises(DecryptionFailedError):
        unwrap_vault_key(new_envelope, old_password)

    # Verify new password successfully recovers identical key
    recovered_key = unwrap_vault_key(new_envelope, new_password)
    assert recovered_key.raw_bytes == vault_key.raw_bytes


# 17. Validation against golden test vectors (shared/test-vectors/vectors_v1.json)
def test_golden_vectors_verification():
    vectors_path = Path(__file__).parents[2] / "shared" / "test-vectors" / "vectors_v1.json"
    assert vectors_path.is_file(), f"Golden vectors file missing at {vectors_path}"

    with open(vectors_path, "r", encoding="utf-8") as f:
        v = json.load(f)

    # Verify KDF and derived keys
    salt = bytes.fromhex(v["kdf_parameters"]["salt_hex"])
    params = Argon2Params(
        memory_cost=v["kdf_parameters"]["memory_cost_kib"],
        time_cost=v["kdf_parameters"]["time_cost"],
        parallelism=v["kdf_parameters"]["parallelism"],
        salt=salt,
    )

    pwd = v["inputs"]["master_password_plain"]
    pwd_bytes = normalize_master_password(pwd)
    assert pwd_bytes.hex() == v["inputs"]["master_password_normalized_utf8_hex"]

    master_secret = derive_master_secret(pwd_bytes, params)
    assert master_secret.hex() == v["derived_keys"]["master_secret_hex"]

    kek = expand_key(master_secret, DOMAIN_KEK_V1)
    assert kek.hex() == v["derived_keys"]["kek_hex"]

    auth_secret = expand_key(master_secret, DOMAIN_AUTH_V1)
    assert auth_secret.hex() == v["derived_keys"]["auth_secret_hex"]

    # Verify Wrapped Vault Key
    wrap_env = WrappedKeyEnvelope.from_json(v["vault_key_wrapping"]["envelope_json"])
    unwrapped_vek = unwrap_vault_key(wrap_env, pwd)
    assert unwrapped_vek.raw_bytes.hex() == v["vault_key_wrapping"]["vault_key_hex"]

    # Verify Record Decryption
    rec_env = EncryptedRecordEnvelope.from_json(v["record_encryption"]["envelope_json"])
    decrypted_record = decrypt_record(unwrapped_vek, rec_env)
    assert decrypted_record.decode("utf-8") == v["record_encryption"]["plaintext_utf8"]


# 18. Validation against adversarial test vectors (shared/test-vectors/malformed_vectors_v1.json)
def test_adversarial_vectors_verification():
    vectors_path = Path(__file__).parents[2] / "shared" / "test-vectors" / "malformed_vectors_v1.json"
    assert vectors_path.is_file(), f"Malformed vectors file missing at {vectors_path}"

    with open(vectors_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Load legitimate VEK from golden vectors for record tests
    golden_path = Path(__file__).parents[2] / "shared" / "test-vectors" / "vectors_v1.json"
    with open(golden_path, "r", encoding="utf-8") as gf:
        gv = json.load(gf)
    vek = VaultKey(bytes.fromhex(gv["vault_key_wrapping"]["vault_key_hex"]))

    for case in data["cases"]:
        name = case["name"]
        expected_error = case["expected_error"]
        payload_str = case["payload"]

        if expected_error == "DecryptionFailedError":
            env = EncryptedRecordEnvelope.from_json(payload_str)
            with pytest.raises(DecryptionFailedError):
                decrypt_record(vek, env)
        elif expected_error == "UnsupportedVersionError":
            with pytest.raises(UnsupportedVersionError):
                EncryptedRecordEnvelope.from_json(payload_str)
        elif expected_error == "UnsupportedAlgorithmError":
            with pytest.raises(UnsupportedAlgorithmError):
                EncryptedRecordEnvelope.from_json(payload_str)
        elif expected_error == "InvalidParameterError":
            with pytest.raises(InvalidParameterError):
                WrappedKeyEnvelope.from_json(payload_str).kdf.to_argon2_params()
