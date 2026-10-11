"""Automated tests for VaultSync desktop cryptography.

Validates golden test vectors, Argon2id parameter enforcement, VEK wrapping/unwrapping,
record encryption/decryption, master password rotation, and passphrase entropy guidance.
"""

import json
from pathlib import Path
import pytest

from vaultsync_server.crypto.envelope import (
    CURRENT_PROTOCOL_VERSION,
    EncryptedRecordEnvelope,
    WrappedKeyEnvelope,
    b64decode,
    b64encode,
)
from vaultsync_server.crypto.errors import (
    DecryptionFailedError,
    MalformedEnvelopeError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
)
from vaultsync_server.crypto.kdf import (
    Argon2Params,
    derive_kek,
    generate_salt,
    normalize_master_password,
)
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey, unwrap_vault_key, wrap_vault_key

from vaultsync_desktop.crypto import (
    clear_key_material,
    create_initial_vault_key_and_envelope,
    evaluate_passphrase_strength,
    rotate_master_password,
    unlock_vault_with_master_password,
)


def load_test_vectors() -> dict:
    vector_file = Path(__file__).parents[2] / "shared" / "test-vectors" / "vectors_v1.json"
    with open(vector_file, "r", encoding="utf-8") as f:
        return json.load(f)


def test_golden_vector_kek_derivation():
    """Verify KEK derivation exactly matches golden test vector v1."""
    vec = load_test_vectors()
    pwd = vec["inputs"]["master_password_plain"]
    kdf_meta = vec["kdf_parameters"]
    salt_bytes = b64decode(kdf_meta["salt_base64"])

    params = Argon2Params(
        memory_cost=kdf_meta["memory_cost_kib"],
        time_cost=kdf_meta["time_cost"],
        parallelism=kdf_meta["parallelism"],
        salt=salt_bytes,
    )

    kek = derive_kek(pwd, params)
    expected_kek_b64 = vec["derived_keys"]["kek_base64"]
    assert b64encode(kek) == expected_kek_b64


def test_golden_vector_vault_key_unwrapping():
    """Verify unwrapping the Vault Encryption Key from the golden envelope."""
    vec = load_test_vectors()
    pwd = vec["inputs"]["master_password_plain"]
    wrap_data = vec["vault_key_wrapping"]
    envelope_json = wrap_data["envelope_json"]

    env = WrappedKeyEnvelope.from_json(envelope_json)
    assert env.compute_aad() == wrap_data["associated_data_utf8"].encode("utf-8")

    vek = unwrap_vault_key(env, pwd)
    expected_vek_b64 = wrap_data["vault_key_base64"]
    assert b64encode(vek.raw_bytes) == expected_vek_b64


def test_golden_vector_record_decryption():
    """Verify decrypting record payload from the golden test vector envelope."""
    vec = load_test_vectors()
    wrap_data = vec["vault_key_wrapping"]
    rec_data = vec["record_encryption"]

    vek = VaultKey(b64decode(wrap_data["vault_key_base64"]))
    rec_envelope = EncryptedRecordEnvelope.from_json(rec_data["envelope_json"])
    assert rec_envelope.compute_aad() == rec_data["associated_data_utf8"].encode("utf-8")

    plaintext_bytes = decrypt_record(vek, rec_envelope)
    assert plaintext_bytes.decode("utf-8") == rec_data["plaintext_utf8"]


def test_client_create_initial_vault_key_and_unlock():
    """Test generating a fresh VEK, wrapping it, and unlocking with correct/wrong password."""
    master_pwd = "CorrectMasterPassword123!"
    vek, salt_b64, envelope_json = create_initial_vault_key_and_envelope(
        master_pwd,
        memory_cost=16384,
        time_cost=1,
        parallelism=2,
    )

    # Verify salt format
    assert len(b64decode(salt_b64)) == 16

    # Unlock with correct password
    unlocked_vek = unlock_vault_with_master_password(envelope_json, master_pwd)
    assert unlocked_vek.raw_bytes == vek.raw_bytes

    # Unlock with wrong password must raise DecryptionFailedError (InvalidTag)
    with pytest.raises(DecryptionFailedError):
        unlock_vault_with_master_password(envelope_json, "WrongMasterPassword456!")


def test_master_password_rotation_preserves_record_ciphertext():
    """Test that rotating the master password re-wraps the VEK without requiring

    re-encryption of existing records.
    """
    initial_pwd = "OldMasterPassword123!"
    new_pwd = "BrandNewMasterPassword789!"

    # 1. Initialize vault and encrypt a record
    vek, salt_b64, envelope_json = create_initial_vault_key_and_envelope(
        initial_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )
    secret_text = '{"title":"Bank","password":"SecretPin1234"}'
    rec_envelope = encrypt_record(vek, "rec-001", secret_text)

    # 2. Rotate master password
    new_salt_b64, new_envelope_json = rotate_master_password(
        vek, new_pwd, memory_cost=16384, time_cost=1, parallelism=2
    )
    assert new_salt_b64 != salt_b64
    assert new_envelope_json != envelope_json

    # 3. Old password fails against new envelope
    with pytest.raises(DecryptionFailedError):
        unlock_vault_with_master_password(new_envelope_json, initial_pwd)

    # 4. New password unlocks the identical VEK
    new_unlocked_vek = unlock_vault_with_master_password(new_envelope_json, new_pwd)
    assert new_unlocked_vek.raw_bytes == vek.raw_bytes

    # 5. Existing record decrypts successfully with newly unlocked VEK!
    decrypted_bytes = decrypt_record(new_unlocked_vek, rec_envelope)
    assert decrypted_bytes.decode("utf-8") == secret_text


def test_passphrase_strength_evaluation():
    """Test passphrase entropy analysis and guidance."""
    # Empty
    score, label, recs = evaluate_passphrase_strength("")
    assert score == 0
    assert label == "Empty"

    # Weak
    score_weak, label_weak, _ = evaluate_passphrase_strength("short")
    assert score_weak < 40
    assert label_weak == "Weak"

    # Moderate
    score_mod, label_mod, _ = evaluate_passphrase_strength("CorrectHorseBattery")
    assert label_mod in ("Moderate", "Strong")

    # Excellent multi-word passphrase
    score_strong, label_strong, _ = evaluate_passphrase_strength("correct-horse-battery-staple-2026")
    assert score_strong >= 80
    assert label_strong in ("Strong", "Excellent")


def test_clear_key_material():
    """Verify clear_key_material runs without error."""
    vek = VaultKey.generate()
    clear_key_material(vek)
    # Does not crash on None
    clear_key_material(None)
