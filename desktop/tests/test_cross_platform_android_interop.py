"""Cross-platform cryptographic interoperability tests between Android and Fedora Desktop.

Validates that JSON envelopes and cryptographic primitives generated according to
shared/test-vectors/KOTLIN_INTEROP_SPEC.md are fully interchangeable between
the native Android Kotlin client and the Python desktop client.
"""

import json
import os
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
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
)
from vaultsync_server.crypto.records import decrypt_record, encrypt_record
from vaultsync_server.crypto.vault_keys import VaultKey, unwrap_vault_key, wrap_vault_key
from vaultsync_desktop.crypto import unlock_vault_with_master_password, create_initial_vault_key_and_envelope


def load_vectors() -> dict:
    path = Path(__file__).parents[2] / "shared" / "test-vectors" / "vectors_v1.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_malformed_vectors() -> dict:
    path = Path(__file__).parents[2] / "shared" / "test-vectors" / "malformed_vectors_v1.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_android_golden_vector_wrapped_key_interop():
    """Verify that Android-compatible wrapped key JSON envelope decrypts cleanly on desktop."""
    vec = load_vectors()
    envelope_json = vec["vault_key_wrapping"]["envelope_json"]
    master_password = vec["inputs"]["master_password_plain"]
    expected_vek_hex = vec["vault_key_wrapping"]["vault_key_hex"]

    envelope = WrappedKeyEnvelope.from_json(envelope_json)
    unwrapped_key = unwrap_vault_key(envelope, master_password)

    assert unwrapped_key.raw_bytes.hex() == expected_vek_hex


def test_android_golden_vector_record_interop():
    """Verify that Android-compatible encrypted record JSON envelope decrypts cleanly on desktop."""
    vec = load_vectors()
    record_json = vec["record_encryption"]["envelope_json"]
    vek_bytes = bytes.fromhex(vec["vault_key_wrapping"]["vault_key_hex"])
    vault_key = VaultKey(vek_bytes)

    envelope = EncryptedRecordEnvelope.from_json(record_json)
    plaintext_bytes = decrypt_record(vault_key, envelope)

    expected_plaintext = vec["record_encryption"]["plaintext_utf8"]
    assert plaintext_bytes.decode("utf-8") == expected_plaintext


def test_desktop_output_compatible_with_android_crypto_spec():
    """Verify that envelopes produced on desktop adhere strictly to Android specifications."""
    master_password = "SyntheticTestMasterPass123!"
    vault_key, salt_b64, envelope_json = create_initial_vault_key_and_envelope(
        master_password, memory_cost=65536, time_cost=3, parallelism=4
    )

    envelope = WrappedKeyEnvelope.from_json(envelope_json)
    envelope_dict = envelope.model_dump()

    # Validate WrappedKeyEnvelope structure
    assert envelope_dict["version"] == 1
    assert envelope_dict["algorithm"] == "AES-256-GCM"
    assert envelope_dict["kdf"]["algorithm"] == "Argon2id"
    assert envelope_dict["kdf"]["memory_cost"] == 65536
    assert envelope_dict["kdf"]["time_cost"] == 3
    assert envelope_dict["kdf"]["parallelism"] == 4
    assert len(b64decode(envelope_dict["kdf"]["salt"])) == 16
    assert len(b64decode(envelope_dict["nonce"])) == 12
    # Ciphertext must contain 32-byte VEK + 16-byte GCM tag = 48 bytes
    assert len(b64decode(envelope_dict["ciphertext"])) == 48

    # Validate EncryptedRecordEnvelope structure
    record_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    payload = json.dumps({"title": "Test Title", "password": "SecretPassword"})
    rec_envelope = encrypt_record(vault_key, record_id, payload)
    rec_dict = rec_envelope.model_dump()

    assert rec_dict["version"] == 1
    assert rec_dict["algorithm"] == "AES-256-GCM"
    assert rec_dict["record_id"] == record_id
    assert len(b64decode(rec_dict["nonce"])) == 12
    # Plaintext length + 16 bytes tag
    assert len(b64decode(rec_dict["ciphertext"])) == len(payload.encode("utf-8")) + 16


def test_malformed_vectors_cross_platform_rejection():
    """Verify all adversarial cases from malformed_vectors_v1.json are rejected properly."""
    malformed = load_malformed_vectors()
    vec = load_vectors()
    vek_bytes = bytes.fromhex(vec["vault_key_wrapping"]["vault_key_hex"])
    vault_key = VaultKey(vek_bytes)

    for case in malformed["cases"]:
        name = case["name"]
        payload_str = case["payload"]

        if name in ("corrupted_ciphertext", "corrupted_tag", "swapped_record_id", "corrupted_nonce"):
            envelope = EncryptedRecordEnvelope.from_json(payload_str)
            with pytest.raises(DecryptionFailedError):
                decrypt_record(vault_key, envelope)

        elif name == "unsupported_version":
            with pytest.raises(UnsupportedVersionError):
                EncryptedRecordEnvelope.from_json(payload_str)

        elif name == "unsupported_algorithm":
            with pytest.raises(UnsupportedAlgorithmError):
                EncryptedRecordEnvelope.from_json(payload_str)

        elif name == "unsafe_kdf_memory_cost":
            with pytest.raises(InvalidParameterError):
                WrappedKeyEnvelope.from_json(payload_str)


def test_record_id_aad_binding_integrity():
    """Tampering with record_id in the envelope must cause decryption to fail due to AAD mismatch."""
    vec = load_vectors()
    record_json = vec["record_encryption"]["envelope_json"]
    vek_bytes = bytes.fromhex(vec["vault_key_wrapping"]["vault_key_hex"])
    vault_key = VaultKey(vek_bytes)

    data = json.loads(record_json)
    data["record_id"] = "11111111-2222-3333-4444-555555555555"

    tampered_envelope = EncryptedRecordEnvelope.model_validate(data)
    with pytest.raises(DecryptionFailedError):
        decrypt_record(vault_key, tampered_envelope)


def test_unicode_and_multiline_synthetic_data_interop():
    """Verify multi-language Unicode, emoji, and multiline secret notes decrypt accurately."""
    vek = VaultKey.generate()
    record_id = "00000000-1111-2222-3333-444444444444"
    complex_payload = json.dumps({
        "title": "München Café ☕",
        "username": "user@тест.рф",
        "password": "複雑なパスワード🔑123!",
        "notes": "Line 1: Normal\nLine 2: 日本語テキスト\nLine 3: 🔒 Zero-Knowledge 🛡️\n\nDouble newline note."
    }, ensure_ascii=False)

    envelope = encrypt_record(vek, record_id, complex_payload)
    decrypted_raw = decrypt_record(vek, envelope)
    decrypted_str = decrypted_raw.decode("utf-8")

    assert decrypted_str == complex_payload
    parsed = json.loads(decrypted_str)
    assert parsed["title"] == "München Café ☕"
    assert parsed["password"] == "複雑なパスワード🔑123!"


def test_fresh_random_nonces_per_encryption():
    """Verify that multiple encryptions of the same plaintext produce unique nonces and ciphertexts."""
    vek = VaultKey.generate()
    record_id = "00000000-1111-2222-3333-444444444444"
    payload = json.dumps({"title": "Same Title", "password": "SamePassword"})

    env1 = encrypt_record(vek, record_id, payload)
    env2 = encrypt_record(vek, record_id, payload)

    assert env1.nonce != env2.nonce
    assert env1.ciphertext != env2.ciphertext


def test_modified_tag_and_nonce_rejected():
    """Verify that bit flips in either the nonce or tag cause GCM verification failure."""
    vek = VaultKey.generate()
    record_id = "00000000-1111-2222-3333-444444444444"
    payload = json.dumps({"title": "Test", "password": "Secret"})
    envelope = encrypt_record(vek, record_id, payload)

    # 1. Corrupt the last byte of ciphertext (which is part of the 16-byte GCM tag)
    raw_ct = bytearray(b64decode(envelope.ciphertext))
    raw_ct[-1] ^= 0x01
    corrupted_tag_env = EncryptedRecordEnvelope(
        version=envelope.version,
        algorithm=envelope.algorithm,
        record_id=envelope.record_id,
        nonce=envelope.nonce,
        ciphertext=b64encode(bytes(raw_ct))
    )
    with pytest.raises(DecryptionFailedError):
        decrypt_record(vek, corrupted_tag_env)

    # 2. Corrupt the nonce
    raw_nonce = bytearray(b64decode(envelope.nonce))
    raw_nonce[0] ^= 0x01
    corrupted_nonce_env = EncryptedRecordEnvelope(
        version=envelope.version,
        algorithm=envelope.algorithm,
        record_id=envelope.record_id,
        nonce=b64encode(bytes(raw_nonce)),
        ciphertext=envelope.ciphertext
    )
    with pytest.raises(DecryptionFailedError):
        decrypt_record(vek, corrupted_nonce_env)
