"""Synthetic vault records encryption, decryption, and authenticated binding."""

import os
import uuid
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultsync_server.crypto.envelope import (
    EncryptedRecordEnvelope,
    MAX_PLAINTEXT_RECORD_SIZE,
    NONCE_LENGTH,
    b64decode,
    b64encode,
)
from vaultsync_server.crypto.errors import (
    DecryptionFailedError,
    InputSizeExceededError,
    InvalidParameterError,
)
from vaultsync_server.crypto.vault_keys import VaultKey


def encrypt_record(
    vault_key: VaultKey,
    record_id: str,
    plaintext: bytes | str,
) -> EncryptedRecordEnvelope:
    """Encrypt a vault record payload bound to record_id via AES-256-GCM authenticated encryption."""
    if not isinstance(record_id, str) or not record_id.strip():
        raise InvalidParameterError("record_id must be a non-empty string")

    if isinstance(plaintext, str):
        payload_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, (bytes, bytearray)):
        payload_bytes = bytes(plaintext)
    else:
        raise InvalidParameterError("Plaintext must be str or bytes")

    if len(payload_bytes) == 0:
        raise InvalidParameterError("Plaintext payload cannot be empty")
    if len(payload_bytes) > MAX_PLAINTEXT_RECORD_SIZE:
        raise InputSizeExceededError(
            f"Plaintext size {len(payload_bytes)} exceeds maximum limit {MAX_PLAINTEXT_RECORD_SIZE}"
        )

    nonce = os.urandom(NONCE_LENGTH)
    envelope_draft = EncryptedRecordEnvelope(
        record_id=record_id,
        nonce=b64encode(nonce),
        ciphertext="",  # temporary for AAD calculation
    )
    aad = envelope_draft.compute_aad()

    aesgcm = AESGCM(vault_key.raw_bytes)
    ciphertext_and_tag = aesgcm.encrypt(nonce, payload_bytes, aad)

    return EncryptedRecordEnvelope(
        record_id=record_id,
        nonce=b64encode(nonce),
        ciphertext=b64encode(ciphertext_and_tag),
    )


def decrypt_record(
    vault_key: VaultKey,
    envelope: EncryptedRecordEnvelope,
) -> bytes:
    """Decrypt an EncryptedRecordEnvelope using the VaultKey.
    
    Verifies AEAD integrity and tag against the envelope's bound record_id.
    """
    nonce = b64decode(envelope.nonce, expected_length=NONCE_LENGTH)
    ciphertext_and_tag = b64decode(envelope.ciphertext)
    aad = envelope.compute_aad()

    aesgcm = AESGCM(vault_key.raw_bytes)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise DecryptionFailedError() from exc
    except Exception as exc:
        raise DecryptionFailedError() from exc

    return plaintext
