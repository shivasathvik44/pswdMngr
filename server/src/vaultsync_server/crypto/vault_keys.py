"""Vault Encryption Key (VEK) representation, generation, wrapping, and unwrapping."""

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultsync_server.crypto.envelope import (
    KdfMetadata,
    KEY_LENGTH,
    NONCE_LENGTH,
    WrappedKeyEnvelope,
    b64decode,
    b64encode,
)
from vaultsync_server.crypto.errors import (
    DecryptionFailedError,
    InvalidParameterError,
)
from vaultsync_server.crypto.kdf import (
    Argon2Params,
    derive_kek,
    generate_salt,
)


class VaultKey:
    """Represents a 256-bit symmetric Vault Encryption Key (VEK).
    
    Protects secret key bytes from accidental exposure in logs, debuggers,
    or exception tracebacks via redacted representations.
    """

    def __init__(self, key_bytes: bytes) -> None:
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise InvalidParameterError("VaultKey must be initialized with bytes")
        if len(key_bytes) != KEY_LENGTH:
            raise InvalidParameterError(f"VaultKey must be exactly {KEY_LENGTH} bytes, got {len(key_bytes)}")
        self._key = bytearray(key_bytes)

    @property
    def raw_bytes(self) -> bytes:
        """Access underlying key bytes."""
        return bytes(self._key)

    def clear(self) -> None:
        """Best-effort zeroization of internal mutable key buffer."""
        for i in range(len(self._key)):
            self._key[i] = 0
        self._key.clear()

    @classmethod
    def generate(cls) -> "VaultKey":
        """Generate a fresh 256-bit key using cryptographically secure random bytes."""
        return cls(os.urandom(KEY_LENGTH))

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> "VaultKey":
        """Load an existing 32-byte key."""
        return cls(key_bytes)

    def __repr__(self) -> str:
        return "<VaultKey: [REDACTED]>"

    def __str__(self) -> str:
        return "<VaultKey: [REDACTED]>"


def wrap_vault_key(
    vault_key: VaultKey,
    kek: bytes,
    params: Argon2Params,
) -> WrappedKeyEnvelope:
    """Wrap (encrypt) a VaultKey using a Key Encryption Key (KEK) via AES-256-GCM."""
    if len(kek) != KEY_LENGTH:
        raise InvalidParameterError(f"KEK must be {KEY_LENGTH} bytes")

    nonce = os.urandom(NONCE_LENGTH)
    kdf_meta = KdfMetadata.from_argon2_params(params)
    
    envelope_draft = WrappedKeyEnvelope(
        kdf=kdf_meta,
        nonce=b64encode(nonce),
        ciphertext="",  # temporary for AAD calculation
    )
    aad = envelope_draft.compute_aad()

    aesgcm = AESGCM(kek)
    ciphertext_and_tag = aesgcm.encrypt(nonce, vault_key.raw_bytes, aad)

    return WrappedKeyEnvelope(
        kdf=kdf_meta,
        nonce=b64encode(nonce),
        ciphertext=b64encode(ciphertext_and_tag),
    )


def unwrap_vault_key(
    envelope: WrappedKeyEnvelope,
    master_password: str,
) -> VaultKey:
    """Unwrap (decrypt) a VaultKey from a WrappedKeyEnvelope using the master password."""
    params = envelope.kdf.to_argon2_params()
    kek = derive_kek(master_password, params)
    
    nonce = b64decode(envelope.nonce, expected_length=NONCE_LENGTH)
    ciphertext_and_tag = b64decode(envelope.ciphertext)
    aad = envelope.compute_aad()

    aesgcm = AESGCM(kek)
    try:
        decrypted_key = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise DecryptionFailedError() from exc
    except Exception as exc:
        raise DecryptionFailedError() from exc

    if len(decrypted_key) != KEY_LENGTH:
        raise DecryptionFailedError()

    return VaultKey(decrypted_key)


def rewrap_vault_key(
    vault_key: VaultKey,
    new_master_password: str,
    params: Argon2Params | None = None,
) -> WrappedKeyEnvelope:
    """Re-wrap an existing VaultKey with a new master password and freshly generated salt."""
    if params is None:
        params = Argon2Params(salt=generate_salt())
    elif not params.salt:
        params = Argon2Params(
            memory_cost=params.memory_cost,
            time_cost=params.time_cost,
            parallelism=params.parallelism,
            salt=generate_salt(),
        )

    new_kek = derive_kek(new_master_password, params)
    return wrap_vault_key(vault_key, new_kek, params)
