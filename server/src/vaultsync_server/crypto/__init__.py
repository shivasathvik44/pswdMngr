"""VaultSync cryptographic package.

Provides versioned key derivation, vault key wrapping, and record encryption.
"""

from vaultsync_server.crypto.envelope import (
    EncryptedRecordEnvelope,
    KdfMetadata,
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
    DEFAULT_MEMORY_COST_KIB,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
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

__all__ = [
    "CryptoError",
    "DecryptionFailedError",
    "InvalidParameterError",
    "MalformedEnvelopeError",
    "UnsupportedVersionError",
    "UnsupportedAlgorithmError",
    "InputSizeExceededError",
    "Argon2Params",
    "DEFAULT_MEMORY_COST_KIB",
    "DEFAULT_TIME_COST",
    "DEFAULT_PARALLELISM",
    "generate_salt",
    "normalize_master_password",
    "derive_master_secret",
    "expand_key",
    "derive_kek",
    "derive_auth_secret",
    "KdfMetadata",
    "WrappedKeyEnvelope",
    "EncryptedRecordEnvelope",
    "b64encode",
    "b64decode",
    "VaultKey",
    "wrap_vault_key",
    "unwrap_vault_key",
    "rewrap_vault_key",
    "encrypt_record",
    "decrypt_record",
]
