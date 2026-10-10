"""Key Derivation Function (KDF) implementation using Argon2id and HKDF-SHA256.

Follows RFC 9106 for Argon2id and RFC 5869 for HKDF domain separation.
"""

import os
import unicodedata
from dataclasses import dataclass
from typing import Final

import argon2.low_level as argon2_lowlevel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from vaultsync_server.crypto.errors import (
    CryptoError,
    InputSizeExceededError,
    InvalidParameterError,
)

# Standard parameter bounds
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 1024
SALT_LENGTH: Final[int] = 16  # 128-bit salt
DERIVED_KEY_LENGTH: Final[int] = 32  # 256-bit symmetric key

# Argon2id defensive resource bounds
MIN_MEMORY_COST_KIB: Final[int] = 16384    # 16 MiB minimum
MAX_MEMORY_COST_KIB: Final[int] = 524288   # 512 MiB maximum defensive upper bound
MIN_TIME_COST: Final[int] = 1
MAX_TIME_COST: Final[int] = 10
MIN_PARALLELISM: Final[int] = 1
MAX_PARALLELISM: Final[int] = 16

# Recommended default baseline (measured ~50-60ms on modern CPUs)
DEFAULT_MEMORY_COST_KIB: Final[int] = 65536  # 64 MiB
DEFAULT_TIME_COST: Final[int] = 3
DEFAULT_PARALLELISM: Final[int] = 4

# Domain separation context tags
DOMAIN_KEK_V1: Final[bytes] = b"vaultsync:kek:v1"
DOMAIN_AUTH_V1: Final[bytes] = b"vaultsync:auth:v1"


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id configuration parameters with strict defensive validation."""

    memory_cost: int = DEFAULT_MEMORY_COST_KIB
    time_cost: int = DEFAULT_TIME_COST
    parallelism: int = DEFAULT_PARALLELISM
    salt: bytes = b""

    def __post_init__(self) -> None:
        if not (MIN_MEMORY_COST_KIB <= self.memory_cost <= MAX_MEMORY_COST_KIB):
            raise InvalidParameterError(
                f"Argon2 memory_cost {self.memory_cost} KiB out of safe bounds "
                f"[{MIN_MEMORY_COST_KIB}, {MAX_MEMORY_COST_KIB}]"
            )
        if not (MIN_TIME_COST <= self.time_cost <= MAX_TIME_COST):
            raise InvalidParameterError(
                f"Argon2 time_cost {self.time_cost} out of safe bounds [{MIN_TIME_COST}, {MAX_TIME_COST}]"
            )
        if not (MIN_PARALLELISM <= self.parallelism <= MAX_PARALLELISM):
            raise InvalidParameterError(
                f"Argon2 parallelism {self.parallelism} out of safe bounds [{MIN_PARALLELISM}, {MAX_PARALLELISM}]"
            )
        if self.salt and len(self.salt) != SALT_LENGTH:
            raise InvalidParameterError(
                f"Argon2 salt length must be exactly {SALT_LENGTH} bytes, got {len(self.salt)}"
            )


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Generate cryptographically secure random bytes for salting."""
    if length != SALT_LENGTH:
        raise InvalidParameterError(f"Salt length must be {SALT_LENGTH} bytes")
    return os.urandom(length)


def normalize_master_password(password: str) -> bytes:
    """Validate and normalize master password to UTF-8 encoded Unicode NFC form.
    
    Protects against string encoding variations across platforms and input methods.
    """
    if not isinstance(password, str):
        raise InvalidParameterError("Master password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidParameterError(
            f"Master password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InputSizeExceededError(
            f"Master password exceeds maximum allowed length of {MAX_PASSWORD_LENGTH} characters"
        )
    
    # Unicode Normalization Form C
    normalized = unicodedata.normalize("NFC", password)
    return normalized.encode("utf-8")


def derive_master_secret(normalized_password: bytes, params: Argon2Params) -> bytes:
    """Derive 256-bit intermediate master secret using Argon2id."""
    if not params.salt:
        raise InvalidParameterError("Salt cannot be empty when deriving keys")

    try:
        return argon2_lowlevel.hash_secret_raw(
            secret=normalized_password,
            salt=params.salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=DERIVED_KEY_LENGTH,
            type=argon2_lowlevel.Type.ID,
        )
    except Exception as exc:
        raise CryptoError("Argon2id key derivation failed") from exc


def expand_key(master_secret: bytes, info: bytes, length: int = DERIVED_KEY_LENGTH) -> bytes:
    """Expand intermediate master secret into domain-separated subkey via HKDF-Expand-SHA256."""
    if len(master_secret) != DERIVED_KEY_LENGTH:
        raise InvalidParameterError(f"Master secret must be {DERIVED_KEY_LENGTH} bytes")
    
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return hkdf.derive(master_secret)


def derive_kek(password: str, params: Argon2Params) -> bytes:
    """Convenience helper to derive Key Encryption Key (KEK) directly from master password.
    
    Performs normalization, Argon2id derivation, and HKDF domain separation.
    """
    pwd_bytes = normalize_master_password(password)
    master_secret = derive_master_secret(pwd_bytes, params)
    return expand_key(master_secret, DOMAIN_KEK_V1)


def derive_auth_secret(password: str, params: Argon2Params) -> bytes:
    """Derive client authentication secret separated from the KEK domain."""
    pwd_bytes = normalize_master_password(password)
    master_secret = derive_master_secret(pwd_bytes, params)
    return expand_key(master_secret, DOMAIN_AUTH_V1)
