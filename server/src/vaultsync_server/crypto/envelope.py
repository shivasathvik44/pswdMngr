"""Versioned encrypted envelope serialization, parsing, and validation."""

import base64
import json
import uuid
from typing import Any, Final

from pydantic import BaseModel, Field, ValidationError

from vaultsync_server.crypto.errors import (
    CryptoError,
    InputSizeExceededError,
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
)
from vaultsync_server.crypto.kdf import (
    Argon2Params,
    MAX_MEMORY_COST_KIB,
    MAX_PARALLELISM,
    MAX_TIME_COST,
    MIN_MEMORY_COST_KIB,
    MIN_PARALLELISM,
    MIN_TIME_COST,
    SALT_LENGTH,
)

CURRENT_PROTOCOL_VERSION: Final[int] = 1
SUPPORTED_CIPHER_ALGORITHM: Final[str] = "AES-256-GCM"
SUPPORTED_KDF_ALGORITHM: Final[str] = "Argon2id"

NONCE_LENGTH: Final[int] = 12       # 96 bits for AES-GCM
TAG_LENGTH: Final[int] = 16         # 128 bits authentication tag
KEY_LENGTH: Final[int] = 32         # 256 bits VEK
WRAPPED_KEY_CIPHERTEXT_LEN: Final[int] = KEY_LENGTH + TAG_LENGTH  # 48 bytes

MAX_PLAINTEXT_RECORD_SIZE: Final[int] = 1_048_576  # 1 MiB
MAX_RECORD_CIPHERTEXT_SIZE: Final[int] = MAX_PLAINTEXT_RECORD_SIZE + TAG_LENGTH
MAX_JSON_ENVELOPE_BYTES: Final[int] = 2_097_152     # 2 MiB


def b64encode(data: bytes) -> str:
    """Encode bytes into standard Base64 string without trailing newlines."""
    return base64.b64encode(data).decode("ascii")


def b64decode(encoded: str, expected_length: int | None = None) -> bytes:
    """Decode standard Base64 string into bytes with length verification."""
    if not isinstance(encoded, str) or not encoded:
        raise MalformedEnvelopeError("Base64 input must be a non-empty string")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise MalformedEnvelopeError("Invalid Base64 payload encoding") from exc

    if expected_length is not None and len(raw) != expected_length:
        raise MalformedEnvelopeError(
            f"Decoded byte length mismatch: expected {expected_length}, got {len(raw)}"
        )
    return raw


class KdfMetadata(BaseModel):
    """Metadata describing the KDF parameters used to derive the KEK."""

    algorithm: str = Field(default=SUPPORTED_KDF_ALGORITHM)
    memory_cost: int = Field(ge=MIN_MEMORY_COST_KIB, le=MAX_MEMORY_COST_KIB)
    time_cost: int = Field(ge=MIN_TIME_COST, le=MAX_TIME_COST)
    parallelism: int = Field(ge=MIN_PARALLELISM, le=MAX_PARALLELISM)
    salt: str  # Base64 encoded 16-byte salt

    def to_argon2_params(self) -> Argon2Params:
        """Convert metadata to typed Argon2Params with decoded salt."""
        salt_bytes = b64decode(self.salt, expected_length=SALT_LENGTH)
        return Argon2Params(
            memory_cost=self.memory_cost,
            time_cost=self.time_cost,
            parallelism=self.parallelism,
            salt=salt_bytes,
        )

    @classmethod
    def from_argon2_params(cls, params: Argon2Params) -> "KdfMetadata":
        """Build KdfMetadata from typed Argon2Params."""
        if not params.salt or len(params.salt) != SALT_LENGTH:
            raise InvalidParameterError(f"Salt must be exactly {SALT_LENGTH} bytes")
        return cls(
            algorithm=SUPPORTED_KDF_ALGORITHM,
            memory_cost=params.memory_cost,
            time_cost=params.time_cost,
            parallelism=params.parallelism,
            salt=b64encode(params.salt),
        )


class WrappedKeyEnvelope(BaseModel):
    """Envelope storing the wrapped Vault Encryption Key (WVEK)."""

    version: int = Field(default=CURRENT_PROTOCOL_VERSION)
    algorithm: str = Field(default=SUPPORTED_CIPHER_ALGORITHM)
    kdf: KdfMetadata
    nonce: str       # Base64 encoded 12-byte nonce
    ciphertext: str  # Base64 encoded 48-byte (32B key + 16B tag)

    def compute_aad(self) -> bytes:
        """Calculate authenticated associated data deterministically bound to key wrapping."""
        return f"vaultsync:key-wrap:v{self.version}:{self.kdf.algorithm}".encode("utf-8")

    def to_json(self) -> str:
        """Serialize envelope to canonical compact JSON."""
        return json.dumps(self.model_dump(), separators=(",", ":"))

    @classmethod
    def from_json(cls, json_str: str) -> "WrappedKeyEnvelope":
        """Parse and strictly validate a WrappedKeyEnvelope from JSON."""
        if not isinstance(json_str, str):
            raise MalformedEnvelopeError("Envelope payload must be a string")
        if len(json_str.encode("utf-8")) > MAX_JSON_ENVELOPE_BYTES:
            raise InputSizeExceededError("Envelope JSON exceeds maximum allowed size")

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise MalformedEnvelopeError("Failed to parse envelope JSON") from exc

        if not isinstance(data, dict):
            raise MalformedEnvelopeError("Envelope JSON must be an object")

        version = data.get("version")
        if version != CURRENT_PROTOCOL_VERSION:
            raise UnsupportedVersionError(
                f"Unsupported envelope version {version} (expected {CURRENT_PROTOCOL_VERSION})"
            )

        algorithm = data.get("algorithm")
        if algorithm != SUPPORTED_CIPHER_ALGORITHM:
            raise UnsupportedAlgorithmError(
                f"Unsupported algorithm '{algorithm}' (expected '{SUPPORTED_CIPHER_ALGORITHM}')"
            )

        kdf_info = data.get("kdf")
        if isinstance(kdf_info, dict) and kdf_info.get("algorithm") != SUPPORTED_KDF_ALGORITHM:
            raise UnsupportedAlgorithmError(
                f"Unsupported KDF '{kdf_info.get('algorithm')}' (expected '{SUPPORTED_KDF_ALGORITHM}')"
            )

        try:
            envelope = cls.model_validate(data)
        except ValidationError as exc:
            for err in exc.errors():
                loc = err.get("loc", ())
                if any(param in loc for param in ("memory_cost", "time_cost", "parallelism")):
                    raise InvalidParameterError(f"Invalid KDF parameter: {err.get('msg')}") from exc
            raise MalformedEnvelopeError(f"Envelope schema validation failed: {exc}") from exc

        # Verify decoded byte lengths
        b64decode(envelope.nonce, expected_length=NONCE_LENGTH)
        b64decode(envelope.ciphertext, expected_length=WRAPPED_KEY_CIPHERTEXT_LEN)
        b64decode(envelope.kdf.salt, expected_length=SALT_LENGTH)

        return envelope


class EncryptedRecordEnvelope(BaseModel):
    """Envelope storing an encrypted vault entry."""

    version: int = Field(default=CURRENT_PROTOCOL_VERSION)
    algorithm: str = Field(default=SUPPORTED_CIPHER_ALGORITHM)
    record_id: str   # UUID string
    nonce: str       # Base64 encoded 12-byte nonce
    ciphertext: str  # Base64 encoded ciphertext + 16B tag

    def compute_aad(self) -> bytes:
        """Calculate authenticated associated data cryptographically bound to record_id."""
        return f"vaultsync:record:v{self.version}:{self.record_id}".encode("utf-8")

    def to_json(self) -> str:
        """Serialize envelope to canonical compact JSON."""
        return json.dumps(self.model_dump(), separators=(",", ":"))

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedRecordEnvelope":
        """Parse and strictly validate an EncryptedRecordEnvelope from JSON."""
        if not isinstance(json_str, str):
            raise MalformedEnvelopeError("Record envelope payload must be a string")
        if len(json_str.encode("utf-8")) > MAX_JSON_ENVELOPE_BYTES:
            raise InputSizeExceededError("Record envelope JSON exceeds maximum size limit")

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise MalformedEnvelopeError("Failed to parse record envelope JSON") from exc

        if not isinstance(data, dict):
            raise MalformedEnvelopeError("Record envelope JSON must be an object")

        version = data.get("version")
        if version != CURRENT_PROTOCOL_VERSION:
            raise UnsupportedVersionError(
                f"Unsupported record version {version} (expected {CURRENT_PROTOCOL_VERSION})"
            )

        algorithm = data.get("algorithm")
        if algorithm != SUPPORTED_CIPHER_ALGORITHM:
            raise UnsupportedAlgorithmError(
                f"Unsupported cipher algorithm '{algorithm}' (expected '{SUPPORTED_CIPHER_ALGORITHM}')"
            )

        record_id = data.get("record_id")
        if not isinstance(record_id, str) or not record_id.strip():
            raise MalformedEnvelopeError("record_id must be a non-empty string")

        try:
            envelope = cls.model_validate(data)
        except ValidationError as exc:
            raise MalformedEnvelopeError(f"Record schema validation failed: {exc}") from exc

        # Verify decoded byte lengths
        b64decode(envelope.nonce, expected_length=NONCE_LENGTH)
        raw_ct = b64decode(envelope.ciphertext)
        if len(raw_ct) < TAG_LENGTH:
            raise MalformedEnvelopeError(
                f"Ciphertext length {len(raw_ct)} is smaller than tag length {TAG_LENGTH}"
            )
        if len(raw_ct) > MAX_RECORD_CIPHERTEXT_SIZE:
            raise InputSizeExceededError(
                f"Ciphertext length {len(raw_ct)} exceeds maximum limit {MAX_RECORD_CIPHERTEXT_SIZE}"
            )

        return envelope
