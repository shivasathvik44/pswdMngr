"""Safe, well-defined cryptographic exceptions for VaultSync.

All errors inherit from CryptoError and sanitize exception messages
to ensure secret material (passwords, keys, plaintexts) is never leaked.
"""


class CryptoError(Exception):
    """Base exception for all cryptographic errors in VaultSync."""


class DecryptionFailedError(CryptoError):
    """Raised when authenticated decryption or key unwrapping fails.
    
    This error is intentionally unified and indistinguishable between
    incorrect passwords, corrupted ciphertexts, invalid tags, or altered AAD
    to prevent cryptographic oracle or side-channel leakage.
    """

    def __init__(self, message: str = "Decryption failed: authenticity check failed or invalid key"):
        super().__init__(message)


class InvalidParameterError(CryptoError):
    """Raised when cryptographic parameters (memory cost, iterations, salt/key size) are invalid."""


class MalformedEnvelopeError(CryptoError):
    """Raised when an encrypted envelope fails validation, parsing, or decoding."""


class UnsupportedVersionError(CryptoError):
    """Raised when encountering an unsupported or future envelope format version."""


class UnsupportedAlgorithmError(CryptoError):
    """Raised when encountering an unsupported cipher or KDF algorithm."""


class InputSizeExceededError(CryptoError):
    """Raised when an input payload exceeds the maximum defensive size limit."""
