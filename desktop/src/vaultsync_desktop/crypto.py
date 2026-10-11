"""VaultSync Desktop cryptographic engine.

Integrates standardized Argon2id key derivation, HKDF domain separation,
AES-256-GCM envelope serialization, and passphrase entropy guidance.
"""

import math
import re
from typing import Optional

from vaultsync_server.crypto.envelope import (
    CURRENT_PROTOCOL_VERSION,
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
    derive_kek,
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


def create_initial_vault_key_and_envelope(
    master_password: str,
    memory_cost: int = DEFAULT_MEMORY_COST_KIB,
    time_cost: int = DEFAULT_TIME_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> tuple[VaultKey, str, str]:
    """Generate a fresh random 256-bit VEK and wrap it with the user's master password.

    Returns:
        tuple of (raw_vek, kdf_salt_b64, wrapped_vault_key_json_envelope)
    """
    salt_bytes = generate_salt()
    kdf_params = Argon2Params(
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        salt=salt_bytes,
    )
    kek = derive_kek(master_password, kdf_params)
    vek = VaultKey.generate()
    envelope = wrap_vault_key(vek, kek, kdf_params)
    return vek, b64encode(salt_bytes), envelope.to_json()


def unlock_vault_with_master_password(
    wrapped_vault_key_json: str,
    master_password: str,
) -> VaultKey:
    """Unwrap and verify the 256-bit VEK from the stored WrappedKeyEnvelope.
    
    Raises:
        DecryptionFailedError: If the master password is wrong or envelope was tampered with.
        MalformedEnvelopeError: If the envelope JSON or structure is invalid.
    """
    envelope = WrappedKeyEnvelope.from_json(wrapped_vault_key_json)
    return unwrap_vault_key(envelope, master_password)


def rotate_master_password(
    current_vek: VaultKey,
    new_master_password: str,
    memory_cost: int = DEFAULT_MEMORY_COST_KIB,
    time_cost: int = DEFAULT_TIME_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> tuple[str, str]:
    """Derive a new KEK from the new master password and re-wrap the existing VEK.

    Preserves the raw 256-bit VEK so that existing encrypted records do not need re-encryption.

    Returns:
        tuple of (new_kdf_salt_b64, new_wrapped_vault_key_json)
    """
    new_salt_bytes = generate_salt()
    new_kdf_params = Argon2Params(
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        salt=new_salt_bytes,
    )
    new_envelope = rewrap_vault_key(current_vek, new_master_password, new_kdf_params)
    return b64encode(new_salt_bytes), new_envelope.to_json()


def evaluate_passphrase_strength(passphrase: str) -> tuple[int, str, list[str]]:
    """Assess passphrase strength with emphasis on multi-word passphrases (Diceware style).

    Returns:
        tuple: (score 0-100, label 'Weak'|'Moderate'|'Strong'|'Excellent', list of recommendations)
    """
    if not passphrase:
        return 0, "Empty", ["Please enter a passphrase."]

    import unicodedata
    normalized = unicodedata.normalize("NFC", passphrase)
    length = len(normalized)
    # Check for whitespace/hyphen/underscore or CamelCase words
    words = [w for w in re.split(r"[\s\-_]+", normalized) if len(w) >= 3]
    if len(words) <= 1:
        camel_words = [w for w in re.findall(r"[A-Z][a-z]+|[a-z]+|[A-Z]+", normalized) if len(w) >= 3]
        if len(camel_words) > len(words):
            words = camel_words

    recs: list[str] = []
    score = 0

    # Word-based scoring (favors memorability and high entropy)
    if len(words) >= 4 and length >= 16:
        score += 70
    elif len(words) >= 3 and length >= 12:
        score += 50
    elif len(words) >= 2 and length >= 10:
        score += 30

    # Length-based scoring
    if length >= 20:
        score += 30
    elif length >= 14:
        score += 20
    elif length >= 10:
        score += 10
    else:
        score -= 20
        recs.append("Minimum recommended length is 14 characters or 4 distinct words.")

    # Character variety bonus
    has_upper = bool(re.search(r"[A-Z]", normalized))
    has_lower = bool(re.search(r"[a-z]", normalized))
    has_digit = bool(re.search(r"[0-9]", normalized))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", normalized))
    variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
    score += variety_count * 5

    # Cap score 0-100
    score = max(0, min(100, score))

    if score < 40:
        label = "Weak"
        recs.append("An attacker with a stolen server database can test guesses offline. Use a stronger passphrase.")
    elif score < 70:
        label = "Moderate"
        recs.append("Consider adding 1-2 more random words for long-term offline resilience.")
    elif score < 90:
        label = "Strong"
    else:
        label = "Excellent"

    return score, label, recs


def clear_key_material(key: Optional[VaultKey]) -> None:
    """Best-effort clearing of key material references from memory.

    Note: Python's memory management and garbage collection cannot guarantee
    immediate hardware zeroization of freed buffers.
    """
    if key is not None:
        try:
            # Overwrite internal bytearray if present, or clear reference
            if hasattr(key, "_raw") and isinstance(key._raw, bytearray):
                for i in range(len(key._raw)):
                    key._raw[i] = 0
        except Exception:
            pass
