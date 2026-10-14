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

    LIMITS OF HEURISTIC SCORING & SHANNON ENTROPY:
    The score (0-100) returned here is a heuristic quality score for user guidance,
    NOT measured cryptographic entropy. Statistical or Shannon entropy estimates on
    human-chosen text significantly overestimate real security because human choices
    suffer from severe cognitive biases, common vocabularies, and syntactic predictability.

    TRUE MEASURED ENTROPY REQUIRES UNBIASED RANDOM SELECTION:
    To achieve true measured cryptographic entropy, words MUST be selected randomly
    using a CSPRNG or physical dice from an established wordlist (e.g. the standard
    7,776-word Diceware list where log2(7776) ≈ 12.92 bits per word):
    - 4 randomly chosen words provide ~51.7 bits of entropy.
    - 5 randomly chosen words provide ~64.6 bits of entropy (recommended minimum).
    - 6 randomly chosen words provide ~77.5 bits of entropy.

    OFFLINE GUESSING THREAT MODEL:
    An attacker who compromises the server database obtains the public KDF salt and
    wrapped VEK ciphertext. This enables offline dictionary cracking attempts using
    Argon2id. A truly random, high-entropy passphrase is the primary barrier preventing
    offline key recovery.

    Returns:
        tuple: (score 0-100, label 'Weak'|'Moderate'|'Strong'|'Excellent', list of recommendations)
    """
    if not passphrase:
        return 0, "Empty", [
            "Please enter a passphrase.",
            "Recommendation: Use 5+ words randomly chosen from a Diceware wordlist (~12.9 bits/word).",
        ]

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

    # Word-based scoring (favors length and memorability)
    if len(words) >= 5 and length >= 20:
        score += 75
    elif len(words) >= 4 and length >= 16:
        score += 65
    elif len(words) >= 3 and length >= 12:
        score += 45
    elif len(words) >= 2 and length >= 10:
        score += 25

    # Length-based scoring
    if length >= 24:
        score += 25
    elif length >= 16:
        score += 15
    elif length >= 10:
        score += 5
    else:
        score -= 20
        recs.append("Minimum recommended length is 16+ characters or 4-5 distinct words.")

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
        recs.append("An attacker with a stolen server database can test guesses offline. Use 5+ random words.")
    elif score < 70:
        label = "Moderate"
        recs.append("Heuristic score only. For true offline resilience (≥64 bits), use 5+ words randomly chosen from a Diceware list.")
    elif score < 90:
        label = "Strong"
        recs.append("Heuristic estimate. Ensure words are randomly selected (e.g. Diceware) rather than predictable phrases.")
    else:
        label = "Excellent"
        recs.append("Heuristic estimate: High. Protected against offline dictionary guessing if words were selected randomly.")

    return score, label, recs


def clear_key_material(key: Optional[VaultKey]) -> None:
    """Best-effort zeroization and clearing of key material references from memory.

    Note on Python memory semantics:
    Python's memory management, immutability of certain primitives, and OS virtual
    memory paging preclude guaranteed hardware-level forensic erasure. This function
    overwrites mutable internal byte buffers with zeros before clearing them.

    Raises:
        CryptoError: If a non-None key object does not expose a supported clearing interface.
    """
    if key is None:
        return

    cleared = False
    if hasattr(key, "clear") and callable(key.clear):
        key.clear()
        cleared = True
    elif hasattr(key, "_key") and isinstance(key._key, bytearray):
        for i in range(len(key._key)):
            key._key[i] = 0
        key._key.clear()
        cleared = True
    elif hasattr(key, "_raw") and isinstance(key._raw, bytearray):
        for i in range(len(key._raw)):
            key._raw[i] = 0
        key._raw.clear()
        cleared = True

    if not cleared:
        raise CryptoError("Failed to clear key material: object does not expose mutable key buffer or clear method")

