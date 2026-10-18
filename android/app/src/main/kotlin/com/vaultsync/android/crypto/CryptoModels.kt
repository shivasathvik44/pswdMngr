package com.vaultsync.android.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Custom cryptographic exceptions matching the VaultSync protocol error types.
 */
open class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

class DecryptionFailedException(message: String = "Decryption failed: authentication tag verification error", cause: Throwable? = null) : CryptoException(message, cause)

class UnsupportedVersionException(message: String = "Unsupported envelope protocol version", cause: Throwable? = null) : CryptoException(message, cause)

class UnsupportedAlgorithmException(message: String = "Unsupported cipher or KDF algorithm", cause: Throwable? = null) : CryptoException(message, cause)

class InvalidParameterException(message: String = "Invalid cryptographic parameter bounds", cause: Throwable? = null) : CryptoException(message, cause)

class SecureStorageException(message: String = "Secure Keystore storage failure", cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Parameters for the Argon2id Key Derivation Function.
 */
@Serializable
data class KdfParameters(
    val algorithm: String = "Argon2id",
    @SerialName("memory_cost") val memoryCost: Int = 65536,
    @SerialName("time_cost") val timeCost: Int = 3,
    val parallelism: Int = 4,
    val salt: String // Base64 encoded 16-byte salt
)

/**
 * Envelope for the wrapped Vault Encryption Key (VEK).
 */
@Serializable
data class WrappedKeyEnvelope(
    val version: Int = 1,
    val algorithm: String = "AES-256-GCM",
    val kdf: KdfParameters,
    val nonce: String,     // Base64 encoded 12-byte nonce
    val ciphertext: String // Base64 encoded ciphertext + 16-byte GCM tag
)

/**
 * Envelope for an individual encrypted vault record.
 */
@Serializable
data class RecordEnvelope(
    val version: Int = 1,
    val algorithm: String = "AES-256-GCM",
    @SerialName("record_id") val recordId: String,
    val nonce: String,     // Base64 encoded 12-byte nonce
    val ciphertext: String // Base64 encoded ciphertext + 16-byte GCM tag
)

/**
 * Custom exceptions for biometric authentication and Keystore lifecycle.
 */
open class BiometricException(message: String, cause: Throwable? = null) : CryptoException(message, cause)

class BiometricKeyInvalidatedException(
    message: String = "Biometric credentials have changed. Re-authentication with Master Password required.",
    cause: Throwable? = null
) : BiometricException(message, cause)

class BiometricAuthFailedException(
    message: String,
    cause: Throwable? = null
) : BiometricException(message, cause)

/**
 * Envelope for a biometric-protected Vault Encryption Key (VEK).
 * Encrypted using a device-local hardware-backed Android Keystore AES-256-GCM key.
 */
@Serializable
data class BiometricWrappedKeyEnvelope(
    val version: Int = 1,
    @SerialName("account_id") val accountId: String,
    val nonce: String,     // Base64 encoded 12-byte IV/nonce
    val ciphertext: String, // Base64 encoded VEK ciphertext + 16-byte GCM tag
    @SerialName("created_at") val createdAt: Long = System.currentTimeMillis()
)

