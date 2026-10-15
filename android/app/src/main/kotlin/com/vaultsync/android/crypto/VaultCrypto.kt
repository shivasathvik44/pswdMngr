package com.vaultsync.android.crypto

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.text.Normalizer
import java.util.Arrays
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Native cryptographic implementation of the VaultSync protocol for Android.
 *
 * Provides bidirectional parity with the Python desktop client:
 * - Master Secret derivation: Argon2id (64 MiB, t=3, p=4, 32 bytes output)
 * - Domain Separation: HKDF-SHA256 (skip-extract, info="vaultsync:kek:v1")
 * - Authenticated Cipher: AES-256-GCM (12-byte nonce, 16-byte tag, specific AAD)
 */
object VaultCrypto {

    const val PROTOCOL_VERSION = 1
    const val CIPHER_ALGORITHM = "AES-256-GCM"
    const val KDF_ALGORITHM = "Argon2id"

    const val KDF_MEMORY_COST = 65536 // 64 MiB
    const val KDF_TIME_COST = 3
    const val KDF_PARALLELISM = 4
    const val KEY_SIZE_BYTES = 32     // 256 bits
    const val NONCE_SIZE_BYTES = 12   // 96 bits
    const val TAG_SIZE_BYTES = 16     // 128 bits
    const val SALT_SIZE_BYTES = 16    // 128 bits

    const val MAX_ALLOWED_MEMORY_COST = 131072 // 128 MiB upper bound guard
    const val MAX_ALLOWED_TIME_COST = 10
    const val MAX_ALLOWED_PARALLELISM = 16

    val AAD_KEY_WRAP: ByteArray = "vaultsync:key-wrap:v1:Argon2id".toByteArray(StandardCharsets.UTF_8)
    const val AAD_RECORD_PREFIX: String = "vaultsync:record:v1:"
    val HKDF_INFO_KEK: ByteArray = "vaultsync:kek:v1".toByteArray(StandardCharsets.UTF_8)

    private val secureRandom = SecureRandom()

    private val jsonHelper = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    // ------------------------------------------------------------------------
    // JSON Serialization Helpers
    // ------------------------------------------------------------------------

    fun parseWrappedKeyEnvelope(json: String): WrappedKeyEnvelope {
        return jsonHelper.decodeFromString<WrappedKeyEnvelope>(json)
    }

    fun serializeWrappedKeyEnvelope(envelope: WrappedKeyEnvelope): String {
        return jsonHelper.encodeToString(envelope)
    }

    fun parseRecordEnvelope(json: String): RecordEnvelope {
        return jsonHelper.decodeFromString<RecordEnvelope>(json)
    }

    fun serializeRecordEnvelope(envelope: RecordEnvelope): String {
        return jsonHelper.encodeToString(envelope)
    }

    // ------------------------------------------------------------------------
    // Key Derivation Functions
    // ------------------------------------------------------------------------

    /**
     * Normalize password to Unicode NFC and return UTF-8 bytes.
     */
    fun normalizePassword(password: String): ByteArray {
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFC)
        return normalized.toByteArray(StandardCharsets.UTF_8)
    }

    fun normalizePassword(password: CharArray): ByteArray {
        val str = String(password)
        val normalized = Normalizer.normalize(str, Normalizer.Form.NFC)
        return normalized.toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Derive a 32-byte master secret from master password and salt using Argon2id.
     */
    fun deriveMasterSecret(
        password: String,
        salt: ByteArray,
        memoryCostKiB: Int = KDF_MEMORY_COST,
        timeCost: Int = KDF_TIME_COST,
        parallelism: Int = KDF_PARALLELISM
    ): ByteArray {
        if (salt.size < 16) {
            throw InvalidParameterException("Salt must be at least 16 bytes")
        }
        if (memoryCostKiB > MAX_ALLOWED_MEMORY_COST || timeCost > MAX_ALLOWED_TIME_COST || parallelism > MAX_ALLOWED_PARALLELISM) {
            throw InvalidParameterException("KDF parameters exceed safe limits")
        }

        val passwordBytes = normalizePassword(password)
        try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(memoryCostKiB)
                .withIterations(timeCost)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build()

            val generator = Argon2BytesGenerator()
            generator.init(params)
            val masterSecret = ByteArray(KEY_SIZE_BYTES)
            generator.generateBytes(passwordBytes, masterSecret)
            return masterSecret
        } finally {
            clearBytes(passwordBytes)
        }
    }

    fun deriveMasterSecret(password: CharArray, kdf: KdfParameters): ByteArray {
        val saltBytes = Base64.getDecoder().decode(kdf.salt)
        val passwordString = String(password)
        return deriveMasterSecret(
            password = passwordString,
            salt = saltBytes,
            memoryCostKiB = kdf.memoryCost,
            timeCost = kdf.timeCost,
            parallelism = kdf.parallelism
        )
    }

    fun deriveMasterSecret(password: String, kdf: KdfParameters): ByteArray {
        val saltBytes = Base64.getDecoder().decode(kdf.salt)
        return deriveMasterSecret(
            password = password,
            salt = saltBytes,
            memoryCostKiB = kdf.memoryCost,
            timeCost = kdf.timeCost,
            parallelism = kdf.parallelism
        )
    }

    /**
     * Derive a 32-byte Key Encryption Key (KEK) via HKDF-SHA256 domain separation.
     */
    fun deriveKek(masterSecret: ByteArray): ByteArray {
        if (masterSecret.size != KEY_SIZE_BYTES) {
            throw InvalidParameterException("Master secret must be exactly 32 bytes")
        }
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters.skipExtractParameters(masterSecret, HKDF_INFO_KEK))
        val kek = ByteArray(KEY_SIZE_BYTES)
        hkdf.generateBytes(kek, 0, KEY_SIZE_BYTES)
        return kek
    }

    // ------------------------------------------------------------------------
    // Symmetric Authenticated Encryption (AES-256-GCM)
    // ------------------------------------------------------------------------

    fun encryptAesGcm(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != KEY_SIZE_BYTES) {
            throw InvalidParameterException("AES-256 key must be 32 bytes")
        }
        if (nonce.size != NONCE_SIZE_BYTES) {
            throw InvalidParameterException("GCM nonce must be 12 bytes")
        }

        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(TAG_SIZE_BYTES * 8, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            return cipher.doFinal(plaintext)
        } catch (e: Exception) {
            throw CryptoException("AES-GCM encryption failed: ${e.message}", e)
        }
    }

    fun decryptAesGcm(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != KEY_SIZE_BYTES) {
            throw InvalidParameterException("AES-256 key must be 32 bytes")
        }
        if (nonce.size != NONCE_SIZE_BYTES) {
            throw InvalidParameterException("GCM nonce must be 12 bytes")
        }
        if (ciphertextWithTag.size < TAG_SIZE_BYTES) {
            throw DecryptionFailedException("Ciphertext payload too short to contain authentication tag")
        }

        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(TAG_SIZE_BYTES * 8, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            if (aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            return cipher.doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            throw DecryptionFailedException("Authentication tag verification failed", e)
        } catch (e: GeneralSecurityException) {
            throw DecryptionFailedException("Decryption error: ${e.message}", e)
        } catch (e: Exception) {
            throw CryptoException("Unexpected decryption failure: ${e.message}", e)
        }
    }

    // ------------------------------------------------------------------------
    // Vault Key Wrapping / Unwrapping (VEK)
    // ------------------------------------------------------------------------

    fun generateRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    fun generateVaultKey(): ByteArray {
        return generateRandomBytes(KEY_SIZE_BYTES)
    }

    fun wrapVaultKey(
        vaultKey: ByteArray,
        masterPassword: String,
        customSalt: ByteArray? = null
    ): Pair<ByteArray, WrappedKeyEnvelope> {
        val salt = customSalt ?: generateRandomBytes(SALT_SIZE_BYTES)
        val masterSecret = deriveMasterSecret(masterPassword, salt)
        val kek = deriveKek(masterSecret)
        clearBytes(masterSecret)

        try {
            val nonce = generateRandomBytes(NONCE_SIZE_BYTES)
            val ciphertextWithTag = encryptAesGcm(kek, nonce, vaultKey, AAD_KEY_WRAP)

            val b64Encoder = Base64.getEncoder()
            val envelope = WrappedKeyEnvelope(
                version = PROTOCOL_VERSION,
                algorithm = CIPHER_ALGORITHM,
                kdf = KdfParameters(
                    algorithm = KDF_ALGORITHM,
                    memoryCost = KDF_MEMORY_COST,
                    timeCost = KDF_TIME_COST,
                    parallelism = KDF_PARALLELISM,
                    salt = b64Encoder.encodeToString(salt)
                ),
                nonce = b64Encoder.encodeToString(nonce),
                ciphertext = b64Encoder.encodeToString(ciphertextWithTag)
            )
            return Pair(salt, envelope)
        } finally {
            clearBytes(kek)
        }
    }

    fun wrapVaultKey(vaultKey: ByteArray, masterPassword: CharArray): WrappedKeyEnvelope {
        val (_, envelope) = wrapVaultKey(vaultKey, String(masterPassword))
        return envelope
    }

    fun unwrapVaultKey(envelope: WrappedKeyEnvelope, masterPassword: String): ByteArray {
        if (envelope.version != PROTOCOL_VERSION) {
            throw UnsupportedVersionException("Unsupported envelope version: ${envelope.version}")
        }
        if (envelope.algorithm != CIPHER_ALGORITHM) {
            throw UnsupportedAlgorithmException("Unsupported cipher algorithm: ${envelope.algorithm}")
        }
        if (envelope.kdf.algorithm != KDF_ALGORITHM) {
            throw UnsupportedAlgorithmException("Unsupported KDF algorithm: ${envelope.kdf.algorithm}")
        }
        if (envelope.kdf.memoryCost > MAX_ALLOWED_MEMORY_COST || envelope.kdf.timeCost > MAX_ALLOWED_TIME_COST) {
            throw InvalidParameterException("KDF parameters exceed safety threshold")
        }

        val b64Decoder = Base64.getDecoder()
        val salt = b64Decoder.decode(envelope.kdf.salt)
        val nonce = b64Decoder.decode(envelope.nonce)
        val ciphertextWithTag = b64Decoder.decode(envelope.ciphertext)

        val masterSecret = deriveMasterSecret(
            password = masterPassword,
            salt = salt,
            memoryCostKiB = envelope.kdf.memoryCost,
            timeCost = envelope.kdf.timeCost,
            parallelism = envelope.kdf.parallelism
        )
        val kek = deriveKek(masterSecret)
        clearBytes(masterSecret)

        try {
            return decryptAesGcm(kek, nonce, ciphertextWithTag, AAD_KEY_WRAP)
        } finally {
            clearBytes(kek)
        }
    }

    fun unwrapVaultKey(envelope: WrappedKeyEnvelope, masterPassword: CharArray): ByteArray {
        return unwrapVaultKey(envelope, String(masterPassword))
    }

    // ------------------------------------------------------------------------
    // Record Encryption / Decryption
    // ------------------------------------------------------------------------

    fun encryptRecord(vaultKey: ByteArray, recordId: String, plaintextUtf8: String): RecordEnvelope {
        if (recordId.isBlank()) {
            throw InvalidParameterException("Record ID cannot be empty")
        }
        val aad = (AAD_RECORD_PREFIX + recordId).toByteArray(StandardCharsets.UTF_8)
        val nonce = generateRandomBytes(NONCE_SIZE_BYTES)
        val plaintextBytes = plaintextUtf8.toByteArray(StandardCharsets.UTF_8)
        val ciphertextWithTag = encryptAesGcm(vaultKey, nonce, plaintextBytes, aad)

        val b64Encoder = Base64.getEncoder()
        return RecordEnvelope(
            version = PROTOCOL_VERSION,
            algorithm = CIPHER_ALGORITHM,
            recordId = recordId,
            nonce = b64Encoder.encodeToString(nonce),
            ciphertext = b64Encoder.encodeToString(ciphertextWithTag)
        )
    }

    fun encryptRecord(recordId: String, plaintextUtf8: String, vaultKey: ByteArray): RecordEnvelope {
        return encryptRecord(vaultKey, recordId, plaintextUtf8)
    }

    fun decryptRecord(vaultKey: ByteArray, envelope: RecordEnvelope): String {
        if (envelope.version != PROTOCOL_VERSION) {
            throw UnsupportedVersionException("Unsupported envelope version: ${envelope.version}")
        }
        if (envelope.algorithm != CIPHER_ALGORITHM) {
            throw UnsupportedAlgorithmException("Unsupported cipher algorithm: ${envelope.algorithm}")
        }
        if (envelope.recordId.isBlank()) {
            throw InvalidParameterException("Envelope record_id cannot be blank")
        }

        val aad = (AAD_RECORD_PREFIX + envelope.recordId).toByteArray(StandardCharsets.UTF_8)
        val b64Decoder = Base64.getDecoder()
        val nonce = b64Decoder.decode(envelope.nonce)
        val ciphertextWithTag = b64Decoder.decode(envelope.ciphertext)

        val plaintextBytes = decryptAesGcm(vaultKey, nonce, ciphertextWithTag, aad)
        return String(plaintextBytes, StandardCharsets.UTF_8)
    }

    fun decryptRecord(envelope: RecordEnvelope, vaultKey: ByteArray): String {
        return decryptRecord(vaultKey, envelope)
    }

    // ------------------------------------------------------------------------
    // Secure Key Material Sanitization
    // ------------------------------------------------------------------------

    fun clearBytes(array: ByteArray?) {
        if (array != null) {
            Arrays.fill(array, 0.toByte())
        }
    }
}
