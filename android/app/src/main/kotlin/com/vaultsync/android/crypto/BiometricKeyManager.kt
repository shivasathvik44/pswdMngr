package com.vaultsync.android.crypto

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Manages biometric hardware key generation, cryptographic VEK wrapping/unwrapping,
 * enrollment validation, and per-account isolation via Android Keystore and AES-256-GCM.
 *
 * Security Invariants:
 * 1. Hardware Binding: Android Keystore keys require biometric user authentication
 *    (setUserAuthenticationRequired = true) and are invalidated on enrollment change
 *    (setInvalidatedByBiometricEnrollment = true).
 * 2. Cryptographic Protection: The raw VEK is NEVER stored in plaintext. It is encrypted
 *    with AES-256-GCM using a dedicated Keystore key and an account-bound AAD.
 * 3. Account Isolation: Every biometric key and envelope is strictly partitioned by accountId.
 *    Account A's envelope can never be decrypted under Account B.
 * 4. Recovery Path: Biometric unlock is an alternate path to obtain the VEK. If biometrics
 *    fail, are cancelled, or are invalidated, the master-password flow remains intact.
 */
open class BiometricKeyManager(
    private val context: Context? = null
) {

    companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val KEY_ALIAS_PREFIX = "VaultSyncBiometricKey_"
        const val PREFS_NAME = "vaultsync_biometric_prefs"
        const val AAD_PREFIX = "vaultsync:biometric-wrap:v1:"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_LENGTH_BITS = 128
        const val GCM_NONCE_LENGTH_BYTES = 12
        const val VEK_SIZE_BYTES = 32

        private val jsonHelper = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }
    }

    enum class BiometricStatus {
        AVAILABLE,
        NOT_ENROLLED,
        NO_HARDWARE,
        HW_UNAVAILABLE,
        SECURITY_UPDATE_REQUIRED,
        UNSUPPORTED
    }

    private val inMemoryFallback = mutableMapOf<String, String>()
    private val inMemoryKeys = mutableMapOf<String, SecretKey>()

    protected open val prefs: SharedPreferences? by lazy {
        context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun validateAccountId(accountId: String) {
        require(accountId.isNotBlank()) { "AccountId must not be blank" }
        require(accountId.length <= 128) { "AccountId exceeds maximum length of 128 characters" }
        require(accountId.matches(Regex("^[a-zA-Z0-9_-]+$"))) { "AccountId contains invalid characters: $accountId" }
    }

    fun getAlias(accountId: String): String {
        validateAccountId(accountId)
        return "$KEY_ALIAS_PREFIX$accountId"
    }

    fun getAad(accountId: String): ByteArray {
        validateAccountId(accountId)
        return "$AAD_PREFIX$accountId".toByteArray(StandardCharsets.UTF_8)
    }

    private val isAndroidKeyStoreAvailable: Boolean
        get() = Security.getProviders().any { it.name == KEYSTORE_PROVIDER }

    // ------------------------------------------------------------------------
    // Keystore Key Lifecycle
    // ------------------------------------------------------------------------

    open fun getBiometricKey(accountId: String): SecretKey? {
        validateAccountId(accountId)
        val alias = getAlias(accountId)

        if (!isAndroidKeyStoreAvailable) {
            return inMemoryKeys[alias]
        }

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(alias)) {
            return null
        }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        return entry?.secretKey
    }

    open fun createBiometricKey(accountId: String): SecretKey {
        validateAccountId(accountId)
        val alias = getAlias(accountId)

        // Delete any prior key entry to ensure clean enrollment and prevent KeyPermanentlyInvalidatedException lockout
        try {
            if (isAndroidKeyStoreAvailable) {
                val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            } else {
                inMemoryKeys.remove(alias)
            }
        } catch (_: Exception) {
        }

        if (!isAndroidKeyStoreAvailable) {
            val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val key = SecretKeySpec(keyBytes, "AES")
            inMemoryKeys[alias] = key
            return key
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    open fun getOrCreateBiometricKey(accountId: String): SecretKey {
        return getBiometricKey(accountId) ?: createBiometricKey(accountId)
    }

    open fun deleteBiometricKey(accountId: String) {
        if (accountId.isBlank()) return
        validateAccountId(accountId)
        val alias = getAlias(accountId)

        try {
            if (isAndroidKeyStoreAvailable) {
                val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            } else {
                inMemoryKeys.remove(alias)
            }
        } catch (_: Exception) {
        }

        // Clear stored envelope and enabled state
        val p = prefs
        if (p != null) {
            p.edit()
                .remove("bio_env_$accountId")
                .remove("bio_enabled_$accountId")
                .apply()
        } else {
            inMemoryFallback.remove("bio_env_$accountId")
            inMemoryFallback.remove("bio_enabled_$accountId")
        }
    }

    open fun hasBiometricKey(accountId: String): Boolean {
        if (accountId.isBlank()) return false
        validateAccountId(accountId)
        val alias = getAlias(accountId)
        return if (isAndroidKeyStoreAvailable) {
            try {
                val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
                keyStore.containsAlias(alias)
            } catch (_: Exception) {
                false
            }
        } else {
            inMemoryKeys.containsKey(alias)
        }
    }

    open fun getKeySecurityLevel(accountId: String): String {
        validateAccountId(accountId)
        if (!isAndroidKeyStoreAvailable) {
            return "IN_MEMORY_SOFTWARE"
        }
        val alias = getAlias(accountId)
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val key = (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
                ?: return "KEY_NOT_FOUND"
            val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                    else -> "UNKNOWN"
                }
            } else {
                if (keyInfo.isInsideSecureHardware) "TEE" else "SOFTWARE"
            }
        } catch (e: Exception) {
            "UNVERIFIED (${e.message})"
        }
    }

    // ------------------------------------------------------------------------
    // Cipher Initialization for BiometricPrompt CryptoObject
    // ------------------------------------------------------------------------

    open fun initEncryptCipher(accountId: String): Cipher {
        validateAccountId(accountId)
        val secretKey = createBiometricKey(accountId)
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    open fun initDecryptCipher(accountId: String): Cipher {
        validateAccountId(accountId)
        val envelope = getBiometricEnvelope(accountId)
            ?: throw BiometricException("No biometric envelope found for account $accountId")

        val nonceBytes = try {
            Base64.getDecoder().decode(envelope.nonce)
        } catch (e: Exception) {
            throw BiometricException("Malformed nonce in biometric envelope", e)
        }

        if (nonceBytes.size != GCM_NONCE_LENGTH_BYTES) {
            throw BiometricException("Invalid nonce length: ${nonceBytes.size}")
        }

        val secretKey = try {
            getBiometricKey(accountId)
                ?: throw BiometricException("No biometric key found in keystore for account $accountId")
        } catch (e: BiometricException) {
            throw e
        } catch (e: Exception) {
            if (e is KeyPermanentlyInvalidatedException || e.cause is KeyPermanentlyInvalidatedException) {
                deleteBiometricKey(accountId)
                throw BiometricKeyInvalidatedException(cause = e)
            }
            throw BiometricException("Failed to retrieve biometric key: ${e.message}", e)
        }

        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonceBytes)
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        } catch (e: KeyPermanentlyInvalidatedException) {
            deleteBiometricKey(accountId)
            throw BiometricKeyInvalidatedException(cause = e)
        } catch (e: Exception) {
            if (e.cause is KeyPermanentlyInvalidatedException) {
                deleteBiometricKey(accountId)
                throw BiometricKeyInvalidatedException(cause = e)
            }
            throw BiometricException("Failed to initialize decryption cipher: ${e.message}", e)
        }
        return cipher
    }

    // ------------------------------------------------------------------------
    // Cryptographic Operations (Wrapping & Unwrapping VEK)
    // ------------------------------------------------------------------------

    open fun wrapVek(authenticatedCipher: Cipher, accountId: String, vek: ByteArray): BiometricWrappedKeyEnvelope {
        validateAccountId(accountId)
        if (vek.size != VEK_SIZE_BYTES) {
            throw InvalidParameterException("VEK must be exactly $VEK_SIZE_BYTES bytes, got ${vek.size}")
        }

        val aad = getAad(accountId)
        authenticatedCipher.updateAAD(aad)

        val ciphertextWithTag = try {
            authenticatedCipher.doFinal(vek)
        } catch (e: Exception) {
            throw BiometricException("Failed to encrypt VEK with biometric key: ${e.message}", e)
        }

        val iv = authenticatedCipher.iv
            ?: throw BiometricException("Biometric cipher produced null IV")

        val b64 = Base64.getEncoder()
        val envelope = BiometricWrappedKeyEnvelope(
            version = 1,
            accountId = accountId,
            nonce = b64.encodeToString(iv),
            ciphertext = b64.encodeToString(ciphertextWithTag)
        )

        saveBiometricEnvelope(envelope)
        setBiometricEnabled(accountId, true)
        return envelope
    }

    open fun unwrapVek(authenticatedCipher: Cipher, accountId: String): ByteArray {
        validateAccountId(accountId)
        val envelope = getBiometricEnvelope(accountId)
            ?: throw BiometricException("No biometric envelope stored for account $accountId")

        if (envelope.version != 1) {
            throw UnsupportedVersionException("Unsupported biometric envelope version: ${envelope.version}")
        }
        if (envelope.accountId != accountId) {
            throw BiometricException("Biometric envelope account mismatch: expected $accountId, got ${envelope.accountId}")
        }

        val ciphertextWithTag = try {
            Base64.getDecoder().decode(envelope.ciphertext)
        } catch (e: Exception) {
            throw BiometricException("Malformed ciphertext in biometric envelope", e)
        }

        val aad = getAad(accountId)
        authenticatedCipher.updateAAD(aad)

        val vek = try {
            authenticatedCipher.doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            throw DecryptionFailedException("Biometric authentication tag verification failed", e)
        } catch (e: Exception) {
            if (e is KeyPermanentlyInvalidatedException || e.cause is KeyPermanentlyInvalidatedException) {
                deleteBiometricKey(accountId)
                throw BiometricKeyInvalidatedException(cause = e)
            }
            throw DecryptionFailedException("Failed to decrypt VEK with biometric key: ${e.message}", e)
        }

        if (vek.size != VEK_SIZE_BYTES) {
            VaultCrypto.clearBytes(vek)
            throw DecryptionFailedException("Unwrapped VEK invalid size: ${vek.size}")
        }

        return vek
    }

    // ------------------------------------------------------------------------
    // Persistence & State Querying
    // ------------------------------------------------------------------------

    open fun saveBiometricEnvelope(envelope: BiometricWrappedKeyEnvelope) {
        validateAccountId(envelope.accountId)
        val jsonStr = jsonHelper.encodeToString(envelope)
        val key = "bio_env_${envelope.accountId}"
        val p = prefs
        if (p != null) {
            p.edit().putString(key, jsonStr).apply()
        } else {
            inMemoryFallback[key] = jsonStr
        }
    }

    open fun getBiometricEnvelope(accountId: String): BiometricWrappedKeyEnvelope? {
        if (accountId.isBlank()) return null
        validateAccountId(accountId)
        val key = "bio_env_$accountId"
        val jsonStr = prefs?.getString(key, null) ?: inMemoryFallback[key] ?: return null
        return try {
            jsonHelper.decodeFromString<BiometricWrappedKeyEnvelope>(jsonStr)
        } catch (_: Exception) {
            null
        }
    }

    open fun isBiometricEnabled(accountId: String): Boolean {
        if (accountId.isBlank()) return false
        validateAccountId(accountId)
        val key = "bio_enabled_$accountId"
        val isExplicitlyEnabled = prefs?.getBoolean(key, false)
            ?: (inMemoryFallback[key]?.toBoolean() ?: false)
        return isExplicitlyEnabled && getBiometricEnvelope(accountId) != null && hasBiometricKey(accountId)
    }

    open fun setBiometricEnabled(accountId: String, enabled: Boolean) {
        if (accountId.isBlank()) return
        validateAccountId(accountId)
        val key = "bio_enabled_$accountId"
        if (enabled) {
            prefs?.edit()?.putBoolean(key, true)?.apply()
            inMemoryFallback[key] = "true"
        } else {
            deleteBiometricKey(accountId)
        }
    }

    // ------------------------------------------------------------------------
    // Hardware Availability Checks
    // ------------------------------------------------------------------------

    open fun checkBiometricAvailability(targetContext: Context? = context): BiometricStatus {
        val ctx = targetContext ?: return BiometricStatus.UNSUPPORTED
        val biometricManager = BiometricManager.from(ctx)
        return when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.NOT_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricStatus.HW_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricStatus.SECURITY_UPDATE_REQUIRED
            else -> BiometricStatus.UNSUPPORTED
        }
    }
}
