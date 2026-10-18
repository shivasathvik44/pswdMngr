package com.vaultsync.android.crypto

import android.content.Context
import android.content.SharedPreferences
import java.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages device-local storage of the session bearer token using the Android Keystore.
 *
 * The raw bearer token is never written to disk in plaintext.
 * Master passwords and Vault Encryption Keys (VEK) are NEVER persisted here.
 */
open class KeyStoreManager(private val context: Context? = null) {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "VaultSyncSessionKey"
        private const val PREFS_NAME = "vaultsync_secure_prefs"
        private const val PREF_ENCRYPTED_TOKEN = "encrypted_session_token"
        private const val PREF_TOKEN_IV = "session_token_iv"
        private const val PREF_SERVER_URL = "server_url"
        private const val PREF_LAST_USERNAME = "last_username"
        private const val PREF_LAST_ACCOUNT_ID = "last_account_id"
        private const val PREF_WRAPPED_VAULT_KEY = "wrapped_vault_key"
        private const val PREF_KDF_SALT = "kdf_salt"
        private const val PREF_AUTO_LOCK_MINUTES = "auto_lock_minutes"
        private const val PREF_CLIPBOARD_CLEAR_SECONDS = "clipboard_clear_seconds"
    }

    private val inMemoryFallback = mutableMapOf<String, Any>()

    protected open val prefs: SharedPreferences? by lazy {
        context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance("AES", KEYSTORE_PROVIDER)
            val keyGenParameterSpec = android.security.keystore.KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()

            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey()
        }

        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        return entry?.secretKey ?: throw IllegalStateException("Keystore key entry could not be retrieved")
    }

    protected open fun encryptToken(token: String): Pair<String, String> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        return Base64.getEncoder().encodeToString(cipher.doFinal(token.toByteArray(Charsets.UTF_8))) to
            Base64.getEncoder().encodeToString(cipher.iv)
    }

    protected open fun decryptToken(encrypted: String, iv: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(),
            GCMParameterSpec(128, Base64.getDecoder().decode(iv)))
        return String(cipher.doFinal(Base64.getDecoder().decode(encrypted)), Charsets.UTF_8)
    }

    private fun storageFailure(message: String, cause: Exception): Nothing {
        val failure = SecureStorageException(message, cause)
        try {
            clearSessionToken()
        } catch (cleanup: Exception) {
            failure.addSuppressed(cleanup)
        }
        throw failure
    }

    open fun saveSessionToken(token: String) {
        val p = prefs
        if (p == null) {
            inMemoryFallback[PREF_ENCRYPTED_TOKEN] = token
            return
        }
        try {
            val (encrypted, iv) = encryptToken(token)
            if (!p.edit()
                    .putString(PREF_ENCRYPTED_TOKEN, encrypted)
                    .putString(PREF_TOKEN_IV, iv)
                    .commit()) {
                throw SecureStorageException("Session token persistence failed")
            }
        } catch (e: Exception) {
            storageFailure("Failed to securely store session token", e)
        }
    }

    open fun getSessionToken(): String? {
        val p = prefs
        if (p == null) {
            return inMemoryFallback[PREF_ENCRYPTED_TOKEN] as? String
        }
        return try {
            val encrypted = p.getString(PREF_ENCRYPTED_TOKEN, null) ?: return null
            val iv = p.getString(PREF_TOKEN_IV, null)
                ?: throw SecureStorageException("Stored session token has no initialization vector")
            decryptToken(encrypted, iv)
        } catch (e: Exception) {
            storageFailure("Failed to securely read session token", e)
        }
    }

    open fun clearSessionToken() {
        val p = prefs
        if (p == null) {
            inMemoryFallback.remove(PREF_ENCRYPTED_TOKEN)
            inMemoryFallback.remove(PREF_TOKEN_IV)
            return
        }
        if (!p.edit()
                .remove(PREF_ENCRYPTED_TOKEN)
                .remove(PREF_TOKEN_IV)
                .commit()) {
            throw SecureStorageException("Failed to clear stored session token")
        }
    }

    // ------------------------------------------------------------------------
    // User Preferences (Non-Sensitive)
    // ------------------------------------------------------------------------

    open var serverUrl: String
        get() = prefs?.getString(PREF_SERVER_URL, "http://10.0.2.2:8000")
            ?: (inMemoryFallback[PREF_SERVER_URL] as? String ?: "http://10.0.2.2:8000")
        set(value) {
            prefs?.edit()?.putString(PREF_SERVER_URL, value)?.apply()
            inMemoryFallback[PREF_SERVER_URL] = value
        }

    open var lastUsername: String
        get() = prefs?.getString(PREF_LAST_USERNAME, "")
            ?: (inMemoryFallback[PREF_LAST_USERNAME] as? String ?: "")
        set(value) {
            prefs?.edit()?.putString(PREF_LAST_USERNAME, value)?.apply()
            inMemoryFallback[PREF_LAST_USERNAME] = value
        }

    open var lastAccountId: String
        get() = prefs?.getString(PREF_LAST_ACCOUNT_ID, "")
            ?: (inMemoryFallback[PREF_LAST_ACCOUNT_ID] as? String ?: "")
        set(value) {
            prefs?.edit()?.putString(PREF_LAST_ACCOUNT_ID, value)?.apply()
            inMemoryFallback[PREF_LAST_ACCOUNT_ID] = value
        }

    open var lastWrappedVaultKey: String?
        get() = prefs?.getString(PREF_WRAPPED_VAULT_KEY, null)
            ?: (inMemoryFallback[PREF_WRAPPED_VAULT_KEY] as? String)
        set(value) {
            if (value != null) {
                prefs?.edit()?.putString(PREF_WRAPPED_VAULT_KEY, value)?.apply()
                inMemoryFallback[PREF_WRAPPED_VAULT_KEY] = value
            } else {
                prefs?.edit()?.remove(PREF_WRAPPED_VAULT_KEY)?.apply()
                inMemoryFallback.remove(PREF_WRAPPED_VAULT_KEY)
            }
        }

    open var lastKdfSalt: String?
        get() = prefs?.getString(PREF_KDF_SALT, null)
            ?: (inMemoryFallback[PREF_KDF_SALT] as? String)
        set(value) {
            if (value != null) {
                prefs?.edit()?.putString(PREF_KDF_SALT, value)?.apply()
                inMemoryFallback[PREF_KDF_SALT] = value
            } else {
                prefs?.edit()?.remove(PREF_KDF_SALT)?.apply()
                inMemoryFallback.remove(PREF_KDF_SALT)
            }
        }

    open var autoLockMinutes: Int
        get() = prefs?.getInt(PREF_AUTO_LOCK_MINUTES, 5)
            ?: (inMemoryFallback[PREF_AUTO_LOCK_MINUTES] as? Int ?: 5)
        set(value) {
            prefs?.edit()?.putInt(PREF_AUTO_LOCK_MINUTES, value)?.apply()
            inMemoryFallback[PREF_AUTO_LOCK_MINUTES] = value
        }

    open var clipboardClearSeconds: Int
        get() = prefs?.getInt(PREF_CLIPBOARD_CLEAR_SECONDS, 30)
            ?: (inMemoryFallback[PREF_CLIPBOARD_CLEAR_SECONDS] as? Int ?: 30)
        set(value) {
            prefs?.edit()?.putInt(PREF_CLIPBOARD_CLEAR_SECONDS, value)?.apply()
            inMemoryFallback[PREF_CLIPBOARD_CLEAR_SECONDS] = value
        }
}
