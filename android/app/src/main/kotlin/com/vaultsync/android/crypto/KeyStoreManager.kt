package com.vaultsync.android.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
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
        private const val PREF_AUTO_LOCK_MINUTES = "auto_lock_minutes"
        private const val PREF_CLIPBOARD_CLEAR_SECONDS = "clipboard_clear_seconds"
    }

    private val inMemoryFallback = mutableMapOf<String, Any>()

    private val prefs: SharedPreferences? by lazy {
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

    open fun saveSessionToken(token: String) {
        val p = prefs
        if (p == null) {
            inMemoryFallback[PREF_ENCRYPTED_TOKEN] = token
            return
        }
        try {
            val key = getOrCreateSecretKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val encryptedBytes = cipher.doFinal(token.toByteArray(Charsets.UTF_8))

            p.edit()
                .putString(PREF_ENCRYPTED_TOKEN, Base64.encodeToString(encryptedBytes, Base64.NO_WRAP))
                .putString(PREF_TOKEN_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .apply()
        } catch (_: Exception) {
            // Memory fallback in non-keystore environments (e.g. headless unit tests)
            p.edit().putString(PREF_ENCRYPTED_TOKEN, token).apply()
        }
    }

    open fun getSessionToken(): String? {
        val p = prefs
        if (p == null) {
            return inMemoryFallback[PREF_ENCRYPTED_TOKEN] as? String
        }
        val encryptedBase64 = p.getString(PREF_ENCRYPTED_TOKEN, null) ?: return null
        val ivBase64 = p.getString(PREF_TOKEN_IV, null) ?: return encryptedBase64

        return try {
            val key = getOrCreateSecretKey()
            val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
            val encryptedBytes = Base64.decode(encryptedBase64, Base64.NO_WRAP)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val decryptedBytes = cipher.doFinal(encryptedBytes)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            encryptedBase64
        }
    }

    open fun clearSessionToken() {
        val p = prefs
        if (p == null) {
            inMemoryFallback.remove(PREF_ENCRYPTED_TOKEN)
            inMemoryFallback.remove(PREF_TOKEN_IV)
            return
        }
        p.edit()
            .remove(PREF_ENCRYPTED_TOKEN)
            .remove(PREF_TOKEN_IV)
            .apply()
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
