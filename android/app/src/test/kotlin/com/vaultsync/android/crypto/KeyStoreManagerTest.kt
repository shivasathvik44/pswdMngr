package com.vaultsync.android.crypto

import android.content.SharedPreferences
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test

class KeyStoreManagerTest {
    private class Fixture {
        val values = mutableMapOf<String, String>()
        val writes = mutableListOf<String>()
        var failEncrypt = false
        var failDecrypt = false
        var failCommit = false
        private val editor = Proxy.newProxyInstance(
            SharedPreferences.Editor::class.java.classLoader,
            arrayOf(SharedPreferences.Editor::class.java)
        ) { proxy, method, args ->
            when (method.name) {
                "putString" -> {
                    values[args!![0] as String] = args[1] as String
                    writes.add(args[1] as String)
                    proxy
                }
                "remove" -> { values.remove(args!![0] as String); proxy }
                "commit" -> !failCommit
                else -> error("Unexpected editor method: ${method.name}")
            }
        } as SharedPreferences.Editor
        private val preferences = Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java)
        ) { _, method, args ->
            when (method.name) {
                "getString" -> values[args!![0] as String] ?: args[1]
                "edit" -> editor
                else -> error("Unexpected preference method: ${method.name}")
            }
        } as SharedPreferences
        val manager = object : KeyStoreManager() {
            override val prefs = preferences
            override fun encryptToken(token: String): Pair<String, String> {
                if (failEncrypt) error("Synthetic cipher failure")
                return "synthetic-ciphertext" to "synthetic-iv"
            }
            override fun decryptToken(encrypted: String, iv: String): String {
                if (failDecrypt) error("Synthetic invalidated key")
                check(encrypted == "synthetic-ciphertext" && iv == "synthetic-iv")
                return "synthetic-token"
            }
        }
    }

    @Test fun encryptionFailureNeverWritesPlaintextAndRemovesStaleToken() {
        val f = Fixture()
        f.values["encrypted_session_token"] = "legacy-plaintext"
        f.failEncrypt = true
        assertThrows(SecureStorageException::class.java) { f.manager.saveSessionToken("synthetic-token") }
        assertTrue(f.values.isEmpty())
        assertFalse(f.writes.contains("synthetic-token"))
        assertNull(f.manager.getSessionToken())
        f.failEncrypt = false
        f.manager.saveSessionToken("synthetic-token")
        assertEquals("synthetic-token", f.manager.getSessionToken())
        assertFalse(f.writes.contains("synthetic-token"))
    }

    @Test fun missingIvNeverReturnsLegacyPlaintext() {
        val f = Fixture()
        f.values["encrypted_session_token"] = "legacy-plaintext"
        assertThrows(SecureStorageException::class.java) { f.manager.getSessionToken() }
        assertTrue(f.values.isEmpty())
    }

    @Test fun invalidatedKeyClearsBothFieldsAndAllowsRecovery() {
        val f = Fixture()
        f.manager.saveSessionToken("synthetic-token")
        f.failDecrypt = true
        assertThrows(SecureStorageException::class.java) { f.manager.getSessionToken() }
        assertTrue(f.values.isEmpty())
        f.failDecrypt = false
        f.manager.saveSessionToken("synthetic-token")
        assertEquals("synthetic-token", f.manager.getSessionToken())
        f.manager.clearSessionToken()
        assertNull(f.manager.getSessionToken())
    }

    @Test fun failedDiskCommitCannotReportSuccessfulSave() {
        val f = Fixture()
        f.failCommit = true
        assertThrows(SecureStorageException::class.java) { f.manager.saveSessionToken("synthetic-token") }
        assertFalse(f.writes.contains("synthetic-token"))
        assertTrue(f.values.isEmpty())
    }

    @Test fun testVaultKeyVersionPersistenceAndDefault() {
        val manager = KeyStoreManager(context = null)
        assertEquals(1, manager.lastVaultKeyVersion)
        manager.lastVaultKeyVersion = 3
        assertEquals(3, manager.lastVaultKeyVersion)
    }
}
