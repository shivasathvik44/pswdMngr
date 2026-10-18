package com.vaultsync.android.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class BiometricKeyManagerTest {

    private lateinit var context: Context
    private lateinit var biometricKeyManager: BiometricKeyManager
    private val secureRandom = SecureRandom()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clear prefs between tests
        context.getSharedPreferences(BiometricKeyManager.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        biometricKeyManager = BiometricKeyManager(context)
    }

    private fun generateVek(): ByteArray {
        val vek = ByteArray(32)
        secureRandom.nextBytes(vek)
        return vek
    }

    @Test
    fun testWrapAndUnwrapVek_success() {
        val accountId = "test_acc_001"
        val originalVek = generateVek()

        val encryptCipher = biometricKeyManager.initEncryptCipher(accountId)
        val envelope = biometricKeyManager.wrapVek(encryptCipher, accountId, originalVek)

        assertNotNull(envelope)
        assertEquals(1, envelope.version)
        assertEquals(accountId, envelope.accountId)
        assertTrue(biometricKeyManager.isBiometricEnabled(accountId))

        val decryptCipher = biometricKeyManager.initDecryptCipher(accountId)
        val unwrappedVek = biometricKeyManager.unwrapVek(decryptCipher, accountId)

        assertNotNull(unwrappedVek)
        assertArrayEquals(originalVek, unwrappedVek)
    }

    @Test
    fun testCrossAccountIsolation_cannotUnwrapDifferentAccountEnvelope() {
        val accountAlice = "alice_account_id"
        val accountBob = "bob_account_id"
        val aliceVek = generateVek()

        val encryptCipherAlice = biometricKeyManager.initEncryptCipher(accountAlice)
        biometricKeyManager.wrapVek(encryptCipherAlice, accountAlice, aliceVek)

        assertTrue(biometricKeyManager.isBiometricEnabled(accountAlice))
        assertFalse(biometricKeyManager.isBiometricEnabled(accountBob))

        // Attempting to decrypt Bob when no envelope exists throws BiometricException
        assertThrows(BiometricException::class.java) {
            biometricKeyManager.initDecryptCipher(accountBob)
        }

        // Even if Bob uses Alice's envelope, AAD mismatch causes AEADBadTagException / DecryptionFailedException
        val aliceEnvelope = biometricKeyManager.getBiometricEnvelope(accountAlice)!!
        val bobEnvelopeWithAliceCiphertext = aliceEnvelope.copy(accountId = accountBob)
        biometricKeyManager.saveBiometricEnvelope(bobEnvelopeWithAliceCiphertext)

        val bobDecryptCipher = biometricKeyManager.initDecryptCipher(accountBob)
        assertThrows(DecryptionFailedException::class.java) {
            biometricKeyManager.unwrapVek(bobDecryptCipher, accountBob)
        }
    }

    @Test
    fun testTamperedCiphertext_failsDecryption() {
        val accountId = "tamper_test_acc"
        val vek = generateVek()

        val encryptCipher = biometricKeyManager.initEncryptCipher(accountId)
        val envelope = biometricKeyManager.wrapVek(encryptCipher, accountId, vek)

        // Alter ciphertext bytes
        val rawCiphertext = Base64.getDecoder().decode(envelope.ciphertext)
        rawCiphertext[rawCiphertext.size - 1] = (rawCiphertext[rawCiphertext.size - 1].toInt() xor 0xFF).toByte()
        val tamperedCiphertext = Base64.getEncoder().encodeToString(rawCiphertext)

        val tamperedEnvelope = envelope.copy(ciphertext = tamperedCiphertext)
        biometricKeyManager.saveBiometricEnvelope(tamperedEnvelope)

        val decryptCipher = biometricKeyManager.initDecryptCipher(accountId)
        assertThrows(DecryptionFailedException::class.java) {
            biometricKeyManager.unwrapVek(decryptCipher, accountId)
        }
    }

    @Test
    fun testTamperedNonce_failsDecryption() {
        val accountId = "tamper_nonce_acc"
        val vek = generateVek()

        val encryptCipher = biometricKeyManager.initEncryptCipher(accountId)
        val envelope = biometricKeyManager.wrapVek(encryptCipher, accountId, vek)

        // Alter nonce bytes
        val rawNonce = Base64.getDecoder().decode(envelope.nonce)
        rawNonce[0] = (rawNonce[0].toInt() xor 0x01).toByte()
        val tamperedNonce = Base64.getEncoder().encodeToString(rawNonce)

        val tamperedEnvelope = envelope.copy(nonce = tamperedNonce)
        biometricKeyManager.saveBiometricEnvelope(tamperedEnvelope)

        val decryptCipher = biometricKeyManager.initDecryptCipher(accountId)
        assertThrows(DecryptionFailedException::class.java) {
            biometricKeyManager.unwrapVek(decryptCipher, accountId)
        }
    }

    @Test
    fun testInvalidVekSize_rejected() {
        val accountId = "invalid_size_acc"
        val invalidVek = ByteArray(16) // Should be 32

        val encryptCipher = biometricKeyManager.initEncryptCipher(accountId)
        assertThrows(InvalidParameterException::class.java) {
            biometricKeyManager.wrapVek(encryptCipher, accountId, invalidVek)
        }
    }

    @Test
    fun testDisableBiometric_clearsEnvelopeAndState() {
        val accountId = "disable_acc"
        val vek = generateVek()

        val encryptCipher = biometricKeyManager.initEncryptCipher(accountId)
        biometricKeyManager.wrapVek(encryptCipher, accountId, vek)

        assertTrue(biometricKeyManager.isBiometricEnabled(accountId))
        assertNotNull(biometricKeyManager.getBiometricEnvelope(accountId))

        // Disable biometric
        biometricKeyManager.setBiometricEnabled(accountId, false)

        assertFalse(biometricKeyManager.isBiometricEnabled(accountId))
        assertNull(biometricKeyManager.getBiometricEnvelope(accountId))
        assertFalse(biometricKeyManager.hasBiometricKey(accountId))
    }

    @Test
    fun testZeroPlaintextLeakInStorage() {
        val accountId = "no_leak_acc"
        val vek = generateVek()

        val encryptCipher = biometricKeyManager.initEncryptCipher(accountId)
        biometricKeyManager.wrapVek(encryptCipher, accountId, vek)

        val prefs = context.getSharedPreferences(BiometricKeyManager.PREFS_NAME, Context.MODE_PRIVATE)
        val allEntries = prefs.all

        val vekBase64 = Base64.getEncoder().encodeToString(vek)
        val vekHex = vek.joinToString("") { "%02x".format(it) }

        for ((_, value) in allEntries) {
            val strVal = value.toString()
            assertFalse("Plaintext Base64 VEK must not appear in preferences", strVal.contains(vekBase64))
            assertFalse("Plaintext hex VEK must not appear in preferences", strVal.contains(vekHex))
        }
    }

    @Test
    fun testBiometricAvailabilityReporting() {
        val status = biometricKeyManager.checkBiometricAvailability(context)
        assertNotNull(status)
    }
}
