package com.vaultsync.android.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

class VaultCryptoTest {

    private val crypto: VaultCrypto = VaultCrypto

    @Before
    fun setUp() {
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        val len = clean.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(clean[i], 16) shl 4) + Character.digit(clean[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    @Test
    fun testArgon2idDerivationMatchesGoldenVector() {
        val masterPassword = "TestMasterPassword123!".toCharArray()
        val salt = Base64.getDecoder().decode("VmF1bHRTeW5jVGVzdFNsdA==")
        val kdf = KdfParameters(
            algorithm = "Argon2id",
            memoryCost = 65536,
            timeCost = 3,
            parallelism = 4,
            salt = "VmF1bHRTeW5jVGVzdFNsdA=="
        )

        val masterSecret = crypto.deriveMasterSecret(masterPassword, kdf)
        val expectedMasterSecretHex = "2fc420a8912a5c53f182e9079e5701e2bc747a41622e0af7fdade886576baafe"
        assertEquals(expectedMasterSecretHex, bytesToHex(masterSecret))

        val kek = crypto.deriveKek(masterSecret)
        val expectedKekHex = "d0aa589af4f49f360f4f61d4ebfee957b8c36da8831715368c7770ab7c56f4ed"
        assertEquals(expectedKekHex, bytesToHex(kek))
    }

    @Test
    fun testUnwrapVaultKeyMatchesGoldenVector() {
        val masterPassword = "TestMasterPassword123!".toCharArray()
        val envelopeJson = "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"kdf\":{\"algorithm\":\"Argon2id\",\"memory_cost\":65536,\"time_cost\":3,\"parallelism\":4,\"salt\":\"VmF1bHRTeW5jVGVzdFNsdA==\"},\"nonce\":\"EBESExQVFhcYGRob\",\"ciphertext\":\"o4ouOLzlar1ABYQAKNc/7udg52skdkyMWhkIbVSiH6UMMF2hCiDApyJ3HLCs8QDl\"}"
        val envelope = crypto.parseWrappedKeyEnvelope(envelopeJson)

        val vek = crypto.unwrapVaultKey(envelope, masterPassword)
        val expectedVekHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        assertEquals(expectedVekHex, bytesToHex(vek))
    }

    @Test
    fun testWrapAndUnwrapVaultKeyRoundTrip() {
        val masterPassword = "TestMasterPassword123!".toCharArray()
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

        val envelope = crypto.wrapVaultKey(vek, masterPassword)
        val json = crypto.serializeWrappedKeyEnvelope(envelope)

        val parsedEnvelope = crypto.parseWrappedKeyEnvelope(json)
        val unwrappedVek = crypto.unwrapVaultKey(parsedEnvelope, masterPassword)

        assertArrayEquals(vek, unwrappedVek)
    }

    @Test
    fun testRecordDecryptionMatchesGoldenVector() {
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val recordId = "d3b07384-d113-4674-8b6a-939e144a14d5"
        val envelopeJson = "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"record_id\":\"d3b07384-d113-4674-8b6a-939e144a14d5\",\"nonce\":\"Hh8gISIjJCUmJygp\",\"ciphertext\":\"14tswzgmqYaM5sQrCYVhCUar0ud20KL1Qjk54enfL5TcVbkn7t5kU09WU4qTXlmbSFUeiJkXFlqF14/eDKFTJ2bkeSoHYd9L12n8kRqxWUN4DQ81sJzLif1PoX+4YRkfhYkPX48=\"}"

        val envelope = crypto.parseRecordEnvelope(envelopeJson)
        val plaintext = crypto.decryptRecord(envelope, vek)
        val expectedPlaintext = "{\"title\":\"Demo Site\",\"username\":\"alice@example.com\",\"password\":\"SyntheticSecret987!\"}"
        assertEquals(expectedPlaintext, plaintext)
    }

    @Test
    fun testRecordEncryptionAndDecryptionRoundTrip() {
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val recordId = "d3b07384-d113-4674-8b6a-939e144a14d5"
        val plaintext = "{\"title\":\"My Bank\",\"username\":\"bob@example.com\",\"password\":\"VeryStrongSecret2026!\"}"

        val envelope = crypto.encryptRecord(recordId, plaintext, vek)
        val json = crypto.serializeRecordEnvelope(envelope)

        val parsedEnvelope = crypto.parseRecordEnvelope(json)
        val decrypted = crypto.decryptRecord(parsedEnvelope, vek)

        assertEquals(plaintext, decrypted)
    }

    @Test
    fun testCorruptedCiphertextFails() {
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val payload = "{\"version\": 1, \"algorithm\": \"AES-256-GCM\", \"record_id\": \"d3b07384-d113-4674-8b6a-939e144a14d5\", \"nonce\": \"Hh8gISIjJCUmJygp\", \"ciphertext\": \"14tswzgnqYaM5sQrCYVhCUar0ud20KL1Qjk54enfL5TcVbkn7t5kU09WU4qTXlmbSFUeiJkXFlqF14/eDKFTJ2bkeSoHYd9L12n8kRqxWUN4DQ81sJzLif1PoX+4YRkfhYkPX48=\"}"

        val envelope = crypto.parseRecordEnvelope(payload)
        assertThrows(DecryptionFailedException::class.java) {
            crypto.decryptRecord(envelope, vek)
        }
    }

    @Test
    fun testCorruptedTagFails() {
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val payload = "{\"version\": 1, \"algorithm\": \"AES-256-GCM\", \"record_id\": \"d3b07384-d113-4674-8b6a-939e144a14d5\", \"nonce\": \"Hh8gISIjJCUmJygp\", \"ciphertext\": \"14tswzgmqYaM5sQrCYVhCUar0ud20KL1Qjk54enfL5TcVbkn7t5kU09WU4qTXlmbSFUeiJkXFlqF14/eDKFTJ2bkeSoHYd9L12n8kRqxWUN4DQ81sJzLif1PoX+4YRkfhYkPX44=\"}"

        val envelope = crypto.parseRecordEnvelope(payload)
        assertThrows(DecryptionFailedException::class.java) {
            crypto.decryptRecord(envelope, vek)
        }
    }

    @Test
    fun testSwappedRecordIdFailsDueToAssociatedData() {
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val payload = "{\"version\": 1, \"algorithm\": \"AES-256-GCM\", \"record_id\": \"00000000-0000-0000-0000-000000000000\", \"nonce\": \"Hh8gISIjJCUmJygp\", \"ciphertext\": \"14tswzgmqYaM5sQrCYVhCUar0ud20KL1Qjk54enfL5TcVbkn7t5kU09WU4qTXlmbSFUeiJkXFlqF14/eDKFTJ2bkeSoHYd9L12n8kRqxWUN4DQ81sJzLif1PoX+4YRkfhYkPX48=\"}"

        val envelope = crypto.parseRecordEnvelope(payload)
        assertThrows(DecryptionFailedException::class.java) {
            crypto.decryptRecord(envelope, vek)
        }
    }

    @Test
    fun testUnsupportedVersionFails() {
        val payload = "{\"version\": 99, \"algorithm\": \"AES-256-GCM\", \"record_id\": \"d3b07384-d113-4674-8b6a-939e144a14d5\", \"nonce\": \"Hh8gISIjJCUmJygp\", \"ciphertext\": \"14tswzgmqYaM5sQrCYVhCUar0ud20KL1Qjk54enfL5TcVbkn7t5kU09WU4qTXlmbSFUeiJkXFlqF14/eDKFTJ2bkeSoHYd9L12n8kRqxWUN4DQ81sJzLif1PoX+4YRkfhYkPX48=\"}"

        val envelope = crypto.parseRecordEnvelope(payload)
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        assertThrows(UnsupportedVersionException::class.java) {
            crypto.decryptRecord(envelope, vek)
        }
    }

    @Test
    fun testUnsupportedAlgorithmFails() {
        val payload = "{\"version\": 1, \"algorithm\": \"CHACHA20-POLY1305\", \"record_id\": \"d3b07384-d113-4674-8b6a-939e144a14d5\", \"nonce\": \"Hh8gISIjJCUmJygp\", \"ciphertext\": \"14tswzgmqYaM5sQrCYVhCUar0ud20KL1Qjk54enfL5TcVbkn7t5kU09WU4qTXlmbSFUeiJkXFlqF14/eDKFTJ2bkeSoHYd9L12n8kRqxWUN4DQ81sJzLif1PoX+4YRkfhYkPX48=\"}"

        val envelope = crypto.parseRecordEnvelope(payload)
        val vek = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        assertThrows(UnsupportedAlgorithmException::class.java) {
            crypto.decryptRecord(envelope, vek)
        }
    }

    @Test
    fun testUnsafeKdfMemoryCostFails() {
        val payload = "{\"version\": 1, \"algorithm\": \"AES-256-GCM\", \"kdf\": {\"algorithm\": \"Argon2id\", \"memory_cost\": 1048576, \"time_cost\": 3, \"parallelism\": 4, \"salt\": \"VmF1bHRTeW5jVGVzdFNsdA==\"}, \"nonce\": \"EBESExQVFhcYGRob\", \"ciphertext\": \"o4ouOLzlar1ABYQAKNc/7udg52skdkyMWhkIbVSiH6UMMF2hCiDApyJ3HLCs8QDl\"}"

        val envelope = crypto.parseWrappedKeyEnvelope(payload)
        val masterPassword = "TestMasterPassword123!".toCharArray()
        assertThrows(InvalidParameterException::class.java) {
            crypto.unwrapVaultKey(envelope, masterPassword)
        }
    }
}
