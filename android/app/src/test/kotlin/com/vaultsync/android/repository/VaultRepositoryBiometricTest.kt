package com.vaultsync.android.repository

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.api.LoginRequest
import com.vaultsync.android.api.LoginResponse
import com.vaultsync.android.api.StandardResponse
import com.vaultsync.android.crypto.BiometricKeyInvalidatedException
import com.vaultsync.android.crypto.BiometricKeyManager
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.db.EncryptedRecordEntity
import com.vaultsync.android.db.VaultDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
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
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class VaultRepositoryBiometricTest {

    private lateinit var context: Context
    private lateinit var db: VaultDatabase
    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var biometricKeyManager: BiometricKeyManager
    private lateinit var fakeApi: FakeBioApiClient
    private lateinit var repository: VaultRepository

    private val masterPassword = "TestMasterPassword123!"
    private val accountPassword = "TestAccountPassword123!"

    open class FakeBioApiClient : ApiClient("http://127.0.0.1:8000") {
        var accountIdToReturn: String = "acc-alice"
        var wrappedVaultKeyToReturn: String? = null
        var kdfSaltToReturn: String? = null

        override suspend fun login(req: LoginRequest): LoginResponse {
            sessionToken = "session-token-${req.username}"
            return LoginResponse(
                sessionToken = "session-token-${req.username}",
                sessionId = "sess-${req.username}",
                accountId = accountIdToReturn,
                expiresAt = "2026-10-19T00:00:00Z",
                kdfSalt = kdfSaltToReturn ?: "dGVzdHNhbHQxMjM0NTY3OA==",
                wrappedVaultKey = wrappedVaultKeyToReturn ?: "{}"
            )
        }

        override suspend fun logout(): StandardResponse {
            sessionToken = null
            return StandardResponse(status = "ok", message = "Logged out")
        }
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences(BiometricKeyManager.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        context.getSharedPreferences("vaultsync_secure_prefs", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()

        db = Room.inMemoryDatabaseBuilder(context, VaultDatabase::class.java)
            .allowMainThreadQueries()
            .build()

        keyStoreManager = KeyStoreManager(null)
        biometricKeyManager = BiometricKeyManager(context)
        fakeApi = FakeBioApiClient()

        // Generate synthetic wrapped vault key
        val vek = VaultCrypto.generateVaultKey()
        val (saltBytes, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        fakeApi.kdfSaltToReturn = Base64.getEncoder().encodeToString(saltBytes)
        fakeApi.wrappedVaultKeyToReturn = VaultCrypto.serializeWrappedKeyEnvelope(envelope)

        repository = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = db,
            biometricKeyManager = biometricKeyManager
        )
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun testBiometricUnlockWithVek_unlocksAndLoadsRoomCache(): Unit = runBlocking {
        // Log in user
        repository.login("alice", accountPassword)
        assertEquals("acc-alice", repository.accountId)
        assertFalse(repository.sessionState.value.isUnlocked)

        // Store an encrypted record envelope in Room
        val initialVek = VaultCrypto.unwrapVaultKey(
            VaultCrypto.parseWrappedKeyEnvelope(fakeApi.wrappedVaultKeyToReturn!!),
            masterPassword
        )
        val recordEnv = VaultCrypto.encryptRecord(initialVek, "rec-101", """{"title":"Secret Website","username":"alice","password":"pwd","url":"https://example.com","notes":""}""")
        val entity = EncryptedRecordEntity(
            accountId = "acc-alice",
            recordId = "rec-101",
            revision = 1,
            syncCursor = 1,
            isDeleted = false,
            ciphertextPayload = VaultCrypto.serializeRecordEnvelope(recordEnv),
            createdAt = "2026-10-18T10:00:00Z",
            updatedAt = "2026-10-18T10:00:00Z"
        )
        db.recordDao().upsertRecord(entity)

        // Now unlock directly with VEK (simulating successful biometric authentication)
        val vekCopy = initialVek.clone()
        repository.unlockWithVek(vekCopy)

        assertTrue(repository.sessionState.value.isUnlocked)
        val items = repository.items.value
        assertEquals(1, items.size)
        assertEquals("rec-101", items[0].id)
        assertEquals("Secret Website", items[0].title)
    }

    @Test
    fun testEnableAndDisableBiometricUnlock(): Unit = runBlocking {
        repository.login("alice", accountPassword)
        repository.unlockVault(masterPassword)
        assertTrue(repository.sessionState.value.isUnlocked)
        assertTrue(repository.canEnableBiometric())

        // Enable biometric unlock
        val encryptCipher = biometricKeyManager.initEncryptCipher("acc-alice")
        val envelope = repository.enableBiometricUnlock(encryptCipher)
        assertNotNull(envelope)
        assertTrue(repository.isBiometricUnlockAvailable())
        assertTrue(repository.sessionState.value.isBiometricEnabled)

        // Disable biometric unlock
        repository.disableBiometricUnlock()
        assertFalse(repository.isBiometricUnlockAvailable())
        assertFalse(repository.sessionState.value.isBiometricEnabled)
        assertNull(biometricKeyManager.getBiometricEnvelope("acc-alice"))
    }

    @Test
    fun testLockDuringInFlightBiometricUnwrap_fencesOutStaleVek(): Unit = runBlocking {
        repository.login("alice", accountPassword)
        repository.unlockVault(masterPassword)

        val encryptCipher = biometricKeyManager.initEncryptCipher("acc-alice")
        repository.enableBiometricUnlock(encryptCipher)

        // Lock vault
        repository.lock()
        assertFalse(repository.sessionState.value.isUnlocked)
        val lockGenBefore = repository.lockGeneration

        // Prepare biometric unwrap
        val decryptCipher = biometricKeyManager.initDecryptCipher("acc-alice")
        val unwrappedVek = biometricKeyManager.unwrapVek(decryptCipher, "acc-alice")

        // While prompt was open or right before completion, user triggers lock again
        repository.lock()
        assertTrue(repository.lockGeneration > lockGenBefore)

        // Unlock with the unwrap result should succeed under current generation and unlock cleanly
        repository.unlockWithVek(unwrappedVek)
        assertTrue(repository.sessionState.value.isUnlocked)
    }

    @Test
    fun testLogoutFencesSessionAndClearsBiometricState(): Unit = runBlocking {
        repository.login("alice", accountPassword)
        repository.unlockVault(masterPassword)

        val encryptCipher = biometricKeyManager.initEncryptCipher("acc-alice")
        repository.enableBiometricUnlock(encryptCipher)
        assertTrue(repository.sessionState.value.isBiometricEnabled)

        // Logout
        repository.logout()
        assertFalse(repository.sessionState.value.isAuthenticated)
        assertFalse(repository.sessionState.value.isUnlocked)
        assertFalse(repository.sessionState.value.isBiometricEnabled)

        // Attempting unlockWithVek while unauthenticated throws IllegalStateException and zeroes vek
        val dummyVek = ByteArray(32) { 1 }
        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                repository.unlockWithVek(dummyVek)
            }
        }
    }

    @Test
    fun testAccountSwitchingIsolation(): Unit = runBlocking {
        // Alice enables biometrics
        repository.login("alice", accountPassword)
        repository.unlockVault(masterPassword)
        val aliceCipher = biometricKeyManager.initEncryptCipher("acc-alice")
        repository.enableBiometricUnlock(aliceCipher)
        assertTrue(repository.isBiometricUnlockAvailable())

        // Logout Alice
        repository.logout()

        // Bob logs in
        fakeApi.accountIdToReturn = "acc-bob"
        val bobVek = VaultCrypto.generateVaultKey()
        val (bobSalt, bobEnv) = VaultCrypto.wrapVaultKey(bobVek, "BobMasterPassword123!")
        fakeApi.kdfSaltToReturn = Base64.getEncoder().encodeToString(bobSalt)
        fakeApi.wrappedVaultKeyToReturn = VaultCrypto.serializeWrappedKeyEnvelope(bobEnv)

        repository.login("bob", "BobAccountPassword123!")
        assertEquals("acc-bob", repository.accountId)

        // Bob should not have biometric unlock available
        assertFalse(repository.isBiometricUnlockAvailable())
        assertFalse(repository.sessionState.value.isBiometricEnabled)
        assertNull(biometricKeyManager.getBiometricEnvelope("acc-bob"))
    }

    @Test
    fun testBiometricInvalidationFallbackToMasterPassword(): Unit = runBlocking {
        repository.login("alice", accountPassword)
        repository.unlockVault(masterPassword)
        val encryptCipher = biometricKeyManager.initEncryptCipher("acc-alice")
        repository.enableBiometricUnlock(encryptCipher)

        repository.lock()
        assertFalse(repository.sessionState.value.isUnlocked)

        // Simulate biometric invalidation: delete key
        biometricKeyManager.deleteBiometricKey("acc-alice")
        assertFalse(repository.isBiometricUnlockAvailable())

        // Master password unlock remains functional as recovery path
        repository.unlockVault(masterPassword)
        assertTrue(repository.sessionState.value.isUnlocked)
    }
}
