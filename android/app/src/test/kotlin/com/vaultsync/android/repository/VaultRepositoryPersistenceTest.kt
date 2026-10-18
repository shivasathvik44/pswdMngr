package com.vaultsync.android.repository

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.api.CreateRecordRequest
import com.vaultsync.android.api.LoginRequest
import com.vaultsync.android.api.LoginResponse
import com.vaultsync.android.api.NetworkConnectionException
import com.vaultsync.android.api.RecordResponse
import com.vaultsync.android.api.SyncResponse
import com.vaultsync.android.api.UpdateRecordRequest
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.RecordEnvelope
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.db.VaultDatabase
import com.vaultsync.android.model.VaultItem
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class VaultRepositoryPersistenceTest {

    private lateinit var db: VaultDatabase
    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var fakeApi: FakePersistenceApiClient
    private lateinit var repository: VaultRepository

    open class FakePersistenceApiClient : ApiClient("http://127.0.0.1:8000") {
        var syncResponseToReturn: SyncResponse? = null
        var syncExceptionToThrow: Exception? = null
        var syncPauseDeferred: CompletableDeferred<Unit>? = null
        var syncStartedDeferred: CompletableDeferred<Unit>? = null
        var wrappedVaultKeyToReturn: String? = null
        var kdfSaltToReturn: String? = "dGVzdHNhbHQxMjM0NTY3OA=="

        override suspend fun login(req: LoginRequest): LoginResponse {
            sessionToken = "test-session-token"
            return LoginResponse(
                sessionToken = "test-session-token",
                sessionId = "sess-1",
                accountId = "acc-test",
                expiresAt = "2026-10-19T00:00:00Z",
                kdfSalt = kdfSaltToReturn ?: "dGVzdHNhbHQxMjM0NTY3OA==",
                wrappedVaultKey = wrappedVaultKeyToReturn
            )
        }

        override suspend fun fetchSync(sinceCursor: Int, limit: Int): SyncResponse {
            syncStartedDeferred?.complete(Unit)
            syncPauseDeferred?.await()
            syncExceptionToThrow?.let { throw it }
            return syncResponseToReturn ?: SyncResponse(items = emptyList(), serverCursor = sinceCursor, nextCursor = sinceCursor, hasMore = false)
        }

        override suspend fun createRecord(req: CreateRecordRequest): RecordResponse {
            return RecordResponse(
                recordId = req.recordId,
                ciphertextPayload = req.ciphertextPayload,
                revision = 1,
                syncCursor = 1,
                isDeleted = false,
                createdAt = "2026-10-18T10:00:00Z",
                updatedAt = "2026-10-18T10:00:00Z"
            )
        }

        override suspend fun deleteRecord(recordId: String, expectedRevision: Int): RecordResponse {
            return RecordResponse(
                recordId = recordId,
                ciphertextPayload = "",
                revision = expectedRevision + 1,
                syncCursor = 2,
                isDeleted = true,
                createdAt = "2026-10-18T10:00:00Z",
                updatedAt = "2026-10-18T10:05:00Z"
            )
        }
    }

    private fun setupUserWithMasterPassword(repo: VaultRepository, masterPassword: String): ByteArray {
        val vek = VaultCrypto.generateVaultKey()
        val (saltBytes, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        val saltB64 = Base64.getEncoder().encodeToString(saltBytes)
        val envelopeJson = VaultCrypto.serializeWrappedKeyEnvelope(envelope)

        fakeApi.wrappedVaultKeyToReturn = envelopeJson
        fakeApi.kdfSaltToReturn = saltB64

        keyStoreManager.lastWrappedVaultKey = envelopeJson
        keyStoreManager.lastKdfSalt = saltB64

        val field = repo.javaClass.getDeclaredField("wrappedVaultKey")
        field.isAccessible = true
        field.set(repo, envelopeJson)

        val saltField = repo.javaClass.getDeclaredField("kdfSalt")
        saltField.isAccessible = true
        saltField.set(repo, saltB64)

        return vek
    }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, VaultDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        keyStoreManager = KeyStoreManager(null)
        fakeApi = FakePersistenceApiClient()
        repository = VaultRepository(fakeApi, keyStoreManager, VaultCrypto, db)
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun testProcessRecreationReloadOfPersistedCiphertextAndMetadata() = runBlocking {
        val masterPassword = "ProcessRecreationMaster123!"
        val vek = setupUserWithMasterPassword(repository, masterPassword)

        repository.login("user1", "accountPassword123!")
        val accountId = repository.accountId
        assertEquals("acc-test", accountId)

        // Setup 2 records returned from server
        val item1 = VaultItem(id = "rec-1", title = "Bank Login", username = "bankuser", password = "secretPassword1!")
        val item2 = VaultItem(id = "rec-2", title = "Email Account", username = "mailuser", password = "secretPassword2!")
        val env1 = VaultCrypto.encryptRecord(vek, item1.id, item1.toSecretJson())
        val env2 = VaultCrypto.encryptRecord(vek, item2.id, item2.toSecretJson())

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = item1.id, ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 50),
                RecordResponse(recordId = item2.id, ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env2), revision = 1, syncCursor = 100)
            ),
            serverCursor = 100,
            nextCursor = 100,
            hasMore = false
        )

        repository.unlockVault(masterPassword)
        assertEquals(2, repository.items.value.size)
        assertEquals(100, repository.syncCursor)

        // Verify entities were written to Room
        val persistedEntities = db.recordDao().getActiveRecords(accountId)
        assertEquals(2, persistedEntities.size)

        // SIMULATE PROCESS DEATH: Create a new repository instance with the same KeyStoreManager & DB
        val recreatedRepo = VaultRepository(fakeApi, keyStoreManager, VaultCrypto, db)

        // Invariant: Before unlock, zero decrypted items in memory
        assertEquals(0, recreatedRepo.items.value.size)
        assertFalse(recreatedRepo.sessionState.value.isUnlocked)

        // Simulate offline unlock (network unreachable)
        fakeApi.syncExceptionToThrow = NetworkConnectionException("Device is offline")

        recreatedRepo.unlockVault(masterPassword)

        // Invariant: Vault immediately reloads and decrypts cached records from Room offline!
        assertTrue(recreatedRepo.sessionState.value.isUnlocked)
        assertEquals(2, recreatedRepo.items.value.size)
        assertEquals(100, recreatedRepo.syncCursor)
        assertEquals("Bank Login", recreatedRepo.getItem("rec-1")?.title)
        assertEquals("secretPassword1!", recreatedRepo.getItem("rec-1")?.password)
        assertEquals("Email Account", recreatedRepo.getItem("rec-2")?.title)

        VaultCrypto.clearBytes(vek)
    }

    @Test
    fun testLocalWriteAndDatabasePersistence() = runBlocking {
        val masterPassword = "LocalWritePassword123!"
        val vek = setupUserWithMasterPassword(repository, masterPassword)

        repository.login("user1", "accountPassword123!")
        val accountId = repository.accountId
        repository.unlockVault(masterPassword)

        // 1. Save new item
        val newItem = VaultItem(id = "rec-local-1", title = "New Service", username = "myuser", password = "plainSecretPassword!")
        repository.saveItem(newItem)

        assertEquals(1, repository.items.value.size)

        // Verify database entity is persisted
        val persisted = db.recordDao().getRecord(accountId, "rec-local-1")
        assertNotNull(persisted)
        assertEquals("rec-local-1", persisted?.recordId)
        assertFalse(persisted!!.isDeleted)

        // CRITICAL INVARIANT: The persisted record in Room contains encrypted payload only!
        assertFalse(persisted.ciphertextPayload.contains("plainSecretPassword!"))
        assertTrue(persisted.ciphertextPayload.contains("AES-256-GCM"))

        // 2. Delete item
        repository.deleteItem("rec-local-1")
        assertEquals(0, repository.items.value.size)

        // Verify tombstone in Room
        val activeAfterDelete = db.recordDao().getActiveRecords(accountId)
        assertEquals(0, activeAfterDelete.size)

        val tombstone = db.recordDao().getRecord(accountId, "rec-local-1")
        assertNotNull(tombstone)
        assertTrue(tombstone!!.isDeleted)
        assertEquals("", tombstone.ciphertextPayload)

        VaultCrypto.clearBytes(vek)
    }

    @Test
    fun testRepeatedSyncAndDuplicateRecords() = runBlocking {
        val masterPassword = "RepeatedSyncPass123!"
        val vek = setupUserWithMasterPassword(repository, masterPassword)

        repository.login("user1", "accountPassword123!")
        val accountId = repository.accountId
        repository.unlockVault(masterPassword)

        val item1 = VaultItem(id = "rec-dup-1", title = "First Title")
        val env1 = VaultCrypto.encryptRecord(vek, item1.id, item1.toSecretJson())

        val recordResp = RecordResponse(
            recordId = item1.id,
            ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1),
            revision = 1,
            syncCursor = 10
        )

        // Server sends duplicate items in the sync response
        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(recordResp, recordResp, recordResp),
            serverCursor = 10,
            nextCursor = 10,
            hasMore = false
        )

        repository.syncRecords()

        assertEquals(1, repository.items.value.size)
        val activeRecords = db.recordDao().getActiveRecords(accountId)
        assertEquals(1, activeRecords.size)

        VaultCrypto.clearBytes(vek)
    }

    @Test
    fun testCorruptedCiphertextHandlingInDatabase() = runBlocking {
        val masterPassword = "CorruptedRecordTest123!"
        val vek = setupUserWithMasterPassword(repository, masterPassword)

        repository.login("user1", "accountPassword123!")
        val accountId = repository.accountId
        repository.unlockVault(masterPassword)

        val validItem = VaultItem(id = "rec-valid", title = "Valid Item")
        val validEnv = VaultCrypto.encryptRecord(vek, validItem.id, validItem.toSecretJson())

        // Corrupted envelope: tampered ciphertext causes AEAD authentication tag failure
        val corruptedPayload = """{"version":1,"algorithm":"AES-256-GCM","record_id":"rec-corrupted","nonce":"dGVzdG5vbmNlMTI=","ciphertext":"dGFtcGVyZWRjaXBoZXJ0ZXh0d2l0aGJhZHRhZw=="}"""

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = validItem.id, ciphertextPayload = VaultCrypto.serializeRecordEnvelope(validEnv), revision = 1, syncCursor = 5),
                RecordResponse(recordId = "rec-corrupted", ciphertextPayload = corruptedPayload, revision = 1, syncCursor = 10)
            ),
            serverCursor = 10,
            nextCursor = 10,
            hasMore = false
        )

        repository.forceFullResync()

        // Invariant: Valid item is decrypted; corrupted record is flagged
        assertEquals(1, repository.items.value.size)
        assertEquals("Valid Item", repository.items.value[0].title)
        assertTrue(repository.corruptedRecords.containsKey("rec-corrupted"))

        // Invariant: Cursor does not advance past highest valid record
        assertEquals(5, repository.syncCursor)

        // Invariant: Corrupted record is persisted in Room with corruption flag
        val corruptedEntity = db.recordDao().getRecord(accountId, "rec-corrupted")
        assertNotNull(corruptedEntity)
        assertTrue(corruptedEntity!!.isCorrupted)

        VaultCrypto.clearBytes(vek)
    }

    @Test
    fun testLockLogoutAndAccountSwitching() = runBlocking {
        val masterPasswordA = "UserAPassword123!"
        val vekA = setupUserWithMasterPassword(repository, masterPasswordA)

        // User A logs in
        repository.login("userA", "passA")
        val accountIdA = repository.accountId
        assertEquals("acc-test", accountIdA)
        repository.unlockVault(masterPasswordA)

        val itemA = VaultItem(id = "item-user-A", title = "User A Confidential")
        repository.saveItem(itemA)
        assertEquals(1, repository.items.value.size)

        // 1. Lock vault
        repository.lock()
        assertEquals(0, repository.items.value.size)
        assertFalse(repository.sessionState.value.isUnlocked)

        // Database still has User A's encrypted record
        assertEquals(1, db.recordDao().getActiveRecords(accountIdA).size)

        // 2. User A logs out
        repository.logout()
        assertFalse(repository.sessionState.value.isAuthenticated)
        assertEquals("", repository.accountId)

        // 3. User B logs in with a different account ID
        class UserBApiClient : FakePersistenceApiClient() {
            override suspend fun login(req: LoginRequest): LoginResponse {
                sessionToken = "session-token-B"
                return LoginResponse(
                    sessionToken = "session-token-B",
                    sessionId = "sess-B",
                    accountId = "acc-user-B",
                    expiresAt = "2026-10-19T00:00:00Z",
                    kdfSalt = kdfSaltToReturn ?: "c2FsdEZvclVzZXJCMTIzNDU2",
                    wrappedVaultKey = wrappedVaultKeyToReturn
                )
            }
        }
        val apiB = UserBApiClient()
        val repoB = VaultRepository(apiB, keyStoreManager, VaultCrypto, db)

        val masterPasswordB = "UserBPassword123!"
        val vekB = setupUserWithMasterPassword(repoB, masterPasswordB)
        apiB.wrappedVaultKeyToReturn = repoB.wrappedVaultKey

        repoB.login("userB", "passB")
        assertEquals("acc-user-B", repoB.accountId)

        repoB.unlockVault(masterPasswordB)

        // CRITICAL INVARIANT: User B MUST NOT see User A's items!
        assertEquals(0, repoB.items.value.size)
        assertNull(repoB.getItem("item-user-A"))

        VaultCrypto.clearBytes(vekA)
        VaultCrypto.clearBytes(vekB)
    }

    @Test
    fun testStaleAsynchronousResponsesAfterLockLogoutWithPersistence() = runBlocking {
        val masterPassword = "StaleAsyncPassword123!"
        val vek = setupUserWithMasterPassword(repository, masterPassword)

        repository.login("user1", "accountPassword123!")
        repository.unlockVault(masterPassword)

        val syncPause = CompletableDeferred<Unit>()
        val syncStarted = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = syncPause
        fakeApi.syncStartedDeferred = syncStarted

        val item1 = VaultItem(id = "rec-stale-1", title = "Stale Record")
        val env1 = VaultCrypto.encryptRecord(vek, item1.id, item1.toSecretJson())

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(RecordResponse(recordId = item1.id, ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 999)),
            serverCursor = 999,
            nextCursor = 999,
            hasMore = false
        )

        // Launch sync in background
        val syncJob = async { repository.syncRecords() }
        withTimeout(5_000L) { syncStarted.await() }

        // Lock vault while sync is in flight
        repository.lock()
        assertFalse(repository.sessionState.value.isUnlocked)

        // Resume sync
        syncPause.complete(Unit)
        withTimeout(5_000L) { syncJob.join() }

        // Invariant: Stale sync response must NOT populate in-memory state or Room DB!
        assertEquals(0, repository.items.value.size)
        assertNull(repository.getItem("rec-stale-1"))
        assertEquals(0, repository.syncCursor)

        VaultCrypto.clearBytes(vek)
    }
}
