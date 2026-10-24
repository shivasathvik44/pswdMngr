package com.vaultsync.android.repository

import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.api.AuthenticationException
import com.vaultsync.android.api.ConflictException
import com.vaultsync.android.api.CreateRecordRequest
import com.vaultsync.android.api.LoginRequest
import com.vaultsync.android.api.LoginResponse
import com.vaultsync.android.api.NetworkConnectionException
import com.vaultsync.android.api.RecordResponse
import com.vaultsync.android.api.SyncResponse
import com.vaultsync.android.api.UpdateRecordRequest
import com.vaultsync.android.api.UpdateVaultKeyRequest
import com.vaultsync.android.api.UpdateVaultKeyResponse
import com.vaultsync.android.api.ValidationException
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.RecordEnvelope
import com.vaultsync.android.crypto.SecureStorageException
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.model.VaultItem
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

class VaultRepositoryTest {

    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var fakeApi: FakeControllableApiClient
    private lateinit var repository: VaultRepository

    class FakeControllableApiClient : ApiClient("http://127.0.0.1:8000") {
        var syncResponseToReturn: SyncResponse? = null
        var syncExceptionToThrow: Exception? = null
        var syncPauseDeferred: CompletableDeferred<Unit>? = null
        var syncStartedDeferred: CompletableDeferred<Unit>? = null
        var syncHandler: (suspend (sinceCursor: Int, limit: Int) -> SyncResponse)? = null

        var syncCallCount: Int = 0
        val requestedSinceCursors = mutableListOf<Int>()

        var createRecordPauseDeferred: CompletableDeferred<Unit>? = null
        var createRecordStartedDeferred: CompletableDeferred<Unit>? = null
        var createRecordCallCount: Int = 0
        var createRecordResponseToReturn: RecordResponse? = null

        var updateRecordPauseDeferred: CompletableDeferred<Unit>? = null
        var updateRecordStartedDeferred: CompletableDeferred<Unit>? = null
        var updateRecordCallCount: Int = 0

        var loginPauseDeferred: CompletableDeferred<Unit>? = null
        var loginStartedDeferred: CompletableDeferred<Unit>? = null
        var loginCallCount: Int = 0
        var loginResponseToReturn: LoginResponse? = null

        var updateVaultKeyPauseDeferred: CompletableDeferred<Unit>? = null
        var updateVaultKeyStartedDeferred: CompletableDeferred<Unit>? = null
        var updateVaultKeyCallCount: Int = 0
        var lastUpdateVaultKeyRequest: UpdateVaultKeyRequest? = null
        var updateVaultKeyResponseToReturn: UpdateVaultKeyResponse? = null
        var updateVaultKeyExceptionToThrow: Exception? = null

        fun resetCounters() {
            syncCallCount = 0
            requestedSinceCursors.clear()
            updateVaultKeyCallCount = 0
            lastUpdateVaultKeyRequest = null
        }

        override suspend fun fetchSync(sinceCursor: Int, limit: Int): SyncResponse {
            syncCallCount++
            requestedSinceCursors.add(sinceCursor)
            syncStartedDeferred?.complete(Unit)

            syncPauseDeferred?.await()

            syncExceptionToThrow?.let { throw it }

            syncHandler?.let { return it.invoke(sinceCursor, limit) }

            return syncResponseToReturn ?: SyncResponse(
                items = emptyList(),
                serverCursor = sinceCursor,
                nextCursor = sinceCursor,
                hasMore = false
            )
        }

        override suspend fun createRecord(req: CreateRecordRequest): RecordResponse {
            createRecordCallCount++
            createRecordStartedDeferred?.complete(Unit)
            createRecordPauseDeferred?.await()
            return createRecordResponseToReturn ?: RecordResponse(
                recordId = req.recordId,
                ciphertextPayload = req.ciphertextPayload,
                revision = 1,
                syncCursor = 1
            )
        }

        override suspend fun updateRecord(recordId: String, req: UpdateRecordRequest): RecordResponse {
            updateRecordCallCount++
            updateRecordStartedDeferred?.complete(Unit)
            updateRecordPauseDeferred?.await()
            return RecordResponse(
                recordId = recordId,
                ciphertextPayload = req.ciphertextPayload,
                revision = req.expectedRevision + 1,
                syncCursor = 2
            )
        }

        override suspend fun login(req: LoginRequest): LoginResponse {
            loginCallCount++
            loginStartedDeferred?.complete(Unit)
            loginPauseDeferred?.await()
            return loginResponseToReturn ?: LoginResponse(
                sessionToken = "tok-${req.username}",
                sessionId = "sess-${req.username}",
                accountId = "acc-${req.username}",
                expiresAt = "2026-10-15T12:00:00Z",
                kdfSalt = "c2FsdA==",
                wrappedVaultKey = "{\"version\":1}",
                vaultKeyVersion = 1
            )
        }

        override suspend fun updateVaultKey(req: UpdateVaultKeyRequest): UpdateVaultKeyResponse {
            updateVaultKeyCallCount++
            lastUpdateVaultKeyRequest = req
            updateVaultKeyStartedDeferred?.complete(Unit)
            updateVaultKeyPauseDeferred?.await()
            updateVaultKeyExceptionToThrow?.let { throw it }
            return updateVaultKeyResponseToReturn ?: UpdateVaultKeyResponse(
                status = "ok",
                message = "Wrapped vault key updated successfully",
                vaultKeyVersion = req.expectedVersion + 1
            )
        }
    }

    @Before
    fun setUp() {
        keyStoreManager = KeyStoreManager(context = null)
        fakeApi = FakeControllableApiClient()
        repository = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto
        )
    }

    private fun unlockRepositoryDirectly(
        repo: VaultRepository,
        masterPass: String = "TestPass123!",
        accountPass: String? = "TestAccountPass123!"
    ) {
        val vek = VaultCrypto.generateVaultKey()
        val (saltBytes, envelope) = VaultCrypto.wrapVaultKey(vek, masterPass)
        val saltB64 = Base64.getEncoder().encodeToString(saltBytes)
        val envelopeJson = VaultCrypto.serializeWrappedKeyEnvelope(envelope)

        repo.keyStoreManager.saveSessionToken("test-session-token")
        repo.api.sessionToken = "test-session-token"

        val field = repo.javaClass.getDeclaredField("wrappedVaultKey")
        field.isAccessible = true
        field.set(repo, envelopeJson)

        val saltField = repo.javaClass.getDeclaredField("kdfSalt")
        saltField.isAccessible = true
        saltField.set(repo, saltB64)

        repo.keyStoreManager.lastWrappedVaultKey = envelopeJson
        repo.keyStoreManager.lastKdfSalt = saltB64
        repo.keyStoreManager.lastVaultKeyVersion = 1

        if (accountPass != null) {
            val accPassField = repo.javaClass.getDeclaredField("_accountPassword")
            accPassField.isAccessible = true
            accPassField.set(repo, accountPass)
        }

        runBlocking {
            repo.unlockVault(masterPass)
        }

        // unlockVault awaits its initial sync. Count only subsequent behavior under test.
        (repo.api as? FakeControllableApiClient)?.let {
            assertEquals(1, it.syncCallCount)
            assertEquals(listOf(0), it.requestedSinceCursors)
            it.resetCounters()
        }
    }

    private fun getVek(repo: VaultRepository): ByteArray {
        val vekField = repo.javaClass.getDeclaredField("_vaultKey")
        vekField.isAccessible = true
        return vekField.get(repo) as ByteArray
    }

    private fun createValidEnvelope(vek: ByteArray, recordId: String, title: String = "Test Item", revision: Int = 1): RecordEnvelope {
        val jsonPayload = "{\"title\":\"$title\",\"username\":\"user\",\"password\":\"pass\",\"notes\":\"\"}"
        return VaultCrypto.encryptRecord(vek, recordId, jsonPayload)
    }

    // ------------------------------------------------------------------------
    // Basic Repository State & Activity Tests
    // ------------------------------------------------------------------------

    @Test
    fun testUnlockFixtureSeparatesInitialSyncFromSubsequentRequests() = runBlocking {
        unlockRepositoryDirectly(repository)
        assertEquals(0, fakeApi.syncCallCount)
        assertTrue(fakeApi.requestedSinceCursors.isEmpty())
        repository.syncRecords()
        assertEquals(1, fakeApi.syncCallCount)
        assertEquals(listOf(0), fakeApi.requestedSinceCursors)
    }

    @Test
    fun testInitialState() {
        val state = repository.sessionState.value
        assertFalse(state.isAuthenticated)
        assertFalse(state.isUnlocked)
        assertEquals(0L, repository.lockGeneration)
        assertEquals(0, repository.items.value.size)
        assertEquals(0, repository.corruptedRecords.size)
    }

    @Test
    fun testLockClearsSensitiveState() {
        unlockRepositoryDirectly(repository)
        assertTrue(repository.sessionState.value.isUnlocked)

        repository.lock()
        assertEquals(2L, repository.lockGeneration)
        assertFalse(repository.sessionState.value.isUnlocked)
        assertEquals(0, repository.items.value.size)
        assertEquals(0, repository.corruptedRecords.size)
    }

    @Test
    fun testAutoLockTimeout() {
        repository.setAutoLockTimeoutMinutes(5)
        assertEquals(5, repository.getAutoLockTimeoutMinutes())
        assertFalse(repository.checkInactivityLock())
    }

    @Test
    fun testServerUrlUpdate() {
        val newUrl = "http://10.0.2.2:8000"
        repository.setServerUrl(newUrl)
        assertEquals(newUrl, repository.getServerUrl())
        assertEquals(newUrl, repository.sessionState.value.serverUrl)
    }

    @Test
    fun testClipboardTimeoutUpdate() {
        repository.setClipboardTimeoutSeconds(60)
        assertEquals(60, repository.getClipboardTimeoutSeconds())
    }

    @Test
    fun testLogoutClearsSessionAndLocks() = runBlocking {
        keyStoreManager.saveSessionToken("dummy-token")
        keyStoreManager.lastUsername = "alice"

        repository.logout()

        assertNull(keyStoreManager.getSessionToken())
        assertFalse(repository.sessionState.value.isAuthenticated)
        assertFalse(repository.sessionState.value.isUnlocked)
        assertEquals("", repository.username)
        assertEquals(0, repository.corruptedRecords.size)
    }

    @Test
    fun testMultipleLockCallsAreSafe() {
        repository.lock()
        repository.lock()
        assertEquals(2L, repository.lockGeneration)
        assertFalse(repository.sessionState.value.isUnlocked)
    }

    // ------------------------------------------------------------------------
    // Task 2: Concurrency & Lock/Logout Fencing Tests
    // ------------------------------------------------------------------------

    @Test
    fun testLockDuringPausedSyncAbortsPublication() = runBlocking {
        unlockRepositoryDirectly(repository)
        assertTrue(repository.sessionState.value.isUnlocked)

        val pauseDeferred = CompletableDeferred<Unit>()
        val syncStarted = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = pauseDeferred
        fakeApi.syncStartedDeferred = syncStarted

        val currentVek = getVek(repository)
        val env = createValidEnvelope(currentVek, "rec-1", "Secret Note")
        val envJson = VaultCrypto.serializeRecordEnvelope(env)

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(RecordResponse(recordId = "rec-1", ciphertextPayload = envJson, revision = 1, syncCursor = 1)),
            serverCursor = 1,
            nextCursor = 1,
            hasMore = false
        )

        val syncJob = launch(Dispatchers.Default) {
            repository.syncRecords()
        }

        withTimeout(5_000L) { syncStarted.await() }

        repository.lock()
        assertFalse(repository.sessionState.value.isUnlocked)

        pauseDeferred.complete(Unit)
        withTimeout(5_000L) { syncJob.join() }

        assertEquals(0, repository.items.value.size)
        assertNull(repository.getItem("rec-1"))
        assertFalse(repository.sessionState.value.isUnlocked)
    }

    @Test
    fun testLogoutDuringPendingNetworkResponseFencesOutPublication() = runBlocking {
        unlockRepositoryDirectly(repository)

        val pauseDeferred = CompletableDeferred<Unit>()
        val syncStarted = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = pauseDeferred
        fakeApi.syncStartedDeferred = syncStarted

        val syncJob = launch(Dispatchers.Default) {
            repository.syncRecords()
        }

        withTimeout(5_000L) { syncStarted.await() }

        val oldSessionGen = repository.sessionGeneration
        repository.logout()
        assertTrue(repository.sessionGeneration > oldSessionGen)

        pauseDeferred.complete(Unit)
        withTimeout(5_000L) { syncJob.join() }

        assertEquals(0, repository.items.value.size)
        assertFalse(repository.sessionState.value.isAuthenticated)
    }

    @Test
    fun testSessionAResponseArrivingAfterSessionBLogsIn() = runBlocking {
        val loginAPause = CompletableDeferred<Unit>()
        val loginAStarted = CompletableDeferred<Unit>()
        fakeApi.loginPauseDeferred = loginAPause
        fakeApi.loginStartedDeferred = loginAStarted

        val loginAJob = launch(Dispatchers.Default) {
            try {
                repository.loginAccount("userA", "passA")
            } catch (_: Exception) {
                // Expected to be fenced out
            }
        }

        withTimeout(5_000L) { loginAStarted.await() }

        // Session B logs in while Session A is pending
        fakeApi.loginPauseDeferred = null
        repository.loginAccount("userB", "passB")

        assertEquals("userB", repository.username)
        assertEquals("acc-userB", repository.accountId)

        // Now Session A's late response completes
        loginAPause.complete(Unit)
        withTimeout(5_000L) { loginAJob.join() }

        // Invariant: Session A must NOT overwrite Session B's state!
        assertEquals("userB", repository.username)
        assertEquals("acc-userB", repository.accountId)
        assertEquals("userB", keyStoreManager.lastUsername)
    }

    @Test
    fun testOldSessionFailedResponseArrivingAfterNewSessionStarts() = runBlocking {
        unlockRepositoryDirectly(repository)

        val syncPause = CompletableDeferred<Unit>()
        val syncStarted = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = syncPause
        fakeApi.syncStartedDeferred = syncStarted

        val syncJob = launch(Dispatchers.Default) {
            repository.syncRecords()
        }

        withTimeout(5_000L) { syncStarted.await() }

        // New session starts: logout then login
        repository.logout()
        fakeApi.loginPauseDeferred = null
        fakeApi.syncPauseDeferred = null
        repository.loginAccount("userB", "passB")

        // Old sync now throws network error
        fakeApi.syncExceptionToThrow = NetworkConnectionException("Connection timeout")
        syncPause.complete(Unit)
        withTimeout(5_000L) { syncJob.join() }

        // Invariant: Stale sync failure must NOT update new session's state
        assertEquals("userB", repository.sessionState.value.username)
        assertTrue(repository.sessionState.value.isAuthenticated)
        assertNull(repository.sessionState.value.errorMessage)
    }

    @Test
    fun testLockDuringCreateOperationAbortsPublication() = runBlocking {
        unlockRepositoryDirectly(repository)

        val createPause = CompletableDeferred<Unit>()
        val createStarted = CompletableDeferred<Unit>()
        fakeApi.createRecordPauseDeferred = createPause
        fakeApi.createRecordStartedDeferred = createStarted

        val itemToCreate = VaultItem(
            id = "item-new-1",
            title = "Top Secret",
            username = "agent",
            password = "secretpassword"
        )

        var createException: Throwable? = null
        val saveJob = launch(Dispatchers.Default) {
            try {
                repository.saveItem(itemToCreate)
            } catch (e: Throwable) {
                createException = e
            }
        }

        withTimeout(5_000L) { createStarted.await() }

        // Lock while saveItem is in flight awaiting network response
        repository.lock()
        assertFalse(repository.sessionState.value.isUnlocked)

        createPause.complete(Unit)
        withTimeout(5_000L) { saveJob.join() }

        // Invariant: Must throw IllegalStateException and NOT publish item!
        assertNotNull(createException)
        assertTrue(createException is IllegalStateException)
        assertEquals(0, repository.items.value.size)
        assertNull(repository.getItem("item-new-1"))
    }

    @Test
    fun testCancellationWhileMutexIsHeldFreesMutex() = runBlocking {
        unlockRepositoryDirectly(repository)

        val pauseDeferred = CompletableDeferred<Unit>()
        val syncStarted = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = pauseDeferred
        fakeApi.syncStartedDeferred = syncStarted

        val syncJob = launch(Dispatchers.Default) {
            repository.syncRecords()
        }

        withTimeout(5_000L) { syncStarted.await() }

        withTimeout(5_000L) { syncJob.cancelAndJoin() }

        pauseDeferred.complete(Unit)
        fakeApi.syncPauseDeferred = null

        fakeApi.syncResponseToReturn = SyncResponse(
            items = emptyList(),
            serverCursor = 0,
            nextCursor = 0,
            hasMore = false
        )

        repository.syncRecords()
        assertTrue(repository.sessionState.value.isUnlocked)
    }

    @Test
    fun testInvalidatedSyncCannotOverwriteActiveCursorOrErrorBanner() = runBlocking {
        unlockRepositoryDirectly(repository)

        val syncPause = CompletableDeferred<Unit>()
        val syncStarted = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = syncPause
        fakeApi.syncStartedDeferred = syncStarted

        val currentVek = getVek(repository)
        val env = createValidEnvelope(currentVek, "stale-1", "Stale Item")
        val envJson = VaultCrypto.serializeRecordEnvelope(env)

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(RecordResponse(recordId = "stale-1", ciphertextPayload = envJson, revision = 1, syncCursor = 999)),
            serverCursor = 999,
            nextCursor = 999,
            hasMore = false
        )

        val syncJob = launch(Dispatchers.Default) {
            repository.syncRecords()
        }

        withTimeout(5_000L) { syncStarted.await() }

        // Lock the repository
        repository.lock()
        assertEquals(0, repository.syncCursor)

        // Resume stale sync
        syncPause.complete(Unit)
        withTimeout(5_000L) { syncJob.join() }

        // Invariant: Stale cursor (999) must NOT overwrite cursor
        assertEquals(0, repository.syncCursor)
        assertEquals(0, repository.items.value.size)
        assertNull(repository.getItem("stale-1"))
    }

    // ------------------------------------------------------------------------
    // Task 3: Pagination, Cursor Semantics, and Corruption Recovery Tests
    // ------------------------------------------------------------------------

    @Test
    fun testResyncEmptyVault() = runBlocking {
        unlockRepositoryDirectly(repository)

        fakeApi.syncResponseToReturn = SyncResponse(
            items = emptyList(),
            serverCursor = 0,
            nextCursor = 0,
            hasMore = false
        )

        repository.forceFullResync()

        assertEquals(0, repository.items.value.size)
        assertEquals(0, repository.syncCursor)
        assertEquals(0, repository.corruptedRecords.size)
        assertTrue(repository.sessionState.value.syncStatusMessage.contains("0 items"))
    }

    @Test
    fun testResyncOnePageHasMoreFalse() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")
        val env2 = createValidEnvelope(vek, "rec-2", "Item 2")

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1),
                RecordResponse(recordId = "rec-2", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env2), revision = 1, syncCursor = 2)
            ),
            serverCursor = 2,
            nextCursor = 2,
            hasMore = false
        )

        repository.forceFullResync()

        assertEquals(2, repository.items.value.size)
        assertEquals(2, repository.syncCursor)
        assertEquals(0, repository.corruptedRecords.size)
        assertEquals(1, fakeApi.syncCallCount)
    }

    @Test
    fun testResyncMultiplePagesMonotonicallyIncreasing() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")
        val env2 = createValidEnvelope(vek, "rec-2", "Item 2")
        val env3 = createValidEnvelope(vek, "rec-3", "Item 3")
        val env4 = createValidEnvelope(vek, "rec-4", "Item 4")

        fakeApi.syncHandler = { sinceCursor, _ ->
            when (sinceCursor) {
                0 -> SyncResponse(
                    items = listOf(
                        RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1),
                        RecordResponse(recordId = "rec-2", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env2), revision = 1, syncCursor = 2)
                    ),
                    serverCursor = 4,
                    nextCursor = 2,
                    hasMore = true
                )
                2 -> SyncResponse(
                    items = listOf(
                        RecordResponse(recordId = "rec-3", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env3), revision = 1, syncCursor = 3),
                        RecordResponse(recordId = "rec-4", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env4), revision = 1, syncCursor = 4)
                    ),
                    serverCursor = 4,
                    nextCursor = 4,
                    hasMore = false
                )
                else -> error("Unexpected cursor: $sinceCursor")
            }
        }

        repository.forceFullResync()

        assertEquals(4, repository.items.value.size)
        assertEquals(4, repository.syncCursor)
        assertEquals(0, repository.corruptedRecords.size)
        assertEquals(2, fakeApi.syncCallCount)
    }

    @Test
    fun testForceFullResyncPreservesExistingItemsOnNetworkFailure() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env = createValidEnvelope(vek, "existing-1", "Bank Account")

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(RecordResponse(recordId = "existing-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env), revision = 1, syncCursor = 10)),
            serverCursor = 10,
            nextCursor = 10,
            hasMore = false
        )
        repository.syncRecords()

        assertEquals(1, repository.items.value.size)
        assertEquals("Bank Account", repository.getItem("existing-1")?.title)
        assertEquals(10, repository.syncCursor)

        // Trigger forceFullResync(), but fake API throws network exception
        fakeApi.syncExceptionToThrow = NetworkConnectionException("Connection refused by peer")

        try {
            repository.forceFullResync()
        } catch (_: Exception) {
            // Expected
        }

        // Invariant: The existing in-memory view must NOT be destroyed!
        assertEquals(1, repository.items.value.size)
        assertEquals("Bank Account", repository.getItem("existing-1")?.title)
        assertEquals(10, repository.syncCursor)
        assertTrue(repository.sessionState.value.errorMessage?.contains("preserved") == true)
    }

    @Test
    fun testForceFullResyncCapturesCorruptedRecordsAndDoesNotAdvanceCursorPastThem() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val validEnv = createValidEnvelope(vek, "valid-1", "Valid Item")
        val corruptedPayload = "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"record_id\":\"bad-1\",\"nonce\":\"Hh8gISIjJCUmJygp\",\"ciphertext\":\"bad-ciphertext-and-tag-12345\"}"

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = "valid-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(validEnv), revision = 1, syncCursor = 5),
                RecordResponse(recordId = "bad-1", ciphertextPayload = corruptedPayload, revision = 1, syncCursor = 6)
            ),
            serverCursor = 6,
            nextCursor = 6,
            hasMore = false
        )

        repository.forceFullResync()

        assertEquals(1, repository.items.value.size)
        assertEquals("Valid Item", repository.getItem("valid-1")?.title)
        assertEquals(1, repository.corruptedRecords.size)
        assertTrue(repository.corruptedRecords.containsKey("bad-1"))
        assertTrue(repository.sessionState.value.warningMessage?.contains("bad-1") == true)
        assertTrue(repository.sessionState.value.syncStatusMessage.contains("incomplete"))
        assertEquals(5, repository.syncCursor) // Cursor NOT advanced past failed record!
    }

    @Test
    fun testCorruptedRecordOnLaterPage() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")
        val env2 = createValidEnvelope(vek, "rec-2", "Item 2")
        val badPayload = "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"record_id\":\"rec-3\",\"nonce\":\"Hh8gISIjJCUmJygp\",\"ciphertext\":\"invalid\"}"

        fakeApi.syncHandler = { sinceCursor, _ ->
            when (sinceCursor) {
                0 -> SyncResponse(
                    items = listOf(RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 10)),
                    serverCursor = 20,
                    nextCursor = 10,
                    hasMore = true
                )
                10 -> SyncResponse(
                    items = listOf(
                        RecordResponse(recordId = "rec-2", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env2), revision = 1, syncCursor = 15),
                        RecordResponse(recordId = "rec-3", ciphertextPayload = badPayload, revision = 1, syncCursor = 20)
                    ),
                    serverCursor = 20,
                    nextCursor = 20,
                    hasMore = false
                )
                else -> error("Unexpected cursor: $sinceCursor")
            }
        }

        repository.forceFullResync()

        assertEquals(2, repository.items.value.size)
        assertEquals(1, repository.corruptedRecords.size)
        assertTrue(repository.corruptedRecords.containsKey("rec-3"))
        assertEquals(15, repository.syncCursor) // Halted at last valid cursor 15, not 20!
    }

    @Test
    fun testRetryingAfterCorruptionRepairedOnServer() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")
        val badPayload = "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"record_id\":\"rec-2\",\"nonce\":\"Hh8gISIjJCUmJygp\",\"ciphertext\":\"corrupted\"}"

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1),
                RecordResponse(recordId = "rec-2", ciphertextPayload = badPayload, revision = 1, syncCursor = 2)
            ),
            serverCursor = 2,
            nextCursor = 2,
            hasMore = false
        )

        repository.forceFullResync()
        assertEquals(1, repository.corruptedRecords.size)
        assertEquals(1, repository.syncCursor)

        // Server repairs rec-2: valid envelope now returned
        val env2Repaired = createValidEnvelope(vek, "rec-2", "Item 2 Repaired")
        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1),
                RecordResponse(recordId = "rec-2", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env2Repaired), revision = 2, syncCursor = 3)
            ),
            serverCursor = 3,
            nextCursor = 3,
            hasMore = false
        )

        repository.forceFullResync()
        assertEquals(2, repository.items.value.size)
        assertEquals(0, repository.corruptedRecords.size)
        assertEquals(3, repository.syncCursor)
        assertNull(repository.sessionState.value.warningMessage)
    }

    @Test
    fun testUnchangedCorruptedRecordOnRepeatedIncrementalSyncDoesNotLoopForever() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")
        val badPayload = "{\"version\":1,\"algorithm\":\"AES-256-GCM\",\"record_id\":\"bad-1\",\"nonce\":\"Hh8gISIjJCUmJygp\",\"ciphertext\":\"invalid\"}"

        fakeApi.syncResponseToReturn = SyncResponse(
            items = listOf(
                RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1),
                RecordResponse(recordId = "bad-1", ciphertextPayload = badPayload, revision = 1, syncCursor = 2)
            ),
            serverCursor = 2,
            nextCursor = 2,
            hasMore = false
        )

        // Initial incremental sync captures and quarantines the bad record
        repository.syncRecords()
        assertEquals(1, repository.corruptedRecords.size)
        assertEquals(2, repository.syncCursor)
        assertEquals(1, fakeApi.syncCallCount)

        // Subsequent incremental syncs: server has no new changes since cursor 2
        fakeApi.syncResponseToReturn = SyncResponse(
            items = emptyList(),
            serverCursor = 2,
            nextCursor = 2,
            hasMore = false
        )

        // Call syncRecords 5 more times
        for (i in 1..5) {
            repository.syncRecords()
        }

        // Must execute exactly 6 calls total without busy looping
        assertEquals(6, fakeApi.syncCallCount)
        assertEquals(2, repository.syncCursor)
        assertEquals(1, repository.corruptedRecords.size)
    }

    @Test
    fun testForceFullResyncHandlesPaginationAndTombstones() = runBlocking {
        lateinit var item1Env: RecordEnvelope
        lateinit var item2Env: RecordEnvelope
        lateinit var item3Env: RecordEnvelope

        val paginatedApi = object : ApiClient("http://127.0.0.1:8000") {
            override suspend fun fetchSync(sinceCursor: Int, limit: Int): SyncResponse {
                return if (sinceCursor == 0) {
                    SyncResponse(
                        items = listOf(
                            RecordResponse(recordId = "item-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(item1Env), revision = 1, syncCursor = 1),
                            RecordResponse(recordId = "item-2", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(item2Env), revision = 1, syncCursor = 2)
                        ),
                        serverCursor = 4,
                        nextCursor = 2,
                        hasMore = true
                    )
                } else {
                    SyncResponse(
                        items = listOf(
                            RecordResponse(recordId = "item-1", ciphertextPayload = "", isDeleted = true, revision = 2, syncCursor = 3),
                            RecordResponse(recordId = "item-3", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(item3Env), revision = 1, syncCursor = 4)
                        ),
                        serverCursor = 4,
                        nextCursor = 4,
                        hasMore = false
                    )
                }
            }
        }

        val testRepo = VaultRepository(
            api = paginatedApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto
        )
        unlockRepositoryDirectly(testRepo)

        val vek = getVek(testRepo)
        item1Env = createValidEnvelope(vek, "item-1", "Item 1")
        item2Env = createValidEnvelope(vek, "item-2", "Item 2")
        item3Env = createValidEnvelope(vek, "item-3", "Item 3")

        testRepo.forceFullResync()

        assertNull(testRepo.getItem("item-1"))
        assertEquals(2, testRepo.items.value.size)
        assertNotNull(testRepo.getItem("item-2"))
        assertNotNull(testRepo.getItem("item-3"))
        assertEquals(4, testRepo.syncCursor)
        assertEquals(0, testRepo.corruptedRecords.size)
        assertTrue(testRepo.sessionState.value.syncStatusMessage.contains("Synced"))
    }

    @Test
    fun testDuplicateRecordIdsAcrossPagesLatestRevisionWins() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val envRev1 = createValidEnvelope(vek, "rec-dup", "Original Title", revision = 1)
        val envRev2 = createValidEnvelope(vek, "rec-dup", "Updated Title", revision = 2)

        fakeApi.syncHandler = { sinceCursor, _ ->
            when (sinceCursor) {
                0 -> SyncResponse(
                    items = listOf(RecordResponse(recordId = "rec-dup", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(envRev1), revision = 1, syncCursor = 1)),
                    serverCursor = 3,
                    nextCursor = 1,
                    hasMore = true
                )
                1 -> SyncResponse(
                    items = listOf(RecordResponse(recordId = "rec-dup", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(envRev2), revision = 2, syncCursor = 3)),
                    serverCursor = 3,
                    nextCursor = 3,
                    hasMore = false
                )
                else -> error("Unexpected cursor: $sinceCursor")
            }
        }

        repository.forceFullResync()

        assertEquals(1, repository.items.value.size)
        val item = repository.getItem("rec-dup")
        assertNotNull(item)
        assertEquals("Updated Title", item?.title)
        assertEquals(2, item?.revision)
        assertEquals(3, repository.syncCursor)
    }

    @Test
    fun testOutOfOrderOrNonMonotonicCursorValuesDoesNotLoopForever() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")

        // Malicious or buggy server returns non-monotonic decreasing next_cursor with has_more=true
        fakeApi.syncHandler = { sinceCursor, _ ->
            when (sinceCursor) {
                0 -> SyncResponse(
                    items = listOf(RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1)),
                    serverCursor = 5,
                    nextCursor = 5,
                    hasMore = true
                )
                5 -> SyncResponse(
                    // Next cursor regressed back to 2, claiming hasMore=true
                    items = emptyList(),
                    serverCursor = 5,
                    nextCursor = 2,
                    hasMore = true
                )
                else -> SyncResponse(
                    items = emptyList(),
                    serverCursor = 5,
                    nextCursor = sinceCursor,
                    hasMore = false
                )
            }
        }

        repository.forceFullResync()

        // Loop detector broke out safely
        assertTrue(fakeApi.syncCallCount <= 3)
        assertEquals(1, repository.items.value.size)
    }

    @Test
    fun testLockDuringPageFetchingAbortsPublication() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Item 1")
        val env2 = createValidEnvelope(vek, "rec-2", "Item 2")
        val page2Pause = CompletableDeferred<Unit>()
        val page2Entered = CompletableDeferred<Unit>()

        fakeApi.syncHandler = { sinceCursor, _ ->
            when (sinceCursor) {
                0 -> SyncResponse(
                    items = listOf(RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1)),
                    serverCursor = 4,
                    nextCursor = 1,
                    hasMore = true
                )
                1 -> {
                    page2Entered.complete(Unit)
                    page2Pause.await()
                    SyncResponse(
                        items = listOf(RecordResponse(recordId = "rec-2", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env2), revision = 1, syncCursor = 2)),
                        serverCursor = 4,
                        nextCursor = 2,
                        hasMore = false
                    )
                }
                else -> error("Unexpected cursor: $sinceCursor")
            }
        }

        val resyncJob = launch(Dispatchers.Default) {
            repository.forceFullResync()
        }

        withTimeout(5_000L) { page2Entered.await() }

        // Lock while page 2 is in flight
        repository.lock()
        assertFalse(repository.sessionState.value.isUnlocked)

        page2Pause.complete(Unit)
        withTimeout(5_000L) { resyncJob.join() }

        // Invariant: Staged records from page 1 and page 2 must NOT be published!
        assertEquals(0, repository.items.value.size)
        assertFalse(repository.sessionState.value.isUnlocked)
        assertEquals(0, repository.syncCursor)
    }

    @Test
    fun testStaleFullResyncReturningAfterNewerSessionBegins() = runBlocking {
        unlockRepositoryDirectly(repository)
        val vek = getVek(repository)

        val env1 = createValidEnvelope(vek, "rec-1", "Session 1 Item")
        val resyncPause = CompletableDeferred<Unit>()
        val resyncStarted = CompletableDeferred<Unit>()
        fakeApi.syncStartedDeferred = resyncStarted

        fakeApi.syncHandler = { sinceCursor, _ ->
            resyncPause.await()
            SyncResponse(
                items = listOf(RecordResponse(recordId = "rec-1", ciphertextPayload = VaultCrypto.serializeRecordEnvelope(env1), revision = 1, syncCursor = 1)),
                serverCursor = 1,
                nextCursor = 1,
                hasMore = false
            )
        }

        val resyncJob = launch(Dispatchers.Default) {
            repository.forceFullResync()
        }

        withTimeout(5_000L) { resyncStarted.await() }

        // Session 1 logs out, Session 2 logs in
        repository.logout()
        fakeApi.loginPauseDeferred = null
        repository.loginAccount("user2", "pass2")

        // Session 1's resync now returns
        resyncPause.complete(Unit)
        withTimeout(5_000L) { resyncJob.join() }

        // Invariant: Session 1's records must NOT publish into Session 2!
        assertEquals("user2", repository.username)
        assertEquals(0, repository.items.value.size)
        assertNull(repository.getItem("rec-1"))
    }

    @Test
    fun testLoginFailureWhenKeystoreFailsToPersist() = runBlocking {
        var failSave = false
        keyStoreManager = object : KeyStoreManager() {
            override fun saveSessionToken(token: String) {
                if (failSave) {
                    clearSessionToken()
                    throw SecureStorageException("Synthetic storage failure")
                }
                super.saveSessionToken(token)
            }
        }
        repository = VaultRepository(fakeApi, keyStoreManager, VaultCrypto)
        unlockRepositoryDirectly(repository)
        val previousKey = getVek(repository)
        failSave = true

        assertThrows(SecureStorageException::class.java) {
            runBlocking {
                repository.loginAccount("testuser", "testpass")
            }
        }

        // Invariant: Repository state must fail closed into clean unauthenticated state
        assertFalse(repository.sessionState.value.isAuthenticated)
        assertFalse(repository.sessionState.value.isUnlocked)
        assertNull(repository.api.sessionToken)
        assertEquals("", repository.username)
        assertEquals("", repository.accountId)
        assertTrue(repository.sessionState.value.errorMessage?.contains("Failed to securely store session") == true)
        assertTrue(previousKey.all { it == 0.toByte() })
        assertNull(keyStoreManager.getSessionToken())
        failSave = false
        repository.loginAccount("testuser", "testpass")
        assertTrue(repository.sessionState.value.isAuthenticated)
    }

    @Test
    fun testInvalidStoredTokenStartsUnauthenticated() {
        val brokenStorage = object : KeyStoreManager() {
            override fun getSessionToken(): String? = throw SecureStorageException("Synthetic invalidated key")
        }
        fakeApi.sessionToken = "synthetic-stale-token"
        val restored = VaultRepository(fakeApi, brokenStorage, VaultCrypto)
        assertFalse(restored.sessionState.value.isAuthenticated)
        assertNull(fakeApi.sessionToken)
    }

    @Test
    fun testRotateMasterPasswordSuccessSubmitsExpectedVersionAndAccountPassword() = runBlocking {
        unlockRepositoryDirectly(repository, "CurrentMasterPass123!", "AccountStepUpPass456!")
        assertEquals(1, repository.vaultKeyVersion)
        val initialWrappedKey = repository.wrappedVaultKey
        val initialSalt = repository.kdfSalt

        repository.rotateMasterPassword("NewMasterPassword789!")

        assertEquals(1, fakeApi.updateVaultKeyCallCount)
        val sentReq = fakeApi.lastUpdateVaultKeyRequest
        assertNotNull(sentReq)
        assertEquals(1, sentReq!!.expectedVersion)
        assertEquals("AccountStepUpPass456!", sentReq.currentPassword)
        assertFalse(sentReq.wrappedVaultKey.isBlank())
        assertFalse(sentReq.kdfSalt.isBlank())
        assertFalse(sentReq.wrappedVaultKey == initialWrappedKey)

        assertEquals(2, repository.vaultKeyVersion)
        assertEquals(sentReq.wrappedVaultKey, repository.wrappedVaultKey)
        assertEquals(sentReq.kdfSalt, repository.kdfSalt)
        assertEquals(2, keyStoreManager.lastVaultKeyVersion)
        assertEquals(sentReq.wrappedVaultKey, keyStoreManager.lastWrappedVaultKey)
        assertEquals(sentReq.kdfSalt, keyStoreManager.lastKdfSalt)
    }

    @Test
    fun testRotateMasterPasswordWithExplicitAccountPasswordOverridesInMemory() = runBlocking {
        unlockRepositoryDirectly(repository, "CurrentMasterPass123!", "DefaultAccountPass!")
        assertEquals(1, repository.vaultKeyVersion)

        repository.rotateMasterPassword("NewMasterPassword789!", accountPassword = "ExplicitStepUpPass!")

        assertEquals(1, fakeApi.updateVaultKeyCallCount)
        val sentReq = fakeApi.lastUpdateVaultKeyRequest
        assertNotNull(sentReq)
        assertEquals(1, sentReq!!.expectedVersion)
        assertEquals("ExplicitStepUpPass!", sentReq.currentPassword)
        assertEquals(2, repository.vaultKeyVersion)
    }

    @Test
    fun testRotateMasterPasswordThrowsWhenNoAccountPasswordAvailable() {
        unlockRepositoryDirectly(repo = repository, masterPass = "CurrentMasterPass123!", accountPass = null)
        val initialKey = repository.wrappedVaultKey
        val initialVersion = repository.vaultKeyVersion

        val ex = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                repository.rotateMasterPassword("NewMasterPassword789!")
            }
        }
        assertTrue(ex.message!!.contains("Account password required for step-up auth"))
        assertEquals(0, fakeApi.updateVaultKeyCallCount)
        assertEquals(initialKey, repository.wrappedVaultKey)
        assertEquals(initialVersion, repository.vaultKeyVersion)
    }

    @Test
    fun testRotateMasterPasswordConflict409PreservesLocalState() {
        unlockRepositoryDirectly(repository, "CurrentMasterPass123!", "AccountStepUpPass456!")
        val initialWrappedKey = repository.wrappedVaultKey
        val initialSalt = repository.kdfSalt
        val initialVersion = repository.vaultKeyVersion
        assertEquals(1, initialVersion)

        fakeApi.updateVaultKeyExceptionToThrow = ConflictException(
            "Conflict: expected vault key version 1, but current version is 2"
        )

        val ex = assertThrows(ConflictException::class.java) {
            runBlocking {
                repository.rotateMasterPassword("NewMasterPassword789!")
            }
        }
        assertEquals(409, ex.statusCode)
        assertTrue(ex.message!!.contains("Conflict"))

        // Invariants: Local state, version, and Keystore metadata remain completely unchanged
        assertEquals(initialVersion, repository.vaultKeyVersion)
        assertEquals(initialWrappedKey, repository.wrappedVaultKey)
        assertEquals(initialSalt, repository.kdfSalt)
        assertEquals(initialVersion, keyStoreManager.lastVaultKeyVersion)
        assertEquals(initialWrappedKey, keyStoreManager.lastWrappedVaultKey)
        assertEquals(initialSalt, keyStoreManager.lastKdfSalt)
    }

    @Test
    fun testRotateMasterPasswordValidation422PreservesLocalState() {
        unlockRepositoryDirectly(repository, "CurrentMasterPass123!", "AccountStepUpPass456!")
        val initialWrappedKey = repository.wrappedVaultKey
        val initialSalt = repository.kdfSalt
        val initialVersion = repository.vaultKeyVersion

        fakeApi.updateVaultKeyExceptionToThrow = ValidationException(
            "Validation error: expected_version must be greater than or equal to 0"
        )

        val ex = assertThrows(ValidationException::class.java) {
            runBlocking {
                repository.rotateMasterPassword("NewMasterPassword789!")
            }
        }
        assertEquals(422, ex.statusCode)

        // Invariants: Local state remains untouched
        assertEquals(initialVersion, repository.vaultKeyVersion)
        assertEquals(initialWrappedKey, repository.wrappedVaultKey)
        assertEquals(initialSalt, repository.kdfSalt)
        assertEquals(initialVersion, keyStoreManager.lastVaultKeyVersion)
    }

    @Test
    fun testRotateMasterPasswordInterruptedNetworkRetrySafe() = runBlocking {
        unlockRepositoryDirectly(repository, "CurrentMasterPass123!", "AccountStepUpPass456!")
        val initialWrappedKey = repository.wrappedVaultKey
        val initialSalt = repository.kdfSalt
        assertEquals(1, repository.vaultKeyVersion)

        // Step 1: Simulate network drop before response arrives
        fakeApi.updateVaultKeyExceptionToThrow = NetworkConnectionException("Connection timeout")
        assertThrows(NetworkConnectionException::class.java) {
            runBlocking {
                repository.rotateMasterPassword("NewMasterPassword789!")
            }
        }

        // Local state was not updated on error
        assertEquals(1, repository.vaultKeyVersion)
        assertEquals(initialWrappedKey, repository.wrappedVaultKey)
        assertEquals(initialSalt, repository.kdfSalt)

        // Step 2: Retry with network restored (server idempotent response returns version 2)
        fakeApi.updateVaultKeyExceptionToThrow = null
        repository.rotateMasterPassword("NewMasterPassword789!")

        // Retry must still submit the original expectedVersion = 1
        assertEquals(2, fakeApi.updateVaultKeyCallCount)
        assertEquals(1, fakeApi.lastUpdateVaultKeyRequest!!.expectedVersion)
        assertEquals(2, repository.vaultKeyVersion)
        assertEquals(2, keyStoreManager.lastVaultKeyVersion)
        assertFalse(repository.wrappedVaultKey == initialWrappedKey)
    }

    @Test
    fun testLoginInitializesVaultKeyVersionAndPropagatesToRotation() = runBlocking {
        fakeApi.loginResponseToReturn = LoginResponse(
            sessionToken = "tok-versioned",
            sessionId = "sess-versioned",
            accountId = "acc-versioned",
            expiresAt = "2026-10-15T12:00:00Z",
            kdfSalt = "c2FsdDE2Ynl0ZXNhbHQ=",
            wrappedVaultKey = "{\"version\":1}",
            vaultKeyVersion = 5
        )

        repository.loginAccount("alice", "AliceAccPassword999!")

        assertEquals(5, repository.vaultKeyVersion)
        assertEquals(5, keyStoreManager.lastVaultKeyVersion)

        // Directly unlock with simulated VEK
        val vek = VaultCrypto.generateVaultKey()
        val (saltBytes, envelope) = VaultCrypto.wrapVaultKey(vek, "AliceMasterPass123!")
        val saltB64 = Base64.getEncoder().encodeToString(saltBytes)
        val envelopeJson = VaultCrypto.serializeWrappedKeyEnvelope(envelope)
        val field = repository.javaClass.getDeclaredField("wrappedVaultKey")
        field.isAccessible = true
        field.set(repository, envelopeJson)
        val saltField = repository.javaClass.getDeclaredField("kdfSalt")
        saltField.isAccessible = true
        saltField.set(repository, saltB64)
        repository.unlockVault("AliceMasterPass123!")

        // Rotate master password: must submit expectedVersion = 5 and currentPassword = "AliceAccPassword999!"
        repository.rotateMasterPassword("AliceNewMasterPass777!")

        assertEquals(1, fakeApi.updateVaultKeyCallCount)
        val sentReq = fakeApi.lastUpdateVaultKeyRequest
        assertNotNull(sentReq)
        assertEquals(5, sentReq!!.expectedVersion)
        assertEquals("AliceAccPassword999!", sentReq.currentPassword)
        assertEquals(6, repository.vaultKeyVersion)
        assertEquals(6, keyStoreManager.lastVaultKeyVersion)
    }

    @Test
    fun testLogoutAndAuthFailureResetVaultKeyVersionAndAccountPassword() {
        runBlocking {
            unlockRepositoryDirectly(repository, "CurrentMasterPass123!", "AccountStepUpPass456!")
            assertEquals(1, repository.vaultKeyVersion)

            // Logout
            repository.logout()

            assertEquals(1, repository.vaultKeyVersion)
            assertEquals(1, keyStoreManager.lastVaultKeyVersion)

            // Rotating while locked/logged out must fail
            assertThrows(IllegalStateException::class.java) {
                runBlocking {
                    repository.rotateMasterPassword("ShouldFailPass!")
                }
            }
        }
    }
}
