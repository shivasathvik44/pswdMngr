package com.vaultsync.android.ui.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.api.HealthResponse
import com.vaultsync.android.api.SyncResponse
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.model.VaultItem
import com.vaultsync.android.repository.VaultRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class AnrRegressionTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val testScheduler = TestCoroutineScheduler()
    private val testDispatcher = StandardTestDispatcher(testScheduler)

    private lateinit var context: Context
    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var fakeApi: FakeAnrApiClient

    open class FakeAnrApiClient : ApiClient("http://127.0.0.1:8000") {
        val syncCount = AtomicInteger(0)
        var syncPauseDeferred: CompletableDeferred<Unit>? = null

        override suspend fun checkHealth(): HealthResponse {
            return HealthResponse(status = "ok")
        }

        override suspend fun fetchSync(sinceCursor: Int, limit: Int): SyncResponse {
            syncCount.incrementAndGet()
            syncPauseDeferred?.await()
            return SyncResponse(items = emptyList(), serverCursor = 0, nextCursor = 0, hasMore = false)
        }
    }

    class TrackingDispatcher(private val target: CoroutineDispatcher) : CoroutineDispatcher() {
        val dispatchCount = AtomicInteger(0)

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            dispatchCount.incrementAndGet()
            target.dispatch(context, block)
        }
    }

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        context = ApplicationProvider.getApplicationContext()
        keyStoreManager = KeyStoreManager(context = null)
        fakeApi = FakeAnrApiClient()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test(timeout = 10_000)
    fun testUnlockVaultDispatchesKdfToDefaultDispatcher(): Unit = runTest(testDispatcher) {
        val trackingDefault = TrackingDispatcher(testDispatcher)
        val trackingIo = TrackingDispatcher(testDispatcher)

        // Seed account state with a wrapped key
        val vek = VaultCrypto.generateVaultKey()
        val masterPassword = "TestMasterPassword123!"
        val (_, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        VaultCrypto.clearBytes(vek)

        keyStoreManager.lastAccountId = "acc-anr-1"
        keyStoreManager.lastUsername = "anruser"
        keyStoreManager.lastWrappedVaultKey = json.encodeToString(envelope)
        keyStoreManager.saveSessionToken("valid-token")

        val repo = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null,
            ioDispatcher = trackingIo,
            defaultDispatcher = trackingDefault
        )

        val initialDefaultDispatches = trackingDefault.dispatchCount.get()

        val unlockJob = launch {
            repo.unlockVault(masterPassword)
        }
        testScheduler.advanceUntilIdle()
        unlockJob.join()

        // Verify KDF derivation dispatched to defaultDispatcher
        assertTrue(
            "Expected unwrapVaultKey to dispatch to defaultDispatcher",
            trackingDefault.dispatchCount.get() > initialDefaultDispatches
        )
        assertTrue(repo.sessionState.value.isUnlocked)
    }

    @Test(timeout = 10_000)
    fun testDatabaseAndSyncDispatchToIoDispatcher(): Unit = runTest(testDispatcher) {
        val trackingIo = TrackingDispatcher(testDispatcher)
        val trackingDefault = TrackingDispatcher(testDispatcher)

        val vek = VaultCrypto.generateVaultKey()
        val masterPassword = "SyncTestPassword123!"
        val (_, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        VaultCrypto.clearBytes(vek)

        keyStoreManager.lastAccountId = "acc-sync-dispatch"
        keyStoreManager.lastUsername = "syncuser"
        keyStoreManager.lastWrappedVaultKey = json.encodeToString(envelope)
        keyStoreManager.saveSessionToken("valid-token")

        val repository = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null,
            ioDispatcher = trackingIo,
            defaultDispatcher = trackingDefault
        )

        // Unlock repository so it is ready for sync
        val unlockJob = launch {
            repository.unlockVault(masterPassword)
        }
        testScheduler.advanceUntilIdle()
        unlockJob.join()
        assertTrue("Vault must be unlocked for sync", repository.sessionState.value.isUnlocked)

        val ioDispatchesBefore = trackingIo.dispatchCount.get()

        val syncJob = launch {
            repository.syncRecords()
        }
        testScheduler.advanceUntilIdle()
        syncJob.join()

        assertTrue(
            "Expected syncRecords to dispatch to ioDispatcher",
            trackingIo.dispatchCount.get() > ioDispatchesBefore
        )
    }

    @Test(timeout = 10_000)
    fun testAuthViewModelUnlockDeduplication(): Unit = runTest(testDispatcher) {
        val trackingDefault = TrackingDispatcher(testDispatcher)
        val trackingIo = TrackingDispatcher(testDispatcher)

        val vek = VaultCrypto.generateVaultKey()
        val masterPassword = "DeduplicationPassword123!"
        val (_, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        VaultCrypto.clearBytes(vek)

        keyStoreManager.lastAccountId = "acc-dedup"
        keyStoreManager.lastUsername = "dedupuser"
        keyStoreManager.lastWrappedVaultKey = json.encodeToString(envelope)
        keyStoreManager.saveSessionToken("valid-token")

        val authRepo = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null,
            ioDispatcher = trackingIo,
            defaultDispatcher = trackingDefault
        )

        val authViewModel = AuthViewModel(authRepo)
        authViewModel.onMasterPasswordChange(masterPassword)

        // Pause sync inside unlock
        val syncPause = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = syncPause

        var successCount = 0
        // Trigger first unlock
        authViewModel.unlockVault { successCount++ }
        testScheduler.runCurrent()

        // AuthViewModel should be loading while sync is paused
        assertTrue("AuthViewModel should be in loading state", authViewModel.uiState.value.isLoading)

        // Second duplicate click while loading must be ignored
        val defaultDispatchesBefore = trackingDefault.dispatchCount.get()
        authViewModel.unlockVault { successCount++ }
        testScheduler.runCurrent()

        // Dispatches must not increase for duplicate click
        assertEquals(defaultDispatchesBefore, trackingDefault.dispatchCount.get())

        // Resume sync and finish
        syncPause.complete(Unit)
        testScheduler.advanceUntilIdle()

        assertFalse("AuthViewModel should no longer be loading", authViewModel.uiState.value.isLoading)
        assertTrue("Vault should be unlocked", authRepo.sessionState.value.isUnlocked)
        assertEquals("Success callback should only be invoked once", 1, successCount)
    }

    @Test(timeout = 10_000)
    fun testVaultViewModelSyncDeduplication(): Unit = runTest(testDispatcher) {
        val trackingDefault = TrackingDispatcher(testDispatcher)
        val trackingIo = TrackingDispatcher(testDispatcher)

        val vek = VaultCrypto.generateVaultKey()
        val masterPassword = "SyncTestPassword123!"
        val (_, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        VaultCrypto.clearBytes(vek)

        keyStoreManager.lastAccountId = "acc-sync"
        keyStoreManager.lastUsername = "syncuser"
        keyStoreManager.lastWrappedVaultKey = json.encodeToString(envelope)
        keyStoreManager.saveSessionToken("valid-token")

        val repository = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null,
            ioDispatcher = trackingIo,
            defaultDispatcher = trackingDefault
        )
        val unlockJob = launch {
            repository.unlockVault(masterPassword)
        }
        testScheduler.advanceUntilIdle()
        unlockJob.join()
        assertTrue(repository.sessionState.value.isUnlocked)

        // Reset sync counter after unlock's sync
        fakeApi.syncCount.set(0)

        // Setup pause for ViewModel sync
        val syncPause = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = syncPause

        val vaultViewModel = VaultViewModel(repository, context)
        testScheduler.runCurrent()

        // Init triggers first sync and is now paused in fetchSync
        assertTrue(vaultViewModel.uiState.value.isSyncing)
        assertEquals(1, fakeApi.syncCount.get())

        // Duplicate sync invocation while already syncing must be ignored
        vaultViewModel.sync()
        testScheduler.runCurrent()
        assertEquals("Duplicate sync() should not trigger additional api call", 1, fakeApi.syncCount.get())

        // Release pause
        syncPause.complete(Unit)
        testScheduler.advanceUntilIdle()

        assertFalse(vaultViewModel.uiState.value.isSyncing)
        assertEquals(1, fakeApi.syncCount.get())
    }

    @Test(timeout = 10_000)
    fun testDecryptRecordSafelyReleasesKeyLockPromptly(): Unit = runBlocking {
        val repository = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null
        )

        // Setup unlocked repository
        val vek = VaultCrypto.generateVaultKey()
        val masterPassword = "TestKeyLock123!"
        val (_, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)

        keyStoreManager.lastAccountId = "acc-lock-test"
        keyStoreManager.lastUsername = "lockuser"
        keyStoreManager.lastWrappedVaultKey = json.encodeToString(envelope)
        keyStoreManager.saveSessionToken("valid-token")

        val repo = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null
        )
        repo.unlockVault(masterPassword)
        assertTrue(repo.sessionState.value.isUnlocked)

        // Multiple concurrent calls to onUserActivity and checkInactivityLock should succeed promptly
        val job1 = launch(Dispatchers.Default) {
            for (i in 0 until 100) {
                repo.onUserActivity()
                repo.checkInactivityLock()
            }
        }
        val job2 = launch(Dispatchers.Default) {
            for (i in 0 until 100) {
                repo.getItems()
            }
        }

        job1.join()
        job2.join()

        VaultCrypto.clearBytes(vek)
    }

    @Test(timeout = 10_000)
    fun testAuthViewModelUnlockCancellationResetsLoading(): Unit = runTest(testDispatcher) {
        val trackingDefault = TrackingDispatcher(testDispatcher)
        val trackingIo = TrackingDispatcher(testDispatcher)

        val vek = VaultCrypto.generateVaultKey()
        val masterPassword = "CancelTestPassword123!"
        val (_, envelope) = VaultCrypto.wrapVaultKey(vek, masterPassword)
        VaultCrypto.clearBytes(vek)

        keyStoreManager.lastAccountId = "acc-cancel"
        keyStoreManager.lastUsername = "canceluser"
        keyStoreManager.lastWrappedVaultKey = json.encodeToString(envelope)
        keyStoreManager.saveSessionToken("valid-token")

        val syncPause = CompletableDeferred<Unit>()
        fakeApi.syncPauseDeferred = syncPause

        val repo = VaultRepository(
            api = fakeApi,
            keyStoreManager = keyStoreManager,
            vaultCrypto = VaultCrypto,
            database = null,
            ioDispatcher = trackingIo,
            defaultDispatcher = trackingDefault
        )

        val viewModelStore = ViewModelStore()
        val factory = VaultViewModelFactory(repo) { context }
        val provider = ViewModelProvider(viewModelStore, factory)
        val vm = provider[AuthViewModel::class.java]

        vm.onMasterPasswordChange(masterPassword)
        vm.unlockVault {}
        testScheduler.runCurrent()

        assertTrue(vm.uiState.value.isLoading)

        // Clearing ViewModelStore cancels viewModelScope and aborts active job
        viewModelStore.clear()
        testScheduler.advanceUntilIdle()

        assertFalse("Cancelling ViewModelScope must reset isLoading state", vm.uiState.value.isLoading)
        syncPause.complete(Unit)
    }
}
