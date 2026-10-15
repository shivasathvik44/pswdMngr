package com.vaultsync.android.repository

import com.vaultsync.android.api.ApiClient
import com.vaultsync.android.api.AuthenticationException
import com.vaultsync.android.api.ChangePasswordRequest
import com.vaultsync.android.api.CreateRecordRequest
import com.vaultsync.android.api.HealthResponse
import com.vaultsync.android.api.LoginRequest
import com.vaultsync.android.api.RegisterRequest
import com.vaultsync.android.api.UpdateRecordRequest
import com.vaultsync.android.api.UpdateVaultKeyRequest
import com.vaultsync.android.crypto.KeyStoreManager
import com.vaultsync.android.crypto.RecordEnvelope
import com.vaultsync.android.crypto.VaultCrypto
import com.vaultsync.android.crypto.WrappedKeyEnvelope
import com.vaultsync.android.model.SessionState
import com.vaultsync.android.model.VaultItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.Base64
import java.util.Collections

/**
 * Central repository managing authentication, client-side encryption,
 * in-memory vault records, synchronization, and auto-lock state.
 *
 * Implements strict lock/logout race safety, structured concurrency,
 * generation fencing, and failure-safe atomic full resynchronization.
 */
class VaultRepository(
    val api: ApiClient,
    val keyStoreManager: KeyStoreManager,
    val vaultCrypto: VaultCrypto = VaultCrypto
) {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    // Mutex serializes state-modifying operations (sync, CRUD, resync, rotation)
    private val mutex = Mutex()

    // Key lock protects atomic reads and zeroization of in-memory VEK
    private val keyLock = Any()

    // In-memory sensitive state (purged upon lock or logout)
    private var _vaultKey: ByteArray? = null
    private val _itemsMap = mutableMapOf<String, VaultItem>()
    private val _corruptedRecords = mutableMapOf<String, String>()
    private val _itemsFlow = MutableStateFlow<List<VaultItem>>(emptyList())
    val items: StateFlow<List<VaultItem>> = _itemsFlow.asStateFlow()

    val corruptedRecords: Map<String, String>
        get() = synchronized(keyLock) { Collections.unmodifiableMap(HashMap(_corruptedRecords)) }

    var syncCursor: Int = 0
        private set

    // Generation counters: incremented monotonically to fence out stale async operations
    var lockGeneration: Long = 0
        private set
    var sessionGeneration: Long = 0
        private set

    var username: String = ""
        private set
    var accountId: String = ""
        private set
    var wrappedVaultKey: String? = null
        private set
    var kdfSalt: String? = null
        private set

    var lastActivityTime: Long = System.currentTimeMillis()
        private set

    private val _sessionState = MutableStateFlow(
        SessionState(
            serverUrl = api.baseUrl,
            username = keyStoreManager.lastUsername,
            autoLockMinutes = keyStoreManager.autoLockMinutes
        )
    )
    val sessionState: StateFlow<SessionState> = _sessionState.asStateFlow()

    init {
        val storedToken = keyStoreManager.getSessionToken()
        if (!storedToken.isNullOrBlank()) {
            api.sessionToken = storedToken
            username = keyStoreManager.lastUsername
            _sessionState.update {
                it.copy(
                    username = username,
                    isAuthenticated = true
                )
            }
        }
    }

    // ------------------------------------------------------------------------
    // Fencing & State Validation
    // ------------------------------------------------------------------------

    /**
     * Verify whether an operation is still valid within its captured generation context.
     * Prevents stale coroutines from reading keys or publishing results after lock/logout.
     */
    fun isOperationValid(capturedLockGen: Long, capturedSessionGen: Long): Boolean {
        synchronized(keyLock) {
            return lockGeneration == capturedLockGen &&
                sessionGeneration == capturedSessionGen &&
                _sessionState.value.isUnlocked &&
                _vaultKey != null
        }
    }

    /**
     * Safely decrypt a record envelope under keyLock protection.
     * Guarantees that key material cannot be zeroized while actively decrypting.
     */
    private fun decryptRecordSafely(
        capturedLockGen: Long,
        capturedSessionGen: Long,
        env: RecordEnvelope
    ): String? {
        synchronized(keyLock) {
            if (lockGeneration != capturedLockGen ||
                sessionGeneration != capturedSessionGen ||
                _vaultKey == null ||
                !_sessionState.value.isUnlocked
            ) {
                return null
            }
            return VaultCrypto.decryptRecord(_vaultKey!!, env)
        }
    }

    /**
     * Safely encrypt a record under keyLock protection.
     */
    private fun encryptRecordSafely(
        capturedLockGen: Long,
        capturedSessionGen: Long,
        recordId: String,
        plaintextJson: String
    ): RecordEnvelope? {
        synchronized(keyLock) {
            if (lockGeneration != capturedLockGen ||
                sessionGeneration != capturedSessionGen ||
                _vaultKey == null ||
                !_sessionState.value.isUnlocked
            ) {
                return null
            }
            return VaultCrypto.encryptRecord(_vaultKey!!, recordId, plaintextJson)
        }
    }

    // ------------------------------------------------------------------------
    // Activity & Preferences
    // ------------------------------------------------------------------------

    fun onUserActivity() {
        lastActivityTime = System.currentTimeMillis()
    }

    fun registerActivity() = onUserActivity()

    fun checkInactivityLock(): Boolean {
        synchronized(keyLock) {
            if (!_sessionState.value.isUnlocked || _vaultKey == null) return false
        }
        val timeoutMinutes = keyStoreManager.autoLockMinutes
        if (timeoutMinutes <= 0) return false
        val elapsedMillis = System.currentTimeMillis() - lastActivityTime
        if (elapsedMillis >= timeoutMinutes * 60 * 1000L) {
            lock()
            return true
        }
        return false
    }

    fun checkInactivity(): Boolean = checkInactivityLock()

    fun getServerUrl(): String = keyStoreManager.serverUrl

    fun setServerUrl(url: String) {
        ApiClient.validateBaseUrl(url)
        api.baseUrl = url
        keyStoreManager.serverUrl = url
        _sessionState.update { it.copy(serverUrl = url) }
    }

    fun updateServerUrl(url: String) = setServerUrl(url)

    fun getAutoLockTimeoutMinutes(): Int = keyStoreManager.autoLockMinutes

    fun setAutoLockTimeoutMinutes(minutes: Int) {
        keyStoreManager.autoLockMinutes = minutes
        _sessionState.update { it.copy(autoLockMinutes = minutes) }
    }

    fun getClipboardTimeoutSeconds(): Int = keyStoreManager.clipboardClearSeconds

    fun setClipboardTimeoutSeconds(seconds: Int) {
        keyStoreManager.clipboardClearSeconds = seconds
    }

    suspend fun checkHealth(): HealthResponse {
        return api.checkHealth()
    }

    // ------------------------------------------------------------------------
    // Lock / Logout Lifecycle
    // ------------------------------------------------------------------------

    /**
     * Synchronously and immediately locks the vault.
     *
     * Invariant guarantees:
     * 1. Acquires keyLock to prevent key clearing during active AES operations.
     * 2. Increments lockGeneration to invalidate all in-flight sync/decrypt operations.
     * 3. Zeroizes and clears _vaultKey memory immediately.
     * 4. Purges all in-memory decrypted items and emits an empty list to subscribers.
     * 5. Never calls mutex.unlock() without holding the mutex.
     * 6. Idempotent and thread-safe for repeated invocations.
     */
    fun lock() {
        val currentLockGen: Long
        synchronized(keyLock) {
            lockGeneration++
            currentLockGen = lockGeneration
            VaultCrypto.clearBytes(_vaultKey)
            _vaultKey = null
            _itemsMap.clear()
            _corruptedRecords.clear()
            _itemsFlow.value = emptyList()
            syncCursor = 0
        }

        _sessionState.update {
            it.copy(
                isUnlocked = false,
                lockGeneration = currentLockGen.toInt(),
                itemCount = 0,
                corruptedRecordCount = 0,
                syncStatusMessage = "Locked"
            )
        }
    }

    private fun handleAuthFailure() {
        synchronized(keyLock) {
            sessionGeneration++
        }
        lock()
        api.sessionToken = null
        keyStoreManager.clearSessionToken()
        _sessionState.update {
            it.copy(
                isAuthenticated = false,
                isUnlocked = false,
                warningMessage = "Your session has expired or was revoked. Please log in again."
            )
        }
    }

    /**
     * Terminates the current session and purges all credentials.
     *
     * Increments sessionGeneration to fence out any lingering network responses.
     */
    suspend fun logout() {
        synchronized(keyLock) {
            sessionGeneration++
        }
        try {
            if (_sessionState.value.isAuthenticated) {
                api.logout()
            }
        } catch (_: Exception) {
            // Best effort network revocation
        } finally {
            keyStoreManager.clearSessionToken()
            api.sessionToken = null
            username = ""
            accountId = ""
            wrappedVaultKey = null
            kdfSalt = null
            lock()
            _sessionState.update {
                it.copy(
                    isAuthenticated = false,
                    isUnlocked = false,
                    username = "",
                    accountId = "",
                    itemCount = 0,
                    corruptedRecordCount = 0
                )
            }
        }
    }

    // ------------------------------------------------------------------------
    // Registration, Login & Unlock
    // ------------------------------------------------------------------------

    suspend fun register(usernameInput: String, accountPasswordInput: String, vaultMasterPasswordInput: CharArray) {
        registerAccount(usernameInput, accountPasswordInput, String(vaultMasterPasswordInput))
    }

    suspend fun registerAccount(usernameInput: String, accountPasswordInput: String, vaultMasterPasswordInput: String) {
        synchronized(keyLock) {
            sessionGeneration++
        }
        val cleanUser = usernameInput.trim()
        val vek = VaultCrypto.generateVaultKey()
        try {
            val (saltBytes, envelope) = VaultCrypto.wrapVaultKey(vek, vaultMasterPasswordInput)
            val saltBase64 = Base64.getEncoder().encodeToString(saltBytes)
            val envelopeJson = json.encodeToString(envelope)

            val req = RegisterRequest(
                username = cleanUser,
                accountPassword = accountPasswordInput,
                kdfSalt = saltBase64,
                wrappedVaultKey = envelopeJson
            )
            api.register(req)
        } finally {
            VaultCrypto.clearBytes(vek)
        }
    }

    suspend fun login(usernameInput: String, accountPasswordInput: String, deviceName: String = "Android Client") {
        loginAccount(usernameInput, accountPasswordInput, deviceName)
    }

    suspend fun loginAccount(usernameInput: String, accountPasswordInput: String, deviceName: String = "Android Client") {
        val capturedSessionGen: Long
        synchronized(keyLock) {
            sessionGeneration++
            capturedSessionGen = sessionGeneration
        }
        val cleanUser = usernameInput.trim()
        val req = LoginRequest(
            username = cleanUser,
            accountPassword = accountPasswordInput,
            deviceName = deviceName
        )
        val res = api.login(req)

        synchronized(keyLock) {
            if (sessionGeneration != capturedSessionGen) {
                throw IllegalStateException("Session invalidated during login")
            }
            username = cleanUser
            accountId = res.accountId
            wrappedVaultKey = res.wrappedVaultKey
            kdfSalt = res.kdfSalt
        }

        keyStoreManager.saveSessionToken(res.sessionToken)
        keyStoreManager.lastUsername = cleanUser

        _sessionState.update {
            if (sessionGeneration != capturedSessionGen) return@update it
            it.copy(
                username = cleanUser,
                accountId = res.accountId,
                isAuthenticated = true,
                isUnlocked = false,
                errorMessage = null,
                warningMessage = null
            )
        }
    }

    suspend fun unlock(vaultMasterPasswordInput: CharArray) {
        unlockVault(String(vaultMasterPasswordInput))
    }

    suspend fun unlockVault(vaultMasterPasswordInput: String) {
        val envelopeString = wrappedVaultKey
            ?: throw IllegalStateException("No wrapped vault key available for this account")

        val envelope = json.decodeFromString<WrappedKeyEnvelope>(envelopeString)
        val vek = VaultCrypto.unwrapVaultKey(envelope, vaultMasterPasswordInput)

        synchronized(keyLock) {
            lockGeneration++
            _vaultKey = vek
        }
        onUserActivity()

        _sessionState.update {
            it.copy(
                isUnlocked = true,
                errorMessage = null
            )
        }

        syncRecords()
    }

    // ------------------------------------------------------------------------
    // Synchronization & Atomic Resync
    // ------------------------------------------------------------------------

    suspend fun sync() = syncRecords()

    /**
     * Failure-Safe Full Resynchronization.
     *
     * Invariants guaranteed:
     * 1. Preserves existing in-memory vault view completely until replacement state
     *    is fully fetched, decrypted, and validated.
     * 2. If network fails or pagination is aborted, existing view remains untouched.
     * 3. Paginates starting from cursor 0 through entire server history.
     * 4. Does not resurrect deleted records (tombstones remove records from staging).
     * 5. If undecryptable/corrupted records exist, records their identifiers in
     *    warningMessage without logging sensitive plaintext or keys.
     * 6. Does not advance syncCursor past failed records, preventing permanent data loss.
     * 7. Publishes replacement state atomically to _itemsMap and _itemsFlow.
     */
    suspend fun forceFullResync() = mutex.withLock {
        val gen: Long
        val sessionGen: Long
        synchronized(keyLock) {
            gen = lockGeneration
            sessionGen = sessionGeneration
            if (!_sessionState.value.isUnlocked || _vaultKey == null) {
                return@withLock
            }
        }

        _sessionState.update { it.copy(isSyncing = true, syncStatusMessage = "Full Resyncing...") }

        // Staging buffers - existing items are NOT cleared until replacement is validated
        val stagingItems = mutableMapOf<String, VaultItem>()
        val stagingCorrupted = mutableMapOf<String, String>()
        var currentCursor = 0
        var highestValidCursor = 0
        var hasEncounteredCorruption = false
        val visitedCursors = mutableSetOf<Int>()

        try {
            while (true) {
                if (!visitedCursors.add(currentCursor)) {
                    break
                }

                val syncData = try {
                    api.fetchSync(sinceCursor = currentCursor, limit = 100)
                } catch (e: AuthenticationException) {
                    handleAuthFailure()
                    throw e
                }

                if (!isOperationValid(gen, sessionGen)) {
                    return@withLock
                }

                for (rec in syncData.items) {
                    if (!isOperationValid(gen, sessionGen)) return@withLock

                    if (rec.isDeleted) {
                        stagingItems.remove(rec.recordId)
                        stagingCorrupted.remove(rec.recordId)
                        if (!hasEncounteredCorruption) {
                            highestValidCursor = maxOf(highestValidCursor, rec.syncCursor)
                        }
                    } else if (rec.ciphertextPayload.isNotBlank()) {
                        try {
                            val env = json.decodeFromString<RecordEnvelope>(rec.ciphertextPayload)
                            if (env.recordId == rec.recordId) {
                                val plaintext = decryptRecordSafely(gen, sessionGen, env)
                                if (plaintext != null) {
                                    val item = VaultItem.fromSecretJson(
                                        recordId = rec.recordId,
                                        revision = rec.revision,
                                        secretJson = plaintext
                                    )
                                    stagingItems[rec.recordId] = item
                                    stagingCorrupted.remove(rec.recordId)
                                    if (!hasEncounteredCorruption) {
                                        highestValidCursor = maxOf(highestValidCursor, rec.syncCursor)
                                    }
                                } else {
                                    // Lock occurred during decryption
                                    return@withLock
                                }
                            } else {
                                stagingCorrupted[rec.recordId] = "Mismatched envelope record_id: ${env.recordId}"
                                hasEncounteredCorruption = true
                            }
                        } catch (e: Exception) {
                            // Record affected identifier safely without leaking plaintext or keys
                            stagingCorrupted[rec.recordId] = e.message ?: "Decryption failed"
                            hasEncounteredCorruption = true
                        }
                    } else {
                        if (!hasEncounteredCorruption) {
                            highestValidCursor = maxOf(highestValidCursor, rec.syncCursor)
                        }
                    }
                }

                val next = syncData.nextCursor
                if (next <= currentCursor && syncData.items.isNotEmpty()) {
                    val maxItemCursor = syncData.items.maxOfOrNull { it.syncCursor } ?: currentCursor
                    currentCursor = if (maxItemCursor > currentCursor) maxItemCursor else break
                } else {
                    currentCursor = next
                }

                if (!hasEncounteredCorruption && stagingCorrupted.isEmpty()) {
                    highestValidCursor = currentCursor
                }

                if (!syncData.hasMore || syncData.items.isEmpty()) {
                    break
                }
            }

            // Final generation check before atomic publication
            synchronized(keyLock) {
                if (lockGeneration != gen || sessionGeneration != sessionGen || !_sessionState.value.isUnlocked) {
                    return@withLock
                }

                val corruptedCount = stagingCorrupted.size
                if (corruptedCount == 0) {
                    _itemsMap.clear()
                    _itemsMap.putAll(stagingItems)
                    _corruptedRecords.clear()
                    syncCursor = currentCursor
                    _itemsFlow.value = _itemsMap.values.filter { !it.isDeleted }.toList()
                } else {
                    val safeCursor = highestValidCursor
                    _itemsMap.clear()
                    _itemsMap.putAll(stagingItems)
                    _corruptedRecords.clear()
                    _corruptedRecords.putAll(stagingCorrupted)
                    syncCursor = safeCursor
                    _itemsFlow.value = _itemsMap.values.filter { !it.isDeleted }.toList()
                }
            }

            val corruptedCount = stagingCorrupted.size
            if (corruptedCount == 0) {
                _sessionState.update {
                    if (!isOperationValid(gen, sessionGen)) return@update it
                    it.copy(
                        isSyncing = false,
                        itemCount = stagingItems.size,
                        corruptedRecordCount = 0,
                        syncStatusMessage = "✓ Synced (${stagingItems.size} items)",
                        warningMessage = null,
                        errorMessage = null
                    )
                }
            } else {
                val affectedIds = stagingCorrupted.keys.joinToString(", ")
                _sessionState.update {
                    if (!isOperationValid(gen, sessionGen)) return@update it
                    it.copy(
                        isSyncing = false,
                        itemCount = stagingItems.size,
                        corruptedRecordCount = corruptedCount,
                        syncStatusMessage = "⚠ Resync incomplete: $corruptedCount record(s) failed",
                        warningMessage = "Resync incomplete: Record(s) [$affectedIds] failed decryption. Cursor not advanced past failed records.",
                        errorMessage = null
                    )
                }
            }
        } catch (e: Exception) {
            _sessionState.update {
                if (!isOperationValid(gen, sessionGen)) return@update it
                it.copy(
                    isSyncing = false,
                    syncStatusMessage = "Resync failed",
                    errorMessage = "Full resync failed: ${e.message}. Existing vault items preserved."
                )
            }
            if (e is AuthenticationException) throw e
        }
    }

    suspend fun syncRecords() = mutex.withLock {
        syncRecordsInternal()
    }

    private suspend fun syncRecordsInternal() {
        val gen: Long
        val sessionGen: Long
        synchronized(keyLock) {
            gen = lockGeneration
            sessionGen = sessionGeneration
            if (!_sessionState.value.isUnlocked || _vaultKey == null) {
                return
            }
        }

        _sessionState.update { it.copy(isSyncing = true, syncStatusMessage = "Syncing...") }

        // Staging buffers for atomic incremental update
        val stagingItems = synchronized(keyLock) { HashMap(_itemsMap) }
        val stagingCorrupted = synchronized(keyLock) { HashMap(_corruptedRecords) }
        var currentCursor = synchronized(keyLock) { syncCursor }
        val visitedCursors = mutableSetOf<Int>()

        try {
            while (true) {
                if (!visitedCursors.add(currentCursor)) {
                    break
                }

                val syncData = try {
                    api.fetchSync(sinceCursor = currentCursor, limit = 100)
                } catch (e: AuthenticationException) {
                    handleAuthFailure()
                    throw e
                }

                if (!isOperationValid(gen, sessionGen)) {
                    return
                }

                for (rec in syncData.items) {
                    if (!isOperationValid(gen, sessionGen)) return

                    if (rec.isDeleted) {
                        stagingItems.remove(rec.recordId)
                        stagingCorrupted.remove(rec.recordId)
                    } else if (rec.ciphertextPayload.isNotBlank()) {
                        try {
                            val env = json.decodeFromString<RecordEnvelope>(rec.ciphertextPayload)
                            if (env.recordId == rec.recordId) {
                                val plaintext = decryptRecordSafely(gen, sessionGen, env)
                                if (plaintext != null) {
                                    val item = VaultItem.fromSecretJson(
                                        recordId = rec.recordId,
                                        revision = rec.revision,
                                        secretJson = plaintext
                                    )
                                    stagingItems[rec.recordId] = item
                                    stagingCorrupted.remove(rec.recordId)
                                } else {
                                    return
                                }
                            } else {
                                stagingCorrupted[rec.recordId] = "Mismatched envelope record_id: ${env.recordId}"
                            }
                        } catch (e: Exception) {
                            stagingCorrupted[rec.recordId] = e.message ?: "Decryption failed"
                        }
                    }
                }

                val next = syncData.nextCursor
                if (next <= currentCursor && syncData.items.isNotEmpty()) {
                    val maxItemCursor = syncData.items.maxOfOrNull { it.syncCursor } ?: currentCursor
                    currentCursor = if (maxItemCursor > currentCursor) maxItemCursor else break
                } else {
                    currentCursor = next
                }

                if (!syncData.hasMore || syncData.items.isEmpty()) {
                    break
                }
            }

            synchronized(keyLock) {
                if (lockGeneration != gen || sessionGeneration != sessionGen || !_sessionState.value.isUnlocked) {
                    return
                }
                _itemsMap.clear()
                _itemsMap.putAll(stagingItems)
                _corruptedRecords.clear()
                _corruptedRecords.putAll(stagingCorrupted)
                syncCursor = currentCursor
                _itemsFlow.value = _itemsMap.values.filter { !it.isDeleted }.toList()
            }

            val corruptedCount = stagingCorrupted.size
            val statusMsg = if (corruptedCount > 0) {
                "⚠ Synced with $corruptedCount corrupted item(s)"
            } else {
                "✓ Synced (${stagingItems.size} items)"
            }

            val warningMsg = if (corruptedCount > 0) {
                val affectedIds = stagingCorrupted.keys.joinToString(", ")
                "Warning: $corruptedCount record(s) [$affectedIds] could not be decrypted. Use 'Full Resync' or check master key."
            } else null

            _sessionState.update {
                if (!isOperationValid(gen, sessionGen)) return@update it
                it.copy(
                    isSyncing = false,
                    itemCount = stagingItems.size,
                    corruptedRecordCount = corruptedCount,
                    syncStatusMessage = statusMsg,
                    warningMessage = warningMsg,
                    errorMessage = null
                )
            }
        } catch (e: Exception) {
            _sessionState.update {
                if (!isOperationValid(gen, sessionGen)) return@update it
                it.copy(
                    isSyncing = false,
                    syncStatusMessage = "Sync failed"
                )
            }
            if (e is AuthenticationException) throw e
        }
    }

    fun getItems(query: String = ""): List<VaultItem> {
        val q = query.trim().lowercase()
        return synchronized(keyLock) {
            _itemsMap.values.filter { !it.isDeleted }.filter { item ->
                if (q.isBlank()) true
                else item.title.lowercase().contains(q) ||
                    item.username.lowercase().contains(q) ||
                    item.url.lowercase().contains(q)
            }.sortedBy { it.title.lowercase() }
        }
    }

    fun getItem(id: String): VaultItem? {
        return synchronized(keyLock) {
            _itemsMap[id]?.takeIf { !it.isDeleted }
        }
    }

    suspend fun saveItem(item: VaultItem): VaultItem = mutex.withLock {
        val gen: Long
        val sessionGen: Long
        synchronized(keyLock) {
            gen = lockGeneration
            sessionGen = sessionGeneration
            if (!_sessionState.value.isUnlocked || _vaultKey == null) {
                throw IllegalStateException("Vault must be unlocked to save records")
            }
        }

        onUserActivity()
        val plaintextJson = item.toSecretJson()
        val env = encryptRecordSafely(gen, sessionGen, item.id, plaintextJson)
            ?: throw IllegalStateException("Operation invalidated: vault was locked while encrypting")
        val envelopeJson = json.encodeToString(env)

        val isNew = synchronized(keyLock) { !_itemsMap.containsKey(item.id) }
        val res = try {
            if (isNew) {
                api.createRecord(CreateRecordRequest(recordId = item.id, ciphertextPayload = envelopeJson))
            } else {
                api.updateRecord(item.id, UpdateRecordRequest(expectedRevision = item.revision, ciphertextPayload = envelopeJson))
            }
        } catch (e: AuthenticationException) {
            handleAuthFailure()
            throw e
        }

        val updatedItem = item.copy(
            revision = res.revision,
            createdAt = res.createdAt ?: item.createdAt,
            updatedAt = res.updatedAt ?: item.updatedAt
        )

        synchronized(keyLock) {
            if (lockGeneration != gen || sessionGeneration != sessionGen || !_sessionState.value.isUnlocked) {
                throw IllegalStateException("Operation invalidated: session or lock generation changed")
            }
            _itemsMap[item.id] = updatedItem
            _itemsFlow.value = _itemsMap.values.filter { !it.isDeleted }.toList()
        }

        _sessionState.update {
            if (!isOperationValid(gen, sessionGen)) return@update it
            it.copy(itemCount = _itemsMap.size)
        }
        return@withLock updatedItem
    }

    suspend fun deleteItem(itemId: String) = mutex.withLock {
        val gen: Long
        val sessionGen: Long
        val existing: VaultItem
        synchronized(keyLock) {
            gen = lockGeneration
            sessionGen = sessionGeneration
            if (!_sessionState.value.isUnlocked) {
                throw IllegalStateException("Vault must be unlocked to delete records")
            }
            existing = _itemsMap[itemId] ?: throw NoSuchElementException("Item not found: $itemId")
        }

        onUserActivity()

        try {
            api.deleteRecord(itemId, existing.revision)
        } catch (e: AuthenticationException) {
            handleAuthFailure()
            throw e
        }

        synchronized(keyLock) {
            if (lockGeneration != gen || sessionGeneration != sessionGen || !_sessionState.value.isUnlocked) {
                throw IllegalStateException("Operation invalidated: session or lock generation changed")
            }
            _itemsMap.remove(itemId)
            _itemsFlow.value = _itemsMap.values.filter { !it.isDeleted }.toList()
        }
        _sessionState.update {
            if (!isOperationValid(gen, sessionGen)) return@update it
            it.copy(itemCount = _itemsMap.size)
        }
    }

    // ------------------------------------------------------------------------
    // Credentials & Password Rotation
    // ------------------------------------------------------------------------

    suspend fun changeAccountPassword(currentPass: String, newPass: String) {
        val req = ChangePasswordRequest(currentPassword = currentPass, newPassword = newPass)
        api.changeAccountPassword(req)
    }

    suspend fun rotateMasterPassword(currentMaster: CharArray, newMaster: CharArray) {
        rotateMasterPassword(String(newMaster))
    }

    suspend fun rotateMasterPassword(newMasterPassword: String) = mutex.withLock {
        val gen: Long
        val sessionGen: Long
        val currentVek: ByteArray
        synchronized(keyLock) {
            gen = lockGeneration
            sessionGen = sessionGeneration
            if (!_sessionState.value.isUnlocked || _vaultKey == null) {
                throw IllegalStateException("Vault must be unlocked to rotate master password")
            }
            currentVek = _vaultKey!!.clone()
        }

        try {
            val (newSaltBytes, newEnvelope) = VaultCrypto.wrapVaultKey(currentVek, newMasterPassword)
            val newSaltBase64 = Base64.getEncoder().encodeToString(newSaltBytes)
            val newEnvelopeJson = json.encodeToString(newEnvelope)

            synchronized(keyLock) {
                if (lockGeneration != gen || sessionGeneration != sessionGen || !_sessionState.value.isUnlocked) {
                    throw IllegalStateException("Operation invalidated: vault was locked during key wrapping")
                }
            }

            try {
                api.updateVaultKey(UpdateVaultKeyRequest(wrappedVaultKey = newEnvelopeJson, kdfSalt = newSaltBase64))
            } catch (e: AuthenticationException) {
                handleAuthFailure()
                throw e
            }

            synchronized(keyLock) {
                if (lockGeneration != gen || sessionGeneration != sessionGen || !_sessionState.value.isUnlocked) {
                    throw IllegalStateException("Operation invalidated: session changed during vault key update")
                }
                wrappedVaultKey = newEnvelopeJson
                kdfSalt = newSaltBase64
            }
        } finally {
            VaultCrypto.clearBytes(currentVek)
        }
    }
}
