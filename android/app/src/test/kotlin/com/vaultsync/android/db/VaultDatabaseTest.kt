package com.vaultsync.android.db

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
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

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class VaultDatabaseTest {

    private lateinit var db: VaultDatabase
    private lateinit var recordDao: RecordDao
    private lateinit var syncStateDao: SyncStateDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, VaultDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        recordDao = db.recordDao()
        syncStateDao = db.syncStateDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun testInsertAndRetrieveEncryptedRecordEnvelope() = runBlocking {
        val payload = """{"version":1,"algorithm":"AES-256-GCM","record_id":"rec-1","nonce":"dGVzdG5vbmNlMTI=","ciphertext":"dGVzdGNpcGhlcnRleHQ="}"""
        val entity = EncryptedRecordEntity(
            accountId = "acc-100",
            recordId = "rec-1",
            revision = 2,
            syncCursor = 15,
            isDeleted = false,
            ciphertextPayload = payload,
            createdAt = "2026-10-18T10:00:00Z",
            updatedAt = "2026-10-18T10:05:00Z",
            isCorrupted = false,
            corruptionReason = null
        )

        recordDao.upsertRecord(entity)

        val retrieved = recordDao.getRecord("acc-100", "rec-1")
        assertNotNull(retrieved)
        assertEquals("acc-100", retrieved?.accountId)
        assertEquals("rec-1", retrieved?.recordId)
        assertEquals(2, retrieved?.revision)
        assertEquals(15, retrieved?.syncCursor)
        assertFalse(retrieved!!.isDeleted)
        assertEquals(payload, retrieved.ciphertextPayload)
        assertEquals("2026-10-18T10:00:00Z", retrieved.createdAt)
        assertEquals("2026-10-18T10:05:00Z", retrieved.updatedAt)
        assertFalse(retrieved.isCorrupted)
    }

    @Test
    fun testPersistedRecordValuesDoNotContainDecryptedPasswordFields() = runBlocking {
        val plaintextSecretPassword = "SuperSecretPlaintextPassword123!"
        val plainUsername = "bankuser"
        val plainTitle = "Bank Account"
        val plainNotes = "Secret PIN: 9876"

        // Encrypted envelope containing opaque ciphertext
        val encryptedEnvelopePayload = """{"version":1,"algorithm":"AES-256-GCM","record_id":"rec-security","nonce":"AAAA1111BBBB","ciphertext":"0000FFFFCCCC"}"""

        val entity = EncryptedRecordEntity(
            accountId = "acc-sec",
            recordId = "rec-security",
            revision = 1,
            syncCursor = 5,
            isDeleted = false,
            ciphertextPayload = encryptedEnvelopePayload,
            createdAt = "2026-10-18T10:00:00Z",
            updatedAt = "2026-10-18T10:00:00Z"
        )
        recordDao.upsertRecord(entity)

        val persisted = recordDao.getRecord("acc-sec", "rec-security")!!

        // Invariant: database entity columns must NEVER contain plaintext secret fields
        assertFalse(persisted.ciphertextPayload.contains(plaintextSecretPassword))
        assertFalse(persisted.ciphertextPayload.contains(plainUsername))
        assertFalse(persisted.ciphertextPayload.contains(plainTitle))
        assertFalse(persisted.ciphertextPayload.contains(plainNotes))
    }

    @Test
    fun testTombstonePersistenceAndQueryFiltering() = runBlocking {
        val entity1 = EncryptedRecordEntity(
            accountId = "acc-tomb",
            recordId = "rec-live",
            revision = 1,
            syncCursor = 1,
            isDeleted = false,
            ciphertextPayload = "payload-1"
        )
        val entity2 = EncryptedRecordEntity(
            accountId = "acc-tomb",
            recordId = "rec-dead",
            revision = 2,
            syncCursor = 2,
            isDeleted = false,
            ciphertextPayload = "payload-2"
        )
        recordDao.upsertRecords(listOf(entity1, entity2))

        assertEquals(2, recordDao.getActiveRecords("acc-tomb").size)

        // Mark rec-dead as tombstone
        recordDao.markDeleted("acc-tomb", "rec-dead", "2026-10-18T10:10:00Z")

        val activeRecords = recordDao.getActiveRecords("acc-tomb")
        assertEquals(1, activeRecords.size)
        assertEquals("rec-live", activeRecords[0].recordId)

        // All records still contain the tombstone with cleared payload
        val allRecords = recordDao.getAllRecords("acc-tomb")
        assertEquals(2, allRecords.size)
        val dead = allRecords.first { it.recordId == "rec-dead" }
        assertTrue(dead.isDeleted)
        assertEquals("", dead.ciphertextPayload)
    }

    @Test
    fun testReplaceAccountRecords() = runBlocking {
        val oldRecords = listOf(
            EncryptedRecordEntity("acc-replace", "old-1", 1, 1, false, "old-p1"),
            EncryptedRecordEntity("acc-replace", "old-2", 1, 2, false, "old-p2")
        )
        recordDao.upsertRecords(oldRecords)
        assertEquals(2, recordDao.getActiveRecords("acc-replace").size)

        val newRecords = listOf(
            EncryptedRecordEntity("acc-replace", "new-1", 1, 3, false, "new-p1"),
            EncryptedRecordEntity("acc-replace", "new-2", 1, 4, false, "new-p2"),
            EncryptedRecordEntity("acc-replace", "new-3", 1, 5, false, "new-p3")
        )
        recordDao.replaceAccountRecords("acc-replace", newRecords)

        val active = recordDao.getActiveRecords("acc-replace")
        assertEquals(3, active.size)
        assertTrue(active.none { it.recordId.startsWith("old") })
        assertTrue(active.all { it.recordId.startsWith("new") })
    }

    @Test
    fun testCursorPersistenceAndMonotonicProgression() = runBlocking {
        assertNull(syncStateDao.getSyncState("acc-cursor"))

        syncStateDao.setSyncState(SyncStateEntity("acc-cursor", lastSyncCursor = 10, lastSyncedAt = 1000L))
        val state1 = syncStateDao.getSyncState("acc-cursor")
        assertNotNull(state1)
        assertEquals(10, state1?.lastSyncCursor)

        syncStateDao.setSyncState(SyncStateEntity("acc-cursor", lastSyncCursor = 25, lastSyncedAt = 2000L))
        val state2 = syncStateDao.getSyncState("acc-cursor")
        assertEquals(25, state2?.lastSyncCursor)
        assertEquals(2000L, state2?.lastSyncedAt)
    }

    @Test
    fun testMultiAccountIsolationInDatabase() = runBlocking {
        val accountARecord = EncryptedRecordEntity("user-A", "item-shared-id", 1, 1, false, "A-payload")
        val accountBRecord = EncryptedRecordEntity("user-B", "item-shared-id", 1, 1, false, "B-payload")

        recordDao.upsertRecord(accountARecord)
        recordDao.upsertRecord(accountBRecord)

        val userAActive = recordDao.getActiveRecords("user-A")
        assertEquals(1, userAActive.size)
        assertEquals("A-payload", userAActive[0].ciphertextPayload)

        val userBActive = recordDao.getActiveRecords("user-B")
        assertEquals(1, userBActive.size)
        assertEquals("B-payload", userBActive[0].ciphertextPayload)

        val nonExistentUser = recordDao.getActiveRecords("user-C")
        assertEquals(0, nonExistentUser.size)
    }

    @Test
    fun testCorruptedRecordEnvelopeFlagging() = runBlocking {
        val corruptedEntity = EncryptedRecordEntity(
            accountId = "acc-corrupt",
            recordId = "rec-bad",
            revision = 1,
            syncCursor = 12,
            isDeleted = false,
            ciphertextPayload = "corrupted-payload",
            isCorrupted = true,
            corruptionReason = "AEADBadTagException: tag mismatch"
        )
        recordDao.upsertRecord(corruptedEntity)

        val loaded = recordDao.getRecord("acc-corrupt", "rec-bad")
        assertNotNull(loaded)
        assertTrue(loaded!!.isCorrupted)
        assertEquals("AEADBadTagException: tag mismatch", loaded.corruptionReason)
    }
}
