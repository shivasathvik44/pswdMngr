package com.vaultsync.android.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction

@Dao
abstract class RecordDao {

    @Query("SELECT * FROM encrypted_records WHERE account_id = :accountId AND is_deleted = 0")
    abstract suspend fun getActiveRecords(accountId: String): List<EncryptedRecordEntity>

    @Query("SELECT * FROM encrypted_records WHERE account_id = :accountId")
    abstract suspend fun getAllRecords(accountId: String): List<EncryptedRecordEntity>

    @Query("SELECT * FROM encrypted_records WHERE account_id = :accountId AND record_id = :recordId LIMIT 1")
    abstract suspend fun getRecord(accountId: String, recordId: String): EncryptedRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun upsertRecord(record: EncryptedRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun upsertRecords(records: List<EncryptedRecordEntity>)

    @Query("UPDATE encrypted_records SET is_deleted = 1, ciphertext_payload = '', updated_at = :updatedAt WHERE account_id = :accountId AND record_id = :recordId")
    abstract suspend fun markDeleted(accountId: String, recordId: String, updatedAt: String?)

    @Query("DELETE FROM encrypted_records WHERE account_id = :accountId AND record_id = :recordId")
    abstract suspend fun deleteRecord(accountId: String, recordId: String)

    @Query("DELETE FROM encrypted_records WHERE account_id = :accountId")
    abstract suspend fun clearAccountRecords(accountId: String)

    @Query("DELETE FROM encrypted_records")
    abstract suspend fun deleteAll()

    @Transaction
    open suspend fun replaceAccountRecords(accountId: String, records: List<EncryptedRecordEntity>) {
        clearAccountRecords(accountId)
        if (records.isNotEmpty()) {
            upsertRecords(records)
        }
    }
}
