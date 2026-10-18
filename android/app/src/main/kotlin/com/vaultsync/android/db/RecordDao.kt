package com.vaultsync.android.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction

@Dao
interface RecordDao {

    @Query("SELECT * FROM encrypted_records WHERE account_id = :accountId AND is_deleted = 0")
    suspend fun getActiveRecords(accountId: String): List<EncryptedRecordEntity>

    @Query("SELECT * FROM encrypted_records WHERE account_id = :accountId")
    suspend fun getAllRecords(accountId: String): List<EncryptedRecordEntity>

    @Query("SELECT * FROM encrypted_records WHERE account_id = :accountId AND record_id = :recordId LIMIT 1")
    suspend fun getRecord(accountId: String, recordId: String): EncryptedRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRecord(record: EncryptedRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRecords(records: List<EncryptedRecordEntity>)

    @Query("UPDATE encrypted_records SET is_deleted = 1, ciphertext_payload = '', updated_at = :updatedAt WHERE account_id = :accountId AND record_id = :recordId")
    suspend fun markDeleted(accountId: String, recordId: String, updatedAt: String?)

    @Query("DELETE FROM encrypted_records WHERE account_id = :accountId AND record_id = :recordId")
    suspend fun deleteRecord(accountId: String, recordId: String)

    @Query("DELETE FROM encrypted_records WHERE account_id = :accountId")
    suspend fun clearAccountRecords(accountId: String)

    @Query("DELETE FROM encrypted_records")
    suspend fun deleteAll()

    @Transaction
    suspend fun replaceAccountRecords(accountId: String, records: List<EncryptedRecordEntity>) {
        clearAccountRecords(accountId)
        if (records.isNotEmpty()) {
            upsertRecords(records)
        }
    }
}
