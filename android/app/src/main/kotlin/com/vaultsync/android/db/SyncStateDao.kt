package com.vaultsync.android.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface SyncStateDao {

    @Query("SELECT * FROM sync_states WHERE account_id = :accountId LIMIT 1")
    suspend fun getSyncState(accountId: String): SyncStateEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun setSyncState(syncState: SyncStateEntity)

    @Query("DELETE FROM sync_states WHERE account_id = :accountId")
    suspend fun deleteSyncState(accountId: String)

    @Query("DELETE FROM sync_states")
    suspend fun deleteAll()
}
