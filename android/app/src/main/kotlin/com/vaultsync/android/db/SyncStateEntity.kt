package com.vaultsync.android.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Synchronization state tracking monotonic progress per account.
 */
@Entity(tableName = "sync_states")
data class SyncStateEntity(
    @PrimaryKey
    @ColumnInfo(name = "account_id")
    val accountId: String,

    @ColumnInfo(name = "last_sync_cursor")
    val lastSyncCursor: Int = 0,

    @ColumnInfo(name = "last_synced_at")
    val lastSyncedAt: Long = 0L
)
