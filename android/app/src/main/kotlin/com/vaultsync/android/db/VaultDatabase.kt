package com.vaultsync.android.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * Room Database for offline encrypted record persistence and sync state.
 *
 * All vault items stored within are AES-256-GCM encrypted envelopes.
 * Decrypted item fields and raw keys are strictly in-memory and never written here.
 */
@Database(
    entities = [EncryptedRecordEntity::class, SyncStateEntity::class],
    version = 1,
    exportSchema = false
)
abstract class VaultDatabase : RoomDatabase() {

    abstract fun recordDao(): RecordDao
    abstract fun syncStateDao(): SyncStateDao

    companion object {
        const val DB_NAME = "vaultsync_local.db"

        @Volatile
        private var INSTANCE: VaultDatabase? = null

        fun getInstance(context: Context): VaultDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    VaultDatabase::class.java,
                    DB_NAME
                ).build().also { INSTANCE = it }
            }
        }

        fun createInMemory(context: Context): VaultDatabase {
            return Room.inMemoryDatabaseBuilder(
                context.applicationContext,
                VaultDatabase::class.java
            ).allowMainThreadQueries().build()
        }
    }
}
