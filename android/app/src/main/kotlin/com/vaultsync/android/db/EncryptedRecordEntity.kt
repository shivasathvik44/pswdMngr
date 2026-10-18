package com.vaultsync.android.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index

/**
 * Persisted database entity storing encrypted vault record envelopes and sync metadata.
 *
 * CRITICAL SECURITY INVARIANT:
 * This entity NEVER stores decrypted secret fields (password, title, username, url, notes,
 * or raw encryption keys). All sensitive vault contents remain encrypted inside
 * [ciphertextPayload] as an AES-256-GCM envelope authenticated by the user's master key.
 */
@Entity(
    tableName = "encrypted_records",
    primaryKeys = ["account_id", "record_id"],
    indices = [
        Index(value = ["account_id", "is_deleted"]),
        Index(value = ["account_id", "sync_cursor"])
    ]
)
data class EncryptedRecordEntity(
    @ColumnInfo(name = "account_id")
    val accountId: String,

    @ColumnInfo(name = "record_id")
    val recordId: String,

    @ColumnInfo(name = "revision")
    val revision: Int = 1,

    @ColumnInfo(name = "sync_cursor")
    val syncCursor: Int = 0,

    @ColumnInfo(name = "is_deleted")
    val isDeleted: Boolean = false,

    @ColumnInfo(name = "ciphertext_payload")
    val ciphertextPayload: String = "",

    @ColumnInfo(name = "created_at")
    val createdAt: String? = null,

    @ColumnInfo(name = "updated_at")
    val updatedAt: String? = null,

    @ColumnInfo(name = "is_corrupted")
    val isCorrupted: Boolean = false,

    @ColumnInfo(name = "corruption_reason")
    val corruptionReason: String? = null
)
