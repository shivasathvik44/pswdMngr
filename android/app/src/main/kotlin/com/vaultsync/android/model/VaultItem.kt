package com.vaultsync.android.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant
import java.util.UUID

/**
 * Plaintext in-memory representation of an individual vault entry.
 *
 * Only exists in memory when the vault is unlocked.
 */
@Serializable
data class VaultItem(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    val revision: Int = 1,
    @SerialName("is_deleted") val isDeleted: Boolean = false,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
) {
    val version: Int
        get() = revision

    /**
     * Serializes confidential fields into the exact plaintext JSON payload
     * encrypted inside an EncryptedRecordEnvelope.
     */
    fun toSecretJson(): String {
        val payload = SecretPayload(
            title = title,
            username = username,
            password = password,
            url = url,
            notes = notes,
            createdAt = createdAt ?: Instant.now().toString(),
            updatedAt = updatedAt ?: Instant.now().toString()
        )
        return jsonSerializer.encodeToString(payload)
    }

    companion object {
        private val jsonSerializer = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun fromSecretJson(recordId: String, revision: Int, secretJson: String): VaultItem {
            val payload = jsonSerializer.decodeFromString<SecretPayload>(secretJson)
            return VaultItem(
                id = recordId,
                title = payload.title.ifBlank { "Untitled" },
                username = payload.username,
                password = payload.password,
                url = payload.url,
                notes = payload.notes,
                revision = revision,
                isDeleted = false,
                createdAt = payload.createdAt ?: Instant.now().toString(),
                updatedAt = payload.updatedAt ?: Instant.now().toString()
            )
        }
    }
}

@Serializable
private data class SecretPayload(
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
)
