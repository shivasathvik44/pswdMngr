package com.vaultsync.android.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class RegisterRequest(
    val username: String,
    @SerialName("account_password") val accountPassword: String,
    @SerialName("kdf_salt") val kdfSalt: String,
    @SerialName("wrapped_vault_key") val wrappedVaultKey: String
)

@Serializable
data class RegisterResponse(
    @SerialName("account_id") val accountId: String,
    val username: String,
    @SerialName("kdf_salt") val kdfSalt: String,
    @SerialName("created_at") val createdAt: String
)

@Serializable
data class LoginRequest(
    val username: String,
    @SerialName("account_password") val accountPassword: String,
    @SerialName("device_name") val deviceName: String = "Android Client",
    @SerialName("device_id") val deviceId: String? = null
)

@Serializable
data class LoginResponse(
    @SerialName("session_token") val sessionToken: String,
    @SerialName("session_id") val sessionId: String,
    @SerialName("account_id") val accountId: String,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("kdf_salt") val kdfSalt: String,
    @SerialName("wrapped_vault_key") val wrappedVaultKey: String? = null
)

@Serializable
data class SaltResponse(
    val username: String,
    @SerialName("kdf_salt") val kdfSalt: String
)

@Serializable
data class VaultKeyResponse(
    @SerialName("wrapped_vault_key") val wrappedVaultKey: String? = null,
    @SerialName("kdf_salt") val kdfSalt: String
)

@Serializable
data class UpdateVaultKeyRequest(
    @SerialName("wrapped_vault_key") val wrappedVaultKey: String,
    @SerialName("kdf_salt") val kdfSalt: String
)

@Serializable
data class ChangePasswordRequest(
    @SerialName("current_password") val currentPassword: String,
    @SerialName("new_password") val newPassword: String
)

@Serializable
data class CreateRecordRequest(
    @SerialName("record_id") val recordId: String,
    @SerialName("ciphertext_payload") val ciphertextPayload: String
)

@Serializable
data class UpdateRecordRequest(
    @SerialName("expected_revision") val expectedRevision: Int,
    @SerialName("ciphertext_payload") val ciphertextPayload: String
)

@Serializable
data class RecordResponse(
    @SerialName("record_id") val recordId: String,
    @SerialName("ciphertext_payload") val ciphertextPayload: String = "",
    val revision: Int = 1,
    @SerialName("sync_cursor") val syncCursor: Int = 0,
    @SerialName("is_deleted") val isDeleted: Boolean = false,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
)

@Serializable
data class SyncResponse(
    val items: List<RecordResponse>,
    @SerialName("server_cursor") val serverCursor: Int,
    @SerialName("next_cursor") val nextCursor: Int,
    @SerialName("has_more") val hasMore: Boolean
)

@Serializable
data class StandardResponse(
    val status: String? = null,
    val message: String? = null,
    val detail: String? = null
)

@Serializable
data class HealthResponse(
    val status: String,
    val version: String? = null
)
