package com.vaultsync.android.api

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Asynchronous HTTP client communicating with the VaultSync REST backend.
 */
open class ApiClient(
    var baseUrl: String = "http://10.0.2.2:8000",
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()
) {

    var sessionToken: String? = null

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    init {
        validateBaseUrl(baseUrl)
    }

    companion object {
        fun validateBaseUrl(url: String) {
            val httpUrl = url.toHttpUrlOrNull()
                ?: throw InsecureConnectionException("Invalid server URL: '$url'. Protocol and host are required.")

            val host = httpUrl.host.lowercase()
            val isLoopbackOrDev = host == "127.0.0.1" || host == "localhost" || host == "10.0.2.2"

            if (httpUrl.scheme == "http" && !isLoopbackOrDev) {
                throw InsecureConnectionException(
                    "Insecure HTTP connection rejected for '$url'. Remote production endpoints must use HTTPS."
                )
            }
        }
    }

    protected open fun newRequestBuilder(path: String): Request.Builder {
        val cleanBase = baseUrl.trimEnd('/')
        val cleanPath = if (path.startsWith("/")) path else "/$path"
        val fullUrl = "$cleanBase$cleanPath"

        val builder = Request.Builder()
            .url(fullUrl)
            .header("Accept", "application/json")

        sessionToken?.let { token ->
            builder.header("Authorization", "Bearer $token")
        }

        return builder
    }

    protected open suspend fun executeRequest(request: Request): String = withContext(Dispatchers.IO) {
        val response: Response = try {
            client.newCall(request).execute()
        } catch (e: IOException) {
            throw NetworkConnectionException("Network request failed: ${e.message}", e)
        }

        val bodyString = response.body?.string() ?: ""

        if (response.isSuccessful) {
            return@withContext bodyString
        }

        val detailMessage = try {
            val errObj = json.decodeFromString<StandardResponse>(bodyString)
            errObj.detail ?: errObj.message ?: "Server error (${response.code})"
        } catch (e: Exception) {
            bodyString.ifBlank { "Server error (${response.code})" }
        }

        when (response.code) {
            401 -> throw AuthenticationException(detailMessage)
            403 -> throw MigrationRequiredException(detailMessage)
            404 -> throw NotFoundException(detailMessage)
            409 -> throw ConflictException(detailMessage)
            413 -> throw PayloadTooLargeException(detailMessage)
            429 -> throw RateLimitException(detailMessage)
            else -> throw ApiException(detailMessage, response.code)
        }
    }

    // ------------------------------------------------------------------------
    // Public Endpoints
    // ------------------------------------------------------------------------

    open suspend fun checkHealth(): HealthResponse {
        val request = newRequestBuilder("/api/v1/health").get().build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun register(req: RegisterRequest): RegisterResponse {
        val reqBody = json.encodeToString(req).toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/auth/register").post(reqBody).build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun login(req: LoginRequest): LoginResponse {
        val reqBody = json.encodeToString(req).toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/auth/login").post(reqBody).build()
        val res = executeRequest(request)
        val loginRes = json.decodeFromString<LoginResponse>(res)
        sessionToken = loginRes.sessionToken
        return loginRes
    }

    open suspend fun logout(): StandardResponse {
        val reqBody = "".toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/auth/logout").post(reqBody).build()
        val res = executeRequest(request)
        sessionToken = null
        return try {
            json.decodeFromString(res)
        } catch (e: Exception) {
            StandardResponse(status = "ok")
        }
    }

    open suspend fun getSalt(username: String): SaltResponse {
        val request = newRequestBuilder("/api/v1/auth/salt?username=$username").get().build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun getVaultKey(): VaultKeyResponse {
        val request = newRequestBuilder("/api/v1/auth/vault-key").get().build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun updateVaultKey(req: UpdateVaultKeyRequest): StandardResponse {
        val reqBody = json.encodeToString(req).toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/auth/vault-key").put(reqBody).build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun changeAccountPassword(req: ChangePasswordRequest): StandardResponse {
        val reqBody = json.encodeToString(req).toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/auth/password").put(reqBody).build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun createRecord(req: CreateRecordRequest): RecordResponse {
        val reqBody = json.encodeToString(req).toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/records").post(reqBody).build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun updateRecord(recordId: String, req: UpdateRecordRequest): RecordResponse {
        val reqBody = json.encodeToString(req).toRequestBody(jsonMediaType)
        val request = newRequestBuilder("/api/v1/records/$recordId").put(reqBody).build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun deleteRecord(recordId: String, expectedRevision: Int): RecordResponse {
        val request = newRequestBuilder("/api/v1/records/$recordId?expected_revision=$expectedRevision").delete().build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }

    open suspend fun fetchSync(sinceCursor: Int = 0, limit: Int = 100): SyncResponse {
        val request = newRequestBuilder("/api/v1/sync?since_cursor=$sinceCursor&limit=$limit").get().build()
        val res = executeRequest(request)
        return json.decodeFromString(res)
    }
}
