package com.vaultsync.android.api

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ApiClientTest {

    private lateinit var server: MockWebServer
    private lateinit var client: ApiClient

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        val baseUrl = server.url("/").toString().removeSuffix("/")
        client = ApiClient(baseUrl = baseUrl)
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun testHealthCheckSuccess() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"status\":\"ok\",\"version\":\"0.1.0\"}")
        )

        val health = client.checkHealth()
        assertEquals("ok", health.status)
        assertEquals("0.1.0", health.version)
    }

    @Test
    fun testRegisterSuccess() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"account_id\":\"user-123\",\"username\":\"testuser\",\"kdf_salt\":\"c2FsdA==\",\"created_at\":\"2026-10-15T00:00:00Z\"}")
        )

        val resp = client.register(
            RegisterRequest(
                username = "testuser",
                accountPassword = "testpass123",
                kdfSalt = "c2FsdA==",
                wrappedVaultKey = "{\"version\":1}"
            )
        )
        assertEquals("testuser", resp.username)
        assertEquals("user-123", resp.accountId)
    }

    @Test
    fun testLoginSuccessSetsToken() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"session_token\":\"token-abc-xyz\",\"session_id\":\"sess-1\",\"account_id\":\"user-123\",\"expires_at\":\"2026-10-15T12:00:00Z\",\"kdf_salt\":\"c2FsdA==\",\"wrapped_vault_key\":\"{\\\"version\\\":1}\"}")
        )

        val resp = client.login(
            LoginRequest(
                username = "testuser",
                accountPassword = "testpass123"
            )
        )
        assertEquals("token-abc-xyz", resp.sessionToken)
        assertEquals("token-abc-xyz", client.sessionToken)
    }

    @Test
    fun testAuthenticationFailureThrowsAuthenticationException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"detail\":\"Invalid username or password\"}")
        )

        assertThrows(AuthenticationException::class.java) {
            runBlocking {
                client.login(LoginRequest("testuser", "wrongpass"))
            }
        }
    }

    @Test
    fun testConflictThrowsConflictException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(409)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"detail\":\"Username already exists\"}")
        )

        assertThrows(ConflictException::class.java) {
            runBlocking {
                client.register(
                    RegisterRequest(
                        username = "existinguser",
                        accountPassword = "pass12345",
                        kdfSalt = "c2FsdA==",
                        wrappedVaultKey = "{}"
                    )
                )
            }
        }
    }

    @Test
    fun testRateLimitThrowsRateLimitException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(429)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"detail\":\"Rate limit exceeded. Please wait 60 seconds.\"}")
        )

        assertThrows(RateLimitException::class.java) {
            runBlocking {
                client.login(LoginRequest("user", "pass"))
            }
        }
    }

    @Test
    fun testPayloadTooLargeThrowsPayloadTooLargeException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(413)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"detail\":\"Request body exceeds limit\"}")
        )

        assertThrows(PayloadTooLargeException::class.java) {
            runBlocking {
                client.createRecord(CreateRecordRequest("id-1", "huge-payload"))
            }
        }
    }

    @Test
    fun testMigrationRequiredThrowsMigrationRequiredException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(403)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"detail\":\"Client migration required\"}")
        )

        assertThrows(MigrationRequiredException::class.java) {
            runBlocking {
                client.fetchSync(sinceCursor = 0)
            }
        }
    }

    @Test
    fun testInsecureCleartextRemoteUrlThrowsException() {
        val remoteHttpUrl = "http://api.vaultsync.example.com"
        assertThrows(InsecureConnectionException::class.java) {
            ApiClient(baseUrl = remoteHttpUrl)
        }
    }
}
