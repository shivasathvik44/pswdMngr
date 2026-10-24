package com.vaultsync.android.api

open class ApiException(message: String, val statusCode: Int? = null) : Exception(message)

class AuthenticationException(message: String = "Authentication failed: invalid credentials or session expired") : ApiException(message, 401)

class MigrationRequiredException(message: String = "Account requires credential migration") : ApiException(message, 403)

class NotFoundException(message: String = "Resource not found") : ApiException(message, 404)

class ConflictException(message: String = "Concurrency conflict: record was modified on another device") : ApiException(message, 409)

class PayloadTooLargeException(message: String = "Payload exceeds server size limit (2 MiB)") : ApiException(message, 413)

class ValidationException(message: String = "Validation error: invalid request payload") : ApiException(message, 422)

class RateLimitException(message: String = "Rate limit exceeded. Please wait before retrying.") : ApiException(message, 429)

class NetworkConnectionException(message: String, cause: Throwable? = null) : ApiException(message)

class InsecureConnectionException(message: String) : ApiException(message)
