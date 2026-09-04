package com.burprest.server

import io.ktor.http.HttpStatusCode

/**
 * An expected API failure whose public contract is independent of the exception that caused it.
 *
 * [clientMessage] is the only exception text that may be returned to an HTTP client. The optional
 * [cause] is retained for server-side diagnostics and is deliberately never serialized.
 */
sealed class ApiException(
    val status: HttpStatusCode,
    val code: String,
    val clientMessage: String,
    cause: Throwable? = null,
) : RuntimeException(clientMessage, cause)

class InvalidParamException(
    message: String = "invalid parameter",
    cause: Throwable? = null,
) : ApiException(HttpStatusCode.BadRequest, "INVALID_PARAM", message, cause)

class NotFoundException(
    message: String = "resource not found",
    cause: Throwable? = null,
) : ApiException(HttpStatusCode.NotFound, "NOT_FOUND", message, cause)

class UnsupportedException(
    message: String = "operation not supported",
    cause: Throwable? = null,
) : ApiException(HttpStatusCode.NotImplemented, "UNSUPPORTED", message, cause)

class NoResponseException(
    message: String = "upstream server returned no response",
    cause: Throwable? = null,
) : ApiException(HttpStatusCode.BadGateway, "NO_RESPONSE", message, cause)

class CredentialScopeViolationException(
    message: String = "credentials may only be sent to their configured origin",
    cause: Throwable? = null,
) : ApiException(HttpStatusCode.Forbidden, "CREDENTIAL_SCOPE_VIOLATION", message, cause)

class ServiceUnavailableException(
    message: String = "service unavailable",
    cause: Throwable? = null,
) : ApiException(HttpStatusCode.ServiceUnavailable, "SERVICE_UNAVAILABLE", message, cause)

/** Compatibility exception used by scanner services and the Python client's PRO_REQUIRED handling. */
class ProRequiredException(message: String) : RuntimeException(message)
