package com.burprest.models

import kotlinx.serialization.Serializable

@Serializable
data class SetSessionRequest(
    val cookies: Map<String, String>,
    val headers: Map<String, String>? = null,
    val name: String? = null,
    val origin: String? = null,
)

@Serializable
data class SessionInfo(
    val name: String,
    val cookieCount: Int,
    val headerCount: Int,
    val cookies: Map<String, String>,
    val headers: Map<String, String>,
    val origin: String? = null,
)

@Serializable
data class AuthenticatedRequest(
    val method: String = "GET",
    val url: String,
    val body: String? = null,
    val extraHeaders: Map<String, String>? = null,
)

@Serializable
data class AuthenticatedResponse(
    val statusCode: Int,
    val headers: List<HttpHeader>,
    val body: String?,
    val durationMs: Long,
    val hasResponse: Boolean = true,
    val persistence: SessionPersistence = SessionPersistence.notConfigured(),
)

@Serializable
data class SessionPersistence(
    val status: PersistenceStatus,
    val historyPersisted: Boolean = false,
    val sitemapPersisted: Boolean = false,
    val historyId: Long? = null,
    val warning: String? = null,
) {
    companion object {
        fun notConfigured() = SessionPersistence(PersistenceStatus.NOT_CONFIGURED)
    }
}

@Serializable
data class BatchAuthenticatedRequest(
    val requests: List<AuthenticatedRequest>,
)

@Serializable
data class BatchAuthenticatedResponse(
    val results: List<AuthenticatedResponse>,
    val totalDurationMs: Long,
)

@Serializable
data class CookieEntry(
    val domain: String,
    val name: String,
    val value: String,
    val path: String = "/",
    val secure: Boolean = false,
    val expiresAt: Long? = null,
    val hostOnly: Boolean = true,
)

@Serializable
data class CookieJarResponse(
    val cookies: List<CookieEntry>,
    val total: Int,
)
