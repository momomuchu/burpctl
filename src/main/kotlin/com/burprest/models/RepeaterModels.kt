package com.burprest.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SendRequest(
    val request: HttpRequestData? = null,
    val requestId: Int? = null,
    val modifications: RequestModifications? = null,
)

@Serializable
data class RequestModifications(
    val headers: Map<String, String>? = null,
    val body: String? = null,
    val method: String? = null,
    val path: String? = null,
)

@Serializable
data class SendResponse(
    val request: HttpRequestData,
    val response: HttpResponseData,
    val durationMs: Long,
    /** Successful responses are response-bearing; response-less sends use the typed NO_RESPONSE error. */
    val hasResponse: Boolean = true,
    /** Best-effort local recording state; it never changes whether the target send succeeded. */
    val persistence: RepeaterPersistence = RepeaterPersistence.notConfigured(),
)

@Serializable
data class RepeaterPersistence(
    val status: PersistenceStatus,
    val historyPersisted: Boolean = false,
    val sitemapPersisted: Boolean = false,
    /** Database history primary key, when history and sitemap were committed together. */
    val historyId: Long? = null,
    /** Sanitized, retry-safe detail when optional recording was incomplete. */
    val warning: String? = null,
) {
    companion object {
        fun notConfigured() = RepeaterPersistence(PersistenceStatus.NOT_CONFIGURED)
    }
}

@Serializable
enum class PersistenceStatus {
    @SerialName("persisted")
    PERSISTED,

    @SerialName("partial")
    PARTIAL,

    @SerialName("failed")
    FAILED,

    @SerialName("not_configured")
    NOT_CONFIGURED,
}

@Serializable
data class BatchSendRequest(
    val requests: List<SendRequest>,
)

@Serializable
data class BatchSendResponse(
    val results: List<SendResponse>,
    val totalDurationMs: Long,
)

@Serializable
data class CreateTabRequest(
    val name: String? = null,
    val request: HttpRequestData? = null,
    val requestId: Int? = null,
)

@Serializable
data class CreateTabResponse(
    val name: String,
    val created: Boolean,
)
