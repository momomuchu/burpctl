package com.burprest.models

import kotlinx.serialization.Serializable

@Serializable
data class HttpHeader(
    val name: String,
    val value: String,
)

@Serializable
data class HttpRequestData(
    val method: String,
    val url: String,
    val headers: List<HttpHeader> = emptyList(),
    val body: String? = null,
    /** Exact request bytes; when present this takes precedence over [body]. */
    val bodyBase64: String? = null,
) {
    /** Replace the body with exact bytes, leaving no potentially lossy text projection. */
    fun withBodyBytes(bytes: ByteArray): HttpRequestData = copy(
        body = null,
        bodyBase64 = java.util.Base64.getEncoder().encodeToString(bytes),
    )

    /** Replace the body with UTF-8 text while keeping the exact-byte projection consistent. */
    fun withTextBody(value: String?): HttpRequestData = copy(
        body = value,
        bodyBase64 = value?.encodeToByteArray()?.let(java.util.Base64.getEncoder()::encodeToString),
    )

    /** Resolve the authoritative bytes according to the public Base64-over-text precedence rule. */
    fun bodyBytes(): ByteArray? = bodyBase64?.let(java.util.Base64.getDecoder()::decode)
        ?: body?.encodeToByteArray()
}


@Serializable
data class HttpResponseData(
    val statusCode: Int,
    val headers: List<HttpHeader> = emptyList(),
    val body: String? = null,
)

@Serializable
data class ProxyEntry(
    val id: Int,
    val request: HttpRequestData,
    val response: HttpResponseData? = null,
    val timestamp: String? = null,
    val listenerInterface: String? = null,
    val clientIp: String? = null,
    val listenerPort: Int? = null,
)

@Serializable
data class ProxyHistoryResponse(
    val total: Int,
    val entries: List<ProxyEntry>,
)

@Serializable
data class WebSocketEntry(
    val id: Int,
    val url: String?,
    val direction: String?,
    /** Legacy text projection retained for compatibility; use [payloadBase64] for exact bytes. */
    val payload: String?,
    /** Compatibility alias for [time]. */
    val timestamp: String? = null,
    /** Stable connection identity from Montoya; defaults preserve source compatibility. */
    val webSocketId: Int = id,
    val payloadBase64: String? = payload,
    val editedPayloadBase64: String? = null,
    val time: String? = timestamp,
    val listenerPort: Int? = null,
)

@Serializable
data class WebSocketHistoryResponse(
    val total: Int,
    val entries: List<WebSocketEntry>,
)

@Serializable
data class InterceptStatusResponse(
    val enabled: Boolean,
)
