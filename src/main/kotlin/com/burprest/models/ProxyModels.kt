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
)

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
    val url: String,
    val direction: String,
    /** Legacy text projection retained for compatibility; use [payloadBase64] for exact bytes. */
    val payload: String,
    /** Compatibility alias for [time]. */
    val timestamp: String? = null,
    /** Stable connection identity from Montoya; defaults preserve source compatibility. */
    val webSocketId: Int = id,
    val payloadBase64: String = payload,
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
