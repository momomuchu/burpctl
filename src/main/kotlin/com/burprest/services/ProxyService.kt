package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.burprest.models.*
import com.burprest.server.InvalidParamException
import com.burprest.server.NotFoundException
import com.burprest.server.ServiceUnavailableException
import com.burprest.server.UnsupportedException
import com.burprest.server.validateParameter
import java.net.IDN
import java.net.InetAddress
import java.util.Base64
import java.util.Locale

class ProxyService(private val api: MontoyaApi) {

    fun getHistory(limit: Int? = null, offset: Int? = null, filterHost: String? = null): ProxyHistoryResponse {
        validateBounds(limit, offset)
        // Normalize before touching Montoya so an invalid filter can never trigger even a history read.
        val normalizedFilter = filterHost?.let(::normalizeFilterHost)
        val history = api.proxy().history()

        val projected = history.withIndex().mapNotNull { (absoluteIndex, entry) ->
            try {
                if (normalizedFilter == null || normalizeHost(entry.host()) == normalizedFilter) {
                    entry.toProxyEntry(absoluteIndex)
                } else {
                    null
                }
            } catch (_: MalformedRequestException) {
                // A corrupt stored message is not evidence that every other proxy row is unavailable.
                null
            }
        }
        val start = offset ?: 0
        val page = if (start >= projected.size) {
            emptyList()
        } else {
            // Deriving the count from the remaining size avoids `start + limit` integer overflow.
            val remaining = projected.size - start
            val count = limit?.coerceAtMost(remaining) ?: remaining
            projected.subList(start, start + count)
        }

        return ProxyHistoryResponse(
            total = projected.size,
            entries = page,
        )
    }

    fun getHistoryEntry(id: Int): ProxyEntry {
        validateParameter(id, "id", "must be at least 0") { it >= 0 }
        val history = api.proxy().history()
        val entry = history.getOrNull(id) ?: throw NotFoundException("proxy history entry was not found")
        return try {
            entry.toProxyEntry(id)
        } catch (cause: MalformedRequestException) {
            throw ServiceUnavailableException("proxy history entry is malformed", cause)
        }
    }

    fun getWebSocketHistory(): WebSocketHistoryResponse {
        val history = api.proxy().webSocketHistory()
        return WebSocketHistoryResponse(
            total = history.size,
            entries = history.mapIndexed { historyIndex, message ->
                // Montoya reports no edited payload for a message that was never edited, and every
                // one of these accessors is a platform type. A single absent value used to raise a
                // null dereference that failed the whole listing with INTERNAL_ERROR, so `bp ws`
                // could not read any WebSocket traffic at all. Absence is now reported as absence.
                val originalPayloadBytes = message.payload()
                val originalPayload = originalPayloadBytes
                    ?.getBytes()
                    ?.let { Base64.getEncoder().encodeToString(it) }
                val editedPayload = message.editedPayload()
                    ?.getBytes()
                    ?.let { Base64.getEncoder().encodeToString(it) }
                val capturedAt = message.time()?.toString()
                WebSocketEntry(
                    // Preserve the old row index/text projections for source and wire compatibility;
                    // the explicit fields below carry stable identity and byte-faithful evidence.
                    id = historyIndex,
                    webSocketId = message.webSocketId(),
                    url = message.upgradeRequest()?.url(),
                    direction = message.direction()?.name,
                    payload = originalPayloadBytes?.toString(),
                    payloadBase64 = originalPayload,
                    editedPayloadBase64 = editedPayload,
                    timestamp = capturedAt,
                    time = capturedAt,
                    listenerPort = message.listenerPort(),
                )
            },
        )
    }

    fun enableIntercept(): Boolean {
        val proxy = api.proxy()
        proxy.enableIntercept()
        return proxy.isInterceptEnabled()
    }

    fun disableIntercept(): Boolean {
        val proxy = api.proxy()
        proxy.disableIntercept()
        return proxy.isInterceptEnabled()
    }

    fun isIntercepting(): Boolean = api.proxy().isInterceptEnabled()

    fun forwardInterceptedMessage(): Nothing = throw UnsupportedException(
        "Montoya 2025.3 does not expose a primitive for forwarding the currently intercepted message",
    )

    fun dropInterceptedMessage(): Nothing = throw UnsupportedException(
        "Montoya 2025.3 does not expose a primitive for dropping the currently intercepted message",
    )

    private fun validateBounds(limit: Int?, offset: Int?) {
        if (limit != null && limit < 1) throw InvalidParamException("limit must be at least 1")
        if (offset != null && offset < 0) throw InvalidParamException("offset must be at least 0")
    }

    private fun normalizeFilterHost(value: String): String {
        val host = value.trim()
        if (host.isEmpty()) throw InvalidParamException("host must not be blank")
        if (host.contains("://") || host.any { it == '/' || it == '?' || it == '#' || it == '@' }) {
            throw InvalidParamException("host must be a hostname or IP literal, not a URL")
        }
        return normalizeHost(host)
            ?: throw InvalidParamException("host is not a valid hostname or IP literal")
    }

    private fun normalizeHost(value: String): String? {
        val trimmed = value.trim()
        val bracketed = trimmed.startsWith('[') || trimmed.endsWith(']')
        if (bracketed && !(trimmed.startsWith('[') && trimmed.endsWith(']'))) return null
        val withoutBrackets = trimmed.removeSurrounding("[", "]").removeSuffix(".")
        if (withoutBrackets.isEmpty()) return null
        // Scoped IPv6 addresses are interface-local rather than stable host identities. Reject them
        // instead of silently dropping the zone and equating two distinct literals.
        if (withoutBrackets.contains('%')) return null
        if (bracketed && !withoutBrackets.contains(':')) return null

        return if (withoutBrackets.contains(':')) {
            try {
                val address = InetAddress.getByName(withoutBrackets)
                if (address.address.size != 16) null else address.hostAddress.substringBefore('%').lowercase(Locale.ROOT)
            } catch (_: Exception) {
                null
            }
        } else {
            try {
                IDN.toASCII(withoutBrackets.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
                    .lowercase(Locale.ROOT)
                    .takeIf { it.isNotEmpty() }
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }

    private fun ProxyHttpRequestResponse.toProxyEntry(id: Int): ProxyEntry {
        val request = finalRequest()
        val response = response()
        val requestBody = request.body()

        return ProxyEntry(
            id = id,
            request = HttpRequestData(
                method = request.method(),
                url = request.url(),
                headers = request.headers().map { HttpHeader(it.name(), it.value()) },
                body = if (requestBody.length() > 0) request.bodyToString() else null,
                bodyBase64 = requestBody
                    .takeIf { it.length() > 0 }
                    ?.getBytes()
                    ?.let { Base64.getEncoder().encodeToString(it) },
            ),
            response = response?.let {
                HttpResponseData(
                    statusCode = it.statusCode().toInt(),
                    headers = it.headers().map { header -> HttpHeader(header.name(), header.value()) },
                    body = if (it.body().length() > 0) it.bodyToString() else null,
                )
            },
            timestamp = time().toString(),
            listenerPort = listenerPort(),
        )
    }
}
