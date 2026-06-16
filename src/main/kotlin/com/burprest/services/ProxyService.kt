package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.burprest.models.*
import java.time.Instant

class ProxyService(private val api: MontoyaApi) {

    fun getHistory(limit: Int? = null, offset: Int? = null, filterHost: String? = null): ProxyHistoryResponse {
        val history = api.proxy().history()

        val filtered = if (filterHost != null) {
            history.filter { it.finalRequest().url().contains(filterHost) }
        } else {
            history
        }

        val start = offset ?: 0
        val end = if (limit != null) minOf(start + limit, filtered.size) else filtered.size
        val page = if (start < filtered.size) filtered.subList(start, end) else emptyList()

        return ProxyHistoryResponse(
            total = filtered.size,
            entries = page.mapIndexed { idx, entry -> entry.toProxyEntry(start + idx) },
        )
    }

    fun getHistoryEntry(id: Int): ProxyEntry {
        val history = api.proxy().history()
        require(id in history.indices) { "Invalid history entry ID: $id" }
        return history[id].toProxyEntry(id)
    }

    fun getWebSocketHistory(): WebSocketHistoryResponse {
        val history = api.proxy().webSocketHistory()
        return WebSocketHistoryResponse(
            total = history.size,
            entries = history.mapIndexed { idx, msg ->
                WebSocketEntry(
                    id = idx,
                    url = msg.upgradeRequest().url(),
                    direction = msg.direction().name,
                    payload = msg.payload().toString(),
                    timestamp = Instant.now().toString(),
                )
            },
        )
    }

    // Tracks API-driven intercept state (Montoya does not expose the live status).
    @Volatile
    private var intercepting = false

    fun enableIntercept() {
        api.proxy().enableIntercept()
        intercepting = true
    }

    fun disableIntercept() {
        api.proxy().disableIntercept()
        intercepting = false
    }

    fun isIntercepting(): Boolean = intercepting

    private fun ProxyHttpRequestResponse.toProxyEntry(id: Int): ProxyEntry {
        val req = this.finalRequest()
        val resp = this.response()

        return ProxyEntry(
            id = id,
            request = HttpRequestData(
                method = req.method(),
                url = req.url(),
                headers = req.headers().map { HttpHeader(it.name(), it.value()) },
                body = if (req.body().length() > 0) req.bodyToString() else null,
            ),
            response = resp?.let {
                HttpResponseData(
                    statusCode = it.statusCode().toInt(),
                    headers = it.headers().map { h -> HttpHeader(h.name(), h.value()) },
                    body = if (it.body().length() > 0) it.bodyToString() else null,
                )
            },
        )
    }
}
