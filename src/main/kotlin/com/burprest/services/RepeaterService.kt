package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.db.HistoryDao
import com.burprest.db.SitemapDao
import com.burprest.models.*

class RepeaterService(
    private val api: MontoyaApi,
    private val historyDao: HistoryDao? = null,
    private val sitemapDao: SitemapDao? = null,
) {

    fun send(request: SendRequest): SendResponse {
        val httpRequest = resolveRequest(request)

        val start = System.currentTimeMillis()
        val httpResponse = api.http().sendRequest(httpRequest)
        val duration = System.currentTimeMillis() - start

        val resp = httpResponse.response()
        val reqHeaders = httpRequest.headers().map { HttpHeader(it.name(), it.value()) }
        val resHeaders = resp.headers().map { HttpHeader(it.name(), it.value()) }
        val reqBody = if (httpRequest.body().length() > 0) httpRequest.bodyToString() else null
        val resBody = if (resp.body().length() > 0) resp.bodyToString() else null

        // Record to history
        historyDao?.insert(
            source = "repeater",
            method = httpRequest.method(),
            url = httpRequest.url(),
            reqHeaders = reqHeaders,
            reqBody = reqBody,
            statusCode = resp.statusCode().toInt(),
            resHeaders = resHeaders,
            resBody = resBody,
            durationMs = duration,
        )
        sitemapDao?.upsert(httpRequest.url(), httpRequest.method())

        return SendResponse(
            request = HttpRequestData(
                method = httpRequest.method(),
                url = httpRequest.url(),
                headers = reqHeaders,
                body = reqBody,
            ),
            response = HttpResponseData(
                statusCode = resp.statusCode().toInt(),
                headers = resHeaders,
                body = resBody,
            ),
            durationMs = duration,
        )
    }

    fun sendBatch(batch: BatchSendRequest): BatchSendResponse {
        val start = System.currentTimeMillis()
        val results = batch.requests.map { send(it) }
        val totalDuration = System.currentTimeMillis() - start

        return BatchSendResponse(
            results = results,
            totalDurationMs = totalDuration,
        )
    }

    fun createTab(request: CreateTabRequest): CreateTabResponse {
        val name = request.name ?: "REST API Tab"
        val httpRequest = if (request.request != null) {
            buildRequest(request.request)
        } else if (request.requestId != null) {
            getHistoryRequest(request.requestId)
        } else {
            HttpRequest.httpRequestFromUrl("https://example.com")
        }

        api.repeater().sendToRepeater(httpRequest, name)

        return CreateTabResponse(name = name, created = true)
    }

    private fun resolveRequest(request: SendRequest): HttpRequest {
        val base = if (request.request != null) {
            buildRequest(request.request)
        } else if (request.requestId != null) {
            getHistoryRequest(request.requestId)
        } else {
            throw IllegalArgumentException("Either 'request' or 'requestId' is required")
        }

        return applyModifications(base, request.modifications)
    }

    private fun applyModifications(base: HttpRequest, mods: RequestModifications?): HttpRequest {
        if (mods == null) return base
        var req = base

        mods.method?.let { req = req.withMethod(it) }
        mods.path?.let { req = req.withPath(it) }
        mods.body?.let { req = req.withBody(it) }
        mods.headers?.forEach { (name, value) ->
            req = req.withRemovedHeader(name).withAddedHeader(name, value)
        }

        return req
    }

    internal fun buildRequest(data: HttpRequestData): HttpRequest {
        var req = HttpRequest.httpRequestFromUrl(data.url)
            .withMethod(data.method)

        data.headers.forEach { h ->
            // Remove any existing same-named header first so we set, not duplicate (e.g. Host).
            req = req.withRemovedHeader(h.name).withAddedHeader(h.name, h.value)
        }

        data.body?.let { req = req.withBody(it) }

        return req
    }

    private fun getHistoryRequest(id: Int): HttpRequest {
        val history = api.proxy().history()
        require(id in history.indices) { "Invalid history entry ID: $id" }
        return history[id].finalRequest()
    }
}
