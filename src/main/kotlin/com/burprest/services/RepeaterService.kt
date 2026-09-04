package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.db.HistoryDao
import com.burprest.db.SitemapDao
import com.burprest.models.*
import com.burprest.server.NoResponseException
import java.net.URI
import java.net.URISyntaxException
import java.util.Locale
import java.util.concurrent.TimeUnit

class RepeaterService(
    private val api: MontoyaApi,
    private val historyDao: HistoryDao? = null,
    private val sitemapDao: SitemapDao? = null,
    private val requestFactory: (String) -> HttpRequest = { HttpRequest.httpRequestFromUrl(it) },
) {

    fun send(request: SendRequest): SendResponse = sendPrepared(resolveRequest(request))

    fun sendBatch(batch: BatchSendRequest): BatchSendResponse {
        val start = System.nanoTime()
        // Resolve and validate the whole batch before the first target effect. In particular, do not
        // implement this as requests.map(::send): a bad late item must not leave an earlier item sent.
        val prepared = batch.requests.mapIndexed { index, request ->
            try {
                resolveRequest(request)
            } catch (failure: IllegalArgumentException) {
                throw IllegalArgumentException("requests[$index]: ${failure.message ?: "invalid request"}", failure)
            }
        }

        val results = prepared.map(::sendPrepared)
        return BatchSendResponse(
            results = results,
            totalDurationMs = elapsedMillis(start),
        )
    }

    fun createTab(request: CreateTabRequest): CreateTabResponse {
        requireExactlyOneSource(request.request, request.requestId)

        val httpRequest = request.request?.let { data ->
            validateRequestData(data)
            buildRequest(data)
        } ?: getHistoryRequest(requireNotNull(request.requestId)).also(::validateHttpRequest)

        api.repeater().sendToRepeater(httpRequest, request.name ?: "REST API Tab")
        return CreateTabResponse(name = request.name ?: "REST API Tab", created = true)
    }

    private fun sendPrepared(httpRequest: HttpRequest): SendResponse {
        val start = System.nanoTime()
        val exchange = api.http().sendRequest(httpRequest)
        val duration = elapsedMillis(start)

        // Montoya's response() accessor is not valid when no upstream response was received. Checking
        // this flag both gives callers a stable NO_RESPONSE result and avoids fabricating status 0.
        if (!exchange.hasResponse()) {
            throw NoResponseException("target send completed without an upstream response")
        }
        val response = exchange.response()
            ?: throw NoResponseException("target send completed without an upstream response")

        val requestHeaders = httpRequest.headers().map { HttpHeader(it.name(), it.value()) }
        val responseHeaders = response.headers().map { HttpHeader(it.name(), it.value()) }
        val requestBody = httpRequest.body().let { if (it.length() > 0) httpRequest.bodyToString() else null }
        val responseBody = response.body().let { if (it.length() > 0) response.bodyToString() else null }
        val responseData = HttpResponseData(
            statusCode = response.statusCode().toInt(),
            headers = responseHeaders,
            body = responseBody,
        )

        // Sending is the primary effect. Optional recording happens afterwards and can never turn a
        // completed target request into an error that invites the caller to repeat a mutation.
        val persistence = persist(
            httpRequest = httpRequest,
            requestHeaders = requestHeaders,
            requestBody = requestBody,
            response = responseData,
            durationMs = duration,
        )

        return SendResponse(
            request = HttpRequestData(
                method = httpRequest.method(),
                url = httpRequest.url(),
                headers = requestHeaders,
                body = requestBody,
            ),
            response = responseData,
            durationMs = duration,
            hasResponse = true,
            persistence = persistence,
        )
    }

    private fun persist(
        httpRequest: HttpRequest,
        requestHeaders: List<HttpHeader>,
        requestBody: String?,
        response: HttpResponseData,
        durationMs: Long,
    ): RepeaterPersistence {
        if (historyDao == null && sitemapDao == null) return RepeaterPersistence.notConfigured()

        if (historyDao != null && sitemapDao != null) {
            return try {
                val historyId = historyDao.insertWithSitemap(
                    sitemapDao = sitemapDao,
                    source = "repeater",
                    method = httpRequest.method(),
                    url = httpRequest.url(),
                    reqHeaders = requestHeaders,
                    reqBody = requestBody,
                    statusCode = response.statusCode,
                    resHeaders = response.headers,
                    resBody = response.body,
                    durationMs = durationMs,
                )
                RepeaterPersistence(
                    status = PersistenceStatus.PERSISTED,
                    historyPersisted = true,
                    sitemapPersisted = true,
                    historyId = historyId,
                )
            } catch (_: Exception) {
                persistenceFailure(
                    status = PersistenceStatus.FAILED,
                    warning = "Target send completed, but optional history and sitemap persistence failed; do not retry the target send.",
                )
            }
        }

        // Production wires both DAOs together. These branches keep the public optional constructor
        // truthful for integrations that provide only one recorder.
        return if (historyDao != null) {
            try {
                val historyId = historyDao.insert(
                    source = "repeater",
                    method = httpRequest.method(),
                    url = httpRequest.url(),
                    reqHeaders = requestHeaders,
                    reqBody = requestBody,
                    statusCode = response.statusCode,
                    resHeaders = response.headers,
                    resBody = response.body,
                    durationMs = durationMs,
                )
                RepeaterPersistence(
                    status = PersistenceStatus.PARTIAL,
                    historyPersisted = true,
                    historyId = historyId,
                    warning = "Target send completed and history was persisted, but sitemap persistence is not configured.",
                )
            } catch (_: Exception) {
                persistenceFailure(
                    status = PersistenceStatus.FAILED,
                    warning = "Target send completed, but optional history persistence failed; do not retry the target send.",
                )
            }
        } else {
            try {
                requireNotNull(sitemapDao).upsert(httpRequest.url(), httpRequest.method())
                RepeaterPersistence(
                    status = PersistenceStatus.PARTIAL,
                    sitemapPersisted = true,
                    warning = "Target send completed and sitemap was persisted, but history persistence is not configured.",
                )
            } catch (_: Exception) {
                persistenceFailure(
                    status = PersistenceStatus.FAILED,
                    warning = "Target send completed, but optional sitemap persistence failed; do not retry the target send.",
                )
            }
        }
    }

    private fun persistenceFailure(status: PersistenceStatus, warning: String): RepeaterPersistence {
        // Do not leak JDBC/path details and do not allow a logging adapter failure to alter the result.
        runCatching { api.logging().logToError("[burp-rest] $warning") }
        return RepeaterPersistence(status = status, warning = warning)
    }

    private fun resolveRequest(request: SendRequest): HttpRequest {
        requireExactlyOneSource(request.request, request.requestId)
        validateModifications(request.modifications)

        val base = request.request?.let { data ->
            validateRequestData(data)
            buildRequest(data)
        } ?: getHistoryRequest(requireNotNull(request.requestId)).also(::validateHttpRequest)

        return applyModifications(base, request.modifications).also(::validateHttpRequest)
    }

    private fun applyModifications(base: HttpRequest, modifications: RequestModifications?): HttpRequest {
        if (modifications == null) return base
        var request = base

        modifications.method?.let { request = request.withMethod(it) }
        modifications.path?.let { request = request.withPath(it) }
        modifications.body?.let { request = request.withBody(it) }
        modifications.headers?.forEach { (name, value) ->
            request = request.withRemovedHeader(name).withAddedHeader(name, value)
        }

        return request
    }

    internal fun buildRequest(data: HttpRequestData): HttpRequest {
        // Keep validation here as well as in resolveRequest because this helper is used directly by
        // sibling services and tests.
        validateRequestData(data)
        var request = requestFactory(data.url).withMethod(data.method)

        data.headers.forEach { header ->
            request = request.withRemovedHeader(header.name).withAddedHeader(header.name, header.value)
        }
        data.body?.let { request = request.withBody(it) }
        return request
    }

    private fun getHistoryRequest(id: Int): HttpRequest {
        require(id >= 0) { "requestId must be >= 0" }
        val history = api.proxy().history()
        require(id in history.indices) { "Invalid history entry ID: $id" }
        return history[id].finalRequest()
    }

    private fun validateRequestData(data: HttpRequestData) {
        validateMethod(data.method, "request.method")
        validateUrl(data.url, "request.url")
        data.headers.forEachIndexed { index, header ->
            validateHeader(header.name, header.value, "request.headers[$index]")
        }
    }

    private fun validateHttpRequest(request: HttpRequest) {
        validateMethod(request.method(), "request.method")
        validateUrl(request.url(), "request.url")
        request.headers().forEachIndexed { index, header ->
            validateHeader(header.name(), header.value(), "request.headers[$index]")
        }
    }

    private fun validateModifications(modifications: RequestModifications?) {
        if (modifications == null) return
        modifications.method?.let { validateMethod(it, "modifications.method") }
        modifications.path?.let { validatePath(it) }
        modifications.headers?.forEach { (name, value) ->
            validateHeader(name, value, "modifications.headers")
        }
    }

    private fun validateUrl(value: String, field: String) {
        require(value.isNotBlank()) { "$field must not be blank" }
        require(value.none(::isForbiddenUrlCharacter)) { "$field contains invalid characters" }
        val uri = parseUri(value, field)
        require(uri.scheme?.lowercase(Locale.ROOT) in SUPPORTED_SCHEMES) {
            "$field must use http or https"
        }
        require(uri.isAbsolute && !uri.rawAuthority.isNullOrBlank() && !uri.host.isNullOrBlank()) {
            "$field must be an absolute HTTP URL with a host"
        }
        require(uri.rawUserInfo == null) { "$field must not contain user information" }
        require(uri.rawFragment == null) { "$field must not contain a fragment" }
        require(!uri.rawAuthority.endsWith(':')) { "$field contains an invalid port" }
        require(uri.port == -1 || uri.port in 1..65535) { "$field contains an invalid port" }
    }

    private fun validatePath(value: String) {
        require(value.isNotBlank()) { "modifications.path must not be blank" }
        require(value.none(::isForbiddenUrlCharacter)) { "modifications.path contains invalid characters" }
        if (value == "*") return
        require(value.startsWith('/')) { "modifications.path must start with '/'" }
        val uri = parseUri(value, "modifications.path")
        require(!uri.isAbsolute && uri.rawAuthority == null) { "modifications.path must be a path, not a URL" }
        require(uri.rawFragment == null) { "modifications.path must not contain a fragment" }
    }

    private fun validateMethod(value: String, field: String) {
        require(value.isNotBlank()) { "$field must not be blank" }
        require(value.all(::isTokenCharacter)) { "$field must be a valid HTTP token" }
    }

    private fun validateHeader(name: String, value: String, field: String) {
        require(name.isNotBlank()) { "$field name must not be blank" }
        require(name.all(::isTokenCharacter)) { "$field name must be a valid HTTP token" }
        require(value.none { it == '\r' || it == '\n' || it == '\u0000' }) {
            "$field value contains forbidden CR, LF, or NUL"
        }
    }

    private fun parseUri(value: String, field: String): URI = try {
        URI(value)
    } catch (failure: URISyntaxException) {
        throw IllegalArgumentException("$field is malformed", failure)
    }

    private fun isForbiddenUrlCharacter(character: Char): Boolean =
        character == '\r' || character == '\n' || character == '\u0000' || character.isWhitespace()

    private fun isTokenCharacter(character: Char): Boolean =
        character in '0'..'9' ||
            character in 'A'..'Z' ||
            character in 'a'..'z' ||
            character in TOKEN_PUNCTUATION

    private fun requireExactlyOneSource(request: HttpRequestData?, requestId: Int?) {
        require((request == null) xor (requestId == null)) {
            "exactly one of 'request' or 'requestId' is required"
        }
    }

    private fun elapsedMillis(startNanos: Long): Long =
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos)

    private companion object {
        val SUPPORTED_SCHEMES = setOf("http", "https")
        val TOKEN_PUNCTUATION = setOf('!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~')
    }
}
