package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.db.HistoryDao
import com.burprest.db.SessionDao
import com.burprest.db.SitemapDao
import com.burprest.models.*
import java.net.URI
import java.util.concurrent.ConcurrentHashMap

class SessionService(
    private val api: MontoyaApi,
    private val historyDao: HistoryDao? = null,
    private val sitemapDao: SitemapDao? = null,
    private val sessionDao: SessionDao? = null,
) {

    // Concurrent maps: Netty dispatches requests on many threads; a plain HashMap could corrupt
    // internally under concurrent set/read. clear()+putAll() is not atomic but no longer corrupts.
    private val sessionCookies = ConcurrentHashMap<String, String>()
    private val sessionHeaders = ConcurrentHashMap<String, String>()
    private var sessionName = "default"

    // Cookie jar: domain -> (name -> value)
    private val cookieJar = ConcurrentHashMap<String, ConcurrentHashMap<String, String>>()

    init {
        // Restore persisted session
        sessionDao?.load()?.let { persisted ->
            sessionName = persisted.name
            sessionCookies.putAll(persisted.cookies)
            sessionHeaders.putAll(persisted.headers)
        }
    }

    fun setSession(request: SetSessionRequest): SessionInfo {
        // Reject cookie names/values that could inject extra cookies or headers into the Cookie line.
        request.cookies.forEach { (name, value) ->
            require(';' !in name && '=' !in name && ';' !in value && '\n' !in name && '\n' !in value) {
                "Invalid cookie '$name': name must not contain ';' or '=', value must not contain ';' or newlines"
            }
        }
        sessionCookies.clear()
        sessionCookies.putAll(request.cookies)
        sessionHeaders.clear()
        request.headers?.let { sessionHeaders.putAll(it) }
        request.name?.let { sessionName = it }
        sessionDao?.save(sessionName, sessionCookies.toMap(), sessionHeaders.toMap())
        return getSession()
    }

    fun getSession(): SessionInfo {
        return SessionInfo(
            name = sessionName,
            cookieCount = sessionCookies.size,
            headerCount = sessionHeaders.size,
            cookies = sessionCookies.toMap(),
            headers = sessionHeaders.toMap(),
        )
    }

    fun clearSession(): SessionInfo {
        sessionCookies.clear()
        sessionHeaders.clear()
        sessionName = "default"
        sessionDao?.clear()
        return getSession()
    }

    fun send(request: AuthenticatedRequest): AuthenticatedResponse {
        var httpReq = HttpRequest.httpRequestFromUrl(request.url)
            .withMethod(request.method)

        // Add session cookies
        if (sessionCookies.isNotEmpty()) {
            val cookieHeader = sessionCookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
            // Remove any existing Cookie first so the session Cookie doesn't become a duplicate header.
            httpReq = httpReq.withRemovedHeader("Cookie").withAddedHeader("Cookie", cookieHeader)
        }

        // Add session headers
        sessionHeaders.forEach { (name, value) ->
            httpReq = httpReq.withRemovedHeader(name).withAddedHeader(name, value)
        }

        // Add per-request extra headers
        request.extraHeaders?.forEach { (name, value) ->
            httpReq = httpReq.withRemovedHeader(name).withAddedHeader(name, value)
        }

        // Add body
        request.body?.let { httpReq = httpReq.withBody(it) }

        val start = System.currentTimeMillis()
        val httpResponse = api.http().sendRequest(httpReq)
        val duration = System.currentTimeMillis() - start

        val resp = httpResponse.response()
        val reqHeaders = httpReq.headers().map { HttpHeader(it.name(), it.value()) }
        val resHeaders = resp.headers().map { HttpHeader(it.name(), it.value()) }
        val resBody = if (resp.body().length() > 0) resp.bodyToString() else null

        // Record to history
        historyDao?.insert(
            source = "session",
            method = request.method,
            url = request.url,
            reqHeaders = reqHeaders,
            reqBody = request.body,
            statusCode = resp.statusCode().toInt(),
            resHeaders = resHeaders,
            resBody = resBody,
            durationMs = duration,
        )
        sitemapDao?.upsert(request.url, request.method)

        // Auto-capture Set-Cookie headers into cookie jar
        captureCookies(request.url, resHeaders)

        return AuthenticatedResponse(
            statusCode = resp.statusCode().toInt(),
            headers = resHeaders,
            body = resBody,
            durationMs = duration,
        )
    }

    private fun captureCookies(url: String, headers: List<HttpHeader>) {
        val domain = try { URI(url).host ?: return } catch (_: Exception) { return }
        headers.filter { it.name.equals("Set-Cookie", ignoreCase = true) }.forEach { h ->
            val parts = h.value.split(";")[0].split("=", limit = 2)
            if (parts.size == 2) {
                cookieJar.getOrPut(domain) { ConcurrentHashMap() }[parts[0].trim()] = parts[1].trim()
            }
        }
    }

    fun getCookieJar(): CookieJarResponse {
        val entries = cookieJar.flatMap { (domain, cookies) ->
            cookies.map { (name, value) -> CookieEntry(domain, name, value) }
        }
        return CookieJarResponse(cookies = entries, total = entries.size)
    }

    fun clearCookieJar(): CookieJarResponse {
        cookieJar.clear()
        return CookieJarResponse(cookies = emptyList(), total = 0)
    }

    fun sendBatch(batch: BatchAuthenticatedRequest): BatchAuthenticatedResponse {
        val start = System.currentTimeMillis()
        val results = batch.requests.map { send(it) }
        val totalDuration = System.currentTimeMillis() - start
        return BatchAuthenticatedResponse(
            results = results,
            totalDurationMs = totalDuration,
        )
    }
}
