package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.db.HistoryDao
import com.burprest.db.SessionDao
import com.burprest.models.AuthenticatedRequest
import com.burprest.models.AuthenticatedResponse
import com.burprest.models.BatchAuthenticatedRequest
import com.burprest.models.BatchAuthenticatedResponse
import com.burprest.models.CookieEntry
import com.burprest.models.CookieJarResponse
import com.burprest.models.HttpHeader
import com.burprest.models.PersistenceStatus
import com.burprest.models.SessionInfo
import com.burprest.models.SessionPersistence
import com.burprest.models.SetSessionRequest
import com.burprest.server.NoResponseException
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Collections
import java.util.LinkedHashMap
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal enum class CredentialMode { FULL, COOKIES_ONLY, NONE }

class SessionService(
    private val api: MontoyaApi,
    private val historyDao: HistoryDao? = null,
    private val sitemapDao: com.burprest.db.SitemapDao? = null,
    private val sessionDao: SessionDao? = null,
    private val clock: () -> Long = System::currentTimeMillis,
    private val requestFactory: (String) -> HttpRequest = { HttpRequest.httpRequestFromUrl(it) },
) {
    private data class Origin(
        val scheme: String,
        val host: String,
        val port: Int,
    ) {
        fun externalForm(): String {
            val renderedHost = if (':' in host) "[$host]" else host
            val defaultPort = if (scheme == "https") 443 else 80
            val renderedPort = if (port == defaultPort) "" else ":$port"
            return "$scheme://$renderedHost$renderedPort"
        }
    }

    private data class ParsedHttpUri(
        val uri: URI,
        val scheme: String,
        val host: String,
        val explicitPort: Int?,
    )

    private data class Target(
        val origin: Origin,
        val requestPath: String,
    )

    private data class SessionSnapshot(
        val name: String,
        val cookies: Map<String, String>,
        val headers: Map<String, String>,
        val origin: Origin?,
    ) {
        fun hasCredentials(): Boolean = cookies.isNotEmpty() || headers.isNotEmpty()
    }

    private data class StoredCookie(
        val domain: String,
        val name: String,
        val value: String,
        val path: String,
        val secure: Boolean,
        val expiresAt: Long?,
        val hostOnly: Boolean,
        val creationIndex: Long,
    )

    private data class CookieKey(val name: String, val domain: String, val path: String)

    private val sessionMutationLock = Any()
    private val cookieMutationLock = Any()
    private val cookieSequence = AtomicLong()
    private val cookieJar = AtomicReference<List<StoredCookie>>(emptyList())
    private val session = AtomicReference(loadSession())

    fun setSession(request: SetSessionRequest): SessionInfo {
        val cookies = immutableCopy(request.cookies)
        val headers = immutableCopy(request.headers.orEmpty())
        validateCookies(cookies)
        validateHeaders(headers)
        val requestedOrigin = request.origin?.let(::parseOrigin)

        return synchronized(sessionMutationLock) {
            val current = session.get()
            val next = SessionSnapshot(
                name = request.name ?: current.name,
                cookies = cookies,
                headers = headers,
                origin = requestedOrigin,
            )
            persist(next)
            session.set(next)
            next.toInfo()
        }
    }

    fun getSession(): SessionInfo = session.get().toInfo()

    fun clearSession(): SessionInfo = synchronized(sessionMutationLock) {
        val next = emptySession()
        sessionDao?.clear()
        session.set(next)
        next.toInfo()
    }

    /**
     * Sends with one immutable snapshot of the configured session. If old persisted credentials do
     * not yet have an origin, their first use is serialized and persisted before they are published
     * or sent.
     */
    fun send(request: AuthenticatedRequest): AuthenticatedResponse {
        val target = validateRequest(request)
        val snapshot = snapshotForAuthenticatedSend(target.origin, CredentialMode.FULL)
        return execute(
            request = request,
            target = target,
            authSnapshot = snapshot,
            credentialMode = CredentialMode.FULL,
            orderedHeaders = emptyList(),
            credentialHeaderNames = snapshot.headers.keys.lowercaseNames(),
            captureResponseCookies = true,
        )
    }

    /**
     * Sends without reading or applying configured session credentials or observed cookies, and does
     * not capture response cookies. This is intended for cross-origin supporting-resource fetches.
     */
    fun sendUnauthenticated(request: AuthenticatedRequest): AuthenticatedResponse {
        val target = validateRequest(request)
        val credentialHeaderNames = snapshotCredentialHeaderNames()
        return execute(
            request = request,
            target = target,
            authSnapshot = null,
            credentialMode = CredentialMode.NONE,
            orderedHeaders = emptyList(),
            credentialHeaderNames = credentialHeaderNames,
            captureResponseCookies = false,
        )
    }

    /**
     * Internal scan integration that preserves repeated source headers while still routing all
     * credential decisions through the same atomic origin-bound session snapshot as [send].
     */
    internal fun sendPreservingHeaders(
        request: AuthenticatedRequest,
        headers: List<HttpHeader>,
        credentialMode: CredentialMode,
        persistObservation: Boolean = true,
    ): AuthenticatedResponse {
        val target = validateRequest(request)
        headers.forEach { validateHeader(it.name, it.value) }
        val snapshot = when (credentialMode) {
            CredentialMode.FULL, CredentialMode.COOKIES_ONLY ->
                snapshotForAuthenticatedSend(target.origin, credentialMode)
            CredentialMode.NONE -> null
        }
        val credentialHeaderNames = snapshot?.headers?.keys?.lowercaseNames()
            ?: snapshotCredentialHeaderNames()
        return execute(
            request = request,
            target = target,
            authSnapshot = snapshot,
            credentialMode = credentialMode,
            orderedHeaders = headers,
            credentialHeaderNames = credentialHeaderNames,
            captureResponseCookies = false,
            persistObservation = persistObservation,
        )
    }

    fun getCookieJar(): CookieJarResponse {
        val cookies = synchronized(cookieMutationLock) {
            val now = clock()
            val current = cookieJar.get()
            val live = current.filterNot { it.isExpired(now) }
            if (live.size != current.size) cookieJar.set(live)
            live
        }
        val entries = cookies
            .sortedWith(compareBy<StoredCookie>({ it.domain }, { it.path }, { it.name }))
            .map { cookie ->
                CookieEntry(
                    domain = cookie.domain,
                    name = cookie.name,
                    value = cookie.value,
                    path = cookie.path,
                    secure = cookie.secure,
                    expiresAt = cookie.expiresAt,
                    hostOnly = cookie.hostOnly,
                )
            }
        return CookieJarResponse(cookies = entries, total = entries.size)
    }

    fun clearCookieJar(): CookieJarResponse {
        synchronized(cookieMutationLock) { cookieJar.set(emptyList()) }
        return CookieJarResponse(cookies = emptyList(), total = 0)
    }

    fun sendBatch(batch: BatchAuthenticatedRequest): BatchAuthenticatedResponse {
        require(batch.requests.isNotEmpty()) { "requests must not be empty" }
        val targets = batch.requests.mapIndexed { index, request ->
            try {
                validateRequest(request)
            } catch (failure: IllegalArgumentException) {
                throw IllegalArgumentException("requests[$index]: ${failure.message ?: "invalid request"}", failure)
            }
        }

        // Hold the mutation monitor from origin preflight through the sequential sends. This prevents a
        // concurrent replacement from making a later batch item fail only after earlier target effects.
        return synchronized(sessionMutationLock) {
            preflightBatchOrigins(targets)
            val start = clock()
            val results = batch.requests.map(::send)
            BatchAuthenticatedResponse(
                results = results,
                totalDurationMs = elapsedSince(start),
            )
        }
    }

    private fun loadSession(): SessionSnapshot {
        val persisted = sessionDao?.load() ?: return emptySession()
        val cookies = immutableCopy(persisted.cookies)
        val headers = immutableCopy(persisted.headers)
        validateCookies(cookies)
        validateHeaders(headers)
        return SessionSnapshot(
            name = persisted.name,
            cookies = cookies,
            headers = headers,
            origin = persisted.boundOrigin?.let(::parseOrigin),
        )
    }

    private fun emptySession() = SessionSnapshot(
        name = "default",
        cookies = emptyMap(),
        headers = emptyMap(),
        origin = null,
    )

    private fun persist(snapshot: SessionSnapshot) {
        sessionDao?.save(
            snapshot.name,
            snapshot.cookies,
            snapshot.headers,
            snapshot.origin?.externalForm(),
        )
    }

    private fun preflightBatchOrigins(targets: List<Target>) {
        // Caller holds sessionMutationLock. Validation does not bind or persist: the first actual send
        // owns that mutation, after all batch rejection conditions have been settled.
        val current = session.get()
        if (!current.hasCredentials()) return
        val distinctOrigins = targets.map { it.origin }.distinct()
        val bound = current.origin
        if (bound != null) {
            require(distinctOrigins.all { it == bound }) {
                "Session credentials are bound to ${bound.externalForm()}; batch contains another origin"
            }
        } else {
            require(distinctOrigins.size <= 1) {
                "Unbound session credentials cannot be sent to multiple origins in one batch"
            }
        }
    }

    private fun snapshotCredentialHeaderNames(): Set<String> = synchronized(sessionMutationLock) {
        session.get().headers.keys.lowercaseNames()
    }

    private fun snapshotForAuthenticatedSend(
        targetOrigin: Origin,
        credentialMode: CredentialMode,
    ): SessionSnapshot = synchronized(sessionMutationLock) {
        // This is the sole session-state read performed for this send.
        val current = session.get()
        val hasApplicableCredentials = when (credentialMode) {
            CredentialMode.FULL -> current.hasCredentials()
            CredentialMode.COOKIES_ONLY -> current.cookies.isNotEmpty()
            CredentialMode.NONE -> false
        }
        if (!hasApplicableCredentials) return@synchronized current

        val bound = current.origin
        if (bound != null) {
            require(bound == targetOrigin) {
                "Session credentials are bound to ${bound.externalForm()}, not ${targetOrigin.externalForm()}"
            }
            return@synchronized current
        }

        val boundSnapshot = current.copy(origin = targetOrigin)
        persist(boundSnapshot)
        session.set(boundSnapshot)
        boundSnapshot
    }

    private fun execute(
        request: AuthenticatedRequest,
        target: Target,
        authSnapshot: SessionSnapshot?,
        credentialMode: CredentialMode,
        orderedHeaders: List<HttpHeader>,
        credentialHeaderNames: Set<String>,
        captureResponseCookies: Boolean,
        persistObservation: Boolean = true,
    ): AuthenticatedResponse {
        var httpRequest = requestFactory(request.url).withMethod(request.method)

        if (authSnapshot != null) {
            val jarCookies = if (credentialMode == CredentialMode.FULL) matchingCookies(target) else emptyList()
            val configuredNames = authSnapshot.cookies.keys
            val cookiePairs = buildList {
                jarCookies
                    .filterNot { it.name in configuredNames }
                    .forEach { add("${it.name}=${it.value}") }
                authSnapshot.cookies.forEach { (name, value) -> add("$name=$value") }
            }
            if (cookiePairs.isNotEmpty()) {
                httpRequest = httpRequest
                    .withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", cookiePairs.joinToString("; "))
            }

            if (credentialMode == CredentialMode.FULL) {
                authSnapshot.headers.forEach { (name, value) ->
                    httpRequest = httpRequest.withRemovedHeader(name).withAddedHeader(name, value)
                }
            }
        } else {
            // Defend against any Cookie header a request implementation might synthesize.
            httpRequest = httpRequest.withRemovedHeader("Cookie")
        }

        // Raw scan requests regenerate standard credentials above. Preserve only their ordered,
        // noncredential source headers, including duplicates, after applying the session snapshot.
        val prohibitedPreservedHeaders = CREDENTIAL_HEADER_NAMES + credentialHeaderNames
        val preservedHeaders = orderedHeaders.filterNot { header ->
            header.name.lowercase(Locale.ROOT) in prohibitedPreservedHeaders
        }
        preservedHeaders
            .map { it.name.lowercase(Locale.ROOT) }
            .distinct()
            .forEach { name -> httpRequest = httpRequest.withRemovedHeader(name) }
        preservedHeaders.forEach { header ->
            httpRequest = httpRequest.withAddedHeader(header.name, header.value)
        }

        request.extraHeaders.orEmpty().forEach { (name, value) ->
            httpRequest = httpRequest.withRemovedHeader(name).withAddedHeader(name, value)
        }
        when (credentialMode) {
            CredentialMode.NONE -> (UNAUTHENTICATED_HEADER_DENYLIST + credentialHeaderNames).forEach { name ->
                httpRequest = httpRequest.withRemovedHeader(name)
            }
            CredentialMode.COOKIES_ONLY -> (AUTHORIZATION_HEADER_DENYLIST + credentialHeaderNames).forEach { name ->
                httpRequest = httpRequest.withRemovedHeader(name)
            }
            CredentialMode.FULL -> Unit
        }
        request.body?.let { httpRequest = httpRequest.withBody(it) }

        val start = clock()
        val exchange = api.http().sendRequest(httpRequest)
        val duration = elapsedSince(start)
        if (!exchange.hasResponse()) {
            throw NoResponseException("target send completed without an upstream response")
        }
        val response = exchange.response()
            ?: throw NoResponseException("target send completed without an upstream response")
        val requestHeaders = httpRequest.headers().map { HttpHeader(it.name(), it.value()) }
        val responseHeaders = response.headers().map { HttpHeader(it.name(), it.value()) }
        val responseBody = if (response.body().length() > 0) response.bodyToString() else null

        val persistence = if (persistObservation) {
            recordObservation(
                request = request,
                requestHeaders = requestHeaders,
                statusCode = response.statusCode().toInt(),
                responseHeaders = responseHeaders,
                responseBody = responseBody,
                durationMs = duration,
            )
        } else {
            SessionPersistence.notConfigured()
        }

        if (captureResponseCookies) captureCookies(target, responseHeaders)

        return AuthenticatedResponse(
            statusCode = response.statusCode().toInt(),
            headers = responseHeaders,
            body = responseBody,
            durationMs = duration,
            hasResponse = true,
            persistence = persistence,
        )
    }

    private fun recordObservation(
        request: AuthenticatedRequest,
        requestHeaders: List<HttpHeader>,
        statusCode: Int,
        responseHeaders: List<HttpHeader>,
        responseBody: String?,
        durationMs: Long,
    ): SessionPersistence {
        if (historyDao == null && sitemapDao == null) return SessionPersistence.notConfigured()

        if (historyDao != null && sitemapDao != null) {
            return try {
                val historyId = historyDao.insertWithSitemap(
                    sitemapDao = sitemapDao,
                    source = "session",
                    method = request.method,
                    url = request.url,
                    reqHeaders = requestHeaders,
                    reqBody = request.body,
                    statusCode = statusCode,
                    resHeaders = responseHeaders,
                    resBody = responseBody,
                    durationMs = durationMs,
                )
                SessionPersistence(
                    status = PersistenceStatus.PERSISTED,
                    historyPersisted = true,
                    sitemapPersisted = true,
                    historyId = historyId,
                )
            } catch (_: Exception) {
                persistenceFailure(
                    "Target send completed, but optional history and sitemap persistence failed; do not retry the target send."
                )
            }
        }

        return if (historyDao != null) {
            try {
                val historyId = historyDao.insert(
                    source = "session",
                    method = request.method,
                    url = request.url,
                    reqHeaders = requestHeaders,
                    reqBody = request.body,
                    statusCode = statusCode,
                    resHeaders = responseHeaders,
                    resBody = responseBody,
                    durationMs = durationMs,
                )
                SessionPersistence(
                    status = PersistenceStatus.PARTIAL,
                    historyPersisted = true,
                    historyId = historyId,
                    warning = "Target send completed and history was persisted, but sitemap persistence is not configured.",
                )
            } catch (_: Exception) {
                persistenceFailure(
                    "Target send completed, but optional history persistence failed; do not retry the target send."
                )
            }
        } else {
            try {
                requireNotNull(sitemapDao).upsert(request.url, request.method)
                SessionPersistence(
                    status = PersistenceStatus.PARTIAL,
                    sitemapPersisted = true,
                    warning = "Target send completed and sitemap was persisted, but history persistence is not configured.",
                )
            } catch (_: Exception) {
                persistenceFailure(
                    "Target send completed, but optional sitemap persistence failed; do not retry the target send."
                )
            }
        }
    }

    private fun persistenceFailure(warning: String): SessionPersistence {
        runCatching { api.logging().logToError("[burp-rest] $warning") }
        return SessionPersistence(status = PersistenceStatus.FAILED, warning = warning)
    }

    private fun validateRequest(request: AuthenticatedRequest): Target {
        require(TOKEN.matches(request.method)) { "Invalid HTTP method" }
        validateHeaders(request.extraHeaders.orEmpty())
        return parseTarget(request.url)
    }

    private fun validateCookies(cookies: Map<String, String>) {
        cookies.forEach { (name, value) ->
            require(TOKEN.matches(name)) { "Invalid cookie name '$name'" }
            require(isCookieValue(value)) { "Invalid cookie value for '$name'" }
        }
    }

    private fun validateHeaders(headers: Map<String, String>) {
        headers.forEach { (name, value) ->
            require(TOKEN.matches(name)) { "Invalid HTTP header name '$name'" }
            require(value.none { it == '\u0000' || it == '\r' || it == '\n' || it == '\u007f' || (it < ' ' && it != '\t') }) {
                "Invalid HTTP header value for '$name'"
            }
        }
    }

    private fun validateHeader(name: String, value: String) {
        require(TOKEN.matches(name)) { "Invalid HTTP header name '$name'" }
        require(value.none { char ->
            char == '\u0000' || char == '\r' || char == '\n' || char == '\u007f' ||
                (char < ' ' && char != '\t')
        }) { "Invalid HTTP header value for '$name'" }
    }

    private fun isCookieValue(value: String): Boolean {
        val unquoted = if (value.length >= 2 && value.first() == '"' && value.last() == '"') {
            value.substring(1, value.lastIndex)
        } else {
            value
        }
        if ('"' in unquoted) return false
        return unquoted.all { char ->
            val code = char.code
            code == 0x21 || code in 0x23..0x2b || code in 0x2d..0x3a ||
                code in 0x3c..0x5b || code in 0x5d..0x7e
        }
    }

    private fun parseOrigin(value: String): Origin {
        val parsed = parseHttpUri(value, "origin")
        require(parsed.uri.rawQuery == null && parsed.uri.rawFragment == null) { "Invalid HTTP origin" }
        require(parsed.uri.rawPath.isNullOrEmpty() || parsed.uri.rawPath == "/") { "Invalid HTTP origin" }
        return originOf(parsed)
    }

    private fun parseTarget(value: String): Target {
        val parsed = parseHttpUri(value, "URL")
        require(parsed.uri.rawFragment == null) { "Invalid HTTP URL" }
        val path = parsed.uri.rawPath?.takeIf { it.startsWith('/') } ?: "/"
        return Target(originOf(parsed), path)
    }

    private fun parseHttpUri(value: String, description: String): ParsedHttpUri {
        val uri = try {
            URI(value)
        } catch (failure: Exception) {
            throw IllegalArgumentException("Invalid HTTP $description", failure)
        }
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
            ?: throw IllegalArgumentException("Invalid HTTP $description")
        require(scheme == "http" || scheme == "https") { "Invalid HTTP $description" }
        require(uri.isAbsolute && uri.rawUserInfo == null) { "Invalid HTTP $description" }
        val authority = uri.rawAuthority ?: throw IllegalArgumentException("Invalid HTTP $description")
        require('@' !in authority) { "Invalid HTTP $description" }

        val (rawHost, explicitPort) = if (uri.host != null) {
            uri.host to uri.port.takeIf { it >= 0 }
        } else {
            require(!authority.startsWith('[') && ':' !in authority.dropLastWhile(Char::isDigit).removeSuffix(":")) {
                "Invalid HTTP $description"
            }
            val separator = authority.lastIndexOf(':')
            if (separator >= 0) {
                val portText = authority.substring(separator + 1)
                require(portText.isNotEmpty() && portText.all(Char::isDigit)) { "Invalid HTTP $description port" }
                authority.substring(0, separator) to (portText.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid HTTP $description port"))
            } else {
                authority to null
            }
        }
        require(explicitPort == null || explicitPort in 1..65535) { "Invalid HTTP $description port" }
        val host = normalizeHost(rawHost)
        return ParsedHttpUri(uri, scheme, host, explicitPort)
    }

    private fun originOf(parsed: ParsedHttpUri): Origin {
        val port = parsed.explicitPort ?: if (parsed.scheme == "https") 443 else 80
        return Origin(parsed.scheme, parsed.host, port)
    }

    private fun normalizeHost(rawHost: String): String {
        val host = rawHost.removePrefix("[").removeSuffix("]")
        require(host.isNotEmpty() && '%' !in host) { "Invalid HTTP host" }
        if (':' in host) {
            val address = try {
                InetAddress.getByName(host)
            } catch (failure: Exception) {
                throw IllegalArgumentException("Invalid IPv6 host", failure)
            }
            require(address is Inet6Address) { "Invalid IPv6 host" }
            return address.hostAddress.lowercase(Locale.ROOT)
        }
        if (host.all { it.isDigit() || it == '.' } && host.any(Char::isDigit)) {
            val address = try {
                InetAddress.getByName(host)
            } catch (failure: Exception) {
                throw IllegalArgumentException("Invalid IPv4 host", failure)
            }
            require(address is Inet4Address) { "Invalid IPv4 host" }
            return address.hostAddress
        }
        val ascii = try {
            IDN.toASCII(host.trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
        } catch (failure: Exception) {
            throw IllegalArgumentException("Invalid HTTP host", failure)
        }
        require(ascii.isNotEmpty()) { "Invalid HTTP host" }
        return ascii.lowercase(Locale.ROOT)
    }

    private fun captureCookies(target: Target, headers: List<HttpHeader>) {
        val setCookieValues = headers
            .asSequence()
            .filter { it.name.equals("Set-Cookie", ignoreCase = true) }
            .map { it.value }
            .toList()
        if (setCookieValues.isEmpty()) return

        synchronized(cookieMutationLock) {
            val now = clock()
            val mutable = LinkedHashMap<CookieKey, StoredCookie>()
            cookieJar.get().filterNot { it.isExpired(now) }.forEach { cookie ->
                mutable[CookieKey(cookie.name, cookie.domain, cookie.path)] = cookie
            }
            setCookieValues.forEach { value -> applySetCookie(value, target, now, mutable) }
            cookieJar.set(mutable.values.toList())
        }
    }

    private fun applySetCookie(
        headerValue: String,
        target: Target,
        now: Long,
        jar: MutableMap<CookieKey, StoredCookie>,
    ) {
        val segments = headerValue.split(';')
        val first = segments.firstOrNull()?.trim().orEmpty()
        val equals = first.indexOf('=')
        if (equals <= 0) return
        val name = first.substring(0, equals).trim()
        val value = first.substring(equals + 1).trim()
        if (!TOKEN.matches(name) || !isCookieValue(value)) return

        var domain = target.origin.host
        var hostOnly = true
        var path = defaultCookiePath(target.requestPath)
        var secure = false
        var expiresAt: Long? = null
        var validMaxAge: Long? = null
        var invalid = false

        segments.drop(1).forEach { rawAttribute ->
            val attribute = rawAttribute.trim()
            if (attribute.isEmpty()) return@forEach
            val separator = attribute.indexOf('=')
            val attributeName = (if (separator < 0) attribute else attribute.substring(0, separator))
                .trim()
                .lowercase(Locale.ROOT)
            val attributeValue = if (separator < 0) "" else attribute.substring(separator + 1).trim()
            when (attributeName) {
                "domain" -> {
                    if (attributeValue.isEmpty() || attributeValue.endsWith('.')) {
                        invalid = true
                    } else {
                        val candidate = try {
                            normalizeHost(attributeValue.trimStart('.'))
                        } catch (_: IllegalArgumentException) {
                            invalid = true
                            return@forEach
                        }
                        if (!domainMatches(target.origin.host, candidate, hostOnly = false)) {
                            invalid = true
                        } else {
                            domain = candidate
                            hostOnly = false
                        }
                    }
                }
                "path" -> if (attributeValue.startsWith('/')) path = attributeValue
                "secure" -> secure = true
                "max-age" -> attributeValue.toLongOrNull()?.let { validMaxAge = it }
                "expires" -> parseCookieDate(attributeValue)?.let { expiresAt = it }
            }
        }
        if (invalid) return
        if (name.startsWith("__Secure-") && (!secure || target.origin.scheme != "https")) return
        if (name.startsWith("__Host-") && (!secure || target.origin.scheme != "https" || !hostOnly || path != "/")) return

        if (validMaxAge != null) expiresAt = maxAgeExpiry(now, validMaxAge!!)
        val key = CookieKey(name, domain, path)
        if (expiresAt != null && expiresAt!! <= now) {
            jar.remove(key)
            return
        }

        val prior = jar[key]
        jar[key] = StoredCookie(
            domain = domain,
            name = name,
            value = value,
            path = path,
            secure = secure,
            expiresAt = expiresAt,
            hostOnly = hostOnly,
            creationIndex = prior?.creationIndex ?: cookieSequence.getAndIncrement(),
        )
    }

    private fun matchingCookies(target: Target): List<StoredCookie> {
        val now = clock()
        return cookieJar.get()
            .asSequence()
            .filterNot { it.isExpired(now) }
            .filter { !it.secure || target.origin.scheme == "https" }
            .filter { domainMatches(target.origin.host, it.domain, it.hostOnly) }
            .filter { pathMatches(target.requestPath, it.path) }
            .sortedWith(compareByDescending<StoredCookie> { it.path.length }.thenBy { it.creationIndex })
            .toList()
    }

    private fun StoredCookie.isExpired(now: Long): Boolean = expiresAt?.let { it <= now } ?: false

    private fun domainMatches(host: String, cookieDomain: String, hostOnly: Boolean): Boolean {
        if (host == cookieDomain) return true
        if (hostOnly || isIpAddress(host) || isIpAddress(cookieDomain)) return false
        return host.endsWith(".$cookieDomain")
    }

    private fun isIpAddress(host: String): Boolean = ':' in host || host.all { it.isDigit() || it == '.' }

    private fun pathMatches(requestPath: String, cookiePath: String): Boolean {
        if (requestPath == cookiePath) return true
        if (!requestPath.startsWith(cookiePath)) return false
        return cookiePath.endsWith('/') || requestPath.getOrNull(cookiePath.length) == '/'
    }

    private fun defaultCookiePath(requestPath: String): String {
        if (!requestPath.startsWith('/') || requestPath.count { it == '/' } <= 1) return "/"
        return requestPath.substringBeforeLast('/').ifEmpty { "/" }
    }

    private fun parseCookieDate(value: String): Long? = try {
        ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
    } catch (_: DateTimeParseException) {
        null
    }

    private fun maxAgeExpiry(now: Long, seconds: Long): Long {
        if (seconds <= 0) return Long.MIN_VALUE
        val millis = if (seconds > Long.MAX_VALUE / 1_000) Long.MAX_VALUE else seconds * 1_000
        return if (millis == Long.MAX_VALUE || now > Long.MAX_VALUE - millis) Long.MAX_VALUE else now + millis
    }

    private fun elapsedSince(start: Long): Long = (clock() - start).coerceAtLeast(0)

    private fun SessionSnapshot.toInfo() = SessionInfo(
        name = name,
        cookieCount = cookies.size,
        headerCount = headers.size,
        cookies = cookies,
        headers = headers,
        origin = origin?.externalForm(),
    )

    private fun Iterable<String>.lowercaseNames(): Set<String> =
        mapTo(linkedSetOf()) { it.lowercase(Locale.ROOT) }

    private fun <K, V> immutableCopy(source: Map<K, V>): Map<K, V> =
        Collections.unmodifiableMap(LinkedHashMap(source))

    private companion object {
        val TOKEN = Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        val UNAUTHENTICATED_HEADER_DENYLIST = listOf("Cookie", "Authorization", "Proxy-Authorization")
        val AUTHORIZATION_HEADER_DENYLIST = listOf("Authorization", "Proxy-Authorization")
        val CREDENTIAL_HEADER_NAMES = UNAUTHENTICATED_HEADER_DENYLIST.map { it.lowercase(Locale.ROOT) }.toSet()
    }
}
