package com.burprest.services

import burp.api.montoya.MontoyaApi
import com.burprest.db.HistoryDao
import com.burprest.db.HistoryEntry
import com.burprest.db.HistoryFilter
import com.burprest.models.*
import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.util.Locale

open class SecurityScanService(
    private val api: MontoyaApi,
    private val sessionService: SessionService,
    private val historyDao: HistoryDao?,
) {

    /** A transport failure has no HTTP status. [error] makes that state explicit. */
    internal data class RawProbe(
        val status: Int?,
        val bodyText: String,
        val durationMs: Long,
        val error: String? = null,
        val inconclusiveReason: String? = null,
    ) {
        init {
            require(status == null || status in 100..599) { "probe status must be a real HTTP status" }
            require((status == null) == (error != null)) {
                "a probe must have either an HTTP status or an explicit error"
            }
            require(error == null || inconclusiveReason == null) {
                "a transport error must not also carry an HTTP inconclusive reason"
            }
        }

        val failed: Boolean get() = error != null
        private val effectiveInconclusiveReason: String?
            get() = inconclusiveReason ?: transientReasonFor(status)
        val inconclusive: Boolean get() = failed || effectiveInconclusiveReason != null

        fun toProbeResult() = AuthBypassProbeResult(
            status = status,
            length = bodyText.length,
            durationMs = durationMs,
            error = error,
            inconclusiveReason = effectiveInconclusiveReason,
        )
    }

    /** Exact request identity retained from extension-owned H2 history. */
    internal data class EndpointRequest(
        val method: String,
        val url: String,
        val headers: List<HttpHeader>,
        val body: String?,
    )

    fun authBypass(request: AuthBypassRequest): AuthBypassResponse {
        val method = validatedMethod(request.method, "method")
        require(request.endpoints.size in 1..MAX_PLAN_ITEMS) {
            "endpoints must contain between 1 and $MAX_PLAN_ITEMS entries"
        }
        val baseUrl = validatedHttpUrl(request.baseUrl, "baseUrl")
        require(URI(baseUrl).rawQuery == null) { "baseUrl must not contain a query" }

        // Validate and materialize the complete plan before the first probe. A bad later
        // endpoint must not leave earlier endpoints already sent.
        val plan = request.endpoints.mapIndexed { index, endpoint ->
            require(endpoint.isNotBlank()) { "endpoints[$index] must not be blank" }
            require(!containsUnsafeText(endpoint)) { "endpoints[$index] contains unsafe characters" }
            require(endpoint.startsWith('/') && !endpoint.startsWith("//")) {
                "endpoints[$index] must be an absolute path beginning with one '/'"
            }
            val endpointUri = runCatching { URI(endpoint) }.getOrElse {
                throw IllegalArgumentException("endpoints[$index] must be a valid relative URL path")
            }
            require(!endpointUri.isAbsolute && endpointUri.rawAuthority == null && endpointUri.rawFragment == null) {
                "endpoints[$index] must not change authority or contain a fragment"
            }
            endpoint to validatedHttpUrl(baseUrl.trimEnd('/') + endpoint, "endpoints[$index]")
        }

        val results = plan.map { (endpoint, url) ->
            val withAuthRaw = probeWithAuthRaw(url, method)
            val withoutAuthRaw = probeNoAuthRaw(url, method)
            val cookieOnly = probeCookieOnly(url, method)
            val errors = buildList {
                withAuthRaw.issue("authenticated control", requireSubstantive = true)?.let(::add)
                withoutAuthRaw.issue("unauthenticated probe")?.let(::add)
                if (cookieOnly.inconclusive) {
                    add("cookie-only probe: ${cookieOnly.error ?: cookieOnly.inconclusiveReason ?: "inconclusive"}")
                } else if (cookieOnly.status.isTransientFailure()) {
                    add("cookie-only probe returned HTTP ${cookieOnly.status}")
                }
            }
            val baselineSubstantive = !withAuthRaw.inconclusive &&
                withAuthRaw.status.isSubstantiveSuccess(withAuthRaw.bodyText)
            val vulnerable = !withAuthRaw.inconclusive && !withoutAuthRaw.inconclusive &&
                !withoutAuthRaw.status.isTransientFailure() && baselineSubstantive &&
                withoutAuthRaw.status.isSuccess() &&
                contentSimilar(withAuthRaw.bodyText, withoutAuthRaw.bodyText)
            val inconclusive = withAuthRaw.inconclusive || withoutAuthRaw.inconclusive ||
                cookieOnly.inconclusive || !baselineSubstantive || withoutAuthRaw.status.isTransientFailure()

            AuthBypassEndpointResult(
                endpoint = endpoint,
                withAuth = withAuthRaw.toProbeResult(),
                withoutAuth = withoutAuthRaw.toProbeResult(),
                cookieOnly = cookieOnly,
                vulnerable = vulnerable,
                inconclusive = inconclusive,
                errors = errors,
            )
        }

        return AuthBypassResponse(
            results = results,
            totalScanned = results.size,
            vulnerableCount = results.count { it.vulnerable },
            inconclusiveCount = results.count { it.inconclusive },
        )
    }

    fun idor(request: IdorRequest): IdorResponse {
        val method = validatedMethod(request.method, "method")
        require(request.param.isNotBlank()) { "param must not be blank" }
        require(PARAM_NAME.matches(request.param)) { "param contains unsafe characters" }
        require(request.ownValues.size in 1..MAX_PLAN_ITEMS) {
            "ownValues must contain between 1 and $MAX_PLAN_ITEMS entries"
        }
        require(request.targetValues.size in 1..MAX_PLAN_ITEMS) {
            "targetValues must contain between 1 and $MAX_PLAN_ITEMS entries"
        }
        request.ownValues.forEachIndexed { index, value -> validateParameterValue(value, "ownValues[$index]") }
        request.targetValues.forEachIndexed { index, value -> validateParameterValue(value, "targetValues[$index]") }
        validateBody(request.body)
        validateHeaders(request.extraHeaders.orEmpty().map { HttpHeader(it.key, it.value) }, "extraHeaders")

        // Validate every substituted URL before any send. This also permits the documented
        // {param} template while still checking the concrete wire targets.
        val ownUrls = request.ownValues.mapIndexed { index, value ->
            validatedHttpUrl(substituteParam(request.endpoint, request.param, value), "ownValues[$index] URL")
        }
        val targetUrls = request.targetValues.mapIndexed { index, value ->
            validatedHttpUrl(substituteParam(request.endpoint, request.param, value), "targetValues[$index] URL")
        }

        val baselineOrigin = normalizedOrigin(ownUrls.first())
        require((ownUrls + targetUrls).all { normalizedOrigin(it) == baselineOrigin }) {
            "all ownValues and targetValues must resolve to the same HTTP origin"
        }

        val ignoredOwnValues = request.ownValues.drop(1)
        val note = "Reports any cross-object access regardless of privilege direction; " +
            "verify findings manually to confirm whether direction implies a real security issue."

        val baselineRaw = sendAuthenticated(
            AuthenticatedRequest(method, ownUrls.first(), request.body, request.extraHeaders)
        )
        val baselineSucceeded = !baselineRaw.inconclusive && baselineRaw.status.isSuccess()
        val baseline = IdorProbeResult(
            value = request.ownValues.first(),
            status = baselineRaw.status,
            length = baselineRaw.bodyText.length,
            bodyPreview = baselineRaw.bodyText.take(200).ifEmpty { null },
            sameAsBaseline = true,
            vulnerable = false,
            inconclusive = baselineRaw.inconclusive || !baselineSucceeded || baselineRaw.status.isTransientFailure(),
            error = baselineRaw.error ?: baselineRaw.inconclusiveReason ?: baselineRaw.status.transientReason(),
        )

        val results = if (baselineRaw.inconclusive || baselineRaw.status.isTransientFailure()) {
            request.targetValues.map { value ->
                IdorProbeResult(
                    value = value,
                    status = null,
                    length = 0,
                    bodyPreview = null,
                    sameAsBaseline = false,
                    vulnerable = false,
                    inconclusive = true,
                    error = "not sent because the baseline probe failed",
                )
            }
        } else {
            request.targetValues.zip(targetUrls).map { (targetValue, url) ->
                val raw = sendAuthenticated(AuthenticatedRequest(method, url, request.body, request.extraHeaders))
                if (raw.inconclusive || raw.status.isTransientFailure()) {
                    IdorProbeResult(
                        value = targetValue,
                        status = raw.status,
                        length = raw.bodyText.length,
                        bodyPreview = raw.bodyText.take(200).ifEmpty { null },
                        sameAsBaseline = false,
                        vulnerable = false,
                        inconclusive = true,
                        error = raw.error ?: raw.inconclusiveReason ?: raw.status.transientReason(),
                    )
                } else {
                    val sameAsBaseline = bodiesEqualForIdor(baselineRaw.bodyText, raw.bodyText)
                    val vulnerable = baselineSucceeded && !sameAsBaseline &&
                        raw.status.isSuccess() && raw.bodyText.isNotEmpty()
                    IdorProbeResult(
                        value = targetValue,
                        status = raw.status,
                        length = raw.bodyText.length,
                        bodyPreview = raw.bodyText.take(200).ifEmpty { null },
                        sameAsBaseline = sameAsBaseline,
                        vulnerable = vulnerable,
                        inconclusive = !baselineSucceeded,
                        error = if (!baselineSucceeded) "baseline did not return a successful response" else null,
                    )
                }
            }
        }

        return IdorResponse(
            baseline = baseline,
            results = results,
            vulnerableCount = results.count { it.vulnerable },
            inconclusiveCount = results.count { it.inconclusive } + if (baseline.inconclusive) 1 else 0,
            ignoredOwnValues = ignoredOwnValues,
            note = note,
        )
    }

    fun headersBypass(request: HeadersBypassRequest): HeadersBypassResponse {
        val method = validatedMethod(request.method, "method")
        val url = validatedHttpUrl(request.url, "url")
        validateBody(request.body)
        request.protectedContentMarker?.let { marker ->
            require(marker.isNotBlank()) { "protectedContentMarker must not be blank" }
            require(marker.length <= MAX_MARKER_CHARS) {
                "protectedContentMarker must be at most $MAX_MARKER_CHARS characters"
            }
        }

        val baselineRaw = sendAuthenticated(AuthenticatedRequest(method, url, request.body))
        val baseline = baselineRaw.toProbeResult()
        if (baselineRaw.inconclusive) {
            return HeadersBypassResponse(
                baseline = baseline,
                results = emptyList(),
                anomalousCount = 0,
                vulnerableCount = 0,
                inconclusiveCount = 1,
            )
        }

        val results = BYPASS_HEADERS.map { (header, value) ->
            val raw = sendAuthenticated(
                AuthenticatedRequest(method, url, request.body, mapOf(header to value))
            )
            if (raw.inconclusive) {
                HeadersBypassResult(
                    header = header,
                    value = value,
                    status = raw.status,
                    length = raw.bodyText.length,
                    anomalous = false,
                    vulnerable = false,
                    inconclusive = true,
                    error = raw.error ?: raw.inconclusiveReason ?: raw.status.transientReason(),
                )
            } else {
                val statusChanged = raw.status != baselineRaw.status
                val lengthChanged = kotlin.math.abs(raw.bodyText.length - baselineRaw.bodyText.length) >
                    (baselineRaw.bodyText.length * 0.1).toInt().coerceAtLeast(10)
                val anomalous = statusChanged || lengthChanged
                val marker = request.protectedContentMarker
                val vulnerable = baselineRaw.status.isDenial() &&
                    raw.status.isSubstantiveSuccess(raw.bodyText) && marker != null &&
                    !baselineRaw.bodyText.contains(marker) && raw.bodyText.contains(marker)
                HeadersBypassResult(
                    header = header,
                    value = value,
                    status = raw.status,
                    length = raw.bodyText.length,
                    anomalous = anomalous,
                    vulnerable = vulnerable,
                )
            }
        }

        return HeadersBypassResponse(
            baseline = baseline,
            results = results,
            anomalousCount = results.count { it.anomalous },
            vulnerableCount = results.count { it.vulnerable },
            inconclusiveCount = results.count { it.inconclusive },
        )
    }

    fun cors(request: CorsRequest): CorsResponse {
        val method = validatedMethod(request.method, "method")
        require(method in SIMPLE_CORS_METHODS) {
            "CORS scanning supports only simple GET, HEAD, or POST requests"
        }
        val url = validatedHttpUrl(request.url, "url")
        val host = requireNotNull(URI(url).host)
        val attackerLabel = host
            .removePrefix("[")
            .removeSuffix("]")
            .lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9-]"), "-")
            .trim('-')
            .take(40)
            .ifEmpty { "target" }

        // Every value is an attacker-origin candidate. In particular, never probe
        // evil.<target> or sub.<target>: those are target-owned DNS names.
        val origins = listOf(
            "https://evil.com",
            "http://evil.com",
            "https://www.evil.com",
            "https://evil.com:8443",
            "null",
            "https://$attackerLabel.evil.com",
            "http://$attackerLabel.evil.com",
            "https://$attackerLabel-target.evil.com",
        )

        val results = origins.map { origin ->
            val rawResponse = try {
                sessionService.sendPreservingHeaders(
                    AuthenticatedRequest(method = method, url = url, extraHeaders = mapOf("Origin" to origin)),
                    emptyList(),
                    CredentialMode.FULL,
                    persistObservation = false,
                )
            } catch (_: Exception) {
                null
            }
            if (rawResponse == null || rawResponse.statusCode !in 100..599) {
                CorsProbeResult(
                    origin = origin,
                    acao = null,
                    acac = null,
                    vulnerable = false,
                    status = null,
                    inconclusive = true,
                    error = REQUEST_FAILED,
                )
            } else if (rawResponse.statusCode.isTransientFailure()) {
                CorsProbeResult(
                    origin = origin,
                    acao = null,
                    acac = null,
                    vulnerable = false,
                    status = rawResponse.statusCode,
                    inconclusive = true,
                    error = rawResponse.statusCode.transientReason(),
                )
            } else {
                val acaoValues = rawResponse.headers
                    .filter { it.name.equals("Access-Control-Allow-Origin", ignoreCase = true) }
                    .map { it.value }
                val acacValues = rawResponse.headers
                    .filter { it.name.equals("Access-Control-Allow-Credentials", ignoreCase = true) }
                    .map { it.value }
                // Multiple field instances are not a usable CORS grant in browsers.
                val acao = acaoValues.singleOrNull()
                val acac = acacValues.singleOrNull()
                val vulnerable = acao == origin && acac == "true"
                CorsProbeResult(
                    origin = origin,
                    acao = acao,
                    acac = acac,
                    vulnerable = vulnerable,
                    status = rawResponse.statusCode,
                )
            }
        }

        return CorsResponse(
            results = results,
            vulnerableCount = results.count { it.vulnerable },
            inconclusiveCount = results.count { it.inconclusive },
        )
    }

    fun scanEndpoints(request: EndpointsScanRequest): EndpointsScanResponse {
        val tests = validateEndpointsRequest(request)
        val dao = historyDao ?: throw IllegalStateException("Database required for endpoint scanning")
        val start = System.currentTimeMillis()
        val entries = dao.search(HistoryFilter(host = request.host, pageSize = request.limit))

        // Build and validate the complete history-derived plan before any probe. Unsafe or corrupt
        // rows become explicit errors; they never partially execute a scan.
        val validationErrors = mutableListOf<EndpointProbeError>()
        val prepared = entries.mapNotNull { entry ->
            runCatching { prepareEndpointRequest(entry) }
                .onFailure { cause ->
                    validationErrors += EndpointProbeError(
                        endpoint = entry.url,
                        method = entry.method,
                        test = "history",
                        probe = "validation",
                        error = cause.message ?: "invalid history request",
                    )
                }
                .getOrNull()
                ?.let {
                    PreparedEndpoint(
                        source = entry.source,
                        request = it,
                        identity = CapturedRequestIdentity(
                            method = entry.method,
                            url = entry.url,
                            headers = entry.reqHeaders,
                            body = entry.reqBody,
                        ),
                    )
                }
        }.distinctBy { it.identity }

        val findings = mutableListOf<EndpointFinding>()
        val errors = validationErrors.toMutableList()
        val inconclusiveIdentities = mutableSetOf<CapturedRequestIdentity>()

        if ("auth-bypass" in tests) {
            prepared.forEach { preparedEndpoint ->
                val wire = preparedEndpoint.request
                val withAuth = probeWithAuthRaw(wire)
                if (withAuth.inconclusive || withAuth.status.isTransientFailure() ||
                    !withAuth.status.isSubstantiveSuccess(withAuth.bodyText)
                ) {
                    val reason = withAuth.error ?: withAuth.inconclusiveReason ?:
                        withAuth.status.transientReason() ?: "authenticated control was not a substantive 2xx response"
                    errors += EndpointProbeError(
                        endpoint = wire.url,
                        method = wire.method,
                        test = "auth-bypass",
                        probe = "auth-bypass-authenticated-control",
                        status = withAuth.status,
                        error = reason,
                    )
                    inconclusiveIdentities += preparedEndpoint.identity
                    return@forEach
                }

                val withoutAuth = probeNoAuthRaw(wire)
                if (withoutAuth.inconclusive || withoutAuth.status.isTransientFailure()) {
                    errors += wire.probeError(
                        "auth-bypass",
                        "auth-bypass-unauthenticated",
                        withoutAuth,
                        withoutAuth.status.transientReason(),
                    )
                    inconclusiveIdentities += preparedEndpoint.identity
                    return@forEach
                }
                if (withoutAuth.status.isSuccess() &&
                    contentSimilar(withAuth.bodyText, withoutAuth.bodyText)
                ) {
                    findings += EndpointFinding(
                        endpoint = wire.url,
                        method = wire.method,
                        test = "auth-bypass",
                        detail = "Accessible without auth: ${withoutAuth.status} (${withoutAuth.bodyText.length} bytes)",
                        severity = "high",
                    )
                }
            }
        }

        if ("method-switch" in tests) {
            val knownIdentities = prepared.map { it.identity }.toSet()
            prepared.forEach { preparedEndpoint ->
                val original = preparedEndpoint.request
                for (method in METHOD_SWITCH_METHODS) {
                    if (preparedEndpoint.identity.copy(method = method) in knownIdentities) continue
                    val switched = original.copy(method = method)
                    val raw = probeWithAuthRaw(switched)
                    if (raw.inconclusive || raw.status.isTransientFailure()) {
                        errors += switched.probeError(
                            "method-switch",
                            "method-switch-$method",
                            raw,
                            raw.status.transientReason(),
                        )
                        inconclusiveIdentities += preparedEndpoint.identity
                    } else if (raw.status.isSuccess() && raw.bodyText.isNotBlank() &&
                        !raw.bodyText.trimStart().startsWith("<!")
                    ) {
                        findings += EndpointFinding(
                            endpoint = switched.url,
                            method = method,
                            test = "method-switch",
                            detail = "Method $method returns ${raw.status} (${raw.bodyText.length} bytes) — not tested before",
                            severity = "medium",
                        )
                    }
                }
            }
        }

        return EndpointsScanResponse(
            scanned = prepared.count { it.identity !in inconclusiveIdentities },
            findings = findings,
            durationMs = System.currentTimeMillis() - start,
            source = "extension-h2-send-history",
            sourceCounts = prepared.groupingBy { it.source }.eachCount(),
            errors = errors,
            inconclusiveCount = errors.size,
        )
    }

    // --- Probe helpers ---

    internal open fun probeWithAuthRaw(url: String, method: String): RawProbe =
        sendAuthenticated(AuthenticatedRequest(method = method, url = url))

    internal open fun probeNoAuthRaw(url: String, method: String): RawProbe =
        sendRaw(EndpointRequest(method, url, emptyList(), null), CredentialMode.NONE)

    internal open fun probeWithAuthRaw(request: EndpointRequest): RawProbe =
        sendRaw(request, CredentialMode.FULL)

    internal open fun probeNoAuthRaw(request: EndpointRequest): RawProbe =
        sendRaw(request, CredentialMode.NONE)

    private fun sendAuthenticated(request: AuthenticatedRequest): RawProbe {
        return try {
            val start = System.currentTimeMillis()
            val response = sessionService.sendPreservingHeaders(
                request,
                emptyList(),
                CredentialMode.FULL,
                persistObservation = false,
            )
            response.toRawProbe(System.currentTimeMillis() - start)
        } catch (_: Exception) {
            RawProbe(null, "", 0, REQUEST_FAILED)
        }
    }

    private fun sendRaw(request: EndpointRequest, credentialMode: CredentialMode): RawProbe {
        return try {
            val response = sessionService.sendPreservingHeaders(
                request = AuthenticatedRequest(
                    method = request.method,
                    url = request.url,
                    body = request.body,
                ),
                headers = if (credentialMode == CredentialMode.NONE) {
                    request.headers.filter { it.name.lowercase(Locale.ROOT) in SAFE_REPLAY_HEADERS }
                } else {
                    request.headers
                },
                credentialMode = credentialMode,
                persistObservation = false,
            )
            response.toRawProbe(response.durationMs)
        } catch (_: Exception) {
            RawProbe(null, "", 0, REQUEST_FAILED)
        }
    }

    private fun probeCookieOnly(url: String, method: String): AuthBypassProbeResult =
        sendRaw(
            EndpointRequest(method = method, url = url, headers = emptyList(), body = null),
            CredentialMode.COOKIES_ONLY,
        ).toProbeResult()

    // --- Validation and comparison helpers ---

    private fun validateEndpointsRequest(request: EndpointsScanRequest): Set<String> {
        validateHistoryHost(request.host)
        require(request.tests.size in 1..ENDPOINT_TESTS.size) {
            "tests must contain between 1 and ${ENDPOINT_TESTS.size} entries"
        }
        require(request.tests.distinct().size == request.tests.size) { "tests must not contain duplicates" }
        request.tests.forEachIndexed { index, test ->
            require(test in ENDPOINT_TESTS) {
                "tests[$index] must be one of: ${ENDPOINT_TESTS.sorted().joinToString(", ")}"
            }
        }
        require(request.limit in 1..MAX_HISTORY_LIMIT) {
            "limit must be between 1 and $MAX_HISTORY_LIMIT"
        }
        return request.tests.toSet()
    }

    private fun validateHistoryHost(value: String) {
        require(value.isNotBlank() && value == value.trim() && !containsUnsafeText(value)) {
            "host must be a hostname without a scheme, path, port, or control characters"
        }
        val uri = runCatching { URI("http://$value/") }.getOrElse {
            throw IllegalArgumentException("host must be a valid hostname or IP literal")
        }
        require(uri.rawAuthority == value && uri.rawUserInfo == null && uri.port == -1 &&
            !uri.host.isNullOrBlank()
        ) { "host must be a hostname or IP literal without a scheme, path, or port" }
    }

    private fun prepareEndpointRequest(entry: HistoryEntry): EndpointRequest {
        val method = validatedMethod(entry.method, "history method")
        val url = validatedHttpUrl(entry.url, "history URL")
        validateBody(entry.reqBody)
        require(entry.reqHeaders.size <= MAX_HEADERS) {
            "history headers must contain at most $MAX_HEADERS headers"
        }
        entry.reqHeaders.forEachIndexed { index, header ->
            validateHeaderSyntax(header.name, header.value, "history headers[$index]")
        }
        val headers = entry.reqHeaders.filterNot {
            val name = it.name.lowercase(Locale.ROOT)
            name in KNOWN_CREDENTIAL_HEADERS || name in REGENERATED_HEADERS
        }
        return EndpointRequest(method, url, headers, entry.reqBody)
    }

    private fun validatedMethod(value: String, field: String): String {
        require(METHOD_TOKEN.matches(value) && value in SAFE_METHODS) {
            "$field must be one of: ${SAFE_METHODS.joinToString(", ")}"
        }
        return value
    }

    private fun validatedHttpUrl(value: String, field: String): String {
        require(value.isNotBlank() && value == value.trim() && !containsUnsafeText(value) && '\\' !in value) {
            "$field must be a non-blank safe HTTP URL"
        }
        val uri = runCatching { URI(value) }.getOrElse {
            throw IllegalArgumentException("$field must be a valid absolute HTTP URL")
        }
        require(uri.scheme?.lowercase(Locale.ROOT) in setOf("http", "https") && uri.isAbsolute &&
            !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawFragment == null
        ) { "$field must be an absolute HTTP(S) URL without user info or a fragment" }
        require(uri.port == -1 || uri.port in 1..65535) { "$field contains an invalid port" }
        return value
    }

    private fun validateHeaders(headers: List<HttpHeader>, field: String) {
        require(headers.size <= MAX_HEADERS) { "$field must contain at most $MAX_HEADERS headers" }
        headers.forEachIndexed { index, header -> validateHeader(header.name, header.value, "$field[$index]") }
    }

    private fun validateHeader(name: String, value: String, field: String) {
        validateHeaderSyntax(name, value, field)
        require(name.lowercase(Locale.ROOT) !in REGENERATED_HEADERS) {
            "$field may not set transport-controlled header '$name'"
        }
    }

    private fun validateHeaderSyntax(name: String, value: String, field: String) {
        require(HEADER_NAME.matches(name)) { "$field has an invalid header name" }
        require(value.none { it != '\t' && it.isISOControl() }) {
            "$field has an unsafe header value"
        }
    }

    private fun validateParameterValue(value: String, field: String) {
        require(value.isNotBlank()) { "$field must not be blank" }
        require(!containsUnsafeText(value)) { "$field contains unsafe characters" }
    }

    private fun validateBody(body: String?) {
        require(body == null || body.length <= MAX_BODY_CHARS) {
            "body must be at most $MAX_BODY_CHARS characters"
        }
    }

    private fun containsUnsafeText(value: String): Boolean =
        value.any { it.isISOControl() }


    private fun normalizedOrigin(url: String): String {
        val uri = URI(url)
        val scheme = requireNotNull(uri.scheme).lowercase(Locale.ROOT)
        val rawHost = requireNotNull(uri.host).removePrefix("[").removeSuffix("]").trimEnd('.')
        val host = if (':' in rawHost) {
            val address = InetAddress.getByName(rawHost)
            require(address is Inet6Address) { "invalid IPv6 origin" }
            address.hostAddress.lowercase(Locale.ROOT)
        } else {
            IDN.toASCII(rawHost, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        }
        val port = if (uri.port >= 0) uri.port else if (scheme == "https") 443 else 80
        return "$scheme://$host:$port"
    }

    private fun RawProbe.issue(label: String, requireSubstantive: Boolean = false): String? = when {
        error != null -> "$label: $error"
        inconclusiveReason != null -> "$label: $inconclusiveReason"
        status.isTransientFailure() -> "$label returned HTTP $status"
        requireSubstantive && !status.isSubstantiveSuccess(bodyText) ->
            "$label was not a substantive 2xx response"
        else -> null
    }

    private fun Int?.isTransientFailure(): Boolean = transientReasonFor(this) != null

    private fun Int?.transientReason(): String? = transientReasonFor(this)

    private fun bodiesEqualForIdor(baseline: String, target: String): Boolean {
        if (baseline.isEmpty() != target.isEmpty()) return false
        if (baseline.isEmpty()) return true
        return baseline == target
    }

    private fun contentSimilar(authBody: String, unauthBody: String): Boolean {
        if (authBody.isEmpty() || unauthBody.isEmpty()) return false
        if (authBody.take(200) != unauthBody.take(200)) return false
        val longer = maxOf(authBody.length, unauthBody.length).toDouble()
        val shorter = minOf(authBody.length, unauthBody.length).toDouble()
        if (shorter / longer < 0.80) return false
        return authBody == unauthBody
    }

    internal fun substituteParam(urlTemplate: String, param: String, value: String): String {
        if (urlTemplate.contains("{$param}")) return urlTemplate.replace("{$param}", value)
        val queryParamRegex = Regex("([?&])(${Regex.escape(param)})=([^&#]*)", RegexOption.IGNORE_CASE)
        if (queryParamRegex.containsMatchIn(urlTemplate)) {
            return queryParamRegex.replace(urlTemplate) {
                "${it.groupValues[1]}${it.groupValues[2]}=$value"
            }
        }
        val hashIndex = urlTemplate.indexOf('#')
        val base = if (hashIndex >= 0) urlTemplate.substring(0, hashIndex) else urlTemplate
        val fragment = if (hashIndex >= 0) urlTemplate.substring(hashIndex) else ""
        val separator = if (base.contains('?')) "&" else "?"
        return "$base$separator$param=$value$fragment"
    }

    private fun AuthenticatedResponse.toRawProbe(durationMs: Long): RawProbe =
        if (statusCode in 100..599) {
            val bodyText = body ?: ""
            val reason = transientReasonFor(statusCode) ?: if (
                bodyText.trimStart().startsWith("<!") && bodyText.length > 50_000
            ) {
                "large HTML response may be a catch-all"
            } else {
                null
            }
            RawProbe(statusCode, bodyText, durationMs, inconclusiveReason = reason)
        } else {
            RawProbe(null, "", 0, REQUEST_FAILED)
        }

    private fun Int?.isSuccess(): Boolean = this != null && this in 200..299

    private fun Int?.isSubstantiveSuccess(body: String): Boolean =
        this != null && this in 200..299 && this != 204 && this != 205 && body.isNotBlank()

    private fun Int?.isDenial(): Boolean = this in DENIAL_STATUSES

    private fun EndpointRequest.probeError(
        test: String,
        probe: String,
        raw: RawProbe,
        fallback: String? = null,
    ) = EndpointProbeError(
        endpoint = url,
        method = method,
        test = test,
        probe = probe,
        status = raw.status,
        error = raw.error ?: raw.inconclusiveReason ?: fallback ?: REQUEST_FAILED,
    )

    private data class CapturedRequestIdentity(
        val method: String,
        val url: String,
        val headers: List<HttpHeader>,
        val body: String?,
    )

    private data class PreparedEndpoint(
        val source: String,
        val request: EndpointRequest,
        val identity: CapturedRequestIdentity,
    )

    companion object {
        private const val REQUEST_FAILED = "request failed"
        private const val MAX_PLAN_ITEMS = 1000
        private const val MAX_HISTORY_LIMIT = 1000
        private const val MAX_HEADERS = 200
        private const val MAX_BODY_CHARS = 1_048_576
        private const val MAX_MARKER_CHARS = 4_096

        private fun transientReasonFor(status: Int?): String? =
            if (status == 408 || status == 425 || status == 429 ||
                (status != null && status in 500..599)
            ) {
                "probe returned transient HTTP $status"
            } else {
                null
            }

        private val SAFE_METHODS = linkedSetOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
        private val SIMPLE_CORS_METHODS = setOf("GET", "HEAD", "POST")
        private val METHOD_SWITCH_METHODS = listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
        private val ENDPOINT_TESTS = setOf("auth-bypass", "method-switch")
        private val DENIAL_STATUSES = setOf(401, 403)
        private val METHOD_TOKEN = Regex("^[A-Z]+$")
        private val PARAM_NAME = Regex("^[A-Za-z0-9._~-]+$")
        private val HEADER_NAME = Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        private val KNOWN_CREDENTIAL_HEADERS = setOf(
            "authorization", "proxy-authorization", "cookie", "cookie2",
            "x-api-key", "api-key", "x-auth-token", "x-access-token",
            "private-token", "x-gitlab-token", "x-session-token",
        )
        private val SAFE_REPLAY_HEADERS = setOf(
            "accept", "accept-charset", "accept-encoding", "accept-language",
            "content-type", "content-encoding", "content-language", "user-agent",
        )
        private val REGENERATED_HEADERS = setOf(
            "host", "content-length", "transfer-encoding", "connection", "proxy-connection",
            "trailer", "upgrade", "te",
        )

        private val BYPASS_HEADERS = listOf(
            "X-Forwarded-For" to "127.0.0.1",
            "X-Forwarded-For" to "0.0.0.0",
            "X-Real-IP" to "127.0.0.1",
            "X-Original-URL" to "/admin",
            "X-Rewrite-URL" to "/admin",
            "X-Custom-IP-Authorization" to "127.0.0.1",
            "X-Forwarded-Host" to "127.0.0.1",
            "X-Remote-IP" to "127.0.0.1",
            "X-Remote-Addr" to "127.0.0.1",
            "X-ProxyUser-Ip" to "127.0.0.1",
            "X-Original-Remote-Addr" to "127.0.0.1",
            "Client-IP" to "127.0.0.1",
            "True-Client-IP" to "127.0.0.1",
            "X-Forwarded-Proto" to "https",
            "X-Forwarded-Port" to "443",
            "X-Host" to "127.0.0.1",
        )
    }
}
