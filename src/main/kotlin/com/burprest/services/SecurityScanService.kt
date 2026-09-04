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
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.text.Normalizer
import java.util.Base64
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
        val requestMaterial: SessionRequestMaterialSnapshot? = null,
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

    private data class RequestCookie(
        val name: String,
        val value: String,
    )

    private data class RequestMaterial(
        val method: String,
        val url: String,
        val body: String?,
        val headers: List<HttpHeader>,
        val cookies: List<RequestCookie> = emptyList(),
        val cookieHeaderValue: String? = null,
    )

    private data class HeaderBypassExperiment(
        val method: String,
        val url: String,
        val body: String?,
        val marker: String?,
        val probeTimeoutMs: Long,
    )

    private data class RequestRendering(
        val requestTarget: String,
        val identityComponents: List<String>,
        val cookiePairs: List<String>,
        val cookieValue: String,
    )

    private data class RepresentationTransform(
        val name: String,
        val decode: (String) -> List<String>,
    )

    private enum class MarkerProvenance {
        CLEAR,
        ACTOR_SUPPLIED,
        UNKNOWN,
    }

    private val representationTransforms = listOf(
        RepresentationTransform("percent") { listOf(decodePercentEscapes(it, plusAsSpace = false)) },
        RepresentationTransform("form-percent") { listOf(decodePercentEscapes(it, plusAsSpace = true)) },
        RepresentationTransform("html-entity") { listOf(decodeHtmlEntities(it)) },
        RepresentationTransform("json-unicode-escape") { listOf(decodeJsonEscapes(it)) },
        RepresentationTransform("base64") { decodeBase64Representations(it) },
    )

    fun authBypass(request: AuthBypassRequest): AuthBypassResponse {
        val method = validatedMethod(request.method, "method")
        val probeTimeoutMs = validatedProbeTimeout(request.probeTimeoutMs)
        val protectedContentMarker = validatedMarker(request.protectedContentMarker)
        val cookieOnlyDistinct = sessionService.cookieOnlyDiffersFromNone()
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
            classifyAuthEndpoint(
                endpoint,
                AuthExperiment(
                    url,
                    method,
                    probeTimeoutMs,
                    cookieOnlyDistinct,
                    protectedContentMarker,
                ),
            )
        }

        return AuthBypassResponse(
            results = results,
            totalScanned = results.size,
            vulnerableCount = results.count { it.vulnerable },
            inconclusiveCount = results.count { it.inconclusive },
        )
    }

    private data class AuthExperiment(
        val url: String,
        val method: String,
        val probeTimeoutMs: Long,
        val cookieOnlyDistinct: Boolean,
        val protectedContentMarker: String?,
    )

    private data class AuthProbeSet(
        val full: RawProbe,
        val none: RawProbe,
        val cookieOnly: RawProbe,
        val fullIsSubstantive: Boolean,
        val cookieOnlyDistinct: Boolean,
    )

    private data class AuthDecision(
        val vulnerable: Boolean = false,
        val inconclusive: Boolean = false,
        val note: String? = null,
    )

    private fun classifyAuthEndpoint(
        endpoint: String,
        experiment: AuthExperiment,
    ): AuthBypassEndpointResult {
        if (authExperimentContainsMarker(experiment)) {
            return actorSuppliedMarkerResult(endpoint)
        }

        val probes = collectAuthProbes(
            experiment.url,
            experiment.method,
            experiment.probeTimeoutMs,
            experiment.cookieOnlyDistinct,
        )
        val markerProvenance = experiment.protectedContentMarker?.let { marker ->
            observedMarkerProvenance(
                method = experiment.method,
                url = experiment.url,
                body = null,
                marker = marker,
                snapshot = probes.none.requestMaterial,
            )
        } ?: MarkerProvenance.CLEAR
        val candidateEquality = probes.fullIsSubstantive &&
            !probes.none.inconclusive && probes.none.status.isSuccess() &&
            contentSimilar(probes.full.bodyText, probes.none.bodyText)
        val protectedReadObserved = experiment.protectedContentMarker?.let { marker ->
            probes.none.status.isSubstantiveSuccess(probes.none.bodyText) &&
                probes.none.bodyText.contains(marker)
        } == true
        val unprovenSubstantiveRead = experiment.protectedContentMarker == null &&
            probes.none.status.isSubstantiveSuccess(probes.none.bodyText)
        val decision = decideAuthBypass(
            probes,
            markerProvenance,
            candidateEquality,
            protectedReadObserved,
            unprovenSubstantiveRead,
        )
        val errors = buildList {
            probes.full.issue("authenticated control", requireSubstantive = true)?.let(::add)
            probes.none.issue("unauthenticated probe")?.let(::add)
            markerProvenance.reasonOrNull()?.let(::add)
            if (candidateEquality && !decision.vulnerable) {
                probes.cookieOnly.issue("cookie-only probe")?.let(::add)
            }
        }

        return AuthBypassEndpointResult(
            endpoint = endpoint,
            withAuth = probes.full.toProbeResult(),
            withoutAuth = probes.none.toProbeResult(),
            cookieOnly = probes.cookieOnly.toProbeResult(),
            vulnerable = decision.vulnerable,
            inconclusive = decision.inconclusive,
            errors = errors,
            note = decision.note,
        )
    }

    private fun authExperimentContainsMarker(experiment: AuthExperiment): Boolean =
        experiment.protectedContentMarker?.let { marker ->
            requestMaterialContainsMarker(
                RequestMaterial(
                    method = experiment.method,
                    url = experiment.url,
                    body = null,
                    headers = emptyList(),
                ),
                marker,
            )
        } == true

    private fun actorSuppliedMarkerResult(endpoint: String): AuthBypassEndpointResult {
        val unavailable = notSentProbe("not sent because $ACTOR_SUPPLIED_MARKER")
        return AuthBypassEndpointResult(
            endpoint = endpoint,
            withAuth = unavailable.toProbeResult(),
            withoutAuth = unavailable.toProbeResult(),
            cookieOnly = unavailable.toProbeResult(),
            vulnerable = false,
            inconclusive = true,
            errors = listOf(ACTOR_SUPPLIED_MARKER),
            note = ACTOR_SUPPLIED_MARKER,
        )
    }

    private fun collectAuthProbes(
        url: String,
        method: String,
        probeTimeoutMs: Long,
        cookieOnlyDistinct: Boolean,
    ): AuthProbeSet {
        val full = probeWithAuthRaw(url, method, probeTimeoutMs)
        val fullIsSubstantive = !full.inconclusive && full.status.isSubstantiveSuccess(full.bodyText)
        val unavailableReason = "not sent because the authenticated control was inconclusive"
        val none = if (fullIsSubstantive) {
            probeNoAuthRaw(url, method, probeTimeoutMs)
        } else {
            notSentProbe(unavailableReason)
        }
        val cookieOnly = when {
            !fullIsSubstantive -> notSentProbe(unavailableReason)
            !cookieOnlyDistinct ->
                notSentProbe("cookie-only probe carries no configured credentials and is identical to NONE")
            else -> probeCookieOnlyRaw(url, method, probeTimeoutMs)
        }
        return AuthProbeSet(full, none, cookieOnly, fullIsSubstantive, cookieOnlyDistinct)
    }

    private fun decideAuthBypass(
        probes: AuthProbeSet,
        markerProvenance: MarkerProvenance,
        candidateEquality: Boolean,
        protectedReadObserved: Boolean,
        unprovenSubstantiveRead: Boolean,
    ): AuthDecision = when {
        !probes.fullIsSubstantive || probes.none.inconclusive -> AuthDecision(inconclusive = true)
        markerProvenance != MarkerProvenance.CLEAR -> AuthDecision(
            inconclusive = true,
            note = markerProvenance.reasonOrNull(),
        )
        protectedReadObserved -> AuthDecision(vulnerable = true)
        candidateEquality -> AuthDecision(inconclusive = true, note = AUTH_BYPASS_PROOF_CEILING)
        unprovenSubstantiveRead -> AuthDecision(
            inconclusive = true,
            note = if (probes.cookieOnlyDistinct) {
                AUTH_BYPASS_MARKER_REQUIRED
            } else {
                COOKIE_CONTROL_DEGENERATED
            },
        )
        else -> AuthDecision()
    }

    fun idor(request: IdorRequest): IdorResponse {
        val method = validatedMethod(request.method, "method")
        val probeTimeoutMs = validatedProbeTimeout(request.probeTimeoutMs)
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
            AuthenticatedRequest(method, ownUrls.first(), request.body, request.extraHeaders),
            probeTimeoutMs,
        )
        val baselineSucceeded = !baselineRaw.inconclusive && baselineRaw.status.isSuccess()
        val baseline = IdorProbeResult(
            value = request.ownValues.first(),
            status = baselineRaw.status,
            length = baselineRaw.bodyText.length,
            bodyPreview = baselineRaw.bodyText.take(200).ifEmpty { null },
            sameAsBaseline = true,
            vulnerable = false,
            inconclusive = !baselineSucceeded,
            error = baselineRaw.error ?: baselineRaw.inconclusiveReason ?:
                baselineRaw.status.transientReason() ?:
                if (!baselineSucceeded) "baseline did not return a successful response" else null,
        )

        // A target result without a usable own-object control is not evidence. The live 404 case
        // exposed that sending it anyway also left the baseline's reason absent from JSON, making
        // the structured inconclusive outcome look too much like a clean scan to clients.
        val results = if (!baselineSucceeded) {
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
                val raw = sendAuthenticated(
                    AuthenticatedRequest(method, url, request.body, request.extraHeaders),
                    probeTimeoutMs,
                )
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
        val experiment = HeaderBypassExperiment(
            method = validatedMethod(request.method, "method"),
            url = validatedHttpUrl(request.url, "url"),
            body = request.body.also(::validateBody),
            marker = validatedMarker(request.protectedContentMarker),
            probeTimeoutMs = validatedProbeTimeout(request.probeTimeoutMs),
        )
        val baselineRaw = sendAuthenticated(
            AuthenticatedRequest(experiment.method, experiment.url, experiment.body),
            experiment.probeTimeoutMs,
        )
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

        val results = BYPASS_HEADERS.map { injectedHeader ->
            classifyHeaderBypassTreatment(experiment, baselineRaw, injectedHeader)
        }
        return HeadersBypassResponse(
            baseline = baseline,
            results = results,
            anomalousCount = results.count { it.anomalous },
            vulnerableCount = results.count { it.vulnerable },
            inconclusiveCount = results.count { it.inconclusive },
        )
    }

    private fun classifyHeaderBypassTreatment(
        experiment: HeaderBypassExperiment,
        baseline: RawProbe,
        injectedHeader: Pair<String, String>,
    ): HeadersBypassResult {
        val (header, value) = injectedHeader
        val request = AuthenticatedRequest(
            experiment.method,
            experiment.url,
            experiment.body,
            mapOf(header to value),
        )
        val raw = if (experiment.marker == null) {
            sendAuthenticated(request, experiment.probeTimeoutMs)
        } else {
            sendAuthenticatedObservedResponse(request, experiment.probeTimeoutMs).toRawProbe()
        }
        val markerProvenance = experiment.marker?.let { marker ->
            observedMarkerProvenance(
                method = experiment.method,
                url = experiment.url,
                body = experiment.body,
                marker = marker,
                snapshot = raw.requestMaterial,
            )
        } ?: MarkerProvenance.CLEAR
        val anomalous = raw.isAnomalousComparedWith(baseline)
        return when {
            markerProvenance != MarkerProvenance.CLEAR || raw.inconclusive -> HeadersBypassResult(
                header = header,
                value = value,
                status = raw.status,
                length = raw.bodyText.length,
                anomalous = anomalous,
                vulnerable = false,
                inconclusive = true,
                error = provenanceOrProbeError(markerProvenance, raw),
            )
            else -> HeadersBypassResult(
                header = header,
                value = value,
                status = raw.status,
                length = raw.bodyText.length,
                anomalous = anomalous,
                vulnerable = baseline.status.isDenial() &&
                    raw.status.isSubstantiveSuccess(raw.bodyText) && experiment.marker != null &&
                    !baseline.bodyText.contains(experiment.marker) && raw.bodyText.contains(experiment.marker),
            )
        }
    }

    private fun RawProbe.isAnomalousComparedWith(baseline: RawProbe): Boolean {
        val statusChanged = status != baseline.status
        val threshold = (baseline.bodyText.length * HEADER_ANOMALY_RATIO).toInt()
            .coerceAtLeast(MIN_HEADER_ANOMALY_CHARS)
        val lengthChanged = kotlin.math.abs(bodyText.length - baseline.bodyText.length) > threshold
        return !inconclusive && (statusChanged || lengthChanged)
    }

    private fun provenanceOrProbeError(provenance: MarkerProvenance, raw: RawProbe): String? = when (provenance) {
        MarkerProvenance.ACTOR_SUPPLIED -> ACTOR_SUPPLIED_MARKER
        MarkerProvenance.UNKNOWN -> MARKER_PROVENANCE_UNAVAILABLE
        MarkerProvenance.CLEAR -> raw.error ?: raw.inconclusiveReason ?: raw.status.transientReason()
    }

    fun cors(request: CorsRequest): CorsResponse {
        val method = validatedMethod(request.method, "method")
        val probeTimeoutMs = validatedProbeTimeout(request.probeTimeoutMs)
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
            val attempt = sendAuthenticatedResponse(
                AuthenticatedRequest(method = method, url = url, extraHeaders = mapOf("Origin" to origin)),
                probeTimeoutMs,
            )
            val rawResponse = attempt.response
            if (rawResponse == null || rawResponse.statusCode !in 100..599) {
                CorsProbeResult(
                    origin = origin,
                    acao = null,
                    acac = null,
                    vulnerable = false,
                    status = null,
                    inconclusive = true,
                    error = attempt.error ?: REQUEST_FAILED,
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
        val probeTimeoutMs = validatedProbeTimeout(request.probeTimeoutMs)
        val protectedContentMarker = validatedMarker(request.protectedContentMarker)
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
                val markerWasActorSupplied = protectedContentMarker?.let { marker ->
                    wire.containsRequestMarker(marker)
                } == true
                if (markerWasActorSupplied) {
                    errors += wire.ambiguousAuthProbeError(ACTOR_SUPPLIED_MARKER)
                    inconclusiveIdentities += preparedEndpoint.identity
                    return@forEach
                }

                val withAuth = probeEndpointWithAuthRaw(wire, probeTimeoutMs)
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

                val withoutAuth = probeEndpointNoAuthRaw(wire, probeTimeoutMs)
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
                val markerProvenance = protectedContentMarker?.let { marker ->
                    observedMarkerProvenance(
                        method = wire.method,
                        url = wire.url,
                        body = wire.body,
                        marker = marker,
                        snapshot = withoutAuth.requestMaterial,
                    )
                } ?: MarkerProvenance.CLEAR
                if (markerProvenance != MarkerProvenance.CLEAR) {
                    errors += wire.ambiguousAuthProbeError(
                        requireNotNull(markerProvenance.reasonOrNull()),
                    )
                    inconclusiveIdentities += preparedEndpoint.identity
                    return@forEach
                }
                val protectedRepresentationObserved = protectedContentMarker?.let { marker ->
                    withoutAuth.status.isSubstantiveSuccess(withoutAuth.bodyText) &&
                        withoutAuth.bodyText.contains(marker)
                } == true
                if (protectedRepresentationObserved) {
                    findings += EndpointFinding(
                        endpoint = wire.url,
                        method = wire.method,
                        test = "auth-bypass",
                        detail = "Unauthenticated response returned the configured protected marker",
                        severity = "high",
                    )
                    return@forEach
                }

                val candidateEquality = withoutAuth.status.isSuccess() &&
                    contentSimilar(withAuth.bodyText, withoutAuth.bodyText)
                val missingMarkerProof = protectedContentMarker == null &&
                    withoutAuth.status.isSubstantiveSuccess(withoutAuth.bodyText)
                if (candidateEquality || missingMarkerProof) {
                    val reason = if (candidateEquality) {
                        AUTH_BYPASS_PROOF_CEILING
                    } else {
                        AUTH_BYPASS_MARKER_REQUIRED
                    }
                    errors += wire.ambiguousAuthProbeError(reason)
                    inconclusiveIdentities += preparedEndpoint.identity
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
                    val raw = probeEndpointWithAuthRaw(switched, probeTimeoutMs)
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

    internal open fun probeWithAuthRaw(
        url: String,
        method: String,
        probeTimeoutMs: Long = DEFAULT_PROBE_TIMEOUT_MS,
    ): RawProbe = sendAuthenticated(AuthenticatedRequest(method = method, url = url), probeTimeoutMs)

    internal open fun probeNoAuthRaw(
        url: String,
        method: String,
        probeTimeoutMs: Long = DEFAULT_PROBE_TIMEOUT_MS,
    ): RawProbe = sendRawObserved(
        EndpointRequest(method, url, emptyList(), null),
        CredentialMode.NONE,
        probeTimeoutMs,
    )

    internal open fun probeEndpointWithAuthRaw(
        request: EndpointRequest,
        probeTimeoutMs: Long = DEFAULT_PROBE_TIMEOUT_MS,
    ): RawProbe = sendRaw(request, CredentialMode.FULL, probeTimeoutMs)

    internal open fun probeEndpointNoAuthRaw(
        request: EndpointRequest,
        probeTimeoutMs: Long = DEFAULT_PROBE_TIMEOUT_MS,
    ): RawProbe = sendRawObserved(request, CredentialMode.NONE, probeTimeoutMs)

    /** A bounded send can prove only that no response arrived within its configured budget. */
    private data class BoundedResponse(
        val response: AuthenticatedResponse?,
        val error: String? = null,
        val requestMaterial: SessionRequestMaterialSnapshot? = null,
    )

    private fun sendAuthenticated(request: AuthenticatedRequest, probeTimeoutMs: Long): RawProbe =
        sendAuthenticatedResponse(request, probeTimeoutMs).toRawProbe()

    private fun sendAuthenticatedResponse(
        request: AuthenticatedRequest,
        probeTimeoutMs: Long,
    ): BoundedResponse = sendWithBudget(probeTimeoutMs) {
        sessionService.sendPreservingHeaders(
            request,
            emptyList(),
            CredentialMode.FULL,
            persistObservation = false,
            responseTimeoutMs = probeTimeoutMs,
        )
    }

    private fun sendAuthenticatedObservedResponse(
        request: AuthenticatedRequest,
        probeTimeoutMs: Long,
    ): BoundedResponse = sendObservedWithBudget(probeTimeoutMs) {
        sessionService.sendPreservingHeadersObserved(
            request,
            emptyList(),
            CredentialMode.FULL,
            persistObservation = false,
            responseTimeoutMs = probeTimeoutMs,
        )
    }

    private fun sendRaw(
        request: EndpointRequest,
        credentialMode: CredentialMode,
        probeTimeoutMs: Long,
    ): RawProbe = sendWithBudget(probeTimeoutMs) {
        sessionService.sendPreservingHeaders(
            request = AuthenticatedRequest(
                method = request.method,
                url = request.url,
                body = request.body,
            ),
            headers = request.headers,
            credentialMode = credentialMode,
            persistObservation = false,
            responseTimeoutMs = probeTimeoutMs,
        )
    }.toRawProbe()

    private fun sendRawObserved(
        request: EndpointRequest,
        credentialMode: CredentialMode,
        probeTimeoutMs: Long,
    ): RawProbe = sendObservedWithBudget(probeTimeoutMs) {
        sessionService.sendPreservingHeadersObserved(
            request = AuthenticatedRequest(
                method = request.method,
                url = request.url,
                body = request.body,
            ),
            headers = request.headers,
            credentialMode = credentialMode,
            persistObservation = false,
            responseTimeoutMs = probeTimeoutMs,
        )
    }.toRawProbe()

    private fun probeCookieOnlyRaw(url: String, method: String, probeTimeoutMs: Long): RawProbe =
        sendRaw(
            EndpointRequest(method = method, url = url, headers = emptyList(), body = null),
            CredentialMode.COOKIES_ONLY,
            probeTimeoutMs,
        )

    private fun notSentProbe(reason: String): RawProbe = RawProbe(null, "", 0, reason)

    private fun sendWithBudget(
        probeTimeoutMs: Long,
        send: () -> AuthenticatedResponse,
    ): BoundedResponse = try {
        val response: AuthenticatedResponse? = send()
        if (response == null) {
            BoundedResponse(null, REQUEST_FAILED)
        } else {
            BoundedResponse(response)
        }
    } catch (_: BoundedSendNoResponseException) {
        BoundedResponse(
            null,
            "probe produced no response within the configured $probeTimeoutMs ms response budget",
        )
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        BoundedResponse(null, REQUEST_FAILED)
    } catch (_: RuntimeException) {
        BoundedResponse(null, REQUEST_FAILED)
    }

    private fun sendObservedWithBudget(
        probeTimeoutMs: Long,
        send: () -> ObservedAuthenticatedSend,
    ): BoundedResponse = try {
        val observed = send()
        BoundedResponse(observed.response, requestMaterial = observed.requestMaterial)
    } catch (_: BoundedSendNoResponseException) {
        BoundedResponse(
            null,
            "probe produced no response within the configured $probeTimeoutMs ms response budget",
        )
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        BoundedResponse(null, REQUEST_FAILED)
    } catch (_: RuntimeException) {
        BoundedResponse(null, REQUEST_FAILED)
    }

    private fun BoundedResponse.toRawProbe(): RawProbe {
        val completed = response
        return if (completed == null) {
            RawProbe(null, "", 0, error ?: REQUEST_FAILED, requestMaterial = requestMaterial)
        } else {
            completed.toRawProbe(completed.durationMs, requestMaterial)
        }
    }

    // --- Validation and comparison helpers ---

    private fun validatedProbeTimeout(value: Long): Long {
        require(value in MIN_PROBE_TIMEOUT_MS..MAX_PROBE_TIMEOUT_MS) {
            "probeTimeoutMs must be between $MIN_PROBE_TIMEOUT_MS and $MAX_PROBE_TIMEOUT_MS"
        }
        return value
    }

    private fun validatedMarker(value: String?): String? = value?.also { marker ->
        require(marker.isNotBlank()) { "protectedContentMarker must not be blank" }
        require(marker.length <= MAX_MARKER_CHARS) {
            "protectedContentMarker must be at most $MAX_MARKER_CHARS characters"
        }
    }

    private fun validateEndpointsRequest(request: EndpointsScanRequest): Set<String> {
        validateHistoryHost(request.host)
        validatedProbeTimeout(request.probeTimeoutMs)
        validatedMarker(request.protectedContentMarker)
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

    private fun EndpointRequest.containsRequestMarker(marker: String): Boolean =
        requestMaterialContainsMarker(RequestMaterial(method, url, body, headers), marker)

    private fun observedMarkerProvenance(
        method: String,
        url: String,
        body: String?,
        marker: String,
        snapshot: SessionRequestMaterialSnapshot?,
    ): MarkerProvenance {
        if (snapshot !is SessionRequestMaterialSnapshot.Available) return MarkerProvenance.UNKNOWN
        val wireMaterial = RequestMaterial(
            method = method,
            url = url,
            body = body,
            headers = snapshot.headers,
            cookieHeaderValue = snapshot.cookieHeaderValue,
        )
        return when {
            requestMaterialContainsMarker(wireMaterial, marker) -> MarkerProvenance.ACTOR_SUPPLIED
            !snapshot.cookieMaterialIsConsistent() -> MarkerProvenance.UNKNOWN
            requestMaterialContainsMarker(
                wireMaterial.copy(cookies = snapshot.cookies.map { RequestCookie(it.name, it.value) }),
                marker,
            ) -> MarkerProvenance.ACTOR_SUPPLIED
            else -> MarkerProvenance.CLEAR
        }
    }

    private fun SessionRequestMaterialSnapshot.Available.cookieMaterialIsConsistent(): Boolean {
        val renderedPairs = cookies.joinToString("; ") { "${it.name}=${it.value}" }
        return cookieHeaderValue?.let { it == renderedPairs } ?: cookies.isEmpty()
    }

    private fun MarkerProvenance.reasonOrNull(): String? = when (this) {
        MarkerProvenance.ACTOR_SUPPLIED -> ACTOR_SUPPLIED_MARKER
        MarkerProvenance.UNKNOWN -> MARKER_PROVENANCE_UNAVAILABLE
        MarkerProvenance.CLEAR -> null
    }

    private fun requestMaterialContainsMarker(request: RequestMaterial, marker: String): Boolean {
        val markerRepresentations = representationClosure(marker).mapTo(linkedSetOf(), ::canonicalRepresentation)
        return request.renderedComponents().any { component ->
            transformedMaterialContainsMarker(component, markerRepresentations)
        }
    }

    private fun RequestMaterial.renderedComponents(): List<String> {
        val rendering = rendering()
        return rendering.identityComponents +
            renderedHeaderComponents(rendering) +
            renderedRequestComponents(rendering)
    }

    private fun RequestMaterial.rendering(): RequestRendering {
        val uri = URI(url)
        val path = uri.rawPath?.ifEmpty { "/" } ?: "/"
        val requestTarget = uri.rawQuery?.let { "$path?$it" } ?: path
        val authority = requireNotNull(uri.rawAuthority)
        val cookiePairs = cookies.map { "${it.name}=${it.value}" }
        val cookieValue = cookieHeaderValue ?: cookiePairs.joinToString("; ")
        return RequestRendering(
            requestTarget = requestTarget,
            identityComponents = listOfNotNull(
                method,
                url,
                uri.scheme,
                authority,
                uri.host,
                path,
                uri.rawQuery,
                requestTarget,
                body,
            ),
            cookiePairs = cookiePairs,
            cookieValue = cookieValue,
        )
    }

    private fun RequestMaterial.renderedHeaderComponents(rendering: RequestRendering): List<String> = buildList {
        headers.forEach { header ->
            add(header.name)
            add(header.value)
            add("${header.name}: ${header.value}")
        }
        if (rendering.cookieValue.isNotEmpty()) {
            add("Cookie")
            addAll(rendering.cookiePairs)
            add(rendering.cookieValue)
            add("Cookie: ${rendering.cookieValue}")
        }
    }

    private fun RequestMaterial.renderedRequestComponents(rendering: RequestRendering): List<String> =
        listOf("$method ${rendering.requestTarget}")

    private fun transformedMaterialContainsMarker(
        material: String,
        markerRepresentations: Set<String>,
    ): Boolean = representationClosure(material).any { candidate ->
        val canonicalCandidate = canonicalRepresentation(candidate)
        markerRepresentations.any(canonicalCandidate::contains)
    }

    private fun representationClosure(initial: String): Set<String> {
        val pending = ArrayDeque<String>()
        val seen = linkedSetOf<String>()
        pending.add(initial)

        while (pending.isNotEmpty() && seen.size < MAX_PROVENANCE_REPRESENTATIONS) {
            val candidate = pending.removeFirst()
            if (!seen.add(candidate)) continue
            val transformed = representationTransforms.flatMap { transform -> transform.decode(candidate) }
            transformed
                .filter { it != candidate && it !in seen }
                .take(MAX_PROVENANCE_REPRESENTATIONS - seen.size)
                .forEach(pending::addLast)
        }
        return seen
    }

    private fun canonicalRepresentation(value: String): String {
        val normalized = Normalizer.normalize(value, Normalizer.Form.NFKC).lowercase(Locale.ROOT)
        return buildString(normalized.length) {
            var inWhitespace = false
            normalized.forEach { char ->
                if (char.isWhitespace()) {
                    if (!inWhitespace) append(' ')
                    inWhitespace = true
                } else {
                    append(char)
                    inWhitespace = false
                }
            }
        }.trim()
    }

    private fun decodePercentEscapes(value: String, plusAsSpace: Boolean): String {
        val formAdjusted = if (plusAsSpace) value.replace('+', ' ') else value
        return PERCENT_RUN.replace(formAdjusted) { encoded ->
            val bytes = encoded.value.chunked(PERCENT_ENCODED_OCTET_LENGTH).map { triplet ->
                triplet.substring(PERCENT_HEX_OFFSET).toInt(HEX_RADIX).toByte()
            }.toByteArray()
            decodeUtf8(bytes) ?: encoded.value
        }
    }

    private fun decodeHtmlEntities(value: String): String = HTML_ENTITY.replace(value) { encoded ->
        val entity = encoded.groupValues[1]
        val codePoint = when {
            entity.startsWith("#x", ignoreCase = true) ->
                entity.substring(HTML_HEX_ENTITY_PREFIX_LENGTH).toIntOrNull(HEX_RADIX)
            entity.startsWith('#') -> entity.substring(HTML_DECIMAL_ENTITY_PREFIX_LENGTH).toIntOrNull()
            else -> HTML_NAMED_ENTITIES[entity.lowercase(Locale.ROOT)]
        }
        codePoint?.takeIf(Character::isValidCodePoint)
            ?.let { String(Character.toChars(it)) }
            ?: encoded.value
    }

    private fun decodeJsonEscapes(value: String): String {
        val decoded = StringBuilder(value.length)
        var index = 0
        while (index < value.length) {
            if (value[index] != '\\' || index + 1 >= value.length) {
                decoded.append(value[index++])
                continue
            }
            when (value[index + 1]) {
                '"', '\\', '/' -> {
                    decoded.append(value[index + 1])
                    index += 2
                }
                'b' -> {
                    decoded.append('\b')
                    index += 2
                }
                'f' -> {
                    decoded.append('')
                    index += 2
                }
                'n' -> {
                    decoded.append('\n')
                    index += 2
                }
                'r' -> {
                    decoded.append('\r')
                    index += 2
                }
                't' -> {
                    decoded.append('\t')
                    index += 2
                }
                'u' -> {
                    val unicode = decodeUnicodeEscape(value, index)
                    if (unicode == null) {
                        decoded.append(value[index++])
                    } else {
                        decoded.append(unicode.first)
                        index += unicode.second
                    }
                }
                else -> decoded.append(value[index++])
            }
        }
        return decoded.toString()
    }

    private fun decodeUnicodeEscape(value: String, slashIndex: Int): Pair<String, Int>? {
        val escapeEnd = slashIndex + JSON_UNICODE_ESCAPE_LENGTH
        val first = if (escapeEnd <= value.length) {
            value.substring(slashIndex + UNICODE_HEX_OFFSET, escapeEnd).toIntOrNull(HEX_RADIX)
        } else {
            null
        }
        return first?.let { firstCodeUnit ->
            val firstChar = firstCodeUnit.toChar()
            val second = decodeTrailingLowSurrogate(value, escapeEnd, firstChar)
            if (second == null) {
                firstChar.toString() to JSON_UNICODE_ESCAPE_LENGTH
            } else {
                val codePoint = Character.toCodePoint(firstChar, second)
                String(Character.toChars(codePoint)) to JSON_SURROGATE_PAIR_ESCAPE_LENGTH
            }
        }
    }

    private fun decodeTrailingLowSurrogate(value: String, nextSlash: Int, firstChar: Char): Char? {
        val secondEscapeEnd = nextSlash + JSON_UNICODE_ESCAPE_LENGTH
        val hasSecondEscape = firstChar.isHighSurrogate() && secondEscapeEnd <= value.length &&
            value.startsWith("\\u", nextSlash)
        val second = if (hasSecondEscape) {
            value.substring(nextSlash + UNICODE_HEX_OFFSET, secondEscapeEnd).toIntOrNull(HEX_RADIX)?.toChar()
        } else {
            null
        }
        return second?.takeIf(Char::isLowSurrogate)
    }

    private fun decodeBase64Representations(value: String): List<String> {
        val decoded = linkedSetOf<String>()
        BASE64_TOKEN.findAll(value).take(MAX_BASE64_TOKENS).forEach { match ->
            val token = match.value.trimEnd('=')
            if (token.length % BASE64_QUANTUM_LENGTH == BASE64_INVALID_REMAINDER) return@forEach
            val paddedLength = (token.length + BASE64_QUANTUM_LENGTH - 1) / BASE64_QUANTUM_LENGTH *
                BASE64_QUANTUM_LENGTH
            val padded = token.padEnd(paddedLength, '=')
            listOf(Base64.getDecoder(), Base64.getUrlDecoder()).forEach { decoder ->
                runCatching { decoder.decode(padded) }
                    .getOrNull()
                    ?.let(::decodeUtf8)
                    ?.let(decoded::add)
            }
        }
        return decoded.toList()
    }

    private fun decodeUtf8(bytes: ByteArray): String? {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return runCatching { decoder.decode(ByteBuffer.wrap(bytes)).toString() }.getOrNull()
    }

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

    private fun AuthenticatedResponse.toRawProbe(
        durationMs: Long,
        requestMaterial: SessionRequestMaterialSnapshot? = null,
    ): RawProbe =
        if (statusCode in 100..599) {
            val bodyText = body ?: ""
            val reason = transientReasonFor(statusCode) ?: if (
                bodyText.trimStart().startsWith("<!") && bodyText.length > 50_000
            ) {
                "large HTML response may be a catch-all"
            } else {
                null
            }
            RawProbe(
                statusCode,
                bodyText,
                durationMs,
                inconclusiveReason = reason,
                requestMaterial = requestMaterial,
            )
        } else {
            RawProbe(null, "", 0, REQUEST_FAILED)
        }

    private fun Int?.isSuccess(): Boolean = this != null && this in 200..299

    private fun Int?.isSubstantiveSuccess(body: String): Boolean =
        this != null && this in 200..299 && this != 204 && this != 205 && body.isNotBlank()

    private fun Int?.isDenial(): Boolean = this in DENIAL_STATUSES

    private fun EndpointRequest.ambiguousAuthProbeError(reason: String) = EndpointProbeError(
        endpoint = url,
        method = method,
        test = "auth-bypass",
        probe = "auth-bypass-discriminator",
        error = reason,
    )

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
        private const val MAX_PROVENANCE_REPRESENTATIONS = 128
        private const val MAX_BASE64_TOKENS = 128
        private const val HEADER_ANOMALY_RATIO = 0.1
        private const val MIN_HEADER_ANOMALY_CHARS = 10
        private const val PERCENT_ENCODED_OCTET_LENGTH = 3
        private const val PERCENT_HEX_OFFSET = 1
        private const val HEX_RADIX = 16
        private const val HTML_HEX_ENTITY_PREFIX_LENGTH = 2
        private const val HTML_DECIMAL_ENTITY_PREFIX_LENGTH = 1
        private const val UNICODE_HEX_OFFSET = 2
        private const val JSON_UNICODE_ESCAPE_LENGTH = 6
        private const val JSON_SURROGATE_PAIR_ESCAPE_LENGTH = JSON_UNICODE_ESCAPE_LENGTH * 2
        private const val BASE64_QUANTUM_LENGTH = 4
        private const val BASE64_INVALID_REMAINDER = 1
        private const val MIN_PROBE_TIMEOUT_MS = 100L
        private const val MAX_PROBE_TIMEOUT_MS = 120_000L
        private const val ACTOR_SUPPLIED_MARKER =
            "protectedContentMarker appears in actor-supplied request material and cannot prove a protected read"
        private const val MARKER_PROVENANCE_UNAVAILABLE =
            "marker provenance could not be established from session request material; protected read is inconclusive"
        private const val COOKIE_CONTROL_DEGENERATED =
            "cookie-only probe carried no configured credentials, so it was identical to NONE and added no evidence; " +
                "header-only, API-key-only, and jar-cookie-only bypasses are not detectable in this state"
        private const val AUTH_BYPASS_PROOF_CEILING =
            "matching responses are not proof of a protected read; supply protectedContentMarker to decide"
        private const val AUTH_BYPASS_MARKER_REQUIRED =
            "a substantive unauthenticated response is not proof of a protected read; " +
                "supply protectedContentMarker to decide"

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
        private val PERCENT_RUN = Regex("(?:%[0-9A-Fa-f]{2})+")
        private val HTML_ENTITY = Regex(
            "&(#(?:[xX][0-9A-Fa-f]+|[0-9]+)|amp|lt|gt|quot|apos|nbsp);",
            RegexOption.IGNORE_CASE,
        )
        private val HTML_NAMED_ENTITIES = mapOf(
            "amp" to '&'.code,
            "lt" to '<'.code,
            "gt" to '>'.code,
            "quot" to '"'.code,
            "apos" to '\''.code,
            "nbsp" to 0xA0,
        )
        private val BASE64_TOKEN = Regex("(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{4,}={0,2}")
        private val METHOD_TOKEN = Regex("^[A-Z]+$")
        private val PARAM_NAME = Regex("^[A-Za-z0-9._~-]+$")
        private val HEADER_NAME = Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        private val KNOWN_CREDENTIAL_HEADERS = setOf(
            "authorization", "proxy-authorization", "cookie", "cookie2",
            "x-api-key", "api-key", "x-auth-token", "x-access-token",
            "private-token", "x-gitlab-token", "x-session-token",
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
