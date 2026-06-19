package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.models.*
import java.net.URI

class SecurityScanService(
    private val api: MontoyaApi,
    private val sessionService: SessionService,
    private val historyDao: HistoryDao?,
) {

    /**
     * Internal raw probe result carrying response body text alongside status/timing.
     * Used for content-aware comparisons (auth-bypass similarity, IDOR baseline matching)
     * without polluting the serialized [AuthBypassProbeResult] model with a body field.
     */
    internal data class RawProbe(val status: Int, val bodyText: String, val durationMs: Long) {
        fun toProbeResult() = AuthBypassProbeResult(
            status = status,
            length = bodyText.length,
            durationMs = durationMs,
        )
    }

    fun authBypass(request: AuthBypassRequest): AuthBypassResponse {
        require(request.endpoints.isNotEmpty()) { "endpoints list must not be empty" }

        val results = request.endpoints.map { endpoint ->
            val url = request.baseUrl.trimEnd('/') + endpoint

            // Probe 1: with full session auth — raw to capture body for content comparison
            val withAuthRaw = probeWithAuthRaw(url, request.method)
            val withAuth = withAuthRaw.toProbeResult()

            // Probe 2: no auth at all (bypass SessionService entirely)
            val withoutAuthRaw = probeNoAuthRaw(url, request.method)
            val withoutAuth = withoutAuthRaw.toProbeResult()

            // Probe 3: cookies only (no extra session headers like x-group-id)
            val cookieOnly = probeCookieOnly(url, request.method)

            // [07] Flag vulnerable only when BOTH probes are 2xx AND the unauthenticated
            // response carries substantially similar content to the authenticated one.
            // A login page / redirect stub that returns 200 with DIFFERENT content is NOT a bypass.
            val vulnerable = withoutAuthRaw.status in 200..299
                && withAuthRaw.status in 200..299
                && contentSimilar(withAuthRaw.bodyText, withoutAuthRaw.bodyText)

            AuthBypassEndpointResult(
                endpoint = endpoint,
                withAuth = withAuth,
                withoutAuth = withoutAuth,
                cookieOnly = cookieOnly,
                vulnerable = vulnerable,
            )
        }

        return AuthBypassResponse(
            results = results,
            totalScanned = results.size,
            vulnerableCount = results.count { it.vulnerable },
        )
    }

    fun idor(request: IdorRequest): IdorResponse {
        require(request.ownValues.isNotEmpty()) { "ownValues must not be empty" }
        require(request.targetValues.isNotEmpty()) { "targetValues must not be empty" }

        // [11] Surface ignored own values — only the first is used as baseline; callers
        // supplying multiple ownValues should know the rest are not tested.
        val ignoredOwnValues = request.ownValues.drop(1)

        // [08] Limitation note: IDOR detection reports any cross-object access regardless of
        // privilege direction; whether admin→user or user→admin is meaningful is analyst judgment.
        val idorNote = "Reports any cross-object access regardless of privilege direction; " +
            "verify findings manually to confirm whether direction implies a real security issue."

        // Baseline: use first own value
        val baselineUrl = substituteParam(request.endpoint, request.param, request.ownValues.first())
        val baselineResp = sessionService.send(AuthenticatedRequest(
            method = request.method, url = baselineUrl, body = request.body,
            extraHeaders = request.extraHeaders,
        ))

        val baselineBodyPreview = baselineResp.body?.take(200)

        val baseline = IdorProbeResult(
            value = request.ownValues.first(),
            status = baselineResp.statusCode,
            length = baselineResp.body?.length ?: 0,
            bodyPreview = baselineBodyPreview,
            sameAsBaseline = true,
            vulnerable = false,
        )

        // Test each target value
        val results = request.targetValues.map { targetValue ->
            val url = substituteParam(request.endpoint, request.param, targetValue)
            val resp = sessionService.send(AuthenticatedRequest(
                method = request.method, url = url, body = request.body,
                extraHeaders = request.extraHeaders,
            ))

            val length = resp.body?.length ?: 0
            val targetBodyPreview = resp.body?.take(200)

            // [09] sameAsBaseline is content-primary with length tiebreaker:
            //  - When BOTH previews are available and DIFFER → different record → NOT same as baseline.
            //  - When previews are EQUAL (first 200 chars match) → fall back to length-delta check.
            //    A target body that shares the first 200 chars but is materially longer (extra secret
            //    fields beyond byte 200) must NOT be treated as the same record. Reuse the same
            //    5% / coerceAtLeast(10) threshold to decide "materially different".
            //  - When previews are unavailable → length-delta check only (original heuristic).
            val lengthThreshold = (baseline.length * 0.05).toInt().coerceAtLeast(10)
            val sameAsBaseline = if (baselineBodyPreview != null && targetBodyPreview != null) {
                // Primary signal: content equality of first 200 chars
                if (baselineBodyPreview != targetBodyPreview) {
                    false  // Different previews → different record
                } else {
                    // Previews equal — tiebreaker: length must also be within threshold
                    kotlin.math.abs(length - baseline.length) < lengthThreshold
                }
            } else {
                // Secondary fallback: length delta (original heuristic, kept when content unavailable)
                resp.statusCode == baseline.status &&
                    kotlin.math.abs(length - baseline.length) < lengthThreshold
            }

            val vulnerable = !sameAsBaseline && resp.statusCode in 200..299 && length > 0

            IdorProbeResult(
                value = targetValue,
                status = resp.statusCode,
                length = length,
                bodyPreview = targetBodyPreview,
                sameAsBaseline = sameAsBaseline,
                vulnerable = vulnerable,
            )
        }

        return IdorResponse(
            baseline = baseline,
            results = results,
            vulnerableCount = results.count { it.vulnerable },
            ignoredOwnValues = ignoredOwnValues,
            note = idorNote,
        )
    }

    fun headersBypass(request: HeadersBypassRequest): HeadersBypassResponse {
        // Baseline request
        val baselineResp = sessionService.send(AuthenticatedRequest(
            method = request.method, url = request.url, body = request.body,
        ))
        val baseline = AuthBypassProbeResult(
            status = baselineResp.statusCode,
            length = baselineResp.body?.length ?: 0,
            durationMs = baselineResp.durationMs,
        )

        val results = BYPASS_HEADERS.map { (header, value) ->
            val resp = sessionService.send(AuthenticatedRequest(
                method = request.method, url = request.url, body = request.body,
                extraHeaders = mapOf(header to value),
            ))
            val status = resp.statusCode
            val length = resp.body?.length ?: 0
            val anomalous = status != baseline.status ||
                kotlin.math.abs(length - baseline.length) > (baseline.length * 0.1).toInt().coerceAtLeast(50)

            HeadersBypassResult(
                header = header, value = value,
                status = status, length = length, anomalous = anomalous,
            )
        }

        return HeadersBypassResponse(
            baseline = baseline,
            results = results,
            anomalousCount = results.count { it.anomalous },
        )
    }

    fun cors(request: CorsRequest): CorsResponse {
        val host = try { URI(request.url).host ?: "unknown" } catch (_: Exception) { "unknown" }

        val origins = listOf(
            "https://evil.com",
            "null",
            "https://$host.evil.com",
            "https://evil.$host",
            "https://${host}evil.com",
            "https://evil.com%40$host",
            "https://$host%60.evil.com",
            "https://sub.$host",
        )

        val results = origins.map { origin ->
            val resp = sessionService.send(AuthenticatedRequest(
                method = request.method, url = request.url,
                extraHeaders = mapOf("Origin" to origin),
            ))
            val acao = resp.headers.find { it.name.equals("Access-Control-Allow-Origin", ignoreCase = true) }?.value
            val acac = resp.headers.find { it.name.equals("Access-Control-Allow-Credentials", ignoreCase = true) }?.value

            // Vulnerable if origin is reflected (server echoes back the attacker-controlled origin)
            // AND credentials are allowed. A static ACAO that never mirrors the sent origin is NOT
            // exploitable as a CORS credential-theft vector even when ACAC is true.
            val vulnerable = acao != null && acao != "*" && acao == origin &&
                acac?.equals("true", ignoreCase = true) == true

            CorsProbeResult(origin = origin, acao = acao, acac = acac, vulnerable = vulnerable)
        }

        return CorsResponse(results = results, vulnerableCount = results.count { it.vulnerable })
    }

    fun scanEndpoints(request: EndpointsScanRequest): EndpointsScanResponse {
        val dao = historyDao ?: throw IllegalStateException("Database required for endpoint scanning")
        val start = System.currentTimeMillis()

        val entries = dao.search(HistoryFilter(host = request.host, pageSize = request.limit))
        val uniqueEndpoints = entries.map { it.method to it.url }.distinct()
        val findings = mutableListOf<EndpointFinding>()

        if ("auth-bypass" in request.tests) {
            // [10] Use the ORIGINAL method from history, not a hardcoded "GET".
            // A POST-only endpoint probed as GET returns 405 and the bypass is missed.
            for ((method, url) in uniqueEndpoints) {
                val withAuthRaw = probeWithAuthRaw(url, method)
                val withoutAuthRaw = probeNoAuthRaw(url, method)
                // Report when unauthenticated probe receives a non-error response AND the
                // content resembles the authenticated response (not just a login page redirect).
                if (withoutAuthRaw.status in 200..299
                    && withAuthRaw.status in 200..299
                    && contentSimilar(withAuthRaw.bodyText, withoutAuthRaw.bodyText)
                ) {
                    findings.add(EndpointFinding(
                        endpoint = url, method = method, test = "auth-bypass",
                        detail = "Accessible without auth: ${withoutAuthRaw.status} (${withoutAuthRaw.bodyText.length} bytes)",
                        severity = "high",
                    ))
                }
            }
        }

        if ("method-switch" in request.tests) {
            val altMethods = listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
            val urlsByMethod = uniqueEndpoints.groupBy({ it.second }, { it.first })

            for ((url, knownMethods) in urlsByMethod) {
                for (method in altMethods) {
                    if (method in knownMethods) continue
                    val resp = try {
                        sessionService.send(AuthenticatedRequest(method = method, url = url))
                    } catch (_: Exception) { continue }
                    if (resp.statusCode in 200..299 && resp.body?.let { it.length > 0 && !it.trimStart().startsWith("<!") } == true) {
                        findings.add(EndpointFinding(
                            endpoint = url, method = method, test = "method-switch",
                            detail = "Method $method returns ${resp.statusCode} (${resp.body?.length ?: 0} bytes) — not tested before",
                            severity = "medium",
                        ))
                    }
                }
            }
        }

        return EndpointsScanResponse(
            scanned = uniqueEndpoints.size,
            findings = findings,
            durationMs = System.currentTimeMillis() - start,
        )
    }

    // --- Internal helpers ---

    /**
     * Probe with full session auth and return a [RawProbe] that includes the response body.
     * Internal and open so tests can override via spyk without hitting the Montoya static factory.
     */
    internal open fun probeWithAuthRaw(url: String, method: String): RawProbe {
        val start = System.currentTimeMillis()
        val resp = sessionService.send(AuthenticatedRequest(method = method, url = url))
        return RawProbe(
            status = resp.statusCode,
            bodyText = resp.body ?: "",
            durationMs = System.currentTimeMillis() - start,
        )
    }

    /**
     * Probe with NO auth, bypassing SessionService entirely.
     * Not recorded in history (intentional: avoids polluting session history with unauth probes).
     * Internal and open so tests can override via spyk without hitting the Montoya static factory.
     */
    internal open fun probeNoAuthRaw(url: String, method: String): RawProbe {
        return try {
            val start = System.currentTimeMillis()
            val req = HttpRequest.httpRequestFromUrl(url).withMethod(method)
            val httpResponse = api.http().sendRequest(req)
            val resp = httpResponse.response()
            val body = if (resp.body().length() > 0) resp.bodyToString() else ""
            // Filter out SPA HTML catch-all (returns 200 with HTML for any unknown route)
            val isSpaHtml = body.trimStart().startsWith("<!") && body.length > 50000
            RawProbe(
                status = if (isSpaHtml) 302 else resp.statusCode().toInt(),
                bodyText = if (isSpaHtml) "" else body,
                durationMs = System.currentTimeMillis() - start,
            )
        } catch (e: Exception) {
            RawProbe(status = 0, bodyText = "", durationMs = 0)
        }
    }

    private fun probeCookieOnly(url: String, method: String): AuthBypassProbeResult {
        return try {
            val start = System.currentTimeMillis()
            val session = sessionService.getSession()
            val cookieHeader = session.cookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
            var req = HttpRequest.httpRequestFromUrl(url).withMethod(method)
            if (cookieHeader.isNotEmpty()) {
                req = req.withAddedHeader("Cookie", cookieHeader)
            }
            val httpResponse = api.http().sendRequest(req)
            val resp = httpResponse.response()
            AuthBypassProbeResult(
                status = resp.statusCode().toInt(),
                length = if (resp.body().length() > 0) resp.bodyToString().length else 0,
                durationMs = System.currentTimeMillis() - start,
            )
        } catch (e: Exception) {
            AuthBypassProbeResult(status = 0, length = 0, durationMs = 0)
        }
    }

    /**
     * Returns true when two response bodies are substantially similar — i.e. the unauthenticated
     * probe returned the same protected content as the authenticated one.
     *
     * Similarity is determined by:
     *  1. Exact equality of the first 200 chars (body preview) — primary signal.
     *  2. Length within 10% as a secondary tiebreaker when bodies are short and previews are equal.
     *
     * A short login/redirect page that shares no content with the auth response will score false.
     */
    private fun contentSimilar(authBody: String, unauthBody: String): Boolean {
        // Both empty: inconclusive — no protected content is present to confirm a bypass.
        // Returning true here would flag every public endpoint that returns an empty 200 body
        // as a vulnerability (false positive). Return false so callers skip it.
        if (authBody.isEmpty() && unauthBody.isEmpty()) return false
        if (authBody.isEmpty() || unauthBody.isEmpty()) return false
        val authPreview = authBody.take(200)
        val unauthPreview = unauthBody.take(200)
        if (authPreview != unauthPreview) return false
        // Previews match; check overall length ratio for long bodies that share a short prefix
        val longer = maxOf(authBody.length, unauthBody.length).toDouble()
        val shorter = minOf(authBody.length, unauthBody.length).toDouble()
        return shorter / longer >= 0.80
    }

    internal fun substituteParam(urlTemplate: String, param: String, value: String): String {
        // 1) {param} placeholder -> value
        if (urlTemplate.contains("{$param}")) {
            return urlTemplate.replace("{$param}", value)
        }
        // 2) existing ?param=old / &param=old -> replace the value
        val queryParamRegex = Regex("([?&])${Regex.escape(param)}=([^&#]*)")
        if (queryParamRegex.containsMatchIn(urlTemplate)) {
            return queryParamRegex.replace(urlTemplate) { "${it.groupValues[1]}$param=$value" }
        }
        // 3) param absent: APPEND it. Otherwise the IDOR check would test the SAME url for the
        // baseline and every target value (a silent false negative on a real IDOR). Preserve any
        // #fragment and pick ? or & correctly.
        val hashIdx = urlTemplate.indexOf('#')
        val base = if (hashIdx >= 0) urlTemplate.substring(0, hashIdx) else urlTemplate
        val frag = if (hashIdx >= 0) urlTemplate.substring(hashIdx) else ""
        val sep = if (base.contains("?")) "&" else "?"
        return "$base$sep$param=$value$frag"
    }

    companion object {
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
