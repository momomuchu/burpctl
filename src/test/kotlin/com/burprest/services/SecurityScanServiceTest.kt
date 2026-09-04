package com.burprest.services

import com.burprest.db.HistoryDao
import com.burprest.db.HistoryEntry
import com.burprest.db.HistoryFilter
import com.burprest.models.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.verify
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SecurityScanServiceTest {

    private data class ProvenanceRequest(
        val method: String = "GET",
        val url: String = "https://target.example/protected",
        val headers: List<HttpHeader> = emptyList(),
        val body: String? = null,
    )

    private val api = mockk<burp.api.montoya.MontoyaApi>(relaxed = true)
    private val sessionService = mockk<SessionService>(relaxed = true)
    private val historyDao = mockk<HistoryDao>(relaxed = true)
    private val svc = SecurityScanService(api, sessionService, historyDao)

    init {
        every { sessionService.cookieOnlyDiffersFromNone() } returns true
        bridgeObservedSends(sessionService)
    }

    // ---------------------------------------------------------------------------
    // substituteParam (pre-existing, kept as-is)
    // ---------------------------------------------------------------------------

    @Test
    fun `substituteParam replaces a {param} placeholder`() {
        assertEquals("http://t/orders/42", svc.substituteParam("http://t/orders/{id}", "id", "42"))
    }

    @Test
    fun `substituteParam replaces an existing query value`() {
        assertEquals("http://t/u?id=42&x=1", svc.substituteParam("http://t/u?id=1&x=1", "id", "42"))
    }

    @Test
    fun `substituteParam appends the param when absent (avoids the IDOR false negative)`() {
        assertEquals("http://t/u?id=42", svc.substituteParam("http://t/u", "id", "42"))
        assertEquals("http://t/u?a=1&id=42", svc.substituteParam("http://t/u?a=1", "id", "42"))
    }

    @Test
    fun `substituteParam preserves a fragment when appending`() {
        assertEquals("http://t/u?id=42#frag", svc.substituteParam("http://t/u#frag", "id", "42"))
    }

    // ---------------------------------------------------------------------------
    // [09] IDOR — sameAsBaseline must use content equality as primary signal
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [09]: different bodyPreview must be flagged vulnerable even when byte delta < floor.
     *
     * Baseline: own value "alice", bodyPreview="alice-record" (12 chars).
     * Target:   value "bob",   bodyPreview="bob-record  " (12 chars, DIFFERENT content, same length).
     * Old logic: same length -> abs(12-12)=0 < max(12*0.05=0,10)=10 -> sameAsBaseline=true -> NOT vulnerable.
     * New logic: bodyPreviews differ -> sameAsBaseline=false -> status 200 + length>0 -> vulnerable=true.
     */
    @Test
    fun `idor - different bodyPreview is flagged vulnerable even when byte delta is small`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("alice") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-record",
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("bob") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "bob-record  ",   // same length, different content
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/user?id={id}",
                param = "id",
                ownValues = listOf("alice"),
                targetValues = listOf("bob"),
            )
        )

        val bobResult = resp.results.first()
        assertFalse(bobResult.sameAsBaseline, "bob's record has different content — must NOT be sameAsBaseline")
        assertTrue(bobResult.vulnerable, "Different content returned for a target ID -> IDOR should be flagged vulnerable")
        assertEquals(1, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [09] counter-case: identical bodyPreview -> sameAsBaseline=true, not vulnerable.
     */
    @Test
    fun `idor - identical bodyPreview is sameAsBaseline regardless of small byte difference`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("alice") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-record",
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("alice2") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-record",   // identical content
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/user?id={id}",
                param = "id",
                ownValues = listOf("alice"),
                targetValues = listOf("alice2"),
            )
        )

        val result = resp.results.first()
        assertTrue(result.sameAsBaseline, "Identical bodyPreview -> must be sameAsBaseline=true")
        assertFalse(result.vulnerable, "Same content -> not vulnerable")
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [09]: simulate the exact reported scenario.
     * Baseline alice=71 bytes ("a"*71), target bob=67 bytes ("b"*67).
     * Byte delta=4, which is below the old floor of max(71*0.05=3,10)=10.
     * Old code: sameAsBaseline=true -> vulnerable=false (MISSED IDOR).
     * New code: bodyPreviews differ -> sameAsBaseline=false -> vulnerable=true.
     */
    @Test
    fun `idor - reported scenario alice 71 bytes vs bob 67 bytes different content is vulnerable`() {
        val aliceBody = "a".repeat(71)
        val bobBody   = "b".repeat(67)   // different content, smaller length (delta=4 < old floor 10)

        every {
            sessionService.scanSend(
                match { it.url.contains("alice") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = aliceBody,
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("bob") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = bobBody,
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/user?id={id}",
                param = "id",
                ownValues = listOf("alice"),
                targetValues = listOf("bob"),
            )
        )

        val bobResult = resp.results.first()
        assertFalse(bobResult.sameAsBaseline, "delta=4 with different content must not be sameAsBaseline")
        assertTrue(bobResult.vulnerable, "IDOR: different 200-content for bob must be flagged")
    }

    // ---------------------------------------------------------------------------
    // [07] auth-bypass — compare withoutAuth content against withAuth baseline
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [07]: withoutAuth returning DIFFERENT content (login page) is NOT vulnerable.
     *
     * Old logic: withoutAuth.status 200 + length>0 -> vulnerable=true (FALSE POSITIVE).
     * New logic: withoutAuth body differs from withAuth body -> vulnerable=false.
     *
     * Uses spyk to override probeNoAuthRaw and probeWithAuthRaw, bypassing the Montoya static
     * factory that cannot run outside a live Burp process.
     */
    @Test
    fun `authBypass - withoutAuth returning different content (login page) is not vulnerable`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        val protectedData = "protected-user-data-payload-with-lots-of-content"
        val loginPage     = "login-page-short-html"

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, protectedData, 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, loginPage, 0)

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/users"),
                baseUrl = "http://t",
                method = "GET",
                protectedContentMarker = protectedData,
            )
        )

        val result = resp.results.first()
        assertFalse(result.vulnerable,
            "Login-page body differs from auth body -> must NOT be flagged vulnerable")
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [07]: withoutAuth returning the authenticated representation while the
     * cookie-only control is denied establishes a credential-sensitive boundary and a bypass.
     */
    @Test
    fun `authBypass - unauthenticated protected content past a denied cookie-only control is vulnerable`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        val protectedData = "protected-user-data-payload-with-lots-of-content"

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, protectedData, 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            observedClearProbe(200, protectedData, 0)
        every {
            sessionService.scanSend(any(), emptyList(), CredentialMode.COOKIES_ONLY, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/users"),
                baseUrl = "http://t",
                method = "GET",
                protectedContentMarker = protectedData,
            )
        )

        val result = resp.results.first()
        assertTrue(result.vulnerable,
            "Same protected content without auth -> genuine bypass -> vulnerable=true")
        assertEquals(1, resp.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // [10] scanEndpoints — auth-bypass sub-test uses original method, not hardcoded GET
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [10]: a POST endpoint in history is probed with POST, not GET.
     *
     * Strategy: use spyk to override probeWithAuthRaw and probeNoAuthRaw, capture the
     * method argument, and assert it is "POST".
     */
    @Test
    fun `scanEndpoints auth-bypass probes a POST endpoint with POST not GET`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        // Track which methods probeNoAuthRaw was called with
        val capturedMethods = mutableListOf<String>()

        every { spy.probeEndpointWithAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(200, "protected", 0)
        every { spy.probeEndpointNoAuthRaw(match<SecurityScanService.EndpointRequest> {
            capturedMethods += it.method
            true
        }) } returns SecurityScanService.RawProbe(401, "", 0)

        // One POST endpoint in history
        val entry = HistoryEntry(
            id = 1,
            source = "proxy",
            method = "POST",
            url = "http://t/api/submit",
            host = "t",
            reqHeaders = emptyList(),
            reqBody = null,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = null,
            durationMs = 10,
            timestamp = "2026-01-01T00:00:00Z",
        )
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(entry)

        spy.scanEndpoints(
            EndpointsScanRequest(
                host = "t",
                tests = listOf("auth-bypass"),
                limit = 10,
            )
        )

        assertTrue(capturedMethods.isNotEmpty(),
            "probeNoAuthRaw must have been called at least once")
        assertTrue(capturedMethods.all { it == "POST" },
            "auth-bypass must probe the POST endpoint with POST, not hardcoded GET; got: $capturedMethods")
    }

    // ---------------------------------------------------------------------------
    // [01] CORS — vulnerable only when server reflects the attacker-controlled origin
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [01]: static ACAO (https://myapp.com) + ACAC=true but NOT reflecting the
     * sent origin -> vulnerable must be false (false-positive guard).
     */
    @Test
    fun `cors - static non-reflected ACAO with credentials allowed is NOT vulnerable`() {
        // sessionService.send returns a response where ACAO is a static value, not the probed origin
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } answers {
            AuthenticatedResponse(
                statusCode = 200,
                headers = listOf(
                    // Static ACAO — never reflects the sent origin
                    HttpHeader("Access-Control-Allow-Origin", "https://myapp.com"),
                    HttpHeader("Access-Control-Allow-Credentials", "true"),
                ),
                body = "ok",
                durationMs = 0,
            )
        }

        val resp = svc.cors(CorsRequest(url = "https://myapp.com/api/data", method = "GET"))

        assertEquals(8, resp.results.size, "every configured attacker origin must be exercised")
        // None of the 8 probes should be vulnerable: ACAO never mirrors the sent origin
        assertTrue(
            resp.results.none { it.vulnerable },
            "Static ACAO (not reflecting origin) + ACAC=true must NOT be flagged vulnerable; got: ${resp.results.filter { it.vulnerable }}"
        )
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [01]: server ECHOES back the sent origin (reflection) + ACAC=true -> vulnerable=true.
     */
    @Test
    fun `cors - reflected origin with credentials allowed IS vulnerable`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } answers {
            val req = firstArg<AuthenticatedRequest>()
            val origin = req.extraHeaders?.get("Origin") ?: "https://evil.com"
            AuthenticatedResponse(
                statusCode = 200,
                headers = listOf(
                    // Echo the exact origin back — this is the reflection that makes it exploitable
                    HttpHeader("Access-Control-Allow-Origin", origin),
                    HttpHeader("Access-Control-Allow-Credentials", "true"),
                ),
                body = "ok",
                durationMs = 0,
            )
        }

        val resp = svc.cors(CorsRequest(url = "https://target.com/api/data", method = "GET"))

        // All probes receive reflected ACAO + ACAC=true -> all should be vulnerable
        assertTrue(
            resp.results.any { it.vulnerable },
            "Reflected ACAO + ACAC=true must be flagged vulnerable"
        )
        assertTrue(resp.vulnerableCount > 0)
    }

    // ---------------------------------------------------------------------------
    // [02] contentSimilar — both empty bodies must NOT be similar (inconclusive)
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [02]: contentSimilar("","") must return false.
     * Two empty bodies are inconclusive — no protected content to confirm a bypass.
     */
    @Test
    fun `authBypass - two empty bodies are NOT flagged vulnerable (contentSimilar false for both-empty)`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "", 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "", 0)

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/public-empty"),
                baseUrl = "http://t",
                method = "GET",
            )
        )

        val result = resp.results.first()
        assertFalse(
            result.vulnerable,
            "Both bodies empty -> inconclusive -> contentSimilar must return false -> not vulnerable"
        )
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [02] counter-case: a denied cookie-only control plus a non-empty authenticated
     * representation returned with no credentials still yields vulnerable=true.
     */
    @Test
    fun `authBypass - equal non-empty protected bodies past denied cookie-only control ARE vulnerable`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        val body = "protected-content-payload"
        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, body, 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            observedClearProbe(200, body, 0)
        every {
            sessionService.scanSend(any(), emptyList(), CredentialMode.COOKIES_ONLY, false)
        } returns AuthenticatedResponse(401, emptyList(), "login required", 1)

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/data"),
                baseUrl = "http://t",
                method = "GET",
                protectedContentMarker = body,
            )
        )

        assertTrue(resp.results.first().vulnerable, "Equal non-empty bodies -> bypass confirmed -> vulnerable=true")
        assertEquals(1, resp.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // [03] IDOR — equal preview but materially longer target must NOT be sameAsBaseline
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [03]: baseline and target share the same first 200 chars but target has
     * 200 extra bytes (well beyond the 5% / coerceAtLeast(10) threshold).
     * Old code: previews equal -> sameAsBaseline=true -> NOT vulnerable (FALSE NEGATIVE).
     * New code: previews equal BUT length delta too large -> sameAsBaseline=false -> vulnerable=true.
     */
    @Test
    fun `idor - equal preview but target materially longer is NOT sameAsBaseline and IS vulnerable`() {
        val sharedPrefix = "x".repeat(200)  // exactly 200 chars — identical preview for both
        val baselineBody = sharedPrefix + "baseline-only-data"
        val targetBody   = sharedPrefix + "target-extra-secret-fields-" + "y".repeat(200)  // ~200+ extra bytes

        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = baselineBody,
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("other") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = targetBody,
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("other"),
            )
        )

        val result = resp.results.first()
        assertFalse(
            result.sameAsBaseline,
            "Equal preview but target is ${targetBody.length - baselineBody.length} bytes longer than baseline — must NOT be sameAsBaseline"
        )
        assertTrue(result.vulnerable, "Materially longer response for another ID -> IDOR -> vulnerable=true")
        assertEquals(1, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [03] counter-case: equal preview AND equal length -> sameAsBaseline=true, not vulnerable.
     */
    @Test
    fun `idor - equal preview and equal length IS sameAsBaseline and NOT vulnerable`() {
        val sharedBody = "x".repeat(200) + "common-suffix"

        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = sharedBody,
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("other"),
            )
        )

        val result = resp.results.first()
        assertTrue(result.sameAsBaseline, "Equal preview + equal length -> same record -> sameAsBaseline=true")
        assertFalse(result.vulnerable, "Same content -> not an IDOR -> not vulnerable")
        assertEquals(0, resp.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // [06] IDOR — baseline non-2xx must suppress all vulnerable flags (false-positive guard)
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [06]: baseline (own ID) returns 404 (error page).
     * Target returns 200 with a completely different body.
     * Old code: sameAsBaseline=false (different previews) + status 200 + length>0 -> vulnerable=true (FALSE POSITIVE).
     * New code: baseline.status=404 is not in 200..299 -> no target may be marked vulnerable -> vulnerableCount=0.
     */
    @Test
    fun `idor - baseline returning 404 suppresses all vulnerable flags even when target returns 200 with different body`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 404,
            headers = emptyList(),
            body = "Not Found — error page content that differs from any real record",
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("other") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "real-user-record-content-completely-different-from-baseline",
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("other"),
            )
        )

        assertEquals(
            0,
            resp.vulnerableCount,
            "Baseline is 404 — comparison against an error body is meaningless; no target must be flagged vulnerable"
        )
        assertFalse(
            resp.results.first().vulnerable,
            "Target must not be vulnerable when baseline itself failed (404)"
        )
    }

    /**
     * RED->GREEN [06] regression lock: baseline 200 + target 200 + different body still flags vulnerable.
     * Verifies the fix does not regress the normal detection path.
     */
    @Test
    fun `idor - baseline returning 200 and target returning 200 with different body remains vulnerable`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-private-record",
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("other") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "bob-private-record-different",
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("other"),
            )
        )

        assertEquals(
            1,
            resp.vulnerableCount,
            "Baseline 200 + target 200 with different content -> genuine IDOR -> vulnerableCount must be 1"
        )
        assertTrue(resp.results.first().vulnerable)
    }

    // ---------------------------------------------------------------------------
    // [01] IDOR — null/empty baseline body with non-empty target body is structurally DIFFERENT
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [01]: SessionService returns body=null for an empty HTTP response body.
     * Baseline: own value, body=null (empty), status=200.
     * Target:   value "tgt", body="ok" (non-empty), status=200.
     *
     * Old logic: baselineBodyPreview=null, targetBodyPreview="ok" -> falls into ELSE branch
     * (length-delta only). lengthThreshold=max((0*0.05).toInt(),10)=10.
     * abs(2-0)=2 < 10 -> sameAsBaseline=true -> vulnerable=false. (FALSE NEGATIVE)
     *
     * New logic: exactly one of {baselineBodyPreview, targetBodyPreview} is null/empty and
     * the other is non-empty -> structurally DIFFERENT records -> sameAsBaseline=false ->
     * baselineSucceeded=true + status 200 + length>0 -> vulnerable=true.
     */
    @Test
    fun `idor - null baseline body with non-empty target body is NOT sameAsBaseline and IS vulnerable`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = null,   // SessionService returns null when HTTP response body is empty
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("tgt") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "ok",   // short affirmative body — the real IDOR payload
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("tgt"),
            )
        )

        val result = resp.results.first()
        assertFalse(
            result.sameAsBaseline,
            "Null baseline body vs non-empty target body must be structurally DIFFERENT -> sameAsBaseline=false"
        )
        assertTrue(
            result.vulnerable,
            "Non-empty target body when baseline is empty (null) -> IDOR must be flagged vulnerable"
        )
        assertEquals(1, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [01] counter-case: baseline body=null AND target body=null
     * -> both empty -> sameAsBaseline=true -> NOT vulnerable.
     * No content to compare; treating two empty responses as "the same" avoids false positives.
     */
    @Test
    fun `idor - null baseline body with null target body is sameAsBaseline and NOT vulnerable`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = null,   // both baseline and target return null body
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("tgt"),
            )
        )

        val result = resp.results.first()
        assertTrue(
            result.sameAsBaseline,
            "Both baseline and target body null (both empty) -> sameAsBaseline=true (no content to differentiate)"
        )
        assertFalse(result.vulnerable, "Both empty responses -> not vulnerable")
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [01] regression lock: non-null baseline body with non-null target body
     * (different content) must still be flagged vulnerable — the asymmetric-null guard
     * must not break the existing content-primary path.
     */
    @Test
    fun `idor - non-null different bodies still flagged vulnerable after null guard`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-record",
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("tgt") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "bob-record",
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("tgt"),
            )
        )

        val result = resp.results.first()
        assertFalse(result.sameAsBaseline, "Different non-null bodies must not be sameAsBaseline")
        assertTrue(result.vulnerable, "Different non-null bodies -> IDOR -> vulnerable=true")
        assertEquals(1, resp.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // [round-5][01] IDOR — full-body equality: identical first 200 chars but differ after byte 200
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [round-5][01]: two bodies that share IDENTICAL first 200 chars AND equal total
     * length but differ AFTER byte 200 (e.g. different role/SSN/salary in the tail).
     *
     * Old code: baselineBodyPreview == targetBodyPreview (previews equal) AND
     *           abs(length - baseline.length) == 0 < threshold -> sameAsBaseline=true -> NOT vulnerable.
     *           (FALSE NEGATIVE — IDOR missed)
     *
     * New code (full-body equality): full baseline body != full target body -> sameAsBaseline=false
     *           -> baselineSucceeded=true + status 200 + length>0 -> vulnerable=true.
     */
    @Test
    fun `idor - identical first 200 chars same length but different tail is NOT sameAsBaseline and IS vulnerable`() {
        val sharedPrefix = "x".repeat(200)
        val baselineBody = sharedPrefix + "role=admin;ssn=111-22-3333;salary=150000"
        val targetBody   = sharedPrefix + "role=user;ssn=999-88-7777;salary=60000"
        // Pad target to match length so the old length-delta tiebreaker would also pass
        val targetBodyPadded = targetBody.padEnd(baselineBody.length, '.')

        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = baselineBody,
            durationMs = 0,
        )
        every {
            sessionService.scanSend(
                match { it.url.contains("other") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = targetBodyPadded,
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("other"),
            )
        )

        val result = resp.results.first()
        // Previews are identical (first 200 chars = sharedPrefix), length is same,
        // but bodies differ after byte 200 — must NOT be sameAsBaseline
        assertFalse(
            result.sameAsBaseline,
            "Bodies share identical first 200 chars and equal length but differ in tail — sameAsBaseline must be false"
        )
        assertTrue(
            result.vulnerable,
            "Different tail content (role/SSN/salary) for another ID -> IDOR must be flagged vulnerable"
        )
        assertEquals(1, resp.vulnerableCount)
    }

    /**
     * [round-5][01] counter-case: FULLY identical bodies (including tail) -> sameAsBaseline=true, not vulnerable.
     */
    @Test
    fun `idor - fully identical bodies including tail IS sameAsBaseline and NOT vulnerable`() {
        val body = "x".repeat(200) + "role=admin;ssn=111-22-3333;salary=150000"

        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = body,
            durationMs = 0,
        )

        val resp = svc.idor(
            IdorRequest(
                endpoint = "http://t/resource?id={id}",
                param = "id",
                ownValues = listOf("own"),
                targetValues = listOf("other"),
            )
        )

        val result = resp.results.first()
        assertTrue(
            result.sameAsBaseline,
            "Fully identical bodies (same prefix AND same tail) -> sameAsBaseline=true"
        )
        assertFalse(result.vulnerable, "Fully identical bodies -> not an IDOR -> not vulnerable")
        assertEquals(0, resp.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // [08] and [11] — model fields wired (note, ignoredOwnValues)
    // ---------------------------------------------------------------------------

    // [08] IDOR detection reports cross-object access regardless of privilege direction;
    // that limitation is surfaced as a note so the analyst applies judgement.
    @Test
    fun `idor - response includes privilege direction limitation note`() {
        every {
            sessionService.scanSend(
                any(),
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(200, emptyList(), "body", 0)
        val resp = svc.idor(IdorRequest("http://t?id={id}", "id", listOf("1"), listOf("2")))
        assertNotNull(resp.note)
        assertTrue(resp.note!!.contains("privilege direction", ignoreCase = true))
    }

    // [11] Only the first own value is the baseline; the rest are not tested and must be surfaced.
    @Test
    fun `idor - multiple own values lists ignored ones in ignoredOwnValues`() {
        every {
            sessionService.scanSend(
                any(),
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(200, emptyList(), "body", 0)
        val resp = svc.idor(IdorRequest("http://t?id={id}", "id", listOf("1", "2", "3"), listOf("99")))
        assertEquals(listOf("2", "3"), resp.ignoredOwnValues)
    }

    // ---------------------------------------------------------------------------
    // [02] substituteParam — case-insensitive query-param match (IDOR false-negative guard)
    // ---------------------------------------------------------------------------

    /**
     * RED->[02]: caller passes --param ID (uppercase) but URL has ?id=1 (lowercase).
     * Old code: Regex is case-sensitive, misses ?id=, falls to append branch -> ?id=1&ID=3.
     * Server ignores duplicate-cased param, serves original resource, IDOR silently missed.
     * Fix: add RegexOption.IGNORE_CASE so ?id= is REPLACED, not appended.
     * Expected: the result contains exactly one occurrence of the param assignment with value 3,
     * and does NOT contain a second ampersand-separated assignment for the same param.
     */
    @Test
    fun `substituteParam replaces existing query param case-insensitively when caller param casing differs from URL`() {
        // URL has ?id= (lower), caller passes ID (upper)
        val result = svc.substituteParam("http://t/u?id=1", "ID", "3")
        // Must NOT append &ID=3 — that would mean two assignments for the same logical param
        assertFalse(
            result.contains("id=1"),
            "Old lowercase assignment must be replaced, not kept: got $result"
        )
        assertFalse(
            result.contains("&ID=3"),
            "No second ampersand-appended assignment must exist: got $result"
        )
        // The value 3 must appear exactly once as a param assignment
        assertTrue(
            result.contains("=3"),
            "New value must appear in the result: got $result"
        )
        // The URL's ORIGINAL param-name casing (id) must be preserved — replacing it with the
        // caller's casing (ID) would still miss a case-sensitive server that only reads ?id=.
        assertTrue(
            result.contains("id=3"),
            "Matched URL param name (id) must be preserved, not rewritten to caller casing: got $result"
        )
    }

    @Test
    fun `substituteParam exact-case replacement still works after adding IGNORE_CASE`() {
        // Regression lock: existing same-case replacement must not be broken
        assertEquals(
            "http://t/u?id=3&x=1",
            svc.substituteParam("http://t/u?id=1&x=1", "id", "3")
        )
    }

    // ---------------------------------------------------------------------------
    // [04] contentSimilar — full-body equality: bodies identical in first 200 chars
    //      and similar length but different tails must NOT be similar
    // ---------------------------------------------------------------------------

    /**
     * RED->[04]: two bodies with identical first 200 chars and within-80%-length-ratio
     * but diverging after byte 200.
     * Old code: preview match + length ratio >= 0.80 -> contentSimilar=true -> false positive.
     * Fix: require FULL-body equality; 200-char/length checks are only fast-negative pre-checks.
     * Expected: contentSimilar=false -> authBypass not flagged vulnerable.
     */
    @Test
    fun `authBypass - bodies equal in first 200 chars and similar length but different tails are NOT similar`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        val sharedPrefix = "A".repeat(200)
        val authBody   = sharedPrefix + "secret-field=salary=150000;role=admin"
        val unauthBody = sharedPrefix + "public-stub=no-content;role=guest---"   // same length, different tail

        // Ensure same length so the old 80%-ratio check would have passed
        val unauthBodyPadded = unauthBody.padEnd(authBody.length, '-')

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, authBody, 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, unauthBodyPadded, 0)

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/sensitive"),
                baseUrl = "http://t",
                method = "GET",
                protectedContentMarker = "role=admin",
            )
        )

        assertFalse(
            resp.results.first().vulnerable,
            "Bodies share 200-char prefix and similar length but differ after byte 200 " +
                "-> contentSimilar must be false -> NOT vulnerable; got: ${resp.results.first()}"
        )
        assertEquals(0, resp.vulnerableCount)
    }

    @Test
    fun `authBypass - fully identical protected bodies past denied cookie control ARE vulnerable`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val body = "A".repeat(200) + "role=admin;salary=150000"

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, body, 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            observedClearProbe(200, body, 0)
        every {
            sessionService.scanSend(any(), emptyList(), CredentialMode.COOKIES_ONLY, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/sensitive"),
                baseUrl = "http://t",
                method = "GET",
                protectedContentMarker = "role=admin",
            )
        )

        assertTrue(
            resp.results.first().vulnerable,
            "Fully identical bodies -> contentSimilar=true -> vulnerable=true"
        )
        assertEquals(1, resp.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // [headersBypass-floor] anomaly threshold floor lowered from 50 to 10
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [headersBypass-floor]: baseline ~22-byte JSON, probe body grows by ~15 bytes
     * (same status 200).
     *
     * Old floor (50): abs(37-22)=15 > max((22*0.1).toInt()=2, 50)=50 -> 15 > 50 is FALSE
     * -> anomalous=false -> bypass silently missed.
     *
     * New floor (10): abs(37-22)=15 > max((22*0.1).toInt()=2, 10)=10 -> 15 > 10 is TRUE
     * -> anomalous=true -> bypass detected.
     */
    @Test
    fun `headersBypass - small-baseline probe growing 15 bytes above floor 10 is flagged anomalous`() {
        val baselineBody = """{"ok":true}"""          // 11 chars — well under 500-byte breakpoint
        val probeBody    = """{"ok":true,"extra":"injected-val"}"""  // 11+26=37 chars, delta=26 > floor 10

        every {
            sessionService.scanSend(
                match { it.extraHeaders == null || it.extraHeaders!!.isEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(statusCode = 200, headers = emptyList(), body = baselineBody, durationMs = 0)
        every {
            sessionService.scanSend(
                match { it.extraHeaders != null && it.extraHeaders!!.isNotEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(statusCode = 200, headers = emptyList(), body = probeBody, durationMs = 0)

        val resp = svc.headersBypass(
            HeadersBypassRequest(url = "http://t/api/data", method = "GET")
        )

        assertTrue(
            resp.results.any { it.anomalous },
            "Probe body grew 26 bytes on a 11-byte baseline (delta > floor 10) " +
                "-> at least one result must be anomalous; got: ${resp.results.map { it.anomalous }}"
        )
        assertTrue(resp.anomalousCount > 0)
    }

    /**
     * [headersBypass-floor] counter-case: tiny jitter of 5 bytes on a 22-byte baseline
     * is below floor 10 and must NOT be anomalous.
     *
     * abs(27-22)=5 > max((22*0.1).toInt()=2, 10)=10 -> 5 > 10 is FALSE -> anomalous=false.
     */
    @Test
    fun `headersBypass - tiny jitter under floor 10 is NOT anomalous`() {
        val baselineBody = """{"id":1,"v":1}"""          // 14 chars
        val probeBody    = """{"id":1,"v":1,"x":1}"""    // 20 chars, delta=6 < floor 10

        every {
            sessionService.scanSend(
                match { it.extraHeaders == null || it.extraHeaders!!.isEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(statusCode = 200, headers = emptyList(), body = baselineBody, durationMs = 0)
        every {
            sessionService.scanSend(
                match { it.extraHeaders != null && it.extraHeaders!!.isNotEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(statusCode = 200, headers = emptyList(), body = probeBody, durationMs = 0)

        val resp = svc.headersBypass(
            HeadersBypassRequest(url = "http://t/api/data", method = "GET")
        )

        assertEquals(16, resp.results.size, "every bypass header treatment must be exercised")
        assertTrue(
            resp.results.none { it.anomalous },
            "Probe body grew only 6 bytes on a 14-byte baseline (delta < floor 10) " +
                "-> no result must be anomalous; got: ${resp.results.map { it.anomalous }}"
        )
        assertEquals(0, resp.anomalousCount)
    }

    /**
     * [headersBypass-floor] regression lock: status change always flags anomalous
     * regardless of body length change.
     */
    @Test
    fun `headersBypass - status change from baseline is always anomalous`() {
        val body = """{"ok":true}"""

        every {
            sessionService.scanSend(
                match { it.extraHeaders == null || it.extraHeaders!!.isEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(statusCode = 200, headers = emptyList(), body = body, durationMs = 0)
        every {
            sessionService.scanSend(
                match { it.extraHeaders != null && it.extraHeaders!!.isNotEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(statusCode = 403, headers = emptyList(), body = body, durationMs = 0)

        val resp = svc.headersBypass(
            HeadersBypassRequest(url = "http://t/api/admin", method = "GET")
        )

        assertTrue(
            resp.results.any { it.anomalous },
            "Status change 200->403 must always be anomalous regardless of body size"
        )
        assertTrue(resp.anomalousCount > 0)
    }

    // ---------------------------------------------------------------------------
    // [03] CORS — own-subdomain reflection must NOT be flagged vulnerable (false-positive guard)
    // ---------------------------------------------------------------------------

    /**
     * RED->GREEN [03]: a server that echoes back the target's OWN subdomain origin
     * (https://sub.corp.com) with ACAC=true must NOT be flagged vulnerable.
     *
     * Rationale: https://sub.<host> is the target's own legitimate subdomain, NOT an
     * attacker-controlled origin.  A correct wildcard-subdomain CORS policy (reflecting
     * any *.corp.com with credentials) is expected behaviour.  Exploiting it would
     * require an independent subdomain-takeover — a separate, distinct class of finding.
     * The CORS detector's probe list must contain only genuinely attacker-controlled
     * origins so that a reflected-subdomain response cannot produce a false positive.
     *
     * Scenario:
     *   - Target URL: https://corp.com/api/data  (host = "corp.com")
     *   - Server policy: reflect any *.corp.com origin with ACAC=true.
     *   - Only the https://sub.corp.com probe would be reflected; all other probes
     *     (evil.com, null, etc.) are rejected (ACAO absent / not reflected).
     *
     * Before fix: "https://sub.corp.com" is in the probe list -> reflected -> vulnerable=true (FALSE POSITIVE).
     * After fix:  "https://sub.corp.com" is removed from probe list -> no reflection match -> vulnerable=false.
     */
    @Test
    fun `cors - server reflecting own subdomain origin with credentials is NOT vulnerable`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } answers {
            val req = firstArg<AuthenticatedRequest>()
            val origin = req.extraHeaders?.get("Origin") ?: return@answers AuthenticatedResponse(
                statusCode = 200, headers = emptyList(), body = "ok", durationMs = 0,
            )
            // Server reflects ONLY its own subdomain (https://sub.corp.com).
            // All other origins (evil.com, null, scheme tricks) are rejected.
            val isOwnSubdomain = origin == "https://sub.corp.com"
            val headers = if (isOwnSubdomain) {
                listOf(
                    HttpHeader("Access-Control-Allow-Origin", origin),
                    HttpHeader("Access-Control-Allow-Credentials", "true"),
                )
            } else {
                // Not reflected — no CORS headers for attacker-controlled origins
                emptyList()
            }
            AuthenticatedResponse(statusCode = 200, headers = headers, body = "ok", durationMs = 0)
        }

        val resp = svc.cors(CorsRequest(url = "https://corp.com/api/data", method = "GET"))

        assertEquals(8, resp.results.size, "every configured attacker origin must be exercised")
        // The own-subdomain origin must not appear in the probe list at all; if it does
        // it would produce vulnerable=true here, which is the false positive under test.
        assertTrue(
            resp.results.none { it.vulnerable },
            "Server reflecting its own subdomain (https://sub.corp.com) with credentials " +
                "must NOT be flagged vulnerable — subdomain is not an attacker-controlled origin; " +
                "got vulnerable probes: ${resp.results.filter { it.vulnerable }.map { it.origin }}"
        )
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [03] regression: a server reflecting https://evil.com (genuine attacker-controlled
     * origin) with ACAC=true IS still flagged vulnerable after the subdomain is removed.
     */
    @Test
    fun `cors - server reflecting evil dot com origin with credentials IS vulnerable`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } answers {
            val req = firstArg<AuthenticatedRequest>()
            val origin = req.extraHeaders?.get("Origin") ?: return@answers AuthenticatedResponse(
                statusCode = 200, headers = emptyList(), body = "ok", durationMs = 0,
            )
            // Server reflects ONLY https://evil.com — a genuine attacker-controlled origin
            val isEvilOrigin = origin == "https://evil.com"
            val headers = if (isEvilOrigin) {
                listOf(
                    HttpHeader("Access-Control-Allow-Origin", origin),
                    HttpHeader("Access-Control-Allow-Credentials", "true"),
                )
            } else {
                emptyList()
            }
            AuthenticatedResponse(statusCode = 200, headers = headers, body = "ok", durationMs = 0)
        }

        val resp = svc.cors(CorsRequest(url = "https://corp.com/api/data", method = "GET"))

        assertTrue(
            resp.results.any { it.vulnerable },
            "Server reflecting https://evil.com (attacker-controlled) with ACAC=true " +
                "must still be flagged vulnerable; got: ${resp.results.map { it.origin to it.vulnerable }}"
        )
        assertTrue(resp.vulnerableCount > 0)
    }

    // ---------------------------------------------------------------------------
    // [03] probeWithAuthRaw — must not propagate exceptions (sentinel on failure)
    // ---------------------------------------------------------------------------

    /**
     * RED->[03]: sessionService.send throws an exception inside probeWithAuthRaw.
     * Old code: no try/catch -> exception propagates -> whole scan aborts with opaque error.
     * Fix: wrap in same try/catch as probeNoAuthRaw, return RawProbe(status=0, bodyText="", durationMs=0).
     * Expected: probeWithAuthRaw returns the sentinel instead of throwing.
     */
    @Test
    fun `probeWithAuthRaw reports an explicit error when sessionService send throws`() {
        val throwingSvc = mockk<SessionService>(relaxed = true)
        every {
            throwingSvc.scanSend(any(), emptyList(), CredentialMode.FULL, false)
        } throws RuntimeException("connection refused")

        val result = SecurityScanService(api, throwingSvc, historyDao)
            .probeWithAuthRaw("http://t/api/resource", "GET")

        assertNull(result.status, "A transport failure is not an HTTP status")
        assertNotNull(result.error, "A failed probe must be explicit")
        assertEquals("", result.bodyText)
        assertEquals(0L, result.durationMs)
    }

    @Test
    fun `probeWithAuthRaw treats an absent session response as inconclusive`() {
        val absentSession = mockk<SessionService>()
        every {
            absentSession.scanSend(any(), emptyList(), CredentialMode.FULL, false)
        } answers { absentValue() }

        val result = SecurityScanService(api, absentSession, historyDao)
            .probeWithAuthRaw("https://target.example/resource", "GET")

        assertNull(result.status)
        assertTrue(result.inconclusive)
        assertEquals("request failed", result.error)
        assertEquals(0L, result.durationMs, "absent response uses the no-measurement sentinel")
    }

    @Test
    fun `probeWithAuthRaw returns real response when sessionService send succeeds`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "real-body",
            durationMs = 42,
        )

        val result = svc.probeWithAuthRaw("http://t/api/resource", "GET")

        assertEquals(200, result.status)
        assertNull(result.error)
        assertEquals("real-body", result.bodyText)
    }

    // ---------------------------------------------------------------------------
    // Comprehensive behavior hardening: validate the complete plan before effects
    // ---------------------------------------------------------------------------

    @Test
    fun `authBypass rejects an unsafe endpoint anywhere in the plan before every probe`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeWithAuthRaw(any(), any()) } returns SecurityScanService.RawProbe(200, "ok", 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns SecurityScanService.RawProbe(401, "", 0)

        assertFailsWith<IllegalArgumentException> {
            spy.authBypass(
                AuthBypassRequest(
                    endpoints = listOf("/safe", "https://other.example/escape"),
                    baseUrl = "https://target.example",
                )
            )
        }

        verify(exactly = 0) { spy.probeWithAuthRaw(any(), any()) }
        verify(exactly = 0) { spy.probeNoAuthRaw(any(), any()) }
        verify(exactly = 0) { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) }
    }

    @Test
    fun `all direct scanners reject unsafe methods and URLs without sending`() {
        val calls = listOf<() -> Unit>(
            { svc.authBypass(AuthBypassRequest(listOf("/x"), "file:///etc/passwd", "GET")) },
            { svc.authBypass(AuthBypassRequest(listOf("/x"), "https://target.example", "GET\r\nX-Evil: 1")) },
            { svc.idor(IdorRequest("https://target.example/u?id={id}", "id", listOf("1"), listOf("2"), "CONNECT")) },
            { svc.idor(IdorRequest("https://user:pass@target.example/u?id={id}", "id", listOf("1"), listOf("2"))) },
            { svc.headersBypass(HeadersBypassRequest("//target.example/x", "GET")) },
            { svc.headersBypass(HeadersBypassRequest("https://target.example/x#fragment", "GET")) },
            { svc.cors(CorsRequest("javascript:alert(1)", "GET")) },
            { svc.cors(CorsRequest("https://target.example/x", "TRACE")) },
        )

        assertEquals(8, calls.size, "every direct scanner rejection case must execute")
        calls.forEach { call -> assertFailsWith<IllegalArgumentException> { call() } }
        verify(exactly = 0) { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) }
    }

    @Test
    fun `all scanners reject unbounded or excessive probe budgets before effects`() {
        val invalidTimeouts = listOf(0L, 120_001L)
        assertEquals(2, invalidTimeouts.size, "both timeout boundaries must be exercised")
        for (timeoutMs in invalidTimeouts) {
            val calls = listOf<() -> Unit>(
                {
                    svc.authBypass(
                        AuthBypassRequest(listOf("/x"), "https://target.example", probeTimeoutMs = timeoutMs)
                    )
                },
                {
                    svc.idor(
                        IdorRequest(
                            "https://target.example/u?id={id}",
                            "id",
                            listOf("1"),
                            listOf("2"),
                            probeTimeoutMs = timeoutMs,
                        )
                    )
                },
                {
                    svc.headersBypass(
                        HeadersBypassRequest("https://target.example/x", probeTimeoutMs = timeoutMs)
                    )
                },
                { svc.cors(CorsRequest("https://target.example/x", probeTimeoutMs = timeoutMs)) },
                {
                    svc.scanEndpoints(
                        EndpointsScanRequest(
                            "target.example",
                            listOf("auth-bypass"),
                            probeTimeoutMs = timeoutMs,
                        )
                    )
                },
            )

            assertEquals(5, calls.size, "every scanner budget rejection case must execute")
            calls.forEach { call -> assertFailsWith<IllegalArgumentException> { call() } }
        }

        verify(exactly = 0) { historyDao.search(any<HistoryFilter>()) }
        verify(exactly = 0) { sessionService.scanSend(any(), any(), any(), any()) }
    }

    @Test
    fun `idor rejects blank values and header injection before baseline send`() {
        val invalidRequests = listOf(
            IdorRequest("https://target.example/u?id={id}", "", listOf("1"), listOf("2")),
            IdorRequest("https://target.example/u?id={id}", "id", listOf(""), listOf("2")),
            IdorRequest("https://target.example/u?id={id}", "id", listOf("1"), listOf("")),
            IdorRequest(
                "https://target.example/u?id={id}", "id", listOf("1"), listOf("2"),
                extraHeaders = mapOf("X-Test\r\nInjected" to "yes"),
            ),
            IdorRequest(
                "https://target.example/u?id={id}", "id", listOf("1"), listOf("2"),
                extraHeaders = mapOf("X-Test" to "yes\r\nInjected: true"),
            ),
        )

        assertEquals(5, invalidRequests.size, "every IDOR rejection case must execute")
        invalidRequests.forEach { request ->
            assertFailsWith<IllegalArgumentException> { svc.idor(request) }
        }
        verify(exactly = 0) { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) }
    }

    @Test
    fun `endpoint scan rejects unsupported tests blank hosts and out of range limits before history access`() {
        val invalidRequests = listOf(
            EndpointsScanRequest("target.example", listOf("auth-bypass", "unknown"), 10),
            EndpointsScanRequest("target.example", listOf("auth-bypass", "auth-bypass"), 10),
            EndpointsScanRequest("target.example", emptyList(), 10),
            EndpointsScanRequest("", listOf("auth-bypass"), 10),
            EndpointsScanRequest("https://target.example/path", listOf("auth-bypass"), 10),
            EndpointsScanRequest("target.example", listOf("auth-bypass"), 0),
            EndpointsScanRequest("target.example", listOf("auth-bypass"), 1001),
        )

        assertEquals(7, invalidRequests.size, "every endpoint-scan rejection case must execute")
        invalidRequests.forEach { request ->
            assertFailsWith<IllegalArgumentException> { svc.scanEndpoints(request) }
        }
        verify(exactly = 0) { historyDao.search(any<HistoryFilter>()) }
        verify(exactly = 0) { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) }
    }

    @Test
    fun `endpoint scan accepts both limit boundaries`() {
        every { historyDao.search(any<HistoryFilter>()) } returns emptyList()

        svc.scanEndpoints(EndpointsScanRequest("target.example", listOf("auth-bypass"), 1))
        svc.scanEndpoints(EndpointsScanRequest("target.example", listOf("method-switch"), 1000))

        verify(exactly = 1) { historyDao.search(match { it.pageSize == 1 }) }
        verify(exactly = 1) { historyDao.search(match { it.pageSize == 1000 }) }
    }

    // ---------------------------------------------------------------------------
    // Header bypass: anomaly is observation; only a denied control -> substantive 2xx is vulnerable
    // ---------------------------------------------------------------------------

    @Test
    fun `headersBypass confirms denial to substantive 2xx and reports vulnerableCount`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "protected admin content", 1)

        val response = svc.headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = "admin content",
            )
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertEquals(response.results.size, response.anomalousCount)
        assertEquals(response.results.size, response.vulnerableCount)
        assertTrue(response.results.all { it.anomalous && it.vulnerable })
    }

    @Test
    fun `headersBypass denial to 2xx without a protected marker remains anomaly only`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "generic login page", 1)

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/admin"))

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous && !it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass mismatched protected marker remains anomaly only`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "generic login page", 1)

        val response = svc.headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = "server-held admin marker",
            )
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous && !it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass treats reflection of its injected marker as inconclusive`() {
        val marker = "127.0.0.1"
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(403, emptyList(), "access denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } answers {
            val suppliedHeaders = firstArg<AuthenticatedRequest>().extraHeaders.orEmpty()
            if (suppliedHeaders["X-Forwarded-For"] == marker) {
                AuthenticatedResponse(200, emptyList(), "reflected:$marker", 1)
            } else {
                AuthenticatedResponse(403, emptyList(), "access denied", 1)
            }
        }

        val response = svc.headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = marker,
            )
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        val reflected = response.results.single {
            it.header == "X-Forwarded-For" && it.value == marker
        }
        assertFalse(
            reflected.vulnerable,
            "reflection of a marker supplied in the injected bypass header cannot prove a protected read",
        )
        assertTrue(reflected.inconclusive, "an actor-supplied marker must not fall through to clean")
        assertTrue(reflected.anomalous, "the denial-to-success response change remains an observation")
        assertTrue(reflected.error?.contains("actor-supplied") == true)
        assertEquals(0, response.vulnerableCount)
        assertTrue(response.inconclusiveCount > 0)
    }

    @Test
    fun `headersBypass marker already present in denial baseline cannot corroborate bypass`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(403, emptyList(), "admin marker - access denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "admin marker - login required", 1)

        val response = svc.headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = "admin marker",
            )
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous && !it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass rejects a blank protected marker before sending`() {
        assertFailsWith<IllegalArgumentException> {
            svc.headersBypass(
                HeadersBypassRequest(
                    "https://target.example/admin",
                    protectedContentMarker = "  ",
                )
            )
        }
        verify(exactly = 0) {
            sessionService.scanSend(any(), any(), any(), any())
        }
    }

    @Test
    fun `headersBypass keeps successful baseline deltas anomalous but never vulnerable`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "ordinary", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(201, emptyList(), "different substantive body", 1)

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/resource"))

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous })
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass does not call an empty or no-content success vulnerable`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(204, emptyList(), null, 1)

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/admin"))

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous })
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass does not call a 2xx denial body substantive`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(403, emptyList(), "access denied", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "access denied", 1)

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/admin"))

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous })
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass does not infer denial from a 404`() {
        every {
            sessionService.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(404, emptyList(), "not found", 1)
        every {
            sessionService.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "some other resource", 1)

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/missing"))

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.anomalous })
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass baseline transport failure is explicit and stops dependent probes`() {
        every {
            sessionService.scanSend(
                any(),
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } throws RuntimeException("connection refused")

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/admin"))

        assertNull(response.baseline.status)
        assertNotNull(response.baseline.error)
        assertTrue(response.results.isEmpty())
        assertEquals(1, response.inconclusiveCount)
        assertEquals(0, response.anomalousCount)
        assertEquals(0, response.vulnerableCount)
        verify(exactly = 1) { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) }
    }

    @Test
    fun `headersBypass transient baseline is explicit and stops dependent probes`() {
        every {
            sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(503, emptyList(), "unavailable", 1)

        val response = svc.headersBypass(HeadersBypassRequest("https://target.example/admin"))

        assertEquals(503, response.baseline.status)
        assertTrue(response.baseline.inconclusive)
        assertNotNull(response.baseline.inconclusiveReason)
        assertTrue(response.results.isEmpty())
        assertEquals(1, response.inconclusiveCount)
        verify(exactly = 1) {
            sessionService.scanSend(any(), any(), any(), false)
        }
    }

    @Test
    fun `headersBypass transient treatment is inconclusive not anomalous or vulnerable`() {
        every {
            sessionService.scanSend(match { it.extraHeaders.isNullOrEmpty() }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            sessionService.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(429, emptyList(), "slow down", 1)

        val response = svc.headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = "admin content",
            )
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertTrue(response.results.all { it.status == 429 && it.inconclusive })
        assertTrue(response.results.none { it.anomalous || it.vulnerable })
        assertEquals(response.results.size, response.inconclusiveCount)
    }

    // ---------------------------------------------------------------------------
    // Probe failures and CORS classification are explicit and conservative
    // ---------------------------------------------------------------------------

    @Test
    fun `authBypass failed classifier probe is explicit and never status zero`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(null, "", 0, "request failed")
        every { spy.probeNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(401, "denied", 1)

        val response = spy.authBypass(
            AuthBypassRequest(listOf("/admin"), "https://target.example")
        )

        val result = response.results.single()
        assertNull(result.withAuth.status)
        assertNotNull(result.withAuth.error)
        assertTrue(result.withAuth.inconclusive)
        assertTrue(result.inconclusive)
        assertFalse(result.vulnerable)
        assertEquals(1, response.inconclusiveCount)
    }

    @Test
    fun `idor target transport failure is explicit rather than status zero or clean`() {
        every {
            sessionService.scanSend(
                match { it.url.contains("own") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns
            AuthenticatedResponse(200, emptyList(), "own record", 1)
        every {
            sessionService.scanSend(
                match { it.url.contains("other") },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } throws
            RuntimeException("connection refused")

        val response = svc.idor(
            IdorRequest("https://target.example/u?id={id}", "id", listOf("own"), listOf("other"))
        )

        val result = response.results.single()
        assertNull(result.status)
        assertNotNull(result.error)
        assertTrue(result.inconclusive)
        assertFalse(result.vulnerable)
        assertEquals(1, response.inconclusiveCount)
    }

    @Test
    fun `cors transport failures are explicit and never vulnerable`() {
        every {
            sessionService.scanSend(
                any(),
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } throws RuntimeException("connection refused")

        val response = svc.cors(CorsRequest("https://target.example/data"))

        assertTrue(response.results.isNotEmpty())
        assertTrue(response.results.all { it.status == null && it.error != null && it.inconclusive })
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(response.results.size, response.inconclusiveCount)
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `cors uses no target-owned subdomain and requires byte-exact reflection with credentials`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } answers {
            val origin = firstArg<AuthenticatedRequest>().extraHeaders!!.getValue("Origin")
            val headers = when (origin) {
                "https://evil.com" -> listOf(
                    HttpHeader("Access-Control-Allow-Origin", "HTTPS://EVIL.COM"),
                    HttpHeader("Access-Control-Allow-Credentials", "true"),
                )
                else -> listOf(
                    HttpHeader("Access-Control-Allow-Origin", origin),
                    HttpHeader("Access-Control-Allow-Credentials", "false"),
                )
            }
            AuthenticatedResponse(200, headers, "ok", 1)
        }

        val response = svc.cors(CorsRequest("https://corp.example/data"))

        assertEquals(8, response.results.size, "every configured attacker origin must be exercised")
        assertTrue(response.results.none { result ->
            runCatching { java.net.URI(result.origin).host }.getOrNull()
                ?.endsWith(".corp.example", ignoreCase = true) == true
        })
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `cors rejects duplicate ACAO grants as non-exploitable ambiguity`() {
        every { sessionService.scanSend(any(), emptyList(), CredentialMode.FULL, false) } answers {
            val origin = firstArg<AuthenticatedRequest>().extraHeaders!!.getValue("Origin")
            AuthenticatedResponse(
                200,
                listOf(
                    HttpHeader("Access-Control-Allow-Origin", origin),
                    HttpHeader("Access-Control-Allow-Origin", "*"),
                    HttpHeader("Access-Control-Allow-Credentials", "true"),
                ),
                "ok",
                1,
            )
        }

        val response = svc.cors(CorsRequest("https://corp.example/data"))

        assertEquals(8, response.results.size, "every configured attacker origin must be exercised")
        assertTrue(response.results.none { it.vulnerable })
        assertEquals(0, response.vulnerableCount)
    }

    // ---------------------------------------------------------------------------
    // Endpoint H2 source and replay fidelity
    // ---------------------------------------------------------------------------

    @Test
    fun `scanEndpoints identifies extension H2 source and deduplicates only exact requests`() {
        val headersA = listOf(HttpHeader("Accept", "application/json"))
        val headersB = listOf(HttpHeader("Accept", "text/plain"))
        val entries = listOf(
            historyEntry(
                5, "session", "POST", "https://target.example/items",
                listOf(HttpHeader("Authorization", "Bearer first"), HttpHeader("X-Variant", "a")), "one",
            ),
            historyEntry(4, "session", "POST", "https://target.example/items", headersA, "one"),
            historyEntry(3, "session", "POST", "https://target.example/items", headersA, "one"),
            historyEntry(2, "repeater", "POST", "https://target.example/items", headersA, "two"),
            historyEntry(1, "repeater", "POST", "https://target.example/items", headersB, "one"),
        )
        every { historyDao.search(any<HistoryFilter>()) } returns entries
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val captured = mutableListOf<SecurityScanService.EndpointRequest>()
        every { spy.probeEndpointWithAuthRaw(capture(captured)) } returns SecurityScanService.RawProbe(200, "body", 1)
        every { spy.probeEndpointNoAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(401, "", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest("target.example", listOf("auth-bypass"), 10)
        )

        assertEquals(4, response.scanned)
        assertEquals(4, captured.size)
        assertEquals("extension-h2-send-history", response.source)
        assertEquals(mapOf("session" to 2, "repeater" to 2), response.sourceCounts)
        assertTrue(captured.none { request ->
            request.headers.any { it.name.equals("Authorization", ignoreCase = true) }
        })
    }

    @Test
    fun `scanEndpoints preserves method body and ordered noncredential duplicate headers`() {
        val headers = listOf(
            HttpHeader("Authorization", "Bearer stale-secret"),
            HttpHeader("Cookie", "old=session"),
            HttpHeader("X-Variant", "first"),
            HttpHeader("X-Variant", "second"),
            HttpHeader("Accept", "application/json"),
            HttpHeader("Accept", "text/plain"),
            HttpHeader("Content-Type", "application/json"),
        )
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(1, "repeater", "PATCH", "https://target.example/items/1", headers, "{\"x\":1}")
        )
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val authenticated = mutableListOf<SecurityScanService.EndpointRequest>()
        val unauthenticated = mutableListOf<SecurityScanService.EndpointRequest>()
        every {
            spy.probeEndpointWithAuthRaw(capture(authenticated))
        } returns SecurityScanService.RawProbe(200, "body", 1)
        every { spy.probeEndpointNoAuthRaw(capture(unauthenticated)) } returns SecurityScanService.RawProbe(401, "", 1)

        spy.scanEndpoints(EndpointsScanRequest("target.example", listOf("auth-bypass"), 10))

        val authRequest = authenticated.single()
        val noAuthRequest = unauthenticated.single()
        assertEquals("PATCH", authRequest.method)
        assertEquals("{\"x\":1}", authRequest.body)
        assertEquals(
            listOf(
                HttpHeader("X-Variant", "first"),
                HttpHeader("X-Variant", "second"),
                HttpHeader("Accept", "application/json"),
                HttpHeader("Accept", "text/plain"),
                HttpHeader("Content-Type", "application/json"),
            ),
            authRequest.headers,
        )
        assertEquals(authRequest, noAuthRequest)
    }

    @Test
    fun `scanEndpoints method switch retains the captured body and duplicate headers`() {
        val headers = listOf(HttpHeader("Accept", "application/json"), HttpHeader("Accept", "text/plain"))
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(1, "session", "POST", "https://target.example/action", headers, "payload")
        )
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val requests = mutableListOf<SecurityScanService.EndpointRequest>()
        every { spy.probeEndpointWithAuthRaw(capture(requests)) } returns SecurityScanService.RawProbe(405, "", 1)

        spy.scanEndpoints(EndpointsScanRequest("target.example", listOf("method-switch"), 10))

        assertEquals(5, requests.size, "all five unobserved method-switch treatments must be sent")
        assertEquals(setOf("GET", "PUT", "PATCH", "DELETE", "OPTIONS"), requests.map { it.method }.toSet())
        assertTrue(requests.all { it.body == "payload" && it.headers == headers })
    }

    @Test
    fun `method switch known-method suppression is scoped to full captured identity`() {
        val headersA = listOf(HttpHeader("Accept", "application/json"))
        val headersB = listOf(HttpHeader("Accept", "text/plain"))
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(2, "session", "GET", "https://target.example/action", headersA, "body-a"),
            historyEntry(1, "session", "POST", "https://target.example/action", headersB, "body-b"),
        )
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val requests = mutableListOf<SecurityScanService.EndpointRequest>()
        every { spy.probeEndpointWithAuthRaw(capture(requests)) } returns SecurityScanService.RawProbe(405, "", 1)

        spy.scanEndpoints(EndpointsScanRequest("target.example", listOf("method-switch"), 10))

        assertTrue(requests.any {
            it.method == "GET" && it.body == "body-b" && it.headers == headersB
        })
        assertTrue(requests.any {
            it.method == "POST" && it.body == "body-a" && it.headers == headersA
        })
    }

    @Test
    fun `raw scan probes delegate credential stripping and origin binding to SessionService`() {
        val rawSession = mockk<SessionService>()
        bridgeObservedSends(rawSession)
        val local = SecurityScanService(api, rawSession, historyDao)
        every { rawSession.cookieOnlyDiffersFromNone() } returns true
        every {
            rawSession.scanSend(any(), any(), any(), false)
        } answers {
            val mode = thirdArg<CredentialMode>()
            when (mode) {
                CredentialMode.FULL -> AuthenticatedResponse(200, emptyList(), "protected", 1)
                CredentialMode.COOKIES_ONLY -> AuthenticatedResponse(401, emptyList(), "denied", 1)
                CredentialMode.NONE -> AuthenticatedResponse(401, emptyList(), "denied", 1)
            }
        }

        val capturedRequest = SecurityScanService.EndpointRequest(
            "POST",
            "https://target.example/action",
            listOf(
                HttpHeader("X-Custom-Auth", "captured-stale-value"),
                HttpHeader("Accept", "application/json"),
                HttpHeader("Accept", "text/plain"),
            ),
            "payload",
        )
        local.probeEndpointWithAuthRaw(capturedRequest)
        local.probeEndpointNoAuthRaw(capturedRequest)
        local.probeNoAuthRaw("https://target.example/action", "GET")
        local.authBypass(AuthBypassRequest(listOf("/action"), "https://target.example"))

        verify(exactly = 3) {
            rawSession.scanSend(any(), any(), CredentialMode.NONE, false)
        }
        verify(exactly = 1) {
            rawSession.scanSend(match { it.method == "POST" && it.body == "payload" }, match {
                    it == listOf(
                        HttpHeader("X-Custom-Auth", "captured-stale-value"),
                        HttpHeader("Accept", "application/json"),
                        HttpHeader("Accept", "text/plain"),
                    )
                }, CredentialMode.FULL, false)
        }
        verify(exactly = 1) {
            rawSession.scanSend(match { it.method == "POST" && it.body == "payload" }, match {
                    it == listOf(
                        HttpHeader("X-Custom-Auth", "captured-stale-value"),
                        HttpHeader("Accept", "application/json"),
                        HttpHeader("Accept", "text/plain"),
                    )
                }, CredentialMode.NONE, false)
        }
        verify(exactly = 1) {
            rawSession.scanSend(any(), any(), CredentialMode.COOKIES_ONLY, false)
        }
    }

    @Test
    fun `scanEndpoints exposes individual send failures as errors rather than omitting them`() {
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(1, "session", "GET", "https://target.example/data", emptyList(), null)
        )
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeEndpointWithAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(null, "", 0, "request failed")
        every { spy.probeEndpointNoAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(401, "", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest("target.example", listOf("auth-bypass"), 10)
        )

        assertEquals(1, response.inconclusiveCount)
        assertEquals(1, response.errors.size)
        assertEquals("auth-bypass-authenticated-control", response.errors.single().probe)
        assertNull(response.errors.single().status)
        assertTrue(response.findings.isEmpty())
    }

    @Test
    fun `authBypass treats unauthenticated rate limits and server failures as inconclusive`() {
        val transientStatuses = listOf(429, 500, 503)
        assertEquals(3, transientStatuses.size, "all transient status classes must be exercised")
        for (status in transientStatuses) {
            val spy = spyk(SecurityScanService(api, sessionService, historyDao))
            every { spy.probeWithAuthRaw(any(), any()) } returns
                SecurityScanService.RawProbe(200, "protected", 1)
            every { spy.probeNoAuthRaw(any(), any()) } returns
                SecurityScanService.RawProbe(status, "temporary failure", 1)

            val response = spy.authBypass(
                AuthBypassRequest(listOf("/admin"), "https://target.example")
            )

            val result = response.results.single()
            assertTrue(result.inconclusive, "status $status must be inconclusive")
            assertTrue(result.withoutAuth.inconclusive, "status $status arm must be inconclusive")
            assertNotNull(result.withoutAuth.inconclusiveReason)
            assertEquals(1, response.inconclusiveCount)
            assertEquals(0, response.vulnerableCount)
        }
    }

    @Test
    fun `idor validates every target URL before sending its baseline`() {
        assertFailsWith<IllegalArgumentException> {
            svc.idor(
                IdorRequest(
                    endpoint = "https://target.example/users?id={id}",
                    param = "id",
                    ownValues = listOf("own"),
                    targetValues = listOf("other", "bad#fragment"),
                )
            )
        }

        verify(exactly = 0) {
            sessionService.scanSend(any(), any(), any(), any())
        }
    }

    @Test
    fun `idor rejects value-substituted cross-origin plans before baseline`() {
        assertFailsWith<IllegalArgumentException> {
            svc.idor(
                IdorRequest(
                    endpoint = "https://{id}.example/path",
                    param = "id",
                    ownValues = listOf("one"),
                    targetValues = listOf("two"),
                )
            )
        }

        verify(exactly = 0) {
            sessionService.scanSend(any(), any(), any(), any())
        }
    }

    @Test
    fun `idor target rate limit is explicit and inconclusive`() {
        every {
            sessionService.scanSend(match { it.url.contains("own") }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(200, emptyList(), "own record", 1)
        every {
            sessionService.scanSend(match { it.url.contains("other") }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(429, emptyList(), "slow down", 1)

        val response = svc.idor(
            IdorRequest("https://target.example/users?id={id}", "id", listOf("own"), listOf("other"))
        )

        assertTrue(response.results.single().inconclusive)
        assertNotNull(response.results.single().error)
        assertEquals(1, response.inconclusiveCount)
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `large SPA HTML retains observed status and becomes explicitly inconclusive`() {
        val localSession = mockk<SessionService>()
        every {
            localSession.scanSend(any(), any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(200, emptyList(), "<!doctype html>" + "x".repeat(50_001), 7)
        val local = SecurityScanService(api, localSession, historyDao)

        val result = local.probeEndpointWithAuthRaw(
            SecurityScanService.EndpointRequest("GET", "https://target.example/unknown", emptyList(), null)
        )

        assertEquals(200, result.status)
        assertNotNull(result.inconclusiveReason)
        assertEquals(7, result.durationMs)
    }

    @Test
    fun `cors rejects non-simple methods before every send`() {
        assertFailsWith<IllegalArgumentException> {
            svc.cors(CorsRequest("https://target.example/data", "PUT"))
        }

        verify(exactly = 0) {
            sessionService.scanSend(any(), any(), any(), any())
        }
    }

    @Test
    fun `endpoint scan records unusable authenticated controls as inconclusive`() {
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(1, "session", "GET", "https://target.example/data", emptyList(), null)
        )
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeEndpointWithAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(503, "unavailable", 1)
        every { spy.probeEndpointNoAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(401, "denied", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest("target.example", listOf("auth-bypass"), 10)
        )

        assertEquals(1, response.inconclusiveCount)
        assertEquals("auth-bypass-authenticated-control", response.errors.single().probe)
        assertEquals(503, response.errors.single().status)
        assertTrue(response.findings.isEmpty())
    }

    @Test
    fun `historical credential-like headers are removed from replay but retained in identity`() {
        val first = listOf(
            HttpHeader("Private-Token", "first-private"),
            HttpHeader("X-GitLab-Token", "first-gitlab"),
            HttpHeader("X-Session-Token", "first-session"),
            HttpHeader("Accept", "application/json"),
            HttpHeader("Accept", "text/plain"),
            HttpHeader("Content-Type", "application/json"),
        )
        val second = listOf(
            HttpHeader("Private-Token", "second-private"),
            HttpHeader("X-GitLab-Token", "second-gitlab"),
            HttpHeader("X-Session-Token", "second-session"),
            HttpHeader("Accept", "application/json"),
            HttpHeader("Accept", "text/plain"),
            HttpHeader("Content-Type", "application/json"),
        )
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(2, "session", "GET", "https://target.example/data", first, null),
            historyEntry(1, "session", "GET", "https://target.example/data", second, null),
        )
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val captured = mutableListOf<SecurityScanService.EndpointRequest>()
        every { spy.probeEndpointWithAuthRaw(capture(captured)) } returns SecurityScanService.RawProbe(200, "data", 1)
        every { spy.probeEndpointNoAuthRaw(any<SecurityScanService.EndpointRequest>()) } returns
            SecurityScanService.RawProbe(401, "denied", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest("target.example", listOf("auth-bypass"), 10)
        )

        assertEquals(2, response.scanned, "credential differences remain part of captured identity")
        assertEquals(2, captured.size, "both retained identities must reach the authenticated probe")
        assertTrue(captured.all { request ->
            request.headers == listOf(
                HttpHeader("Accept", "application/json"),
                HttpHeader("Accept", "text/plain"),
                HttpHeader("Content-Type", "application/json"),
            )
        })
    }

    // ---------------------------------------------------------------------------
    // Live classifier regressions: public equality, bounded probes, and outcomes
    // ---------------------------------------------------------------------------

    /**
     * RED C1: the live /ok fixture returned these same bytes in all three credential modes.
     * Equality proves that removing credentials changed nothing; it does not establish an auth
     * boundary, so treating this ordinary public representation as a bypass is a false positive.
     */
    @Test
    fun `authBypass does not report an identical public representation as vulnerable`() {
        val publicSession = mockk<SessionService>()
        bridgeObservedSends(publicSession)
        every { publicSession.cookieOnlyDiffersFromNone() } returns false
        every {
            publicSession.scanSend(any(), any(), any(), false)
        } returns AuthenticatedResponse(200, emptyList(), "ordinary public response", 1)

        val response = SecurityScanService(api, publicSession, historyDao).authBypass(
            AuthBypassRequest(listOf("/ok"), "https://target.example")
        )

        val result = response.results.single()
        assertFalse(result.vulnerable, "identical public responses without a marker cannot prove a protected read")
        assertTrue(result.inconclusive, "2xx equality without a server-held marker is ambiguous")
        assertTrue(result.note?.contains("protectedContentMarker") == true)
        assertEquals(0, response.vulnerableCount)
        assertEquals(1, response.inconclusiveCount)
        verify(exactly = 1) {
            publicSession.scanSend(any(), any(), CredentialMode.FULL, false)
            publicSession.scanSend(any(), any(), CredentialMode.NONE, false)
        }
        verify(exactly = 0) {
            publicSession.scanSend(any(), any(), CredentialMode.COOKIES_ONLY, false)
        }
    }

    /**
     * RED C2: live Burp waited for every 1.5 s /slow response. The service must stop waiting at the
     * per-probe budget, classify the timeout explicitly, and avoid dependent probes whose control
     * is unavailable; otherwise a slow public response can still become a false finding.
     */
    @Test
    fun `authBypass reports a degenerate cookie control as inconclusive instead of clean`() {
        val publicSession = mockk<SessionService>()
        bridgeObservedSends(publicSession)
        every { publicSession.cookieOnlyDiffersFromNone() } returns false
        every {
            publicSession.scanSend(any(), any(), any(), false)
        } answers {
            when (thirdArg<CredentialMode>()) {
                CredentialMode.FULL -> AuthenticatedResponse(200, emptyList(), "protected representation", 1)
                CredentialMode.NONE -> AuthenticatedResponse(200, emptyList(), "ordinary public response", 1)
                CredentialMode.COOKIES_ONLY -> error("degenerate control must not be sent")
            }
        }

        val response = SecurityScanService(api, publicSession, historyDao).authBypass(
            AuthBypassRequest(
                endpoints = listOf("/records"),
                baseUrl = "https://target.example",
            )
        )

        val result = response.results.single()
        assertFalse(result.vulnerable)
        assertTrue(result.inconclusive)
        assertTrue(result.note?.contains("added no evidence") == true)
        assertTrue(result.note?.contains("header-only") == true)
        verify(exactly = 0) {
            publicSession.scanSend(any(), any(), CredentialMode.COOKIES_ONLY, false)
        }
    }

    @Test
    fun `authBypass keeps public equality with a denying cookie inconclusive without marker`() {
        val localSession = mockk<SessionService>()
        bridgeObservedSends(localSession)
        every { localSession.cookieOnlyDiffersFromNone() } returns true
        every {
            localSession.scanSend(any(), any(), any(), false)
        } answers {
            when (thirdArg<CredentialMode>()) {
                CredentialMode.FULL,
                CredentialMode.NONE -> AuthenticatedResponse(200, emptyList(), "public response", 1)
                CredentialMode.COOKIES_ONLY -> AuthenticatedResponse(403, emptyList(), "cookie denied", 1)
            }
        }

        val response = SecurityScanService(api, localSession, historyDao).authBypass(
            AuthBypassRequest(listOf("/public"), "https://target.example")
        )

        val result = response.results.single()
        assertFalse(result.vulnerable)
        assertTrue(result.inconclusive)
        assertTrue(result.note?.contains("protectedContentMarker") == true)
    }

    @Test
    fun `authBypass keeps cookie-sufficient all-success tuple inconclusive without marker`() {
        val localSession = mockk<SessionService>()
        bridgeObservedSends(localSession)
        every { localSession.cookieOnlyDiffersFromNone() } returns true
        every {
            localSession.scanSend(any(), any(), any(), false)
        } returns AuthenticatedResponse(200, emptyList(), "same protected-or-public representation", 1)

        val response = SecurityScanService(api, localSession, historyDao).authBypass(
            AuthBypassRequest(listOf("/ambiguous"), "https://target.example")
        )

        val result = response.results.single()
        assertFalse(result.vulnerable)
        assertTrue(result.inconclusive)
        assertTrue(result.note?.contains("protectedContentMarker") == true)
    }

    @Test
    fun `authBypass treats a marker supplied in any composed URL material as inconclusive`() {
        val marker = "actor-marker"
        val cases = listOf(
            Triple("baseUrl", "https://$marker.example", "/records"),
            Triple("endpoint", "https://target.example", "/records?selector=$marker"),
        )
        assertEquals(2, cases.size, "both composed URL channels must be exercised")

        for ((material, baseUrl, endpoint) in cases) {
            val spy = spyk(SecurityScanService(api, sessionService, historyDao))
            every { spy.probeWithAuthRaw(any(), any()) } returns
                SecurityScanService.RawProbe(200, "authenticated control", 1)
            every { spy.probeNoAuthRaw(any(), any()) } returns
                SecurityScanService.RawProbe(200, "reflected:$marker", 1)
            every {
                sessionService.scanSend(any(), emptyList(), CredentialMode.COOKIES_ONLY, false)
            } returns AuthenticatedResponse(403, emptyList(), "cookie denied", 1)

            val response = spy.authBypass(
                AuthBypassRequest(
                    endpoints = listOf(endpoint),
                    baseUrl = baseUrl,
                    protectedContentMarker = marker,
                )
            )

            val result = response.results.single()
            assertFalse(
                result.vulnerable,
                "a marker supplied in $material cannot prove a protected read",
            )
            assertTrue(result.inconclusive, "an actor-supplied marker must not fall through to clean")
            assertTrue(result.note?.contains("actor-supplied") == true)
            assertEquals(0, response.vulnerableCount)
            assertEquals(1, response.inconclusiveCount)
        }
    }

    @Test
    fun `authBypass treats marker-bearing NONE as primary proof when FULL differs and lacks marker`() {
        val marker = "SERVER-HELD-NONE-ONLY-MARKER"
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "authenticated-owner-summary", 1)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            observedClearProbe(200, "different-record:$marker", 1)
        every {
            sessionService.scanSend(any(), emptyList(), CredentialMode.COOKIES_ONLY, false)
        } returns AuthenticatedResponse(403, emptyList(), "cookie denied", 1)

        val response = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/records"),
                baseUrl = "https://target.example",
                protectedContentMarker = marker,
            )
        )

        val result = response.results.single()
        assertTrue(
            result.vulnerable,
            "a substantive marker-bearing NONE response proves the protected read " +
                "without body equality or a FULL marker",
        )
        assertFalse(result.inconclusive)
        assertEquals(1, response.vulnerableCount)
        assertEquals(0, response.inconclusiveCount)
    }

    @Test
    fun `authBypass marker proof overrides a degenerate cookie control when FULL lacks marker`() {
        val marker = "SERVER-HELD-DEGENERATE-CONTROL-MARKER"
        val localSession = mockk<SessionService>()
        bridgeObservedSends(localSession)
        every { localSession.cookieOnlyDiffersFromNone() } returns false
        every {
            localSession.scanSend(any(), any(), any(), false)
        } answers {
            when (thirdArg<CredentialMode>()) {
                CredentialMode.FULL -> AuthenticatedResponse(200, emptyList(), "authenticated-owner-summary", 1)
                CredentialMode.NONE -> AuthenticatedResponse(200, emptyList(), "different-record:$marker", 1)
                CredentialMode.COOKIES_ONLY -> error("marker proof must not depend on cookie-only")
            }
        }

        val response = SecurityScanService(api, localSession, historyDao).authBypass(
            AuthBypassRequest(
                endpoints = listOf("/records"),
                baseUrl = "https://target.example",
                protectedContentMarker = marker,
            )
        )

        val result = response.results.single()
        assertTrue(
            result.vulnerable,
            "COOKIE_ONLY degeneracy is descriptive and must not gate marker-backed proof",
        )
        assertFalse(result.inconclusive)
        assertEquals(1, response.vulnerableCount)
        assertEquals(0, response.inconclusiveCount)
        verify(exactly = 0) {
            localSession.scanSend(any(), any(), CredentialMode.COOKIES_ONLY, false)
        }
    }

    @Test
    fun `authBypass proves a read from marker in NONE even when cookie control is degenerate`() {
        val marker = "SERVER-HELD-PROTECTED-MARKER"
        val localSession = mockk<SessionService>()
        bridgeObservedSends(localSession)
        every { localSession.cookieOnlyDiffersFromNone() } returns false
        every {
            localSession.scanSend(any(), any(), any(), false)
        } answers {
            when (thirdArg<CredentialMode>()) {
                CredentialMode.FULL -> AuthenticatedResponse(200, emptyList(), "owner-record:$marker", 1)
                CredentialMode.NONE -> AuthenticatedResponse(200, emptyList(), "different-record:$marker", 1)
                CredentialMode.COOKIES_ONLY -> error("marker proof must not depend on cookie-only")
            }
        }

        val response = SecurityScanService(api, localSession, historyDao).authBypass(
            AuthBypassRequest(
                endpoints = listOf("/records"),
                baseUrl = "https://target.example",
                protectedContentMarker = marker,
            )
        )

        val result = response.results.single()
        assertTrue(result.vulnerable)
        assertFalse(result.inconclusive)
        assertEquals(1, response.vulnerableCount)
    }

    @Test
    fun `scanEndpoints does not report identical public FULL and NONE responses as auth bypass`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        val entry = HistoryEntry(
            id = 91,
            source = "proxy",
            method = "GET",
            url = "https://target.example/public",
            host = "target.example",
            reqHeaders = emptyList(),
            reqBody = null,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = "ordinary public response",
            durationMs = 1,
            timestamp = "2026-01-01T00:00:00Z",
        )
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(entry)
        every { spy.probeEndpointWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "ordinary public response", 1)
        every { spy.probeEndpointNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "ordinary public response", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest(
                host = "target.example",
                tests = listOf("auth-bypass"),
            )
        )

        assertTrue(response.findings.isEmpty())
        assertEquals(1, response.inconclusiveCount)
        assertTrue(response.errors.single().error.contains("protectedContentMarker"))
    }

    @Test
    fun `scanEndpoints treats a marker supplied in any replay material as inconclusive`() {
        val marker = "ACTOR-SUPPLIED-HISTORY-MARKER"
        val cases = listOf(
            "query" to historyEntry(
                id = 94,
                source = "proxy",
                method = "POST",
                url = "https://target.example/protected?selector=$marker",
                headers = emptyList(),
                body = null,
            ),
            "body" to historyEntry(
                id = 95,
                source = "proxy",
                method = "POST",
                url = "https://target.example/protected",
                headers = emptyList(),
                body = "requested=$marker",
            ),
            "header name" to historyEntry(
                id = 96,
                source = "proxy",
                method = "POST",
                url = "https://target.example/protected",
                headers = listOf(HttpHeader(marker, "present")),
                body = null,
            ),
            "header value" to historyEntry(
                id = 97,
                source = "proxy",
                method = "POST",
                url = "https://target.example/protected",
                headers = listOf(HttpHeader("X-Selector", marker)),
                body = null,
            ),
        )
        assertEquals(4, cases.size, "all four replay material channels must be exercised")

        for ((material, entry) in cases) {
            val response = scanEndpointReplay(entry, marker)

            assertTrue(
                response.findings.isEmpty(),
                "replayed $material cannot corroborate its own reflection",
            )
            assertEquals(1, response.inconclusiveCount, material)
            assertEquals(0, response.scanned, material)
            assertTrue(response.errors.single().error.contains("actor-supplied"), material)
        }
    }

    @Test
    fun `scanEndpoints reports marker-backed NONE read when bodies differ and FULL lacks marker`() {
        val marker = "SERVER-HELD-ENDPOINT-NONE-ONLY-MARKER"
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(
                id = 93,
                source = "proxy",
                method = "GET",
                url = "https://target.example/protected",
                headers = emptyList(),
                body = null,
            )
        )
        every { spy.probeEndpointWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "authenticated-owner-summary", 1)
        every { spy.probeEndpointNoAuthRaw(any(), any()) } returns
            observedClearProbe(200, "different-record:$marker", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest(
                host = "target.example",
                tests = listOf("auth-bypass"),
                protectedContentMarker = marker,
            )
        )

        assertEquals(
            1,
            response.findings.size,
            "a substantive marker-bearing NONE response proves the read without body equality or a FULL marker",
        )
        assertEquals(0, response.inconclusiveCount)
        assertEquals(1, response.scanned)
    }

    @Test
    fun `scanEndpoints reports marker-backed unauthenticated protected read`() {
        val marker = "SERVER-HELD-ENDPOINT-MARKER"
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { historyDao.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(
                id = 92,
                source = "proxy",
                method = "GET",
                url = "https://target.example/protected",
                headers = emptyList(),
                body = null,
            )
        )
        every { spy.probeEndpointWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "record:$marker", 1)
        every { spy.probeEndpointNoAuthRaw(any(), any()) } returns
            observedClearProbe(200, "record:$marker", 1)

        val response = spy.scanEndpoints(
            EndpointsScanRequest(
                host = "target.example",
                tests = listOf("auth-bypass"),
                protectedContentMarker = marker,
            )
        )

        assertEquals(1, response.findings.size)
        assertEquals(0, response.inconclusiveCount)
    }

    @Test
    fun `NONE endpoint probe preserves noncredential request context at SessionService boundary`() {
        val localSession = mockk<SessionService>()
        bridgeObservedSends(localSession)
        val capturedHeaders = mutableListOf<HttpHeader>()
        every {
            localSession.sendPreservingHeaders(any(), any(), CredentialMode.NONE, false, 5_000)
        } answers {
            capturedHeaders += secondArg<List<HttpHeader>>()
            AuthenticatedResponse(401, emptyList(), "denied", 1)
        }
        val service = SecurityScanService(api, localSession, historyDao)
        val request = SecurityScanService.EndpointRequest(
            method = "GET",
            url = "https://target.example/record",
            headers = listOf(
                HttpHeader("X-Tenant", "tenant-a"),
                HttpHeader("X-Version", "2026-09"),
                HttpHeader("Authorization", "Bearer captured"),
            ),
            body = null,
        )

        service.probeEndpointNoAuthRaw(request)

        assertEquals(request.headers, capturedHeaders)
    }

    @Test
    fun `authBypass makes a response exceeding its configured budget inconclusive`() {
        val calls = AtomicInteger()
        val slowSession = mockk<SessionService>()
        every { slowSession.cookieOnlyDiffersFromNone() } returns false
        every {
            slowSession.sendPreservingHeaders(any(), any(), any(), false, 100)
        } answers {
            calls.incrementAndGet()
            throw BoundedSendNoResponseException(100)
        }

        val response = SecurityScanService(api, slowSession, historyDao).authBypass(
            AuthBypassRequest(
                endpoints = listOf("/slow"),
                baseUrl = "https://target.example",
                probeTimeoutMs = 100,
            )
        )

        val result = response.results.single()
        assertEquals(1, calls.get(), "dependent probes must not start after their control exceeds its budget")
        assertTrue(result.inconclusive)
        assertTrue(result.withAuth.inconclusive)
        assertTrue(
            result.withAuth.error?.let { "no response" in it && "100 ms" in it } == true,
            "reason must name the configured budget without inventing timeout causality: ${result.withAuth.error}",
        )
        assertFalse(result.vulnerable)
        assertEquals(0, response.vulnerableCount)
        assertEquals(1, response.inconclusiveCount)
    }

    /**
     * RED C3: a non-success own-object control cannot support an IDOR comparison. The old code still
     * sent the dependent target, and reported an inconclusive baseline with no reason. That makes
     * the structured result too ambiguous for a client to distinguish it from clean execution.
     */
    @Test
    fun `idor reports why a non-success baseline is inconclusive and suppresses targets`() {
        val targetCalls = AtomicInteger()
        val localSession = mockk<SessionService>()
        every {
            localSession.scanSend(match { it.url.contains("own") }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(404, emptyList(), "not found", 1)
        every {
            localSession.scanSend(match { it.url.contains("other") }, any(), CredentialMode.FULL, false)
        } answers {
            targetCalls.incrementAndGet()
            AuthenticatedResponse(200, emptyList(), "other record", 1)
        }

        val response = SecurityScanService(api, localSession, historyDao).idor(
            IdorRequest("https://target.example/users?id={id}", "id", listOf("own"), listOf("other"))
        )

        assertTrue(response.baseline.inconclusive)
        assertEquals("baseline did not return a successful response", response.baseline.error)
        assertEquals(0, targetCalls.get(), "a target must not be sent after an unusable baseline")
        assertTrue(response.results.single().inconclusive)
        assertNull(response.results.single().status)
        assertNotNull(response.results.single().error)
        assertTrue(response.inconclusiveCount > 0)
        assertEquals(0, response.vulnerableCount)
    }

    /**
     * C3 contract lock: independent probes may produce both a confirmed finding and an inconclusive
     * observation. Both top-level counts must survive so a CLI can prioritize the confirmed finding
     * without silently relabelling the incomplete part of the run as clean.
     */
    @Test
    fun `headersBypass reports confirmed and inconclusive probes together without conflating them`() {
        val mixedSession = mockk<SessionService>()
        bridgeObservedSends(mixedSession)
        every {
            mixedSession.scanSend(match { it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            mixedSession.scanSend(
                match { it.extraHeaders?.containsKey("X-Original-URL") == true },
                any(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(200, emptyList(), "PROTECTED-MARKER-7Q", 1)
        every {
            mixedSession.scanSend(
                match {
                    !it.extraHeaders.isNullOrEmpty() &&
                        it.extraHeaders?.containsKey("X-Original-URL") != true
                },
                any(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(503, emptyList(), "unavailable", 1)

        val response = SecurityScanService(api, mixedSession, historyDao).headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = "PROTECTED-MARKER-7Q",
            )
        )

        assertEquals(1, response.vulnerableCount)
        assertTrue(response.inconclusiveCount > 0)
        assertTrue(response.results.any { it.vulnerable && !it.inconclusive })
        assertTrue(response.results.any { it.inconclusive && !it.vulnerable })
        assertTrue(response.results.none { it.vulnerable && it.inconclusive })
    }

    /**
     * The four live fixture discriminators are a single contract: a denial-to-success delta is only
     * an anomaly until a marker absent from the control appears in the treatment. The decoy never
     * becomes vulnerable, whether the caller supplies the marker or not.
     */
    @Test
    fun `headersBypass preserves all four live confirmed versus anomaly outcomes`() {
        fun scan(
            treatmentHeader: String,
            treatmentBody: String,
            marker: String?,
        ): HeadersBypassResponse {
            val fixtureSession = mockk<SessionService>()
            bridgeObservedSends(fixtureSession)
            every {
                fixtureSession.scanSend(match { it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
            } returns AuthenticatedResponse(403, emptyList(), "access denied", 1)
            every {
                fixtureSession.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
            } answers {
                val injected = firstArg<AuthenticatedRequest>().extraHeaders.orEmpty()
                if (injected.containsKey(treatmentHeader)) {
                    AuthenticatedResponse(200, emptyList(), treatmentBody, 1)
                } else {
                    AuthenticatedResponse(403, emptyList(), "access denied", 1)
                }
            }
            return SecurityScanService(api, fixtureSession, historyDao).headersBypass(
                HeadersBypassRequest(
                    "https://target.example/admin",
                    protectedContentMarker = marker,
                )
            )
        }

        val confirmed = scan(
            "X-Original-URL",
            "admin data PROTECTED-MARKER-7Q",
            "PROTECTED-MARKER-7Q",
        )
        val adminWithoutMarker = scan(
            "X-Original-URL",
            "admin data PROTECTED-MARKER-7Q",
            null,
        )
        val decoyWithMarker = scan(
            "X-Rewrite-URL",
            "sign in to continue",
            "PROTECTED-MARKER-7Q",
        )
        val decoyWithoutMarker = scan(
            "X-Rewrite-URL",
            "sign in to continue",
            null,
        )

        assertEquals(1, confirmed.anomalousCount)
        assertEquals(1, confirmed.vulnerableCount)
        val anomalyOnlyCases = listOf(adminWithoutMarker, decoyWithMarker, decoyWithoutMarker)
        assertEquals(3, anomalyOnlyCases.size, "all anomaly-only marker configurations must be exercised")
        for (anomalyOnly in anomalyOnlyCases) {
            assertEquals(1, anomalyOnly.anomalousCount)
            assertEquals(0, anomalyOnly.vulnerableCount)
            assertEquals(0, anomalyOnly.inconclusiveCount)
        }
    }

    // ---------------------------------------------------------------------------
    // R9 classifier provenance: every actor-controlled channel and representation
    // ---------------------------------------------------------------------------

    @Test
    fun `authBypass rejects a URL-encoded response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "%61ctor-marker",
            endpoint = "/records?selector=actor-marker",
            representation = "URL-encoded response marker",
        )
    }

    @Test
    fun `authBypass rejects a double-percent-encoded response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "%2561ctor-marker",
            endpoint = "/records?selector=actor-marker",
            representation = "double-percent-encoded response marker",
        )
    }

    @Test
    fun `authBypass rejects an HTML-entity-encoded response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor&amp;marker",
            endpoint = "/records?selector=actor%26marker",
            representation = "HTML-entity-encoded response marker",
        )
    }

    @Test
    fun `authBypass rejects a base64-encoded response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "YWN0b3ItbWFya2Vy",
            endpoint = "/records?selector=actor-marker",
            representation = "base64-encoded response marker",
        )
    }

    @Test
    fun `authBypass rejects a URL-safe base64 response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "YWN0b3I_bWFya2Vy",
            endpoint = "/records?selector=actor%3Fmarker",
            representation = "URL-safe base64 response marker",
        )
    }

    @Test
    fun `authBypass rejects a JSON-escaped response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor\\/marker",
            endpoint = "/records?selector=actor%2Fmarker",
            representation = "JSON-escaped response marker",
        )
    }

    @Test
    fun `authBypass rejects a unicode-escaped response marker derived from raw URL material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "\\u0061ctor-marker",
            endpoint = "/records?selector=actor-marker",
            representation = "unicode-escaped response marker",
        )
    }

    @Test
    fun `authBypass rejects a percent-decoded marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor-marker",
            endpoint = "/records?selector=%61ctor-marker",
            representation = "percent-decoded URL",
        )
    }

    @Test
    fun `authBypass rejects a double-percent-decoded marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor-marker",
            endpoint = "/records?selector=%2561ctor-marker",
            representation = "double-percent-decoded URL",
        )
    }

    @Test
    fun `authBypass rejects an HTML-entity-decoded marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor&marker",
            endpoint = "/records?selector=actor%26amp%3Bmarker",
            representation = "HTML-entity-decoded URL",
        )
    }

    @Test
    fun `authBypass rejects a base64-decoded marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor-marker",
            endpoint = "/records?selector=YWN0b3ItbWFya2Vy",
            representation = "base64-decoded URL value",
        )
    }

    @Test
    fun `authBypass rejects a URL-safe base64-decoded marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor?marker",
            endpoint = "/records?selector=YWN0b3I_bWFya2Vy",
            representation = "URL-safe base64-decoded URL value",
        )
    }

    @Test
    fun `authBypass rejects a case-folded marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor-marker",
            endpoint = "/records?selector=ACTOR-MARKER",
            representation = "case-folded URL",
        )
    }

    @Test
    fun `authBypass rejects a whitespace-normalised marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor marker",
            endpoint = "/records?selector=actor+++marker",
            representation = "whitespace-normalised URL value",
        )
    }

    @Test
    fun `authBypass rejects a JSON-escaped marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor/marker",
            endpoint = "/records?selector=actor%5C%2Fmarker",
            representation = "JSON-escaped URL value",
        )
    }

    @Test
    fun `authBypass rejects a unicode-escaped marker in its URL`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor-marker",
            endpoint = "/records?selector=%5Cu0061ctor-marker",
            representation = "unicode-escaped URL value",
        )
    }

    @Test
    fun `headersBypass rejects a percent-decoded marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive("actor-marker", "selector=%61ctor-marker", "percent-decoded body")
    }

    @Test
    fun `headersBypass rejects a double-percent-decoded marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor-marker",
            "selector=%2561ctor-marker",
            "double-percent-decoded body",
        )
    }

    @Test
    fun `headersBypass rejects an HTML-entity-decoded marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor&marker",
            """{"selector":"actor&amp;marker"}""",
            "HTML-entity-decoded body",
        )
    }

    @Test
    fun `headersBypass rejects a numeric HTML-entity-decoded marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor&marker",
            """{"selector":"actor&#38;marker"}""",
            "numeric HTML-entity-decoded body",
        )
    }

    @Test
    fun `headersBypass rejects a base64-decoded marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor-marker",
            "selector=YWN0b3ItbWFya2Vy",
            "base64-decoded body value",
        )
    }

    @Test
    fun `headersBypass rejects a case-folded marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive("actor-marker", "selector=ACTOR-MARKER", "case-folded body")
    }

    @Test
    fun `headersBypass rejects a whitespace-normalised marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor marker",
            "selector=actor\t   marker",
            "whitespace-normalised body",
        )
    }

    @Test
    fun `headersBypass rejects a JSON-escaped marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor/marker",
            """{"selector":"actor\/marker"}""",
            "JSON-escaped body",
        )
    }

    @Test
    fun `headersBypass rejects a unicode-escaped marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor-marker",
            "{\"selector\":\"\\u0061ctor-marker\"}",
            "unicode-escaped body",
        )
    }

    @Test
    fun `headersBypass rejects a surrogate-pair unicode-escaped marker in its body`() {
        assertHeadersBodyRepresentationIsInconclusive(
            "actor😀marker",
            "{\"selector\":\"actor\\uD83D\\uDE00marker\"}",
            "surrogate-pair unicode-escaped body",
        )
    }

    @Test
    fun `scanEndpoints rejects a percent-decoded marker in replay body`() {
        assertEndpointRepresentationIsInconclusive("actor-marker", "selector=%61ctor-marker", "percent-decoded body")
    }

    @Test
    fun `scanEndpoints rejects a double-percent-decoded marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor-marker",
            "selector=%2561ctor-marker",
            "double-percent-decoded body",
        )
    }

    @Test
    fun `scanEndpoints rejects an HTML-entity-decoded marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor&marker",
            """{"selector":"actor&amp;marker"}""",
            "HTML-entity-decoded body",
        )
    }

    @Test
    fun `scanEndpoints rejects a base64-decoded marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor-marker",
            "selector=YWN0b3ItbWFya2Vy",
            "base64-decoded body value",
        )
    }

    @Test
    fun `scanEndpoints rejects a case-folded marker in replay body`() {
        assertEndpointRepresentationIsInconclusive("actor-marker", "selector=ACTOR-MARKER", "case-folded body")
    }

    @Test
    fun `scanEndpoints rejects an NFKC-normalised marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor-marker",
            "selector=ａｃｔｏｒ－ｍａｒｋｅｒ",
            "NFKC-normalised body",
        )
    }

    @Test
    fun `scanEndpoints rejects a whitespace-normalised marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor marker",
            "selector=actor\t   marker",
            "whitespace-normalised body",
        )
    }

    @Test
    fun `scanEndpoints rejects a JSON-escaped marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor/marker",
            """{"selector":"actor\/marker"}""",
            "JSON-escaped body",
        )
    }

    @Test
    fun `scanEndpoints rejects a unicode-escaped marker in replay body`() {
        assertEndpointRepresentationIsInconclusive(
            "actor-marker",
            "{\"selector\":\"\\u0061ctor-marker\"}",
            "unicode-escaped body",
        )
    }

    @Test
    fun `authBypass treats the HTTP method as actor-supplied material`() {
        assertAuthBypassRepresentationIsInconclusive("POST", "/records", "HTTP method", method = "POST")
    }

    @Test
    fun `headersBypass treats the HTTP method as actor-supplied material`() {
        assertHeadersRequestMaterialIsInconclusive(
            marker = "POST",
            material = "HTTP method",
            request = ProvenanceRequest(method = "POST", url = "https://target.example/admin"),
        )
    }

    @Test
    fun `scanEndpoints treats the HTTP method as actor-supplied material`() {
        assertEndpointRequestMaterialIsInconclusive(
            marker = "POST",
            material = "HTTP method",
            request = ProvenanceRequest(method = "POST"),
        )
    }

    @Test
    fun `authBypass checks encoded path separately from query material`() {
        assertAuthBypassRepresentationIsInconclusive(
            marker = "actor-marker",
            endpoint = "/%61ctor-marker/records",
            representation = "percent-decoded path",
        )
    }

    @Test
    fun `headersBypass checks case-folded URL authority material`() {
        assertHeadersRequestMaterialIsInconclusive(
            marker = "target.example",
            material = "case-folded URL authority",
            request = ProvenanceRequest(url = "https://TARGET.EXAMPLE/admin"),
        )
    }

    @Test
    fun `headersBypass checks its injected header name after case folding`() {
        val marker = "x-forwarded-for"
        val localSession = emptyProvenanceSession()
        every {
            localSession.scanSend(match { it.extraHeaders.isNullOrEmpty() }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            localSession.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, emptyList(), CredentialMode.FULL, false)
        } answers {
            val request = firstArg<AuthenticatedRequest>()
            val reflected = request.extraHeaders.orEmpty().keys.any { it.equals(marker, ignoreCase = true) }
            if (reflected) {
                AuthenticatedResponse(200, emptyList(), "reflected:$marker", 1)
            } else {
                AuthenticatedResponse(403, emptyList(), "denied", 1)
            }
        }

        val response = SecurityScanService(api, localSession, historyDao).headersBypass(
            HeadersBypassRequest("https://target.example/admin", protectedContentMarker = marker)
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        val result = response.results.first { it.header.equals(marker, ignoreCase = true) }
        assertFalse(result.vulnerable, "case-folded injected header name supplied the marker")
        assertTrue(result.inconclusive, "the injected-header reflection must be inconclusive")
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `headersBypass checks configured session header names added after its request`() {
        val configured = SessionRequestMaterialSnapshot.Available(
            headers = listOf(HttpHeader("ACTOR-MARKER", "ordinary")),
            cookies = emptyList(),
            cookieHeaderValue = null,
        )
        assertHeadersRequestMaterialIsInconclusive(
            marker = "actor-marker",
            material = "configured header name",
            session = emptyProvenanceSession(snapshot = configured),
        )
    }

    @Test
    fun `headersBypass checks configured session header values added after its request`() {
        val configured = SessionRequestMaterialSnapshot.Available(
            headers = listOf(HttpHeader("X-Provenance", "ACTOR-MARKER")),
            cookies = emptyList(),
            cookieHeaderValue = null,
        )
        assertHeadersRequestMaterialIsInconclusive(
            marker = "actor-marker",
            material = "configured header value",
            session = emptyProvenanceSession(snapshot = configured),
        )
    }

    @Test
    fun `headersBypass checks configured session cookie names`() {
        assertConfiguredCookieMaterialIsInconclusive(
            marker = "actor-marker",
            cookies = mapOf("ACTOR-MARKER" to "ordinary"),
            material = "configured cookie name",
        )
    }

    @Test
    fun `headersBypass checks configured session cookie values`() {
        assertConfiguredCookieMaterialIsInconclusive(
            marker = "actor-marker",
            cookies = mapOf("sid" to "ACTOR-MARKER"),
            material = "configured cookie value",
        )
    }

    @Test
    fun `headersBypass checks serialized configured session cookie pairs`() {
        assertSerializedCookieMaterialIsInconclusive(
            marker = "sid=actor-marker",
            cookieHeaderValue = "sid=actor-marker",
            material = "serialized configured cookie pair",
        )
    }

    @Test
    fun `headersBypass checks cookie jar names`() {
        assertJarCookieMaterialIsInconclusive(
            marker = "actor-marker",
            cookie = CookieEntry("target.example", "ACTOR-MARKER", "ordinary"),
            material = "cookie-jar name",
        )
    }

    @Test
    fun `headersBypass checks cookie jar values`() {
        assertJarCookieMaterialIsInconclusive(
            marker = "actor-marker",
            cookie = CookieEntry("target.example", "sid", "ACTOR-MARKER"),
            material = "cookie-jar value",
        )
    }

    @Test
    fun `headersBypass checks serialized cookie jar pairs`() {
        assertSerializedCookieMaterialIsInconclusive(
            marker = "sid=actor-marker",
            cookieHeaderValue = "sid=actor-marker",
            material = "serialized cookie-jar pair",
        )
    }

    @Test
    fun `headersBypass checks markers spanning serialized cookie pairs`() {
        assertSerializedCookieMaterialIsInconclusive(
            marker = "one; beta=two",
            cookieHeaderValue = "alpha=one; beta=two",
            material = "marker spanning serialized cookie pairs",
        )
    }

    @Test
    fun `scanEndpoints checks transformed preserved replay header names`() {
        assertEndpointRequestMaterialIsInconclusive(
            marker = "actor-marker",
            material = "preserved header name",
            request = ProvenanceRequest(headers = listOf(HttpHeader("ACTOR-MARKER", "ordinary"))),
        )
    }

    @Test
    fun `scanEndpoints checks transformed preserved replay header values`() {
        assertEndpointRequestMaterialIsInconclusive(
            marker = "actor-marker",
            material = "preserved header value",
            request = ProvenanceRequest(headers = listOf(HttpHeader("X-Provenance", "ACTOR-MARKER"))),
        )
    }

    @Test
    fun `headersBypass checks deterministic request-line material`() {
        assertHeadersRequestMaterialIsInconclusive(
            marker = "POST /admin",
            material = "request line",
            request = ProvenanceRequest(method = "POST", url = "https://target.example/admin"),
        )
    }

    @Test
    fun `headersBypass checks deterministic Host header material`() {
        assertHeadersRequestMaterialIsInconclusive(
            marker = "Host: target.example",
            material = "generated Host header",
        )
    }

    @Test
    fun `headersBypass checks deterministic Content-Length header material`() {
        assertHeadersRequestMaterialIsInconclusive(
            marker = "Content-Length: 12",
            material = "generated Content-Length header",
            request = ProvenanceRequest(
                method = "POST",
                url = "https://target.example/admin",
                body = "abcdefghijkl",
            ),
        )
    }

    @Test
    fun `headersBypass fails closed when final session material cannot be read`() {
        val unreadableSession = mockk<SessionService>()
        bridgeObservedSends(unreadableSession, SessionRequestMaterialSnapshot.Unavailable)
        every {
            unreadableSession.scanSend(
                match { it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            unreadableSession.scanSend(
                match { !it.extraHeaders.isNullOrEmpty() },
                emptyList(),
                CredentialMode.FULL,
                false,
            )
        } returns AuthenticatedResponse(200, emptyList(), "server-held-marker", 1)

        val response = SecurityScanService(api, unreadableSession, historyDao).headersBypass(
            HeadersBypassRequest(
                "https://target.example/admin",
                protectedContentMarker = "server-held-marker",
            )
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        assertEquals(0, response.vulnerableCount, "unknown final request provenance must never certify a read")
        assertEquals(response.results.size, response.inconclusiveCount)
        assertTrue(response.results.all { it.error?.contains("provenance") == true })
    }

    @Test
    fun `headersBypass uses post-override observed headers rather than replaced session values`() {
        val marker = "SESSION-VALUE-THAT-WILL-BE-REPLACED"
        val sessionSnapshot = SessionRequestMaterialSnapshot.Available(
            headers = listOf(HttpHeader("X-Forwarded-For", marker)),
            cookies = emptyList(),
            cookieHeaderValue = null,
        )
        val localSession = emptyProvenanceSession(sessionSnapshot)
        every {
            localSession.scanSend(match { it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            localSession.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } answers {
            val injected = firstArg<AuthenticatedRequest>().extraHeaders.orEmpty()
            if (injected["X-Forwarded-For"] == "127.0.0.1") {
                AuthenticatedResponse(200, emptyList(), "protected:$marker", 1)
            } else {
                AuthenticatedResponse(403, emptyList(), "denied", 1)
            }
        }

        val response = SecurityScanService(api, localSession, historyDao).headersBypass(
            HeadersBypassRequest("https://target.example/admin", protectedContentMarker = marker)
        )

        assertEquals(16, response.results.size, "every bypass header treatment must be exercised")
        val replaced = response.results.first {
            it.header == "X-Forwarded-For" && it.value == "127.0.0.1"
        }
        assertTrue(replaced.vulnerable, "a replaced session value was not sent and must not taint provenance")
        assertFalse(replaced.inconclusive)
    }

    @Test
    fun `headersBypass accepts an empty configured observed snapshot as definitive`() {
        val marker = "SERVER-HELD-EMPTY-SESSION-MARKER"
        val emptyConfigured = SessionRequestMaterialSnapshot.Available(emptyList(), emptyList(), null)
        val localSession = emptyProvenanceSession(emptyConfigured)
        every {
            localSession.scanSend(match { it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            localSession.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } answers {
            val injected = firstArg<AuthenticatedRequest>().extraHeaders.orEmpty()
            if (injected.containsKey("X-Original-URL")) {
                AuthenticatedResponse(200, emptyList(), "protected:$marker", 1)
            } else {
                AuthenticatedResponse(403, emptyList(), "denied", 1)
            }
        }

        val response = SecurityScanService(api, localSession, historyDao).headersBypass(
            HeadersBypassRequest("https://target.example/admin", protectedContentMarker = marker)
        )

        assertEquals(1, response.vulnerableCount)
        assertTrue(response.results.any { it.vulnerable && !it.inconclusive })
    }

    @Test
    fun `headersBypass surfaces disagreement between Cookie wire value and parsed pairs`() {
        val marker = "PARSED-ONLY-MARKER"
        val inconsistent = SessionRequestMaterialSnapshot.Available(
            headers = emptyList(),
            cookies = listOf(SessionRequestCookie("sid", marker)),
            cookieHeaderValue = "sid=ordinary",
        )
        val session = emptyProvenanceSession(inconsistent)
        every {
            session.scanSend(match { it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            session.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(200, emptyList(), "protected:$marker", 1)

        val response = SecurityScanService(api, session, historyDao).headersBypass(
            HeadersBypassRequest("https://target.example/admin", protectedContentMarker = marker)
        )

        assertEquals(16, response.results.size)
        assertEquals(0, response.vulnerableCount)
        assertEquals(16, response.inconclusiveCount)
        assertTrue(response.results.all { it.error?.contains("provenance") == true })
        assertTrue(response.results.none { it.error?.contains("actor-supplied") == true })
    }

    @Test
    fun `headersBypass trusts Cookie wire marker over disagreeing parsed pairs`() {
        val marker = "WIRE-MARKER"
        val inconsistent = SessionRequestMaterialSnapshot.Available(
            headers = emptyList(),
            cookies = listOf(SessionRequestCookie("sid", "ordinary")),
            cookieHeaderValue = "sid=$marker",
        )
        val session = emptyProvenanceSession(inconsistent)
        every {
            session.scanSend(match { it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            session.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, any(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(200, emptyList(), "reflected:$marker", 1)

        val response = SecurityScanService(api, session, historyDao).headersBypass(
            HeadersBypassRequest("https://target.example/admin", protectedContentMarker = marker)
        )

        assertEquals(16, response.results.size)
        assertEquals(0, response.vulnerableCount)
        assertEquals(16, response.inconclusiveCount)
        assertTrue(response.results.all { it.error?.contains("actor-supplied") == true })
    }

    @Test
    fun `authBypass fails closed when observed NONE request material is unavailable`() {
        val marker = "SERVER-HELD-UNAVAILABLE-AUTH-MARKER"
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "authenticated", 1)
        every { spy.probeNoAuthRaw(any(), any()) } returns SecurityScanService.RawProbe(
            200,
            "protected:$marker",
            1,
            requestMaterial = SessionRequestMaterialSnapshot.Unavailable,
        )

        val response = spy.authBypass(
            AuthBypassRequest(listOf("/records"), "https://target.example", protectedContentMarker = marker)
        )

        assertEquals(1, response.results.size, "the requested auth endpoint must be classified")
        val result = response.results.single()
        assertFalse(result.vulnerable)
        assertTrue(result.inconclusive)
        assertTrue(result.note?.contains("provenance") == true)
        assertEquals(0, response.vulnerableCount)
    }

    @Test
    fun `scanEndpoints fails closed when observed NONE request material is unavailable`() {
        val marker = "SERVER-HELD-UNAVAILABLE-ENDPOINT-MARKER"
        val localHistory = mockk<HistoryDao>()
        every { localHistory.search(any<HistoryFilter>()) } returns listOf(
            historyEntry(
                300,
                "proxy",
                "GET",
                "https://target.example/protected",
                emptyList(),
                null,
            )
        )
        val spy = spyk(SecurityScanService(api, sessionService, localHistory))
        every { spy.probeEndpointWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "authenticated", 1)
        every { spy.probeEndpointNoAuthRaw(any(), any()) } returns SecurityScanService.RawProbe(
            200,
            "protected:$marker",
            1,
            requestMaterial = SessionRequestMaterialSnapshot.Unavailable,
        )

        val response = spy.scanEndpoints(
            EndpointsScanRequest(
                host = "target.example",
                tests = listOf("auth-bypass"),
                protectedContentMarker = marker,
            )
        )

        assertEquals(0, response.findings.size)
        assertEquals(1, response.errors.size)
        assertTrue(response.errors.single().error.contains("provenance"))
        assertEquals(1, response.inconclusiveCount)
    }

    private fun assertAuthBypassRepresentationIsInconclusive(
        marker: String,
        endpoint: String,
        representation: String,
        method: String = "GET",
    ) {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))
        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "authenticated control", 1)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "reflected:$marker", 1)
        every {
            sessionService.scanSend(any(), emptyList(), CredentialMode.COOKIES_ONLY, false)
        } returns AuthenticatedResponse(403, emptyList(), "cookie denied", 1)

        val response = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf(endpoint),
                baseUrl = "https://target.example",
                method = method,
                protectedContentMarker = marker,
            )
        )

        assertEquals(1, response.results.size, "$representation must classify the requested endpoint")
        val result = response.results.single()
        assertFalse(result.vulnerable, "$representation supplied the response marker")
        assertTrue(result.inconclusive, "$representation must make marker provenance inconclusive")
        assertTrue(result.note?.contains("actor-supplied") == true, representation)
        assertEquals(0, response.vulnerableCount, representation)
        assertEquals(1, response.inconclusiveCount, representation)
    }

    private fun assertHeadersBodyRepresentationIsInconclusive(
        marker: String,
        body: String,
        representation: String,
    ) = assertHeadersRequestMaterialIsInconclusive(
        marker = marker,
        material = representation,
        request = ProvenanceRequest(method = "POST", body = body),
    )

    private fun assertHeadersRequestMaterialIsInconclusive(
        marker: String,
        material: String,
        request: ProvenanceRequest = ProvenanceRequest(url = "https://target.example/admin"),
        session: SessionService = emptyProvenanceSession(),
    ) {
        every {
            session.scanSend(match { it.extraHeaders.isNullOrEmpty() }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(403, emptyList(), "denied", 1)
        every {
            session.scanSend(match { !it.extraHeaders.isNullOrEmpty() }, emptyList(), CredentialMode.FULL, false)
        } returns AuthenticatedResponse(200, emptyList(), "reflected:$marker", 1)

        val response = SecurityScanService(api, session, historyDao).headersBypass(
            HeadersBypassRequest(
                url = request.url,
                method = request.method,
                body = request.body,
                protectedContentMarker = marker,
            )
        )

        assertEquals(0, response.vulnerableCount, "$material supplied the response marker")
        assertTrue(response.results.isNotEmpty(), "$material must exercise every treatment")
        assertEquals(
            response.results.size,
            response.inconclusiveCount,
            "$material must make every marker-bearing treatment inconclusive",
        )
        assertTrue(response.results.all { it.error?.contains("actor-supplied") == true }, material)
    }

    private fun assertConfiguredCookieMaterialIsInconclusive(
        marker: String,
        cookies: Map<String, String>,
        material: String,
    ) {
        val cookieHeaderValue = cookies.entries.joinToString("; ") { (name, value) -> "$name=$value" }
        val snapshot = SessionRequestMaterialSnapshot.Available(
            headers = emptyList(),
            cookies = cookies.map { (name, value) -> SessionRequestCookie(name, value) },
            cookieHeaderValue = cookieHeaderValue,
        )
        assertHeadersRequestMaterialIsInconclusive(
            marker = marker,
            material = material,
            session = emptyProvenanceSession(snapshot = snapshot),
        )
    }

    private fun assertJarCookieMaterialIsInconclusive(
        marker: String,
        cookie: CookieEntry,
        material: String,
    ) {
        val snapshot = SessionRequestMaterialSnapshot.Available(
            headers = emptyList(),
            cookies = listOf(SessionRequestCookie(cookie.name, cookie.value)),
            cookieHeaderValue = "${cookie.name}=${cookie.value}",
        )
        assertHeadersRequestMaterialIsInconclusive(
            marker = marker,
            material = material,
            session = emptyProvenanceSession(snapshot = snapshot),
        )
    }

    private fun assertSerializedCookieMaterialIsInconclusive(
        marker: String,
        cookieHeaderValue: String,
        material: String,
    ) {
        val parsedCookies = cookieHeaderValue.split(';').map { segment ->
            val (name, value) = segment.trim().split('=', limit = 2)
            SessionRequestCookie(name, value)
        }
        val snapshot = SessionRequestMaterialSnapshot.Available(
            headers = emptyList(),
            cookies = parsedCookies,
            cookieHeaderValue = cookieHeaderValue,
        )
        assertHeadersRequestMaterialIsInconclusive(
            marker = marker,
            material = material,
            session = emptyProvenanceSession(snapshot = snapshot),
        )
    }

    private fun assertEndpointRepresentationIsInconclusive(
        marker: String,
        body: String,
        representation: String,
    ) = assertEndpointRequestMaterialIsInconclusive(
        marker = marker,
        material = representation,
        request = ProvenanceRequest(method = "POST", body = body),
    )

    private fun assertEndpointRequestMaterialIsInconclusive(
        marker: String,
        material: String,
        request: ProvenanceRequest = ProvenanceRequest(),
    ) {
        val response = scanEndpointReplay(
            historyEntry(
                id = 200,
                source = "proxy",
                method = request.method,
                url = request.url,
                headers = request.headers,
                body = request.body,
            ),
            marker,
        )

        assertTrue(response.findings.isEmpty(), "$material supplied the response marker")
        assertEquals(1, response.inconclusiveCount, material)
        assertEquals(0, response.scanned, material)
        assertTrue(response.errors.single().error.contains("actor-supplied"), material)
    }

    private fun observedClearProbe(
        status: Int,
        body: String,
        durationMs: Long,
    ) = SecurityScanService.RawProbe(
        status,
        body,
        durationMs,
        requestMaterial = SessionRequestMaterialSnapshot.Available(emptyList(), emptyList(), null),
    )

    private fun emptyProvenanceSession(
        snapshot: SessionRequestMaterialSnapshot = SessionRequestMaterialSnapshot.NotConfigured,
    ): SessionService = mockk<SessionService>().also { session ->
        bridgeObservedSends(session, snapshot)
    }

    private fun bridgeObservedSends(
        session: SessionService,
        snapshot: SessionRequestMaterialSnapshot = SessionRequestMaterialSnapshot.NotConfigured,
    ) {
        every {
            session.sendPreservingHeadersObserved(any(), any(), any(), any(), any())
        } answers {
            val request = firstArg<AuthenticatedRequest>()
            val preservedHeaders = secondArg<List<HttpHeader>>()
            val credentialMode = thirdArg<CredentialMode>()
            val persistObservation = arg<Boolean>(3)
            val responseTimeoutMs = arg<Long?>(4)
            val response = session.sendPreservingHeaders(
                request,
                preservedHeaders,
                credentialMode,
                persistObservation,
                responseTimeoutMs,
            )
            ObservedAuthenticatedSend(response, observedMaterial(request, preservedHeaders, snapshot))
        }
    }

    private fun observedMaterial(
        request: AuthenticatedRequest,
        preservedHeaders: List<HttpHeader>,
        snapshot: SessionRequestMaterialSnapshot,
    ): SessionRequestMaterialSnapshot = when (snapshot) {
        SessionRequestMaterialSnapshot.Unavailable -> SessionRequestMaterialSnapshot.Unavailable
        SessionRequestMaterialSnapshot.NotConfigured -> observedAvailable(request, preservedHeaders, emptyList(), null)
        is SessionRequestMaterialSnapshot.Available -> observedAvailable(
            request,
            snapshot.headers + preservedHeaders,
            snapshot.cookies,
            snapshot.cookieHeaderValue,
        )
    }

    private fun observedAvailable(
        request: AuthenticatedRequest,
        headers: List<HttpHeader>,
        cookies: List<SessionRequestCookie>,
        cookieHeaderValue: String?,
    ): SessionRequestMaterialSnapshot.Available {
        val authority = java.net.URI(request.url).rawAuthority
        val generated = buildList {
            add(HttpHeader("Host", authority))
            request.body?.let { add(HttpHeader("Content-Length", it.encodeToByteArray().size.toString())) }
        }
        val beforeRequestOverrides = (generated + headers).fold(emptyList<HttpHeader>()) { final, header ->
            final.filterNot { it.name.equals(header.name, ignoreCase = true) } + header
        }
        val overrideNames = request.extraHeaders.orEmpty().keys
        val finalHeaders = beforeRequestOverrides.filterNot { header ->
            overrideNames.any { it.equals(header.name, ignoreCase = true) }
        } + request.extraHeaders.orEmpty().map { (name, value) -> HttpHeader(name, value) }
        return SessionRequestMaterialSnapshot.Available(finalHeaders, cookies, cookieHeaderValue)
    }

    private fun scanEndpointReplay(entry: HistoryEntry, marker: String): EndpointsScanResponse {
        val localHistory = mockk<HistoryDao>()
        every { localHistory.search(any<HistoryFilter>()) } returns listOf(entry)
        val spy = spyk(SecurityScanService(api, sessionService, localHistory))
        every { spy.probeEndpointWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "authenticated control", 1)
        every { spy.probeEndpointNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "reflected:$marker", 1)
        return spy.scanEndpoints(
            EndpointsScanRequest(
                host = "target.example",
                tests = listOf("auth-bypass"),
                protectedContentMarker = marker,
            )
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> absentValue(): T = null as T

    /** Match the product's documented default explicitly instead of silently binding null. */
    private fun SessionService.scanSend(
        request: AuthenticatedRequest,
        headers: List<HttpHeader>,
        credentialMode: CredentialMode,
        persistObservation: Boolean,
    ): AuthenticatedResponse = sendPreservingHeaders(
        request,
        headers,
        credentialMode,
        persistObservation,
        5_000,
    )

    private fun historyEntry(
        id: Long,
        source: String,
        method: String,
        url: String,
        headers: List<HttpHeader>,
        body: String?,
    ) = HistoryEntry(
        id = id,
        source = source,
        method = method,
        url = url,
        host = java.net.URI(url).host,
        reqHeaders = headers,
        reqBody = body,
        statusCode = 200,
        resHeaders = emptyList(),
        resBody = "ok",
        durationMs = 1,
        timestamp = "2026-01-01T00:00:00Z",
    )
}
