package com.burprest.services

import com.burprest.db.HistoryDao
import com.burprest.db.HistoryEntry
import com.burprest.db.HistoryFilter
import com.burprest.models.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SecurityScanServiceTest {

    private val api = mockk<burp.api.montoya.MontoyaApi>(relaxed = true)
    private val sessionService = mockk<SessionService>(relaxed = true)
    private val historyDao = mockk<HistoryDao>(relaxed = true)
    private val svc = SecurityScanService(api, sessionService, historyDao)

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
        every { sessionService.send(match { it.url.contains("alice") }) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-record",
            durationMs = 0,
        )
        every { sessionService.send(match { it.url.contains("bob") }) } returns AuthenticatedResponse(
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
        every { sessionService.send(match { it.url.contains("alice") }) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = "alice-record",
            durationMs = 0,
        )
        every { sessionService.send(match { it.url.contains("alice2") }) } returns AuthenticatedResponse(
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

        every { sessionService.send(match { it.url.contains("alice") }) } returns AuthenticatedResponse(
            statusCode = 200,
            headers = emptyList(),
            body = aliceBody,
            durationMs = 0,
        )
        every { sessionService.send(match { it.url.contains("bob") }) } returns AuthenticatedResponse(
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
            )
        )

        val result = resp.results.first()
        assertFalse(result.vulnerable,
            "Login-page body differs from auth body -> must NOT be flagged vulnerable")
        assertEquals(0, resp.vulnerableCount)
    }

    /**
     * RED->GREEN [07]: withoutAuth returning SAME content as withAuth -> genuine bypass.
     */
    @Test
    fun `authBypass - withoutAuth returning same content as withAuth is vulnerable`() {
        val spy = spyk(SecurityScanService(api, sessionService, historyDao))

        val protectedData = "protected-user-data-payload-with-lots-of-content"

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, protectedData, 0)
        every { spy.probeNoAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, protectedData, 0)   // same content

        val resp = spy.authBypass(
            AuthBypassRequest(
                endpoints = listOf("/api/users"),
                baseUrl = "http://t",
                method = "GET",
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

        every { spy.probeWithAuthRaw(any(), any()) } returns
            SecurityScanService.RawProbe(200, "protected", 0)
        every { spy.probeNoAuthRaw(any(), capture(capturedMethods)) } returns
            SecurityScanService.RawProbe(401, "", 0)

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
    // [08] and [11] — model fields wired (note, ignoredOwnValues)
    // ---------------------------------------------------------------------------

    // [08] IDOR detection reports cross-object access regardless of privilege direction;
    // that limitation is surfaced as a note so the analyst applies judgement.
    @Test
    fun `idor - response includes privilege direction limitation note`() {
        every { sessionService.send(any()) } returns AuthenticatedResponse(200, emptyList(), "body", 0)
        val resp = svc.idor(IdorRequest("http://t?id={id}", "id", listOf("1"), listOf("2")))
        assertNotNull(resp.note)
        assertTrue(resp.note!!.contains("privilege direction", ignoreCase = true))
    }

    // [11] Only the first own value is the baseline; the rest are not tested and must be surfaced.
    @Test
    fun `idor - multiple own values lists ignored ones in ignoredOwnValues`() {
        every { sessionService.send(any()) } returns AuthenticatedResponse(200, emptyList(), "body", 0)
        val resp = svc.idor(IdorRequest("http://t?id={id}", "id", listOf("1", "2", "3"), listOf("99")))
        assertEquals(listOf("2", "3"), resp.ignoredOwnValues)
    }
}
