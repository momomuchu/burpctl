package com.burprest.integration

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Version
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.Scanner
import com.burprest.models.AddScopeRequest
import com.burprest.models.CreateAttackRequest
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.PayloadPosition
import com.burprest.models.PersistenceStatus
import com.burprest.models.QuickFuzzRequest
import com.burprest.models.ScanRequest
import com.burprest.models.SendRequest
import com.burprest.models.SetSessionRequest
import com.burprest.services.IntruderService
import com.burprest.services.RepeaterService
import com.burprest.services.ScannerService
import com.burprest.services.SessionService
import com.burprest.services.SessionServiceCollaborators
import com.burprest.services.TargetService
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import java.net.URI
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RepeaterIntruderCompositionTest {
    @Test
    fun `repeater result seeds an intruder attack with the same request material`() {
        val harness = MutableHttpHarness()
        val repeater = RepeaterService(
            api = harness.api,
            requestFactory = harness::request,
            bodyFactory = harness::body,
        )
        val intruder = IntruderService(harness.api, repeater)
        val original = HttpRequestData(
            method = "POST",
            url = "$ORIGIN/submit",
            headers = listOf(
                HttpHeader("Content-Type", "text/plain; charset=utf-8"),
                HttpHeader("X-Order", "first"),
                HttpHeader("X-Order", "second"),
            ),
            body = "account=α&value=before",
        )

        val repeated = repeater.send(SendRequest(request = original)).request
        val raw = canonicalRaw(repeated)
        val marker = "before".encodeToByteArray()
        val start = raw.indexOf(marker)
        val attack = intruder.createAttack(
            CreateAttackRequest(
                request = repeated,
                positions = listOf(PayloadPosition(start, start + marker.size, "value")),
                payloads = mapOf("value" to listOf("after-✓")),
            )
        )
        intruder.startAttack(attack.attackId)
        awaitCompleted(intruder, attack.attackId)

        assertEquals(2, harness.sent.size)
        val initial = harness.sent[0]
        val treatment = harness.sent[1]
        assertEquals(initial.method, treatment.method)
        assertEquals(initial.url, treatment.url)
        assertEquals(
            initial.headers,
            treatment.headers.filterNot {
                it.first.equals("Host", ignoreCase = true) || it.first.equals("Content-Length", ignoreCase = true)
            },
        )
        assertEquals(
            treatment.body.size.toString(),
            treatment.headers.single { it.first.equals("Content-Length", ignoreCase = true) }.second,
        )
        assertContentEquals("account=α&value=before".encodeToByteArray(), initial.body)
        assertContentEquals("account=α&value=after-✓".encodeToByteArray(), treatment.body)
        val status = intruder.attackStatus(attack.attackId)
        assertTrue(status.isComplete)
        assertEquals(1, status.requestCount)
        assertEquals(0, status.errorCount)
        assertEquals("after-✓", intruder.attackResults(attack.attackId).results.single().payload)
    }

    @Test
    fun `intruder inherits its base request instead of later session state`() {
        val harness = MutableHttpHarness()
        val session = SessionService(
            harness.api,
            null,
            null,
            null,
            SessionServiceCollaborators(
                requestFactory = harness::request,
                bodyFactory = harness::body,
            ),
        )
        val repeater = RepeaterService(
            api = harness.api,
            requestFactory = harness::request,
            bodyFactory = harness::body,
        )
        val intruder = IntruderService(harness.api, repeater)
        session.setSession(
            SetSessionRequest(
                cookies = mapOf("auth_token" to "configured-cookie"),
                headers = mapOf("X-Csrf-Token" to "configured-header"),
                origin = ORIGIN,
            )
        )

        intruder.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData(
                    method = "GET",
                    url = "$ORIGIN/session-gap?q=before",
                    headers = listOf(HttpHeader("Authorization", "Bearer captured-base")),
                ),
                param = "q",
                payloads = listOf("after"),
            )
        )

        assertTrue(harness.sent.isNotEmpty())
        // Fuzz inherits the captured/base request, not a separately configured session.
        harness.sent.forEach { sent ->
            assertTrue(sent.headers.contains("Authorization" to "Bearer captured-base"))
            assertFalse(sent.headers.any { it.second.contains("configured-cookie") })
            assertFalse(sent.headers.any { it.second.contains("configured-header") })
        }
    }

    @Test
    fun `response-less intruder step leaves the next repeater send clean`() {
        val failedUrl = "$ORIGIN/fails?q=before"
        val harness = MutableHttpHarness { request, _ ->
            WireResponse(hasResponse = request.url != failedUrl)
        }
        val repeater = RepeaterService(
            api = harness.api,
            requestFactory = harness::request,
            bodyFactory = harness::body,
        )
        val intruder = IntruderService(harness.api, repeater)

        val failed = intruder.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData("GET", failedUrl),
                param = "q",
                payloads = listOf("must-not-send"),
            )
        )
        val recovered = repeater.send(
            SendRequest(
                request = HttpRequestData("POST", "$ORIGIN/recovers", body = "clean-next-step")
            )
        )

        assertEquals("NO_RESPONSE", failed.baseline?.errorCode)
        assertEquals(0, failed.total)
        assertEquals(listOf(failedUrl, "$ORIGIN/recovers"), harness.sent.map { it.url })
        assertEquals(PersistenceStatus.NOT_CONFIGURED, recovered.persistence.status)
        assertContentEquals("clean-next-step".encodeToByteArray(), harness.sent.last().body)
    }

    @Test
    fun `scope exclusion does not block a later scanner audit`() {
        val fixture = ScopedOperationsFixture()
        val canonical = fixture.target.addToScope(AddScopeRequest("HTTPS://EXAMPLE.TEST:443/a/../private?q=1"))
        assertTrue(canonical.inScope)
        val allowed = fixture.scannerService.audit(ScanRequest(canonical.url))
        fixture.scannerService.stop(allowed.scanId)

        val excluded = fixture.target.removeFromScope(AddScopeRequest(canonical.url))
        assertFalse(excluded.inScope)
        // Scope is currently bookkeeping, not an outbound-traffic guard. Pin that release hazard.
        val afterExclusion = fixture.scannerService.audit(ScanRequest(excluded.url))

        assertEquals(2, fixture.startedAudits)
        fixture.scannerService.stop(afterExclusion.scanId)
    }

    @Test
    fun `scope exclusion does not block a later quick fuzz`() {
        val fixture = ScopedOperationsFixture()
        val scoped = fixture.target.addToScope(AddScopeRequest("$ORIGIN/search?q=before"))
        assertTrue(scoped.inScope)
        val allowed = fixture.intruder.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData("GET", scoped.url),
                param = "q",
                payloads = listOf("inside"),
            )
        )
        assertEquals(1, allowed.total)
        val sentWhileScoped = fixture.harness.sent.size

        val excluded = fixture.target.removeFromScope(AddScopeRequest(scoped.url))
        assertFalse(excluded.inScope)
        // Scope is currently bookkeeping, not an outbound-traffic guard. Pin that release hazard.
        val afterExclusion = fixture.intruder.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData("GET", excluded.url),
                param = "q",
                payloads = listOf("outside"),
            )
        )

        assertEquals(1, afterExclusion.total)
        assertEquals(sentWhileScoped + 2, fixture.harness.sent.size)
        assertEquals("https://composition.example/search?q=outside", fixture.harness.sent.last().url)
    }

    private class ScopedOperationsFixture {
        val harness = MutableHttpHarness()
        private val api: MontoyaApi = harness.api
        private val scope = mockk<burp.api.montoya.scope.Scope>()
        private val burpSuite = mockk<BurpSuite>()
        private val version = mockk<Version>()
        private val scanner = mockk<Scanner>()
        private val audit = mockk<burp.api.montoya.scanner.audit.Audit>()
        private val auditConfiguration = mockk<burp.api.montoya.scanner.AuditConfiguration>()
        private val seed = mockk<HttpRequest>()
        private var inScope = false
        var startedAudits = 0
            private set
        val target = TargetService(api)
        val scannerService: ScannerService
        val intruder: IntruderService

        init {
            every { api.scope() } returns scope
            every { scope.includeInScope(any()) } answers { inScope = true }
            every { scope.excludeFromScope(any()) } answers { inScope = false }
            every { scope.isInScope(any()) } answers { inScope }
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { api.scanner() } returns scanner
            every { scanner.startAudit(auditConfiguration) } answers {
                startedAudits++
                audit
            }
            every { audit.addRequest(seed) } just runs
            every { audit.requestCount() } returns 1
            every { audit.errorCount() } returns 0
            every { audit.issues() } returns emptyList()
            every { audit.delete() } just runs
            scannerService = ScannerService(
                api = api,
                auditConfigurationFactory = { auditConfiguration },
                requestFactory = { seed },
                scanIdFactory = { "scan-$startedAudits" },
            )
            val repeater = RepeaterService(
                api = api,
                requestFactory = harness::request,
                bodyFactory = harness::body,
            )
            intruder = IntruderService(api, repeater)
        }
    }

    private fun canonicalRaw(request: HttpRequestData): ByteArray {
        val uri = URI(request.url)
        val target = uri.rawPath.ifEmpty { "/" } + (uri.rawQuery?.let { "?$it" } ?: "")
        val lines = buildList {
            add("${request.method} $target HTTP/1.1")
            if (request.headers.none { it.name.equals("Host", ignoreCase = true) }) {
                add("Host: ${uri.rawAuthority}")
            }
            request.headers.forEach { add("${it.name}: ${it.value}") }
        }
        return (lines.joinToString("\r\n") + "\r\n\r\n").encodeToByteArray() +
            (request.bodyBytes() ?: byteArrayOf())
    }

    private fun awaitCompleted(service: IntruderService, id: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (service.attackStatus(id).isComplete) return
            Thread.onSpinWait()
        }
        assertTrue(service.attackStatus(id).isComplete, "attack did not complete")
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        for (start in 0..size - needle.size) {
            if (needle.indices.all { this[start + it] == needle[it] }) return start
        }
        return -1
    }

    private companion object {
        const val ORIGIN = "https://composition.example"
    }
}
