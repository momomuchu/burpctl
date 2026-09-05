package com.burprest.integration

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Version
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.Scanner
import com.burprest.models.ConfigUpdateRequest
import com.burprest.models.HeadersBypassRequest
import com.burprest.models.ScanRequest
import com.burprest.models.SetSessionRequest
import com.burprest.services.ConfigService
import com.burprest.services.ScannerService
import com.burprest.services.SecurityScanService
import com.burprest.services.SessionService
import com.burprest.services.SessionServiceCollaborators
import com.burprest.server.ServiceUnavailableException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import io.mockk.verify
import io.mockk.verifyOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConfigSecurityScanCompositionTest {
    @Test
    fun `configured session material reaches security scan provenance classification`() {
        val marker = "PROTECTED_MARKER_FROM_RESPONSE_7Q"
        val harness = MutableHttpHarness { request, _ ->
            val bypassed = request.headers.any {
                it.first.equals("X-Original-URL", ignoreCase = true) && it.second == "/admin"
            }
            if (bypassed) {
                WireResponse(status = 200, body = "protected:$marker".encodeToByteArray())
            } else {
                WireResponse(status = 403, body = "denied".encodeToByteArray())
            }
        }
        val session = SessionService(
            harness.api,
            null,
            null,
            null,
            SessionServiceCollaborators(
                requestFactory = harness::request,
                bodyFactory = harness::body,
                boundedRequestSender = { request, _ -> harness.send(request) },
            ),
        )
        val scanner = SecurityScanService(harness.api, session, null)
        session.setSession(
            SetSessionRequest(
                cookies = emptyMap(),
                headers = mapOf("X-Session-Provenance" to marker),
                origin = ORIGIN,
            )
        )

        val actorSupplied = scanner.headersBypass(
            HeadersBypassRequest(url = "$ORIGIN/admin", protectedContentMarker = marker)
        ).results.single { it.header == "X-Original-URL" }

        assertTrue(actorSupplied.anomalous)
        assertFalse(actorSupplied.vulnerable)
        assertTrue(actorSupplied.inconclusive)
        assertTrue(actorSupplied.error.orEmpty().contains("actor-supplied"))
        assertTrue(harness.sent.all { sent ->
            sent.headers.any { it == "X-Session-Provenance" to marker }
        })

        session.setSession(
            SetSessionRequest(
                cookies = emptyMap(),
                headers = mapOf("X-Session-Provenance" to "ordinary-session-value"),
                origin = ORIGIN,
            )
        )
        val serverHeld = scanner.headersBypass(
            HeadersBypassRequest(url = "$ORIGIN/admin", protectedContentMarker = marker)
        ).results.single { it.header == "X-Original-URL" }

        assertTrue(serverHeld.anomalous)
        assertTrue(serverHeld.vulnerable)
        assertFalse(serverHeld.inconclusive)
    }

    @Test
    fun `safe config import retains an existing scanner task handle`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        val version = mockk<Version>()
        val scanner = mockk<Scanner>()
        val crawl = mockk<Crawl>()
        val crawlConfiguration = mockk<CrawlConfiguration>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
        every { api.scanner() } returns scanner
        every { scanner.startCrawl(crawlConfiguration) } returns crawl
        every { crawl.requestCount() } returns 4
        every { crawl.errorCount() } returns 0
        every { crawl.delete() } just runs
        every { burpSuite.importUserOptionsFromJson(any()) } just runs
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returnsMany listOf(
            SAFE_EXPORTED_USER_OPTIONS,
            SAFE_EXPORTED_USER_OPTIONS,
        )
        val scannerService = ScannerService(
            api = api,
            crawlConfigurationFactory = { crawlConfiguration },
            scanIdFactory = { "composition-scan" },
        )
        val started = scannerService.crawl(ScanRequest("$ORIGIN/crawl"))
        val requested = Json.parseToJsonElement(REQUESTED_USER_OPTIONS)

        val imported = ConfigService(api).updateUserConfig(ConfigUpdateRequest(requested))
        val stopped = scannerService.stop(started.scanId)

        assertTrue(imported.applied)
        assertEquals(listOf("user_options.extender.extensions"), imported.excludedPaths)
        assertNotNull(imported.config)
        val captured = slot<String>()
        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(capture(captured)) }
        val extender = Json.parseToJsonElement(captured.captured)
            .jsonObject.getValue("user_options").jsonObject.getValue("extender").jsonObject
        assertFalse("extensions" in extender)
        assertEquals("stopped", stopped.status)
        assertEquals(4, stopped.requestCount)
        verifyOrder {
            scanner.startCrawl(crawlConfiguration)
            burpSuite.importUserOptionsFromJson(any())
            crawl.delete()
        }
    }

    @Test
    fun `failed config import leaves an existing scanner handle usable`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        val version = mockk<Version>()
        val scanner = mockk<Scanner>()
        val crawl = mockk<Crawl>()
        val crawlConfiguration = mockk<CrawlConfiguration>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
        every { api.scanner() } returns scanner
        every { scanner.startCrawl(crawlConfiguration) } returns crawl
        every { crawl.requestCount() } returns 2
        every { crawl.errorCount() } returns 0
        every { crawl.delete() } just runs
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returns SAFE_EXPORTED_USER_OPTIONS
        every { burpSuite.importUserOptionsFromJson(any()) } throws IllegalStateException("injected import failure")
        val scannerService = ScannerService(
            api = api,
            crawlConfigurationFactory = { crawlConfiguration },
            scanIdFactory = { "survives-failed-import" },
        )
        val started = scannerService.crawl(ScanRequest("$ORIGIN/error-boundary"))

        assertFailsWith<ServiceUnavailableException> {
            ConfigService(api).updateUserConfig(
                ConfigUpdateRequest(Json.parseToJsonElement(SAFE_EXPORTED_USER_OPTIONS))
            )
        }
        val stopped = scannerService.stop(started.scanId)

        assertEquals("stopped", stopped.status)
        assertEquals(2, stopped.requestCount)
        verify(exactly = 1) { crawl.delete() }
    }

    private companion object {
        const val ORIGIN = "https://composition.example"
        const val SAFE_EXPORTED_USER_OPTIONS =
            "{\"user_options\":{\"theme\":\"dark\",\"extender\":{\"settings\":" +
                "{\"suppress_extension_loaded_popup\":true}}}}"
        const val REQUESTED_USER_OPTIONS =
            "{\"user_options\":{\"theme\":\"dark\",\"extender\":{\"extensions\":" +
                "[{\"extension_file\":\"INERT_EXTENSION_MARKER\"}],\"settings\":" +
                "{\"suppress_extension_loaded_popup\":true}}}}"
    }
}
