package com.burprest.audit

import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.BurpSuiteEdition.COMMUNITY_EDITION
import burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL
import burp.api.montoya.core.Version
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.Scanner
import com.burprest.db.DatabaseManager
import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.db.SitemapDao
import com.burprest.models.HttpRequestData
import com.burprest.models.PersistenceStatus
import com.burprest.models.ScanRequest
import com.burprest.models.SendRequest
import com.burprest.routes.historyRoutes
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.server.unavailableHistoryRoutes
import com.burprest.services.RepeaterService
import com.burprest.services.ScannerService
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Small, local-only state fixture for the command audit.
 *
 * It exercises the existing service and route seams with mocked Montoya objects and a real
 * disposable H2 file. It intentionally never starts Burp or a target listener.
 */
class AuditStateFixtureTest {

    @Test
    fun `Community gates Pro capability before effect while Professional publishes task state`() {
        val community = scannerFixture(COMMUNITY_EDITION)
        assertFailsWith<RuntimeException> { community.service.crawl(ScanRequest("https://127.0.0.1/")) }
        verify(exactly = 0) { community.scanner.startCrawl(any()) }

        val professional = scannerFixture(PROFESSIONAL)
        val crawl = mockk<Crawl>()
        every { professional.scanner.startCrawl(professional.configuration) } returns crawl
        every { crawl.statusMessage() } returns "Running"
        every { crawl.requestCount() } returns 1
        every { crawl.errorCount() } returns 0

        val started = professional.service.crawl(ScanRequest("https://127.0.0.1/"))
        val status = professional.service.status(started.scanId)
        assertEquals("running", started.status)
        assertEquals("Running", status.status)
        assertEquals(1, status.requestCount)
        verify(exactly = 1) { professional.scanner.startCrawl(professional.configuration) }
    }

    @Test
    fun `available H2 history and unavailable history routes have distinct outcomes`() {
        val root = createTempDirectory("audit-state-").toRealPath()
        val db = DatabaseManager(root.resolve("history").toString())
        try {
            val history = HistoryDao(db)
            val sitemap = SitemapDao(db)
            history.insert(
                source = "fixture",
                method = "GET",
                url = "http://127.0.0.1:18080/health",
                reqHeaders = emptyList(),
                reqBody = null,
                statusCode = 200,
                resHeaders = emptyList(),
                resBody = "ok",
                durationMs = 2,
                timestamp = "2026-10-23T10:00:00Z",
            )

            testApplication {
                application {
                    installStrictJson()
                    installErrorHandling { }
                    routing { historyRoutes(history, sitemap, RepeaterService(mockk())) }
                }
                val response = client.get("/history")
                assertEquals(HttpStatusCode.OK, response.status)
                assertTrue(response.bodyAsText().contains("http://127.0.0.1:18080/health"))
                assertEquals(1, history.search(HistoryFilter()).size)
            }

            testApplication {
                application {
                    installStrictJson()
                    installErrorHandling { }
                    routing { unavailableHistoryRoutes() }
                }
                val response = client.get("/history")
                assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
                assertTrue(response.bodyAsText().contains("SERVICE_UNAVAILABLE"))
            }
        } finally {
            db.close()
            assertTrue(root.toFile().deleteRecursively(), "audit-state fixture root should be removed")
        }
    }

    @Test
    fun `local target send is counted once and post-effect persistence failure is retry-safe`() {
        val api = mockk<burp.api.montoya.MontoyaApi>()
        val http = mockk<Http>()
        val proxy = mockk<Proxy>()
        val request = mockRequest()
        val entry = mockk<ProxyHttpRequestResponse>()
        every { api.http() } returns http
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(entry)
        every { entry.finalRequest() } returns request
        every { http.sendRequest(request) } returns exchange(200)

        val root = createTempDirectory("audit-send-").toRealPath()
        val db = DatabaseManager(root.resolve("history").toString())
        try {
            val history = HistoryDao(db)
            val sitemap = SitemapDao(db)
            val persisted = RepeaterService(api, history, sitemap).send(SendRequest(requestId = 0))
            assertEquals(PersistenceStatus.PERSISTED, persisted.persistence.status)
            assertTrue(persisted.persistence.historyPersisted)
            assertTrue(persisted.persistence.sitemapPersisted)
            assertEquals(1, history.search(HistoryFilter()).size)
            assertEquals(1, sitemap.list().size)
            verify(exactly = 1) { http.sendRequest(request) }

            val invalid = RepeaterService(api, history, sitemap)
            assertFailsWith<IllegalArgumentException> {
                invalid.send(SendRequest(request = HttpRequestData(method = "GET", url = "not-a-url")))
            }
            verify(exactly = 1) { http.sendRequest(request) }

            val failingHistory = mockk<HistoryDao>()
            val failingSitemap = mockk<SitemapDao>()
            every {
                failingHistory.insertWithSitemap(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
            } throws IllegalStateException("database detail")
            val logging = mockk<burp.api.montoya.logging.Logging>()
            every { api.logging() } returns logging
            every { logging.logToError(any<String>()) } just runs
            val afterEffectFailure = RepeaterService(api, failingHistory, failingSitemap).send(SendRequest(requestId = 0))
            assertEquals(200, afterEffectFailure.response.statusCode)
            assertEquals(PersistenceStatus.FAILED, afterEffectFailure.persistence.status)
            assertTrue(afterEffectFailure.persistence.warning.orEmpty().contains("do not retry"))
            assertFalse(afterEffectFailure.persistence.warning.orEmpty().contains("database detail"))
            verify(exactly = 2) { http.sendRequest(request) }
        } finally {
            db.close()
            assertTrue(root.toFile().deleteRecursively(), "audit-send fixture root should be removed")
        }
    }

    private data class ScannerFixture(
        val scanner: Scanner,
        val configuration: CrawlConfiguration,
        val service: ScannerService,
    )

    private fun scannerFixture(edition: BurpSuiteEdition): ScannerFixture {
        val api = mockk<burp.api.montoya.MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        val version = mockk<Version>()
        val scanner = mockk<Scanner>()
        val configuration = mockk<CrawlConfiguration>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns edition
        every { api.scanner() } returns scanner
        return ScannerFixture(
            scanner = scanner,
            configuration = configuration,
            service = ScannerService(
                api = api,
                crawlConfigurationFactory = { configuration },
                scanIdFactory = { edition.name.lowercase() },
            ),
        )
    }

    private fun mockRequest(): HttpRequest = mockk<HttpRequest>().also { request ->
        val body = mockk<burp.api.montoya.core.ByteArray>()
        every { request.method() } returns "GET"
        every { request.url() } returns "http://127.0.0.1:18080/path"
        every { request.headers() } returns emptyList()
        every { request.body() } returns body
        every { body.length() } returns 0
    }

    private fun exchange(statusCode: Short): HttpRequestResponse = mockk<HttpRequestResponse>().also { exchange ->
        val response = mockk<HttpResponse>()
        val body = mockk<burp.api.montoya.core.ByteArray>()
        every { exchange.hasResponse() } returns true
        every { exchange.response() } returns response
        every { response.statusCode() } returns statusCode
        every { response.headers() } returns emptyList()
        every { response.body() } returns body
        every { body.length() } returns 0
    }
}
