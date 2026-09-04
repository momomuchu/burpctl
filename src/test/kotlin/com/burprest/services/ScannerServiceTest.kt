package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Version
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.burprest.models.ScanConfig
import com.burprest.models.ScanRequest
import com.burprest.server.InvalidParamException
import com.burprest.server.NotFoundException
import com.burprest.server.ProRequiredException
import com.burprest.server.ServiceUnavailableException
import com.burprest.server.UnsupportedException
import io.mockk.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ScannerServiceTest {

    private data class Fixture(
        val api: MontoyaApi,
        val scanner: Scanner,
        val crawlConfiguration: CrawlConfiguration,
        val auditConfiguration: AuditConfiguration,
        val seedRequest: HttpRequest,
        val capturedCrawlUrls: MutableList<String>,
        val capturedRequestUrls: MutableList<String>,
        val service: ScannerService,
    )

    private fun fixture(edition: BurpSuiteEdition = BurpSuiteEdition.PROFESSIONAL): Fixture {
        val api = mockk<MontoyaApi>()
        val scanner = mockk<Scanner>()
        val burpSuite = mockk<BurpSuite>()
        val version = mockk<Version>()
        val crawlConfiguration = mockk<CrawlConfiguration>()
        val auditConfiguration = mockk<AuditConfiguration>()
        val seedRequest = mockk<HttpRequest>()
        val capturedCrawlUrls = mutableListOf<String>()
        val capturedRequestUrls = mutableListOf<String>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns edition
        every { api.scanner() } returns scanner
        return Fixture(
            api,
            scanner,
            crawlConfiguration,
            auditConfiguration,
            seedRequest,
            capturedCrawlUrls,
            capturedRequestUrls,
            ScannerService(
                api = api,
                crawlConfigurationFactory = { url ->
                    capturedCrawlUrls += url
                    crawlConfiguration
                },
                auditConfigurationFactory = { auditConfiguration },
                requestFactory = { url ->
                    capturedRequestUrls += url
                    seedRequest
                },
                scanIdFactory = { "scan-id" },
            ),
        )
    }

    @Test
    fun `invalid URLs are rejected before any Montoya or factory call`() {
        val api = mockk<MontoyaApi>()
        val crawlFactory = mockk<(String) -> CrawlConfiguration>()
        val auditFactory = mockk<() -> AuditConfiguration>()
        val requestFactory = mockk<(String) -> HttpRequest>()
        val service = ScannerService(api, crawlFactory, auditFactory, requestFactory)

        listOf("", "relative/path", "ftp://example.com/", "https:///missing-host").forEach { url ->
            assertFailsWith<InvalidParamException> { service.crawl(ScanRequest(url)) }
            assertFailsWith<InvalidParamException> { service.audit(ScanRequest(url)) }
        }

        verify(exactly = 0) {
            api.burpSuite()
            api.scanner()
            crawlFactory(any())
            auditFactory()
            requestFactory(any())
        }
    }

    @Test
    fun `ignored scanner configuration is rejected before Montoya effects`() {
        val api = mockk<MontoyaApi>()
        val service = ScannerService(api)

        assertFailsWith<UnsupportedException> {
            service.crawl(ScanRequest("https://example.com/", ScanConfig(crawlStrategy = "fast")))
        }
        assertFailsWith<UnsupportedException> {
            service.audit(ScanRequest("https://example.com/", ScanConfig(auditOptimization = "speed")))
        }
        verify(exactly = 0) { api.scanner(); api.burpSuite() }
    }

    @Test
    fun `scanner canonicalizes URL and rejects credentials fragments and invalid ports before effects`() {
        val fixture = fixture()
        val crawl = mockk<Crawl>()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } returns crawl

        fixture.service.crawl(ScanRequest("HTTPS://BÜCHER.EXAMPLE.:443/a/../seed?q=1"))
        assertEquals(listOf("https://xn--bcher-kva.example/seed?q=1"), fixture.capturedCrawlUrls)

        val api = mockk<MontoyaApi>()
        val service = ScannerService(api)
        listOf(
            "https://user:pass@example.com/",
            "https://example.com/path#fragment",
            "https://example.com:70000/",
            "https://example.com:0/",
            "https://example.com:-1/",
            "https://example.com:/",
            "https://example.com:+1/",
        ).forEach { invalid ->
            assertFailsWith<InvalidParamException> { service.crawl(ScanRequest(invalid)) }
        }
        verify(exactly = 0) { api.scanner(); api.burpSuite() }
    }

    @Test
    fun `captured Professional edition prevents changing diagnostic read from relabeling failure`() {
        val fixture = fixture()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } throws IllegalStateException("engine unavailable")

        assertFailsWith<ServiceUnavailableException> {
            fixture.service.crawl(ScanRequest("https://example.com/"))
        }
        verify(exactly = 1) { fixture.api.burpSuite() }
    }

    @Test
    fun `Community edition is identified as Pro gated before a scan starts`() {
        val fixture = fixture(BurpSuiteEdition.COMMUNITY_EDITION)

        assertFailsWith<ProRequiredException> {
            fixture.service.crawl(ScanRequest("https://example.com/"))
        }
        verify(exactly = 0) { fixture.api.scanner() }
    }

    @Test
    fun `operational crawl failure on Professional is not mislabeled Pro required`() {
        val fixture = fixture()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } throws IllegalStateException("engine unavailable")

        assertFailsWith<ServiceUnavailableException> {
            fixture.service.crawl(ScanRequest("https://example.com/"))
        }
    }

    @Test
    fun `crawl status exposes authoritative message and counts with nullable progress`() {
        val fixture = fixture()
        val crawl = mockk<Crawl>()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } returns crawl
        every { crawl.statusMessage() } returns "Crawling seed"
        every { crawl.requestCount() } returns 17
        every { crawl.errorCount() } returns 2

        val started = fixture.service.crawl(ScanRequest("https://example.com/"))
        val status = fixture.service.status(started.scanId)

        assertEquals("Crawling seed", status.status)
        assertEquals("Crawling seed", status.statusMessage)
        assertEquals(17, status.requestCount)
        assertEquals(2, status.errorCount)
        assertEquals(0, status.issueCount)
        assertNull(status.crawlProgress)
        assertNull(status.auditProgress)
    }

    @Test
    fun `audit is seeded with the supplied URL request`() {
        val fixture = fixture()
        val audit = mockk<Audit>()
        every { fixture.scanner.startAudit(fixture.auditConfiguration) } returns audit
        every { audit.addRequest(fixture.seedRequest) } just Runs

        fixture.service.audit(ScanRequest("https://example.com/exact-seed"))

        assertEquals(listOf("https://example.com/exact-seed"), fixture.capturedRequestUrls)
        verifyOrder {
            fixture.scanner.startAudit(fixture.auditConfiguration)
            audit.addRequest(fixture.seedRequest)
        }
    }

    @Test
    fun `audit is deleted and never registered when seeding fails`() {
        val fixture = fixture()
        val audit = mockk<Audit>()
        every { fixture.scanner.startAudit(fixture.auditConfiguration) } returns audit
        every { audit.addRequest(fixture.seedRequest) } throws IllegalArgumentException("cannot seed")
        every { audit.delete() } just Runs

        assertFailsWith<ServiceUnavailableException> {
            fixture.service.audit(ScanRequest("https://example.com/"))
        }

        verify(exactly = 1) { audit.delete() }
        assertFailsWith<NotFoundException> { fixture.service.status("scan-id") }
    }

    @Test
    fun `audit status and issues come from its task`() {
        val fixture = fixture()
        val audit = mockk<Audit>()
        val issue = mockk<AuditIssue>()
        every { fixture.scanner.startAudit(fixture.auditConfiguration) } returns audit
        every { audit.addRequest(fixture.seedRequest) } just Runs
        every { audit.statusMessage() } returns "Auditing"
        every { audit.requestCount() } returns 9
        every { audit.errorCount() } returns 1
        every { audit.issues() } returns listOf(issue)
        every { issue.name() } returns "Example issue"
        every { issue.baseUrl() } returns "https://example.com/"
        every { issue.severity() } returns AuditIssueSeverity.HIGH
        every { issue.confidence() } returns AuditIssueConfidence.CERTAIN
        every { issue.detail() } returns "detail"
        every { issue.remediation() } returns "fix"

        val started = fixture.service.audit(ScanRequest("https://example.com/"))
        val status = fixture.service.status(started.scanId)
        val issues = fixture.service.issues(started.scanId)

        assertEquals("Auditing", status.status)
        assertEquals(9, status.requestCount)
        assertEquals(1, status.errorCount)
        assertEquals(1, status.issueCount)
        assertEquals(1, issues.total)
        assertEquals("Example issue", issues.issues.single().name)
    }

    @Test
    fun `issue mapping failures are operational errors`() {
        val fixture = fixture()
        val audit = mockk<Audit>()
        val issue = mockk<AuditIssue>()
        every { fixture.scanner.startAudit(fixture.auditConfiguration) } returns audit
        every { audit.addRequest(fixture.seedRequest) } just Runs
        every { audit.issues() } returns listOf(issue)
        every { issue.name() } throws IllegalStateException("unavailable")
        val started = fixture.service.audit(ScanRequest("https://example.com/"))

        assertFailsWith<ServiceUnavailableException> { fixture.service.issues(started.scanId) }
    }

    @Test
    fun `task read failures are operational errors rather than fabricated status`() {
        val fixture = fixture()
        val crawl = mockk<Crawl>()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } returns crawl
        every { crawl.statusMessage() } throws IllegalStateException("lost task")

        val started = fixture.service.crawl(ScanRequest("https://example.com/"))

        assertFailsWith<ServiceUnavailableException> { fixture.service.status(started.scanId) }
    }

    @Test
    fun `stop deletes task before returning stopped and removes it only after success`() {
        val fixture = fixture()
        val crawl = mockk<Crawl>()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } returns crawl
        every { crawl.statusMessage() } returns "Running"
        every { crawl.requestCount() } returns 4
        every { crawl.errorCount() } returns 0
        every { crawl.delete() } just Runs
        val started = fixture.service.crawl(ScanRequest("https://example.com/"))

        val stopped = fixture.service.stop(started.scanId)

        verify(exactly = 1) { crawl.delete() }
        assertEquals("stopped", stopped.status)
        assertEquals(4, stopped.requestCount)
        assertFailsWith<NotFoundException> { fixture.service.status(started.scanId) }
    }

    @Test
    fun `failed delete does not falsely report stopped or forget the task`() {
        val fixture = fixture()
        val crawl = mockk<Crawl>()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } returns crawl
        every { crawl.statusMessage() } returns "Running"
        every { crawl.requestCount() } returns 1
        every { crawl.errorCount() } returns 0
        every { crawl.delete() } throws IllegalStateException("delete failed")
        val started = fixture.service.crawl(ScanRequest("https://example.com/"))

        assertFailsWith<ServiceUnavailableException> { fixture.service.stop(started.scanId) }
        assertEquals("Running", fixture.service.status(started.scanId).status)
    }

    @Test
    fun `duplicate generated scan ID deletes the unregistered task and preserves the first`() {
        val fixture = fixture()
        val first = mockk<Crawl>()
        val second = mockk<Crawl>()
        every { fixture.scanner.startCrawl(fixture.crawlConfiguration) } returnsMany listOf(first, second)
        every { second.delete() } just Runs
        every { first.statusMessage() } returns "first task"
        every { first.requestCount() } returns 1
        every { first.errorCount() } returns 0

        fixture.service.crawl(ScanRequest("https://example.com/one"))
        assertFailsWith<ServiceUnavailableException> {
            fixture.service.crawl(ScanRequest("https://example.com/two"))
        }

        verify(exactly = 1) { second.delete() }
        verify(exactly = 0) { first.delete() }
        assertEquals("first task", fixture.service.status("scan-id").status)
    }

    @Test
    fun `pause resume and combined operation fail unsupported before effects`() {
        val api = mockk<MontoyaApi>()
        val service = ScannerService(api)

        assertFailsWith<UnsupportedException> { service.pause("anything") }
        assertFailsWith<UnsupportedException> { service.resume("anything") }
        assertFailsWith<UnsupportedException> {
            service.crawlAndAudit(ScanRequest("not even a URL"))
        }
        verify(exactly = 0) { api.scanner(); api.burpSuite() }
    }
}
