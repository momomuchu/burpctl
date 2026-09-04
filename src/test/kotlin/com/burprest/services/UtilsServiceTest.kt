package com.burprest.services

import com.burprest.models.AuthenticatedRequest
import com.burprest.models.AuthenticatedResponse
import com.burprest.models.DiffRequest
import com.burprest.models.DiffTarget
import com.burprest.models.ExtractEndpointsRequest
import com.burprest.models.HttpHeader
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class UtilsServiceTest {

    private fun response(
        body: String?,
        headers: List<HttpHeader> = emptyList(),
        status: Int = 200,
    ) = AuthenticatedResponse(status, headers, body, 0)

    @Test
    fun `diff preflights both targets before its first network effect`() {
        val sessions = mockk<SessionService>(relaxed = true)
        val service = UtilsService(sessions)

        assertFailsWith<IllegalArgumentException> {
            service.diff(
                DiffRequest(
                    a = DiffTarget(url = "https://example.test/valid"),
                    b = DiffTarget(url = "https://example.test/bad", extraHeaders = mapOf("X-Test" to "ok\r\ninjected")),
                )
            )
        }

        verify(exactly = 0) { sessions.send(any()) }
        verify(exactly = 0) { sessions.sendUnauthenticated(any()) }
    }

    @Test
    fun `diff rejects malformed URLs methods and headers without network effects`() {
        val sessions = mockk<SessionService>(relaxed = true)
        val service = UtilsService(sessions)
        val invalid = listOf(
            DiffTarget(url = "/relative"),
            DiffTarget(url = "ftp://example.test/file"),
            DiffTarget(url = "https://example.test:0/file"),
            DiffTarget(url = "https://example.test/file#fragment"),
            DiffTarget(url = "https://example.test", method = "GET POST"),
            DiffTarget(url = "https://example.test", extraHeaders = mapOf("Bad Name" to "value")),
            DiffTarget(url = "https://example.test", extraHeaders = mapOf("X-Test" to "nul\u0000value")),
        )

        invalid.forEach { target ->
            assertFailsWith<IllegalArgumentException> {
                service.diff(DiffRequest(target, DiffTarget(url = "https://example.test/control")))
            }
        }

        verify(exactly = 0) { sessions.send(any()) }
    }

    @Test
    fun `endpoint extraction rejects an unsafe page URL before network effects`() {
        val sessions = mockk<SessionService>(relaxed = true)

        assertFailsWith<IllegalArgumentException> {
            UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest("https://example.test/page#fragment"))
        }

        verify(exactly = 0) { sessions.send(any()) }
        verify(exactly = 0) { sessions.sendUnauthenticated(any()) }
    }

    @Test
    fun `diff reports UTF-8 byte lengths and every duplicate header value`() {
        val sessions = mockk<SessionService>()
        every { sessions.send(match { it.url.endsWith("/a") }) } returns response(
            body = "é",
            headers = listOf(HttpHeader("X-Test", "one"), HttpHeader("x-test", "two")),
        )
        every { sessions.send(match { it.url.endsWith("/b") }) } returns response(
            body = "a",
            headers = listOf(HttpHeader("X-TEST", "one")),
        )

        val result = UtilsService(sessions).diff(
            DiffRequest(DiffTarget(url = "https://example.test/a"), DiffTarget(url = "https://example.test/b"))
        )

        assertEquals(2, result.lengthA)
        assertEquals(1, result.lengthB)
        assertEquals(1, result.lengthDiff)
        assertEquals(1, result.headerDiffs.size)
        assertEquals(listOf("one", "two"), result.headerDiffs.single().aValues)
        assertEquals(listOf("one"), result.headerDiffs.single().bValues)
    }

    @Test
    fun `endpoint extraction uses RFC resolution preserving IPv6 and explicit ports`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://[2001:db8::1]:8443/app/index.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            """
            <!doctype html>
            <script src="assets/app.js"></script>
            <script src="/root.js"></script>
            <script src="//cdn.example.test:9443/lib.js"></script>
            <script src="https://[2001:db8::1]:8443/v6.js"></script>
            """.trimIndent()
        )
        every { sessions.send(match { it.url != pageUrl }) } returns response("fetch('/api/same')")
        every { sessions.sendUnauthenticated(any()) } returns response("fetch('/api/cross')")

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        verify(exactly = 1) { sessions.send(match { it.url == "https://[2001:db8::1]:8443/app/assets/app.js" }) }
        verify(exactly = 1) { sessions.send(match { it.url == "https://[2001:db8::1]:8443/root.js" }) }
        verify(exactly = 1) { sessions.send(match { it.url == "https://[2001:db8::1]:8443/v6.js" }) }
        verify(exactly = 1) {
            sessions.sendUnauthenticated(match { it.url == "https://cdn.example.test:9443/lib.js" })
        }
        assertEquals(4, result.bundlesDiscovered)
        assertEquals(4, result.bundlesAttempted)
        assertEquals(4, result.bundlesFetched)
        assertEquals(0, result.bundlesFailed)
        assertEquals(listOf("/api/cross", "/api/same"), result.endpoints)
    }

    @Test
    fun `equivalent default port is same origin and remains authenticated`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://example.test/app/index.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            "<script src=\"https://example.test:443/bundle.js\"></script>"
        )
        every { sessions.send(match { it.url != pageUrl }) } returns response("fetch('/api/default-port')")

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        verify(exactly = 1) {
            sessions.send(match { it.url == "https://example.test:443/bundle.js" })
        }
        verify(exactly = 0) { sessions.sendUnauthenticated(any()) }
        assertEquals(1, result.bundlesFetched)
    }

    @Test
    fun `same host with another protocol is cross origin and receives no credentials`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://example.test/index.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            "<script src='http://example.test/bundle.js'></script>"
        )
        every { sessions.sendUnauthenticated(any()) } returns response(null)

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        verify(exactly = 1) {
            sessions.sendUnauthenticated(match { it.url == "http://example.test/bundle.js" })
        }
        verify(exactly = 1) { sessions.send(any()) }
        assertEquals(1, result.bundlesFetched)
    }

    @Test
    fun `equivalent IPv6 spellings remain same origin`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://[2001:0db8:0:0:0:0:0:1]/index.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            "<script src=\"https://[2001:db8::1]/bundle.js\"></script>"
        )
        every { sessions.send(match { it.url != pageUrl }) } returns response(null)

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        verify(exactly = 1) {
            sessions.send(match { it.url == "https://[2001:db8::1]/bundle.js" })
        }
        verify(exactly = 0) { sessions.sendUnauthenticated(any()) }
        assertEquals(1, result.bundlesFetched)
    }

    @Test
    fun `relative references resolve against a page path rather than by string concatenation`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "http://example.test:8080/dir/page.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            "<script src='child.js'></script><script src='/root.js'></script>"
        )
        every { sessions.send(match { it.url != pageUrl }) } returns response(null)

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        verify(exactly = 1) { sessions.send(match { it.url == "http://example.test:8080/dir/child.js" }) }
        verify(exactly = 1) { sessions.send(match { it.url == "http://example.test:8080/root.js" }) }
        assertEquals(2, result.bundlesFetched)
    }

    @Test
    fun `bundle URI query is retained and fragment is not sent in an HTTP request`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://example.test/app/index.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            "<script src='bundle.js?v=1#content-hash'></script>"
        )
        every { sessions.send(match { it.url != pageUrl }) } returns response(null)

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        verify(exactly = 1) {
            sessions.send(match { it.url == "https://example.test/app/bundle.js?v=1" })
        }
        assertEquals(1, result.bundlesFetched)
        assertTrue(result.failures.isEmpty())
    }

    @Test
    fun `bundle failures are returned with truthful fetch counts`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://example.test/index.html"
        every { sessions.send(match { it.url == pageUrl }) } returns response(
            "<script src='/ok.js'></script><script src='https://cdn.test/fail.js'></script>"
        )
        every { sessions.send(match { it.url.endsWith("/ok.js") }) } returns response("fetch('/api/ok')")
        every { sessions.sendUnauthenticated(any()) } throws IllegalStateException("connection refused")

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        assertEquals(2, result.bundlesDiscovered)
        assertEquals(2, result.bundlesAttempted)
        assertEquals(1, result.bundlesFetched)
        assertEquals(1, result.bundlesFailed)
        assertEquals("https://cdn.test/fail.js", result.failures.single().url)
        assertTrue(result.failures.single().error.contains("connection refused"))
        assertEquals(listOf("/api/ok"), result.endpoints)
    }

    @Test
    fun `endpoint extraction enforces ten bundle attempt limit and reports discovery count`() {
        val sessions = mockk<SessionService>()
        val pageUrl = "https://example.test/index.html"
        val scripts = (1..12).joinToString("") { "<script src='/b$it.js'></script>" }
        every { sessions.send(match { it.url == pageUrl }) } returns response(scripts)
        every { sessions.send(match { it.url != pageUrl }) } returns response(null)

        val result = UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest(pageUrl))

        assertEquals(12, result.bundlesDiscovered)
        assertEquals(10, result.bundlesAttempted)
        assertEquals(10, result.bundlesFetched)
        verify(exactly = 11) { sessions.send(any()) }
    }

    @Test
    fun `invalid extraction URL is rejected before any request`() {
        val sessions = mockk<SessionService>(relaxed = true)

        assertFailsWith<IllegalArgumentException> {
            UtilsService(sessions).extractEndpoints(ExtractEndpointsRequest("mailto:user@example.test"))
        }

        verify(exactly = 0) { sessions.send(any()) }
        verify(exactly = 0) { sessions.sendUnauthenticated(any()) }
    }
}
