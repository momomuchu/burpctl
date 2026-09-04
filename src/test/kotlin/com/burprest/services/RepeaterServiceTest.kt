package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpHeader as BurpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.repeater.Repeater
import com.burprest.db.HistoryDao
import com.burprest.db.SitemapDao
import com.burprest.models.BatchSendRequest
import com.burprest.models.CreateTabRequest
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.PersistenceStatus
import com.burprest.models.RequestModifications
import com.burprest.models.SendRequest
import com.burprest.server.InvalidParamException
import com.burprest.server.NoResponseException
import io.mockk.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RepeaterServiceTest {
    private val api = mockk<MontoyaApi>()
    private val http = mockk<Http>()
    private val proxy = mockk<Proxy>()
    private val repeater = mockk<Repeater>()

    init {
        every { api.http() } returns http
        every { api.proxy() } returns proxy
        every { api.repeater() } returns repeater
    }

    @Test
    fun `send rejects neither request source without effects`() {
        val service = RepeaterService(api)

        val error = assertFailsWith<IllegalArgumentException> {
            service.send(SendRequest())
        }

        assertTrue(error.message.orEmpty().contains("exactly one", ignoreCase = true))
        verifyNoSendOrPersistence()
    }

    @Test
    fun `send rejects both request sources without effects`() {
        val service = RepeaterService(api)
        val inline = validInline()

        val error = assertFailsWith<IllegalArgumentException> {
            service.send(SendRequest(request = inline, requestId = 0))
        }

        assertTrue(error.message.orEmpty().contains("exactly one", ignoreCase = true))
        verifyNoSendOrPersistence()
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `blank and tab-only inline method or URL are rejected before construction`() {
        val service = RepeaterService(api)
        val invalid = listOf(
            HttpRequestData(method = "", url = "https://example.test"),
            HttpRequestData(method = " \t ", url = "https://example.test"),
            HttpRequestData(method = "GET", url = ""),
            HttpRequestData(method = "GET", url = "\t"),
        )

        invalid.forEach { request ->
            assertFailsWith<IllegalArgumentException> {
                service.send(SendRequest(request = request))
            }
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `invalid inline URL forms and URL control characters are rejected without effects`() {
        val service = RepeaterService(api)
        val invalidUrls = listOf(
            "example.test/path",
            "/relative",
            "ftp://example.test/file",
            "http:///missing-host",
            "https://example.test:70000/path",
            "https://example.test:0/path",
            "https://example.test:/path",
            "https://example.test/path with space",
            "https://example.test/%zz",
            "https://example.test/path#fragment",
            "https://example.test/path\rX-Test: injected",
            "https://example.test/path\nX-Test: injected",
            "https://example.test/path\u0000suffix",
        )

        invalidUrls.forEach { url ->
            assertFailsWith<IllegalArgumentException>("URL should be rejected: ${url.toCharArray().contentToString()}") {
                service.send(SendRequest(request = validInline(url = url)))
            }
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `valid inline request accepts RFC tokens and horizontal tabs in header values`() {
        val request = mockBuildableRequest(
            method = "PATCH",
            url = "https://[::1]:8443/a?b=c",
            headers = listOf("X_Custom" to "one\ttwo"),
            body = "payload",
        )
        every { http.sendRequest(request) } returns mockExchange(statusCode = 202)
        val builtUrls = mutableListOf<String>()
        val burpBody = mockk<BurpByteArray>()
        every { request.withBody(burpBody) } returns request
        val service = RepeaterService(
            api,
            requestFactory = { url ->
                builtUrls += url
                request
            },
            bodyFactory = { burpBody },
        )

        val result = service.send(
            SendRequest(
                request = HttpRequestData(
                    method = "PATCH",
                    url = "https://[::1]:8443/a?b=c",
                    headers = listOf(HttpHeader("X_Custom", "one\ttwo")),
                    body = "payload",
                ),
            ),
        )

        assertEquals(listOf("https://[::1]:8443/a?b=c"), builtUrls)
        assertEquals(202, result.response.statusCode)
        verify(exactly = 1) { http.sendRequest(request) }
    }

    @Test
    fun `invalid inline and modified methods are rejected without effects`() {
        val historical = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(historical))
        val service = RepeaterService(api)
        val invalidMethods = listOf("", " ", "\t", "GET POST", "GET\r", "GET\nX", "GET\u0000X", "GÉT")

        invalidMethods.forEach { method ->
            assertFailsWith<IllegalArgumentException> {
                service.send(SendRequest(request = validInline(method = method)))
            }
            assertFailsWith<IllegalArgumentException> {
                service.send(SendRequest(requestId = 0, modifications = RequestModifications(method = method)))
            }
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `invalid inline header names and values are rejected without effects`() {
        val service = RepeaterService(api)
        val invalidHeaders = listOf(
            HttpHeader("", "value"),
            HttpHeader("\t", "value"),
            HttpHeader("Bad Name", "value"),
            HttpHeader("Bad:Name", "value"),
            HttpHeader("Bad\rName", "value"),
            HttpHeader("Bad\nName", "value"),
            HttpHeader("Bad\u0000Name", "value"),
            HttpHeader("X-Test", "one\rtwo"),
            HttpHeader("X-Test", "one\ntwo"),
            HttpHeader("X-Test", "one\u0000two"),
        )

        invalidHeaders.forEach { header ->
            assertFailsWith<IllegalArgumentException> {
                service.send(SendRequest(request = validInline(headers = listOf(header))))
            }
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `invalid modified headers and paths are rejected before history mutation or send`() {
        val historical = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(historical))
        val service = RepeaterService(api)
        val invalidMods = listOf(
            RequestModifications(headers = mapOf("Bad Name" to "value")),
            RequestModifications(headers = mapOf("X-Test" to "one\r\ntwo")),
            RequestModifications(headers = mapOf("X-Test" to "nul\u0000value")),
            RequestModifications(path = "\t"),
            RequestModifications(path = "relative/path"),
            RequestModifications(path = "/ok\r\nX-Test: injected"),
            RequestModifications(path = "https://other.test/path"),
            RequestModifications(path = "/path#fragment"),
        )

        invalidMods.forEach { modifications ->
            assertFailsWith<IllegalArgumentException> {
                service.send(SendRequest(requestId = 0, modifications = modifications))
            }
        }

        verify(exactly = 0) { historical.withMethod(any()) }
        verify(exactly = 0) { historical.withPath(any()) }
        verify(exactly = 0) { historical.withRemovedHeader(any<String>()) }
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `invalid requestId is rejected without target or persistence effects`() {
        every { proxy.history() } returns emptyList()
        val historyDao = mockk<HistoryDao>(relaxed = true)
        val sitemapDao = mockk<SitemapDao>(relaxed = true)
        val service = RepeaterService(api, historyDao, sitemapDao)

        assertFailsWith<IllegalArgumentException> {
            service.send(SendRequest(requestId = -1))
        }
        assertFailsWith<IllegalArgumentException> {
            service.send(SendRequest(requestId = 0))
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
        verify { historyDao wasNot Called }
        verify { sitemapDao wasNot Called }
    }

    @Test
    fun `requestId source is validated before the fetched request is sent`() {
        val invalidHistorical = mockRequest(
            url = "https://example.test/path",
            headers = listOf("X-Test" to "one\r\ntwo"),
        )
        every { proxy.history() } returns listOf(mockHistoryEntry(invalidHistorical))
        val service = RepeaterService(api)

        assertFailsWith<IllegalArgumentException> {
            service.send(SendRequest(requestId = 0))
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `all preflight rejection classes leave target and persistence untouched`() {
        every { proxy.history() } returns emptyList()
        val historyDao = mockk<HistoryDao>(relaxed = true)
        val sitemapDao = mockk<SitemapDao>(relaxed = true)
        val service = RepeaterService(api, historyDao, sitemapDao)
        val invalidRequests = listOf(
            SendRequest(),
            SendRequest(request = validInline(), requestId = 0),
            SendRequest(request = validInline(method = "\t")),
            SendRequest(request = validInline(url = "https://example.test/a\r\nb")),
            SendRequest(request = validInline(headers = listOf(HttpHeader("Bad Name", "value")))),
            SendRequest(requestId = -1),
            SendRequest(requestId = 0),
            SendRequest(requestId = 0, modifications = RequestModifications(path = "\t")),
            SendRequest(
                requestId = 0,
                modifications = RequestModifications(headers = mapOf("X-Test" to "bad\u0000value")),
            ),
        )

        invalidRequests.forEach { request ->
            assertFailsWith<IllegalArgumentException> { service.send(request) }
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
        verify { historyDao wasNot Called }
        verify { sitemapDao wasNot Called }
    }

    @Test
    fun `batch preflights every item before sending any target request`() {
        val first = mockRequest(url = "https://one.example.test/valid")
        every { proxy.history() } returns listOf(mockHistoryEntry(first))
        val historyDao = mockk<HistoryDao>(relaxed = true)
        val sitemapDao = mockk<SitemapDao>(relaxed = true)
        val service = RepeaterService(api, historyDao, sitemapDao)
        val batch = BatchSendRequest(
            requests = listOf(
                SendRequest(requestId = 0),
                SendRequest(request = validInline(url = "https://two.example.test"), requestId = 0),
            ),
        )

        val error = assertFailsWith<IllegalArgumentException> { service.sendBatch(batch) }

        assertTrue(error.message.orEmpty().contains("requests[1]"))
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
        verify { historyDao wasNot Called }
        verify { sitemapDao wasNot Called }
    }

    @Test
    fun `batch sends only after complete preflight and preserves order`() {
        val first = mockRequest(url = "https://one.example.test/a")
        val second = mockRequest(url = "https://two.example.test/b")
        every { proxy.history() } returns listOf(mockHistoryEntry(first), mockHistoryEntry(second))
        val firstExchange = mockExchange(statusCode = 201)
        val secondExchange = mockExchange(statusCode = 202)
        every { http.sendRequest(first) } returns firstExchange
        every { http.sendRequest(second) } returns secondExchange
        val service = RepeaterService(api)

        val result = service.sendBatch(
            BatchSendRequest(listOf(SendRequest(requestId = 0), SendRequest(requestId = 1))),
        )

        assertEquals(listOf(201, 202), result.results.map { it.response.statusCode })
        verify(exactly = 1) { http.sendRequest(first) }
        verify(exactly = 1) { http.sendRequest(second) }
    }

    @Test
    fun `send checks hasResponse and returns typed no-response without dereferencing response`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        val exchange = mockk<HttpRequestResponse>()
        every { exchange.hasResponse() } returns false
        every { http.sendRequest(request) } returns exchange
        val historyDao = mockk<HistoryDao>(relaxed = true)
        val sitemapDao = mockk<SitemapDao>(relaxed = true)
        val service = RepeaterService(api, historyDao, sitemapDao)

        val error = assertFailsWith<NoResponseException> {
            service.send(SendRequest(requestId = 0))
        }

        assertTrue(error.message.orEmpty().contains("completed", ignoreCase = true))
        verify(exactly = 1) { exchange.hasResponse() }
        verify(exactly = 0) { exchange.response() }
        verify { historyDao wasNot Called }
        verify { sitemapDao wasNot Called }
    }

    @Test
    fun `send does not treat a null response as response-bearing even when adapter flag is true`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        val exchange = mockk<HttpRequestResponse>()
        every { exchange.hasResponse() } returns true
        every { exchange.response() } returns null
        every { http.sendRequest(request) } returns exchange
        val service = RepeaterService(api)

        val error = assertFailsWith<NoResponseException> {
            service.send(SendRequest(requestId = 0))
        }

        assertTrue(error.message.orEmpty().contains("without an upstream response", ignoreCase = true))
    }

    @Test
    fun `successful response and atomic persistence are represented truthfully`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        every { http.sendRequest(request) } returns mockExchange(statusCode = 204)
        val historyDao = mockk<HistoryDao>()
        val sitemapDao = mockk<SitemapDao>()
        every {
            historyDao.insertWithSitemap(
                sitemapDao = sitemapDao,
                source = "repeater",
                method = "GET",
                url = "https://example.test/path",
                reqHeaders = any(),
                reqBody = null,
                statusCode = 204,
                resHeaders = any(),
                resBody = null,
                durationMs = any(),
                timestamp = any(),
            )
        } returns 73L
        val service = RepeaterService(api, historyDao, sitemapDao)

        val result = service.send(SendRequest(requestId = 0))

        assertTrue(result.hasResponse)
        assertEquals(204, result.response.statusCode)
        assertEquals(PersistenceStatus.PERSISTED, result.persistence.status)
        assertTrue(result.persistence.historyPersisted)
        assertTrue(result.persistence.sitemapPersisted)
        assertEquals(73L, result.persistence.historyId)
        assertNull(result.persistence.warning)
        verify(exactly = 1) { historyDao.insertWithSitemap(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        verify(exactly = 0) { sitemapDao.upsert(any(), any(), any()) }
    }

    @Test
    fun `atomic persistence failure after target send returns response and sanitized warning`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        every { http.sendRequest(request) } returns mockExchange(statusCode = 200)
        val historyDao = mockk<HistoryDao>()
        val sitemapDao = mockk<SitemapDao>()
        every {
            historyDao.insertWithSitemap(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } throws IllegalStateException("database secret")
        val logging = mockk<Logging>()
        val loggedWarning = slot<String>()
        every { api.logging() } returns logging
        every { logging.logToError(capture(loggedWarning)) } just Runs
        val service = RepeaterService(api, historyDao, sitemapDao)

        val result = service.send(SendRequest(requestId = 0))

        assertEquals(200, result.response.statusCode)
        assertEquals(PersistenceStatus.FAILED, result.persistence.status)
        assertFalse(result.persistence.historyPersisted)
        assertFalse(result.persistence.sitemapPersisted)
        assertNull(result.persistence.historyId)
        assertTrue(result.persistence.warning.orEmpty().contains("send completed", ignoreCase = true))
        assertTrue(result.persistence.warning.orEmpty().contains("do not retry", ignoreCase = true))
        assertFalse(result.persistence.warning.orEmpty().contains("database secret"))
        assertTrue(loggedWarning.captured.contains("send completed", ignoreCase = true))
        assertFalse(loggedWarning.captured.contains("database secret"))
        verify(exactly = 1) { http.sendRequest(request) }
        verify(exactly = 1) {
            historyDao.insertWithSitemap(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
        verify(exactly = 0) { sitemapDao.upsert(any(), any(), any()) }
    }

    @Test
    fun `single configured history recorder reports partial persistence`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        every { http.sendRequest(request) } returns mockExchange(statusCode = 200)
        val historyDao = mockk<HistoryDao>()
        every {
            historyDao.insert(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns 91L
        val service = RepeaterService(api, historyDao, null)

        val result = service.send(SendRequest(requestId = 0))

        assertEquals(PersistenceStatus.PARTIAL, result.persistence.status)
        assertTrue(result.persistence.historyPersisted)
        assertFalse(result.persistence.sitemapPersisted)
        assertEquals(91L, result.persistence.historyId)
        assertTrue(result.persistence.warning.orEmpty().contains("not configured", ignoreCase = true))
    }

    @Test
    fun `create tab enforces exactly one request source without UI effects`() {
        val service = RepeaterService(api)

        assertFailsWith<IllegalArgumentException> { service.createTab(CreateTabRequest()) }
        assertFailsWith<IllegalArgumentException> {
            service.createTab(CreateTabRequest(request = validInline(), requestId = 0))
        }

        verify { repeater wasNot Called }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `malformed history request is rejected before send or UI effects`() {
        val malformed = mockk<HttpRequest>()
        every { malformed.method() } throws MalformedRequestException("stored bytes are malformed")
        every { proxy.history() } returns listOf(mockHistoryEntry(malformed))
        val service = RepeaterService(api)

        assertFailsWith<InvalidParamException> {
            service.send(SendRequest(requestId = 0))
        }
        assertFailsWith<InvalidParamException> {
            service.createTab(CreateTabRequest(requestId = 0))
        }

        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
        verify { repeater wasNot Called }
    }

    @Test
    fun `create tab rejects a blank name before any UI effect`() {
        every { proxy.history() } returns listOf(mockHistoryEntry(mockRequest()))
        val service = RepeaterService(api)

        listOf("", " ", "\t").forEach { blank ->
            assertFailsWith<InvalidParamException> {
                service.createTab(CreateTabRequest(requestId = 0, name = blank))
            }
        }

        verify { repeater wasNot Called }
    }

    @Test
    fun `create tab validates a fetched history request without UI effects`() {
        val invalidHistorical = mockRequest(method = "\t")
        every { proxy.history() } returns listOf(mockHistoryEntry(invalidHistorical))
        val service = RepeaterService(api)

        assertFailsWith<IllegalArgumentException> {
            service.createTab(CreateTabRequest(requestId = 0))
        }

        verify { repeater wasNot Called }
    }

    @Test
    fun `create tab loads a valid history request without target traffic or persistence`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        every { repeater.sendToRepeater(request, "REST API Tab") } returns Unit
        val historyDao = mockk<HistoryDao>(relaxed = true)
        val sitemapDao = mockk<SitemapDao>(relaxed = true)
        val service = RepeaterService(api, historyDao, sitemapDao)

        val result = service.createTab(CreateTabRequest(requestId = 0))

        assertEquals("REST API Tab", result.name)
        assertTrue(result.created)
        verify(exactly = 1) { repeater.sendToRepeater(request, "REST API Tab") }
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
        verify { historyDao wasNot Called }
        verify { sitemapDao wasNot Called }
    }

    @Test
    fun `unconfigured optional persistence is explicit and does not warn`() {
        val request = mockRequest()
        every { proxy.history() } returns listOf(mockHistoryEntry(request))
        every { http.sendRequest(request) } returns mockExchange(statusCode = 200)
        val service = RepeaterService(api)

        val result = service.send(SendRequest(requestId = 0))

        assertEquals(PersistenceStatus.NOT_CONFIGURED, result.persistence.status)
        assertFalse(result.persistence.historyPersisted)
        assertFalse(result.persistence.sitemapPersisted)
        assertNull(result.persistence.warning)
    }

    private fun validInline(
        method: String = "GET",
        url: String = "https://example.test/path",
        headers: List<HttpHeader> = emptyList(),
    ) = HttpRequestData(method = method, url = url, headers = headers)

    private fun mockHistoryEntry(request: HttpRequest): ProxyHttpRequestResponse =
        mockk<ProxyHttpRequestResponse>().also { entry ->
            every { entry.finalRequest() } returns request
        }

    private fun mockBuildableRequest(
        method: String,
        url: String,
        headers: List<Pair<String, String>>,
        body: String?,
    ): HttpRequest = mockRequest(method, url, headers, body).also { request ->
        every { request.withMethod(any()) } returns request
        every { request.withPath(any()) } returns request
        every { request.withBody(any<String>()) } returns request
        every { request.withRemovedHeader(any<String>()) } returns request
        every { request.withRemovedHeaders(any<List<BurpHeader>>()) } returns request
        every { request.withAddedHeader(any<String>(), any()) } returns request
    }

    private fun mockRequest(
        method: String = "GET",
        url: String = "https://example.test/path",
        headers: List<Pair<String, String>> = emptyList(),
        body: String? = null,
    ): HttpRequest {
        val request = mockk<HttpRequest>()
        val requestBody = mockk<BurpByteArray>()
        val burpHeaders = headers.map { (name, value) ->
            mockk<BurpHeader>().also { header ->
                every { header.name() } returns name
                every { header.value() } returns value
            }
        }
        every { request.method() } returns method
        every { request.url() } returns url
        every { request.headers() } returns burpHeaders
        every { request.body() } returns requestBody
        every { requestBody.length() } returns (body?.length ?: 0)
        every { requestBody.getBytes() } returns (body?.encodeToByteArray() ?: byteArrayOf())
        every { request.bodyToString() } returns (body ?: "")
        return request
    }

    private fun mockExchange(
        statusCode: Short,
        headers: List<Pair<String, String>> = emptyList(),
        body: String? = null,
    ): HttpRequestResponse {
        val exchange = mockk<HttpRequestResponse>()
        val response = mockk<HttpResponse>()
        val responseBody = mockk<BurpByteArray>()
        val burpHeaders = headers.map { (name, value) ->
            mockk<BurpHeader>().also { header ->
                every { header.name() } returns name
                every { header.value() } returns value
            }
        }
        every { exchange.hasResponse() } returns true
        every { exchange.response() } returns response
        every { response.statusCode() } returns statusCode
        every { response.headers() } returns burpHeaders
        every { response.body() } returns responseBody
        every { responseBody.length() } returns (body?.length ?: 0)
        every { response.bodyToString() } returns (body ?: "")
        return exchange
    }

    private fun verifyNoSendOrPersistence() {
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }
}
