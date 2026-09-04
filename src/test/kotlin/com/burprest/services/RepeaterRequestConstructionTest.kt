package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpHeader as BurpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.RequestModifications
import com.burprest.models.SendRequest
import com.burprest.server.InvalidParamException
import io.mockk.every
import io.mockk.mockk
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull

class RepeaterRequestConstructionTest {
    private val api = mockk<MontoyaApi>()
    private val http = mockk<Http>()
    private val proxy = mockk<Proxy>()

    init {
        every { api.http() } returns http
        every { api.proxy() } returns proxy
    }

    @Test
    fun `inline text body reaches Montoya as UTF-8 bytes`() {
        val body = "éαβγ😀"
        var transmitted: kotlin.ByteArray? = null
        val burpBody = mockk<BurpByteArray>()
        val request = buildableRequest("POST", "https://example.test/unicode")
        every { request.withBody(any<String>()) } answers {
            transmitted = firstArg<String>().map { it.code.toByte() }.toByteArray()
            request
        }
        every { request.withBody(burpBody) } returns request
        val service = service(request, burpBody) { transmitted = it.copyOf() }

        service.buildRequest(
            HttpRequestData(method = "POST", url = "https://example.test/unicode", body = body)
        )

        assertContentEquals(body.encodeToByteArray(), assertNotNull(transmitted))
    }

    @Test
    fun `modified text body also reaches Montoya as UTF-8 bytes`() {
        val body = "éαβγ😀"
        var transmitted: kotlin.ByteArray? = null
        val burpBody = mockk<BurpByteArray>()
        val historical = buildableRequest("GET", "https://example.test/history")
        every { historical.withBody(burpBody) } returns historical
        every { proxy.history() } returns listOf(historyEntry(historical))
        every { http.sendRequest(historical) } returns exchange()
        val service = RepeaterService(
            api,
            bodyFactory = { bytes ->
                transmitted = bytes.copyOf()
                burpBody
            },
        )

        service.send(
            SendRequest(
                requestId = 0,
                modifications = RequestModifications(body = body),
            )
        )

        assertContentEquals(body.encodeToByteArray(), assertNotNull(transmitted))
    }

    @Test
    fun `inline Base64 body wins over text and preserves arbitrary bytes`() {
        val raw = byteArrayOf(0, 0xff.toByte(), 0x41, 0x80.toByte())
        var transmitted: kotlin.ByteArray? = null
        val burpBody = mockk<BurpByteArray>()
        val request = buildableRequest("POST", "https://example.test/binary")
        every { request.withBody(any<String>()) } answers {
            transmitted = firstArg<String>().encodeToByteArray()
            request
        }
        every { request.withBody(burpBody) } returns request
        val service = service(request, burpBody) { transmitted = it.copyOf() }

        service.buildRequest(
            HttpRequestData(
                method = "POST",
                url = "https://example.test/binary",
                body = "ignored text",
                bodyBase64 = Base64.getEncoder().encodeToString(raw),
            )
        )

        assertContentEquals(raw, assertNotNull(transmitted))
    }

    @Test
    fun `invalid Base64 body is rejected before request construction`() {
        var factoryCalled = false
        val service = RepeaterService(
            api,
            requestFactory = {
                factoryCalled = true
                mockk()
            },
        )

        val failure = assertFailsWith<InvalidParamException> {
            service.buildRequest(
                HttpRequestData(
                    method = "POST",
                    url = "https://example.test/binary",
                    bodyBase64 = "%%%not-base64%%%",
                )
            )
        }

        assertEquals("request.bodyBase64 must be valid Base64", failure.clientMessage)
        assertFalse(factoryCalled)
    }

    @Test
    fun `send response retains exact request bytes alongside its text projection`() {
        val raw = byteArrayOf(0, 0xff.toByte(), 0x41)
        val burpBody = mockk<BurpByteArray>()
        val request = buildableRequest("POST", "https://example.test/binary")
        every { request.body() } returns burpBody
        every { burpBody.length() } returns raw.size
        every { burpBody.getBytes() } returns raw
        every { request.bodyToString() } returns "lossy"
        every { request.withBody(burpBody) } returns request
        every { http.sendRequest(request) } returns exchange()
        val service = service(request, burpBody)

        val result = service.send(
            SendRequest(
                request = HttpRequestData(
                    method = "POST",
                    url = "https://example.test/binary",
                    bodyBase64 = Base64.getEncoder().encodeToString(raw),
                )
            )
        )

        assertEquals(Base64.getEncoder().encodeToString(raw), result.request.bodyBase64)
    }

    @Test
    fun `inline construction strips factory headers and preserves ordered duplicate caller headers`() {
        val request = mutableHeaderRequest(
            listOf(
                "Accept" to "*/*",
                "User-Agent" to "browser-like default",
            )
        )
        val service = RepeaterService(api, requestFactory = { request })
        val callerHeaders = listOf(
            HttpHeader("Cookie", "first=one"),
            HttpHeader("Cookie", "second=two"),
            HttpHeader("X-Order", "last"),
        )

        val built = service.buildRequest(
            HttpRequestData(
                method = "POST",
                url = "https://example.test/headers",
                headers = callerHeaders,
            )
        )

        assertEquals(
            callerHeaders.map { it.name to it.value },
            built.headers().map { it.name() to it.value() },
        )
    }

    private fun service(
        request: HttpRequest,
        burpBody: BurpByteArray,
        capture: (kotlin.ByteArray) -> Unit = {},
    ) = RepeaterService(
        api,
        requestFactory = { request },
        bodyFactory = { bytes ->
            capture(bytes)
            burpBody
        },
    )

    private fun buildableRequest(method: String, url: String): HttpRequest {
        val request = mockk<HttpRequest>()
        val body = mockk<BurpByteArray>()
        every { request.method() } returns method
        every { request.url() } returns url
        every { request.headers() } returns emptyList()
        every { request.body() } returns body
        every { body.length() } returns 0
        every { body.getBytes() } returns byteArrayOf()
        every { request.bodyToString() } returns ""
        every { request.withMethod(any()) } returns request
        every { request.withRemovedHeaders(any<List<BurpHeader>>()) } returns request
        every { request.withAddedHeader(any<String>(), any<String>()) } returns request
        return request
    }

    private fun mutableHeaderRequest(initial: List<Pair<String, String>>): HttpRequest {
        val request = mockk<HttpRequest>()
        val headers = initial.map { (name, value) -> header(name, value) }.toMutableList()
        every { request.method() } returns "GET"
        every { request.url() } returns "https://example.test/headers"
        every { request.withMethod(any()) } returns request
        every { request.headers() } answers { headers.toList() }
        every { request.withRemovedHeaders(any<List<BurpHeader>>()) } answers {
            headers.removeAll(firstArg<List<BurpHeader>>().toSet())
            request
        }
        every { request.withAddedHeader(any<String>(), any<String>()) } answers {
            headers += header(firstArg(), secondArg())
            request
        }
        return request
    }

    private fun header(name: String, value: String): BurpHeader = mockk<BurpHeader>().also { header ->
        every { header.name() } returns name
        every { header.value() } returns value
    }

    private fun historyEntry(request: HttpRequest): ProxyHttpRequestResponse =
        mockk<ProxyHttpRequestResponse>().also { entry ->
            every { entry.finalRequest() } returns request
        }

    private fun exchange(): HttpRequestResponse {
        val exchange = mockk<HttpRequestResponse>()
        val response = mockk<HttpResponse>()
        val body = mockk<BurpByteArray>()
        every { exchange.hasResponse() } returns true
        every { exchange.response() } returns response
        every { response.statusCode() } returns 200
        every { response.headers() } returns emptyList()
        every { response.body() } returns body
        every { body.length() } returns 0
        every { response.bodyToString() } returns ""
        return exchange
    }
}
