package com.burprest.integration

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader as BurpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import java.net.URI
import java.util.Collections

internal data class WireRequest(
    val method: String,
    val url: String,
    val headers: List<Pair<String, String>>,
    val body: ByteArray,
)

internal data class WireResponse(
    val status: Short = 200,
    val headers: List<Pair<String, String>> = emptyList(),
    val body: ByteArray = "ok".encodeToByteArray(),
    val hasResponse: Boolean = true,
)

internal class MutableHttpHarness(
    private val responder: (WireRequest, Int) -> WireResponse = { _, _ -> WireResponse() },
) {
    val api: MontoyaApi = mockk()
    val http: Http = mockk()
    val sent: MutableList<WireRequest> = Collections.synchronizedList(mutableListOf())

    init {
        every { api.http() } returns http
        every { http.sendRequest(any<HttpRequest>()) } answers { send(firstArg()) }
        every { http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) } answers { send(firstArg()) }
    }

    fun request(url: String): HttpRequest {
        val request = mockk<HttpRequest>()
        val headers = mutableListOf<BurpHeader>()
        var method = "GET"
        var currentUrl = url
        var bodyBytes = byteArrayOf()
        val body = mockk<BurpByteArray>()

        every { request.method() } answers { method }
        every { request.url() } answers { currentUrl }
        every { request.headers() } answers { synchronized(headers) { headers.toList() } }
        every { request.body() } returns body
        every { request.bodyToString() } answers { bodyBytes.decodeToString() }
        every { body.length() } answers { bodyBytes.size }
        every { body.getBytes() } answers { bodyBytes.copyOf() }
        every { request.withMethod(any()) } answers {
            method = firstArg()
            request
        }
        every { request.withPath(any()) } answers {
            val replacement = firstArg<String>()
            val old = URI(currentUrl)
            currentUrl = URI(
                old.scheme,
                old.rawAuthority,
                replacement.substringBefore('?'),
                replacement.substringAfter('?', "").ifEmpty { null },
                null,
            ).toString()
            request
        }
        every { request.withBody(any<String>()) } answers {
            bodyBytes = firstArg<String>().encodeToByteArray()
            request
        }
        every { request.withBody(any<BurpByteArray>()) } answers {
            bodyBytes = firstArg<BurpByteArray>().getBytes().copyOf()
            request
        }
        every { request.withRemovedHeader(any<String>()) } answers {
            val name = firstArg<String>()
            synchronized(headers) { headers.removeAll { it.name().equals(name, ignoreCase = true) } }
            request
        }
        every { request.withRemovedHeaders(any<List<BurpHeader>>()) } answers {
            val removed = firstArg<List<BurpHeader>>().toSet()
            synchronized(headers) { headers.removeAll(removed) }
            request
        }
        every { request.withAddedHeader(any<String>(), any<String>()) } answers {
            val header = header(firstArg(), secondArg())
            synchronized(headers) { headers += header }
            request
        }
        return request
    }

    fun body(bytes: ByteArray): BurpByteArray = mockk<BurpByteArray>().also { body ->
        every { body.length() } returns bytes.size
        every { body.getBytes() } returns bytes.copyOf()
    }

    fun send(request: HttpRequest): HttpRequestResponse {
        val snapshot = WireRequest(
            method = request.method(),
            url = request.url(),
            headers = request.headers().map { it.name() to it.value() },
            body = request.body().getBytes().copyOf(),
        )
        val index = synchronized(sent) {
            val next = sent.size
            sent += snapshot
            next
        }
        return exchange(responder(snapshot, index))
    }

    private fun exchange(spec: WireResponse): HttpRequestResponse {
        val exchange = mockk<HttpRequestResponse>()
        val response = mockk<HttpResponse>()
        val body = body(spec.body)
        every { exchange.hasResponse() } returns spec.hasResponse
        if (spec.hasResponse) {
            every { exchange.response() } returns response
            every { response.statusCode() } returns spec.status
            every { response.headers() } returns spec.headers.map { (name, value) -> header(name, value) }
            every { response.body() } returns body
            every { response.bodyToString() } returns spec.body.decodeToString()
        }
        return exchange
    }

    private fun header(name: String, value: String): BurpHeader = mockk<BurpHeader>().also { header ->
        every { header.name() } returns name
        every { header.value() } returns value
    }
}
