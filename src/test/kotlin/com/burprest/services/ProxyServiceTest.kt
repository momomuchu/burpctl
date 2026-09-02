package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.message.HttpHeader as BurpHeader
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.core.ByteArray as BurpByteArray
import io.mockk.*
import kotlin.test.Test
import kotlin.test.assertEquals

class ProxyServiceTest {

    private val api = mockk<MontoyaApi>()
    private val proxy = mockk<Proxy>()
    private val service: ProxyService

    init {
        every { api.proxy() } returns proxy
        service = ProxyService(api)
    }

    private fun mockEntry(url: String, method: String = "GET", statusCode: Short = 200): ProxyHttpRequestResponse {
        val entry = mockk<ProxyHttpRequestResponse>()
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        val body = mockk<BurpByteArray>()

        every { request.url() } returns url
        every { request.method() } returns method
        every { request.headers() } returns emptyList()
        every { request.body() } returns body
        every { request.bodyToString() } returns ""
        every { body.length() } returns 0

        val respBody = mockk<BurpByteArray>()
        every { response.statusCode() } returns statusCode
        every { response.headers() } returns emptyList()
        every { response.body() } returns respBody
        every { response.bodyToString() } returns ""
        every { respBody.length() } returns 0

        every { entry.finalRequest() } returns request
        every { entry.response() } returns response

        return entry
    }

    @Test
    fun `getHistory returns all entries`() {
        val entries = listOf(
            mockEntry("https://example.com/a"),
            mockEntry("https://example.com/b"),
        )
        every { proxy.history() } returns entries

        val result = service.getHistory()
        assertEquals(2, result.total)
        assertEquals(2, result.entries.size)
        assertEquals("https://example.com/a", result.entries[0].request.url)
    }

    @Test
    fun `getHistory with limit`() {
        val entries = listOf(
            mockEntry("https://example.com/a"),
            mockEntry("https://example.com/b"),
            mockEntry("https://example.com/c"),
        )
        every { proxy.history() } returns entries

        val result = service.getHistory(limit = 2)
        assertEquals(3, result.total)
        assertEquals(2, result.entries.size)
    }

    @Test
    fun `getHistory with offset`() {
        val entries = listOf(
            mockEntry("https://example.com/a"),
            mockEntry("https://example.com/b"),
            mockEntry("https://example.com/c"),
        )
        every { proxy.history() } returns entries

        val result = service.getHistory(offset = 1)
        assertEquals(3, result.total)
        assertEquals(2, result.entries.size)
        assertEquals("https://example.com/b", result.entries[0].request.url)
    }

    @Test
    fun `getHistory with host filter`() {
        val entries = listOf(
            mockEntry("https://example.com/a"),
            mockEntry("https://other.com/b"),
            mockEntry("https://example.com/c"),
        )
        every { proxy.history() } returns entries

        val result = service.getHistory(filterHost = "example.com")
        assertEquals(2, result.total)
        assertEquals(2, result.entries.size)
        assertEquals(listOf(0, 2), result.entries.map { it.id })
    }

    @Test
    fun `getHistoryEntry returns specific entry`() {
        val entries = listOf(
            mockEntry("https://example.com/first"),
            mockEntry("https://example.com/second"),
        )
        every { proxy.history() } returns entries

        val result = service.getHistoryEntry(1)
        assertEquals("https://example.com/second", result.request.url)
    }

    @Test
    fun `enableIntercept calls proxy`() {
        every { proxy.enableIntercept() } just Runs
        service.enableIntercept()
        verify { proxy.enableIntercept() }
    }

    @Test
    fun `disableIntercept calls proxy`() {
        every { proxy.disableIntercept() } just Runs
        service.disableIntercept()
        verify { proxy.disableIntercept() }
    }
}
