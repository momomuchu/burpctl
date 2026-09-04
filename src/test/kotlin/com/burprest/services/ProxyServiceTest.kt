package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import com.burprest.server.InvalidParamException
import com.burprest.server.NotFoundException
import com.burprest.server.ServiceUnavailableException
import com.burprest.server.UnsupportedException
import io.mockk.*
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
        val capturedAt = ZonedDateTime.of(2026, 1, 2, 3, 4, 5, 0, ZoneOffset.UTC)

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
        every { entry.host() } returns runCatching { java.net.URL(url).host }.getOrDefault("")
        every { entry.time() } returns capturedAt
        every { entry.listenerPort() } returns 8080

        return entry
    }

    @Test
    fun `history skips one malformed stored request and preserves valid absolute IDs`() {
        val malformedEntry = mockk<ProxyHttpRequestResponse>()
        val malformedRequest = mockk<HttpRequest>()
        val malformedBody = mockk<BurpByteArray>()
        every { malformedEntry.finalRequest() } returns malformedRequest
        every { malformedEntry.response() } returns null
        every { malformedEntry.host() } returns "example.com"
        every { malformedRequest.body() } returns malformedBody
        every { malformedBody.length() } returns 0
        every { malformedRequest.method() } throws MalformedRequestException("stored bytes are malformed")
        every { proxy.history() } returns listOf(
            malformedEntry,
            mockEntry("https://example.com/valid"),
        )

        val result = service.getHistory()

        assertEquals(1, result.total)
        assertEquals(1, result.entries.single().id)
        assertEquals("https://example.com/valid", result.entries.single().request.url)
    }

    @Test
    fun `direct malformed history entry returns a typed operational failure`() {
        val malformedEntry = mockk<ProxyHttpRequestResponse>()
        val malformedRequest = mockk<HttpRequest>()
        val body = mockk<BurpByteArray>()
        every { proxy.history() } returns listOf(malformedEntry)
        every { malformedEntry.finalRequest() } returns malformedRequest
        every { malformedEntry.response() } returns null
        every { malformedRequest.body() } returns body
        every { body.length() } returns 0
        every { malformedRequest.method() } throws MalformedRequestException("stored bytes are malformed")

        assertFailsWith<ServiceUnavailableException> { service.getHistoryEntry(0) }
    }

    @Test
    fun `history pagination retains absolute IDs`() {
        every { proxy.history() } returns listOf(
            mockEntry("https://example.com/a"),
            mockEntry("https://example.com/b"),
            mockEntry("https://example.com/c"),
        )

        val result = service.getHistory(limit = 1, offset = 1)

        assertEquals(3, result.total)
        assertEquals(listOf(1), result.entries.map { it.id })
        assertEquals("https://example.com/b", result.entries.single().request.url)
    }

    @Test
    fun `pagination cannot overflow`() {
        every { proxy.history() } returns listOf(mockEntry("https://example.com/a"))

        val result = service.getHistory(limit = Int.MAX_VALUE, offset = Int.MAX_VALUE)

        assertEquals(1, result.total)
        assertTrue(result.entries.isEmpty())
    }

    @Test
    fun `invalid bounds are rejected before reading Montoya`() {
        assertFailsWith<InvalidParamException> { service.getHistory(limit = 0) }
        assertFailsWith<InvalidParamException> { service.getHistory(offset = -1) }
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `host filter is exact rather than a URL substring`() {
        every { proxy.history() } returns listOf(
            mockEntry("https://example.com/a?next=https://other.example"),
            mockEntry("https://example.com.evil/b"),
            mockEntry("https://user@example.com@evil.example/c"),
            mockEntry("https://EXAMPLE.COM./d"),
        )

        val result = service.getHistory(filterHost = "example.com")

        assertEquals(2, result.total)
        assertEquals(listOf(0, 3), result.entries.map { it.id })
    }

    @Test
    fun `host filter normalizes Unicode IDN and keeps absolute IDs`() {
        every { proxy.history() } returns listOf(
            mockEntry("https://other.example/"),
            mockEntry("https://xn--bcher-kva.example/a"),
            mockEntry("https://bücher.example/b"),
        )

        val result = service.getHistory(filterHost = "BÜCHER.EXAMPLE.")

        assertEquals(2, result.total)
        assertEquals(listOf(1, 2), result.entries.map { it.id })
    }

    @Test
    fun `host filter normalizes bracketed and expanded IPv6 literals`() {
        every { proxy.history() } returns listOf(
            mockEntry("https://[2001:db8::1]/a"),
            mockEntry("https://[2001:db8::2]/b"),
        )

        val result = service.getHistory(filterHost = "[2001:0DB8:0:0:0:0:0:1]")

        assertEquals(1, result.total)
        assertEquals(0, result.entries.single().id)
    }

    @Test
    fun `blank or URL-shaped host filters fail before history read`() {
        assertFailsWith<InvalidParamException> { service.getHistory(filterHost = " ") }
        assertFailsWith<InvalidParamException> { service.getHistory(filterHost = "https://example.com") }
        assertFailsWith<InvalidParamException> { service.getHistory(filterHost = "[example.com]") }
        assertFailsWith<InvalidParamException> { service.getHistory(filterHost = "[fe80::1%25en0]") }
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `history entry rejects negative ID before reading Montoya`() {
        assertFailsWith<InvalidParamException> { service.getHistoryEntry(-1) }
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `history entry uses absolute index and missing index is not found`() {
        every { proxy.history() } returns listOf(mockEntry("https://example.com/first"))

        assertEquals("https://example.com/first", service.getHistoryEntry(0).request.url)
        assertFailsWith<NotFoundException> { service.getHistoryEntry(1) }
    }

    @Test
    fun `intercept status always comes from Montoya`() {
        every { proxy.isInterceptEnabled() } returnsMany listOf(true, false)

        assertTrue(service.isIntercepting())
        assertFalse(service.isIntercepting())
        verify(exactly = 2) { proxy.isInterceptEnabled() }
    }

    @Test
    fun `enable and disable return authoritative Montoya state`() {
        every { proxy.enableIntercept() } just Runs
        every { proxy.disableIntercept() } just Runs
        every { proxy.isInterceptEnabled() } returnsMany listOf(false, true)

        assertFalse(service.enableIntercept())
        assertTrue(service.disableIntercept())
        verifyOrder {
            proxy.enableIntercept()
            proxy.isInterceptEnabled()
            proxy.disableIntercept()
            proxy.isInterceptEnabled()
        }
    }

    @Test
    fun `forward and drop are explicit unsupported operations with no Montoya effects`() {
        assertFailsWith<UnsupportedException> { service.forwardInterceptedMessage() }
        assertFailsWith<UnsupportedException> { service.dropInterceptedMessage() }
        verify(exactly = 0) { api.proxy() }
    }

    @Test
    fun `websocket history preserves compatibility rows plus stable socket metadata and binary bytes`() {
        val first = mockk<ProxyWebSocketMessage>()
        val second = mockk<ProxyWebSocketMessage>()
        val upgrade = mockk<HttpRequest>()
        val firstPayload = mockk<BurpByteArray>()
        val firstEditedPayload = mockk<BurpByteArray>()
        val secondPayload = mockk<BurpByteArray>()
        val secondEditedPayload = mockk<BurpByteArray>()
        val firstTime = ZonedDateTime.of(2025, 12, 31, 23, 59, 58, 0, ZoneOffset.UTC)
        val secondTime = firstTime.plusSeconds(1)
        val originalBytes = byteArrayOf(0, 1, 0x7f, 0x80.toByte(), 0xff.toByte())
        val editedBytes = byteArrayOf(0x41, 0, 0x42)

        every { proxy.webSocketHistory() } returns listOf(first, second)
        every { upgrade.url() } returns "wss://example.com/socket"
        listOf(first, second).forEach { message ->
            every { message.webSocketId() } returns 8123
            every { message.upgradeRequest() } returns upgrade
            every { message.listenerPort() } returns 8443
        }
        every { first.direction() } returns burp.api.montoya.websocket.Direction.CLIENT_TO_SERVER
        every { first.payload() } returns firstPayload
        every { firstPayload.getBytes() } returns originalBytes
        every { firstPayload.toString() } returns "legacy first"
        every { first.editedPayload() } returns firstEditedPayload
        every { firstEditedPayload.getBytes() } returns editedBytes
        every { first.time() } returns firstTime
        every { second.direction() } returns burp.api.montoya.websocket.Direction.SERVER_TO_CLIENT
        every { second.payload() } returns secondPayload
        every { secondPayload.getBytes() } returns byteArrayOf(0x43)
        every { secondPayload.toString() } returns "legacy second"
        every { second.editedPayload() } returns secondEditedPayload
        every { secondEditedPayload.getBytes() } returns byteArrayOf(0x44)
        every { second.time() } returns secondTime

        val entries = service.getWebSocketHistory().entries
        val entry = entries.first()

        assertEquals(listOf(0, 1), entries.map { it.id })
        assertEquals(listOf(8123, 8123), entries.map { it.webSocketId })
        assertEquals(firstTime.toString(), entry.timestamp)
        assertEquals(firstTime.toString(), entry.time)
        assertEquals(8443, entry.listenerPort)
        assertEquals("legacy first", entry.payload)
        assertEquals(Base64.getEncoder().encodeToString(originalBytes), entry.payloadBase64)
        assertEquals(Base64.getEncoder().encodeToString(editedBytes), entry.editedPayloadBase64)
    }

    @Test
    fun `websocket history preserves an unedited message with explicit edited payload absence`() {
        val message = mockk<ProxyWebSocketMessage>()
        val upgrade = mockk<HttpRequest>()
        val payload = mockk<BurpByteArray>()
        val capturedAt = ZonedDateTime.of(2026, 2, 3, 4, 5, 6, 0, ZoneOffset.UTC)

        every { proxy.webSocketHistory() } returns listOf(message)
        every { message.webSocketId() } returns 91
        every { message.upgradeRequest() } returns upgrade
        every { upgrade.url() } returns "wss://example.com/unedited"
        every { message.direction() } returns burp.api.montoya.websocket.Direction.SERVER_TO_CLIENT
        every { message.payload() } returns payload
        every { payload.getBytes() } returns byteArrayOf(0x45)
        every { payload.toString() } returns "legacy unedited"
        every { message.editedPayload() } returns null
        every { message.time() } returns capturedAt
        every { message.listenerPort() } returns 9443

        val result = service.getWebSocketHistory()

        assertEquals(1, result.total)
        assertEquals("legacy unedited", result.entries.single().payload)
        assertNull(result.entries.single().editedPayloadBase64)
    }

    @Test
    fun `websocket history keeps a row when Montoya platform references are absent`() {
        val message = mockk<ProxyWebSocketMessage>()

        every { proxy.webSocketHistory() } returns listOf(message)
        every { message.webSocketId() } returns 92
        every { message.upgradeRequest() } returns null
        every { message.direction() } returns null
        every { message.payload() } returns null
        every { message.editedPayload() } returns null
        every { message.time() } returns null
        every { message.listenerPort() } returns 9443

        val result = service.getWebSocketHistory()
        val entry = result.entries.single()

        assertEquals(1, result.total)
        assertNull(entry.url)
        assertNull(entry.direction)
        assertNull(entry.payload)
        assertNull(entry.payloadBase64)
        assertNull(entry.editedPayloadBase64)
        assertNull(entry.timestamp)
        assertNull(entry.time)
    }
}
