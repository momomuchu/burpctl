package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.Proxy
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.HttpResponseData
import com.burprest.models.QuickFuzzRequest
import com.burprest.models.SendRequest
import com.burprest.models.SendResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class IntruderQuickFuzzPartialFailureTest {
    @Test
    fun `quick fuzz preserves partial results and continues after payload failure`() {
        val api = mockk<MontoyaApi>()
        every { api.proxy() } returns mockk<Proxy>()
        val repeater = mockk<RepeaterService>()
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            sent += request
            when (sent.size) {
                1 -> success(request, body = "baseline", statusCode = 200)
                2 -> success(request, body = "first", statusCode = 201)
                3 -> error("transport secret-token")
                else -> success(request, body = "third", statusCode = 202)
            }
        }
        val service = IntruderService(api, repeater)

        val response = service.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData("GET", "https://example.test/?q=original"),
                param = "q",
                payloads = listOf("one", "two", "three"),
            ),
        )

        assertEquals(
            listOf(
                "https://example.test/?q=original",
                "https://example.test/?q=one",
                "https://example.test/?q=two",
                "https://example.test/?q=three",
            ),
            sent.map { it.url },
        )
        verify(exactly = 4) { repeater.send(any()) }
        assertEquals(3, response.total)
        assertEquals(listOf("one", "two", "three"), response.results.map { it.payload })
        assertEquals(200, response.baseline?.statusCode)
        assertEquals(8, response.baseline?.length)
        assertNull(response.baseline?.errorCode)

        val first = response.results[0]
        assertEquals(201, first.statusCode)
        assertEquals(5, first.length)
        assertEquals("first", first.bodyPreview)
        assertNull(first.errorCode)

        val second = response.results[1]
        assertEquals(0, second.statusCode)
        assertEquals(0, second.length)
        assertEquals("SEND_FAILED", second.errorCode)
        assertFalse(second.anomalous)
        assertFalse(second.error.orEmpty().contains("secret-token"))

        val third = response.results[2]
        assertEquals(202, third.statusCode)
        assertEquals(5, third.length)
        assertEquals("third", third.bodyPreview)
        assertNull(third.errorCode)
        assertFalse(response.results.any { it.error.orEmpty().contains("secret-token") })
        assertFalse(response.baseline?.error.orEmpty().contains("secret-token"))
    }

    private fun success(
        request: HttpRequestData,
        body: String,
        statusCode: Int,
    ): SendResponse = SendResponse(
        request = request,
        response = HttpResponseData(
            statusCode = statusCode,
            headers = listOf(HttpHeader("Content-Type", "text/plain")),
            body = body,
        ),
        durationMs = 1,
    )
}
