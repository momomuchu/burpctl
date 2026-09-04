package com.burprest.services

import burp.api.montoya.MontoyaApi
import com.burprest.models.CreateAttackRequest
import com.burprest.models.HttpRequestData
import com.burprest.models.HttpResponseData
import com.burprest.models.PayloadPosition
import com.burprest.models.QuickFuzzRequest
import com.burprest.models.SendRequest
import com.burprest.models.SendResponse
import io.mockk.every
import io.mockk.mockk
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class IntruderBinaryBodyTest {
    private val api = mockk<MontoyaApi>()
    private val repeater = mockk<RepeaterService>()

    @Test
    fun `createAttack uses Base64 body bytes as the canonical mutation source`() {
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            firstArg<SendRequest>().request!!.also(sent::add).let(::success)
        }
        val service = IntruderService(api, repeater)
        val request = HttpRequestData(
            method = "POST",
            url = "https://example.test/submit",
            bodyBase64 = Base64.getEncoder().encodeToString("value".encodeToByteArray()),
        )
        val raw = rawBytes(request)
        val start = raw.indexOf("value".encodeToByteArray())

        val creation = runCatching {
            service.createAttack(
                CreateAttackRequest(
                    request = request,
                    positions = listOf(PayloadPosition(start, start + 5, "body")),
                    payloads = mapOf("body" to listOf("mutated")),
                )
            )
        }
        assertTrue(
            creation.isSuccess,
            "createAttack discarded bodyBase64 from its canonical bytes: ${creation.exceptionOrNull()}",
        )
        val attack = creation.getOrThrow()
        service.startAttack(attack.attackId)
        awaitCompleted(service, attack.attackId)

        assertEquals(
            "mutated",
            Base64.getDecoder().decode(assertNotNull(sent.single().bodyBase64)).toString(UTF_8),
        )
    }

    @Test
    fun `query attack preserves unrelated arbitrary body bytes`() {
        val rawBody = byteArrayOf(0xff.toByte(), 0, 0x41)
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            firstArg<SendRequest>().request!!.also(sent::add).let(::success)
        }
        val service = IntruderService(api, repeater)
        val request = HttpRequestData(
            method = "POST",
            url = "https://example.test/submit?q=old",
            bodyBase64 = Base64.getEncoder().encodeToString(rawBody),
        )
        val raw = rawBytes(request)
        val start = raw.indexOf("old".encodeToByteArray())

        val attack = service.createAttack(
            CreateAttackRequest(
                request = request,
                positions = listOf(PayloadPosition(start, start + 3, "query")),
                payloads = mapOf("query" to listOf("new")),
            )
        )
        service.startAttack(attack.attackId)
        awaitCompleted(service, attack.attackId)

        val treatment = sent.single()
        assertEquals("https://example.test/submit?q=new", treatment.url)
        assertContentEquals(rawBody, Base64.getDecoder().decode(assertNotNull(treatment.bodyBase64)))
    }

    @Test
    fun `requestId query attack preserves unrelated arbitrary body bytes`() {
        val rawBody = byteArrayOf(0xff.toByte(), 0, 0x42)
        val rawRequest = "POST /submit?q=old HTTP/1.1\r\nHost: example.test\r\n\r\n".encodeToByteArray() + rawBody
        val historical = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
        val historyEntry = mockk<burp.api.montoya.proxy.ProxyHttpRequestResponse>()
        val proxy = mockk<burp.api.montoya.proxy.Proxy>()
        val bytes = mockk<burp.api.montoya.core.ByteArray>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(historyEntry)
        every { historyEntry.finalRequest() } returns historical
        every { historical.toByteArray() } returns bytes
        every { bytes.length() } returns rawRequest.size
        every { bytes.getByte(any()) } answers { rawRequest[firstArg<Int>()] }
        every { historical.url() } returns "https://example.test/submit?q=old"
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            firstArg<SendRequest>().request!!.also(sent::add).let(::success)
        }
        val service = IntruderService(api, repeater)
        val start = rawRequest.indexOf("old".encodeToByteArray())

        val creation = runCatching {
            service.createAttack(
                CreateAttackRequest(
                    requestId = 0,
                    positions = listOf(PayloadPosition(start, start + 3, "query")),
                    payloads = mapOf("query" to listOf("new")),
                )
            )
        }
        assertTrue(
            creation.isSuccess,
            "unrelated binary body prevented a query-only attack: ${creation.exceptionOrNull()}",
        )
        val attack = creation.getOrThrow()
        service.startAttack(attack.attackId)
        awaitCompleted(service, attack.attackId)

        val treatment = sent.single()
        assertEquals("https://example.test/submit?q=new", treatment.url)
        assertContentEquals(rawBody, Base64.getDecoder().decode(assertNotNull(treatment.bodyBase64)))
    }

    @Test
    fun `quick fuzz requestId projection preserves exact arbitrary body bytes`() {
        val rawBody = byteArrayOf(0xff.toByte(), 0, 0x43)
        val historical = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
        val historyEntry = mockk<burp.api.montoya.proxy.ProxyHttpRequestResponse>()
        val proxy = mockk<burp.api.montoya.proxy.Proxy>()
        val body = mockk<burp.api.montoya.core.ByteArray>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(historyEntry)
        every { historyEntry.finalRequest() } returns historical
        every { historical.method() } returns "POST"
        every { historical.url() } returns "https://example.test/submit?q=old"
        every { historical.headers() } returns emptyList()
        every { historical.body() } returns body
        every { body.length() } returns rawBody.size
        every { body.getBytes() } returns rawBody
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            firstArg<SendRequest>().request!!.also(sent::add).let(::success)
        }
        val service = IntruderService(api, repeater)

        service.quickFuzz(
            QuickFuzzRequest(requestId = 0, param = "q", payloads = listOf("new")),
        )

        assertEquals(2, sent.size)
        sent.forEach { request ->
            assertContentEquals(rawBody, Base64.getDecoder().decode(assertNotNull(request.bodyBase64)))
        }
        assertEquals("https://example.test/submit?q=new", sent.last().url)
    }

    @Test
    fun `invalid Base64 is rejected before attack or quick fuzz sends`() {
        val malformed = HttpRequestData(
            method = "POST",
            url = "https://example.test/submit",
            bodyBase64 = "%%%not-base64%%%",
        )
        val service = IntruderService(api, repeater)

        val attackFailure = kotlin.test.assertFailsWith<IllegalArgumentException> {
            service.createAttack(
                CreateAttackRequest(
                    request = malformed,
                    positions = listOf(PayloadPosition(0, 1, "body")),
                    payloads = mapOf("body" to listOf("x")),
                )
            )
        }
        val quickFailure = kotlin.test.assertFailsWith<IllegalArgumentException> {
            service.quickFuzz(
                QuickFuzzRequest(request = malformed, param = "q", payloads = listOf("x")),
            )
        }

        assertTrue(attackFailure.message.orEmpty().contains("bodyBase64"))
        assertTrue(quickFailure.message.orEmpty().contains("bodyBase64"))
    }

    @Test
    fun `quick fuzz mutates a Base64 body and sends internally consistent bytes`() {
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            sent += request
            success(request)
        }
        val service = IntruderService(api, repeater)
        val original = "q=original".encodeToByteArray()
        val base = HttpRequestData(
            method = "POST",
            url = "https://example.test/fuzz",
            bodyBase64 = Base64.getEncoder().encodeToString(original),
        )

        service.quickFuzz(
            QuickFuzzRequest(request = base, param = "q", payloads = listOf("mutated")),
        )

        // The baseline is an observation, not a mutation; preserving it exactly avoids inventing a
        // text projection the caller did not send. The treatment changes both fields together.
        assertEquals(base, sent.first())
        assertEquals(2, sent.size, sent.toString())
        val treatment = sent.last()
        assertEquals("q=mutated", treatment.body)
        assertEquals(
            "q=mutated",
            Base64.getDecoder().decode(assertNotNull(treatment.bodyBase64)).toString(UTF_8),
        )
    }

    private fun rawBytes(request: HttpRequestData): ByteArray {
        val uri = java.net.URI(request.url)
        val target = uri.rawPath.ifEmpty { "/" } + (uri.rawQuery?.let { "?$it" } ?: "")
        val head = "${request.method} $target HTTP/1.1\r\nHost: ${uri.rawAuthority}\r\n\r\n"
        return head.toByteArray(UTF_8) + (request.bodyBytes() ?: byteArrayOf())
    }

    private fun success(request: HttpRequestData): SendResponse = SendResponse(
        request = request,
        response = HttpResponseData(200, emptyList(), "ok"),
        durationMs = 1,
    )

    private fun awaitCompleted(service: IntruderService, id: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (service.attackStatus(id).status == "completed") return
            Thread.onSpinWait()
        }
        assertEquals("completed", service.attackStatus(id).status)
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        for (start in 0..size - needle.size) {
            if (needle.indices.all { this[start + it] == needle[it] }) return start
        }
        return -1
    }
}
