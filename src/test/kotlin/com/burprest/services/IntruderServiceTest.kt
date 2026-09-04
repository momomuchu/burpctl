package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.burprest.models.AttackOptions
import com.burprest.models.CreateAttackRequest
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.HttpResponseData
import com.burprest.models.PayloadPosition
import com.burprest.models.QuickFuzzRequest
import com.burprest.models.SendRequest
import com.burprest.models.SendResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IntruderServiceTest {
    private val api = mockk<MontoyaApi>()
    private val proxy = mockk<Proxy>()
    private val repeater = mockk<RepeaterService>()

    init {
        every { api.proxy() } returns proxy
    }

    @Test
    fun `create rejects unsupported attack modes and invalid options before effects`() {
        val service = IntruderService(api, repeater)
        val base = validPlan()
        val invalid = listOf(
            base.copy(attackType = "battering-ram"),
            base.copy(attackType = "pitchfork"),
            base.copy(attackType = "cluster-bomb"),
            base.copy(attackType = "unknown"),
            base.copy(options = AttackOptions(followRedirects = false)),
            base.copy(options = AttackOptions(maxRetries = 1)),
            base.copy(options = AttackOptions(throttleMs = -1)),
            base.copy(options = AttackOptions(throttleMs = 60_001)),
        )

        invalid.forEach { request ->
            assertFailsWith<IllegalArgumentException> { service.createAttack(request) }
        }

        verify(exactly = 0) { repeater.send(any()) }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `create requires exactly one request source and complete payload bindings`() {
        val service = IntruderService(api, repeater)
        val base = validPlan()
        val invalid = listOf(
            base.copy(request = null, requestId = null),
            base.copy(requestId = 0),
            base.copy(positions = emptyList()),
            base.copy(payloads = emptyMap()),
            base.copy(positions = listOf(base.positions.single().copy(name = ""))),
            base.copy(payloads = mapOf("body" to emptyList())),
            base.copy(payloads = mapOf("other" to listOf("x"))),
            base.copy(payloads = base.payloads + ("unused" to listOf("x"))),
        )

        invalid.forEach { request ->
            assertFailsWith<IllegalArgumentException> { service.createAttack(request) }
        }

        verify(exactly = 0) { repeater.send(any()) }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `create rejects duplicate overlapping and out of range byte positions`() {
        val service = IntruderService(api, repeater)
        val request = inlineRequest(body = "abcdef")
        val raw = rawBytes(request)
        val bodyStart = raw.indexOf("abcdef".toByteArray(UTF_8))
        val validPayloads = mapOf("a" to listOf("x"), "b" to listOf("y"))
        val invalidPositions = listOf(
            listOf(PayloadPosition(-1, 1, "a")),
            listOf(PayloadPosition(1, 1, "a")),
            listOf(PayloadPosition(2, 1, "a")),
            listOf(PayloadPosition(0, raw.size + 1, "a")),
            listOf(
                PayloadPosition(bodyStart, bodyStart + 2, "a"),
                PayloadPosition(bodyStart, bodyStart + 2, "b"),
            ),
            listOf(
                PayloadPosition(bodyStart, bodyStart + 3, "a"),
                PayloadPosition(bodyStart + 2, bodyStart + 4, "b"),
            ),
        )

        invalidPositions.forEach { positions ->
            assertFailsWith<IllegalArgumentException> {
                service.createAttack(
                    CreateAttackRequest(
                        request = request,
                        positions = positions,
                        payloads = validPayloads.filterKeys { key -> positions.any { it.name == key } },
                    ),
                )
            }
        }

        verify(exactly = 0) { repeater.send(any()) }
    }

    @Test
    fun `create rejects raw-only changes the structured Repeater bridge cannot preserve`() {
        val service = IntruderService(api, repeater)
        val request = inlineRequest()
        val raw = rawBytes(request)
        val start = raw.indexOf("HTTP/1.1".toByteArray(UTF_8))

        val error = assertFailsWith<IllegalArgumentException> {
            service.createAttack(
                CreateAttackRequest(
                    request = request,
                    positions = listOf(PayloadPosition(start, start + 8, "version")),
                    payloads = mapOf("version" to listOf("HTTP/2.0")),
                ),
            )
        }

        assertTrue(error.message.orEmpty().contains("cannot represent"))
        verify(exactly = 0) { repeater.send(any()) }
    }

    @Test
    fun `create preflights the bounded shot cardinality before insertion or send`() {
        val service = IntruderService(api, repeater)
        val request = inlineRequest(body = "ab")
        val bodyStart = rawBytes(request).indexOf("ab".toByteArray(UTF_8))

        val error = assertFailsWith<IllegalArgumentException> {
            service.createAttack(
                CreateAttackRequest(
                    request = request,
                    positions = listOf(
                        PayloadPosition(bodyStart, bodyStart + 1, "a"),
                        PayloadPosition(bodyStart + 1, bodyStart + 2, "b"),
                    ),
                    payloads = mapOf(
                        "a" to Collections.nCopies(5_001, "x"),
                        "b" to Collections.nCopies(5_000, "y"),
                    ),
                ),
            )
        }

        assertTrue(error.message.orEmpty().contains("10,000"))
        verify(exactly = 0) { repeater.send(any()) }
    }

    @Test
    fun `sniper uses UTF-8 byte offsets and every positions named payload list`() {
        val sent = Collections.synchronizedList(mutableListOf<HttpRequestData>())
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            sent += request
            success(request)
        }
        val service = IntruderService(api, repeater)
        val request = inlineRequest(body = "α=old&β=end")
        val raw = rawBytes(request)
        val oldStart = raw.indexOf("old".toByteArray(UTF_8))
        val endStart = raw.indexOf("end".toByteArray(UTF_8))
        val created = service.createAttack(
            CreateAttackRequest(
                request = request,
                positions = listOf(
                    PayloadPosition(oldStart, oldStart + 3, "first"),
                    PayloadPosition(endStart, endStart + 3, "second"),
                ),
                payloads = linkedMapOf(
                    "first" to listOf("✓", "long"),
                    "second" to listOf("1", "22", "333"),
                ),
            ),
        )

        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")

        assertEquals(
            listOf(
                "α=✓&β=end",
                "α=long&β=end",
                "α=old&β=1",
                "α=old&β=22",
                "α=old&β=333",
            ),
            sent.map { it.body },
        )
        assertEquals(5, service.attackResults(created.attackId).total)
        assertEquals(5, service.attackStatus(created.attackId).requestCount)
        assertEquals(100, service.attackStatus(created.attackId).progress)
    }

    @Test
    fun `body substitution repairs duplicate content length using payload byte count`() {
        val request = HttpRequestData(
            method = "POST",
            url = "https://example.test/submit",
            headers = listOf(
                HttpHeader("Content-Length", "2"),
                HttpHeader("content-length", "999"),
            ),
            body = "é",
        )
        val raw = rawBytes(request)
        val start = raw.size - "é".toByteArray(UTF_8).size
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            val concrete = firstArg<SendRequest>().request!!
            sent += concrete
            success(concrete)
        }
        val service = IntruderService(api, repeater)
        val created = service.createAttack(
            CreateAttackRequest(
                request = request,
                positions = listOf(PayloadPosition(start, raw.size, "body")),
                payloads = mapOf("body" to listOf("✓x")),
            ),
        )

        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")

        assertEquals("✓x", sent.single().body)
        val lengths = sent.single().headers.filter { it.name.equals("Content-Length", ignoreCase = true) }
        assertEquals(listOf("4"), lengths.map { it.value })
    }

    @Test
    fun `requestId positions apply to the exact captured raw UTF-8 bytes`() {
        val raw = (
            "POST /captured?q=old HTTP/1.1\r\n" +
                "Host: history.example.test\r\n" +
                "X-Unicode: α\r\n\r\n" +
                "body=old"
            ).toByteArray(UTF_8)
        val historical = mockHistoryRequest(raw, "https://history.example.test/captured?q=old")
        val entry = mockk<ProxyHttpRequestResponse>()
        every { entry.finalRequest() } returns historical
        every { proxy.history() } returns listOf(entry)
        val sent = mutableListOf<HttpRequestData>()
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            sent += request
            success(request)
        }
        val service = IntruderService(api, repeater)
        val bodyStart = raw.lastIndexOf("old".toByteArray(UTF_8))
        val created = service.createAttack(
            CreateAttackRequest(
                requestId = 0,
                positions = listOf(PayloadPosition(bodyStart, bodyStart + 3, "body")),
                payloads = mapOf("body" to listOf("✓")),
            ),
        )

        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")

        assertEquals("body=✓", sent.single().body)
        assertEquals("https://history.example.test/captured?q=old", sent.single().url)
        verify(exactly = 1) { proxy.history() }
    }

    @Test
    fun `positions may touch both raw request edges`() {
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            success(request)
        }
        val service = IntruderService(api, repeater)
        val request = inlineRequest(method = "GET", body = "tail")
        val raw = rawBytes(request)
        val created = service.createAttack(
            CreateAttackRequest(
                request = request,
                positions = listOf(
                    PayloadPosition(0, 3, "method"),
                    PayloadPosition(raw.size - 4, raw.size, "tail"),
                ),
                payloads = linkedMapOf(
                    "method" to listOf("PUT"),
                    "tail" to listOf("done"),
                ),
            ),
        )

        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")

        val results = service.attackResults(created.attackId)
        assertEquals(2, results.total)
        verify(exactly = 1) {
            repeater.send(match { it.request?.method == "PUT" && it.request?.body == "tail" })
        }
        verify(exactly = 1) {
            repeater.send(match { it.request?.method == "GET" && it.request?.body == "done" })
        }
    }

    @Test
    fun `only one worker can start and terminal attacks cannot restart`() {
        val enteredSend = CountDownLatch(1)
        val releaseSend = CountDownLatch(1)
        val calls = AtomicInteger()
        every { repeater.send(any()) } answers {
            calls.incrementAndGet()
            enteredSend.countDown()
            assertTrue(releaseSend.await(2, TimeUnit.SECONDS))
            val request = firstArg<SendRequest>().request!!
            success(request)
        }
        val service = IntruderService(api, repeater)
        val created = service.createAttack(validPlan(payloads = listOf("one")))

        assertEquals("running", service.startAttack(created.attackId).status)
        assertTrue(enteredSend.await(2, TimeUnit.SECONDS))
        assertFailsWith<IllegalArgumentException> { service.startAttack(created.attackId) }
        releaseSend.countDown()
        awaitStatus(service, created.attackId, "completed")

        assertEquals(1, calls.get())
        assertFailsWith<IllegalArgumentException> { service.startAttack(created.attackId) }
        assertFailsWith<IllegalArgumentException> { service.resumeAttack(created.attackId) }
        assertFailsWith<IllegalArgumentException> { service.pauseAttack(created.attackId) }
    }

    @Test
    fun `pause resume and stop are legal atomic transitions without duplicate sends`() {
        val firstEntered = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val secondEntered = CountDownLatch(1)
        val releaseSecond = CountDownLatch(1)
        val calls = AtomicInteger()
        every { repeater.send(any()) } answers {
            val number = calls.incrementAndGet()
            val request = firstArg<SendRequest>().request!!
            if (number == 1) {
                firstEntered.countDown()
                assertTrue(releaseFirst.await(2, TimeUnit.SECONDS))
            } else {
                secondEntered.countDown()
                assertTrue(releaseSecond.await(2, TimeUnit.SECONDS))
            }
            success(request)
        }
        val service = IntruderService(api, repeater)
        val created = service.createAttack(validPlan(payloads = listOf("one", "two")))

        assertFailsWith<IllegalArgumentException> { service.pauseAttack(created.attackId) }
        assertFailsWith<IllegalArgumentException> { service.resumeAttack(created.attackId) }
        assertFailsWith<IllegalArgumentException> { service.stopAttack(created.attackId) }
        service.startAttack(created.attackId)
        assertTrue(firstEntered.await(2, TimeUnit.SECONDS))
        assertEquals("paused", service.pauseAttack(created.attackId).status)
        releaseFirst.countDown()
        awaitResultCount(service, created.attackId, 1)
        assertFalse(secondEntered.await(100, TimeUnit.MILLISECONDS))

        assertEquals("running", service.resumeAttack(created.attackId).status)
        assertTrue(secondEntered.await(2, TimeUnit.SECONDS))
        releaseSecond.countDown()
        awaitStatus(service, created.attackId, "completed")
        assertEquals(2, calls.get())
    }

    @Test
    fun `pause during the final in-flight send requires resume before completion`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        every { repeater.send(any()) } answers {
            entered.countDown()
            assertTrue(release.await(2, TimeUnit.SECONDS))
            success(firstArg<SendRequest>().request!!)
        }
        val service = IntruderService(api, repeater)
        val created = service.createAttack(validPlan(payloads = listOf("one")))

        service.startAttack(created.attackId)
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        assertEquals("paused", service.pauseAttack(created.attackId).status)
        release.countDown()
        awaitResultCount(service, created.attackId, 1)
        assertEquals("paused", service.attackStatus(created.attackId).status)
        assertFalse(service.attackStatus(created.attackId).isComplete)

        service.resumeAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")
    }

    @Test
    fun `stop wakes a worker paused in throttle and quarantines terminal state`() {
        val firstEntered = CountDownLatch(1)
        val secondEntered = CountDownLatch(1)
        val calls = AtomicInteger()
        every { repeater.send(any()) } answers {
            val number = calls.incrementAndGet()
            if (number == 1) firstEntered.countDown() else secondEntered.countDown()
            success(firstArg<SendRequest>().request!!)
        }
        val service = IntruderService(api, repeater)
        val plan = validPlan(payloads = listOf("one", "two")).copy(
            options = AttackOptions(throttleMs = 60_000),
        )
        val created = service.createAttack(plan)

        service.startAttack(created.attackId)
        assertTrue(firstEntered.await(2, TimeUnit.SECONDS))
        awaitResultCount(service, created.attackId, 1)
        assertEquals("stopped", service.stopAttack(created.attackId).status)

        assertFalse(secondEntered.await(100, TimeUnit.MILLISECONDS))
        assertEquals(1, calls.get())
        assertFailsWith<IllegalArgumentException> { service.startAttack(created.attackId) }
        assertFailsWith<IllegalArgumentException> { service.resumeAttack(created.attackId) }
    }

    @Test
    fun `results pagination is overflow safe and snapshots do not change`() {
        every { repeater.send(any()) } answers { success(firstArg<SendRequest>().request!!) }
        val service = IntruderService(api, repeater)
        val created = service.createAttack(validPlan(payloads = listOf("a", "b", "c")))
        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")

        val snapshot = service.attackResults(created.attackId, offset = 1, limit = Int.MAX_VALUE)
        assertEquals(listOf("b", "c"), snapshot.results.map { it.payload })
        assertEquals(emptyList(), service.attackResults(created.attackId, Int.MAX_VALUE, Int.MAX_VALUE).results)
        assertFailsWith<IllegalArgumentException> { service.attackResults(created.attackId, -1, 1) }
        assertFailsWith<IllegalArgumentException> { service.attackResults(created.attackId, 0, -1) }
        assertEquals(listOf("b", "c"), snapshot.results.map { it.payload })
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (snapshot.results as MutableList).clear()
        }
    }

    @Test
    fun `unexpected worker failure enters a sanitized terminal error state`() {
        every { repeater.send(any()) } throws AssertionError("internal secret value")
        val service = IntruderService(api, repeater)
        val created = service.createAttack(validPlan())

        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "error")

        val status = service.attackStatus(created.attackId)
        assertTrue(status.isComplete)
        assertEquals("ATTACK_FAILED", status.errorCode)
        assertFalse(status.error.orEmpty().contains("secret"))
        assertFailsWith<IllegalArgumentException> { service.startAttack(created.attackId) }
    }

    @Test
    fun `async send failures are counted and sanitized with a stable error code`() {
        every { repeater.send(any()) } throws IllegalStateException("Authorization: secret-token")
        val service = IntruderService(api, repeater)
        val created = service.createAttack(validPlan())

        service.startAttack(created.attackId)
        awaitStatus(service, created.attackId, "completed")

        val status = service.attackStatus(created.attackId)
        val result = service.attackResults(created.attackId).results.single()
        assertEquals(1, status.requestCount)
        assertEquals(1, status.errorCount)
        assertEquals("SEND_FAILED", result.errorCode)
        assertFalse(result.error.orEmpty().contains("secret-token"))
        assertFalse(result.anomalous)
    }

    @Test
    fun `quick fuzz preflights its full bounded plan before baseline effects`() {
        val service = IntruderService(api, repeater)
        val base = QuickFuzzRequest(
            request = HttpRequestData("GET", "https://example.test/?q=original"),
            param = "q",
            payloads = listOf("one"),
        )
        val invalid = listOf(
            base.copy(request = null),
            base.copy(requestId = 0),
            base.copy(param = " "),
            base.copy(payloads = emptyList()),
            base.copy(payloads = Collections.nCopies(10_001, "x")),
            base.copy(options = AttackOptions(followRedirects = false)),
            base.copy(options = AttackOptions(maxRetries = 1)),
            base.copy(options = AttackOptions(throttleMs = -1)),
        )

        invalid.forEach { request ->
            assertFailsWith<IllegalArgumentException> { service.quickFuzz(request) }
        }

        verify(exactly = 0) { repeater.send(any()) }
        verify(exactly = 0) { proxy.history() }
    }

    @Test
    fun `quick fuzz sends untouched baseline first excludes it from total and uses byte lengths`() {
        val sent = mutableListOf<HttpRequestData>()
        val call = AtomicInteger()
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            sent += request
            when (call.getAndIncrement()) {
                0 -> success(request, body = "é", statusCode = 200, contentType = "text/plain")
                1 -> success(request, body = "éé", statusCode = 200, contentType = "text/plain")
                else -> success(request, body = "x", statusCode = 403, contentType = "text/plain")
            }
        }
        val service = IntruderService(api, repeater)
        val base = HttpRequestData("GET", "https://example.test/?q=original")

        val response = service.quickFuzz(
            QuickFuzzRequest(request = base, param = "q", payloads = listOf("one", "two")),
        )

        assertEquals(base, sent.first())
        assertEquals(listOf("https://example.test/?q=one", "https://example.test/?q=two"), sent.drop(1).map { it.url })
        assertEquals(2, response.total)
        assertEquals(2, response.results.size)
        assertEquals(2, response.baseline?.length)
        assertEquals(4, response.results.first().length)
        assertFalse(response.results.first().anomalous)
        assertTrue(response.results.last().anomalous)
        assertNull(response.baseline?.error)
        assertNull(response.baseline?.errorCode)
    }

    @Test
    fun `failed quick fuzz baseline is sanitized and stops all payload sends`() {
        every { repeater.send(any()) } throws IllegalStateException("credential=top-secret")
        val service = IntruderService(api, repeater)

        val response = service.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData("GET", "https://example.test/?q=original"),
                param = "q",
                payloads = listOf("one", "two"),
            ),
        )

        assertEquals(0, response.total)
        assertTrue(response.results.isEmpty())
        val baseline = assertNotNull(response.baseline)
        assertEquals(0, baseline.statusCode)
        assertEquals(0, baseline.length)
        assertEquals("SEND_FAILED", baseline.errorCode)
        assertFalse(baseline.error.orEmpty().contains("top-secret"))
        verify(exactly = 1) { repeater.send(any()) }
    }

    @Test
    fun `payload failures carry stable sanitized error codes and are never anomalies`() {
        val calls = AtomicInteger()
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            if (calls.getAndIncrement() == 0) success(request)
            else throw IllegalStateException("internal token secret-token")
        }
        val service = IntruderService(api, repeater)

        val response = service.quickFuzz(
            QuickFuzzRequest(
                request = HttpRequestData("GET", "https://example.test/?q=original"),
                param = "q",
                payloads = listOf("one"),
            ),
        )

        val result = response.results.single()
        assertEquals("SEND_FAILED", result.errorCode)
        assertFalse(result.error.orEmpty().contains("secret-token"))
        assertFalse(result.anomalous)
    }

    private fun validPlan(payloads: List<String> = listOf("x")): CreateAttackRequest {
        val request = inlineRequest(body = "value")
        val raw = rawBytes(request)
        val start = raw.indexOf("value".toByteArray(UTF_8))
        return CreateAttackRequest(
            request = request,
            positions = listOf(PayloadPosition(start, start + 5, "body")),
            payloads = mapOf("body" to payloads),
        )
    }

    private fun inlineRequest(
        method: String = "POST",
        body: String = "value",
    ) = HttpRequestData(
        method = method,
        url = "https://example.test/submit",
        headers = listOf(HttpHeader("Content-Type", "text/plain")),
        body = body,
    )

    private fun rawBytes(request: HttpRequestData): ByteArray {
        val target = java.net.URI(request.url).rawPath.ifEmpty { "/" }
        val lines = buildList {
            add("${request.method} $target HTTP/1.1")
            if (request.headers.none { it.name.equals("Host", ignoreCase = true) }) {
                add("Host: example.test")
            }
            request.headers.forEach { add("${it.name}: ${it.value}") }
        }
        return (lines.joinToString("\r\n") + "\r\n\r\n" + (request.body ?: "")).toByteArray(UTF_8)
    }

    private fun success(
        request: HttpRequestData,
        body: String = "ok",
        statusCode: Int = 200,
        contentType: String? = "text/plain",
    ): SendResponse = SendResponse(
        request = request,
        response = HttpResponseData(
            statusCode = statusCode,
            headers = contentType?.let { listOf(HttpHeader("Content-Type", it)) } ?: emptyList(),
            body = body,
        ),
        durationMs = 1,
    )

    private fun mockHistoryRequest(raw: ByteArray, url: String): HttpRequest {
        val request = mockk<HttpRequest>()
        val bytes = mockk<BurpByteArray>()
        every { request.toByteArray() } returns bytes
        every { bytes.length() } returns raw.size
        every { bytes.getByte(any()) } answers { raw[firstArg<Int>()] }
        every { request.url() } returns url
        return request
    }

    private fun awaitStatus(service: IntruderService, id: String, expected: String) {
        eventually {
            assertEquals(expected, service.attackStatus(id).status)
        }
    }

    private fun awaitResultCount(service: IntruderService, id: String, expected: Int) {
        eventually {
            assertEquals(expected, service.attackResults(id).total)
        }
    }

    private fun eventually(timeoutMs: Long = 2_000, assertion: () -> Unit) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        var lastFailure: AssertionError? = null
        while (System.nanoTime() < deadline) {
            try {
                assertion()
                return
            } catch (failure: AssertionError) {
                lastFailure = failure
                Thread.onSpinWait()
            }
        }
        throw lastFailure ?: AssertionError("condition was not met")
    }

    private fun ByteArray.lastIndexOf(needle: ByteArray): Int {
        for (start in size - needle.size downTo 0) {
            if (needle.indices.all { this[start + it] == needle[it] }) return start
        }
        return -1
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        for (start in 0..size - needle.size) {
            if (needle.indices.all { this[start + it] == needle[it] }) return start
        }
        return -1
    }
}
