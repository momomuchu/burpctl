package com.burprest.routes

import burp.api.montoya.MontoyaApi
import com.burprest.models.ApiResponse
import com.burprest.models.AttackOptions
import com.burprest.models.CreateAttackRequest
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.HttpResponseData
import com.burprest.models.PayloadPosition
import com.burprest.models.SendRequest
import com.burprest.models.SendResponse
import com.burprest.services.IntruderService
import com.burprest.services.RepeaterService
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.plugins.statuspages.exception
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.mockk.every
import io.mockk.mockk
import java.nio.charset.StandardCharsets.UTF_8
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class IntruderRoutesTest {
    private val json = Json { encodeDefaults = true }

    @Test
    fun `routes expose exact sniper cardinality and safe result slices`() = testApplication {
        val service = serviceWithSuccessfulSends()
        application { testModule(service) }
        val plan = twoPositionPlan()

        val create = client.post("/intruder/attack/create") {
            contentType(ContentType.Application.Json)
            setBody(json.encodeToString(plan))
        }
        assertEquals(HttpStatusCode.OK, create.status)
        val id = create.bodyAsText().dataObject()["attackId"]!!.jsonPrimitive.content

        assertEquals(HttpStatusCode.OK, client.post("/intruder/attack/$id/start").status)
        awaitCompleted(id)

        val results = client.get("/intruder/attack/$id/results?offset=1&limit=2")
        assertEquals(HttpStatusCode.OK, results.status)
        val data = results.bodyAsText().dataObject()
        assertEquals(5, data["total"]!!.jsonPrimitive.content.toInt())
        assertEquals(2, data["results"]!!.jsonArray.size)
    }

    @Test
    fun `lifecycle routes enforce created running paused and terminal transitions`() = testApplication {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val service = serviceWithSuccessfulSends(entered, release)
        application { testModule(service) }
        val plan = onePositionPlan(listOf("one"))
        val create = client.post("/intruder/attack/create") {
            contentType(ContentType.Application.Json)
            setBody(json.encodeToString(plan))
        }
        val id = create.bodyAsText().dataObject()["attackId"]!!.jsonPrimitive.content

        assertEquals(HttpStatusCode.BadRequest, client.post("/intruder/attack/$id/pause").status)
        assertEquals(HttpStatusCode.OK, client.post("/intruder/attack/$id/start").status)
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        assertEquals(HttpStatusCode.BadRequest, client.post("/intruder/attack/$id/start").status)

        val paused = client.post("/intruder/attack/$id/pause")
        assertEquals("paused", paused.bodyAsText().dataObject()["status"]!!.jsonPrimitive.content)
        val resumed = client.post("/intruder/attack/$id/resume")
        assertEquals("running", resumed.bodyAsText().dataObject()["status"]!!.jsonPrimitive.content)
        release.countDown()
        awaitCompleted(id)

        assertEquals(HttpStatusCode.BadRequest, client.post("/intruder/attack/$id/start").status)
        assertEquals(HttpStatusCode.BadRequest, client.post("/intruder/attack/$id/resume").status)
    }

    @Test
    fun `stop route interrupts throttle and leaves a non-restartable terminal attack`() = testApplication {
        val service = serviceWithSuccessfulSends()
        application { testModule(service) }
        val plan = onePositionPlan(listOf("one", "two")).copy(
            options = AttackOptions(throttleMs = 60_000),
        )
        val create = client.post("/intruder/attack/create") {
            contentType(ContentType.Application.Json)
            setBody(json.encodeToString(plan))
        }
        val id = create.bodyAsText().dataObject()["attackId"]!!.jsonPrimitive.content

        client.post("/intruder/attack/$id/start")
        awaitResultTotal(id, 1)
        val stopped = client.post("/intruder/attack/$id/stop")

        assertEquals(HttpStatusCode.OK, stopped.status)
        assertEquals("stopped", stopped.bodyAsText().dataObject()["status"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.BadRequest, client.post("/intruder/attack/$id/start").status)
        assertEquals(1, client.get("/intruder/attack/$id/results").bodyAsText()
            .dataObject()["total"]!!.jsonPrimitive.content.toInt())
    }

    @Test
    fun `results route rejects malformed and negative pagination`() = testApplication {
        val service = serviceWithSuccessfulSends()
        application { testModule(service) }
        val create = client.post("/intruder/attack/create") {
            contentType(ContentType.Application.Json)
            setBody(json.encodeToString(onePositionPlan(listOf("one"))))
        }
        val id = create.bodyAsText().dataObject()["attackId"]!!.jsonPrimitive.content

        listOf(
            "offset=nope",
            "offset=-1",
            "limit=nope",
            "limit=-1",
            "offset=999999999999999999999",
        ).forEach { query ->
            val response = client.get("/intruder/attack/$id/results?$query")
            assertEquals(HttpStatusCode.BadRequest, response.status)
            val envelope = json.parseToJsonElement(response.bodyAsText()).jsonObject
            assertFalse(envelope["success"]!!.jsonPrimitive.content.toBoolean())
            assertEquals("INVALID_REQUEST", envelope["error"]!!.jsonObject["code"]!!.jsonPrimitive.content)
        }
    }

    private fun io.ktor.server.application.Application.testModule(service: IntruderService) {
        install(ContentNegotiation) { json(this@IntruderRoutesTest.json) }
        install(StatusPages) {
            exception<IllegalArgumentException> { call, cause ->
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse.error<Unit>("INVALID_REQUEST", cause.message ?: "invalid request"),
                )
            }
        }
        routing { intruderRoutes(service) }
    }

    private fun serviceWithSuccessfulSends(
        entered: CountDownLatch? = null,
        release: CountDownLatch? = null,
    ): IntruderService {
        val api = mockk<MontoyaApi>()
        val repeater = mockk<RepeaterService>()
        every { repeater.send(any()) } answers {
            val request = firstArg<SendRequest>().request!!
            entered?.countDown()
            if (release != null) assertTrue(release.await(2, TimeUnit.SECONDS))
            SendResponse(
                request = request,
                response = HttpResponseData(
                    statusCode = 200,
                    headers = listOf(HttpHeader("Content-Type", "text/plain")),
                    body = "ok",
                ),
                durationMs = 1,
            )
        }
        return IntruderService(api, repeater)
    }

    private fun onePositionPlan(payloads: List<String>): CreateAttackRequest {
        val request = HttpRequestData(
            method = "POST",
            url = "https://example.test/submit",
            headers = listOf(HttpHeader("Content-Type", "text/plain")),
            body = "a",
        )
        val raw = rawBytes(request)
        val start = raw.size - 1
        return CreateAttackRequest(
            request = request,
            positions = listOf(PayloadPosition(start, start + 1, "a")),
            payloads = mapOf("a" to payloads),
        )
    }

    private fun twoPositionPlan(): CreateAttackRequest {
        val request = HttpRequestData(
            method = "POST",
            url = "https://example.test/submit",
            headers = listOf(HttpHeader("Content-Type", "text/plain")),
            body = "ab",
        )
        val raw = rawBytes(request)
        val start = raw.size - 2
        return CreateAttackRequest(
            request = request,
            positions = listOf(
                PayloadPosition(start, start + 1, "a"),
                PayloadPosition(start + 1, start + 2, "b"),
            ),
            payloads = linkedMapOf(
                "a" to listOf("1", "2"),
                "b" to listOf("x", "y", "z"),
            ),
        )
    }

    private fun rawBytes(request: HttpRequestData): ByteArray {
        val uri = java.net.URI(request.url)
        val target = buildString {
            append(uri.rawPath.ifEmpty { "/" })
            uri.rawQuery?.let { append('?').append(it) }
        }
        val lines = buildList {
            add("${request.method} $target HTTP/1.1")
            if (request.headers.none { it.name.equals("Host", ignoreCase = true) }) {
                add("Host: ${uri.rawAuthority}")
            }
            request.headers.forEach { add("${it.name}: ${it.value}") }
        }
        return (lines.joinToString("\r\n") + "\r\n\r\n" + request.body.orEmpty()).toByteArray(UTF_8)
    }

    private fun String.dataObject() =
        json.parseToJsonElement(this).jsonObject["data"]!!.jsonObject

    private suspend fun io.ktor.server.testing.ApplicationTestBuilder.awaitResultTotal(id: String, expected: Int) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            val response = client.get("/intruder/attack/$id/results")
            val total = response.bodyAsText().dataObject()["total"]!!.jsonPrimitive.content.toInt()
            if (total == expected) return
            Thread.onSpinWait()
        }
        throw AssertionError("attack did not produce $expected results")
    }

    private suspend fun io.ktor.server.testing.ApplicationTestBuilder.awaitCompleted(id: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            val response = client.get("/intruder/attack/$id/status")
            val status = response.bodyAsText().dataObject()["status"]!!.jsonPrimitive.content
            if (status == "completed") return
            Thread.onSpinWait()
        }
        throw AssertionError("attack did not complete")
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        for (start in 0..size - needle.size) {
            if (needle.indices.all { this[start + it] == needle[it] }) return start
        }
        return -1
    }
}
