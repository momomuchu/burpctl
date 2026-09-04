package com.burprest.routes

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import com.burprest.models.HttpRequestData
import com.burprest.models.HttpResponseData
import com.burprest.models.PersistenceStatus
import com.burprest.models.RepeaterPersistence
import com.burprest.models.SendResponse
import com.burprest.server.NoResponseException
import com.burprest.server.installErrorHandling
import com.burprest.services.RepeaterService
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.mockk.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RepeaterRoutesTest {
    private fun ApplicationTestBuilder.setup(service: RepeaterService) {
        application {
            install(ContentNegotiation) {
                json(Json { encodeDefaults = true })
            }
            installErrorHandling { }
            routing { repeaterRoutes(service) }
        }
    }

    @Test
    fun `send route rejects a tab-whitespace inline request before target traffic`() = testApplication {
        val api = mockk<MontoyaApi>()
        val http = mockk<Http>()
        every { api.http() } returns http
        val service = RepeaterService(api)
        setup(service)

        client.post("/repeater/send") {
            contentType(ContentType.Application.Json)
            setBody("""{"request":{"method":"\t","url":"\t"}}""")
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertTrue(bodyAsText().contains("INVALID_REQUEST"))
        }

        verify(exactly = 0) { http.sendRequest(any()) }
    }

    @Test
    fun `send route maps a response-less completed send to typed NO_RESPONSE`() = testApplication {
        val service = mockk<RepeaterService>()
        every { service.send(any()) } throws NoResponseException(
            "target send completed without an upstream response",
        )
        setup(service)

        client.post("/repeater/send") {
            contentType(ContentType.Application.Json)
            setBody("""{"requestId":0}""")
        }.apply {
            assertEquals(HttpStatusCode.BadGateway, status)
            val error = Json.parseToJsonElement(bodyAsText()).jsonObject["error"]!!.jsonObject
            assertEquals("NO_RESPONSE", error["code"]!!.jsonPrimitive.content)
            assertTrue(error["message"]!!.jsonPrimitive.content.contains("completed"))
        }
    }

    @Test
    fun `send route keeps successful target response and serializes failed persistence warning`() = testApplication {
        val service = mockk<RepeaterService>()
        every { service.send(any()) } returns SendResponse(
            request = HttpRequestData("POST", "https://example.test/mutate"),
            response = HttpResponseData(204),
            durationMs = 12,
            persistence = RepeaterPersistence(
                status = PersistenceStatus.FAILED,
                warning = "Target send completed, but optional persistence failed; do not retry the target send.",
            ),
        )
        setup(service)

        client.post("/repeater/send") {
            contentType(ContentType.Application.Json)
            setBody("""{"requestId":0}""")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val envelope = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertTrue(envelope["success"]!!.jsonPrimitive.boolean)
            val data = envelope["data"]!!.jsonObject
            assertEquals(204, data["response"]!!.jsonObject["statusCode"]!!.jsonPrimitive.content.toInt())
            val persistence = data["persistence"]!!.jsonObject
            assertEquals("failed", persistence["status"]!!.jsonPrimitive.content)
            assertFalse(persistence["historyPersisted"]!!.jsonPrimitive.boolean)
            assertFalse(persistence["sitemapPersisted"]!!.jsonPrimitive.boolean)
            assertTrue(persistence["warning"]!!.jsonPrimitive.content.contains("do not retry"))
        }
    }
}
