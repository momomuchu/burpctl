package com.burprest.routes

import com.burprest.models.BatchGenerateResponse
import com.burprest.models.CollaboratorPayload
import com.burprest.server.installErrorHandling
import com.burprest.services.CollaboratorPayloadNotFoundException
import com.burprest.services.CollaboratorProviderException
import com.burprest.services.CollaboratorService
import com.burprest.services.CollaboratorUnavailableException
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.testing.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CollaboratorRoutesTest {

    @Test
    fun `generate capability failure maps to PRO_REQUIRED and never leaks internals`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.generateBatch(1) } throws CollaboratorUnavailableException("SECRET internal detail")
        installRoutes(service)

        client.post("/collaborator/generate").apply {
            val body = bodyAsText()
            assertEquals(HttpStatusCode.ServiceUnavailable, status)
            assertEquals("PRO_REQUIRED", errorCode(body))
            assertFalse(body.contains("SECRET"), body)
            assertFalse(body.contains("CollaboratorUnavailableException"), body)
        }

        verify(exactly = 1) { service.generateBatch(1) }
    }

    @Test
    fun `generate provider failure is not mislabeled as PRO_REQUIRED and leaks no internals`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.generateBatch(1) } throws CollaboratorProviderException("SECRET generate failure")
        installRoutes(service)

        client.post("/collaborator/generate").apply {
            val body = bodyAsText()
            assertEquals(HttpStatusCode.ServiceUnavailable, status)
            assertEquals("SERVICE_UNAVAILABLE", errorCode(body))
            assertFalse(body.contains("PRO_REQUIRED"), body)
            assertFalse(body.contains("SECRET"), body)
            assertFalse(body.contains("CollaboratorProviderException"), body)
        }
    }

    @Test
    fun `poll provider failure is not converted to a clean empty response`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.poll() } throws CollaboratorProviderException("SECRET poll failure")
        installRoutes(service)

        client.get("/collaborator/poll").apply {
            val body = bodyAsText()
            assertEquals(HttpStatusCode.ServiceUnavailable, status)
            assertEquals("SERVICE_UNAVAILABLE", errorCode(body))
            assertFalse(body.contains("PRO_REQUIRED"), body)
            assertFalse(body.contains("SECRET"), body)
            assertFalse(body.contains("\"found\""), body)
        }
    }

    @Test
    fun `unknown scoped payload returns distinguishable NOT_FOUND`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.pollById("unknown") } throws CollaboratorPayloadNotFoundException("unknown")
        installRoutes(service)

        client.get("/collaborator/poll/unknown").apply {
            val body = bodyAsText()
            assertEquals(HttpStatusCode.NotFound, status)
            assertEquals("NOT_FOUND", errorCode(body))
            assertEquals("Collaborator payload not found", errorMessage(body))
            assertFalse(body.contains("PRO_REQUIRED"), body)
            assertFalse(body.contains("CollaboratorPayloadNotFoundException"), body)
        }
    }

    @Test
    fun `unrelated failures are not relabeled as PRO_REQUIRED`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.generateBatch(1) } throws RuntimeException("SECRET unrelated failure")
        installRoutes(service)

        client.post("/collaborator/generate").apply {
            val body = bodyAsText()
            assertEquals(HttpStatusCode.InternalServerError, status)
            assertEquals("INTERNAL_ERROR", errorCode(body))
            assertFalse(body.contains("PRO_REQUIRED"), body)
            assertFalse(body.contains("SECRET"), body)
        }
    }

    @Test
    fun `generate returns the unified payloads list shape`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.generateBatch(1) } returns BatchGenerateResponse(
            payloads = listOf(CollaboratorPayload(id = "x", payload = "a.oastify.com", interactionId = "x")),
        )
        installRoutes(service)

        client.post("/collaborator/generate").apply {
            assertEquals(HttpStatusCode.OK, status)
            val data = Json.parseToJsonElement(bodyAsText()).jsonObject["data"]?.jsonObject
            assertTrue(data?.containsKey("payloads") == true, bodyAsText())
        }

        verify(exactly = 1) { service.generateBatch(1) }
    }

    @Test
    fun `batch generate rejects counts outside one through one hundred before service call`() = testApplication {
        val service = mockk<CollaboratorService>(relaxed = true)
        installRoutes(service)

        listOf(-1, 0, 101).forEach { count ->
            client.post("/collaborator/generate/batch") {
                contentType(ContentType.Application.Json)
                setBody("""{"count":$count}""")
            }.apply {
                assertEquals(HttpStatusCode.BadRequest, status, "count=$count body=${bodyAsText()}")
            }
        }

        verify(exactly = 0) { service.generateBatch(any()) }
    }

    private fun ApplicationTestBuilder.installRoutes(service: CollaboratorService) {
        application {
            install(ContentNegotiation) { json() }
            installErrorHandling { }
            install(io.ktor.server.routing.Routing) { collaboratorRoutes(service) }
        }
    }

    private fun errorCode(body: String): String? =
        Json.parseToJsonElement(body).jsonObject["error"]?.jsonObject?.get("code")?.jsonPrimitive?.content

    private fun errorMessage(body: String): String? =
        Json.parseToJsonElement(body).jsonObject["error"]?.jsonObject?.get("message")?.jsonPrimitive?.content
}
