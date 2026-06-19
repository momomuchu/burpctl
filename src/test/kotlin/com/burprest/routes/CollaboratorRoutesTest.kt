package com.burprest.routes

import com.burprest.services.CollaboratorService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.testing.*
import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CollaboratorRoutesTest {

    @Test
    fun `generate failure maps to PRO_REQUIRED and never leaks internals`() = testApplication {
        val service = mockk<CollaboratorService>()
        every { service.generatePayload() } throws RuntimeException("SECRET internal detail")

        application {
            install(ContentNegotiation) { json() }
            install(io.ktor.server.routing.Routing) { collaboratorRoutes(service) }
        }

        client.post("/collaborator/generate").apply {
            val body = bodyAsText()
            // Python client maps PRO_REQUIRED -> exit 4 (Pro-only degradation).
            assertTrue(body.contains("PRO_REQUIRED"), body)
            assertFalse(body.contains("SECRET"), body)
            assertFalse(body.contains("RuntimeException"), body)
        }
    }
}
