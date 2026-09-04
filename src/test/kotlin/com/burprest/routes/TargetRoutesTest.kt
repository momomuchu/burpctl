package com.burprest.routes

import burp.api.montoya.MontoyaApi
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.services.TargetService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TargetRoutesTest {

    @Test
    fun `scope listing and replacement return typed unsupported without Montoya effects`() = testApplication {
        val api = mockk<MontoyaApi>()
        val service = TargetService(api)
        application {
            installStrictJson()
            installErrorHandling { }
            routing { targetRoutes(service) }
        }

        client.get("/target/scope").assertUnsupported()
        client.post("/target/scope").assertUnsupported()
        verify(exactly = 0) { api.scope() }
    }

    @Test
    fun `missing scope check URL is a typed bad request before service call`() = testApplication {
        val service = mockk<TargetService>()
        application {
            installStrictJson()
            installErrorHandling { }
            routing { targetRoutes(service) }
        }

        assertEquals(HttpStatusCode.BadRequest, client.get("/target/scope/check").status)
        verify(exactly = 0) { service.isInScope(any()) }
    }

    private suspend fun HttpResponse.assertUnsupported() {
        assertEquals(HttpStatusCode.NotImplemented, status)
        assertTrue(bodyAsText().contains("\"code\":\"UNSUPPORTED\""), bodyAsText())
    }
}
