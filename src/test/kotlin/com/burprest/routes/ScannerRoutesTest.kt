package com.burprest.routes

import burp.api.montoya.MontoyaApi
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.services.ScannerService
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

class ScannerRoutesTest {

    @Test
    fun `invalid crawl URL produces typed 400 before Montoya effects`() = testApplication {
        val api = mockk<MontoyaApi>()
        val service = ScannerService(api)
        application {
            installStrictJson()
            installErrorHandling { }
            routing { scannerRoutes(service) }
        }

        client.post("/scanner/crawl") {
            contentType(ContentType.Application.Json)
            setBody("""{"url":"not-a-url"}""")
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertTrue(bodyAsText().contains("\"code\":\"INVALID_PARAM\""), bodyAsText())
        }
        verify(exactly = 0) { api.scanner(); api.burpSuite() }
    }

    @Test
    fun `combined pause and resume endpoints are typed unsupported with no Montoya effects`() = testApplication {
        val api = mockk<MontoyaApi>()
        val service = ScannerService(api)
        application {
            installStrictJson()
            installErrorHandling { }
            routing { scannerRoutes(service) }
        }

        val combined = client.post("/scanner/crawl-and-audit")
        assertEquals(HttpStatusCode.NotImplemented, combined.status)
        assertTrue(combined.bodyAsText().contains("\"code\":\"UNSUPPORTED\""))

        assertEquals(HttpStatusCode.NotImplemented, client.post("/scanner/unknown/pause").status)
        assertEquals(HttpStatusCode.NotImplemented, client.post("/scanner/unknown/resume").status)
        verify(exactly = 0) { api.scanner(); api.burpSuite() }
    }
}
