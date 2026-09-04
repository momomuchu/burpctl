package com.burprest.routes

import burp.api.montoya.MontoyaApi
import com.burprest.models.InterceptStatusResponse
import com.burprest.server.UnsupportedException
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.services.ProxyService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProxyRoutesTest {

    @Test
    fun `malformed and overflowing pagination never call the service`() = testApplication {
        val service = mockk<ProxyService>()
        application {
            installStrictJson()
            installErrorHandling { }
            routing { proxyRoutes(service) }
        }

        for (query in listOf("limit=not-a-number", "limit=2147483648", "offset=-1")) {
            assertEquals(HttpStatusCode.BadRequest, client.get("/proxy/history?$query").status)
        }
        verify(exactly = 0) { service.getHistory(any(), any(), any()) }
    }

    @Test
    fun `intercept mutation responds with service authoritative state`() = testApplication {
        val service = mockk<ProxyService>()
        every { service.enableIntercept() } returns false
        application {
            installStrictJson()
            installErrorHandling { }
            routing { proxyRoutes(service) }
        }

        client.post("/proxy/intercept/enable").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertTrue(bodyAsText().contains("\"enabled\":false"), bodyAsText())
        }
    }

    @Test
    fun `unsupported forward is a typed 501 response`() = testApplication {
        val service = mockk<ProxyService>()
        every { service.forwardInterceptedMessage() } throws UnsupportedException("forward is unavailable")
        application {
            installStrictJson()
            installErrorHandling { }
            routing { proxyRoutes(service) }
        }

        client.post("/proxy/intercept/forward").apply {
            assertEquals(HttpStatusCode.NotImplemented, status)
            assertTrue(bodyAsText().contains("\"code\":\"UNSUPPORTED\""), bodyAsText())
        }
    }
}
