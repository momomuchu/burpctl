package com.burprest.server

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StatusPagesTest {

    @Test
    fun `unexpected exception does not leak class name or message to the client`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            installErrorHandling { /* discard server-side log in the test */ }
            routing {
                get("/boom") { throw RuntimeException("SECRET jdbc:h2 schema detail") }
            }
        }
        client.get("/boom").apply {
            assertEquals(HttpStatusCode.InternalServerError, status)
            val text = bodyAsText()
            assertFalse(text.contains("SECRET"), "leaked exception message: $text")
            assertFalse(text.contains("RuntimeException"), "leaked exception class: $text")
            assertTrue(text.contains("INTERNAL_ERROR"))
        }
    }

    @Test
    fun `BadRequestException does not leak ktor class-name message to the client`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            installErrorHandling { }
            routing {
                get("/bad-req") {
                    throw io.ktor.server.plugins.BadRequestException(
                        "Failed to convert request body to class com.burprest.models.ScanRequest"
                    )
                }
            }
        }
        client.get("/bad-req").apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            val text = bodyAsText()
            assertFalse(text.contains("com.burprest"), "leaked internal class name: $text")
            assertFalse(text.contains("ScanRequest"), "leaked internal class name: $text")
            assertTrue(text.contains("INVALID_REQUEST"))
        }
    }

    @Test
    fun `route validation IllegalArgumentException keeps its clean message`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            installErrorHandling { }
            routing {
                get("/bad") { throw IllegalArgumentException("page must be >= 0") }
            }
        }
        client.get("/bad").apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertTrue(bodyAsText().contains("page must be >= 0"))
        }
    }

    // -------------------------------------------------------------------------
    // [13] ProRequiredException -> PRO_REQUIRED; IllegalStateException stays SERVICE_UNAVAILABLE
    // -------------------------------------------------------------------------

    @Test
    fun `ProRequiredException maps to PRO_REQUIRED code not SERVICE_UNAVAILABLE`() = testApplication {
        // [13] RED→GREEN: scanner crawl/audit on Community throws ProRequiredException; the
        // StatusPages handler must return code PRO_REQUIRED (not SERVICE_UNAVAILABLE) so the
        // Python client exits 4 (EXIT_PRO), not 1 (EXIT_GENERIC).
        application {
            install(ContentNegotiation) { json() }
            installErrorHandling { }
            routing {
                get("/pro-gate") { throw ProRequiredException("requires Burp Suite Professional") }
            }
        }
        client.get("/pro-gate").apply {
            assertEquals(HttpStatusCode.ServiceUnavailable, status)
            val text = bodyAsText()
            assertTrue(text.contains("PRO_REQUIRED"), "expected PRO_REQUIRED code in body: $text")
            assertFalse(text.contains("SERVICE_UNAVAILABLE"), "must not contain SERVICE_UNAVAILABLE: $text")
            // Internal detail must not leak to the client
            assertFalse(text.contains("ProRequiredException"), "leaked exception class: $text")
        }
    }

    @Test
    fun `IllegalStateException still maps to SERVICE_UNAVAILABLE not PRO_REQUIRED`() = testApplication {
        // [13] Regression lock: ordinary IllegalStateException (e.g. missing endpoints DB) must
        // still produce SERVICE_UNAVAILABLE → Python client exits 1 (EXIT_GENERIC), not 4.
        application {
            install(ContentNegotiation) { json() }
            installErrorHandling { }
            routing {
                get("/infra-fail") { throw IllegalStateException("endpoints DB not initialised") }
            }
        }
        client.get("/infra-fail").apply {
            assertEquals(HttpStatusCode.ServiceUnavailable, status)
            val text = bodyAsText()
            assertTrue(text.contains("SERVICE_UNAVAILABLE"), "expected SERVICE_UNAVAILABLE in body: $text")
            assertFalse(text.contains("PRO_REQUIRED"), "must not contain PRO_REQUIRED: $text")
        }
    }
}
