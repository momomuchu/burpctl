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
}
