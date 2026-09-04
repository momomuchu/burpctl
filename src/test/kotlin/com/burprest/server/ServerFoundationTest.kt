package com.burprest.server

import com.burprest.models.ApiResponse
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ServerFoundationTest {

    @Serializable
    private data class StrictPayload(val value: String)

    @Test
    fun `strict JSON accepts a valid body`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                post("/payload") {
                    call.respond(ApiResponse.ok(call.receive<StrictPayload>()))
                }
            }
        }

        client.post("/payload") {
            contentType(ContentType.Application.Json)
            setBody("""{"value":"accepted"}""")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertTrue(bodyAsText().contains("accepted"))
        }
    }

    @Test
    fun `strict JSON rejects unknown fields`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                post("/payload") {
                    call.respond(ApiResponse.ok(call.receive<StrictPayload>()))
                }
            }
        }

        client.post("/payload") {
            contentType(ContentType.Application.Json)
            setBody("""{"value":"accepted","unexpected":"must fail"}""")
        }.assertJsonError(HttpStatusCode.BadRequest, "INVALID_REQUEST")
    }

    @Test
    fun `strict JSON rejects lenient unquoted values`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                post("/payload") {
                    call.respond(ApiResponse.ok(call.receive<StrictPayload>()))
                }
            }
        }

        client.post("/payload") {
            contentType(ContentType.Application.Json)
            setBody("""{"value":unquoted}""")
        }.assertJsonError(HttpStatusCode.BadRequest, "INVALID_REQUEST")
    }

    @Test
    fun `typed API exceptions have truthful statuses codes and safe messages`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                get("/invalid") {
                    throw InvalidParamException(
                        "page must be at least 0",
                        IllegalArgumentException("SECRET parser implementation"),
                    )
                }
                get("/missing") {
                    throw NotFoundException(
                        "history entry was not found",
                        NoSuchElementException("SECRET storage key"),
                    )
                }
                get("/unsupported") {
                    throw UnsupportedException(
                        "this operation is not supported",
                        UnsupportedOperationException("SECRET Montoya type"),
                    )
                }
                get("/no-response") {
                    throw NoResponseException(
                        "the upstream server returned no response",
                        IllegalStateException("SECRET connection detail"),
                    )
                }
                get("/service-unavailable") {
                    throw ServiceUnavailableException(
                        "service is temporarily unavailable",
                        IllegalStateException("SECRET Burp implementation"),
                    )
                }
                get("/credential-scope") {
                    throw CredentialScopeViolationException(
                        "credentials may only be sent to their configured origin",
                        SecurityException("SECRET credential target"),
                    )
                }
            }
        }

        val cases = listOf(
            ErrorCase("/invalid", HttpStatusCode.BadRequest, "INVALID_PARAM", "page must be at least 0"),
            ErrorCase("/missing", HttpStatusCode.NotFound, "NOT_FOUND", "history entry was not found"),
            ErrorCase("/unsupported", HttpStatusCode.NotImplemented, "UNSUPPORTED", "this operation is not supported"),
            ErrorCase("/no-response", HttpStatusCode.BadGateway, "NO_RESPONSE", "the upstream server returned no response"),
            ErrorCase(
                "/service-unavailable",
                HttpStatusCode.ServiceUnavailable,
                "SERVICE_UNAVAILABLE",
                "service is temporarily unavailable",
            ),
            ErrorCase(
                "/credential-scope",
                HttpStatusCode.Forbidden,
                "CREDENTIAL_SCOPE_VIOLATION",
                "credentials may only be sent to their configured origin",
            ),
        )

        cases.forEach { expected ->
            val response = client.get(expected.path)
            assertEquals(expected.status, response.status, expected.path)
            assertTrue(response.headers[HttpHeaders.ContentType]?.startsWith(ContentType.Application.Json.toString()) == true)
            val body = response.bodyAsText()
            assertTrue(body.contains("\"success\":false"), body)
            assertTrue(body.contains("\"code\":\"${expected.code}\""), body)
            assertTrue(body.contains("\"message\":\"${expected.message}\""), body)
            assertFalse(body.contains("SECRET"), body)
            assertFalse(body.contains("Exception"), body)
        }
    }

    @Test
    fun `unmatched route returns a JSON not found envelope`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                get("/known") { call.respond(ApiResponse.ok("ok")) }
            }
        }

        client.get("/does-not-exist")
            .assertJsonError(HttpStatusCode.NotFound, "NOT_FOUND")
    }

    @Test
    fun `unsupported method returns a JSON method not allowed envelope`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                get("/known") { call.respond(ApiResponse.ok("ok")) }
            }
        }

        client.post("/known")
            .assertJsonError(HttpStatusCode.MethodNotAllowed, "METHOD_NOT_ALLOWED")
    }

    @Test
    fun `database-backed history routes remain present when the database is unavailable`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                unavailableHistoryRoutes()
            }
        }

        val requests = listOf<suspend () -> HttpResponse>(
            { client.get("/history") },
            { client.get("/history/17") },
            { client.get("/history/sitemap") },
            { client.post("/history/17/replay") },
            { client.delete("/history") },
        )
        requests.forEach { request ->
            request().assertJsonError(HttpStatusCode.ServiceUnavailable, "SERVICE_UNAVAILABLE")
        }

        client.put("/history")
            .assertJsonError(HttpStatusCode.MethodNotAllowed, "METHOD_NOT_ALLOWED")
    }

    @Test
    fun `request logging records path but never query string`() = testApplication {
        val messages = mutableListOf<String>()
        application {
            installStrictJson()
            installErrorHandling { }
            installRequestLogging(messages::add)
            routing {
                get("/logged") { call.respond(ApiResponse.ok("ok")) }
            }
        }

        assertEquals(HttpStatusCode.OK, client.get("/logged?token=TOP_SECRET&next=value").status)
        assertEquals(1, messages.size)
        assertTrue(messages.single().contains("GET /logged 200"), messages.single())
        assertFalse(messages.single().contains("?"), messages.single())
        assertFalse(messages.single().contains("TOP_SECRET"), messages.single())
        assertFalse(messages.single().contains("next=value"), messages.single())
    }

    private data class ErrorCase(
        val path: String,
        val status: HttpStatusCode,
        val code: String,
        val message: String,
    )

    @Test
    fun `an unsupported request media type still answers with the typed envelope`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                post("/payload") {
                    call.respond(ApiResponse.ok(call.receive<StrictPayload>()))
                }
            }
        }

        // Content negotiation rejects these before the route runs; each used to answer a bodiless
        // 415 that no client could parse as an error.
        client.post("/payload") {
            setBody(object : OutgoingContent.ByteArrayContent() {
                override fun bytes(): ByteArray = """{"value":"x"}""".encodeToByteArray()
            })
        }.assertJsonError(HttpStatusCode.UnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE")

        client.post("/payload") {
            contentType(ContentType.Text.Plain)
            setBody("""{"value":"x"}""")
        }.assertJsonError(HttpStatusCode.UnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE")

        client.post("/payload") {
            contentType(ContentType.Application.Json)
            setBody("")
        }.assertJsonError(HttpStatusCode.UnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE")
    }

    private suspend fun HttpResponse.assertJsonError(expectedStatus: HttpStatusCode, expectedCode: String) {
        assertEquals(expectedStatus, status)
        assertTrue(headers[HttpHeaders.ContentType]?.let { ContentType.parse(it).match(ContentType.Application.Json) } == true)
        val body = bodyAsText()
        assertTrue(body.contains("\"success\":false"), body)
        assertTrue(body.contains("\"code\":\"$expectedCode\""), body)
        assertFalse(body.contains("Exception"), body)
    }
}
