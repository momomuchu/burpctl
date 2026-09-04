package com.burprest.server

import com.burprest.models.ApiResponse
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.contentType
import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private const val CAUSE_NEUTRAL_MESSAGE =
    "request Content-Type may be missing or unsupported, or the body may be unparseable"

class UnsupportedMediaTypeErrorTest {

    @Serializable
    private data class StrictPayload(val value: String)

    @Test
    fun `all 415 causes receive one cause-neutral typed envelope`() = testApplication {
        application {
            installStrictJson()
            installErrorHandling { }
            routing {
                post("/payload") {
                    call.respond(ApiResponse.ok(call.receive<StrictPayload>()))
                }
            }
        }

        val cases = listOf(
            "missing Content-Type" to client.post("/payload") {
                setBody(object : OutgoingContent.ByteArrayContent() {
                    override fun bytes(): ByteArray = """{"value":"x"}""".encodeToByteArray()
                })
            },
            "unsupported Content-Type" to client.post("/payload") {
                contentType(ContentType.Text.Plain)
                setBody("""{"value":"x"}""")
            },
            "unparseable body" to client.post("/payload") {
                contentType(ContentType.Application.Json)
                setBody("")
            },
        )

        val envelopes = cases.map { (condition, response) ->
            assertEquals(HttpStatusCode.UnsupportedMediaType, response.status, condition)
            assertTrue(
                response.headers[HttpHeaders.ContentType]?.let {
                    ContentType.parse(it).match(ContentType.Application.Json)
                } == true,
                condition,
            )
            Json.decodeFromString<ApiResponse<Unit>>(response.bodyAsText())
        }
        val expectedEnvelope = ApiResponse.error<Unit>(
            "UNSUPPORTED_MEDIA_TYPE",
            CAUSE_NEUTRAL_MESSAGE,
        )

        assertEquals(
            List(cases.size) { expectedEnvelope },
            envelopes,
            "all three causes must receive the same typed envelope",
        )
        val messages = envelopes.map { assertNotNull(it.error).message }
        assertEquals(
            setOf(CAUSE_NEUTRAL_MESSAGE),
            messages.toSet(),
            "all three arms must share one message",
        )
        val sharedMessage = messages.first()
        assertTrue(sharedMessage.contains("Content-Type may be missing or unsupported"))
        assertTrue(sharedMessage.contains("body may be unparseable"))
        listOf("must", "was missing", "was unsupported", "was unparseable").forEach { causeClaim ->
            assertFalse(sharedMessage.contains(causeClaim), "message selects a cause: $causeClaim")
        }
    }
}
