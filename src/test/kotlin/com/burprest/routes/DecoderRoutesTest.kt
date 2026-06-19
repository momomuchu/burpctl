package com.burprest.routes

import com.burprest.services.DecoderService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class DecoderRoutesTest {

    private val decoderService = DecoderService()

    private fun ApplicationTestBuilder.setup() {
        application {
            install(ContentNegotiation) { json() }
            install(io.ktor.server.routing.Routing) {
                decoderRoutes(decoderService)
            }
        }
    }

    @Test
    fun `encode base64 via route`() = testApplication {
        setup()

        client.post("/decoder/encode") {
            contentType(ContentType.Application.Json)
            setBody("""{"data":"hello","encoding":"base64"}""")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            val data = body["data"]?.jsonObject
            assertEquals("aGVsbG8=", data?.get("result")?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `decode base64 via route`() = testApplication {
        setup()

        client.post("/decoder/decode") {
            contentType(ContentType.Application.Json)
            setBody("""{"data":"aGVsbG8=","encoding":"base64"}""")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            val data = body["data"]?.jsonObject
            assertEquals("hello", data?.get("result")?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `hash md5 via route`() = testApplication {
        setup()

        client.post("/decoder/hash") {
            contentType(ContentType.Application.Json)
            setBody("""{"data":"hello","algorithm":"md5"}""")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            val data = body["data"]?.jsonObject
            assertEquals("5d41402abc4b2a76b9719d911017c592", data?.get("result")?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `smart decode via route`() = testApplication {
        setup()

        client.post("/decoder/smart-decode") {
            contentType(ContentType.Application.Json)
            setBody("""{"data":"aGVsbG8="}""")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            val data = body["data"]?.jsonObject
            // [05] smart-decode's terminal value is serialized as `final` (spec contract,
            // docs/bdd/10-decoder-utils.feature §smart-decode), distinct from steps[].result.
            assertEquals("hello", data?.get("final")?.jsonPrimitive?.content)
        }
    }
}
