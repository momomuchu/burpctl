package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.HealthResponse
import com.burprest.models.VersionResponse
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
import kotlin.test.assertTrue

class HealthRoutesTest {

    @Test
    fun `health endpoint returns ok`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            install(io.ktor.server.routing.Routing) {
                healthRoutes(System.currentTimeMillis())
            }
        }

        client.get("/health").apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals("true", body["success"]?.jsonPrimitive?.content)
            val data = body["data"]?.jsonObject
            assertEquals("ok", data?.get("status")?.jsonPrimitive?.content)
            assertEquals("0.1.0", data?.get("version")?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `version endpoint returns version info`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            install(io.ktor.server.routing.Routing) {
                healthRoutes(System.currentTimeMillis())
            }
        }

        client.get("/version").apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            val data = body["data"]?.jsonObject
            assertEquals("0.1.0", data?.get("version")?.jsonPrimitive?.content)
            assertEquals("burp-rest-extension", data?.get("name")?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `docs endpoint returns openapi json`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            install(io.ktor.server.routing.Routing) {
                healthRoutes(System.currentTimeMillis())
            }
        }

        client.get("/docs").apply {
            assertEquals(HttpStatusCode.OK, status)
            val body = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals("3.0.3", body["openapi"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun `health reports burpVersion when supplied`() = testApplication {
        application {
            install(ContentNegotiation) { json() }
            install(io.ktor.server.routing.Routing) {
                healthRoutes(System.currentTimeMillis(), "Burp Suite Professional 2025.3")
            }
        }

        client.get("/health").apply {
            assertEquals(HttpStatusCode.OK, status)
            val data = Json.parseToJsonElement(bodyAsText()).jsonObject["data"]?.jsonObject
            assertEquals(
                "Burp Suite Professional 2025.3",
                data?.get("burpVersion")?.jsonPrimitive?.content,
            )
        }
    }
}
