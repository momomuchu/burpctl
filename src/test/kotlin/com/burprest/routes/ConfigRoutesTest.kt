package com.burprest.routes

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.services.ConfigService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConfigRoutesTest {

    @Test
    fun `project GET serializes nested JSON without string flattening`() = testApplication {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"nested":{"enabled":true}}}"""
        application {
            installStrictJson()
            installErrorHandling { }
            routing { configRoutes(ConfigService(api)) }
        }

        client.get("/config/project").apply {
            assertEquals(HttpStatusCode.OK, status)
            val data = Json.parseToJsonElement(bodyAsText()).jsonObject["data"]!!.jsonObject
            assertEquals(
                true,
                data["config"]!!.jsonObject["project_options"]!!.jsonObject["nested"]!!.jsonObject["enabled"]!!.jsonPrimitive.boolean,
            )
        }
    }

    @Test
    fun `non-object project config is rejected before import`() = testApplication {
        val api = mockk<MontoyaApi>()
        application {
            installStrictJson()
            installErrorHandling { }
            routing { configRoutes(ConfigService(api)) }
        }

        client.put("/config/project") {
            contentType(ContentType.Application.Json)
            setBody("""{"config":["not","an","object"]}""")
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertTrue(bodyAsText().contains("\"code\":\"INVALID_PARAM\""), bodyAsText())
        }
        verify(exactly = 0) { api.burpSuite() }
    }
}
