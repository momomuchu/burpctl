package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.extension.Extension
import com.burprest.models.ConfigUpdateRequest
import com.burprest.server.InvalidParamException
import com.burprest.server.ServiceUnavailableException
import io.mockk.*
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ConfigServiceTest {

    @Test
    fun `project export preserves nested JSON types`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"http":{"redirections":{"type":2,"enabled":true}},"names":["a",null]}}"""

        val config = ConfigService(api).getProjectConfig().config

        assertEquals(2, config["project_options"]!!.jsonObject["http"]!!.jsonObject["redirections"]!!.jsonObject["type"]!!.jsonPrimitive.int)
        assertEquals(true, config["project_options"]!!.jsonObject["http"]!!.jsonObject["redirections"]!!.jsonObject["enabled"]!!.jsonPrimitive.boolean)
        assertEquals(JsonNull, config["project_options"]!!.jsonObject["names"]!!.jsonArray[1])
    }

    @Test
    fun `user export preserves nested JSON`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returns
            """{"user_options":{"connections":{"upstream_proxy":{"servers":[{"port":8080}]}}}}"""

        val config = ConfigService(api).getUserConfig().config

        assertEquals(8080, config["user_options"]!!.jsonObject["connections"]!!.jsonObject["upstream_proxy"]!!.jsonObject["servers"]!!.jsonArray.single().jsonObject["port"]!!.jsonPrimitive.int)
    }

    @Test
    fun `project import sends nested JSON and returns authoritative post import export`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importProjectOptionsFromJson(any()) } just Runs
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"applied":true,"count":3}}"""
        val requested = Json.parseToJsonElement(
            """{"project_options":{"requested":{"nested":[true,2,"three"]}}}""",
        )

        val response = ConfigService(api).updateProjectConfig(ConfigUpdateRequest(requested))

        val imported = slot<String>()
        verify { burpSuite.importProjectOptionsFromJson(capture(imported)) }
        assertEquals(requested, Json.parseToJsonElement(imported.captured))
        assertEquals(true, response.config["project_options"]!!.jsonObject["applied"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `user import uses user API and returns its authoritative export`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importUserOptionsFromJson(any()) } just Runs
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returns """{"user_options":{"applied":true}}"""
        val requested = Json.parseToJsonElement("""{"user_options":{"theme":"dark"}}""")

        val response = ConfigService(api).updateUserConfig(ConfigUpdateRequest(requested))

        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(requested.toString()) }
        verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        assertEquals(true, response.config["user_options"]!!.jsonObject["applied"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `non-object config is rejected before Montoya mutation`() {
        val api = mockk<MontoyaApi>()
        val service = ConfigService(api)

        for (invalid in listOf(JsonPrimitive("text"), JsonArray(emptyList()), JsonNull)) {
            assertFailsWith<InvalidParamException> {
                service.updateProjectConfig(ConfigUpdateRequest(invalid))
            }
            assertFailsWith<InvalidParamException> {
                service.updateUserConfig(ConfigUpdateRequest(invalid))
            }
        }
        verify(exactly = 0) { api.burpSuite() }
    }

    @Test
    fun `invalid Montoya export is an operational failure`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns "not-json"

        assertFailsWith<ServiceUnavailableException> { ConfigService(api).getProjectConfig() }
    }

    @Test
    fun `non-object Montoya export is an operational failure`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns "[]"

        assertFailsWith<ServiceUnavailableException> { ConfigService(api).getProjectConfig() }
    }

    @Test
    fun `failed import does not attempt an authoritative export`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importProjectOptionsFromJson(any()) } throws IllegalStateException("rejected")
        val request = ConfigUpdateRequest(Json.parseToJsonElement("""{"project_options":{}}"""))

        assertFailsWith<ServiceUnavailableException> { ConfigService(api).updateProjectConfig(request) }
        verify(exactly = 0) { burpSuite.exportProjectOptionsAsJson(*anyVararg()) }
    }

    @Test
    fun `extension listing contains only this extension`() {
        val api = mockk<MontoyaApi>()
        val extension = mockk<Extension>()
        every { api.extension() } returns extension
        every { extension.filename() } returns "/tmp/burp-rest.jar"

        val result = ConfigService(api).getExtensions()

        assertEquals(1, result.total)
        assertEquals(1, result.extensions.size)
        assertEquals("current-extension-only", result.scope)
        assertEquals("Burp REST API", result.extensions.single().name)
        assertEquals("/tmp/burp-rest.jar", result.extensions.single().filename)
    }
}
