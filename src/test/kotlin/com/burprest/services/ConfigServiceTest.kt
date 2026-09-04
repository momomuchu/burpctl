package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.extension.Extension
import com.burprest.models.ConfigUpdateRequest
import com.burprest.server.InvalidParamException
import com.burprest.server.ServiceUnavailableException
import io.mockk.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returnsMany listOf(
            """{"project_options":{"requested":{"nested":[false,0,""]}}}""",
            """{"project_options":{"applied":true,"count":3}}""",
        )
        val requested = Json.parseToJsonElement(
            """{"project_options":{"requested":{"nested":[true,2,"three"]}}}""",
        )

        val response = ConfigService(api).updateProjectConfig(ConfigUpdateRequest(requested))

        val imported = slot<String>()
        verify { burpSuite.importProjectOptionsFromJson(capture(imported)) }
        assertEquals(requested, Json.parseToJsonElement(imported.captured))
        assertEquals(
            true,
            requireNotNull(response.config)["project_options"]!!.jsonObject["applied"]!!.jsonPrimitive.boolean,
        )
        assertTrue(response.applied)
        assertEquals(null, response.warning)
    }

    @Test
    fun `user import uses user API and returns its authoritative export`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importUserOptionsFromJson(any()) } just Runs
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returnsMany listOf(
            """{"user_options":{"theme":"light"}}""",
            """{"user_options":{"applied":true}}""",
        )
        val requested = Json.parseToJsonElement("""{"user_options":{"theme":"dark"}}""")

        val response = ConfigService(api).updateUserConfig(ConfigUpdateRequest(requested))

        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(requested.toString()) }
        verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        assertEquals(
            true,
            requireNotNull(response.config)["user_options"]!!.jsonObject["applied"]!!.jsonPrimitive.boolean,
        )
        assertTrue(response.applied)
        assertEquals(null, response.warning)
    }

    @Test
    fun `user import excludes extension inventory and reports the excluded path`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importUserOptionsFromJson(any()) } just Runs
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returns
            """{"user_options":{"theme":"dark","extender":{"settings":{"suppress_extension_loaded_popup":true}}}}"""
        val requested = buildJsonObject {
            put("user_options", buildJsonObject {
                put("theme", "dark")
                put("extender", buildJsonObject {
                    put("extensions", buildJsonArray {
                        add(buildJsonObject { put("extension_file", "/tmp/other.jar") })
                    })
                    put("settings", buildJsonObject {
                        put("suppress_extension_loaded_popup", true)
                    })
                })
            })
        }

        val response = ConfigService(api).updateUserConfig(ConfigUpdateRequest(requested))

        val imported = slot<String>()
        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(capture(imported)) }
        val importedUserOptions = Json.parseToJsonElement(imported.captured)
            .jsonObject["user_options"]!!
            .jsonObject
        val importedExtender = importedUserOptions["extender"]!!.jsonObject
        val importedSettings = importedExtender["settings"]!!.jsonObject
        assertFalse("extensions" in importedExtender, imported.captured)
        assertEquals(
            true,
            importedSettings["suppress_extension_loaded_popup"]!!.jsonPrimitive.boolean,
        )
        assertEquals("dark", importedUserOptions["theme"]!!.jsonPrimitive.content)
        val represented = Json.encodeToString(response)
        assertTrue("user_options.extender.extensions" in represented, represented)
        assertFalse(represented.contains("/tmp/other.jar"))
    }

    @Test
    fun `project import rejects a wrong option type before any Montoya mutation`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"target":{"scope":{"advanced_mode":false,"include":[],"exclude":[]}}}}"""
        every { burpSuite.importProjectOptionsFromJson(any()) } just Runs
        val wrongType = Json.parseToJsonElement(
            """{"project_options":{"target":{"scope":{"advanced_mode":"false"}}}}""",
        )

        assertFailsWith<InvalidParamException> {
            ConfigService(api).updateProjectConfig(ConfigUpdateRequest(wrongType))
        }

        verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
    }

    @Test
    fun `project import rejects an unknown option before any Montoya mutation`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"target":{"scope":{"advanced_mode":false}}}}"""
        every { burpSuite.importProjectOptionsFromJson(any()) } just Runs
        val unknown = Json.parseToJsonElement(
            """{"project_options":{"target":{"scope":{"advanced_mode":false,"unknown_option":true}}}}""",
        )

        assertFailsWith<InvalidParamException> {
            ConfigService(api).updateProjectConfig(ConfigUpdateRequest(unknown))
        }

        verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
    }

    @Test
    fun `project import rejects uncheckable items when the exported array is empty`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"target":{"scope":{"include":[]}}}}"""
        every { burpSuite.importProjectOptionsFromJson(any()) } just Runs
        val requested = Json.parseToJsonElement(
            """{"project_options":{"target":{"scope":{"include":[{"unknown":true}]}}}}""",
        )

        assertFailsWith<InvalidParamException> {
            ConfigService(api).updateProjectConfig(ConfigUpdateRequest(requested))
        }

        verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
    }

    @Test
    fun `project import fails closed for null-shaped and fractional integer options`() {
        val cases = listOf(
            """{"project_options":{"maybe":null}}""" to
                """{"project_options":{"maybe":{"unknown":true}}}""",
            """{"project_options":{"listener_port":8080}}""" to
                """{"project_options":{"listener_port":1.5}}""",
        )

        cases.forEach { (exported, requested) ->
            val api = mockk<MontoyaApi>()
            val burpSuite = mockk<BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns exported
            every { burpSuite.importProjectOptionsFromJson(any()) } just Runs

            assertFailsWith<InvalidParamException> {
                ConfigService(api).updateProjectConfig(
                    ConfigUpdateRequest(Json.parseToJsonElement(requested))
                )
            }
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
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
    fun `failed import does not attempt a post import export`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns """{"project_options":{}}"""
        every { burpSuite.importProjectOptionsFromJson(any()) } throws IllegalStateException("rejected")
        val request = ConfigUpdateRequest(Json.parseToJsonElement("""{"project_options":{}}"""))

        assertFailsWith<ServiceUnavailableException> { ConfigService(api).updateProjectConfig(request) }
        verify(exactly = 1) { burpSuite.exportProjectOptionsAsJson(*anyVararg()) }
    }

    @Test
    fun `completed project import is not reported as failed when post import export fails`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importProjectOptionsFromJson(any()) } just Runs
        every { burpSuite.exportProjectOptionsAsJson(*anyVararg()) } returns
            """{"project_options":{"enabled":false}}""" andThenThrows
            IllegalStateException("post-import export secret")
        val request = ConfigUpdateRequest(
            Json.parseToJsonElement("""{"project_options":{"enabled":true}}"""),
        )

        val outcome = runCatching { ConfigService(api).updateProjectConfig(request) }

        assertTrue(
            outcome.isSuccess,
            "project import completed, so the caller-visible outcome must report applied=true with a " +
                "do-not-retry warning instead of SERVICE_UNAVAILABLE; received " +
                "${outcome.exceptionOrNull()?.message}",
        )
        val responseJson = Json.encodeToJsonElement(outcome.getOrThrow()).jsonObject
        assertEquals(true, responseJson["applied"]?.jsonPrimitive?.booleanOrNull)
        assertEquals(JsonNull, responseJson["config"], "unavailable post-import state must not be fabricated")
        val warning = responseJson["warning"]?.jsonPrimitive?.content.orEmpty()
        assertEquals(
            "Project configuration import completed, but Burp could not export the applied options; " +
                "do not retry the import.",
            warning,
        )
        assertFalse("post-import export secret" in warning)
        verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
        verify(exactly = 2) { burpSuite.exportProjectOptionsAsJson(*anyVararg()) }
    }

    @Test
    fun `completed user import is not reported as failed when post import export fails`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.importUserOptionsFromJson(any()) } just Runs
        every { burpSuite.exportUserOptionsAsJson(*anyVararg()) } returns
            """{"user_options":{"theme":"light"}}""" andThenThrows
            IllegalStateException("post-import export secret")
        val request = ConfigUpdateRequest(
            Json.parseToJsonElement("""{"user_options":{"theme":"dark"}}"""),
        )

        val outcome = runCatching { ConfigService(api).updateUserConfig(request) }

        assertTrue(
            outcome.isSuccess,
            "user import completed, so the caller-visible outcome must report applied=true with a " +
                "do-not-retry warning instead of SERVICE_UNAVAILABLE; received " +
                "${outcome.exceptionOrNull()?.message}",
        )
        val responseJson = Json.encodeToJsonElement(outcome.getOrThrow()).jsonObject
        assertEquals(true, responseJson["applied"]?.jsonPrimitive?.booleanOrNull)
        assertEquals(JsonNull, responseJson["config"], "unavailable post-import state must not be fabricated")
        val warning = responseJson["warning"]?.jsonPrimitive?.content.orEmpty()
        assertEquals(
            "User configuration import completed, but Burp could not export the applied options; " +
                "do not retry the import.",
            warning,
        )
        assertFalse("post-import export secret" in warning)
        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(any()) }
        verify(exactly = 2) { burpSuite.exportUserOptionsAsJson(*anyVararg()) }
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
