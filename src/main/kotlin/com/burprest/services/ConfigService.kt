package com.burprest.services

import burp.api.montoya.MontoyaApi
import com.burprest.models.ConfigResponse
import com.burprest.models.ConfigUpdateRequest
import com.burprest.models.ExtensionInfo
import com.burprest.models.ExtensionsListResponse
import com.burprest.server.InvalidParamException
import com.burprest.server.ServiceUnavailableException
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

class ConfigService(private val api: MontoyaApi) {

    private val strictJson = Json {
        isLenient = false
        ignoreUnknownKeys = false
    }

    fun getProjectConfig(): ConfigResponse = ConfigResponse(
        config = exportOptions("project") { api.burpSuite().exportProjectOptionsAsJson() },
    )

    fun updateProjectConfig(request: ConfigUpdateRequest): ConfigResponse {
        val config = requireConfigObject(request)
        try {
            api.burpSuite().importProjectOptionsFromJson(config.toString())
        } catch (cause: Exception) {
            throw ServiceUnavailableException("Burp could not import project options", cause)
        }
        return getProjectConfig()
    }

    fun getUserConfig(): ConfigResponse = ConfigResponse(
        config = exportOptions("user") { api.burpSuite().exportUserOptionsAsJson() },
    )

    fun updateUserConfig(request: ConfigUpdateRequest): ConfigResponse {
        val config = requireConfigObject(request)
        try {
            api.burpSuite().importUserOptionsFromJson(config.toString())
        } catch (cause: Exception) {
            throw ServiceUnavailableException("Burp could not import user options", cause)
        }
        return getUserConfig()
    }

    fun getExtensions(): ExtensionsListResponse {
        // Montoya exposes only this extension. Return exactly that one object rather than implying
        // visibility into other installed extensions.
        val filename = try {
            api.extension().filename()
        } catch (cause: Exception) {
            throw ServiceUnavailableException("current extension information is unavailable", cause)
        }
        return ExtensionsListResponse(
            extensions = listOf(
                ExtensionInfo(
                    name = "Burp REST API",
                    enabled = true,
                    filename = filename,
                ),
            ),
            total = 1,
        )
    }

    private fun requireConfigObject(request: ConfigUpdateRequest): JsonObject =
        request.config as? JsonObject
            ?: throw InvalidParamException("config must be a JSON object")

    private fun exportOptions(kind: String, export: () -> String): JsonObject {
        val raw = try {
            export()
        } catch (cause: Exception) {
            throw ServiceUnavailableException("Burp could not export $kind options", cause)
        }
        val parsed = try {
            strictJson.parseToJsonElement(raw)
        } catch (cause: SerializationException) {
            throw ServiceUnavailableException("Burp returned an invalid $kind options export", cause)
        }
        return parsed as? JsonObject
            ?: throw ServiceUnavailableException("Burp returned a non-object $kind options export")
    }
}
