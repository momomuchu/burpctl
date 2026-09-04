package com.burprest.services

import burp.api.montoya.MontoyaApi
import com.burprest.models.ConfigResponse
import com.burprest.models.ConfigUpdateRequest
import com.burprest.models.ExtensionInfo
import com.burprest.models.ExtensionsListResponse
import com.burprest.server.InvalidParamException
import com.burprest.server.ServiceUnavailableException
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

class ConfigService(private val api: MontoyaApi) {

    private val strictJson = Json {
        isLenient = false
        ignoreUnknownKeys = false
    }

    fun getProjectConfig(): ConfigResponse = ConfigResponse(
        config = exportOptions("project") { api.burpSuite().exportProjectOptionsAsJson() },
    )

    fun updateProjectConfig(request: ConfigUpdateRequest): ConfigUpdateResponse {
        val config = requireConfigObject(request)
        validateImportShape(config, getProjectConfig().config)
        try {
            api.burpSuite().importProjectOptionsFromJson(config.toString())
        } catch (cause: Exception) {
            throw ServiceUnavailableException("Burp could not import project options", cause)
        }
        return reportAppliedImport("Project", emptyList(), ::getProjectConfig)
    }

    fun getUserConfig(): ConfigResponse = ConfigResponse(
        config = exportOptions("user") { api.burpSuite().exportUserOptionsAsJson() },
    )

    fun updateUserConfig(request: ConfigUpdateRequest): ConfigUpdateResponse {
        val requestedConfig = requireConfigObject(request)
        val safeImport = excludeExtensionInventory(requestedConfig)
        val exportedShape = excludeExtensionInventory(getUserConfig().config).config
        validateImportShape(safeImport.config, exportedShape)
        try {
            api.burpSuite().importUserOptionsFromJson(safeImport.config.toString())
        } catch (cause: Exception) {
            throw ServiceUnavailableException("Burp could not import user options", cause)
        }
        return reportAppliedImport("User", safeImport.excludedPaths, ::getUserConfig)
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

    private fun reportAppliedImport(
        kind: String,
        excludedPaths: List<String>,
        export: () -> ConfigResponse,
    ): ConfigUpdateResponse = try {
        val postImport = export()
        ConfigUpdateResponse(
            applied = true,
            config = postImport.config,
            excludedPaths = excludedPaths,
            warning = null,
        )
    } catch (_: ServiceUnavailableException) {
        val warning = "$kind configuration import completed, but Burp could not export the applied options; " +
            "do not retry the import."
        runCatching { api.logging().logToError("[burp-rest] $warning") }
        ConfigUpdateResponse(
            applied = true,
            config = null,
            excludedPaths = excludedPaths,
            warning = warning,
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

/**
 * Result of a completed import. A null [config] means only the secondary post-import observation
 * failed; [applied] and [warning] preserve the primary effect and tell the caller not to retry it.
 */
@Serializable
data class ConfigUpdateResponse(
    val applied: Boolean,
    val config: JsonObject?,
    val excludedPaths: List<String>,
    val warning: String?,
)

private data class SafeUserImport(
    val config: JsonObject,
    val excludedPaths: List<String>,
)

private fun excludeExtensionInventory(config: JsonObject): SafeUserImport {
    val userOptions = config[USER_OPTIONS] as? JsonObject
    val extender = userOptions?.get(EXTENDER) as? JsonObject
    val hasInventory = extender?.containsKey(EXTENSIONS) == true
    return if (userOptions != null && extender != null && hasInventory) {
        // Re-importing Burp's extension inventory reloads this extension while its own request is in
        // flight, destroying in-memory state before any warning can reach the caller. Preserve every
        // sibling option while excluding only the inventory that owns extension lifecycle.
        val safeExtender = JsonObject(extender - EXTENSIONS)
        val safeUserOptions = JsonObject(userOptions + (EXTENDER to safeExtender))
        val safeConfig = JsonObject(config + (USER_OPTIONS to safeUserOptions))
        SafeUserImport(safeConfig, listOf(EXTENSION_INVENTORY_PATH))
    } else {
        SafeUserImport(config, emptyList())
    }
}

private fun validateImportShape(requested: JsonObject, exported: JsonObject) {
    validateImportNode(requested, exported, "config")
}

private fun validateImportNode(requested: JsonElement, exported: JsonElement, path: String) {
    if (!sameJsonKind(requested, exported)) {
        val message = if (exported is JsonNull) {
            "$path cannot be changed because its exported type is unknown"
        } else {
            "$path must be ${jsonKind(exported)}"
        }
        throw InvalidParamException(message)
    }
    when {
        requested is JsonObject && exported is JsonObject -> validateObject(requested, exported, path)
        requested is JsonArray && exported is JsonArray -> validateArray(requested, exported, path)
    }
}

private fun validateObject(requested: JsonObject, exported: JsonObject, path: String) {
    requested.forEach { (name, value) ->
        val childPath = "$path.$name"
        val exportedValue = exported[name]
            ?: throw InvalidParamException("config contains unknown option '$childPath'")
        validateImportNode(value, exportedValue, childPath)
    }
}

private fun validateArray(requested: JsonArray, exported: JsonArray, path: String) {
    if (requested.isEmpty()) return
    if (exported.isEmpty()) {
        throw InvalidParamException("$path cannot be validated because the exported option list is empty")
    }
    requested.forEachIndexed { index, value ->
        validateArrayItem(value, exported, index, "$path[$index]")
    }
}

private fun validateArrayItem(value: JsonElement, exported: JsonArray, index: Int, path: String) {
    val candidates = buildList {
        exported.getOrNull(index)
            ?.takeIf { sameJsonKind(value, it) }
            ?.let(::add)
        exported.filterTo(this) { sameJsonKind(value, it) }
    }.distinct()
    if (candidates.isEmpty()) {
        throw InvalidParamException("$path must match the exported item type")
    }

    var firstFailure: InvalidParamException? = null
    candidates.forEach { candidate ->
        try {
            validateImportNode(value, candidate, path)
            return
        } catch (failure: InvalidParamException) {
            if (firstFailure == null) firstFailure = failure
        }
    }
    throw requireNotNull(firstFailure)
}

private fun sameJsonKind(left: JsonElement, right: JsonElement): Boolean =
    jsonKind(left) == jsonKind(right)

private fun jsonKind(value: JsonElement): String = when (value) {
    is JsonNull -> "null"
    is JsonObject -> "an object"
    is JsonArray -> "an array"
    is JsonPrimitive -> when {
        value.isString -> "a string"
        value.booleanOrNull != null -> "a boolean"
        value.longOrNull != null -> "an integer"
        value.doubleOrNull != null -> "a fractional number"
        else -> "a JSON primitive"
    }
}

private const val USER_OPTIONS = "user_options"
private const val EXTENDER = "extender"
private const val EXTENSIONS = "extensions"
private const val EXTENSION_INVENTORY_PATH = "user_options.extender.extensions"
