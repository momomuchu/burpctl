package com.burprest.models

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** A real Burp options export plus any request paths deliberately excluded from an import. */
@Serializable
data class ConfigResponse(
    val config: JsonObject,
    val excludedPaths: List<String> = emptyList(),
)

/** JsonElement permits the service to reject a non-object explicitly before calling Montoya import. */
@Serializable
data class ConfigUpdateRequest(
    val config: JsonElement,
)
