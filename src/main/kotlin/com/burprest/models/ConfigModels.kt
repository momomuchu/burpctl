package com.burprest.models

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** A real Burp options export. Values remain typed and arbitrarily nested. */
@Serializable
data class ConfigResponse(
    val config: JsonObject,
)

/** JsonElement permits the service to reject a non-object explicitly before calling Montoya import. */
@Serializable
data class ConfigUpdateRequest(
    val config: JsonElement,
)
