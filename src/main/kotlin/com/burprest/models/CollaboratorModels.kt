package com.burprest.models

import kotlinx.serialization.Serializable

@Serializable
data class CollaboratorPayload(
    val id: String,
    val payload: String,
    val interactionId: String,
)

@Serializable
data class GeneratePayloadResponse(
    val payload: CollaboratorPayload,
)

@Serializable
data class BatchGenerateRequest(
    val count: Int = 1,
)

@Serializable
data class BatchGenerateResponse(
    val payloads: List<CollaboratorPayload>,
)

@Serializable
data class Interaction(
    val id: String,
    val type: String,
    val clientIp: String? = null,
    val timestamp: String? = null,
    val details: Map<String, String> = emptyMap(),
    val clientPort: Int? = null,
)

@Serializable
data class PollResponse(
    val found: Boolean,
    val interactions: List<Interaction>,
    val queriedPayloadId: String? = null,
)
