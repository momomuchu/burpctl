package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.InteractionFilter
import com.burprest.models.*
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class CollaboratorService(private val api: MontoyaApi) {

    private var client: CollaboratorClient? = null
    private val payloads = ConcurrentHashMap<String, burp.api.montoya.collaborator.CollaboratorPayload>()

    @Synchronized
    private fun ensureClient(): CollaboratorClient {
        if (client == null) {
            val collaborator = try {
                api.collaborator()
            } catch (e: Throwable) {
                throw IllegalStateException(
                    "Burp Collaborator API not available. This requires Burp Suite Professional. " +
                    "Community Edition does not support Collaborator.",
                    e,
                )
            } ?: throw IllegalStateException(
                "Burp Collaborator API returned null. This requires Burp Suite Professional " +
                "with Collaborator server configured (Project Options > Misc > Burp Collaborator Server)."
            )
            try {
                client = collaborator.createClient()
            } catch (e: Throwable) {
                throw IllegalStateException(
                    "Failed to create Collaborator client. Ensure Collaborator server is configured " +
                    "and reachable.",
                    e,
                )
            }
        }
        return client!!
    }

    fun generatePayload(): GeneratePayloadResponse {
        val c = ensureClient()
        val payload = try {
            c.generatePayload()
        } catch (e: Throwable) {
            throw IllegalStateException("Failed to generate Collaborator payload.", e)
        }
        val id = UUID.randomUUID().toString().take(8)
        payloads[id] = payload

        return GeneratePayloadResponse(
            payload = CollaboratorPayload(
                id = id,
                payload = payload.toString(),
                interactionId = id,
            ),
        )
    }

    fun generateBatch(count: Int): BatchGenerateResponse {
        val results = (1..count).map { generatePayload().payload }
        return BatchGenerateResponse(payloads = results)
    }

    // No catch on the poll calls: a poll failure is a real error, not "no interactions found"
    // (which would read as a successful empty poll). It propagates to the route/global handler.
    fun poll(): PollResponse {
        val c = ensureClient()
        val interactions = c.getAllInteractions()
        return PollResponse(
            found = interactions.isNotEmpty(),
            interactions = interactions.map { it.toModel() },
        )
    }

    fun pollById(id: String): PollResponse {
        val payload = payloads[id]
            ?: return PollResponse(found = false, interactions = emptyList())

        val c = ensureClient()
        val interactions = c.getInteractions(InteractionFilter.interactionPayloadFilter(payload.toString()))
        return PollResponse(
            found = interactions.isNotEmpty(),
            interactions = interactions.map { it.toModel() },
        )
    }

    private fun burp.api.montoya.collaborator.Interaction.toModel(): Interaction = Interaction(
        id = id().toString(),
        type = type().name,
        clientIp = clientIp().toString(),
        timestamp = Instant.now().toString(),
    )
}
