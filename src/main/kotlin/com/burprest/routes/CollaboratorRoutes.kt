package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.BatchGenerateRequest
import com.burprest.services.CollaboratorPayloadNotFoundException
import com.burprest.services.CollaboratorProviderException
import com.burprest.services.CollaboratorService
import com.burprest.services.CollaboratorUnavailableException
import com.burprest.server.NotFoundException
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.collaboratorRoutes(service: CollaboratorService) {
    route("/collaborator") {
        post("/generate") {
            try {
                // Keep the same singleton-list shape as /generate/batch.
                call.respond(ApiResponse.ok(service.generateBatch(1)))
            } catch (_: CollaboratorUnavailableException) {
                call.respondCollaboratorUnavailable()
            } catch (_: CollaboratorProviderException) {
                call.respondCollaboratorProviderFailure()
            }
        }

        post("/generate/batch") {
            val request = call.receive<BatchGenerateRequest>()
            require(request.count in 1..100) {
                "count must be between 1 and 100, got ${request.count}"
            }
            try {
                call.respond(ApiResponse.ok(service.generateBatch(request.count)))
            } catch (_: CollaboratorUnavailableException) {
                call.respondCollaboratorUnavailable()
            } catch (_: CollaboratorProviderException) {
                call.respondCollaboratorProviderFailure()
            }
        }

        get("/poll") {
            try {
                call.respond(ApiResponse.ok(service.poll()))
            } catch (_: CollaboratorUnavailableException) {
                call.respondCollaboratorUnavailable()
            } catch (_: CollaboratorProviderException) {
                call.respondCollaboratorProviderFailure()
            }
        }

        get("/poll/{id}") {
            val id = call.parameters["id"]
                ?: return@get call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse.error<Unit>("INVALID_PARAM", "Missing ID"),
                )
            try {
                call.respond(ApiResponse.ok(service.pollById(id)))
            } catch (_: CollaboratorPayloadNotFoundException) {
                // A status-page 404 handler can overwrite a route-authored 404 body. Raising the shared
                // typed exception preserves the payload-specific message through that final boundary.
                throw NotFoundException("Collaborator payload not found")
            } catch (_: CollaboratorUnavailableException) {
                call.respondCollaboratorUnavailable()
            } catch (_: CollaboratorProviderException) {
                call.respondCollaboratorProviderFailure()
            }
        }
    }
}

private suspend fun ApplicationCall.respondCollaboratorUnavailable() {
    respond(
        HttpStatusCode.ServiceUnavailable,
        ApiResponse.error<Unit>(
            "PRO_REQUIRED",
            "Burp Collaborator is unavailable. Burp Suite Professional is required.",
        ),
    )
}

private suspend fun ApplicationCall.respondCollaboratorProviderFailure() {
    respond(
        HttpStatusCode.ServiceUnavailable,
        ApiResponse.error<Unit>(
            "SERVICE_UNAVAILABLE",
            "Burp Collaborator provider operation failed",
        ),
    )
}
