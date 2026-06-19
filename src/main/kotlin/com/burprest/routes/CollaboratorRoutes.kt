package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.BatchGenerateRequest
import com.burprest.services.CollaboratorService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.collaboratorRoutes(service: CollaboratorService) {
    route("/collaborator") {
        post("/generate") {
            try {
                // Return the same {payloads:[...]} shape as /generate/batch (a singleton list) so
                // the client reads one stable shape regardless of --count.
                call.respond(ApiResponse.ok(service.generateBatch(1)))
            } catch (_: Throwable) {
                call.respond(HttpStatusCode.ServiceUnavailable, ApiResponse.error<Unit>(
                    "PRO_REQUIRED",
                    "Burp Collaborator not available. Requires Burp Suite Professional."
                ))
            }
        }

        post("/generate/batch") {
            val request = call.receive<BatchGenerateRequest>()
            // Validate before the try so a bad count is a clean 400 (global handler), not the
            // local PRO_REQUIRED catch below.
            require(request.count in 1..100) { "count must be between 1 and 100, got ${request.count}" }
            try {
                call.respond(ApiResponse.ok(service.generateBatch(request.count)))
            } catch (_: Throwable) {
                call.respond(HttpStatusCode.ServiceUnavailable, ApiResponse.error<Unit>(
                    "PRO_REQUIRED",
                    "Burp Collaborator not available. Requires Burp Suite Professional."
                ))
            }
        }

        get("/poll") {
            try {
                call.respond(ApiResponse.ok(service.poll()))
            } catch (_: Throwable) {
                call.respond(HttpStatusCode.ServiceUnavailable, ApiResponse.error<Unit>(
                    "PRO_REQUIRED",
                    "Burp Collaborator not available. Requires Burp Suite Professional."
                ))
            }
        }

        get("/poll/{id}") {
            val id = call.parameters["id"]
                ?: return@get call.respond(ApiResponse.error<Unit>("INVALID_PARAM", "Missing ID"))
            try {
                call.respond(ApiResponse.ok(service.pollById(id)))
            } catch (_: Throwable) {
                call.respond(HttpStatusCode.ServiceUnavailable, ApiResponse.error<Unit>(
                    "PRO_REQUIRED",
                    "Burp Collaborator not available. Requires Burp Suite Professional."
                ))
            }
        }
    }
}
