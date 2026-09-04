package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.ScanRequest
import com.burprest.server.requiredParameter
import com.burprest.services.ScannerService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.scannerRoutes(service: ScannerService) {
    route("/scanner") {
        post("/crawl") {
            call.respond(ApiResponse.ok(service.crawl(call.receive<ScanRequest>())))
        }

        post("/audit") {
            call.respond(ApiResponse.ok(service.audit(call.receive<ScanRequest>())))
        }

        post("/crawl-and-audit") {
            service.crawlAndAudit()
        }

        get("/{id}/status") {
            val id = requiredParameter(call.parameters["id"], "id")
            call.respond(ApiResponse.ok(service.status(id)))
        }

        get("/{id}/issues") {
            val id = requiredParameter(call.parameters["id"], "id")
            call.respond(ApiResponse.ok(service.issues(id)))
        }

        post("/{id}/pause") {
            val id = requiredParameter(call.parameters["id"], "id")
            service.pause(id)
        }

        post("/{id}/resume") {
            val id = requiredParameter(call.parameters["id"], "id")
            service.resume(id)
        }

        post("/{id}/stop") {
            val id = requiredParameter(call.parameters["id"], "id")
            call.respond(ApiResponse.ok(service.stop(id)))
        }

        get("/issue-definitions") {
            call.respond(ApiResponse.ok(service.issueDefinitions()))
        }
    }
}
