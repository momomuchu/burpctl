package com.burprest.routes

import com.burprest.models.AddScopeRequest
import com.burprest.models.ApiResponse
import com.burprest.server.requiredParameter
import com.burprest.services.TargetService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.targetRoutes(service: TargetService) {
    route("/target") {
        get("/sitemap") {
            call.respond(ApiResponse.ok(service.getSitemap(call.parameters["url"])))
        }

        get("/scope") {
            service.getScope()
        }

        post("/scope") {
            service.setScope()
        }

        post("/scope/add") {
            call.respond(ApiResponse.ok(service.addToScope(call.receive<AddScopeRequest>())))
        }

        post("/scope/remove") {
            call.respond(ApiResponse.ok(service.removeFromScope(call.receive<AddScopeRequest>())))
        }

        get("/scope/check") {
            val url = requiredParameter(call.parameters["url"], "url")
            call.respond(ApiResponse.ok(service.isInScope(url)))
        }
    }
}
