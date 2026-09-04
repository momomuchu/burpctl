package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.ConfigUpdateRequest
import com.burprest.services.ConfigService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.configRoutes(service: ConfigService) {
    route("/config") {
        get("/project") {
            call.respond(ApiResponse.ok(service.getProjectConfig()))
        }

        put("/project") {
            call.respond(ApiResponse.ok(service.updateProjectConfig(call.receive<ConfigUpdateRequest>())))
        }

        get("/user") {
            call.respond(ApiResponse.ok(service.getUserConfig()))
        }

        put("/user") {
            call.respond(ApiResponse.ok(service.updateUserConfig(call.receive<ConfigUpdateRequest>())))
        }
    }

    get("/extensions") {
        call.respond(ApiResponse.ok(service.getExtensions()))
    }
}
