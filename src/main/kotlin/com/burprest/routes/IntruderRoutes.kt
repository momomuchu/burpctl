package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.CreateAttackRequest
import com.burprest.models.QuickFuzzRequest
import com.burprest.services.IntruderService
import io.ktor.http.Parameters
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

private fun Parameters.nonNegativeInt(name: String, default: Int): Int {
    val raw = this[name] ?: return default
    val value = raw.toIntOrNull() ?: throw IllegalArgumentException("$name must be an integer")
    require(value >= 0) { "$name must be >= 0" }
    return value
}

fun Route.intruderRoutes(service: IntruderService) {
    route("/intruder") {
        post("/attack/create") {
            val request = call.receive<CreateAttackRequest>()
            call.respond(ApiResponse.ok(service.createAttack(request)))
        }

        post("/attack/{id}/start") {
            val id = call.parameters["id"]!!
            call.respond(ApiResponse.ok(service.startAttack(id)))
        }

        get("/attack/{id}/status") {
            val id = call.parameters["id"]!!
            call.respond(ApiResponse.ok(service.attackStatus(id)))
        }

        get("/attack/{id}/results") {
            val id = call.parameters["id"]!!
            val offset = call.request.queryParameters.nonNegativeInt("offset", default = 0)
            val limit = call.request.queryParameters.nonNegativeInt("limit", default = 0)
            call.respond(ApiResponse.ok(service.attackResults(id, offset, limit)))
        }

        post("/attack/{id}/pause") {
            val id = call.parameters["id"]!!
            call.respond(ApiResponse.ok(service.pauseAttack(id)))
        }

        post("/attack/{id}/resume") {
            val id = call.parameters["id"]!!
            call.respond(ApiResponse.ok(service.resumeAttack(id)))
        }

        post("/attack/{id}/stop") {
            val id = call.parameters["id"]!!
            call.respond(ApiResponse.ok(service.stopAttack(id)))
        }

        post("/quick-fuzz") {
            val request = call.receive<QuickFuzzRequest>()
            call.respond(ApiResponse.ok(service.quickFuzz(request)))
        }
    }
}
