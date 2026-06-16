package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.InterceptStatusResponse
import com.burprest.services.ProxyService
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.proxyRoutes(service: ProxyService) {
    route("/proxy") {
        get("/history") {
            val limit = call.parameters["limit"]?.toIntOrNull()
            val offset = call.parameters["offset"]?.toIntOrNull()
            val filterHost = call.parameters["host"]
            call.respond(ApiResponse.ok(service.getHistory(limit, offset, filterHost)))
        }

        get("/history/{id}") {
            val id = call.parameters["id"]?.toIntOrNull()
                ?: return@get call.respond(ApiResponse.error<Unit>("INVALID_PARAM", "Invalid ID"))
            call.respond(ApiResponse.ok(service.getHistoryEntry(id)))
        }

        get("/websocket/history") {
            call.respond(ApiResponse.ok(service.getWebSocketHistory()))
        }

        get("/intercept") {
            // Montoya doesn't expose live status; report the last API-driven state.
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = service.isIntercepting())))
        }

        post("/intercept/enable") {
            service.enableIntercept()
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = true)))
        }

        post("/intercept/disable") {
            service.disableIntercept()
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = false)))
        }

        post("/intercept/forward") {
            // Forward requires intercepted message handling — stub
            call.respond(ApiResponse.ok(mapOf("forwarded" to true)))
        }

        post("/intercept/drop") {
            call.respond(ApiResponse.ok(mapOf("dropped" to true)))
        }
    }
}
