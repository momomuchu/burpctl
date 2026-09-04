package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.InterceptStatusResponse
import com.burprest.server.optionalIntParameter
import com.burprest.server.requiredIntParameter
import com.burprest.services.ProxyService
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.proxyRoutes(service: ProxyService) {
    route("/proxy") {
        get("/history") {
            val limit = optionalIntParameter(call.parameters["limit"], "limit", 1..Int.MAX_VALUE)
            val offset = optionalIntParameter(call.parameters["offset"], "offset", 0..Int.MAX_VALUE)
            val filterHost = call.parameters["host"]
            call.respond(ApiResponse.ok(service.getHistory(limit, offset, filterHost)))
        }

        get("/history/{id}") {
            val id = requiredIntParameter(call.parameters["id"], "id", 0..Int.MAX_VALUE)
            call.respond(ApiResponse.ok(service.getHistoryEntry(id)))
        }

        get("/websocket/history") {
            call.respond(ApiResponse.ok(service.getWebSocketHistory()))
        }

        get("/intercept") {
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = service.isIntercepting())))
        }

        post("/intercept/enable") {
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = service.enableIntercept())))
        }

        post("/intercept/disable") {
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = service.disableIntercept())))
        }

        post("/intercept/forward") {
            service.forwardInterceptedMessage()
        }

        post("/intercept/drop") {
            service.dropInterceptedMessage()
        }
    }
}
