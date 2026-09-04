package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.HealthResponse
import com.burprest.models.VersionResponse
import io.ktor.http.ContentType
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

private val OPENAPI_SPEC: String by lazy {
    requireNotNull(object {}.javaClass.getResource("/openapi.json")) {
        "openapi.json resource is missing"
    }.readText()
}

fun Route.healthRoutes(startTime: Long, burpVersion: String? = null) {
    get("/health") {
        val uptime = (System.currentTimeMillis() - startTime) / 1000
        call.respond(
            ApiResponse.ok(
                HealthResponse(
                    status = "ok",
                    version = "0.1.0",
                    uptime = uptime,
                    burpVersion = burpVersion,
                )
            )
        )
    }

    get("/version") {
        call.respond(
            ApiResponse.ok(
                VersionResponse(
                    version = "0.1.0",
                    name = "burp-rest-extension",
                    burpVersion = burpVersion,
                )
            )
        )
    }

    get("/docs") {
        call.respondText(OPENAPI_SPEC, ContentType.Application.Json)
    }
}
