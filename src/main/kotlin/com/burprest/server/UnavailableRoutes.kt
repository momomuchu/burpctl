package com.burprest.server

import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route

/**
 * Keep the documented history surface distinguishable from an unknown route when database startup
 * fails. Only methods implemented by the live history routes are registered, so other methods still
 * receive the normal JSON 405 response.
 */
fun Route.unavailableHistoryRoutes() {
    route("/history") {
        get { historyUnavailable() }
        get("/sitemap") { historyUnavailable() }
        get("/{id}") { historyUnavailable() }
        post("/{id}/replay") { historyUnavailable() }
        delete { historyUnavailable() }
    }
}

private fun historyUnavailable(): Nothing =
    throw ServiceUnavailableException("history storage is unavailable")
