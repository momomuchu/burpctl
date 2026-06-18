package com.burprest.routes

import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.db.SitemapDao
import com.burprest.models.*
import com.burprest.services.RepeaterService
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.historyRoutes(historyDao: HistoryDao, sitemapDao: SitemapDao, repeaterService: RepeaterService) {
    route("/history") {
        get {
            val params = call.request.queryParameters
            val page = params["page"]?.toIntOrNull() ?: 0
            val pageSize = params["pageSize"]?.toIntOrNull() ?: 50
            // Validate before the values reach the SQL LIMIT/OFFSET — a negative page produced a
            // negative OFFSET and H2 leaked a raw SQLException (with schema internals) to the client.
            if (page < 0) throw IllegalArgumentException("page must be >= 0")
            if (pageSize !in 1..1000) throw IllegalArgumentException("pageSize must be between 1 and 1000")
            val filter = HistoryFilter(
                host = params["host"],
                method = params["method"],
                statusCode = params["statusCode"]?.toIntOrNull(),
                source = params["source"],
                search = params["search"],
                since = params["since"],
                until = params["until"],
                page = page,
                pageSize = pageSize,
            )
            val entries = historyDao.search(filter)
            val total = historyDao.count(filter)
            call.respond(
                ApiResponse.ok(
                    HistoryPageResponse(
                        entries = entries.map { it.toResponse() },
                        total = total,
                        page = filter.page,
                        pageSize = filter.pageSize,
                    )
                )
            )
        }

        get("/{id}") {
            val id = call.parameters["id"]?.toLongOrNull()
                ?: throw IllegalArgumentException("id must be a number")
            val entry = historyDao.getById(id)
                ?: throw IllegalArgumentException("History entry $id not found")
            call.respond(ApiResponse.ok(entry.toResponse()))
        }

        get("/sitemap") {
            val host = call.request.queryParameters["host"]
            val entries = sitemapDao.list(host)
            call.respond(
                ApiResponse.ok(
                    SitemapListResponse(
                        entries = entries.map { it.toResponse() },
                        total = entries.size,
                    )
                )
            )
        }

        post("/{id}/replay") {
            val id = call.parameters["id"]?.toLongOrNull()
                ?: throw IllegalArgumentException("id must be a number")
            val entry = historyDao.getById(id)
                ?: throw IllegalArgumentException("History entry $id not found")

            val sendReq = SendRequest(
                request = HttpRequestData(
                    method = entry.method,
                    url = entry.url,
                    headers = entry.reqHeaders,
                    body = entry.reqBody,
                )
            )
            val resp = repeaterService.send(sendReq)

            val replayedEntry = HistoryEntryResponse(
                id = 0,
                source = "replay",
                method = resp.request.method,
                url = resp.request.url,
                host = entry.host,
                reqHeaders = resp.request.headers,
                reqBody = resp.request.body,
                statusCode = resp.response.statusCode,
                resHeaders = resp.response.headers,
                resBody = resp.response.body,
                durationMs = resp.durationMs,
                timestamp = java.time.Instant.now().toString(),
            )

            call.respond(ApiResponse.ok(ReplayResponse(
                original = entry.toResponse(),
                replayed = replayedEntry,
            )))
        }

        delete {
            historyDao.clear()
            sitemapDao.clear()
            call.respond(ApiResponse.ok(mapOf("cleared" to true)))
        }
    }
}
