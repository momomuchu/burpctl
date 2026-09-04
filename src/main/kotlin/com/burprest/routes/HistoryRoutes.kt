package com.burprest.routes

import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.db.SitemapDao
import com.burprest.models.*
import com.burprest.server.InvalidParamException
import com.burprest.server.intParameter
import com.burprest.server.optionalIntParameter
import com.burprest.services.RepeaterService
import io.ktor.http.Parameters
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

/**
 * Build a [HistoryFilter] from raw query parameters, rejecting every malformed value.
 *
 * Malformed input must never be treated as absence: a mistyped `page`/`pageSize`/`statusCode` used
 * to be silently coerced to a default, so the caller received HTTP 200 for a filter the server had
 * quietly discarded. Timestamps are validated for shape only — the failure message is authored here
 * and never carries the parser's identity or the supplied value back to the client.
 */
internal fun historyFilterFrom(params: Parameters): HistoryFilter = HistoryFilter(
    host = params["host"],
    method = params["method"],
    statusCode = optionalIntParameter(params["statusCode"], "statusCode"),
    source = params["source"],
    search = params["search"],
    since = isoInstantParameter(params["since"], "since"),
    until = isoInstantParameter(params["until"], "until"),
    // Validate before the values reach the SQL LIMIT/OFFSET — a negative page produced a negative
    // OFFSET and H2 leaked a raw SQLException (with schema internals) to the client.
    page = intParameter(params["page"], "page", default = 0, range = 0..Int.MAX_VALUE),
    pageSize = intParameter(params["pageSize"], "pageSize", default = 50, range = 1..1000),
)

/**
 * Validate an optional ISO-8601 instant. Stored timestamps are compared lexicographically, so the
 * validated text is returned unchanged; only its shape is checked.
 */
private fun isoInstantParameter(value: String?, name: String): String? = value?.also {
    runCatching { java.time.Instant.parse(it) }
        .onFailure { throw InvalidParamException("$name must be an ISO-8601 instant") }
}

fun Route.historyRoutes(historyDao: HistoryDao, sitemapDao: SitemapDao, repeaterService: RepeaterService) {
    route("/history") {
        get {
            val filter = historyFilterFrom(call.request.queryParameters)
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
            val httpResponse = resp.response

            val replayedEntry = HistoryEntryResponse(
                id = 0,
                source = "replay",
                method = resp.request.method,
                url = resp.request.url,
                host = entry.host,
                reqHeaders = resp.request.headers,
                reqBody = resp.request.body,
                statusCode = httpResponse.statusCode,
                resHeaders = httpResponse.headers,
                resBody = httpResponse.body,
                durationMs = resp.durationMs,
                timestamp = java.time.Instant.now().toString(),
            )

            call.respond(ApiResponse.ok(ReplayResponse(
                original = entry.toResponse(),
                replayed = replayedEntry,
            )))
        }

        delete {
            historyDao.clearWithSitemap(sitemapDao)
            call.respond(ApiResponse.ok(mapOf("cleared" to true)))
        }
    }
}
