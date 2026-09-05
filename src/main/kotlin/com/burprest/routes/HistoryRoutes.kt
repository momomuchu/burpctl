package com.burprest.routes

import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.db.SitemapDao
import com.burprest.db.StorageException
import com.burprest.models.*
import com.burprest.server.InvalidParamException
import com.burprest.server.NotFoundException
import com.burprest.server.ServiceUnavailableException
import com.burprest.server.intParameter
import com.burprest.server.optionalIntParameter
import com.burprest.server.requiredLongParameter
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
internal fun historyFilterFrom(params: Parameters): HistoryFilter {
    val since = isoInstantParameter(singleQueryParameter(params, "since"), "since")
    val until = isoInstantParameter(singleQueryParameter(params, "until"), "until")
    if (since != null && until != null && java.time.Instant.parse(since) > java.time.Instant.parse(until)) {
        throw InvalidParamException("since must not be after until")
    }
    return HistoryFilter(
        host = nonBlankQueryParameter(params, "host"),
        method = nonBlankQueryParameter(params, "method"),
        statusCode = optionalIntParameter(
            singleQueryParameter(params, "statusCode"),
            "statusCode",
            range = 100..599,
        ),
        source = nonBlankQueryParameter(params, "source"),
        search = nonBlankQueryParameter(params, "search"),
        since = since,
        until = until,
        // Validate before the values reach the SQL LIMIT/OFFSET — a negative page produced a negative
        // OFFSET and H2 leaked a raw SQLException (with schema internals) to the client.
        page = intParameter(singleQueryParameter(params, "page"), "page", default = 0, range = 0..Int.MAX_VALUE),
        pageSize = intParameter(singleQueryParameter(params, "pageSize"), "pageSize", default = 50, range = 1..1000),
    )
}

private fun singleQueryParameter(params: Parameters, name: String): String? {
    val values = params.getAll(name).orEmpty()
    if (values.size > 1) throw InvalidParamException("$name must be supplied at most once")
    return values.singleOrNull()
}

private fun nonBlankQueryParameter(params: Parameters, name: String): String? =
    singleQueryParameter(params, name)?.also { value ->
        if (value.isBlank()) throw InvalidParamException("$name must not be blank")
    }

/**
 * Validate an optional ISO-8601 instant. Stored timestamps are compared lexicographically, so the
 * validated text is returned unchanged; only its shape is checked.
 */
private fun isoInstantParameter(value: String?, name: String): String? = value?.also {
    runCatching { java.time.Instant.parse(it) }
        .onFailure { throw InvalidParamException("$name must be an ISO-8601 instant") }
}

private fun historyEntryId(value: String?): Long =
    requiredLongParameter(value, "id", range = 1..Long.MAX_VALUE)

private fun replayReadbackFailure(cause: Throwable? = null) = ServiceUnavailableException(
    "target send completed and persistence reported success, " +
        "but the replay history row is unavailable; do not retry the target send",
    cause,
)

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
            val id = historyEntryId(call.parameters["id"])
            val entry = historyDao.getById(id)
                ?: throw NotFoundException("History entry $id not found")
            call.respond(ApiResponse.ok(entry.toResponse()))
        }

        get("/sitemap") {
            val host = nonBlankQueryParameter(call.request.queryParameters, "host")
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
            val id = historyEntryId(call.parameters["id"])
            val entry = historyDao.getById(id)
                ?: throw NotFoundException("History entry $id not found")

            val sendReq = SendRequest(
                request = HttpRequestData(
                    method = entry.method,
                    url = entry.url,
                    headers = entry.reqHeaders,
                    body = entry.reqBody,
                )
            )
            val resp = repeaterService.send(sendReq)
            // RepeaterService owns persistence and records this operation as source "repeater". Project
            // the row it actually created instead of inventing id=0/source="replay". When optional
            // persistence did not create a row, retain the completed send and expose no fake identity.
            val replayedEntry = resp.persistence.historyId?.let { historyId ->
                val persisted = try {
                    historyDao.getById(historyId)
                } catch (failure: StorageException) {
                    throw replayReadbackFailure(failure)
                }
                persisted?.toResponse() ?: throw replayReadbackFailure()
            }

            call.respond(
                ApiResponse.ok(
                    ReplayResponse(
                        original = entry.toResponse(),
                        replayed = replayedEntry,
                        persistence = resp.persistence,
                    )
                )
            )
        }

        delete {
            historyDao.clearWithSitemap(sitemapDao)
            call.respond(ApiResponse.ok(mapOf("cleared" to true)))
        }
    }
}
