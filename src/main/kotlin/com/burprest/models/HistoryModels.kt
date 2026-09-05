package com.burprest.models

import com.burprest.db.HistoryEntry
import com.burprest.db.SitemapRow
import kotlinx.serialization.Serializable

@Serializable
data class HistoryEntryResponse(
    val id: Long,
    val source: String,
    val method: String,
    val url: String,
    val host: String,
    val reqHeaders: List<HttpHeader>,
    val reqBody: String?,
    val statusCode: Int?,
    val resHeaders: List<HttpHeader>?,
    val resBody: String?,
    val durationMs: Long,
    val timestamp: String,
)

@Serializable
data class HistoryPageResponse(
    val entries: List<HistoryEntryResponse>,
    val total: Long,
    val page: Int,
    val pageSize: Int,
)

@Serializable
data class SitemapEntryResponse(
    val host: String,
    val path: String,
    val method: String,
    val lastSeen: String,
    val hitCount: Int,
)

@Serializable
data class SitemapListResponse(
    val entries: List<SitemapEntryResponse>,
    val total: Int,
)

fun HistoryEntry.toResponse() = HistoryEntryResponse(
    id = id, source = source, method = method, url = url, host = host,
    reqHeaders = reqHeaders, reqBody = reqBody, statusCode = statusCode,
    resHeaders = resHeaders, resBody = resBody, durationMs = durationMs, timestamp = timestamp,
)

fun SitemapRow.toResponse() = SitemapEntryResponse(
    host = host, path = path, method = method, lastSeen = lastSeen, hitCount = hitCount,
)

@Serializable
data class ReplayResponse(
    val original: HistoryEntryResponse,
    val replayed: HistoryEntryResponse?,
    /** Exact best-effort recording result for the completed target send. */
    val persistence: RepeaterPersistence,
)
