package com.burprest.models

import kotlinx.serialization.Serializable

// --- Comparer ---

@Serializable
data class ComparerDiffRequest(
    val requestId1: Int,
    val requestId2: Int,
    val compare: String = "response",
)

@Serializable
data class ComparerDiffResponse(
    val similarityPercent: Double,
    val differences: List<DiffSegment>,
)

@Serializable
data class DiffSegment(
    val type: String,
    val content1: String,
    val content2: String,
)

// --- Logger ---

@Serializable
data class LoggerEntriesResponse(
    val entries: List<LoggerEntry>,
    val total: Int,
)

@Serializable
data class LoggerEntry(
    val id: Int,
    val tool: String,
    val url: String,
    val method: String,
    val statusCode: Int? = null,
    val annotation: String? = null,
)

@Serializable
data class AnnotateRequest(
    val comment: String? = null,
    val highlight: String? = null,
)

@Serializable
data class LoggerExportRequest(
    val format: String = "json",
    val filter: String? = null,
)

// --- Search ---

@Serializable
data class SearchRequest(
    val query: String,
    val scope: String = "all",
    val caseSensitive: Boolean = false,
    val regex: Boolean = false,
)

@Serializable
data class SearchResponse(
    val results: List<SearchResult>,
    val total: Int,
)

@Serializable
data class SearchResult(
    val tool: String,
    val url: String,
    val match: String,
    val context: String? = null,
)

// --- Config DTOs live in ConfigModels.kt so nested JSON retains its types. ---

// --- Extensions ---

@Serializable
data class ExtensionInfo(
    val name: String,
    val enabled: Boolean,
    val filename: String? = null,
)

@Serializable
data class ExtensionsListResponse(
    val extensions: List<ExtensionInfo>,
    val total: Int,
    val scope: String = "current-extension-only",
)

// --- Health ---

@Serializable
data class HealthResponse(
    val status: String,
    val version: String,
    val uptime: Long,
    val burpVersion: String? = null,
)

@Serializable
data class VersionResponse(
    val version: String,
    val name: String,
    val burpVersion: String? = null,
)
