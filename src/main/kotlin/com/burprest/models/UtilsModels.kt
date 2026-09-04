package com.burprest.models

import kotlinx.serialization.Serializable

// --- /utils/diff ---

@Serializable
data class DiffTarget(
    val method: String = "GET",
    val url: String,
    val body: String? = null,
    val extraHeaders: Map<String, String>? = null,
)

@Serializable
data class DiffRequest(
    val a: DiffTarget,
    val b: DiffTarget,
)

@Serializable
data class HeaderDiff(
    val name: String,
    val aValue: String?,
    val bValue: String?,
    /** All values, in response order, so duplicate response headers are not discarded. */
    val aValues: List<String> = aValue?.let(::listOf) ?: emptyList(),
    val bValues: List<String> = bValue?.let(::listOf) ?: emptyList(),
) {
    constructor(name: String, aValues: List<String>, bValues: List<String>) : this(
        name = name,
        aValue = aValues.firstOrNull(),
        bValue = bValues.firstOrNull(),
        aValues = aValues,
        bValues = bValues,
    )
}

@Serializable
data class DiffResponse(
    val statusMatch: Boolean,
    val statusA: Int,
    val statusB: Int,
    val lengthA: Int,
    val lengthB: Int,
    val lengthDiff: Int,
    val headerDiffs: List<HeaderDiff>,
    val bodyDiff: String?,
)

// --- /utils/extract-endpoints ---

@Serializable
data class ExtractEndpointsRequest(
    val url: String,
)

@Serializable
data class BundleFetchFailure(
    val url: String,
    val error: String,
)

@Serializable
data class ExtractEndpointsResponse(
    val endpoints: List<String>,
    val total: Int,
    /** Number of script references found before the ten-bundle safety cap. */
    val bundlesDiscovered: Int = 0,
    /** Number of bundle fetches actually attempted. */
    val bundlesAttempted: Int = 0,
    /** Number of attempted bundle fetches that returned a response. */
    val bundlesFetched: Int = 0,
    /** Number of attempted bundle fetches that could not produce a response. */
    val bundlesFailed: Int = 0,
    /** Per-bundle failures, rather than silently presenting a partial result as complete. */
    val failures: List<BundleFetchFailure> = emptyList(),
)
