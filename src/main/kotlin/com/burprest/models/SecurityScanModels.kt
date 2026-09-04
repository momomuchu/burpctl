package com.burprest.models

import kotlinx.serialization.Serializable

// --- /scan/auth-bypass ---

@Serializable
data class AuthBypassRequest(
    val endpoints: List<String>,
    val baseUrl: String,
    val method: String = "GET",
)

@Serializable
data class AuthBypassProbeResult(
    val status: Int?,
    val length: Int,
    val durationMs: Long,
    val error: String? = null,
    val inconclusiveReason: String? = null,
    val inconclusive: Boolean = error != null || inconclusiveReason != null,
)

@Serializable
data class AuthBypassEndpointResult(
    val endpoint: String,
    val withAuth: AuthBypassProbeResult,
    val withoutAuth: AuthBypassProbeResult,
    val cookieOnly: AuthBypassProbeResult,
    val vulnerable: Boolean,
    val inconclusive: Boolean = false,
    val errors: List<String> = emptyList(),
)

@Serializable
data class AuthBypassResponse(
    val results: List<AuthBypassEndpointResult>,
    val totalScanned: Int,
    val vulnerableCount: Int,
    val inconclusiveCount: Int = 0,
)

// --- /scan/idor ---

@Serializable
data class IdorRequest(
    val endpoint: String,
    val param: String,
    val ownValues: List<String>,
    val targetValues: List<String>,
    val method: String = "GET",
    val body: String? = null,
    val extraHeaders: Map<String, String>? = null,
)

@Serializable
data class IdorProbeResult(
    val value: String,
    val status: Int?,
    val length: Int,
    val bodyPreview: String?,
    val sameAsBaseline: Boolean,
    val vulnerable: Boolean,
    val inconclusive: Boolean = false,
    val error: String? = null,
)

@Serializable
data class IdorResponse(
    val baseline: IdorProbeResult,
    val results: List<IdorProbeResult>,
    val vulnerableCount: Int,
    val inconclusiveCount: Int = 0,
    // [11] own values beyond the first are not tested (only the first is the baseline); surface them.
    val ignoredOwnValues: List<String> = emptyList(),
    // [08] heuristic limitation: cross-object access is flagged regardless of privilege direction.
    val note: String? = null,
)

// --- /scan/headers ---

@Serializable
data class HeadersBypassRequest(
    val url: String,
    val method: String = "GET",
    val body: String? = null,
    val protectedContentMarker: String? = null,
)

@Serializable
data class HeadersBypassResult(
    val header: String,
    val value: String,
    val status: Int?,
    val length: Int,
    val anomalous: Boolean,
    val vulnerable: Boolean = false,
    val inconclusive: Boolean = false,
    val error: String? = null,
)

@Serializable
data class HeadersBypassResponse(
    val baseline: AuthBypassProbeResult,
    val results: List<HeadersBypassResult>,
    val anomalousCount: Int,
    val vulnerableCount: Int = 0,
    val inconclusiveCount: Int = 0,
)

// --- /scan/cors ---

@Serializable
data class CorsRequest(
    val url: String,
    val method: String = "GET",
)

@Serializable
data class CorsProbeResult(
    val origin: String,
    val acao: String?,
    val acac: String?,
    val vulnerable: Boolean,
    val status: Int? = null,
    val inconclusive: Boolean = false,
    val error: String? = null,
)

@Serializable
data class CorsResponse(
    val results: List<CorsProbeResult>,
    val vulnerableCount: Int,
    val inconclusiveCount: Int = 0,
)

// --- /scan/endpoints ---

@Serializable
data class EndpointsScanRequest(
    val host: String,
    val tests: List<String> = listOf("auth-bypass", "method-switch"),
    val limit: Int = 100,
)

@Serializable
data class EndpointFinding(
    val endpoint: String,
    val method: String,
    val test: String,
    val detail: String,
    val severity: String,
)

@Serializable
data class EndpointProbeError(
    val endpoint: String,
    val method: String,
    val test: String,
    val probe: String,
    val status: Int? = null,
    val error: String,
)

@Serializable
data class EndpointsScanResponse(
    val scanned: Int,
    val findings: List<EndpointFinding>,
    val durationMs: Long,
    val source: String = "extension-h2-send-history",
    val sourceCounts: Map<String, Int> = emptyMap(),
    val errors: List<EndpointProbeError> = emptyList(),
    val inconclusiveCount: Int = errors.size,
)
