package com.burprest.models

import kotlinx.serialization.Serializable

@Serializable
data class PayloadPosition(
    val start: Int,
    val end: Int,
    val name: String,
)

@Serializable
data class AttackOptions(
    val followRedirects: Boolean = true,
    val maxRetries: Int = 0,
    val throttleMs: Long = 0,
)

@Serializable
data class CreateAttackRequest(
    val requestId: Int? = null,
    val request: HttpRequestData? = null,
    val attackType: String = "sniper",
    val positions: List<PayloadPosition> = emptyList(),
    val payloads: Map<String, List<String>> = emptyMap(),
    val options: AttackOptions = AttackOptions(),
)

@Serializable
data class CreateAttackResponse(
    val attackId: String,
    val status: String,
)

@Serializable
data class AttackStatusResponse(
    val attackId: String,
    val status: String,
    val progress: Int = 0,
    val requestCount: Int = 0,
    val errorCount: Int = 0,
    val isComplete: Boolean = false,
    val error: String? = null,
    val errorCode: String? = null,
)

@Serializable
data class AttackResultEntry(
    val index: Int,
    val payload: String,
    val statusCode: Int,
    val length: Int,
    val durationMs: Long,
    val positionName: String? = null,
    val error: String? = null,
    val errorCode: String? = null,
    val contentType: String? = null,
    val bodyPreview: String? = null,
    val anomalous: Boolean = false,
)

@Serializable
data class AttackResultsResponse(
    val attackId: String,
    val results: List<AttackResultEntry>,
    val total: Int,
)

@Serializable
data class QuickFuzzRequest(
    val requestId: Int? = null,
    val request: HttpRequestData? = null,
    val param: String,
    val payloads: List<String>,
    val options: AttackOptions = AttackOptions(),
)

@Serializable
data class QuickFuzzResponse(
    val results: List<AttackResultEntry>,
    val total: Int,
    val durationMs: Long,
    val baseline: QuickFuzzBaseline? = null,
)

@Serializable
data class QuickFuzzBaseline(
    val statusCode: Int,
    val length: Int,
    val contentType: String?,
    val error: String? = null,
    val errorCode: String? = null,
)
