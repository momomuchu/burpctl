@file:OptIn(ExperimentalSerializationApi::class)

package com.burprest.routes

import com.burprest.EXTENSION_VERSION
import com.burprest.models.AddScopeRequest
import com.burprest.models.ApiError
import com.burprest.models.AttackOptions
import com.burprest.models.AttackResultsResponse
import com.burprest.models.AttackStatusResponse
import com.burprest.models.AuthBypassRequest
import com.burprest.models.AuthBypassResponse
import com.burprest.models.AuthenticatedRequest
import com.burprest.models.AuthenticatedResponse
import com.burprest.models.BatchAuthenticatedRequest
import com.burprest.models.BatchAuthenticatedResponse
import com.burprest.models.BatchGenerateRequest
import com.burprest.models.BatchGenerateResponse
import com.burprest.models.BatchSendRequest
import com.burprest.models.BatchSendResponse
import com.burprest.models.ConfigResponse
import com.burprest.models.ConfigUpdateRequest
import com.burprest.models.CookieJarResponse
import com.burprest.models.CorsRequest
import com.burprest.models.CorsResponse
import com.burprest.models.CreateAttackRequest
import com.burprest.models.CreateAttackResponse
import com.burprest.models.CreateTabRequest
import com.burprest.models.CreateTabResponse
import com.burprest.models.DecodeRequest
import com.burprest.models.DecodeResponse
import com.burprest.models.DiffRequest
import com.burprest.models.DiffResponse
import com.burprest.models.DiffTarget
import com.burprest.models.EncodeRequest
import com.burprest.models.EncodeResponse
import com.burprest.models.EndpointsScanRequest
import com.burprest.models.EndpointsScanResponse
import com.burprest.models.ExtensionsListResponse
import com.burprest.models.ExtractEndpointsRequest
import com.burprest.models.ExtractEndpointsResponse
import com.burprest.models.HashRequest
import com.burprest.models.HashResponse
import com.burprest.models.HeadersBypassRequest
import com.burprest.models.HeadersBypassResponse
import com.burprest.models.HealthResponse
import com.burprest.models.HistoryEntryResponse
import com.burprest.models.HistoryPageResponse
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.IdorRequest
import com.burprest.models.IdorResponse
import com.burprest.models.InterceptStatusResponse
import com.burprest.models.PayloadPosition
import com.burprest.models.PollResponse
import com.burprest.models.ProxyEntry
import com.burprest.models.ProxyHistoryResponse
import com.burprest.models.QuickFuzzRequest
import com.burprest.models.QuickFuzzResponse
import com.burprest.models.ReplayResponse
import com.burprest.models.RequestModifications
import com.burprest.models.ScanConfig
import com.burprest.models.ScanIssuesResponse
import com.burprest.models.ScanRequest
import com.burprest.models.ScanStartResponse
import com.burprest.models.ScanStatusResponse
import com.burprest.models.ScopeCheckResponse
import com.burprest.models.SendRequest
import com.burprest.models.SendResponse
import com.burprest.models.SessionInfo
import com.burprest.models.SitemapListResponse
import com.burprest.models.SitemapResponse
import com.burprest.models.SmartDecodeResponse
import com.burprest.models.VersionResponse
import com.burprest.models.WebSocketHistoryResponse
import com.burprest.services.ConfigUpdateResponse
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private data class Operation(
    val method: String,
    val path: String,
) {
    override fun toString(): String = "$method $path"
}

private enum class SuccessKind {
    ENVELOPE,
    RAW_DOCUMENT,
    NONE,
}

private data class OperationContract(
    val request: KSerializer<*>? = null,
    val responseData: KSerializer<*>? = null,
    val successKind: SuccessKind = SuccessKind.ENVELOPE,
)

private data class ParameterContract(
    val name: String,
    val location: String,
    val required: Boolean = false,
    val type: String,
    val format: String? = null,
    val default: JsonElement? = null,
    val minimum: Double? = null,
    val maximum: Double? = null,
)

private data class ParameterRules(
    val default: JsonElement? = null,
    val minimum: Double? = null,
    val maximum: Double? = null,
)

private data class SchemaView(
    val local: JsonObject,
    val shape: JsonObject,
    val reference: String?,
) {
    operator fun get(name: String): JsonElement? = local[name] ?: shape[name]
}

private data class SchemaComparison(
    val document: JsonObject,
    val mode: SchemaMode,
    val problems: MutableSet<String>,
    val exercisedRefinements: MutableSet<String> = linkedSetOf(),
)

private val modelJson = Json {
    encodeDefaults = true
    explicitNulls = true
    ignoreUnknownKeys = false
}

private val clearedResponseSerializer = MapSerializer(String.serializer(), Boolean.serializer())

/**
 * This is the route-to-model join Kotlin cannot expose through runtime routing metadata. The
 * inventory equality test below makes every addition or removal explicit; serializers drive all
 * recursive field, type, nullability, default, and nested-model checks.
 */
private val operationContracts = linkedMapOf(
    operation("get", "/health") to response(HealthResponse.serializer()),
    operation("get", "/version") to response(VersionResponse.serializer()),
    operation("get", "/docs") to OperationContract(successKind = SuccessKind.RAW_DOCUMENT),
    operation("get", "/proxy/history") to response(ProxyHistoryResponse.serializer()),
    operation("get", "/proxy/history/{id}") to response(ProxyEntry.serializer()),
    operation("get", "/proxy/intercept") to response(InterceptStatusResponse.serializer()),
    operation("post", "/proxy/intercept/enable") to response(InterceptStatusResponse.serializer()),
    operation("post", "/proxy/intercept/disable") to response(InterceptStatusResponse.serializer()),
    operation("get", "/proxy/websocket/history") to response(WebSocketHistoryResponse.serializer()),
    operation("post", "/repeater/send") to requestResponse(SendRequest.serializer(), SendResponse.serializer()),
    operation("post", "/repeater/send/batch") to
        requestResponse(BatchSendRequest.serializer(), BatchSendResponse.serializer()),
    operation("post", "/repeater/tab/create") to
        requestResponse(CreateTabRequest.serializer(), CreateTabResponse.serializer()),
    operation("post", "/session/set") to
        requestResponse(com.burprest.models.SetSessionRequest.serializer(), SessionInfo.serializer()),
    operation("get", "/session/get") to response(SessionInfo.serializer()),
    operation("delete", "/session/clear") to response(SessionInfo.serializer()),
    operation("post", "/session/send") to
        requestResponse(AuthenticatedRequest.serializer(), AuthenticatedResponse.serializer()),
    operation("post", "/session/send/batch") to requestResponse(
        BatchAuthenticatedRequest.serializer(),
        BatchAuthenticatedResponse.serializer(),
    ),
    operation("get", "/session/cookie-jar") to response(CookieJarResponse.serializer()),
    operation("delete", "/session/cookie-jar") to response(CookieJarResponse.serializer()),
    operation("post", "/intruder/attack/create") to
        requestResponse(CreateAttackRequest.serializer(), CreateAttackResponse.serializer()),
    operation("post", "/intruder/attack/{id}/start") to response(AttackStatusResponse.serializer()),
    operation("get", "/intruder/attack/{id}/status") to response(AttackStatusResponse.serializer()),
    operation("get", "/intruder/attack/{id}/results") to response(AttackResultsResponse.serializer()),
    operation("post", "/intruder/attack/{id}/pause") to response(AttackStatusResponse.serializer()),
    operation("post", "/intruder/attack/{id}/resume") to response(AttackStatusResponse.serializer()),
    operation("post", "/intruder/attack/{id}/stop") to response(AttackStatusResponse.serializer()),
    operation("post", "/intruder/quick-fuzz") to
        requestResponse(QuickFuzzRequest.serializer(), QuickFuzzResponse.serializer()),
    operation("post", "/scanner/crawl") to
        requestResponse(ScanRequest.serializer(), ScanStartResponse.serializer()),
    operation("post", "/scanner/audit") to
        requestResponse(ScanRequest.serializer(), ScanStartResponse.serializer()),
    operation("post", "/scanner/crawl-and-audit") to noSuccess(),
    operation("get", "/scanner/{id}/status") to response(ScanStatusResponse.serializer()),
    operation("get", "/scanner/{id}/issues") to response(ScanIssuesResponse.serializer()),
    operation("post", "/scanner/{id}/pause") to noSuccess(),
    operation("post", "/scanner/{id}/resume") to noSuccess(),
    operation("post", "/scanner/{id}/stop") to response(ScanStatusResponse.serializer()),
    operation("get", "/scanner/issue-definitions") to
        response(com.burprest.models.IssueDefinitionsResponse.serializer()),
    operation("get", "/target/sitemap") to response(SitemapResponse.serializer()),
    operation("get", "/target/scope") to noSuccess(),
    operation("post", "/target/scope") to noSuccess(),
    operation("post", "/target/scope/add") to
        requestResponse(AddScopeRequest.serializer(), ScopeCheckResponse.serializer()),
    operation("post", "/target/scope/remove") to
        requestResponse(AddScopeRequest.serializer(), ScopeCheckResponse.serializer()),
    operation("get", "/target/scope/check") to response(ScopeCheckResponse.serializer()),
    operation("post", "/collaborator/generate") to response(BatchGenerateResponse.serializer()),
    operation("get", "/collaborator/poll") to response(PollResponse.serializer()),
    operation("post", "/decoder/encode") to
        requestResponse(EncodeRequest.serializer(), EncodeResponse.serializer()),
    operation("post", "/decoder/decode") to
        requestResponse(DecodeRequest.serializer(), DecodeResponse.serializer()),
    operation("post", "/decoder/hash") to
        requestResponse(HashRequest.serializer(), HashResponse.serializer()),
    operation("post", "/decoder/smart-decode") to
        requestResponse(DecodeRequest.serializer(), SmartDecodeResponse.serializer()),
    operation("get", "/config/project") to response(ConfigResponse.serializer()),
    operation("put", "/config/project") to
        requestResponse(ConfigUpdateRequest.serializer(), ConfigUpdateResponse.serializer()),
    operation("get", "/config/user") to response(ConfigResponse.serializer()),
    operation("put", "/config/user") to
        requestResponse(ConfigUpdateRequest.serializer(), ConfigUpdateResponse.serializer()),
    operation("get", "/extensions") to response(ExtensionsListResponse.serializer()),
    operation("get", "/history") to response(HistoryPageResponse.serializer()),
    operation("delete", "/history") to response(clearedResponseSerializer),
    operation("get", "/history/{id}") to response(HistoryEntryResponse.serializer()),
    operation("post", "/history/{id}/replay") to response(ReplayResponse.serializer()),
    operation("get", "/history/sitemap") to response(SitemapListResponse.serializer()),
    operation("get", "/collaborator/poll/{id}") to response(PollResponse.serializer()),
    operation("post", "/collaborator/generate/batch") to
        requestResponse(BatchGenerateRequest.serializer(), BatchGenerateResponse.serializer()),
    operation("post", "/proxy/intercept/drop") to noSuccess(),
    operation("post", "/proxy/intercept/forward") to noSuccess(),
    operation("post", "/scan/auth-bypass") to
        requestResponse(AuthBypassRequest.serializer(), AuthBypassResponse.serializer()),
    operation("post", "/scan/cors") to requestResponse(CorsRequest.serializer(), CorsResponse.serializer()),
    operation("post", "/scan/endpoints") to
        requestResponse(EndpointsScanRequest.serializer(), EndpointsScanResponse.serializer()),
    operation("post", "/scan/headers") to
        requestResponse(HeadersBypassRequest.serializer(), HeadersBypassResponse.serializer()),
    operation("post", "/scan/idor") to requestResponse(IdorRequest.serializer(), IdorResponse.serializer()),
    operation("post", "/utils/diff") to requestResponse(DiffRequest.serializer(), DiffResponse.serializer()),
    operation("post", "/utils/extract-endpoints") to requestResponse(
        ExtractEndpointsRequest.serializer(),
        ExtractEndpointsResponse.serializer(),
    ),
)

private val parameterContracts = mapOf(
    operation("get", "/proxy/history") to listOf(
        query("host", "string"),
        query("offset", "integer", format = "int32", rules = rules(minimum = 0.0)),
        query("limit", "integer", format = "int32", rules = rules(minimum = 1.0)),
    ),
    operation("get", "/proxy/history/{id}") to listOf(
        path("id", "integer", format = "int32", minimum = 0.0),
    ),
    operation("post", "/intruder/attack/{id}/start") to listOf(path("id", "string")),
    operation("get", "/intruder/attack/{id}/status") to listOf(path("id", "string")),
    operation("get", "/intruder/attack/{id}/results") to listOf(
        query("offset", "integer", format = "int32", rules = rules(default = JsonPrimitive(0), minimum = 0.0)),
        query("limit", "integer", format = "int32", rules = rules(default = JsonPrimitive(0), minimum = 0.0)),
        path("id", "string"),
    ),
    operation("post", "/intruder/attack/{id}/pause") to listOf(path("id", "string")),
    operation("post", "/intruder/attack/{id}/resume") to listOf(path("id", "string")),
    operation("post", "/intruder/attack/{id}/stop") to listOf(path("id", "string")),
    operation("get", "/scanner/{id}/status") to listOf(path("id", "string")),
    operation("get", "/scanner/{id}/issues") to listOf(path("id", "string")),
    operation("post", "/scanner/{id}/pause") to listOf(path("id", "string")),
    operation("post", "/scanner/{id}/resume") to listOf(path("id", "string")),
    operation("post", "/scanner/{id}/stop") to listOf(path("id", "string")),
    operation("get", "/target/sitemap") to listOf(query("url", "string")),
    operation("get", "/target/scope/check") to listOf(requiredQuery("url", "string")),
    operation("get", "/history") to listOf(
        query("host", "string"),
        query("method", "string"),
        query("statusCode", "integer", format = "int32"),
        query("source", "string"),
        query("search", "string"),
        query("since", "string", format = "date-time"),
        query("until", "string", format = "date-time"),
        query("page", "integer", format = "int32", rules = rules(default = JsonPrimitive(0), minimum = 0.0)),
        query(
            "pageSize",
            "integer",
            format = "int32",
            rules = rules(default = JsonPrimitive(50), minimum = 1.0, maximum = 1000.0),
        ),
    ),
    operation("get", "/history/{id}") to listOf(path("id", "integer", format = "int64")),
    operation("post", "/history/{id}/replay") to listOf(path("id", "integer", format = "int64")),
    operation("get", "/history/sitemap") to listOf(query("host", "string")),
    operation("get", "/collaborator/poll/{id}") to listOf(path("id", "string")),
)

private val requestSerializersByName: Map<String, KSerializer<*>> = listOf(
    BatchGenerateRequest.serializer(),
    PayloadPosition.serializer(),
    AttackOptions.serializer(),
    HttpHeader.serializer(),
    HttpRequestData.serializer(),
    RequestModifications.serializer(),
    SendRequest.serializer(),
    BatchSendRequest.serializer(),
    CreateTabRequest.serializer(),
    com.burprest.models.SetSessionRequest.serializer(),
    AuthenticatedRequest.serializer(),
    BatchAuthenticatedRequest.serializer(),
    CreateAttackRequest.serializer(),
    QuickFuzzRequest.serializer(),
    ScanConfig.serializer(),
    ScanRequest.serializer(),
    AddScopeRequest.serializer(),
    EncodeRequest.serializer(),
    DecodeRequest.serializer(),
    HashRequest.serializer(),
    ConfigUpdateRequest.serializer(),
    AuthBypassRequest.serializer(),
    CorsRequest.serializer(),
    EndpointsScanRequest.serializer(),
    HeadersBypassRequest.serializer(),
    IdorRequest.serializer(),
    DiffTarget.serializer(),
    DiffRequest.serializer(),
    ExtractEndpointsRequest.serializer(),
).associateBy { it.descriptor.serialName.removeSuffix("?") }

/**
 * ConfigUpdateRequest deliberately accepts JsonElement at the transport boundary so ConfigService
 * can issue a stable application error for non-objects. These are explicit semantic refinements,
 * not silent holes in descriptor checking.
 */
private val jsonObjectRequestRefinements = setOf(
    "put /config/project request.config",
    "put /config/user request.config",
)

class OpenApiContractTest {
    @Test
    fun `all 69 operations have an executable contract entry`() {
        val document = openApi()
        val documented = documentedOperations(document)

        assertEquals(69, documented.size, "published operation count changed")
        assertEquals(documented, operationContracts.keys, "route-to-model inventory drift")
        assertTrue(operationContracts.isNotEmpty(), "route-to-model inventory must exercise operations")
    }

    @Test
    fun `every operation parameter matches the value parsed by its route`() {
        val document = openApi()
        val problems = linkedSetOf<String>()
        assertTrue(parameterContracts.isNotEmpty(), "parameter contract inventory must exercise parameters")

        operationContracts.keys.forEach { operation ->
            val actual = operationObject(document, operation)
                .parameters(document, operation)
                .associateBy { parameter ->
                    parameter["in"]!!.jsonPrimitive.content to parameter["name"]!!.jsonPrimitive.content
                }
            val expected = parameterContracts[operation].orEmpty().associateBy { it.location to it.name }
            recordSetDifference(problems, "$operation parameters", expected.keys, actual.keys)
            expected.forEach { (key, contract) ->
                actual[key]?.let { compareParameter(operation, contract, it, problems) }
            }
        }

        assertNoProblems("OpenAPI parameter-contract mismatches", problems)
    }

    @Test
    fun `every JSON request body recursively matches its Kotlin serializer`() {
        val document = openApi()
        val problems = linkedSetOf<String>()
        val exercisedRefinements = linkedSetOf<String>()
        assertTrue(
            operationContracts.values.any { it.request != null },
            "request contract inventory must exercise JSON models",
        )

        val comparison = SchemaComparison(
            document,
            SchemaMode.REQUEST,
            problems,
            exercisedRefinements,
        )
        operationContracts.forEach { (operation, contract) ->
            compareRequestOperation(document, operation, contract, comparison)
        }
        recordSetDifference(
            problems,
            "JSON-object request refinements",
            jsonObjectRequestRefinements,
            exercisedRefinements,
        )

        assertNoProblems("OpenAPI request-model contract mismatches", problems)
    }

    @Test
    fun `every success response joins its ApiResponse data to the returned Kotlin model`() {
        val document = openApi()
        val problems = linkedSetOf<String>()
        assertTrue(
            operationContracts.values.any { it.successKind == SuccessKind.ENVELOPE },
            "response contract inventory must exercise typed envelopes",
        )

        operationContracts.forEach { (operation, contract) ->
            val responses = operationObject(document, operation)["responses"]!!.jsonObject
            when (contract.successKind) {
                SuccessKind.NONE -> compareUnsupportedResponse(operation, responses, problems)
                SuccessKind.RAW_DOCUMENT -> compareRawDocumentResponse(operation, responses, problems)
                SuccessKind.ENVELOPE -> compareSuccessEnvelope(
                    document,
                    operation,
                    responses,
                    requireNotNull(contract.responseData),
                    problems,
                )
            }
        }

        assertNoProblems("OpenAPI response-model contract mismatches", problems)
    }

    @Test
    fun `shared error responses match the ApiResponse error model`() {
        val document = openApi()
        val schemas = document["components"]!!.jsonObject["schemas"]!!.jsonObject
        val problems = linkedSetOf<String>()
        val errorEnvelope = schemas["ApiResponse"]?.jsonObject
        if (errorEnvelope == null) {
            problems += "ApiResponse error envelope: missing component"
        } else {
            compareErrorEnvelope(document, errorEnvelope, problems)
        }

        val sharedResponses = document["components"]!!.jsonObject["responses"]!!.jsonObject
        assertTrue(sharedResponses.isNotEmpty(), "shared error response inventory must not be empty")
        sharedResponses.forEach { (name, response) ->
            val reference = response.jsonObject["content"]
                ?.jsonObject
                ?.get("application/json")
                ?.jsonObject
                ?.get("schema")
                ?.jsonObject
                ?.get("${'$'}ref")
                ?.jsonPrimitive
                ?.contentOrNull
            if (reference != "#/components/schemas/ApiResponse") {
                problems += "components.responses.$name: expected ApiResponse error envelope, " +
                    "found ${reference ?: "missing"}"
            }
        }

        assertNoProblems("OpenAPI shared-error contract mismatches", problems)
    }

    @Test
    fun `non structural request constraints remain documented`() {
        val document = openApi()
        val timeoutOperations = setOf(
            operation("post", "/scan/auth-bypass"),
            operation("post", "/scan/idor"),
            operation("post", "/scan/headers"),
            operation("post", "/scan/cors"),
            operation("post", "/scan/endpoints"),
        )
        assertTrue(timeoutOperations.isNotEmpty(), "timeout constraint inventory must exercise routes")
        timeoutOperations.forEach { operation ->
            val timeout = requestSchema(document, operation)
                .let { schemaView(document, it) }
                .get("properties")!!
                .jsonObject["probeTimeoutMs"]!!
                .jsonObject
            assertEquals(5_000, timeout["default"]!!.jsonPrimitive.content.toInt(), operation.toString())
            assertEquals(100, timeout["minimum"]!!.jsonPrimitive.content.toInt(), operation.toString())
            assertEquals(120_000, timeout["maximum"]!!.jsonPrimitive.content.toInt(), operation.toString())
        }

        val sendRequest = schemaView(
            document,
            requestSchema(document, operation("post", "/repeater/send")),
        )
        val requestData = schemaView(
            document,
            sendRequest["properties"]!!.jsonObject["request"]!!.jsonObject,
        )
        val binaryBody = requestData["properties"]!!
            .jsonObject["bodyBase64"]!!
            .jsonObject
        assertEquals("byte", binaryBody["format"]!!.jsonPrimitive.content)
        assertTrue(binaryBody["description"]!!.jsonPrimitive.content.contains("takes precedence over body"))
    }

    @Test
    fun `served openapi document reports the running extension version`() {
        val declared = openApi()["info"]?.jsonObject?.get("version")?.jsonPrimitive?.content
        assertEquals(EXTENSION_VERSION, declared)
    }

}

private enum class SchemaMode {
    REQUEST,
    RESPONSE,
}

private fun compareRequestOperation(
    document: JsonObject,
    operation: Operation,
    contract: OperationContract,
    comparison: SchemaComparison,
) {
    val operationObject = operationObject(document, operation)
    val requestBody = operationObject["requestBody"]?.jsonObject
    when {
        contract.request == null && requestBody != null ->
            comparison.problems += "$operation request: documented but route decodes no JSON body"
        contract.request == null -> Unit
        requestBody == null ->
            comparison.problems += "$operation request: missing application/json request body"
        else -> comparePresentRequest(operation, contract.request, requestBody, operationObject, comparison)
    }
}

private fun comparePresentRequest(
    operation: Operation,
    serializer: KSerializer<*>,
    requestBody: JsonObject,
    operationObject: JsonObject,
    comparison: SchemaComparison,
) {
    if (requestBody["required"]?.jsonPrimitive?.booleanOrNull != true) {
        comparison.problems += "$operation request: body must be required"
    }
    val schema = requestBody["content"]
        ?.jsonObject
        ?.get("application/json")
        ?.jsonObject
        ?.get("schema")
        ?.jsonObject
    if (schema == null) {
        comparison.problems += "$operation request: missing application/json schema"
    } else {
        compareSchema(comparison, serializer.descriptor, schema, "$operation request")
    }
    val unsupportedMedia = operationObject["responses"]
        ?.jsonObject
        ?.get("415")
        ?.jsonObject
        ?.get("${'$'}ref")
        ?.jsonPrimitive
        ?.contentOrNull
    if (unsupportedMedia != "#/components/responses/UnsupportedMediaType") {
        comparison.problems += "$operation responses.415: expected #/components/responses/UnsupportedMediaType, " +
            "found ${unsupportedMedia ?: "missing"}"
    }
}

private fun compareSuccessEnvelope(
    document: JsonObject,
    operation: Operation,
    responses: JsonObject,
    responseSerializer: KSerializer<*>,
    problems: MutableSet<String>,
) {
    val location = "$operation responses.200"
    val schema = responseSchema(responses, "200")
    if (schema == null) {
        problems += "$location: missing application/json success schema"
    } else {
        val wrapper = schemaViewOrNull(document, schema, location, problems)
        val properties = wrapper?.get("properties")?.jsonObject
        if (wrapper == null) {
            Unit
        } else if (properties == null) {
            problems += "$location: success schema has no properties"
        } else {
            compareSuccessEnvelopeProperties(
                SchemaComparison(document, SchemaMode.RESPONSE, problems),
                location,
                wrapper,
                properties,
                responseSerializer,
            )
        }
    }
}

private fun compareSuccessEnvelopeProperties(
    comparison: SchemaComparison,
    location: String,
    wrapper: SchemaView,
    properties: JsonObject,
    responseSerializer: KSerializer<*>,
) {
    val problems = comparison.problems
    recordSetDifference(
        problems,
        "$location properties",
        setOf("success", "data", "error"),
        properties.keys,
    )
    compareRequired(location, setOf("success", "data", "error"), wrapper["required"], problems)
    compareAdditionalProperties(location, wrapper, false, problems)
    compareBooleanEnum("$location.success", properties["success"], true, problems)
    compareSuccessData(comparison.document, location, properties["data"], responseSerializer, problems)
    compareNullSchema("$location.error", properties["error"], problems)
}

private fun compareSuccessData(
    document: JsonObject,
    envelopeLocation: String,
    dataElement: JsonElement?,
    responseSerializer: KSerializer<*>,
    problems: MutableSet<String>,
) {
    val location = "$envelopeLocation.data"
    val data = dataElement?.jsonObject
    if (data == null) {
        problems += "$location: missing schema"
    } else {
        val expectedReference = responseSerializer.descriptor.componentNameOrNull(SchemaMode.RESPONSE)
        val actualReference = schemaReference(data)
        if (expectedReference != null && actualReference != expectedReference) {
            problems += "$location reference: expected $expectedReference, found ${actualReference ?: "untyped"}"
        } else {
            compareSchema(
                SchemaComparison(document, SchemaMode.RESPONSE, problems),
                responseSerializer.descriptor,
                data,
                location,
            )
        }
    }
}

private fun compareErrorEnvelope(
    document: JsonObject,
    schema: JsonObject,
    problems: MutableSet<String>,
) {
    val view = schemaView(document, schema)
    val location = "components.schemas.ApiResponse"
    val properties = view["properties"]?.jsonObject.orEmpty()
    recordSetDifference(problems, "$location properties", setOf("success", "data", "error"), properties.keys)
    compareRequired(location, setOf("success", "data", "error"), view["required"], problems)
    compareAdditionalProperties(location, view, false, problems)
    compareBooleanEnum("$location.success", properties["success"], false, problems)
    compareNullSchema("$location.data", properties["data"], problems)
    compareErrorData(document, "$location.error", properties["error"], problems)
}

private fun compareBooleanEnum(
    location: String,
    schemaElement: JsonElement?,
    expected: Boolean,
    problems: MutableSet<String>,
) {
    val schema = schemaElement?.jsonObject
    if (schema == null) {
        problems += "$location: missing schema"
    } else {
        compareType(location, "boolean", schema["type"], problems)
        val expectedEnum = JsonArray(listOf(JsonPrimitive(expected)))
        if (schema["enum"]?.jsonArray != expectedEnum) {
            problems += "$location enum: expected $expectedEnum, found ${schema["enum"] ?: "missing"}"
        }
    }
}

private fun compareNullSchema(
    location: String,
    schemaElement: JsonElement?,
    problems: MutableSet<String>,
) {
    val schema = schemaElement?.jsonObject
    if (schema == null) {
        problems += "$location: missing schema"
    } else {
        if (schema["nullable"]?.jsonPrimitive?.booleanOrNull != true) {
            problems += "$location nullable: expected true, found ${schema["nullable"] ?: "missing"}"
        }
        val expectedEnum = JsonArray(listOf(JsonNull))
        if (schema["enum"]?.jsonArray != expectedEnum) {
            problems += "$location enum: expected $expectedEnum, found ${schema["enum"] ?: "missing"}"
        }
    }
}

private fun compareErrorData(
    document: JsonObject,
    location: String,
    errorElement: JsonElement?,
    problems: MutableSet<String>,
) {
    val error = errorElement?.jsonObject
    if (error == null) {
        problems += "$location: missing schema"
    } else {
        compareSchema(
            SchemaComparison(document, SchemaMode.RESPONSE, problems),
            ApiError.serializer().descriptor,
            error,
            location,
        )
    }
}

private fun compareUnsupportedResponse(
    operation: Operation,
    responses: JsonObject,
    problems: MutableSet<String>,
) {
    if ("200" in responses) problems += "$operation responses: impossible 200 success is documented"
    val unsupported = responses["501"]
        ?.jsonObject
        ?.get("${'$'}ref")
        ?.jsonPrimitive
        ?.contentOrNull
    if (unsupported != "#/components/responses/Unsupported") {
        problems += "$operation responses.501: expected #/components/responses/Unsupported, " +
            "found ${unsupported ?: "missing"}"
    }
}

private fun compareRawDocumentResponse(
    operation: Operation,
    responses: JsonObject,
    problems: MutableSet<String>,
) {
    val schema = responseSchema(responses, "200")
    if (schema == null) {
        problems += "$operation responses.200: missing application/json document schema"
        return
    }
    if (schemaReference(schema) != null) {
        problems += "$operation responses.200: raw document must not claim an ApiResponse envelope"
    }
    compareType("$operation responses.200", "object", schema["type"], problems)
    if (schema["additionalProperties"]?.jsonPrimitive?.booleanOrNull != true) {
        problems += "$operation responses.200 additionalProperties: expected true"
    }
}

private fun compareParameter(
    operation: Operation,
    expected: ParameterContract,
    actual: JsonObject,
    problems: MutableSet<String>,
) {
    val location = "$operation parameter ${expected.location}.${expected.name}"
    val required = actual["required"]?.jsonPrimitive?.booleanOrNull ?: false
    if (required != expected.required) {
        problems += "$location required: expected ${expected.required}, found $required"
    }
    val schema = actual["schema"]?.jsonObject
    if (schema == null) {
        problems += "$location: missing schema"
        return
    }
    compareType(location, expected.type, schema["type"], problems)
    compareOptionalText("$location format", expected.format, schema["format"], problems)
    compareOptionalElement("$location default", expected.default, schema["default"], problems)
    compareOptionalNumber("$location minimum", expected.minimum, schema["minimum"], problems)
    compareOptionalNumber("$location maximum", expected.maximum, schema["maximum"], problems)
}

private fun compareSchema(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    schema: JsonObject,
    location: String,
    modelValue: JsonElement? = null,
) {
    when (descriptor.serialName.removeSuffix("?")) {
        "kotlinx.serialization.json.JsonElement" ->
            compareJsonElement(comparison, schema, location)
        "kotlinx.serialization.json.JsonObject" ->
            compareJsonObject(comparison, descriptor, schema, location)
        else -> compareResolvedSchema(comparison, descriptor, schema, location, modelValue)
    }
}

private fun compareJsonElement(
    comparison: SchemaComparison,
    schema: JsonObject,
    location: String,
) {
    if (comparison.mode == SchemaMode.REQUEST && location in jsonObjectRequestRefinements) {
        comparison.exercisedRefinements += location
        val view = schemaView(comparison.document, schema)
        compareType(location, "object", view["type"], comparison.problems)
        compareAdditionalProperties(location, view, true, comparison.problems)
    } else {
        comparison.problems += "$location: unrestricted JsonElement needs an explicit schema refinement"
    }
}

private fun compareJsonObject(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    schema: JsonObject,
    location: String,
) {
    val view = schemaView(comparison.document, schema)
    compareType(location, "object", view["type"], comparison.problems)
    compareAdditionalProperties(location, view, true, comparison.problems)
    compareNullability(location, descriptor, view, comparison.problems)
}

private fun compareResolvedSchema(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    schema: JsonObject,
    location: String,
    modelValue: JsonElement?,
) {
    val view = schemaViewOrNull(comparison.document, schema, location, comparison.problems)
    if (view != null) {
        val expectedReference = descriptor.componentNameOrNull(comparison.mode)
        val wrongReference = view.reference != null &&
            expectedReference != null &&
            view.reference != expectedReference
        if (wrongReference) {
            comparison.problems += "$location reference: expected $expectedReference, found ${view.reference}"
        } else {
            compareNullability(location, descriptor, view, comparison.problems)
            compareDescriptorKind(comparison, descriptor, view, location, modelValue)
        }
    }
}

private fun compareDescriptorKind(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    view: SchemaView,
    location: String,
    modelValue: JsonElement?,
) {
    when (val kind = descriptor.kind) {
        PrimitiveKind.BOOLEAN -> comparePrimitive(location, "boolean", null, view, comparison.problems)
        PrimitiveKind.BYTE,
        PrimitiveKind.SHORT,
        PrimitiveKind.INT,
        -> comparePrimitive(location, "integer", "int32", view, comparison.problems)
        PrimitiveKind.LONG -> comparePrimitive(location, "integer", "int64", view, comparison.problems)
        PrimitiveKind.FLOAT -> comparePrimitive(location, "number", "float", view, comparison.problems)
        PrimitiveKind.DOUBLE -> comparePrimitive(location, "number", "double", view, comparison.problems)
        PrimitiveKind.CHAR,
        PrimitiveKind.STRING,
        -> comparePrimitive(location, "string", null, view, comparison.problems)
        SerialKind.ENUM -> compareEnum(location, descriptor, view, comparison.problems)
        StructureKind.LIST -> compareList(comparison, descriptor, view, location)
        StructureKind.MAP -> compareMap(comparison, descriptor, view, location)
        StructureKind.CLASS,
        StructureKind.OBJECT,
        -> compareClass(comparison, descriptor, view, location, modelValue)
        SerialKind.CONTEXTUAL,
        is PolymorphicKind,
        -> comparison.problems += "$location: unsupported serializer kind $kind"
    }
}

private fun compareClass(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    view: SchemaView,
    location: String,
    modelValue: JsonElement?,
) {
    compareType(location, "object", view["type"], comparison.problems)
    compareAdditionalProperties(location, view, false, comparison.problems)
    val properties = view["properties"]?.jsonObject
    if (properties == null) {
        comparison.problems += "$location properties: missing"
    } else {
        compareClassProperties(comparison, descriptor, view, location, modelValue)
    }
}

private fun compareClassProperties(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    view: SchemaView,
    location: String,
    modelValue: JsonElement?,
) {
    val properties = requireNotNull(view["properties"]?.jsonObject)
    val names = descriptor.elementNames()
    recordSetDifference(comparison.problems, "$location properties", names, properties.keys)
    val required = when (comparison.mode) {
        SchemaMode.REQUEST -> descriptor.requiredElementNames()
        SchemaMode.RESPONSE -> names
    }
    compareRequired(location, required, view["required"], comparison.problems)
    val sample = when {
        comparison.mode != SchemaMode.REQUEST -> null
        modelValue is JsonObject -> modelValue
        else -> requestDefaultSample(descriptor)
    }
    for (index in 0 until descriptor.elementsCount) {
        val name = descriptor.getElementName(index)
        val property = properties[name]?.jsonObject
        if (property != null) {
            val childValue = sample?.get(name)
            compareSchema(
                comparison,
                descriptor.getElementDescriptor(index),
                property,
                "$location.$name",
                childValue,
            )
            if (comparison.mode == SchemaMode.REQUEST && descriptor.isElementOptional(index)) {
                compareOptionalDefault(
                    "$location.$name",
                    childValue ?: JsonNull,
                    property,
                    comparison.problems,
                )
            }
        }
    }
}

private fun compareList(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    view: SchemaView,
    location: String,
) {
    compareType(location, "array", view["type"], comparison.problems)
    val items = view["items"]?.jsonObject
    if (items == null) {
        comparison.problems += "$location.items: missing"
    } else {
        compareSchema(comparison, descriptor.getElementDescriptor(0), items, "$location[]")
    }
}

private fun compareMap(
    comparison: SchemaComparison,
    descriptor: SerialDescriptor,
    view: SchemaView,
    location: String,
) {
    compareType(location, "object", view["type"], comparison.problems)
    val keyDescriptor = descriptor.getElementDescriptor(0)
    if (keyDescriptor.kind != PrimitiveKind.STRING) {
        comparison.problems += "$location: OpenAPI object map cannot represent ${keyDescriptor.serialName} keys"
    }
    val values = view["additionalProperties"]
    if (values !is JsonObject) {
        val valueName = descriptor.getElementDescriptor(1).serialName
        comparison.problems += "$location additionalProperties: expected schema for $valueName"
    } else {
        compareSchema(comparison, descriptor.getElementDescriptor(1), values, "$location{}")
    }
}

private fun comparePrimitive(
    location: String,
    type: String,
    format: String?,
    view: SchemaView,
    problems: MutableSet<String>,
) {
    compareType(location, type, view["type"], problems)
    val semanticFormat = when {
        format != null -> format
        location.endsWith(".bodyBase64") -> "byte"
        location.endsWith(".payloadBase64") -> "byte"
        location.endsWith(".editedPayloadBase64") -> "byte"
        else -> null
    }
    compareOptionalText("$location format", semanticFormat, view["format"], problems)
}

private fun compareEnum(
    location: String,
    descriptor: SerialDescriptor,
    view: SchemaView,
    problems: MutableSet<String>,
) {
    compareType(location, "string", view["type"], problems)
    val expected = (0 until descriptor.elementsCount).map { JsonPrimitive(descriptor.getElementName(it)) }
    val actual = view["enum"]?.jsonArray
    if (actual != JsonArray(expected)) {
        problems += "$location enum: expected ${JsonArray(expected)}, found ${actual ?: "missing"}"
    }
}

private fun compareNullability(
    location: String,
    descriptor: SerialDescriptor,
    view: SchemaView,
    problems: MutableSet<String>,
) {
    val actual = view["nullable"]?.jsonPrimitive?.booleanOrNull ?: false
    if (actual != descriptor.isNullable) {
        problems += "$location nullable: expected ${descriptor.isNullable}, found $actual"
    }
}

private fun compareAdditionalProperties(
    location: String,
    view: SchemaView,
    expected: Boolean,
    problems: MutableSet<String>,
) {
    val actual = view["additionalProperties"]?.jsonPrimitive?.booleanOrNull
    if (actual != expected) {
        problems += "$location additionalProperties: expected $expected, found ${actual ?: "schema-or-missing"}"
    }
}

private fun compareRequired(
    location: String,
    expected: Set<String>,
    actualElement: JsonElement?,
    problems: MutableSet<String>,
) {
    val actual = actualElement?.jsonArray?.mapTo(linkedSetOf()) { it.jsonPrimitive.content }.orEmpty()
    recordSetDifference(problems, "$location required", expected, actual)
}

private fun compareOptionalDefault(
    location: String,
    expected: JsonElement,
    schema: JsonObject,
    problems: MutableSet<String>,
) {
    val actual = schema["default"]
    if (actual != expected) {
        problems += "$location default: expected $expected, found ${actual ?: "missing"}"
    }
}

private fun compareType(
    location: String,
    expected: String,
    actualElement: JsonElement?,
    problems: MutableSet<String>,
) {
    val actual = actualElement?.jsonPrimitive?.contentOrNull
    if (actual != expected) problems += "$location type: expected $expected, found ${actual ?: "missing"}"
}

private fun compareOptionalText(
    location: String,
    expected: String?,
    actualElement: JsonElement?,
    problems: MutableSet<String>,
) {
    val actual = actualElement?.jsonPrimitive?.contentOrNull
    if (actual != expected) problems += "$location: expected ${expected ?: "absent"}, found ${actual ?: "absent"}"
}

private fun compareOptionalElement(
    location: String,
    expected: JsonElement?,
    actual: JsonElement?,
    problems: MutableSet<String>,
) {
    if (actual != expected) problems += "$location: expected ${expected ?: "absent"}, found ${actual ?: "absent"}"
}

private fun compareOptionalNumber(
    location: String,
    expected: Double?,
    actualElement: JsonElement?,
    problems: MutableSet<String>,
) {
    val actual = actualElement?.jsonPrimitive?.doubleOrNull
    if (actual != expected) problems += "$location: expected ${expected ?: "absent"}, found ${actual ?: "absent"}"
}

private fun requestDefaultSample(descriptor: SerialDescriptor): JsonObject? {
    val serializer = requestSerializersByName[descriptor.serialName.removeSuffix("?")] ?: return null
    @Suppress("UNCHECKED_CAST")
    serializer as KSerializer<Any?>
    val sampleDescriptor = serializer.descriptor
    val value = modelJson.decodeFromJsonElement(serializer, minimalJson(sampleDescriptor))
    return modelJson.encodeToJsonElement(serializer, value) as? JsonObject
}

private fun minimalJson(descriptor: SerialDescriptor): JsonElement = when {
    descriptor.isNullable -> JsonNull
    descriptor.serialName.removeSuffix("?") == "kotlinx.serialization.json.JsonElement" ->
        JsonObject(emptyMap())
    else -> minimalNonNullJson(descriptor)
}

private fun minimalNonNullJson(descriptor: SerialDescriptor): JsonElement = when (descriptor.kind) {
    PrimitiveKind.BOOLEAN -> JsonPrimitive(false)
    PrimitiveKind.BYTE,
    PrimitiveKind.SHORT,
    PrimitiveKind.INT,
    PrimitiveKind.LONG,
    PrimitiveKind.FLOAT,
    PrimitiveKind.DOUBLE,
    -> JsonPrimitive(0)
    PrimitiveKind.CHAR,
    PrimitiveKind.STRING,
    -> JsonPrimitive("x")
    SerialKind.ENUM -> JsonPrimitive(descriptor.getElementName(0))
    StructureKind.LIST -> buildJsonArray { }
    StructureKind.MAP -> buildJsonObject { }
    StructureKind.CLASS,
    StructureKind.OBJECT,
    -> buildJsonObject {
        for (index in 0 until descriptor.elementsCount) {
            if (!descriptor.isElementOptional(index)) {
                put(descriptor.getElementName(index), minimalJson(descriptor.getElementDescriptor(index)))
            }
        }
    }
    SerialKind.CONTEXTUAL,
    is PolymorphicKind,
    -> error("No deterministic placeholder for ${descriptor.serialName} (${descriptor.kind})")
}

private fun schemaView(document: JsonObject, schema: JsonObject): SchemaView {
    val reference = schemaReference(schema)
    if (reference == null) return SchemaView(schema, schema, null)
    val shape = document["components"]!!
        .jsonObject["schemas"]!!
        .jsonObject[reference]!!
        .jsonObject
    return SchemaView(schema, shape, reference)
}

private fun schemaViewOrNull(
    document: JsonObject,
    schema: JsonObject,
    location: String,
    problems: MutableSet<String>,
): SchemaView? {
    val reference = schemaReference(schema)
    return if (reference == null) {
        SchemaView(schema, schema, null)
    } else {
        val shape = document["components"]
            ?.jsonObject
            ?.get("schemas")
            ?.jsonObject
            ?.get(reference)
            ?.jsonObject
        if (shape == null) {
            problems += "$location reference: component $reference is missing"
            null
        } else {
            SchemaView(schema, shape, reference)
        }
    }
}

private fun schemaReference(schema: JsonObject): String? {
    val direct = schema["${'$'}ref"]?.jsonPrimitive?.contentOrNull
    val nested = schema["allOf"]
        ?.jsonArray
        ?.singleOrNull()
        ?.jsonObject
        ?.get("${'$'}ref")
        ?.jsonPrimitive
        ?.contentOrNull
    return (direct ?: nested)?.removePrefix("#/components/schemas/")
}

private fun requestSchema(document: JsonObject, operation: Operation): JsonObject =
    operationObject(document, operation)["requestBody"]!!
        .jsonObject["content"]!!
        .jsonObject["application/json"]!!
        .jsonObject["schema"]!!
        .jsonObject

private fun responseSchema(responses: JsonObject, status: String): JsonObject? =
    responses[status]
        ?.jsonObject
        ?.get("content")
        ?.jsonObject
        ?.get("application/json")
        ?.jsonObject
        ?.get("schema")
        ?.jsonObject

private fun operationObject(document: JsonObject, operation: Operation): JsonObject =
    document["paths"]!!
        .jsonObject[operation.path]!!
        .jsonObject[operation.method]!!
        .jsonObject

private fun JsonObject.parameters(document: JsonObject, operation: Operation): List<JsonObject> {
    val pathParameters = document["paths"]!!
        .jsonObject[operation.path]!!
        .jsonObject["parameters"]
        ?.jsonArray
        .orEmpty()
    val operationParameters = this["parameters"]?.jsonArray.orEmpty()
    return (pathParameters + operationParameters).map { it.jsonObject }
}

private fun documentedOperations(document: JsonObject): Set<Operation> {
    val methods = setOf("get", "post", "put", "delete", "patch", "options", "head", "trace")
    return document["paths"]!!.jsonObject.flatMapTo(linkedSetOf()) { (path, item) ->
        item.jsonObject.keys.filter { it in methods }.map { method -> operation(method, path) }
    }
}

private fun openApi(): JsonObject {
    val resource = requireNotNull(OpenApiContractTest::class.java.getResource("/openapi.json"))
    return Json.parseToJsonElement(resource.readText()).jsonObject
}

private fun SerialDescriptor.componentNameOrNull(mode: SchemaMode): String? = when (kind) {
    StructureKind.CLASS,
    StructureKind.OBJECT,
    SerialKind.ENUM,
    -> serialName.removeSuffix("?").substringAfterLast('.').substringBefore('<').let { name ->
        if (mode == SchemaMode.REQUEST && name == "HttpRequestData") "HttpRequestDataInput" else name
    }
    else -> null
}

private fun SerialDescriptor.elementNames(): Set<String> =
    (0 until elementsCount).mapTo(linkedSetOf()) { getElementName(it) }

private fun SerialDescriptor.requiredElementNames(): Set<String> =
    (0 until elementsCount)
        .filterNot(::isElementOptional)
        .mapTo(linkedSetOf()) { getElementName(it) }

private fun recordSetDifference(
    problems: MutableSet<String>,
    location: String,
    expected: Set<*>,
    actual: Set<*>,
) {
    val missing = expected - actual
    val unexpected = actual - expected
    if (missing.isNotEmpty() || unexpected.isNotEmpty()) {
        problems += "$location: missing $missing; unexpected $unexpected"
    }
}

private fun assertNoProblems(heading: String, problems: Set<String>) {
    assertTrue(
        problems.isEmpty(),
        problems.joinToString(separator = "\n - ", prefix = "$heading:\n - "),
    )
}

private fun operation(method: String, path: String) = Operation(method, path)

private fun response(serializer: KSerializer<*>) = OperationContract(responseData = serializer)

private fun requestResponse(request: KSerializer<*>, response: KSerializer<*>) =
    OperationContract(request = request, responseData = response)

private fun noSuccess() = OperationContract(successKind = SuccessKind.NONE)

private fun query(
    name: String,
    type: String,
    format: String? = null,
    rules: ParameterRules = ParameterRules(),
) = ParameterContract(
    name,
    "query",
    false,
    type,
    format,
    rules.default,
    rules.minimum,
    rules.maximum,
)

private fun requiredQuery(
    name: String,
    type: String,
    format: String? = null,
    rules: ParameterRules = ParameterRules(),
) = ParameterContract(
    name,
    "query",
    true,
    type,
    format,
    rules.default,
    rules.minimum,
    rules.maximum,
)

private fun rules(
    default: JsonElement? = null,
    minimum: Double? = null,
    maximum: Double? = null,
) = ParameterRules(default, minimum, maximum)

private fun path(
    name: String,
    type: String,
    format: String? = null,
    minimum: Double? = null,
) = ParameterContract(name, "path", required = true, type, format, minimum = minimum)
