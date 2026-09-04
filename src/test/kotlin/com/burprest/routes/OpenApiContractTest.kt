package com.burprest.routes

import com.burprest.EXTENSION_VERSION
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OpenApiContractTest {
    @Test
    fun `openapi is complete for the executable route inventory`() {
        val resource = requireNotNull(javaClass.getResource("/openapi.json"))
        val document = Json.parseToJsonElement(resource.readText()).jsonObject
        val paths = requireNotNull(document["paths"]).jsonObject
        val methods = setOf("get", "post", "put", "delete", "patch", "options", "head", "trace")
        val operations = paths.values.sumOf { item ->
            item.jsonObject.keys.count { it in methods }
        }

        assertEquals(69, operations)
        paths.forEach { (path, item) ->
            item.jsonObject.filterKeys { it in methods }.forEach { (method, operation) ->
                val contract = operation.jsonObject
                assertTrue(contract.containsKey("operationId"), "$method $path missing operationId")
                assertTrue(contract.containsKey("responses"), "$method $path missing responses")
                Regex("\\{([^}]+)}").findAll(path).forEach { match ->
                    val name = match.groupValues[1]
                    val declared = contract["parameters"]?.jsonArray.orEmpty().any { parameter ->
                        val value = parameter.jsonObject
                        value["name"]?.jsonPrimitive?.content == name &&
                            value["in"]?.jsonPrimitive?.content == "path" &&
                            value["required"]?.jsonPrimitive?.boolean == true
                    }
                    assertTrue(declared, "$method $path missing required path parameter $name")
                }
            }
        }
    }

    @Test
    fun `served openapi document reports the running extension version`() {
        val resource = requireNotNull(javaClass.getResource("/openapi.json"))
        val document = Json.parseToJsonElement(resource.readText()).jsonObject
        val declared = document["info"]?.jsonObject?.get("version")?.jsonPrimitive?.content

        assertEquals(EXTENSION_VERSION, declared)
    }
}
