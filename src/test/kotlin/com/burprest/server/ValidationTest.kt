package com.burprest.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ValidationTest {

    @Test
    fun `required parameter rejects missing and blank values`() {
        assertEquals("value", requiredParameter("value", "name"))
        assertEquals(" value ", requiredParameter(" value ", "name"))

        val missing = assertFailsWith<InvalidParamException> {
            requiredParameter(null, "name")
        }
        assertEquals("name is required", missing.clientMessage)

        val blank = assertFailsWith<InvalidParamException> {
            requiredParameter("   ", "name")
        }
        assertEquals("name must not be blank", blank.clientMessage)
    }

    @Test
    fun `integer parameters distinguish absence from malformed input and enforce ranges`() {
        assertEquals(25, intParameter(null, "limit", default = 25, range = 1..100))
        assertEquals(12, intParameter("12", "limit", default = 25, range = 1..100))
        assertEquals(null, optionalIntParameter(null, "offset", range = 0..100))
        assertEquals(0, optionalIntParameter("0", "offset", range = 0..100))

        assertFailsWith<InvalidParamException> {
            intParameter("not-a-number", "limit", default = 25)
        }
        assertFailsWith<InvalidParamException> {
            intParameter("0", "limit", default = 25, range = 1..100)
        }
    }

    @Test
    fun `required numeric parameters and generic predicates return typed validation failures`() {
        assertEquals(42, requiredIntParameter("42", "count", range = 1..100))
        assertEquals(9L, requiredLongParameter("9", "id", range = 1L..Long.MAX_VALUE))
        assertEquals(8L, optionalLongParameter("8", "after", range = 0L..Long.MAX_VALUE))

        assertFailsWith<InvalidParamException> {
            requiredIntParameter(null, "count")
        }
        assertFailsWith<InvalidParamException> {
            requiredLongParameter("overflow99999999999999999999", "id")
        }

        assertEquals("GET", validateParameter("GET", "method", "must be GET or POST") { it in setOf("GET", "POST") })
        assertFailsWith<InvalidParamException> {
            validateParameter("TRACE", "method", "must be GET or POST") { it in setOf("GET", "POST") }
        }
    }

    @Test
    fun `not found helper preserves the value or throws a typed not found error`() {
        assertEquals("entry", requireFound("entry", "history entry was not found"))
        val failure = assertFailsWith<NotFoundException> {
            requireFound<String>(null, "history entry was not found")
        }
        assertEquals("history entry was not found", failure.clientMessage)
    }
}
