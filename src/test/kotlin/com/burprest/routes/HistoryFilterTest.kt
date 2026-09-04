package com.burprest.routes

import com.burprest.server.InvalidParamException
import io.ktor.http.Parameters
import io.ktor.http.parametersOf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class HistoryFilterTest {

    private fun params(vararg pairs: Pair<String, String>): Parameters =
        Parameters.build { pairs.forEach { (name, value) -> append(name, value) } }

    @Test
    fun `absent pagination uses the documented defaults`() {
        val filter = historyFilterFrom(Parameters.Empty)

        assertEquals(0, filter.page)
        assertEquals(50, filter.pageSize)
        assertNull(filter.statusCode)
        assertNull(filter.since)
        assertNull(filter.until)
    }

    @Test
    fun `valid values are carried through unchanged`() {
        val filter = historyFilterFrom(
            params(
                "page" to "2",
                "pageSize" to "10",
                "statusCode" to "404",
                "host" to "127.0.0.1",
                "since" to "2026-01-01T00:00:00Z",
            )
        )

        assertEquals(2, filter.page)
        assertEquals(10, filter.pageSize)
        assertEquals(404, filter.statusCode)
        assertEquals("127.0.0.1", filter.host)
        assertEquals("2026-01-01T00:00:00Z", filter.since)
    }

    @Test
    fun `a malformed page is rejected rather than silently defaulted`() {
        val failure = assertFailsWith<InvalidParamException> {
            historyFilterFrom(params("page" to "abc"))
        }

        assertEquals("page must be an integer", failure.clientMessage)
    }

    @Test
    fun `a malformed pageSize is rejected rather than silently defaulted`() {
        val failure = assertFailsWith<InvalidParamException> {
            historyFilterFrom(params("pageSize" to "abc"))
        }

        assertEquals("pageSize must be an integer", failure.clientMessage)
    }

    @Test
    fun `a malformed statusCode is rejected rather than silently dropping the filter`() {
        val failure = assertFailsWith<InvalidParamException> {
            historyFilterFrom(params("statusCode" to "abc"))
        }

        assertEquals("statusCode must be an integer", failure.clientMessage)
    }

    @Test
    fun `an overflowing page is rejected rather than silently defaulted`() {
        val failure = assertFailsWith<InvalidParamException> {
            historyFilterFrom(params("page" to "99999999999999"))
        }

        assertEquals("page must be an integer", failure.clientMessage)
    }

    @Test
    fun `pagination bounds are still enforced`() {
        assertFailsWith<InvalidParamException> { historyFilterFrom(params("page" to "-1")) }
        assertFailsWith<InvalidParamException> { historyFilterFrom(params("pageSize" to "0")) }
        assertFailsWith<InvalidParamException> { historyFilterFrom(params("pageSize" to "1001")) }
    }

    @Test
    fun `a malformed timestamp leaks neither parser identity nor the supplied value`() {
        val marker = "HISTORY_QUERY_MARKER_7Q"

        listOf("since", "until").forEach { name ->
            val failure = assertFailsWith<InvalidParamException> {
                historyFilterFrom(params(name to marker))
            }

            assertEquals("$name must be an ISO-8601 instant", failure.clientMessage)
            assertFalse(failure.clientMessage.contains(marker), "$name echoed the raw query value")
            assertFalse(failure.clientMessage.contains("Exception"), "$name leaked parser identity")
            assertFalse(failure.clientMessage.contains("java."), "$name leaked a class name")
        }
    }

    @Test
    fun `an unused parameters overload keeps the call site honest`() {
        // parametersOf is the shape the route hands in; prove the same contract holds for it.
        val failure = assertFailsWith<InvalidParamException> {
            historyFilterFrom(parametersOf("page", "not-a-number"))
        }

        assertEquals("page must be an integer", failure.clientMessage)
    }
}
