package com.burprest.integration

import com.burprest.models.AuthenticatedRequest
import com.burprest.models.ExtractEndpointsRequest
import com.burprest.models.SetSessionRequest
import com.burprest.services.SessionService
import com.burprest.services.SessionServiceCollaborators
import com.burprest.services.UtilsService
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UtilsSessionCompositionTest {
    @Test
    fun `endpoint extraction authenticates same origin and isolates cross origin bundle state`() {
        val harness = MutableHttpHarness { request, _ ->
            when (request.url) {
                "$ORIGIN/index.html" -> WireResponse(
                    body = (
                        "<!doctype html>" +
                            "<script src='/same.js'></script>" +
                            "<script src='https://cdn.example/bundle.js'></script>"
                        ).encodeToByteArray(),
                )
                "$ORIGIN/same.js" -> WireResponse(body = "fetch('/api/same')".encodeToByteArray())
                "https://cdn.example/bundle.js" -> WireResponse(
                    headers = listOf("Set-Cookie" to "cross_cookie=must-not-stick; Secure; Path=/"),
                    body = "fetch('/api/cross')".encodeToByteArray(),
                )
                else -> WireResponse()
            }
        }
        val session = SessionService(
            harness.api,
            null,
            null,
            null,
            SessionServiceCollaborators(
                requestFactory = harness::request,
                bodyFactory = harness::body,
            ),
        )
        session.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "configured-cookie"),
                headers = mapOf("Authorization" to "Bearer configured-header"),
                origin = ORIGIN,
            )
        )

        val extracted = UtilsService(session).extractEndpoints(ExtractEndpointsRequest("$ORIGIN/index.html"))
        session.send(AuthenticatedRequest(url = "$ORIGIN/after-extraction"))

        assertEquals(listOf("/api/cross", "/api/same"), extracted.endpoints)
        val page = harness.sent.single { it.url == "$ORIGIN/index.html" }
        val sameOrigin = harness.sent.single { it.url == "$ORIGIN/same.js" }
        val crossOrigin = harness.sent.single { it.url == "https://cdn.example/bundle.js" }
        val after = harness.sent.single { it.url == "$ORIGIN/after-extraction" }
        listOf(page, sameOrigin, after).forEach { sent ->
            assertTrue(sent.headers.contains("Cookie" to "sid=configured-cookie"))
            assertTrue(sent.headers.contains("Authorization" to "Bearer configured-header"))
        }
        assertTrue(crossOrigin.headers.isEmpty())
        assertEquals(0, session.getCookieJar().total)
        assertFalse(after.headers.any { it.second.contains("must-not-stick") })
    }

    private companion object {
        const val ORIGIN = "https://composition.example"
    }
}
