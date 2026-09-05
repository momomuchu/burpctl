package com.burprest.integration

import burp.api.montoya.logging.Logging
import com.burprest.db.DatabaseManager
import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.db.SessionDao
import com.burprest.db.SitemapDao
import com.burprest.models.AuthenticatedRequest
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.PersistenceStatus
import com.burprest.models.SendRequest
import com.burprest.models.SetSessionRequest
import com.burprest.routes.historyRoutes
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.services.RepeaterService
import com.burprest.services.SessionService
import com.burprest.services.SessionServiceCollaborators
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.application
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.Closeable
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionHistoryCompositionTest {
    @Test
    fun `session send persists exact material and replay reproduces it`() = testApplication {
        IntegrationDatabase().use { database ->
            val fixture = prepareReplay(database)
            application {
                installStrictJson()
                installErrorHandling { }
                routing { historyRoutes(database.history, database.sitemap, fixture.repeater) }
            }

            val routeResponse = client.post("/history/${fixture.originalId}/replay")

            assertEquals(HttpStatusCode.OK, routeResponse.status)
            assertReplayState(database, fixture, routeResponse.bodyAsText())
        }
    }

    @Test
    fun `history replay propagates a completed-send persistence warning`() = testApplication {
        IntegrationDatabase().use { database ->
            val fixture = prepareReplay(database)
            database.dropSitemap()
            application {
                installStrictJson()
                installErrorHandling { }
                routing { historyRoutes(database.history, database.sitemap, fixture.repeater) }
            }

            val response = client.post("/history/${fixture.originalId}/replay")

            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(2, fixture.harness.sent.size)
            assertEquals(1, database.history.count(HistoryFilter()))
            val data = Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("data").jsonObject
            val persistence = data["persistence"]?.jsonObject
            val warning = persistence?.get("warning")?.jsonPrimitive?.contentOrNull
            assertEquals("failed", persistence?.get("status")?.jsonPrimitive?.contentOrNull)
            assertEquals("false", persistence?.get("historyPersisted")?.jsonPrimitive?.contentOrNull)
            assertEquals("false", persistence?.get("sitemapPersisted")?.jsonPrimitive?.contentOrNull)
            assertEquals(
                "Target send completed, but optional history and sitemap persistence failed; " +
                    "do not retry the target send.",
                warning,
                "replay must propagate the delegated completed-send persistence warning",
            )
        }
    }

    @Test
    fun `session clear removes configured and observed credentials before later send`() {
        IntegrationDatabase().use { database ->
            val harness = MutableHttpHarness { _, index ->
                if (index == 0) {
                    WireResponse(
                        headers = listOf("Set-Cookie" to "jar_sid=observed-cookie; Secure; HttpOnly; Path=/"),
                    )
                } else {
                    WireResponse()
                }
            }
            val session = database.sessionService(harness)
            session.setSession(
                SetSessionRequest(
                    cookies = linkedMapOf("configured_sid" to "configured-cookie"),
                    headers = linkedMapOf(
                        "Authorization" to "Bearer configured-header",
                        "X-Configured" to "configured-custom",
                    ),
                    origin = ORIGIN,
                )
            )
            session.send(AuthenticatedRequest(method = "POST", url = "$ORIGIN/login", body = "login"))
            assertEquals("observed-cookie", session.getCookieJar().cookies.single().value)

            val cleared = session.clearSession()
            val afterClear = session.send(
                AuthenticatedRequest(
                    method = "POST",
                    url = "$ORIGIN/after-clear",
                    body = "credential-free",
                    extraHeaders = linkedMapOf("X-After" to "still-present"),
                )
            )

            assertTrue(cleared.cookies.isEmpty())
            assertTrue(cleared.headers.isEmpty())
            assertNull(database.sessions.load())
            assertEquals(0, session.getCookieJar().total)
            assertEquals(PersistenceStatus.PERSISTED, afterClear.persistence.status)
            val later = harness.sent[1]
            assertEquals(listOf("X-After" to "still-present"), later.headers)
            assertContentEquals("credential-free".encodeToByteArray(), later.body)
            val serialized = later.headers.joinToString("\n") { "${it.first}: ${it.second}" }
            listOf(
                "configured-cookie",
                "configured-header",
                "configured-custom",
                "observed-cookie",
            ).forEach { marker -> assertFalse(serialized.contains(marker), "later send leaked $marker") }
        }
    }

    @Test
    fun `repeater and session share unique ordered history ids`() {
        IntegrationDatabase().use { database ->
            val harness = MutableHttpHarness { _, index ->
                WireResponse(status = (210 + index).toShort(), body = "response-$index".encodeToByteArray())
            }
            val repeater = database.repeaterService(harness)
            val session = database.sessionService(harness)

            val repeated = repeater.send(
                SendRequest(
                    request = HttpRequestData(
                        method = "POST",
                        url = "$ORIGIN/from-repeater",
                        headers = listOf(HttpHeader("X-Duplicate", "one"), HttpHeader("X-Duplicate", "two")),
                        body = "repeater-body",
                    )
                )
            )
            session.setSession(
                SetSessionRequest(
                    cookies = mapOf("sid" to "session-cookie"),
                    origin = ORIGIN,
                )
            )
            val authenticated = session.send(
                AuthenticatedRequest(method = "PUT", url = "$ORIGIN/from-session", body = "session-body")
            )

            assertEquals(1L, repeated.persistence.historyId)
            assertEquals(2L, authenticated.persistence.historyId)
            assertEquals(PersistenceStatus.PERSISTED, repeated.persistence.status)
            assertEquals(PersistenceStatus.PERSISTED, authenticated.persistence.status)
            val rows = database.history.search(HistoryFilter())
            assertEquals(listOf(2L, 1L), rows.map { it.id })
            assertEquals(listOf("session", "repeater"), rows.map { it.source })
            assertEquals(
                listOf(HttpHeader("X-Duplicate", "one"), HttpHeader("X-Duplicate", "two")),
                assertNotNull(database.history.getById(1)).reqHeaders,
            )
            assertEquals("session-body", assertNotNull(database.history.getById(2)).reqBody)
        }
    }

    @Test
    fun `one shared recorder failure does not poison the next service send`() {
        val harness = MutableHttpHarness()
        val history = mockk<HistoryDao>()
        val sitemap = mockk<SitemapDao>()
        val logging = mockk<Logging>()
        val sources = mutableListOf<String>()
        every { harness.api.logging() } returns logging
        every { logging.logToError(any<String>()) } just runs
        every {
            history.insertWithSitemap(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
            )
        } answers {
            sources += arg<String>(1)
            if (sources.size == 1) error("INERT_DB_FAILURE_A")
            73L
        }
        val repeater = RepeaterService(
            harness.api,
            history,
            sitemap,
            harness::request,
            harness::body,
        )
        val session = SessionService(
            harness.api,
            history,
            sitemap,
            null,
            SessionServiceCollaborators(
                requestFactory = harness::request,
                bodyFactory = harness::body,
            ),
        )

        val failedPersistence = repeater.send(
            SendRequest(request = HttpRequestData("POST", "$ORIGIN/recorder-fails", body = "first"))
        )
        val recovered = session.send(
            AuthenticatedRequest(method = "POST", url = "$ORIGIN/recorder-recovers", body = "second")
        )

        assertEquals(PersistenceStatus.FAILED, failedPersistence.persistence.status)
        assertTrue(failedPersistence.persistence.warning.orEmpty().contains("do not retry"))
        assertFalse(failedPersistence.persistence.warning.orEmpty().contains("INERT_DB_FAILURE_A"))
        assertEquals(PersistenceStatus.PERSISTED, recovered.persistence.status)
        assertEquals(73L, recovered.persistence.historyId)
        assertEquals(listOf("repeater", "session"), sources)
        assertEquals(
            listOf("$ORIGIN/recorder-fails", "$ORIGIN/recorder-recovers"),
            harness.sent.map { it.url },
        )
        assertTrue(session.getSession().cookies.isEmpty())
        assertEquals(0, session.getCookieJar().total)
        verify(exactly = 1) { logging.logToError(any<String>()) }
    }

    @Test
    fun `absent persistence keeps both primary send effects and reports not configured`() {
        val harness = MutableHttpHarness()
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
        val repeater = RepeaterService(
            api = harness.api,
            requestFactory = harness::request,
            bodyFactory = harness::body,
        )
        session.setSession(SetSessionRequest(cookies = mapOf("sid" to "inert"), origin = ORIGIN))

        val sessionResult = session.send(AuthenticatedRequest(url = "$ORIGIN/session-primary"))
        val repeaterResult = repeater.send(
            SendRequest(request = HttpRequestData("POST", "$ORIGIN/repeater-primary", body = "payload"))
        )

        assertEquals(PersistenceStatus.NOT_CONFIGURED, sessionResult.persistence.status)
        assertEquals(PersistenceStatus.NOT_CONFIGURED, repeaterResult.persistence.status)
        assertTrue(sessionResult.hasResponse)
        assertTrue(repeaterResult.hasResponse)
        assertEquals(200, sessionResult.statusCode)
        assertEquals(200, repeaterResult.response.statusCode)
        assertFalse(sessionResult.persistence.historyPersisted)
        assertFalse(sessionResult.persistence.sitemapPersisted)
        assertFalse(repeaterResult.persistence.historyPersisted)
        assertFalse(repeaterResult.persistence.sitemapPersisted)
        assertNull(sessionResult.persistence.historyId)
        assertNull(repeaterResult.persistence.historyId)
        assertNull(sessionResult.persistence.warning)
        assertNull(repeaterResult.persistence.warning)
        assertEquals(
            listOf("$ORIGIN/session-primary", "$ORIGIN/repeater-primary"),
            harness.sent.map { it.url },
        )
        assertContentEquals("payload".encodeToByteArray(), harness.sent.last().body)
        assertFalse(harness.sent.last().headers.any { it.second.contains("inert") })
    }

    private data class ReplayFixture(
        val body: String,
        val harness: MutableHttpHarness,
        val repeater: RepeaterService,
        val originalId: Long,
    )

    private fun prepareReplay(database: IntegrationDatabase): ReplayFixture {
        val body = "{\"message\":\"café αβγ 😀\"}"
        val harness = MutableHttpHarness { _, index ->
            if (index == 0) {
                WireResponse(
                    status = 201,
                    headers = listOf("Content-Type" to "application/json"),
                    body = "first-response".encodeToByteArray(),
                )
            } else {
                WireResponse(status = 202, body = "replayed-response".encodeToByteArray())
            }
        }
        val session = database.sessionService(harness)
        val repeater = database.repeaterService(harness)
        session.setSession(
            SetSessionRequest(
                cookies = linkedMapOf("sid" to "configured-cookie"),
                headers = linkedMapOf(
                    "Authorization" to "Bearer configured-header",
                    "X-Session" to "configured-secondary",
                ),
                name = "composition",
                origin = ORIGIN,
            )
        )
        val original = session.send(
            AuthenticatedRequest(
                method = "POST",
                url = "$ORIGIN/resource",
                body = body,
                extraHeaders = linkedMapOf("Content-Type" to "application/json"),
            )
        )
        val originalId = assertNotNull(original.persistence.historyId)
        val stored = assertNotNull(database.history.getById(originalId))
        assertEquals(PersistenceStatus.PERSISTED, original.persistence.status)
        assertEquals("session", stored.source)
        assertEquals(
            listOf(
                HttpHeader("Cookie", "sid=configured-cookie"),
                HttpHeader("Authorization", "Bearer configured-header"),
                HttpHeader("X-Session", "configured-secondary"),
                HttpHeader("Content-Type", "application/json"),
            ),
            stored.reqHeaders,
        )
        assertEquals(body, stored.reqBody)
        assertEquals(201, stored.statusCode)
        assertContentEquals(body.encodeToByteArray(), harness.sent.single().body)
        return ReplayFixture(body, harness, repeater, originalId)
    }

    private fun assertReplayState(
        database: IntegrationDatabase,
        fixture: ReplayFixture,
        responseBody: String,
    ) {
        val replayedWire = fixture.harness.sent[1]
        assertEquals(fixture.harness.sent[0].method, replayedWire.method)
        assertEquals(fixture.harness.sent[0].url, replayedWire.url)
        assertEquals(fixture.harness.sent[0].headers, replayedWire.headers)
        assertContentEquals(fixture.harness.sent[0].body, replayedWire.body)
        val rows = database.history.search(HistoryFilter())
        assertEquals(listOf(2L, 1L), rows.map { it.id })
        assertEquals("session", rows.last().source)
        val replayedJson = Json.parseToJsonElement(responseBody)
            .jsonObject.getValue("data").jsonObject.getValue("replayed").jsonObject
        assertEquals("POST", replayedJson.getValue("method").jsonPrimitive.content)
        assertEquals(fixture.body, replayedJson.getValue("reqBody").jsonPrimitive.content)
        assertEquals(
            rows.first().id,
            replayedJson.getValue("id").jsonPrimitive.long,
            "replay response must identify the authoritative history row created by replay",
        )
        assertEquals(
            rows.first().source,
            replayedJson.getValue("source").jsonPrimitive.content,
            "replay response source must match the authoritative history row",
        )
    }

    private class IntegrationDatabase : Closeable {
        private val root: Path = Files.createTempDirectory(
            Path.of(System.getProperty("user.home")),
            "burpctl-integration-",
        )
        private val manager = DatabaseManager(root.resolve("database").resolve("store").toString())
        val history = HistoryDao(manager)
        val sitemap = SitemapDao(manager)
        val sessions = SessionDao(manager)

        fun dropSitemap() {
            manager.withConnection { connection ->
                connection.createStatement().use { it.execute("DROP TABLE sitemap") }
            }
        }

        fun sessionService(harness: MutableHttpHarness) = SessionService(
            harness.api,
            history,
            sitemap,
            sessions,
            SessionServiceCollaborators(
                requestFactory = harness::request,
                bodyFactory = harness::body,
            ),
        )

        fun repeaterService(harness: MutableHttpHarness) = RepeaterService(
            harness.api,
            history,
            sitemap,
            harness::request,
            harness::body,
        )

        override fun close() {
            manager.close()
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private companion object {
        const val ORIGIN = "https://composition.example"
    }
}
