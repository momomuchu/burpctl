package com.burprest.routes

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import com.burprest.db.DatabaseManager
import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.db.SitemapDao
import com.burprest.server.installErrorHandling
import com.burprest.server.installStrictJson
import com.burprest.services.RepeaterService
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HistoryReplayPersistenceTest {
    @Test
    fun `completed replay exposes successful persistence`() = withFixture { fixture ->
        testApplication {
            application {
                installStrictJson()
                installErrorHandling { }
                routing { historyRoutes(fixture.history, fixture.sitemap, fixture.service) }
            }

            val response = client.post("/history/${fixture.originalId}/replay")
            val body = response.bodyAsText()
            val data = Json.parseToJsonElement(body).jsonObject["data"]!!.jsonObject
            val persistence = data["persistence"]!!.jsonObject

            assertEquals(HttpStatusCode.OK, response.status, body)
            assertEquals(1, fixture.sendCount.get(), "a completed replay must be sent exactly once")
            assertEquals(2L, fixture.history.count(HistoryFilter()))
            assertEquals(0, fixture.warningCount.get())
            assertEquals("persisted", persistence["status"]!!.jsonPrimitive.content)
            assertTrue(persistence["historyPersisted"]!!.jsonPrimitive.boolean)
            assertTrue(persistence["sitemapPersisted"]!!.jsonPrimitive.boolean)
            assertTrue(persistence["historyId"]!!.jsonPrimitive.content.toLong() > fixture.originalId)
        }
    }

    @Test
    fun `completed replay exposes failed persistence and no-retry warning`() = withFixture { fixture ->
        fixture.rejectRepeaterPersistence()

        testApplication {
            application {
                installStrictJson()
                installErrorHandling { }
                routing { historyRoutes(fixture.history, fixture.sitemap, fixture.service) }
            }

            val response = client.post("/history/${fixture.originalId}/replay")
            val body = response.bodyAsText()
            val data = Json.parseToJsonElement(body).jsonObject["data"]!!.jsonObject

            assertEquals(HttpStatusCode.OK, response.status, body)
            assertEquals(1, fixture.sendCount.get(), "a completed replay must never be retried")
            assertEquals(fixture.originalId, data["original"]!!.jsonObject["id"]!!.jsonPrimitive.content.toLong())
            assertEquals("replay", data["replayed"]!!.jsonObject["source"]!!.jsonPrimitive.content)
            assertEquals(201, data["replayed"]!!.jsonObject["statusCode"]!!.jsonPrimitive.content.toInt())
            assertEquals(1L, fixture.history.count(HistoryFilter()), "failed optional persistence must roll back")
            assertEquals(1, fixture.warningCount.get(), "the optional persistence failure path must execute once")
            assertTrue(fixture.warning.get().orEmpty().contains("do not retry", ignoreCase = true))

            val persistence = assertNotNull(
                data["persistence"],
                "completed replay response must expose failed persistence so callers do not retry: $body",
            ).jsonObject
            assertEquals("failed", persistence["status"]!!.jsonPrimitive.content)
            assertTrue(persistence["warning"]!!.jsonPrimitive.content.contains("do not retry", ignoreCase = true))
        }
    }

    @Test
    fun `missing history entry performs no target send`() = withFixture { fixture ->
        testApplication {
            application {
                installStrictJson()
                installErrorHandling { }
                routing { historyRoutes(fixture.history, fixture.sitemap, fixture.service) }
            }

            val response = client.post("/history/${fixture.originalId + 1}/replay")

            assertEquals(HttpStatusCode.BadRequest, response.status, response.bodyAsText())
            assertEquals(0, fixture.sendCount.get())
            assertEquals(0, fixture.warningCount.get())
            assertEquals(1L, fixture.history.count(HistoryFilter()))
        }
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        Fixture.create().use(block)
    }

    private class Fixture private constructor(
        private val root: Path,
        private val database: DatabaseManager,
        private val routeState: RouteState,
        val originalId: Long,
        private val observations: TargetObservations,
    ) : AutoCloseable {
        val history: HistoryDao get() = routeState.history
        val sitemap: SitemapDao get() = routeState.sitemap
        val service: RepeaterService get() = routeState.service
        val sendCount: AtomicInteger get() = observations.sendCount
        val warningCount: AtomicInteger get() = observations.warningCount
        val warning: AtomicReference<String?> get() = observations.warning

        fun rejectRepeaterPersistence() {
            database.withConnection { connection ->
                connection.createStatement().use { statement ->
                    statement.execute(
                        "ALTER TABLE request_history ADD CONSTRAINT reject_repeater " +
                            "CHECK (source <> 'repeater')",
                    )
                }
            }
        }

        override fun close() {
            database.close()
            check(root.toFile().deleteRecursively()) { "history replay fixture root should be removed" }
        }

        companion object {
            fun create(): Fixture {
                val root = createTempDirectory("history-replay-persistence-").toRealPath()
                val database = DatabaseManager(root.resolve("history").toString())
                val history = HistoryDao(database)
                val sitemap = SitemapDao(database)
                val originalId = history.insert(
                    source = "fixture",
                    method = "GET",
                    url = "http://127.0.0.1:18080/replay-source",
                    reqHeaders = emptyList(),
                    reqBody = null,
                    statusCode = 200,
                    resHeaders = emptyList(),
                    resBody = "original",
                    durationMs = 2,
                    timestamp = "2026-10-23T10:00:00Z",
                )

                val api = mockk<MontoyaApi>()
                val http = mockk<Http>()
                val logging = mockk<Logging>()
                val request = request()
                val observations = TargetObservations()
                every { api.http() } returns http
                every { api.logging() } returns logging
                every { logging.logToError(any<String>()) } answers {
                    observations.warningCount.incrementAndGet()
                    observations.warning.set(firstArg())
                }
                every { http.sendRequest(request) } answers {
                    observations.sendCount.incrementAndGet()
                    response(statusCode = 201)
                }

                return Fixture(
                    root = root,
                    database = database,
                    routeState = RouteState(
                        history = history,
                        sitemap = sitemap,
                        service = RepeaterService(api, history, sitemap, requestFactory = { request }),
                    ),
                    originalId = originalId,
                    observations = observations,
                )
            }

            private fun request(): HttpRequest = mockk<HttpRequest>().also { request ->
                val body = mockk<BurpByteArray>()
                every { request.withMethod("GET") } returns request
                every { request.method() } returns "GET"
                every { request.url() } returns "http://127.0.0.1:18080/replay-source"
                every { request.headers() } returns emptyList()
                every { request.body() } returns body
                every { body.length() } returns 0
            }

            private fun response(statusCode: Short): HttpRequestResponse =
                mockk<HttpRequestResponse>().also { exchange ->
                    val response = mockk<HttpResponse>()
                    val body = mockk<BurpByteArray>()
                    every { exchange.hasResponse() } returns true
                    every { exchange.response() } returns response
                    every { response.statusCode() } returns statusCode
                    every { response.headers() } returns emptyList()
                    every { response.body() } returns body
                    every { body.length() } returns 0
                }
        }
    }

    private class TargetObservations(
        val sendCount: AtomicInteger = AtomicInteger(),
        val warningCount: AtomicInteger = AtomicInteger(),
        val warning: AtomicReference<String?> = AtomicReference(),
    )

    private data class RouteState(
        val history: HistoryDao,
        val sitemap: SitemapDao,
        val service: RepeaterService,
    )
}
