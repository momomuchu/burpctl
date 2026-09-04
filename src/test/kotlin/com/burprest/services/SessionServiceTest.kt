package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader as BurpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.burprest.db.HistoryDao
import com.burprest.db.PersistedSession
import com.burprest.db.SessionDao
import com.burprest.db.SitemapDao
import com.burprest.models.AuthenticatedRequest
import com.burprest.models.BatchAuthenticatedRequest
import com.burprest.models.HttpHeader
import com.burprest.models.PersistenceStatus
import com.burprest.models.SetSessionRequest
import com.burprest.server.NoResponseException
import io.mockk.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionServiceTest {

    private data class HttpFixture(
        val api: MontoyaApi,
        val http: Http,
        val sent: MutableList<HttpRequest>,
        val requestFactory: (String) -> HttpRequest,
        val bodyFactory: (kotlin.ByteArray) -> BurpByteArray,
    )

    private data class CaptureSchedule(
        val observer: SessionSynchronizationObserver,
        val lockState: MutableMap<SessionSynchronizationPoint, Boolean>,
    )

    private fun forcedClearCaptureSchedule(
        snapshotCaptured: CountDownLatch,
        clearAttempted: CountDownLatch,
        clearReturned: CountDownLatch,
    ): CaptureSchedule {
        val lockState = mutableMapOf<SessionSynchronizationPoint, Boolean>()
        val observer = SessionSynchronizationObserver { point, sessionLockHeld, _ ->
            if (point != SessionSynchronizationPoint.SESSION_SNAPSHOT &&
                point != SessionSynchronizationPoint.COOKIE_EPOCH
            ) {
                return@SessionSynchronizationObserver
            }
            lockState[point] = sessionLockHeld
            when (point) {
                SessionSynchronizationPoint.SESSION_SNAPSHOT -> {
                    snapshotCaptured.countDown()
                    assertTrue(clearAttempted.await(5, TimeUnit.SECONDS))
                }
                SessionSynchronizationPoint.COOKIE_EPOCH -> if (!sessionLockHeld) {
                    assertTrue(clearReturned.await(5, TimeUnit.SECONDS))
                }
                else -> Unit
            }
        }
        return CaptureSchedule(observer, lockState)
    }

    private fun httpFixture(vararg responses: List<Pair<String, String>>): HttpFixture {
        val api = mockk<MontoyaApi>()
        val http = mockk<Http>()
        val sent = Collections.synchronizedList(mutableListOf<HttpRequest>())
        val queue = ArrayDeque(responses.map(::exchange))
        every { api.http() } returns http
        every { http.sendRequest(any<HttpRequest>()) } answers {
            sent.add(firstArg<HttpRequest>())
            synchronized(queue) {
                if (queue.isEmpty()) exchange(emptyList()) else queue.removeFirst()
            }
        }
        every { http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) } answers {
            sent.add(firstArg<HttpRequest>())
            synchronized(queue) {
                if (queue.isEmpty()) exchange(emptyList()) else queue.removeFirst()
            }
        }
        val bodyFactory: (kotlin.ByteArray) -> BurpByteArray = { bytes ->
            mockk<BurpByteArray>().also { body ->
                every { body.length() } returns bytes.size
                every { body.getBytes() } returns bytes.copyOf()
            }
        }
        return HttpFixture(api, http, sent, ::request, bodyFactory)
    }

    private fun request(url: String): HttpRequest {
        val request = mockk<HttpRequest>()
        val headers = mutableListOf<BurpHeader>()
        var bodyBytes = byteArrayOf()
        val body = mockk<BurpByteArray>()
        every { request.url() } returns url
        every { request.headers() } answers { synchronized(headers) { headers.toList() } }
        every { request.body() } returns body
        every { request.bodyToString() } answers { bodyBytes.toString(Charsets.ISO_8859_1) }
        every { body.length() } answers { bodyBytes.size }
        every { body.getBytes() } answers { bodyBytes.copyOf() }
        every { request.withMethod(any()) } returns request
        every { request.withBody(any<String>()) } answers {
            bodyBytes = firstArg<String>().map { it.code.toByte() }.toByteArray()
            request
        }
        every { request.withBody(any<BurpByteArray>()) } answers {
            bodyBytes = firstArg<BurpByteArray>().getBytes().copyOf()
            request
        }
        every { request.withRemovedHeader(any<String>()) } answers {
            val name = firstArg<String>()
            synchronized(headers) { headers.removeAll { it.name().equals(name, ignoreCase = true) } }
            request
        }
        every { request.withAddedHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            val header = mockk<BurpHeader>()
            every { header.name() } returns name
            every { header.value() } returns value
            synchronized(headers) { headers.add(header) }
            request
        }
        return request
    }

    private fun HttpFixture.collaborators(
        clock: () -> Long = System::currentTimeMillis,
        boundedRequestSender: BoundedRequestSender? = null,
        synchronizationObserver: SessionSynchronizationObserver =
            SessionSynchronizationObserver { _, _, _ -> },
    ) = SessionServiceCollaborators(
        clock = clock,
        requestFactory = requestFactory,
        bodyFactory = bodyFactory,
        boundedRequestSender = boundedRequestSender,
        synchronizationObserver = synchronizationObserver,
    )

    private fun HttpFixture.service(
        historyDao: HistoryDao? = null,
        sitemapDao: SitemapDao? = null,
        sessionDao: SessionDao? = null,
        collaborators: SessionServiceCollaborators = collaborators(),
    ): SessionService = SessionService(
        api,
        historyDao,
        sitemapDao,
        sessionDao,
        collaborators,
    )

    private fun exchange(headers: List<Pair<String, String>>, bodyText: String = "ok"): HttpRequestResponse =
        exchangeBytes(headers, bodyText.encodeToByteArray())

    private fun exchangeBytes(
        headers: List<Pair<String, String>>,
        bodyBytes: kotlin.ByteArray,
    ): HttpRequestResponse {
        val exchange = mockk<HttpRequestResponse>()
        val response = mockk<HttpResponse>()
        val body = mockk<BurpByteArray>()
        every { exchange.hasResponse() } returns true
        every { exchange.response() } returns response
        every { response.statusCode() } returns 200
        every { response.headers() } returns headers.map { (name, value) ->
            mockk<BurpHeader>().also { header ->
                every { header.name() } returns name
                every { header.value() } returns value
            }
        }
        every { response.body() } returns body
        every { body.length() } returns bodyBytes.size
        every { body.getBytes() } returns bodyBytes.copyOf()
        every { response.bodyToString() } returns bodyBytes.toString(Charsets.ISO_8859_1)
        return exchange
    }

    private fun HttpRequest.headerValueOrNull(name: String): String? =
        headers().lastOrNull { it.name().equals(name, ignoreCase = true) }?.value()

    @Test
    fun `setSession validates cookie names and values before persistence`() {
        val dao = mockk<SessionDao>(relaxed = true)
        every { dao.load() } returns null
        val service = SessionService(mockk(relaxed = true), sessionDao = dao)
        val badCookies = listOf(
            mapOf("a=b" to "v"),
            mapOf("a b" to "v"),
            mapOf("sid" to "abc; injected=1"),
            mapOf("sid" to "line\rbreak"),
            mapOf("sid" to "line\nbreak"),
            mapOf("sid" to "nul\u0000break"),
            mapOf("sid" to "non-ascii-£"),
        )

        badCookies.forEach { cookies ->
            assertFailsWith<IllegalArgumentException> {
                service.setSession(SetSessionRequest(cookies = cookies))
            }
        }

        verify(exactly = 0) { dao.save(any(), any(), any(), any()) }
        assertTrue(service.getSession().cookies.isEmpty())
    }

    @Test
    fun `setSession validates session header names and values before persistence`() {
        val dao = mockk<SessionDao>(relaxed = true)
        every { dao.load() } returns null
        val service = SessionService(mockk(relaxed = true), sessionDao = dao)
        val badHeaders = listOf(
            mapOf("Bad Header" to "value"),
            mapOf("Bad:Header" to "value"),
            mapOf("X-Test\r\nInjected" to "value"),
            mapOf("X-Test" to "line\rbreak"),
            mapOf("X-Test" to "line\nbreak"),
            mapOf("X-Test" to "nul\u0000break"),
            mapOf("X-Test" to "control\u0001break"),
        )

        badHeaders.forEach { headers ->
            assertFailsWith<IllegalArgumentException> {
                service.setSession(SetSessionRequest(cookies = mapOf("sid" to "safe"), headers = headers))
            }
        }

        verify(exactly = 0) { dao.save(any(), any(), any(), any()) }
        assertTrue(service.getSession().cookies.isEmpty())
    }

    @Test
    fun `setSession accepts RFC cookie and header characters and fully replaces state`() {
        val dao = mockk<SessionDao>(relaxed = true)
        every { dao.load() } returns null
        val service = SessionService(mockk(relaxed = true), sessionDao = dao)
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "abc==", "quoted" to "\"abc-123\""),
                headers = mapOf("X_Test~One" to "text\tvalue £"),
                name = "first",
                origin = "HTTPS://Example.TEST:443/",
            )
        )

        val result = service.setSession(
            SetSessionRequest(
                cookies = mapOf("new" to "fresh"),
                headers = null,
                name = null,
                origin = "https://EXAMPLE.test",
            )
        )

        assertEquals("first", result.name)
        assertEquals(mapOf("new" to "fresh"), result.cookies)
        assertTrue(result.headers.isEmpty())
        assertEquals("https://example.test", result.origin)
        verify { dao.save("first", mapOf("new" to "fresh"), emptyMap(), "https://example.test") }
    }

    @Test
    fun `published snapshot is isolated from caller maps and mutation`() {
        val cookies = linkedMapOf("sid" to "one")
        val headers = linkedMapOf("X-Test" to "one")
        val service = SessionService(mockk(relaxed = true))

        service.setSession(SetSessionRequest(cookies, headers, origin = "https://example.test"))
        cookies["sid"] = "changed"
        headers["X-Test"] = "changed"
        val published = service.getSession()

        assertEquals("one", published.cookies.getValue("sid"))
        assertEquals("one", published.headers.getValue("X-Test"))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (published.cookies as MutableMap<String, String>)["sid"] = "mutated"
        }
        assertEquals("one", service.getSession().cookies.getValue("sid"))
    }

    @Test
    fun `request material snapshot distinguishes absent empty and unavailable states`() {
        val fixture = httpFixture()
        val service = fixture.service()

        assertEquals(
            SessionRequestMaterialSnapshot.NotConfigured,
            service.snapshotSessionRequestMaterial("https://example.test/path"),
        )

        service.setSession(SetSessionRequest(cookies = emptyMap()))
        assertEquals(
            SessionRequestMaterialSnapshot.Available(
                headers = emptyList(),
                cookies = emptyList(),
                cookieHeaderValue = null,
            ),
            service.snapshotSessionRequestMaterial("https://example.test/path"),
        )

        val unavailable = fixture.service(
            collaborators = fixture.collaborators(clock = { error("clock unavailable") }),
        )
        assertEquals(
            SessionRequestMaterialSnapshot.Unavailable,
            unavailable.snapshotSessionRequestMaterial("https://example.test/path"),
        )
    }

    @Test
    fun `request material snapshot returns exact matching cookie pairs and wire value`() {
        val fixture = httpFixture(
            listOf(
                "Set-Cookie" to "jar=one; Domain=example.test; Path=/app; Secure",
                "Set-Cookie" to "outside=two; Path=/outside",
                "Set-Cookie" to "sid=jar-value; Path=/app",
            )
        )
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "configured"),
                headers = mapOf("X-Api-Key" to "key"),
                origin = "https://api.example.test",
            )
        )
        service.send(AuthenticatedRequest(url = "https://api.example.test/app/start"))

        assertEquals(
            SessionRequestMaterialSnapshot.Available(
                headers = listOf(HttpHeader("X-Api-Key", "key")),
                cookies = listOf(
                    SessionRequestCookie("jar", "one"),
                    SessionRequestCookie("sid", "configured"),
                ),
                cookieHeaderValue = "jar=one; sid=configured",
            ),
            service.snapshotSessionRequestMaterial("https://api.example.test/app/next"),
        )
        assertEquals(
            SessionRequestMaterialSnapshot.Available(
                headers = listOf(HttpHeader("X-Api-Key", "key")),
                cookies = listOf(SessionRequestCookie("sid", "configured")),
                cookieHeaderValue = "sid=configured",
            ),
            service.snapshotSessionRequestMaterial("https://api.example.test/not-app"),
        )
    }

    @Test
    fun `setSession publishes only after persistence succeeds`() {
        val dao = mockk<SessionDao>()
        every { dao.load() } returns null
        every { dao.save(any(), any(), any(), any()) } just Runs
        val service = SessionService(mockk(relaxed = true), sessionDao = dao)
        service.setSession(SetSessionRequest(mapOf("old" to "one"), name = "old"))
        every { dao.save(any(), any(), any(), any()) } throws IllegalStateException("disk failed")

        assertFailsWith<IllegalStateException> {
            service.setSession(SetSessionRequest(mapOf("new" to "two"), name = "new"))
        }

        val state = service.getSession()
        assertEquals("old", state.name)
        assertEquals(mapOf("old" to "one"), state.cookies)
        assertNull(state.origin)
    }

    @Test
    fun `setSession does not publish while persistence is in flight`() {
        val dao = mockk<SessionDao>()
        every { dao.load() } returns null
        val saveEntered = CountDownLatch(1)
        val allowSave = CountDownLatch(1)
        every { dao.save(any(), any(), any(), any()) } answers {
            saveEntered.countDown()
            assertTrue(allowSave.await(5, TimeUnit.SECONDS))
        }
        val service = SessionService(mockk(relaxed = true), sessionDao = dao)
        val pool = Executors.newSingleThreadExecutor()
        try {
            val future = pool.submit<com.burprest.models.SessionInfo> {
                service.setSession(SetSessionRequest(mapOf("new" to "two"), name = "new"))
            }
            assertTrue(saveEntered.await(5, TimeUnit.SECONDS))
            assertTrue(service.getSession().cookies.isEmpty())
            allowSave.countDown()
            assertEquals(mapOf("new" to "two"), future.get(5, TimeUnit.SECONDS).cookies)
        } finally {
            allowSave.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `clearSession persists before publishing and clears observed cookie jar on success`() {
        val fixture = httpFixture(listOf("Set-Cookie" to "observed=yes; Path=/"))
        val dao = mockk<SessionDao>()
        every { dao.load() } returns null
        every { dao.save(any(), any(), any(), any()) } just Runs
        every { dao.clear() } returns 1
        val service = fixture.service(sessionDao = dao)
        service.setSession(
            SetSessionRequest(mapOf("auth" to "secret"), mapOf("Authorization" to "Bearer token"), "named")
        )
        service.send(AuthenticatedRequest(url = "https://example.test/login"))
        every { dao.clear() } throws IllegalStateException("disk failed")

        assertFailsWith<IllegalStateException> { service.clearSession() }
        assertEquals(mapOf("auth" to "secret"), service.getSession().cookies)
        assertEquals(1, service.getCookieJar().total)

        every { dao.clear() } returns 1
        val cleared = service.clearSession()
        assertEquals("default", cleared.name)
        assertTrue(cleared.cookies.isEmpty())
        assertTrue(cleared.headers.isEmpty())
        assertNull(cleared.origin)
        assertEquals(0, service.getCookieJar().total)
    }

    @Test
    fun `clearSession removes configured state and the observed cookie jar before returning`() {
        val fixture = httpFixture(listOf("Set-Cookie" to "observed=yes; Path=/"))
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("auth" to "secret"),
                headers = mapOf("Authorization" to "Bearer token"),
                origin = "https://example.test",
            )
        )
        service.send(AuthenticatedRequest(url = "https://example.test/login"))
        assertEquals(1, service.getCookieJar().total)

        val cleared = service.clearSession()

        assertTrue(cleared.cookies.isEmpty())
        assertTrue(cleared.headers.isEmpty())
        assertNull(cleared.origin)
        assertEquals(0, service.getCookieJar().total)
    }

    @Test
    fun `every load-bearing synchronization point holds its required lock`() {
        val fixture = httpFixture()
        val observed = mutableSetOf<SessionSynchronizationPoint>()
        val requiresSessionLock = setOf(
            SessionSynchronizationPoint.SET_SESSION,
            SessionSynchronizationPoint.CLEAR_SESSION,
            SessionSynchronizationPoint.CLEAR_SESSION_COOKIE_JAR,
            SessionSynchronizationPoint.CLEAR_COOKIE_JAR,
            SessionSynchronizationPoint.CLEAR_COOKIE_JAR_COOKIE_JAR,
            SessionSynchronizationPoint.BATCH_SEND,
            SessionSynchronizationPoint.REQUEST_MATERIAL_SNAPSHOT,
            SessionSynchronizationPoint.SESSION_SNAPSHOT,
            SessionSynchronizationPoint.COOKIE_EPOCH,
            SessionSynchronizationPoint.AUTHENTICATED_SEND_SNAPSHOT,
        )
        val requiresCookieLock = setOf(
            SessionSynchronizationPoint.CLEAR_SESSION_COOKIE_JAR,
            SessionSynchronizationPoint.COOKIE_JAR_READ,
            SessionSynchronizationPoint.CLEAR_COOKIE_JAR_COOKIE_JAR,
            SessionSynchronizationPoint.REQUEST_MATERIAL_SNAPSHOT,
            SessionSynchronizationPoint.RESPONSE_COOKIE_COMPARE_CAPTURE,
        )
        val observer = SessionSynchronizationObserver { point, sessionLockHeld, cookieLockHeld ->
            observed += point
            if (point in requiresSessionLock) {
                assertTrue(sessionLockHeld, "$point must hold sessionMutationLock")
            }
            if (point in requiresCookieLock) {
                assertTrue(cookieLockHeld, "$point must hold cookieMutationLock")
            }
        }
        val service = fixture.service(
            collaborators = fixture.collaborators(synchronizationObserver = observer),
        )
        val request = AuthenticatedRequest(url = "https://example.test/path")

        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "configured"),
                headers = mapOf("X-Api-Key" to "configured"),
                origin = "https://example.test",
            )
        )
        service.send(request)
        service.sendUnauthenticated(request)
        service.sendPreservingHeaders(request, emptyList(), CredentialMode.FULL)
        service.sendBatch(BatchAuthenticatedRequest(listOf(request)))
        service.getCookieJar()
        service.snapshotSessionRequestMaterial(request.url)
        service.clearCookieJar()
        service.clearSession()

        assertEquals(SessionSynchronizationPoint.entries.toSet(), observed)
    }

    @Test
    fun `clearSession prevents an older in-flight send from restoring captured cookies`() {
        val fixture = httpFixture(listOf("Set-Cookie" to "late=credential; Path=/"))
        val sendEntered = CountDownLatch(1)
        val allowResponse = CountDownLatch(1)
        every { fixture.http.sendRequest(any<HttpRequest>()) } answers {
            sendEntered.countDown()
            assertTrue(allowResponse.await(5, TimeUnit.SECONDS))
            exchange(listOf("Set-Cookie" to "late=credential; Path=/"))
        }
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(mapOf("sid" to "configured"), origin = "https://example.test")
        )
        val pool = Executors.newSingleThreadExecutor()
        try {
            val send = pool.submit {
                service.send(AuthenticatedRequest(url = "https://example.test/slow"))
            }
            assertTrue(sendEntered.await(5, TimeUnit.SECONDS))

            service.clearSession()
            allowResponse.countDown()
            send.get(5, TimeUnit.SECONDS)

            assertEquals(0, service.getCookieJar().total)
        } finally {
            allowResponse.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `clearSession cannot interleave between credential snapshot and cookie epoch`() =
        assertClearCannotInterleave { it.clearSession() }

    @Test
    fun `clearCookieJar cannot interleave between credential snapshot and cookie epoch`() =
        assertClearCannotInterleave { it.clearCookieJar() }

    private fun assertClearCannotInterleave(clear: (SessionService) -> Unit) {
        val fixture = httpFixture(listOf("Set-Cookie" to "late=credential; Path=/"))
        val snapshotCaptured = CountDownLatch(1)
        val clearAttempted = CountDownLatch(1)
        val clearReturned = CountDownLatch(1)
        every { fixture.http.sendRequest(any<HttpRequest>()) } answers {
            fixture.sent.add(firstArg())
            assertTrue(
                clearReturned.await(5, TimeUnit.SECONDS),
                "the clear operation must return before the late Set-Cookie response is observed",
            )
            exchange(listOf("Set-Cookie" to "late=credential; Path=/"))
        }
        val captureSchedule = forcedClearCaptureSchedule(snapshotCaptured, clearAttempted, clearReturned)
        val service = fixture.service(
            collaborators = fixture.collaborators(synchronizationObserver = captureSchedule.observer),
        )
        service.setSession(
            SetSessionRequest(mapOf("sid" to "configured"), origin = "https://example.test")
        )
        val pool = Executors.newFixedThreadPool(2)
        try {
            val clearFuture = pool.submit {
                snapshotCaptured.await()
                clearAttempted.countDown()
                clear(service)
                clearReturned.countDown()
            }
            val send = pool.submit {
                service.send(AuthenticatedRequest(url = "https://example.test/slow"))
            }

            send.get(10, TimeUnit.SECONDS)
            clearFuture.get(10, TimeUnit.SECONDS)

            assertEquals("sid=configured", fixture.sent.single().headerValueOrNull("Cookie"))
            assertEquals(
                0,
                service.getCookieJar().total,
                "an epoch newer than the credential snapshot let a cleared send restore credentials",
            )
            assertEquals(
                true,
                captureSchedule.lockState[SessionSynchronizationPoint.SESSION_SNAPSHOT],
                "the configured credential snapshot must be captured under the session lock",
            )
            assertEquals(
                true,
                captureSchedule.lockState[SessionSynchronizationPoint.COOKIE_EPOCH],
                "the cookie epoch must be captured under the same session lock",
            )
        } finally {
            snapshotCaptured.countDown()
            clearAttempted.countDown()
            clearReturned.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `clearCookieJar prevents an older in-flight send from restoring captured cookies`() {
        val fixture = httpFixture(listOf("Set-Cookie" to "late=credential; Path=/"))
        val sendEntered = CountDownLatch(1)
        val allowResponse = CountDownLatch(1)
        every { fixture.http.sendRequest(any<HttpRequest>()) } answers {
            sendEntered.countDown()
            assertTrue(allowResponse.await(5, TimeUnit.SECONDS))
            exchange(listOf("Set-Cookie" to "late=credential; Path=/"))
        }
        val service = fixture.service()
        val pool = Executors.newSingleThreadExecutor()
        try {
            val send = pool.submit {
                service.send(AuthenticatedRequest(url = "https://example.test/slow"))
            }
            assertTrue(sendEntered.await(5, TimeUnit.SECONDS))

            service.clearCookieJar()
            allowResponse.countDown()
            send.get(5, TimeUnit.SECONDS)

            assertEquals(0, service.getCookieJar().total)
        } finally {
            allowResponse.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `clearCookieJar leaves session credentials and origin unchanged`() {
        val fixture = httpFixture(listOf("Set-Cookie" to "observed=yes; Path=/"))
        val service = fixture.service()
        service.setSession(SetSessionRequest(mapOf("auth" to "secret"), origin = "https://example.test"))
        service.send(AuthenticatedRequest(url = "https://example.test/login"))

        service.clearCookieJar()

        assertEquals(mapOf("auth" to "secret"), service.getSession().cookies)
        assertEquals("https://example.test", service.getSession().origin)
        assertEquals(0, service.getCookieJar().total)
    }

    @Test
    fun `origin normalization compares scheme host effective port and handles IPv6`() {
        val fixture = httpFixture(emptyList(), emptyList(), emptyList())
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(mapOf("sid" to "secret"), origin = "HTTP://[2001:0db8:0:0:0:0:0:1]:80/")
        )

        service.send(AuthenticatedRequest(url = "http://[2001:db8::1]/one"))
        assertFailsWith<IllegalArgumentException> {
            service.send(AuthenticatedRequest(url = "https://[2001:db8::1]/two"))
        }
        assertFailsWith<IllegalArgumentException> {
            service.send(AuthenticatedRequest(url = "http://[2001:db8::1]:8080/three"))
        }

        assertEquals("http://[2001:db8:0:0:0:0:0:1]", service.getSession().origin)
        assertEquals(1, fixture.sent.size)
    }

    @Test
    fun `origin normalization treats Unicode and punycode host spellings as equal`() {
        val fixture = httpFixture(emptyList())
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(mapOf("sid" to "secret"), origin = "https://bücher.example")
        )

        service.send(AuthenticatedRequest(url = "https://xn--bcher-kva.example/path"))

        assertEquals("https://xn--bcher-kva.example", service.getSession().origin)
        assertEquals(1, fixture.sent.size)
    }

    @Test
    fun `cross-origin credentials are rejected before any target or persistence side effect`() {
        val fixture = httpFixture(emptyList())
        val dao = mockk<SessionDao>(relaxed = true)
        every { dao.load() } returns null
        val service = fixture.service(sessionDao = dao)
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "secret"),
                headers = mapOf("Authorization" to "Bearer secret"),
                origin = "https://example.test",
            )
        )

        assertFailsWith<IllegalArgumentException> {
            service.send(AuthenticatedRequest(url = "https://evil-example.test/path"))
        }

        assertTrue(fixture.sent.isEmpty())
        verify(exactly = 1) { dao.save(any(), any(), any(), any()) }
    }

    @Test
    fun `legacy persisted credentials bind atomically on first use before sending`() {
        val fixture = httpFixture(emptyList())
        val dao = mockk<SessionDao>()
        every { dao.load() } returns PersistedSession(
            name = "legacy",
            cookies = mapOf("sid" to "secret"),
            headers = emptyMap(),
            boundOrigin = null,
        )
        every { dao.save(any(), any(), any(), any()) } just Runs
        val service = fixture.service(sessionDao = dao)

        service.send(AuthenticatedRequest(url = "HTTPS://Example.Test:443/path"))

        assertEquals("https://example.test", service.getSession().origin)
        verify(exactly = 1) {
            dao.save("legacy", mapOf("sid" to "secret"), emptyMap(), "https://example.test")
        }
        assertEquals(1, fixture.sent.size)
    }

    @Test
    fun `legacy binding persistence failure publishes nothing and sends nothing`() {
        val fixture = httpFixture(emptyList())
        val dao = mockk<SessionDao>()
        every { dao.load() } returns PersistedSession(
            name = "legacy",
            cookies = mapOf("sid" to "secret"),
            headers = emptyMap(),
            boundOrigin = null,
        )
        every { dao.save(any(), any(), any(), any()) } throws IllegalStateException("disk failed")
        val service = fixture.service(sessionDao = dao)

        assertFailsWith<IllegalStateException> {
            service.send(AuthenticatedRequest(url = "https://example.test/path"))
        }

        assertNull(service.getSession().origin)
        assertTrue(fixture.sent.isEmpty())
    }

    @Test
    fun `concurrent legacy first use permits only one origin`() {
        val fixture = httpFixture(emptyList(), emptyList())
        val dao = mockk<SessionDao>()
        every { dao.load() } returns PersistedSession("legacy", mapOf("sid" to "secret"), emptyMap(), null)
        every { dao.save(any(), any(), any(), any()) } just Runs
        val service = fixture.service(sessionDao = dao)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val first = pool.submit<Result<Unit>> {
                runCatching {
                    start.await()
                    service.send(AuthenticatedRequest(url = "https://one.test/path"))
                    Unit
                }
            }
            val second = pool.submit<Result<Unit>> {
                runCatching {
                    start.await()
                    service.send(AuthenticatedRequest(url = "https://two.test/path"))
                    Unit
                }
            }
            start.countDown()
            val results = listOf(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS))

            assertEquals(1, results.count { it.isSuccess })
            assertEquals(1, results.count { it.exceptionOrNull() is IllegalArgumentException })
            assertEquals(1, fixture.sent.size)
            assertTrue(service.getSession().origin in setOf("https://one.test", "https://two.test"))
            verify(exactly = 1) { dao.save(any(), any(), any(), any()) }
        } finally {
            start.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `send takes one immutable session snapshot under concurrent replacement`() {
        val fixture = httpFixture(*Array(400) { emptyList<Pair<String, String>>() })
        val service = fixture.service()
        val pool = Executors.newFixedThreadPool(2)
        val start = CountDownLatch(1)
        try {
            val writer = pool.submit {
                start.await()
                repeat(200) { index ->
                    val marker = if (index % 2 == 0) "A" else "B"
                    service.setSession(
                        SetSessionRequest(
                            cookies = mapOf("session" to marker),
                            headers = mapOf("X-Snapshot" to marker),
                            origin = "https://example.test",
                        )
                    )
                }
            }
            val sender = pool.submit {
                start.await()
                repeat(200) { service.send(AuthenticatedRequest(url = "https://example.test/path")) }
            }
            start.countDown()
            writer.get(10, TimeUnit.SECONDS)
            sender.get(10, TimeUnit.SECONDS)

            fixture.sent.forEach { request ->
                val cookieMarker = request.headerValueOrNull("Cookie")?.substringAfter("session=")
                val headerMarker = request.headerValueOrNull("X-Snapshot")
                assertEquals(cookieMarker, headerMarker, "mixed session versions in one request")
            }
        } finally {
            start.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `invalid per-request headers are rejected with zero effects`() {
        val fixture = httpFixture(emptyList())
        val service = fixture.service()
        service.setSession(SetSessionRequest(mapOf("sid" to "safe"), origin = "https://example.test"))
        val invalid = listOf(
            mapOf("Bad Header" to "x"),
            mapOf("X-Test" to "x\r\nInjected: yes"),
            mapOf("X-Test" to "x\u0000y"),
        )

        invalid.forEach { headers ->
            assertFailsWith<IllegalArgumentException> {
                service.send(AuthenticatedRequest(url = "https://example.test/path", extraHeaders = headers))
            }
        }

        assertTrue(fixture.sent.isEmpty())
        assertEquals(0, service.getCookieJar().total)
    }

    @Test
    fun `per-request headers override session headers case-insensitively`() {
        val fixture = httpFixture(emptyList())
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "safe"),
                headers = mapOf("X-Role" to "user"),
                origin = "https://example.test",
            )
        )

        service.send(
            AuthenticatedRequest(
                url = "https://example.test/path",
                extraHeaders = mapOf("x-role" to "admin", "Cookie" to "manual=yes"),
            )
        )

        val request = fixture.sent.single()
        assertEquals("admin", request.headerValueOrNull("X-Role"))
        assertEquals(1, request.headers().count { it.name().equals("X-Role", true) })
        assertEquals("manual=yes", request.headerValueOrNull("Cookie"))
    }

    @Test
    fun `send hands Montoya UTF-8 bytes and persists the transmitted body`() {
        val fixture = httpFixture(emptyList())
        val history = mockk<HistoryDao>()
        var persistedBody: String? = null
        every {
            history.insert(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
            )
        } answers {
            persistedBody = arg(4)
            1L
        }
        val service = fixture.service(historyDao = history)
        val body = """{"f":"café αβγ 😀"}"""

        service.send(
            AuthenticatedRequest(
                url = "https://example.test/unicode",
                method = "POST",
                body = body,
            )
        )

        val transmitted = fixture.sent.single().body().getBytes()
        assertContentEquals(
            body.encodeToByteArray(),
            transmitted,
            "SessionService must hand Montoya the exact UTF-8 request bytes",
        )
        assertEquals(
            transmitted.decodeToString(),
            persistedBody,
            "history must record the body reconstructed from the request actually sent",
        )
    }

    @Test
    fun `response body uses its UTF-8 bytes instead of Montoya text projection`() {
        val expectedBody = """{"f":"café αβγ 😀"}"""
        val fixture = httpFixture()
        every { fixture.http.sendRequest(any<HttpRequest>()) } returns exchange(emptyList(), expectedBody)
        val service = fixture.service()

        val response = service.send(AuthenticatedRequest(url = "https://example.test/unicode"))

        assertEquals(
            expectedBody,
            response.body,
            "response text must be decoded from the exact response bytes as UTF-8",
        )
    }

    @Test
    fun `non-UTF-8 response bytes have only a lossy text representation`() {
        val rawBody = byteArrayOf(0x41, 0x80.toByte(), 0xff.toByte(), 0x42)
        val fixture = httpFixture()
        every { fixture.http.sendRequest(any<HttpRequest>()) } returns exchangeBytes(emptyList(), rawBody)
        val service = fixture.service()

        val response = service.send(AuthenticatedRequest(url = "https://example.test/binary"))

        assertEquals("A��B", response.body)
        assertFalse(
            rawBody.contentEquals(response.body!!.encodeToByteArray()),
            "the text-only response model cannot round-trip arbitrary response bytes",
        )
    }

    @Test
    fun `cookie jar representation retains HttpOnly from Set-Cookie`() {
        val fixture = httpFixture(
            listOf("Set-Cookie" to "sid=opaque; Path=/; HttpOnly")
        )
        val service = fixture.service()
        service.send(AuthenticatedRequest(url = "https://example.test/login"))

        val represented = Json.encodeToString(service.getCookieJar())

        assertTrue("\"httpOnly\":true" in represented, represented)
    }

    @Test
    fun `cookie jar parses metadata enforces domain and prefix rules and matches requests`() {
        val now = AtomicLong(1_700_000_000_000L)
        val fixture = httpFixture(
            listOf(
                "Set-Cookie" to "wide=w; Domain=.example.test; Path=/app; Secure; Max-Age=60",
                "Set-Cookie" to "host=h; Path=/app/login",
                "Set-Cookie" to "defaultPath=d",
                "Set-Cookie" to "foreign=x; Domain=evil.test; Path=/",
                "Set-Cookie" to "__Secure-bad=x; Path=/",
                "Set-Cookie" to "__Host-good=g; Secure; Path=/",
                "Set-Cookie" to "__Host-bad=b; Secure; Domain=example.test; Path=/",
            ),
            emptyList(),
            emptyList(),
        )
        val service = fixture.service(collaborators = fixture.collaborators(clock = now::get))

        service.send(AuthenticatedRequest(url = "https://api.example.test/app/login/start"))
        val jar = service.getCookieJar()

        assertEquals(setOf("wide", "host", "defaultPath", "__Host-good"), jar.cookies.map { it.name }.toSet())
        val wide = jar.cookies.single { it.name == "wide" }
        assertEquals("example.test", wide.domain)
        assertEquals("/app", wide.path)
        assertTrue(wide.secure)
        assertFalse(wide.hostOnly)
        assertEquals(now.get() + 60_000, wide.expiresAt)
        val host = jar.cookies.single { it.name == "host" }
        assertEquals("api.example.test", host.domain)
        assertTrue(host.hostOnly)
        assertEquals("/app/login", host.path)
        assertEquals("/app/login", jar.cookies.single { it.name == "defaultPath" }.path)

        service.send(AuthenticatedRequest(url = "https://api.example.test/app/login/next"))
        val matching = assertNotNull(fixture.sent[1].headerValueOrNull("Cookie"))
        assertTrue("wide=w" in matching)
        assertTrue("host=h" in matching)
        assertTrue("defaultPath=d" in matching)
        assertTrue("__Host-good=g" in matching)

        service.send(AuthenticatedRequest(url = "https://api.example.test/other"))
        val other = assertNotNull(fixture.sent[2].headerValueOrNull("Cookie"))
        assertFalse("wide=w" in other)
        assertFalse("host=h" in other)
        assertFalse("defaultPath=d" in other)
        assertTrue("__Host-good=g" in other)
    }

    @Test
    fun `cookie jar honors secure host-only expiry deletion and path boundary`() {
        val now = AtomicLong(1_700_000_000_000L)
        val fixture = httpFixture(
            listOf(
                "Set-Cookie" to "path=p; Path=/app; Max-Age=1",
                "Set-Cookie" to "secure=s; Secure; Path=/",
                "Set-Cookie" to "host=h; Path=/",
            ),
            emptyList(),
            emptyList(),
            listOf("Set-Cookie" to "host=gone; Path=/; Max-Age=0"),
        )
        val service = fixture.service(collaborators = fixture.collaborators(clock = now::get))
        service.send(AuthenticatedRequest(url = "https://example.test/app/start"))

        service.send(AuthenticatedRequest(url = "http://example.test/application"))
        val insecureWrongPath = assertNotNull(fixture.sent[1].headerValueOrNull("Cookie"))
        assertFalse("path=p" in insecureWrongPath)
        assertFalse("secure=s" in insecureWrongPath)
        assertTrue("host=h" in insecureWrongPath)

        now.addAndGet(1_001)
        service.send(AuthenticatedRequest(url = "https://sub.example.test/app/next"))
        assertNull(fixture.sent[2].headerValueOrNull("Cookie"), "host-only cookies must not reach subdomains")
        assertEquals(setOf("secure", "host"), service.getCookieJar().cookies.map { it.name }.toSet())

        service.send(AuthenticatedRequest(url = "https://example.test/"))
        assertFalse(service.getCookieJar().cookies.any { it.name == "host" })
    }

    @Test
    fun `Max-Age takes precedence over Expires`() {
        val now = AtomicLong(1_700_000_000_000L)
        val fixture = httpFixture(
            listOf(
                "Set-Cookie" to "alive=yes; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=10",
                "Set-Cookie" to "dead=no; Path=/; Expires=Wed, 31 Dec 2099 23:59:59 GMT; Max-Age=0",
            ),
        )
        val service = fixture.service(collaborators = fixture.collaborators(clock = now::get))

        service.send(AuthenticatedRequest(url = "https://example.test/"))

        assertEquals(listOf("alive"), service.getCookieJar().cookies.map { it.name })
        assertEquals(now.get() + 10_000, service.getCookieJar().cookies.single().expiresAt)
    }

    @Test
    fun `batch preflights every request before the first target effect`() {
        val fixture = httpFixture(emptyList())
        val service = fixture.service()

        assertFailsWith<IllegalArgumentException> {
            service.sendBatch(
                BatchAuthenticatedRequest(
                    listOf(
                        AuthenticatedRequest(url = "https://example.test/valid"),
                        AuthenticatedRequest(url = "https://example.test/invalid", extraHeaders = mapOf("Bad Header" to "x")),
                    )
                )
            )
        }
        assertFailsWith<IllegalArgumentException> {
            service.sendBatch(BatchAuthenticatedRequest(emptyList()))
        }

        service.setSession(SetSessionRequest(mapOf("sid" to "bound"), origin = "https://example.test"))
        assertFailsWith<IllegalArgumentException> {
            service.sendBatch(
                BatchAuthenticatedRequest(
                    listOf(
                        AuthenticatedRequest(url = "https://example.test/valid"),
                        AuthenticatedRequest(url = "https://other.test/rejected"),
                    )
                )
            )
        }

        service.setSession(SetSessionRequest(mapOf("sid" to "legacy-unbound")))
        assertFailsWith<IllegalArgumentException> {
            service.sendBatch(
                BatchAuthenticatedRequest(
                    listOf(
                        AuthenticatedRequest(url = "https://one.test/valid"),
                        AuthenticatedRequest(url = "https://two.test/rejected"),
                    )
                )
            )
        }
        assertNull(service.getSession().origin, "a rejected legacy batch must not bind credentials")
        assertTrue(fixture.sent.isEmpty())
    }

    @Test
    fun `response-less exchange throws typed error without persistence or cookie effects`() {
        val fixture = httpFixture(emptyList())
        val noResponse = mockk<HttpRequestResponse>()
        every { noResponse.hasResponse() } returns false
        every { fixture.http.sendRequest(any<HttpRequest>()) } returns noResponse
        val history = mockk<HistoryDao>(relaxed = true)
        val sitemap = mockk<SitemapDao>(relaxed = true)
        val service = fixture.service(history, sitemap)

        assertFailsWith<NoResponseException> {
            service.send(AuthenticatedRequest(url = "https://example.test/no-response"))
        }

        verify(exactly = 0) { noResponse.response() }
        verify(exactly = 0) { history.insertWithSitemap(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        assertEquals(0, service.getCookieJar().total)
    }

    @Test
    fun `bounded response-less exchange carries the configured budget without claiming a cause`() {
        val fixture = httpFixture(emptyList())
        val noResponse = mockk<HttpRequestResponse>()
        every { noResponse.hasResponse() } returns false
        val service = fixture.service(
            collaborators = fixture.collaborators(
                boundedRequestSender = BoundedRequestSender { _, _ -> noResponse },
            ),
        )

        val failure = assertFailsWith<BoundedSendNoResponseException> {
            service.sendPreservingHeaders(
                request = AuthenticatedRequest(url = "https://example.test/no-response"),
                headers = emptyList(),
                credentialMode = CredentialMode.NONE,
                persistObservation = false,
                responseTimeoutMs = 5_000,
            )
        }

        assertEquals(5_000, failure.timeoutMs)
        assertFalse(failure.message.orEmpty().contains("timed out", ignoreCase = true))
        verify(exactly = 0) { noResponse.response() }
    }

    @Test
    fun `bounded exchange with an absent response object carries its configured budget`() {
        val fixture = httpFixture(emptyList())
        val absentResponse = mockk<HttpRequestResponse>()
        every { absentResponse.hasResponse() } returns true
        every { absentResponse.response() } returns null
        val service = fixture.service(
            collaborators = fixture.collaborators(
                boundedRequestSender = BoundedRequestSender { _, _ -> absentResponse },
            ),
        )

        val failure = assertFailsWith<BoundedSendNoResponseException> {
            service.sendPreservingHeaders(
                request = AuthenticatedRequest(url = "https://example.test/absent-response"),
                headers = emptyList(),
                credentialMode = CredentialMode.NONE,
                persistObservation = false,
                responseTimeoutMs = 5_000,
            )
        }

        assertEquals(5_000, failure.timeoutMs)
        assertFalse(failure.message.orEmpty().contains("timed out", ignoreCase = true))
    }

    @Test
    fun `post-send atomic persistence failure returns response with sanitized do-not-retry warning`() {
        val fixture = httpFixture(emptyList())
        val history = mockk<HistoryDao>()
        val sitemap = mockk<SitemapDao>()
        every {
            history.insertWithSitemap(
                sitemap,
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
            )
        } throws IllegalStateException("database secret /private/path")
        val service = fixture.service(history, sitemap)

        val result = service.send(AuthenticatedRequest(url = "https://example.test/mutation", method = "POST"))

        assertEquals(200, result.statusCode)
        assertTrue(result.hasResponse)
        assertEquals(PersistenceStatus.FAILED, result.persistence.status)
        assertFalse(result.persistence.historyPersisted)
        assertFalse(result.persistence.sitemapPersisted)
        assertTrue(result.persistence.warning.orEmpty().contains("send completed", ignoreCase = true))
        assertTrue(result.persistence.warning.orEmpty().contains("do not retry", ignoreCase = true))
        assertFalse(result.persistence.warning.orEmpty().contains("database secret"))
        assertFalse(result.persistence.warning.orEmpty().contains("private/path"))
    }

    @Test
    fun `bounded scan helper builds and passes native Montoya response timeout options`() {
        val fixture = httpFixture(emptyList())
        val baseOptions = mockk<RequestOptions>()
        val configuredOptions = mockk<RequestOptions>()
        mockkStatic(RequestOptions::class)
        try {
            every { RequestOptions.requestOptions() } returns baseOptions
            every { baseOptions.withResponseTimeout(5_000) } returns configuredOptions
            val service = fixture.service()

            service.sendPreservingHeaders(
                request = AuthenticatedRequest(url = "https://example.test/probe"),
                headers = emptyList(),
                credentialMode = CredentialMode.NONE,
                persistObservation = false,
                responseTimeoutMs = 5_000,
            )

            verify(exactly = 1) { baseOptions.withResponseTimeout(5_000) }
            verify(exactly = 1) {
                fixture.http.sendRequest(any<HttpRequest>(), configuredOptions)
            }
            verify(exactly = 0) { fixture.http.sendRequest(any<HttpRequest>()) }
        } finally {
            unmockkStatic(RequestOptions::class)
        }
    }

    @Test
    fun `unbounded session sends keep the original Montoya overload`() {
        val fixture = httpFixture(emptyList())
        val service = fixture.service()

        service.send(AuthenticatedRequest(url = "https://example.test/path"))

        verify(exactly = 1) { fixture.http.sendRequest(any<HttpRequest>()) }
        verify(exactly = 0) { fixture.http.sendRequest(any<HttpRequest>(), any<RequestOptions>()) }
    }

    @Test
    fun `observed send returns exact post-override request material`() {
        val fixture = httpFixture(emptyList())
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "configured"),
                headers = mapOf("X-Role" to "session"),
                origin = "https://example.test",
            )
        )

        val observed = service.sendPreservingHeadersObserved(
            request = AuthenticatedRequest(
                url = "https://example.test/path",
                extraHeaders = linkedMapOf(
                    "x-role" to "treatment",
                    "Cookie" to "manual=one; second=two",
                ),
            ),
            headers = listOf(HttpHeader("X-Trace", "source")),
            credentialMode = CredentialMode.FULL,
            persistObservation = false,
        )

        assertEquals(200, observed.response.statusCode)
        assertEquals(
            SessionRequestMaterialSnapshot.Available(
                headers = listOf(
                    HttpHeader("X-Trace", "source"),
                    HttpHeader("x-role", "treatment"),
                ),
                cookies = listOf(
                    SessionRequestCookie("manual", "one"),
                    SessionRequestCookie("second", "two"),
                ),
                cookieHeaderValue = "manual=one; second=two",
            ),
            observed.requestMaterial,
            "observed material must come from the finalized request, not a separate session prediction",
        )
    }

    @Test
    fun `ordered scan helper preserves duplicate noncredential headers and regenerates credentials`() {
        val fixture = httpFixture(emptyList(), emptyList(), emptyList())
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "secret"),
                headers = mapOf("Authorization" to "Bearer session"),
                origin = "https://example.test",
            )
        )
        val captured = listOf(
            HttpHeader("X-Duplicate", "one"),
            HttpHeader("X-Duplicate", "two"),
            HttpHeader("aUtHoRiZaTiOn", "Bearer stale"),
            HttpHeader("Cookie", "stale=yes"),
        )

        service.sendPreservingHeaders(
            AuthenticatedRequest(url = "https://example.test/path"),
            captured,
            CredentialMode.FULL,
        )
        service.sendPreservingHeaders(
            AuthenticatedRequest(url = "https://example.test/path"),
            captured,
            CredentialMode.COOKIES_ONLY,
        )
        service.sendPreservingHeaders(
            AuthenticatedRequest(url = "https://other.test/path"),
            captured,
            CredentialMode.NONE,
        )

        assertEquals(listOf("one", "two"), fixture.sent[0].headers().filter { it.name().equals("X-Duplicate", true) }.map { it.value() })
        assertEquals("Bearer session", fixture.sent[0].headerValueOrNull("Authorization"))
        assertEquals("sid=secret", fixture.sent[0].headerValueOrNull("Cookie"))
        assertNull(fixture.sent[1].headerValueOrNull("Authorization"))
        assertEquals("sid=secret", fixture.sent[1].headerValueOrNull("Cookie"))
        assertNull(fixture.sent[2].headerValueOrNull("Authorization"))
        assertNull(fixture.sent[2].headerValueOrNull("Cookie"))
    }

    @Test
    fun `ordered scan helper can suppress all observation persistence`() {
        val fixture = httpFixture(listOf("Set-Cookie" to "ignored=yes; Path=/"))
        val history = mockk<HistoryDao>(relaxed = true)
        val sitemap = mockk<SitemapDao>(relaxed = true)
        val service = fixture.service(history, sitemap)
        service.setSession(
            SetSessionRequest(
                cookies = mapOf("sid" to "secret"),
                headers = mapOf("Authorization" to "Bearer session"),
                origin = "https://example.test",
            )
        )

        val response = service.sendPreservingHeaders(
            request = AuthenticatedRequest(url = "https://example.test/probe"),
            headers = listOf(HttpHeader("X-Duplicate", "one"), HttpHeader("X-Duplicate", "two")),
            credentialMode = CredentialMode.FULL,
            persistObservation = false,
        )

        assertEquals(200, response.statusCode)
        assertEquals("Bearer session", fixture.sent.single().headerValueOrNull("Authorization"))
        assertEquals(
            listOf("one", "two"),
            fixture.sent.single().headers().filter { it.name().equals("X-Duplicate", true) }.map { it.value() },
        )
        assertEquals(0, service.getCookieJar().total)
        verify(exactly = 0) {
            history.insertWithSitemap(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
        verify(exactly = 0) { history.insert(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        verify(exactly = 0) { sitemap.upsert(any(), any(), any()) }
    }

    @Test
    fun `sendUnauthenticated applies no session or jar credentials and captures no cookies`() {
        val fixture = httpFixture(
            listOf("Set-Cookie" to "jar=one; Path=/"),
            listOf("Set-Cookie" to "ignored=two; Path=/"),
        )
        val service = fixture.service()
        service.setSession(
            SetSessionRequest(
                mapOf("session" to "secret"),
                mapOf("Authorization" to "Bearer secret", "X-Api-Key" to "session-key"),
                origin = "https://example.test",
            )
        )
        service.send(AuthenticatedRequest(url = "https://example.test/seed"))

        service.sendUnauthenticated(
            AuthenticatedRequest(
                url = "https://example.test/bundle.js",
                extraHeaders = mapOf(
                    "Cookie" to "explicit=credential",
                    "Authorization" to "Bearer explicit",
                    "pRoXy-AuThOrIzAtIoN" to "Basic explicit",
                    "x-api-key" to "explicit-key",
                    "Accept" to "application/javascript",
                ),
            )
        )

        val request = fixture.sent[1]
        assertNull(request.headerValueOrNull("Cookie"))
        assertNull(request.headerValueOrNull("Authorization"))
        assertNull(request.headerValueOrNull("Proxy-Authorization"))
        assertNull(request.headerValueOrNull("X-Api-Key"))
        assertEquals("application/javascript", request.headerValueOrNull("Accept"))
        assertEquals(listOf("jar"), service.getCookieJar().cookies.map { it.name })
    }
}
