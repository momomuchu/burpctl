package com.burprest.db

import com.burprest.models.HttpHeader
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.util.Comparator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DatabaseHardeningTest {
    private val managers = mutableListOf<DatabaseManager>()
    private val roots = mutableListOf<Path>()

    @AfterTest
    fun cleanUp() {
        managers.asReversed().forEach { runCatching { it.close() } }
        roots.asReversed().forEach { root ->
            runCatching {
                Files.walk(root).use { paths ->
                    paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
                }
            }
        }
    }

    @Test
    fun `database directory and files have owner-only POSIX permissions`() {
        val root = temporaryRoot()
        val parent = root.resolve("private")
        val db = managerAt(parent.resolve("store"))

        if (!Files.getFileStore(parent).supportsFileAttributeView("posix")) return

        assertEquals(
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            ),
            Files.getPosixFilePermissions(parent),
        )

        db.withConnection { connection ->
            connection.createStatement().use { it.executeQuery("SELECT 1").use { rs -> assertTrue(rs.next()) } }
        }

        val databaseFiles = Files.list(parent).use { paths ->
            paths.filter { it.fileName.toString().startsWith("store") }.toList()
        }
        assertTrue(databaseFiles.any { it.fileName.toString() == "store.mv.db" })
        databaseFiles.forEach { file ->
            assertEquals(
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(file),
                "unexpected permissions on ${file.fileName}",
            )
        }

        val sidecar = parent.resolve("store.trace.db")
        Files.writeString(sidecar, "trace")
        Files.setPosixFilePermissions(
            sidecar,
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ,
                PosixFilePermission.OTHERS_READ,
            ),
        )
        db.withConnection { connection ->
            connection.createStatement().use { it.executeQuery("SELECT 1").use { rs -> assertTrue(rs.next()) } }
        }
        assertEquals(
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
            Files.getPosixFilePermissions(sidecar),
        )
    }

    @Test
    fun `symlink database file is rejected without touching its target`() {
        val root = temporaryRoot()
        val parent = Files.createDirectories(root.resolve("private"))
        val victim = root.resolve("victim.txt")
        Files.writeString(victim, "do-not-touch")
        try {
            Files.createSymbolicLink(parent.resolve("store.mv.db"), victim)
        } catch (_: UnsupportedOperationException) {
            return
        }

        val failure = assertFailsWith<StorageException> { DatabaseManager(parent.resolve("store").toString()) }

        assertEquals("Unsafe database path", failure.message)
        assertEquals("do-not-touch", Files.readString(victim))
    }

    @Test
    fun `symlink parent is rejected without creating database files`() {
        val root = temporaryRoot()
        val realParent = Files.createDirectories(root.resolve("real"))
        val linkedParent = root.resolve("linked")
        try {
            Files.createSymbolicLink(linkedParent, realParent)
        } catch (_: UnsupportedOperationException) {
            return
        }

        assertFailsWith<StorageException> { DatabaseManager(linkedParent.resolve("store").toString()) }
        assertEquals(emptyList(), Files.list(realParent).use { it.toList() })
    }

    @Test
    fun `scoped transaction rolls back and nested DAO calls enlist in it`() {
        val db = newManager()
        val sessions = SessionDao(db)

        assertFailsWith<IllegalStateException> {
            db.transaction {
                sessions.save("should-rollback", mapOf("sid" to "secret"), emptyMap())
                throw IllegalStateException("injected")
            }
        }

        assertNull(sessions.load())
    }

    @Test
    fun `session save rolls back all legacy keys when a later write fails`() {
        val db = newManager()
        val sessions = SessionDao(db)
        sessions.save("before", emptyMap(), emptyMap())
        db.withConnection { connection ->
            connection.createStatement().use {
                it.execute(
                    """ALTER TABLE session_store ADD CONSTRAINT session_value_cap CHECK (CHAR_LENGTH("value") <= 24)"""
                )
            }
        }

        assertFailsWith<Exception> {
            sessions.save("after", mapOf("large" to "x".repeat(100)), mapOf("new" to "header"))
        }

        assertEquals(PersistedSession("before", emptyMap(), emptyMap()), sessions.load())
    }

    @Test
    fun `history and sitemap insert rolls back together on injected sitemap failure`() {
        val db = newManager()
        val history = HistoryDao(db)
        val sitemap = SitemapDao(db)
        db.withConnection { connection ->
            connection.createStatement().use { it.execute("DROP TABLE sitemap") }
        }

        assertFailsWith<Exception> {
            history.insertWithSitemap(
                sitemapDao = sitemap,
                source = "test",
                method = "GET",
                url = "https://example.test/path",
                reqHeaders = emptyList(),
                reqBody = null,
                statusCode = 200,
                resHeaders = emptyList(),
                resBody = null,
                durationMs = 1,
            )
        }

        assertEquals(0, history.count(HistoryFilter()))
    }

    @Test
    fun `history and sitemap clear rolls back together on injected sitemap failure`() {
        val db = newManager()
        val history = HistoryDao(db)
        val sitemap = SitemapDao(db)
        history.insert(
            source = "test",
            method = "GET",
            url = "https://example.test/path",
            reqHeaders = emptyList(),
            reqBody = null,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = null,
            durationMs = 1,
        )
        db.withConnection { connection ->
            connection.createStatement().use { it.execute("DROP TABLE sitemap") }
        }

        assertFailsWith<Exception> { history.clearWithSitemap(sitemap) }

        assertEquals(1, history.count(HistoryFilter()))
    }

    @Test
    fun `concurrent cross-DAO transactions neither corrupt connections nor lose sitemap hits`() {
        val db = newManager()
        val history = HistoryDao(db)
        val sitemap = SitemapDao(db)
        val workers = 8
        val writesPerWorker = 12
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(workers)

        try {
            val futures = (0 until workers).map { worker ->
                executor.submit {
                    ready.countDown()
                    assertTrue(start.await(10, TimeUnit.SECONDS))
                    repeat(writesPerWorker) { index ->
                        history.insertWithSitemap(
                            sitemapDao = sitemap,
                            source = "worker-$worker",
                            method = "GET",
                            url = "https://EXAMPLE.test/shared",
                            reqHeaders = listOf(HttpHeader("X-Index", index.toString())),
                            reqBody = null,
                            statusCode = 200,
                            resHeaders = emptyList(),
                            resBody = null,
                            durationMs = 1,
                        )
                    }
                }
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS))
            start.countDown()
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            executor.shutdownNow()
        }

        assertEquals((workers * writesPerWorker).toLong(), history.count(HistoryFilter()))
        val rows = sitemap.list("example.TEST.")
        assertEquals(1, rows.size)
        assertEquals(workers * writesPerWorker, rows.single().hitCount)
        assertEquals("example.test", rows.single().host)
    }

    @Test
    fun `request and response bodies are capped by UTF-8 bytes without splitting a code point`() {
        val db = newManager()
        val history = HistoryDao(db)
        val cap = 1_048_576
        val body = "a".repeat(cap - 2) + "🙂" + "unreachable"

        val id = history.insert(
            source = "test",
            method = "POST",
            url = "https://example.test/utf8",
            reqHeaders = emptyList(),
            reqBody = body,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = body,
            durationMs = 1,
        )
        val stored = history.getById(id)!!

        val storedRequestBody = stored.reqBody!!
        assertEquals("a".repeat(cap - 2), storedRequestBody)
        assertEquals("a".repeat(cap - 2), stored.resBody)
        assertTrue(storedRequestBody.toByteArray(StandardCharsets.UTF_8).size <= cap)
        assertFalse(storedRequestBody.contains('�'))
    }

    @Test
    fun `offset timestamps are normalized to UTC for storage and filtering`() {
        val db = newManager()
        val history = HistoryDao(db)
        history.insert(
            source = "test",
            method = "GET",
            url = "https://example.test/early",
            reqHeaders = emptyList(),
            reqBody = null,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = null,
            durationMs = 1,
            timestamp = "2024-01-01T02:00:00+02:00",
        )
        history.insert(
            source = "test",
            method = "GET",
            url = "https://example.test/late",
            reqHeaders = emptyList(),
            reqBody = null,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = null,
            durationMs = 1,
            timestamp = "2024-01-01T00:00:01Z",
        )

        val exact = history.search(
            HistoryFilter(
                since = "2023-12-31T19:00:00-05:00",
                until = "2024-01-01T01:00:00+01:00",
            )
        )

        assertEquals(1, exact.size)
        assertEquals("https://example.test/early", exact.single().url)
        assertEquals("2024-01-01T00:00:00Z", exact.single().timestamp)
    }

    @Test
    fun `host filters use normalized exact matching`() {
        val db = newManager()
        val history = HistoryDao(db)
        val sitemap = SitemapDao(db)
        listOf("https://Example.TEST./wanted", "https://notexample.test/unwanted").forEach { url ->
            history.insertWithSitemap(
                sitemapDao = sitemap,
                source = "test",
                method = "GET",
                url = url,
                reqHeaders = emptyList(),
                reqBody = null,
                statusCode = 200,
                resHeaders = emptyList(),
                resBody = null,
                durationMs = 1,
            )
        }

        val entries = history.search(HistoryFilter(host = "EXAMPLE.test."))

        assertEquals(listOf("https://Example.TEST./wanted"), entries.map { it.url })
        assertEquals(listOf("example.test"), sitemap.list("EXAMPLE.TEST.").map { it.host })
    }

    @Test
    fun `search treats LIKE metacharacters as literals`() {
        val db = newManager()
        val history = HistoryDao(db)
        fun insert(body: String) = history.insert(
            source = "test",
            method = "POST",
            url = "https://example.test/search",
            reqHeaders = emptyList(),
            reqBody = body,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = null,
            durationMs = 1,
        )
        val literalId = insert("literal %_\\ marker")
        insert("ordinary wildcard bait")

        assertEquals(listOf(literalId), history.search(HistoryFilter(search = "%_\\")).map { it.id })
    }

    @Test
    fun `pagination validation rejects invalid limits and uses a non-overflowing offset`() {
        val history = HistoryDao(newManager())

        assertFailsWith<IllegalArgumentException> { history.search(HistoryFilter(page = -1)) }
        assertFailsWith<IllegalArgumentException> { history.search(HistoryFilter(pageSize = 0)) }
        assertFailsWith<IllegalArgumentException> { history.search(HistoryFilter(pageSize = 1001)) }
        assertEquals(emptyList(), history.search(HistoryFilter(page = Int.MAX_VALUE, pageSize = 1000)))
    }

    @Test
    fun `malformed timestamp filters are rejected before SQL`() {
        val history = HistoryDao(newManager())

        val failure = assertFailsWith<IllegalArgumentException> {
            history.search(HistoryFilter(since = "not-an-instant"))
        }

        assertEquals("since must be a valid ISO-8601 instant", failure.message)
    }

    @Test
    fun `corrupt history JSON surfaces a sanitized storage failure`() {
        val db = newManager()
        val history = HistoryDao(db)
        val id = history.insert(
            source = "test",
            method = "GET",
            url = "https://example.test/corrupt",
            reqHeaders = emptyList(),
            reqBody = null,
            statusCode = 200,
            resHeaders = emptyList(),
            resBody = null,
            durationMs = 1,
        )
        db.withConnection { connection ->
            connection.prepareStatement("UPDATE request_history SET req_headers = ? WHERE id = ?").use { stmt ->
                stmt.setString(1, "private-corrupt-header-json")
                stmt.setLong(2, id)
                stmt.executeUpdate()
            }
        }

        val failure = assertFailsWith<StorageException> { history.getById(id) }

        assertEquals("Stored history data is invalid", failure.message)
        assertFalse(failure.message.orEmpty().contains("private-corrupt"))
    }

    @Test
    fun `corrupt or incomplete session state surfaces a sanitized storage failure`() {
        val db = newManager()
        val sessions = SessionDao(db)
        sessions.save("session", emptyMap(), emptyMap())
        db.withConnection { connection ->
            connection.prepareStatement("""UPDATE session_store SET "value" = ? WHERE "key" = 'cookies'""").use { stmt ->
                stmt.setString(1, "private-corrupt-cookie-json")
                stmt.executeUpdate()
            }
        }

        val malformed = assertFailsWith<StorageException> { sessions.load() }
        assertEquals("Stored session data is invalid", malformed.message)
        assertFalse(malformed.message.orEmpty().contains("private-corrupt"))

        sessions.clear()
        db.withConnection { connection ->
            connection.prepareStatement("""INSERT INTO session_store ("key", "value") VALUES ('name', 'partial')""").use {
                it.executeUpdate()
            }
        }
        assertEquals("Stored session data is invalid", assertFailsWith<StorageException> { sessions.load() }.message)
    }

    @Test
    fun `optional bound origin persists without changing legacy session keys`() {
        val db = newManager()
        val sessions = SessionDao(db)

        sessions.save("named", mapOf("sid" to "value"), mapOf("X-Test" to "yes"), "https://example.test")

        assertEquals(
            PersistedSession(
                name = "named",
                cookies = mapOf("sid" to "value"),
                headers = mapOf("X-Test" to "yes"),
                boundOrigin = "https://example.test",
            ),
            sessions.load(),
        )
        val keys = db.withConnection { connection ->
            connection.createStatement().use { stmt ->
                stmt.executeQuery("""SELECT "key" FROM session_store ORDER BY "key"""").use { rs ->
                    buildList { while (rs.next()) add(rs.getString(1)) }
                }
            }
        }
        assertTrue(keys.containsAll(listOf("name", "cookies", "headers")))
    }

    private fun temporaryRoot(): Path = Files.createTempDirectory(
        Path.of(System.getProperty("user.home")),
        "burpctl-db-test-",
    ).also { roots.add(it) }

    private fun managerAt(path: Path): DatabaseManager = DatabaseManager(path.toString()).also { managers.add(it) }

    private fun newManager(): DatabaseManager {
        val root = temporaryRoot()
        return managerAt(root.resolve("database").resolve("store"))
    }
}
