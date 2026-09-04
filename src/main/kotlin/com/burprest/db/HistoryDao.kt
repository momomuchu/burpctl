package com.burprest.db

import com.burprest.models.HttpHeader
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.IDN
import java.net.URI
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Statement
import java.sql.Types
import java.time.DateTimeException
import java.time.Instant

private const val MAX_BODY_BYTES = 1_048_576
private const val MAX_PAGE_SIZE = 1_000

data class HistoryEntry(
    val id: Long = 0,
    val source: String,
    val method: String,
    val url: String,
    val host: String,
    val reqHeaders: List<HttpHeader>,
    val reqBody: String?,
    val statusCode: Int?,
    val resHeaders: List<HttpHeader>?,
    val resBody: String?,
    val durationMs: Long,
    val timestamp: String,
)

data class HistoryFilter(
    val host: String? = null,
    val method: String? = null,
    val statusCode: Int? = null,
    val source: String? = null,
    val search: String? = null,
    val since: String? = null,
    val until: String? = null,
    val page: Int = 0,
    val pageSize: Int = 50,
)

class HistoryDao(private val db: DatabaseManager) {
    private val json = Json { ignoreUnknownKeys = true }

    fun insert(
        source: String,
        method: String,
        url: String,
        reqHeaders: List<HttpHeader>,
        reqBody: String?,
        statusCode: Int?,
        resHeaders: List<HttpHeader>?,
        resBody: String?,
        durationMs: Long,
        timestamp: String = Instant.now().toString(),
    ): Long = db.withConnection { connection ->
        insert(
            connection = connection,
            source = source,
            method = method,
            url = url,
            reqHeaders = reqHeaders,
            reqBody = reqBody,
            statusCode = statusCode,
            resHeaders = resHeaders,
            resBody = resBody,
            durationMs = durationMs,
            timestamp = timestamp,
        )
    }

    /** Atomically records both views of one request for callers that own both DAOs. */
    fun insertWithSitemap(
        sitemapDao: SitemapDao,
        source: String,
        method: String,
        url: String,
        reqHeaders: List<HttpHeader>,
        reqBody: String?,
        statusCode: Int?,
        resHeaders: List<HttpHeader>?,
        resBody: String?,
        durationMs: Long,
        timestamp: String = Instant.now().toString(),
    ): Long {
        require(sitemapDao.uses(db)) { "DAOs must share a DatabaseManager" }
        return db.transaction { connection ->
            val normalizedTimestamp = normalizeTimestamp(timestamp, "timestamp")
            val id = insert(
                connection = connection,
                source = source,
                method = method,
                url = url,
                reqHeaders = reqHeaders,
                reqBody = reqBody,
                statusCode = statusCode,
                resHeaders = resHeaders,
                resBody = resBody,
                durationMs = durationMs,
                timestamp = normalizedTimestamp,
            )
            sitemapDao.upsert(connection, url, method, normalizedTimestamp)
            id
        }
    }

    fun search(filter: HistoryFilter): List<HistoryEntry> {
        val query = buildWhere(filter)
        val offset = validatedOffset(filter)
        val sql = "SELECT * FROM request_history ${query.where} ORDER BY id DESC LIMIT ? OFFSET ?"
        return db.withConnection { connection ->
            connection.prepareStatement(sql).use { statement ->
                var index = bind(statement, query.parameters)
                statement.setInt(index++, filter.pageSize)
                statement.setLong(index, offset)
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) add(rowToEntry(resultSet))
                    }
                }
            }
        }
    }

    fun getById(id: Long): HistoryEntry? = db.withConnection { connection ->
        connection.prepareStatement("SELECT * FROM request_history WHERE id = ?").use { statement ->
            statement.setLong(1, id)
            statement.executeQuery().use { resultSet ->
                if (resultSet.next()) rowToEntry(resultSet) else null
            }
        }
    }

    fun count(filter: HistoryFilter): Long {
        // Count does not use pagination, but validates it so all public filter consumers behave alike.
        validatedOffset(filter)
        val query = buildWhere(filter)
        return db.withConnection { connection ->
            connection.prepareStatement("SELECT COUNT(*) FROM request_history ${query.where}").use { statement ->
                bind(statement, query.parameters)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.getLong(1) else 0L
                }
            }
        }
    }

    fun clear() = db.transaction { connection -> clear(connection) }

    /** Atomically clears both views for callers that own both DAOs. */
    fun clearWithSitemap(sitemapDao: SitemapDao) {
        require(sitemapDao.uses(db)) { "DAOs must share a DatabaseManager" }
        db.transaction { connection ->
            clear(connection)
            sitemapDao.clear(connection)
        }
    }

    internal fun insert(
        connection: Connection,
        source: String,
        method: String,
        url: String,
        reqHeaders: List<HttpHeader>,
        reqBody: String?,
        statusCode: Int?,
        resHeaders: List<HttpHeader>?,
        resBody: String?,
        durationMs: Long,
        timestamp: String,
    ): Long {
        val host = hostFromUrl(url) ?: "unknown"
        val normalizedTimestamp = normalizeTimestamp(timestamp, "timestamp")
        return connection.prepareStatement(
            """INSERT INTO request_history
               (source, method, url, host, req_headers, req_body, status_code, res_headers, res_body, duration_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            Statement.RETURN_GENERATED_KEYS,
        ).use { statement ->
            statement.setString(1, source)
            statement.setString(2, method)
            statement.setString(3, url)
            statement.setString(4, host)
            statement.setString(5, json.encodeToString(reqHeaders))
            statement.setString(6, reqBody?.truncateUtf8(MAX_BODY_BYTES))
            if (statusCode != null) statement.setInt(7, statusCode) else statement.setNull(7, Types.INTEGER)
            statement.setString(8, resHeaders?.let(json::encodeToString))
            statement.setString(9, resBody?.truncateUtf8(MAX_BODY_BYTES))
            statement.setLong(10, durationMs)
            statement.setString(11, normalizedTimestamp)
            statement.executeUpdate()
            statement.generatedKeys.use { keys ->
                if (!keys.next()) throw StorageException("Storage operation failed")
                keys.getLong(1)
            }
        }
    }

    internal fun clear(connection: Connection) {
        connection.createStatement().use { statement -> statement.executeUpdate("DELETE FROM request_history") }
    }

    private fun buildWhere(filter: HistoryFilter): QueryParts {
        val clauses = mutableListOf<String>()
        val parameters = mutableListOf<Any>()

        filter.host?.let {
            clauses.add("host = ?")
            parameters.add(normalizeHostFilter(it))
        }
        filter.method?.let {
            clauses.add("method = ?")
            parameters.add(it)
        }
        filter.statusCode?.let {
            clauses.add("status_code = ?")
            parameters.add(it)
        }
        filter.source?.let {
            clauses.add("source = ?")
            parameters.add(it)
        }
        filter.search?.let {
            val escaped = it.escapeLikeLiteral()
            clauses.add("(url LIKE ? ESCAPE '\\' OR req_body LIKE ? ESCAPE '\\' OR res_body LIKE ? ESCAPE '\\')")
            repeat(3) { parameters.add("%$escaped%") }
        }
        filter.since?.let {
            clauses.add("CAST(timestamp AS TIMESTAMP WITH TIME ZONE) >= CAST(? AS TIMESTAMP WITH TIME ZONE)")
            parameters.add(normalizeTimestamp(it, "since"))
        }
        filter.until?.let {
            clauses.add("CAST(timestamp AS TIMESTAMP WITH TIME ZONE) <= CAST(? AS TIMESTAMP WITH TIME ZONE)")
            parameters.add(normalizeTimestamp(it, "until"))
        }

        val where = if (clauses.isEmpty()) "" else "WHERE ${clauses.joinToString(" AND ")}"
        return QueryParts(where, parameters)
    }

    private fun rowToEntry(resultSet: ResultSet): HistoryEntry {
        val encodedRequestHeaders = resultSet.getString("req_headers")
            ?: throw StorageException("Stored history data is invalid")
        return try {
            HistoryEntry(
                id = resultSet.getLong("id"),
                source = resultSet.getString("source"),
                method = resultSet.getString("method"),
                url = resultSet.getString("url"),
                host = resultSet.getString("host"),
                reqHeaders = json.decodeFromString(encodedRequestHeaders),
                reqBody = resultSet.getString("req_body"),
                statusCode = resultSet.getInt("status_code").let { if (resultSet.wasNull()) null else it },
                resHeaders = resultSet.getString("res_headers")?.let { json.decodeFromString(it) },
                resBody = resultSet.getString("res_body"),
                durationMs = resultSet.getLong("duration_ms"),
                timestamp = normalizePersistedTimestamp(resultSet.getString("timestamp")),
            )
        } catch (failure: SerializationException) {
            throw StorageException("Stored history data is invalid", failure)
        } catch (failure: IllegalArgumentException) {
            throw StorageException("Stored history data is invalid", failure)
        } catch (failure: DateTimeException) {
            throw StorageException("Stored history data is invalid", failure)
        }
    }

    private fun normalizePersistedTimestamp(timestamp: String?): String {
        if (timestamp == null) throw StorageException("Stored history data is invalid")
        return try {
            Instant.parse(timestamp).toString()
        } catch (failure: DateTimeException) {
            throw StorageException("Stored history data is invalid", failure)
        }
    }

    private fun validatedOffset(filter: HistoryFilter): Long {
        require(filter.page >= 0) { "page must be >= 0" }
        require(filter.pageSize in 1..MAX_PAGE_SIZE) { "pageSize must be between 1 and $MAX_PAGE_SIZE" }
        return Math.multiplyExact(filter.page.toLong(), filter.pageSize.toLong())
    }

    private fun bind(statement: java.sql.PreparedStatement, parameters: List<Any>): Int {
        var index = 1
        parameters.forEach { parameter ->
            when (parameter) {
                is String -> statement.setString(index++, parameter)
                is Int -> statement.setInt(index++, parameter)
                else -> throw IllegalArgumentException("Unsupported history filter")
            }
        }
        return index
    }

    private data class QueryParts(val where: String, val parameters: List<Any>)
}

internal fun hostFromUrl(url: String): String? {
    return try {
        val host = URI(url).host ?: return null
        normalizeHost(host)
    } catch (_: Exception) {
        null
    }
}

internal fun normalizeHostFilter(host: String): String = try {
    normalizeHost(host)
} catch (failure: IllegalArgumentException) {
    throw IllegalArgumentException("host must be a valid hostname", failure)
}

private fun normalizeHost(host: String): String {
    val withoutTrailingDot = host.trim().removeSuffix(".")
    require(withoutTrailingDot.isNotEmpty()) { "host must not be empty" }
    if (':' in withoutTrailingDot) return withoutTrailingDot.lowercase()
    return IDN.toASCII(withoutTrailingDot, IDN.USE_STD3_ASCII_RULES).lowercase()
}

internal fun normalizeTimestamp(value: String, field: String): String = try {
    Instant.parse(value).toString()
} catch (failure: DateTimeException) {
    throw IllegalArgumentException("$field must be a valid ISO-8601 instant", failure)
}

private fun String.escapeLikeLiteral(): String = replace("\\", "\\\\")
    .replace("%", "\\%")
    .replace("_", "\\_")

internal fun String.truncateUtf8(maxBytes: Int): String {
    require(maxBytes >= 0) { "maxBytes must be non-negative" }
    if (toByteArray(StandardCharsets.UTF_8).size <= maxBytes) return this
    if (maxBytes == 0) return ""

    val output = ByteBuffer.allocate(maxBytes)
    val encoder = StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
    encoder.encode(CharBuffer.wrap(this), output, true)
    output.flip()
    return StandardCharsets.UTF_8.decode(output).toString()
}
