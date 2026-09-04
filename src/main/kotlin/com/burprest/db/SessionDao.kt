package com.burprest.db

import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.sql.Connection

data class PersistedSession(
    val name: String,
    val cookies: Map<String, String>,
    val headers: Map<String, String>,
    val boundOrigin: String? = null,
)

class SessionDao(private val db: DatabaseManager) {
    private val json = Json { ignoreUnknownKeys = true }

    /** Replaces the complete persisted session in one transaction while preserving legacy keys. */
    fun save(
        name: String,
        cookies: Map<String, String>,
        headers: Map<String, String>,
        boundOrigin: String? = null,
    ) = db.transaction { connection ->
        upsert(connection, NAME_KEY, name)
        upsert(connection, COOKIES_KEY, json.encodeToString(cookies))
        upsert(connection, HEADERS_KEY, json.encodeToString(headers))
        if (boundOrigin == null) {
            delete(connection, BOUND_ORIGIN_KEY)
        } else {
            upsert(connection, BOUND_ORIGIN_KEY, normalizeBoundOrigin(boundOrigin))
        }
    }

    fun load(): PersistedSession? = db.withConnection { connection ->
        val values = connection.prepareStatement(
            """SELECT "key", "value" FROM session_store
               WHERE "key" IN (?, ?, ?, ?)"""
        ).use { statement ->
            statement.setString(1, NAME_KEY)
            statement.setString(2, COOKIES_KEY)
            statement.setString(3, HEADERS_KEY)
            statement.setString(4, BOUND_ORIGIN_KEY)
            statement.executeQuery().use { resultSet ->
                buildMap {
                    while (resultSet.next()) put(resultSet.getString(1), resultSet.getString(2))
                }
            }
        }

        if (values.isEmpty()) return@withConnection null
        val name = values[NAME_KEY]
        val encodedCookies = values[COOKIES_KEY]
        val encodedHeaders = values[HEADERS_KEY]
        if (name == null || encodedCookies == null || encodedHeaders == null) {
            throw StorageException("Stored session data is invalid")
        }

        try {
            PersistedSession(
                name = name,
                cookies = json.decodeFromString(encodedCookies),
                headers = json.decodeFromString(encodedHeaders),
                boundOrigin = values[BOUND_ORIGIN_KEY]?.let(::normalizeBoundOrigin),
            )
        } catch (failure: SerializationException) {
            throw StorageException("Stored session data is invalid", failure)
        } catch (failure: IllegalArgumentException) {
            throw StorageException("Stored session data is invalid", failure)
        }
    }

    /** Clearing is transactional so failure cannot expose a partially deleted session. */
    fun clear() = db.transaction { connection ->
        connection.createStatement().use { statement -> statement.executeUpdate("DELETE FROM session_store") }
    }

    private fun upsert(connection: Connection, key: String, value: String) {
        connection.prepareStatement(
            """MERGE INTO session_store ("key", "value") KEY ("key") VALUES (?, ?)"""
        ).use { statement ->
            statement.setString(1, key)
            statement.setString(2, value)
            statement.executeUpdate()
        }
    }

    private fun delete(connection: Connection, key: String) {
        connection.prepareStatement("""DELETE FROM session_store WHERE "key" = ?""").use { statement ->
            statement.setString(1, key)
            statement.executeUpdate()
        }
    }

    private fun normalizeBoundOrigin(origin: String): String {
        val uri = try {
            URI(origin)
        } catch (failure: Exception) {
            throw IllegalArgumentException("boundOrigin must be an HTTP origin", failure)
        }
        val scheme = uri.scheme?.lowercase()
        require(scheme == "http" || scheme == "https") { "boundOrigin must be an HTTP origin" }
        val rawHost = uri.host ?: throw IllegalArgumentException("boundOrigin must be an HTTP origin")
        require(uri.userInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
            "boundOrigin must be an HTTP origin"
        }
        require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") { "boundOrigin must be an HTTP origin" }
        val host = normalizeHostFilter(rawHost)
        val renderedHost = if (':' in host && !host.startsWith("[")) "[$host]" else host
        val defaultPort = if (scheme == "https") 443 else 80
        val port = uri.port.takeIf { it >= 0 && it != defaultPort }?.let { ":$it" }.orEmpty()
        return "$scheme://$renderedHost$port"
    }

    private companion object {
        const val NAME_KEY = "name"
        const val COOKIES_KEY = "cookies"
        const val HEADERS_KEY = "headers"
        const val BOUND_ORIGIN_KEY = "bound_origin"
    }
}
