package com.burprest.db

import java.net.URI
import java.sql.Connection
import java.sql.SQLException
import java.time.Instant

data class SitemapRow(
    val host: String,
    val path: String,
    val method: String,
    val lastSeen: String,
    val hitCount: Int,
)

class SitemapDao(private val db: DatabaseManager) {
    internal fun uses(database: DatabaseManager): Boolean = db === database

    fun upsert(url: String, method: String, timestamp: String = Instant.now().toString()) {
        db.transaction { connection -> upsert(connection, url, method, timestamp) }
    }

    fun list(host: String? = null): List<SitemapRow> {
        val normalizedHost = host?.let(::normalizeHostFilter)
        val sql = if (normalizedHost != null) {
            "SELECT * FROM sitemap WHERE host = ? ORDER BY path, method"
        } else {
            "SELECT * FROM sitemap ORDER BY host, path, method"
        }
        return db.withConnection { connection ->
            connection.prepareStatement(sql).use { statement ->
                normalizedHost?.let { statement.setString(1, it) }
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            val lastSeen = try {
                                Instant.parse(resultSet.getString("last_seen")).toString()
                            } catch (failure: Exception) {
                                throw StorageException("Stored sitemap data is invalid", failure)
                            }
                            add(
                                SitemapRow(
                                    host = resultSet.getString("host"),
                                    path = resultSet.getString("path"),
                                    method = resultSet.getString("method"),
                                    lastSeen = lastSeen,
                                    hitCount = resultSet.getInt("hit_count"),
                                )
                            )
                        }
                    }
                }
            }
        }
    }

    fun clear() = db.transaction { connection -> clear(connection) }

    internal fun upsert(connection: Connection, url: String, method: String, timestamp: String) {
        val uri = try {
            URI(url)
        } catch (_: Exception) {
            return
        }
        val host = uri.host?.let(::normalizeHostFilter) ?: return
        val path = uri.rawPath?.ifEmpty { "/" } ?: "/"
        val normalizedTimestamp = normalizeTimestamp(timestamp, "timestamp")

        // UPDATE-first avoids MERGE's read/replace race and preserves every increment under contention.
        connection.prepareStatement(
            """UPDATE sitemap
               SET last_seen = ?, hit_count = hit_count + 1
               WHERE host = ? AND path = ? AND method = ?"""
        ).use { update ->
            update.setString(1, normalizedTimestamp)
            update.setString(2, host)
            update.setString(3, path)
            update.setString(4, method)
            if (update.executeUpdate() == 1) return
        }

        try {
            connection.prepareStatement(
                """INSERT INTO sitemap (host, path, method, last_seen, hit_count)
                   VALUES (?, ?, ?, ?, 1)"""
            ).use { insert ->
                insert.setString(1, host)
                insert.setString(2, path)
                insert.setString(3, method)
                insert.setString(4, normalizedTimestamp)
                insert.executeUpdate()
            }
        } catch (failure: SQLException) {
            // Another transaction can win the absent-row race. Retry as an increment; only suppress
            // the insert error if that exact row now exists and was updated.
            connection.prepareStatement(
                """UPDATE sitemap
                   SET last_seen = ?, hit_count = hit_count + 1
                   WHERE host = ? AND path = ? AND method = ?"""
            ).use { retry ->
                retry.setString(1, normalizedTimestamp)
                retry.setString(2, host)
                retry.setString(3, path)
                retry.setString(4, method)
                if (retry.executeUpdate() != 1) throw failure
            }
        }
    }

    internal fun clear(connection: Connection) {
        connection.createStatement().use { statement -> statement.executeUpdate("DELETE FROM sitemap") }
    }
}
