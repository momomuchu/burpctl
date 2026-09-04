package com.burprest.db

import java.io.Closeable
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryFlag
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.util.EnumSet
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/** A storage-layer failure whose message is safe to return without exposing paths or persisted data. */
class StorageException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Owns the H2 database and lends a distinct connection to each top-level operation.
 *
 * DAO calls made on the same thread inside [transaction] automatically enlist in that transaction.
 * This preserves the existing DAO construction API without exposing a process-wide shared connection.
 */
class DatabaseManager(dbPath: String) : Closeable {
    private val databasePath: Path = normalizeDatabasePath(dbPath)
    private val databaseDirectory: Path = databasePath.parent
        ?: throw StorageException("Unsafe database path")
    private val jdbcUrl = "jdbc:h2:file:$databasePath"
    private val closed = AtomicBoolean(false)
    private val lifecycleLock = ReentrantReadWriteLock(true)
    private val transactionState = ThreadLocal<TransactionState?>()

    init {
        try {
            Class.forName("org.h2.Driver")
            prepareSecureDirectory()
            withConnection { connection -> createTables(connection) }
        } catch (failure: StorageException) {
            closed.set(true)
            throw failure
        } catch (failure: Exception) {
            closed.set(true)
            throw StorageException("Database initialization failed", failure)
        }
    }

    /**
     * Runs [block] with a connection scoped to this call. A transaction already active on this thread
     * is reused; otherwise the connection is always closed before this method returns.
     */
    fun <T> withConnection(block: (Connection) -> T): T = lifecycleLock.read {
        ensureOpen()
        transactionState.get()?.let { state ->
            try {
                return@read invokeStorageBlock { block(state.connection) }
            } catch (failure: Throwable) {
                state.rollbackOnly = true
                throw failure
            }
        }

        validateDatabaseFiles()
        try {
            DriverManager.getConnection(jdbcUrl).use { connection ->
                secureDatabaseFiles()
                invokeStorageBlock { block(connection) }
            }
        } catch (failure: StorageException) {
            throw failure
        } catch (failure: SQLException) {
            throw StorageException("Storage operation failed", failure)
        } finally {
            secureDatabaseFilesIfPresent()
        }
    }

    /**
     * Coordinates any number of DAO calls as one transaction. Nested calls join the outer transaction;
     * only the outermost call commits or rolls back.
     */
    fun <T> transaction(block: (Connection) -> T): T = lifecycleLock.read {
        ensureOpen()
        transactionState.get()?.let { state ->
            try {
                return@read invokeStorageBlock { block(state.connection) }
            } catch (failure: Throwable) {
                state.rollbackOnly = true
                throw failure
            }
        }

        validateDatabaseFiles()
        try {
            DriverManager.getConnection(jdbcUrl).use { connection ->
                secureDatabaseFiles()
                connection.autoCommit = false
                val state = TransactionState(connection)
                transactionState.set(state)
                try {
                    val result = invokeStorageBlock { block(connection) }
                    if (state.rollbackOnly) {
                        connection.rollback()
                        throw StorageException("Storage transaction rolled back")
                    }
                    connection.commit()
                    result
                } catch (failure: Throwable) {
                    try {
                        connection.rollback()
                    } catch (rollbackFailure: SQLException) {
                        failure.addSuppressed(rollbackFailure)
                    }
                    throw failure
                } finally {
                    transactionState.remove()
                    runCatching { connection.autoCommit = true }
                }
            }
        } catch (failure: StorageException) {
            throw failure
        } catch (failure: SQLException) {
            throw StorageException("Storage transaction failed", failure)
        } finally {
            transactionState.remove()
            secureDatabaseFilesIfPresent()
        }
    }

    private fun createTables(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.execute(
                """
                CREATE TABLE IF NOT EXISTS request_history (
                    id          IDENTITY PRIMARY KEY,
                    source      VARCHAR NOT NULL,
                    method      VARCHAR NOT NULL,
                    url         VARCHAR NOT NULL,
                    host        VARCHAR NOT NULL,
                    req_headers CLOB NOT NULL,
                    req_body    CLOB,
                    status_code INTEGER,
                    res_headers CLOB,
                    res_body    CLOB,
                    duration_ms BIGINT,
                    timestamp   VARCHAR NOT NULL
                )
                """.trimIndent()
            )
            statement.execute("CREATE INDEX IF NOT EXISTS idx_history_host ON request_history(host)")
            statement.execute("CREATE INDEX IF NOT EXISTS idx_history_status ON request_history(status_code)")
            statement.execute("CREATE INDEX IF NOT EXISTS idx_history_method ON request_history(method)")
            statement.execute("CREATE INDEX IF NOT EXISTS idx_history_ts ON request_history(timestamp)")
            statement.execute(
                """
                CREATE TABLE IF NOT EXISTS sitemap (
                    host        VARCHAR NOT NULL,
                    path        VARCHAR NOT NULL,
                    method      VARCHAR NOT NULL,
                    last_seen   VARCHAR NOT NULL,
                    hit_count   INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (host, path, method)
                )
                """.trimIndent()
            )
            statement.execute(
                """
                CREATE TABLE IF NOT EXISTS session_store (
                    "key"   VARCHAR PRIMARY KEY,
                    "value" CLOB NOT NULL
                )
                """.trimIndent()
            )
        }
    }

    override fun close() {
        if (transactionState.get() != null) {
            throw StorageException("Cannot close database during an active transaction")
        }
        lifecycleLock.write {
            closed.set(true)
            transactionState.remove()
            secureDatabaseFilesIfPresent()
        }
    }

    private fun ensureOpen() {
        if (closed.get()) throw StorageException("Database is closed")
    }

    private fun prepareSecureDirectory() {
        createDirectoriesWithoutFollowingLinks(databaseDirectory)
        validatePathComponents(databaseDirectory)
        // Refuse unsafe existing database objects before changing an existing directory's mode.
        validateDatabaseFiles()
        applyOwnerOnlyPermissions(databaseDirectory, directory = true)
    }

    private fun validateDatabaseFiles() {
        validatePathComponents(databaseDirectory)
        if (Files.exists(databasePath, LinkOption.NOFOLLOW_LINKS)) {
            // H2 uses suffixed files. A bare object at the logical base path is unrelated and must
            // never be followed, chmodded, or overwritten.
            throw StorageException("Unsafe database path")
        }
        databaseCandidates().forEach { path ->
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return@forEach
            if (Files.isSymbolicLink(path)) throw StorageException("Unsafe database path")
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw StorageException("Unsafe database path")
            }
        }
    }

    private fun secureDatabaseFiles() {
        validateDatabaseFiles()
        databaseCandidates().forEach { path ->
            if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                applyOwnerOnlyPermissions(path, directory = false)
            }
        }
    }

    private fun secureDatabaseFilesIfPresent() {
        if (!Files.exists(databaseDirectory, LinkOption.NOFOLLOW_LINKS)) return
        try {
            secureDatabaseFiles()
        } catch (failure: StorageException) {
            throw failure
        } catch (failure: Exception) {
            throw StorageException("Unable to secure database files", failure)
        }
    }

    private fun databaseCandidates(): List<Path> {
        val baseName = databasePath.fileName.toString()
        val candidates = linkedSetOf<Path>()
        listOf(
            ".mv.db",
            ".h2.db",
            ".data.db",
            ".lock.db",
            ".trace.db",
            ".temp.db",
            ".newFile",
            ".tempFile",
            ".oldFile",
        ).forEach {
            candidates.add(databaseDirectory.resolve(baseName + it))
        }
        if (Files.isDirectory(databaseDirectory, LinkOption.NOFOLLOW_LINKS)) {
            Files.newDirectoryStream(databaseDirectory, "$baseName.*.temp.db").use { entries ->
                entries.forEach(candidates::add)
            }
        }
        return candidates.toList()
    }

    private fun applyOwnerOnlyPermissions(path: Path, directory: Boolean) {
        val store = try {
            Files.getFileStore(path)
        } catch (failure: Exception) {
            throw StorageException("Unable to secure database path", failure)
        }
        when {
            store.supportsFileAttributeView(PosixFileAttributeView::class.java) -> {
                val permissions = if (directory) DIRECTORY_PERMISSIONS else FILE_PERMISSIONS
                try {
                    Files.setPosixFilePermissions(path, permissions)
                } catch (failure: Exception) {
                    throw StorageException("Unable to secure database path", failure)
                }
            }
            store.supportsFileAttributeView(AclFileAttributeView::class.java) -> applyOwnerOnlyAcl(path)
            else -> applyBasicOwnerOnlyPermissions(path.toFile(), directory)
        }
    }

    /** Explicit non-POSIX handling for ACL-based file systems such as Windows NTFS. */
    private fun applyOwnerOnlyAcl(path: Path) {
        try {
            val view = Files.getFileAttributeView(path, AclFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                ?: throw StorageException("Unable to secure database path")
            val owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS)
            val entry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission::class.java))
                .setFlags(emptySet<AclEntryFlag>())
                .build()
            view.acl = listOf(entry)
        } catch (failure: StorageException) {
            throw failure
        } catch (failure: Exception) {
            throw StorageException("Unable to secure database path", failure)
        }
    }

    /** Last-resort non-POSIX handling when neither POSIX permissions nor ACLs are available. */
    private fun applyBasicOwnerOnlyPermissions(file: File, directory: Boolean) {
        val results = listOf(
            file.setReadable(false, false),
            file.setWritable(false, false),
            file.setExecutable(false, false),
            file.setReadable(true, true),
            file.setWritable(true, true),
            if (directory) file.setExecutable(true, true) else true,
        )
        if (results.any { !it }) throw StorageException("Unable to secure database path")
    }

    private fun validatePathComponents(path: Path) {
        var current = path.root ?: throw StorageException("Unsafe database path")
        path.forEach { component ->
            current = current.resolve(component)
            if (Files.isSymbolicLink(current)) throw StorageException("Unsafe database path")
        }
    }

    private fun createDirectoriesWithoutFollowingLinks(directory: Path) {
        var current = directory.root ?: throw StorageException("Unsafe database path")
        directory.forEach { component ->
            current = current.resolve(component)
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(current) || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                    throw StorageException("Unsafe database path")
                }
            } else {
                try {
                    Files.createDirectory(current)
                } catch (failure: Exception) {
                    throw StorageException("Unable to create database directory", failure)
                }
            }
        }
    }

    private inline fun <T> invokeStorageBlock(block: () -> T): T = try {
        block()
    } catch (failure: StorageException) {
        throw failure
    } catch (failure: SQLException) {
        throw StorageException("Storage operation failed", failure)
    }

    private data class TransactionState(
        val connection: Connection,
        var rollbackOnly: Boolean = false,
    )

    private companion object {
        val DIRECTORY_PERMISSIONS: Set<PosixFilePermission> = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
        val FILE_PERMISSIONS: Set<PosixFilePermission> = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        )

        fun normalizeDatabasePath(rawPath: String): Path {
            if (rawPath.isBlank() || rawPath.any { it.code == 0 } || ';' in rawPath) {
                throw StorageException("Unsafe database path")
            }
            val input = try {
                Paths.get(rawPath).toAbsolutePath().normalize()
            } catch (failure: Exception) {
                throw StorageException("Unsafe database path", failure)
            }
            val fileName = input.fileName?.toString() ?: throw StorageException("Unsafe database path")
            val baseName = when {
                fileName.endsWith(".mv.db") -> fileName.removeSuffix(".mv.db")
                fileName.endsWith(".h2.db") -> fileName.removeSuffix(".h2.db")
                fileName.endsWith(".db") -> fileName.removeSuffix(".db")
                fileName.endsWith(".mv") -> fileName.removeSuffix(".mv")
                else -> fileName
            }
            if (baseName.isBlank() || baseName == "." || baseName == "..") {
                throw StorageException("Unsafe database path")
            }
            return input.resolveSibling(baseName)
        }
    }
}
