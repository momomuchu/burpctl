package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ScanTask
import burp.api.montoya.scanner.audit.Audit
import com.burprest.models.*
import com.burprest.server.InvalidParamException
import com.burprest.server.NotFoundException
import com.burprest.server.ProRequiredException
import com.burprest.server.ServiceUnavailableException
import com.burprest.server.UnsupportedException
import java.net.IDN
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class ScannerService(
    private val api: MontoyaApi,
    internal val crawlConfigurationFactory: (String) -> CrawlConfiguration = {
        CrawlConfiguration.crawlConfiguration(it)
    },
    internal val auditConfigurationFactory: () -> AuditConfiguration = {
        AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
    },
    internal val requestFactory: (String) -> HttpRequest = { HttpRequest.httpRequestFromUrl(it) },
    internal val scanIdFactory: () -> String = { UUID.randomUUID().toString().take(8) },
) {

    private val scans = ConcurrentHashMap<String, ScanState>()

    sealed class ScanState(val id: String, val task: ScanTask) {
        class CrawlState(id: String, val crawl: Crawl) : ScanState(id, crawl)
        class AuditState(id: String, val audit: Audit) : ScanState(id, audit)
    }

    fun crawl(request: ScanRequest): ScanStartResponse {
        val url = validateScanUrl(request.url)
        rejectUnsupportedConfiguration(request)
        val id = nextScanId()
        val edition = currentEdition()
        ensureScannerAvailable("crawl", edition)

        val crawl = try {
            val configuration = crawlConfigurationFactory(url)
            api.scanner().startCrawl(configuration)
        } catch (cause: Exception) {
            throw classifyStartFailure("crawl", cause, edition)
        }

        val state = ScanState.CrawlState(id, crawl)
        registerOrDelete(state)
        return ScanStartResponse(scanId = state.id, status = "running")
    }

    fun audit(request: ScanRequest): ScanStartResponse {
        val url = validateScanUrl(request.url)
        rejectUnsupportedConfiguration(request)
        val id = nextScanId()
        val edition = currentEdition()
        ensureScannerAvailable("audit", edition)

        var audit: Audit? = null
        try {
            val seed = requestFactory(url)
            audit = api.scanner().startAudit(auditConfigurationFactory())
            // startAudit alone creates an empty task. Bind it to the caller's exact target before
            // publishing an ID, otherwise a successful response would not represent their request.
            audit.addRequest(seed)
        } catch (cause: Exception) {
            audit?.let { started ->
                try {
                    started.delete()
                } catch (cleanupFailure: Exception) {
                    cause.addSuppressed(cleanupFailure)
                }
            }
            throw classifyStartFailure("audit", cause, edition)
        }

        val state = ScanState.AuditState(id, audit)
        registerOrDelete(state)
        return ScanStartResponse(scanId = state.id, status = "running")
    }

    /** Montoya 2025.3 has no linked crawl-and-audit primitive. */
    fun crawlAndAudit(): Nothing = throw UnsupportedException(
        "Montoya 2025.3 cannot start one linked crawl-and-audit task",
    )

    /** Source-compatible overload; the request is intentionally not inspected for an unsupported operation. */
    fun crawlAndAudit(@Suppress("UNUSED_PARAMETER") request: ScanRequest): Nothing = crawlAndAudit()

    fun status(scanId: String): ScanStatusResponse {
        val scan = requireScan(scanId)
        // A live task may temporarily reject individual projections. Keep the task addressable and
        // report only values Montoya actually supplied instead of failing the entire status read.
        val statusMessage = taskValueOrNull { scan.task.statusMessage() }
        val issueCount = when (scan) {
            is ScanState.AuditState -> taskValueOrNull { scan.audit.issues()?.size }
            is ScanState.CrawlState -> 0
        }
        return ScanStatusResponse(
            scanId = scanId,
            status = statusMessage,
            statusMessage = statusMessage,
            crawlProgress = null,
            auditProgress = null,
            requestCount = taskValueOrNull { scan.task.requestCount() },
            errorCount = taskValueOrNull { scan.task.errorCount() },
            issueCount = issueCount,
        )
    }

    fun issues(scanId: String): ScanIssuesResponse {
        val scan = requireScan(scanId)
        val auditIssues = when (scan) {
            is ScanState.AuditState -> taskValueOrNull { scan.audit.issues() }
            is ScanState.CrawlState -> emptyList()
        } ?: return ScanIssuesResponse(scanId = scanId, issues = null, total = null)

        return try {
            val entries = auditIssues.map {
                ScanIssue(
                    name = it.name(),
                    url = it.baseUrl(),
                    severity = it.severity().name,
                    confidence = it.confidence().name,
                    detail = it.detail(),
                    remediation = it.remediation(),
                )
            }
            ScanIssuesResponse(
                scanId = scanId,
                issues = entries,
                total = entries.size,
            )
        } catch (cause: Exception) {
            throw ServiceUnavailableException("scanner task issues are unavailable", cause)
        }
    }

    fun pause(@Suppress("UNUSED_PARAMETER") scanId: String): Nothing = throw UnsupportedException(
        "Montoya 2025.3 does not expose scanner pause",
    )

    fun resume(@Suppress("UNUSED_PARAMETER") scanId: String): Nothing = throw UnsupportedException(
        "Montoya 2025.3 does not expose scanner resume",
    )

    fun stop(scanId: String): ScanStatusResponse {
        val scan = requireScan(scanId)
        // Deletion is the requested effect; task statistics are only best-effort context. Reading a
        // counter used to abort before delete and strand a real task when Montoya rejected projection.
        val counts = TaskCounts(
            requests = taskValueOrNull { scan.task.requestCount() },
            errors = taskValueOrNull { scan.task.errorCount() },
            issues = when (scan) {
                is ScanState.AuditState -> taskValueOrNull { scan.audit.issues()?.size }
                is ScanState.CrawlState -> 0
            },
        )
        try {
            scan.task.delete()
        } catch (cause: Exception) {
            // Keep ownership of a task whose deletion was not confirmed, so a later status/stop can
            // still address it and this call never falsely reports "stopped".
            throw ServiceUnavailableException("scanner task could not be stopped", cause)
        }
        scans.remove(scanId, scan)
        return ScanStatusResponse(
            scanId = scanId,
            status = "stopped",
            statusMessage = "stopped",
            crawlProgress = null,
            auditProgress = null,
            requestCount = counts.requests,
            errorCount = counts.errors,
            issueCount = counts.issues,
        )
    }

    private data class TaskCounts(val requests: Int?, val errors: Int?, val issues: Int?)

    private inline fun <T> taskValueOrNull(read: () -> T): T? = try {
        read()
    } catch (_: Exception) {
        null
    }

    fun issueDefinitions(): IssueDefinitionsResponse {
        val definitions = try {
            api.siteMap().issues()
                .map { it.definition() }
                .distinctBy { it.typeIndex() }
                .map {
                    IssueDefinition(
                        name = it.name(),
                        typeIndex = it.typeIndex().toLong(),
                        description = it.background(),
                        remediation = it.remediation(),
                    )
                }
        } catch (cause: Exception) {
            throw ServiceUnavailableException("scanner issue definitions are unavailable", cause)
        }
        return IssueDefinitionsResponse(definitions = definitions, total = definitions.size)
    }

    private fun nextScanId(): String = scanIdFactory().also {
        if (it.isBlank()) throw ServiceUnavailableException("scanner could not allocate a task ID")
    }

    private fun rejectUnsupportedConfiguration(request: ScanRequest) {
        if (request.config.crawlStrategy != null || request.config.auditOptimization != null) {
            throw UnsupportedException("Montoya 2025.3 does not expose these scanner configuration controls")
        }
    }

    private fun registerOrDelete(state: ScanState) {
        if (scans.putIfAbsent(state.id, state) == null) return
        val collision = IllegalStateException("duplicate scanner task ID")
        try {
            state.task.delete()
        } catch (cleanupFailure: Exception) {
            collision.addSuppressed(cleanupFailure)
        }
        throw ServiceUnavailableException("scanner could not allocate a unique task ID", collision)
    }

    private fun requireScan(scanId: String): ScanState {
        if (scanId.isBlank()) throw InvalidParamException("scan id must not be blank")
        return scans[scanId] ?: throw NotFoundException("scanner task was not found")
    }

    private fun ensureScannerAvailable(operation: String, edition: BurpSuiteEdition?) {
        if (edition != null && edition != BurpSuiteEdition.PROFESSIONAL) {
            throw ProRequiredException("$operation requires Burp Suite Professional")
        }
    }

    private fun classifyStartFailure(
        operation: String,
        cause: Exception,
        edition: BurpSuiteEdition?,
    ): RuntimeException {
        if (edition != null && edition != BurpSuiteEdition.PROFESSIONAL) {
            return ProRequiredException("$operation requires Burp Suite Professional")
        }
        return ServiceUnavailableException("scanner could not start $operation", cause)
    }

    /** Edition lookup is diagnostic. If it is unavailable, do not guess that an operational error is a Pro gate. */
    private fun currentEdition(): BurpSuiteEdition? = try {
        api.burpSuite().version().edition()
    } catch (_: Exception) {
        null
    }

    private fun validateScanUrl(value: String): String {
        if (value.isBlank()) throw InvalidParamException("url must not be blank")
        val uri = try {
            URI(value)
        } catch (cause: Exception) {
            throw InvalidParamException("url must be an absolute HTTP or HTTPS URL", cause)
        }
        if (!uri.isAbsolute || uri.isOpaque) {
            throw InvalidParamException("url must be an absolute HTTP or HTTPS URL")
        }
        val url = try {
            URL(value)
        } catch (cause: Exception) {
            throw InvalidParamException("url must contain a valid host", cause)
        }
        val scheme = url.protocol.lowercase(Locale.ROOT)
        if (scheme != "http" && scheme != "https") {
            throw InvalidParamException("url must use http or https")
        }
        if (url.userInfo != null) throw InvalidParamException("url must not contain user information")
        if (uri.rawFragment != null) throw InvalidParamException("url must not contain a fragment")
        val port = validateAndExtractPort(uri)
        val normalizedHost = normalizeHttpHost(url.host)
            ?: throw InvalidParamException("url must contain a valid host")
        val effectivePort = when {
            port == -1 -> -1
            scheme == "http" && port == 80 -> -1
            scheme == "https" && port == 443 -> -1
            else -> port
        }
        val authorityHost = if (normalizedHost.contains(':')) "[$normalizedHost]" else normalizedHost
        val path = uri.normalize().rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        val query = uri.rawQuery?.let { "?$it" } ?: ""
        return "$scheme://$authorityHost${if (effectivePort == -1) "" else ":$effectivePort"}$path$query"
    }

    private fun validateAndExtractPort(uri: URI): Int {
        val authority = uri.rawAuthority ?: throw InvalidParamException("url must contain a host")
        val hostAndPort = authority.substringAfterLast('@')
        val portText = when {
            hostAndPort.startsWith('[') -> {
                val close = hostAndPort.indexOf(']')
                if (close < 0) throw InvalidParamException("url must contain a valid host")
                hostAndPort.substring(close + 1).let { suffix ->
                    when {
                        suffix.isEmpty() -> null
                        suffix.startsWith(':') -> suffix.substring(1)
                        else -> throw InvalidParamException("url must contain a valid host")
                    }
                }
            }
            hostAndPort.count { it == ':' } == 1 -> hostAndPort.substringAfterLast(':')
            else -> null
        }
        if (portText == null) return -1
        if (portText.isEmpty() || portText.any { !it.isDigit() }) {
            throw InvalidParamException("url port must be an integer between 1 and 65535")
        }
        val port = portText.toIntOrNull()
            ?: throw InvalidParamException("url port must be between 1 and 65535")
        if (port !in 1..65_535) throw InvalidParamException("url port must be between 1 and 65535")
        return port
    }

    private fun normalizeHttpHost(value: String): String? {
        val host = value.removeSurrounding("[", "]").removeSuffix(".")
        if (host.isEmpty() || host.contains('%')) return null
        return if (host.contains(':')) {
            try {
                InetAddress.getByName(host).takeIf { it.address.size == 16 }?.hostAddress?.lowercase(Locale.ROOT)
            } catch (_: Exception) {
                null
            }
        } else {
            try {
                IDN.toASCII(host.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
                    .lowercase(Locale.ROOT)
                    .takeIf { it.isNotEmpty() }
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}
