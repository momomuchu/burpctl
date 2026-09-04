package com.burprest.server

import burp.api.montoya.MontoyaApi
import com.burprest.db.DatabaseManager
import com.burprest.db.HistoryDao
import com.burprest.db.SessionDao
import com.burprest.db.SitemapDao
import com.burprest.models.ApiResponse
import com.burprest.routes.*
import com.burprest.services.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import java.time.Instant
import java.time.format.DateTimeFormatter

class RestServer(private val api: MontoyaApi, private val port: Int = 8089) {

    private var server: ApplicationEngine? = null
    private val startTime = System.currentTimeMillis()

    // Read the running Burp's version once via Montoya so /health and /version can report it
    // (the field was previously always null). Best-effort: null if Montoya changes the API.
    private val burpVersion: String? = try {
        api.burpSuite().version().toString()
    } catch (_: Throwable) {
        null
    }

    // Database (nullable — extension works without DB if init fails)
    private val db: DatabaseManager? = try {
        DatabaseManager(
            System.getProperty("user.home") + "/.burp-rest/burpdata"
        ).also { api.logging().logToOutput("[burp-rest] Database initialized at ~/.burp-rest/burpdata") }
    } catch (e: Exception) {
        api.logging().logToError("[burp-rest] Database init failed: ${e::class.simpleName}: ${e.message}")
        null
    }
    private val historyDao = db?.let { HistoryDao(it) }
    private val sitemapDao = db?.let { SitemapDao(it) }
    private val sessionDao = db?.let { SessionDao(it) }

    // Services
    private val proxyService = ProxyService(api)
    private val repeaterService = RepeaterService(api, historyDao, sitemapDao)
    private val collaboratorService = CollaboratorService(api)
    private val intruderService = IntruderService(api, repeaterService)
    private val scannerService = ScannerService(api)
    private val targetService = TargetService(api)
    private val decoderService = DecoderService()
    private val configService = ConfigService(api)
    private val sessionService = SessionService(api, historyDao, sitemapDao, sessionDao)
    private val securityScanService = SecurityScanService(api, sessionService, historyDao)
    private val utilsService = UtilsService(sessionService)

    fun start() {
        server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            configurePlugins()
            configureRouting()
        }.start(wait = false)

        api.logging().logToOutput("[burp-rest] Server started on http://127.0.0.1:$port")
    }

    fun stop() {
        server?.stop(1000, 2000)
        db?.close()
        api.logging().logToOutput("[burp-rest] Server stopped")
    }

    private fun Application.configurePlugins() {
        installStrictJson()

        install(CORS) {
            // Loopback-only API: restrict cross-origin to localhost so a random website's JS can't
            // drive the local Burp via :8089 (the bp CLI itself sends no Origin and is unaffected).
            allowHost("localhost:$port")
            allowHost("127.0.0.1:$port")
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Post)
            allowMethod(HttpMethod.Put)
            allowMethod(HttpMethod.Delete)
            allowMethod(HttpMethod.Options)
            allowHeader(HttpHeaders.ContentType)
            allowHeader(HttpHeaders.Authorization)
            allowHeader("X-API-Key")
        }

        installErrorHandling { api.logging().logToError(it) }
    }

    private fun Application.configureRouting() {
        installRequestLogging { api.logging().logToOutput(it) }

        routing {
            healthRoutes(startTime, burpVersion)
            proxyRoutes(proxyService)
            repeaterRoutes(repeaterService)
            collaboratorRoutes(collaboratorService)
            intruderRoutes(intruderService)
            scannerRoutes(scannerService)
            targetRoutes(targetService)
            decoderRoutes(decoderService)
            configRoutes(configService)
            sessionRoutes(sessionService)
            securityScanRoutes(securityScanService)
            utilsRoutes(utilsService)
            if (historyDao != null && sitemapDao != null) {
                historyRoutes(historyDao, sitemapDao, repeaterService)
            } else {
                unavailableHistoryRoutes()
            }
        }
    }
}

fun Application.installStrictJson() {
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = false
            isLenient = false
            ignoreUnknownKeys = false
            encodeDefaults = true
        })
    }
}

/** Log only the request path. Query strings frequently contain credentials and other secrets. */
fun Application.installRequestLogging(logOutput: (String) -> Unit) {
    intercept(ApplicationCallPipeline.Monitoring) {
        val start = System.currentTimeMillis()
        try {
            proceed()
        } finally {
            val duration = System.currentTimeMillis() - start
            val method = call.request.local.method.value
            val path = call.request.path()
            val status = call.response.status()?.value ?: 0
            val timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now())
            logOutput("[$timestamp] $method $path $status ${duration}ms")
        }
    }
}

/**
 * Install the shared HTTP error contract. Expected failures use typed [ApiException] values;
 * parser, framework, and unexpected failures are logged in full but receive fixed public messages.
 */
fun Application.installErrorHandling(logError: (String) -> Unit) {
    install(StatusPages) {
        exception<ApiException> { call, cause ->
            logError("[burp-rest] ${cause.code}: ${cause.clientMessage}${formatCause(cause.cause)}")
            call.respond(
                cause.status,
                ApiResponse.error<Unit>(cause.code, cause.clientMessage),
            )
        }
        exception<io.ktor.server.plugins.BadRequestException> { call, cause ->
            logError("[burp-rest] Bad request: ${cause.message}")
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse.error<Unit>("INVALID_REQUEST", "invalid request body"),
            )
        }
        exception<kotlinx.serialization.SerializationException> { call, cause ->
            logError("[burp-rest] Serialization error: ${cause.message}")
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse.error<Unit>("INVALID_REQUEST", "invalid request body"),
            )
        }
        // Compatibility for existing route/service validation. These messages are authored by the
        // application; new code should prefer InvalidParamException for a stable error code.
        exception<IllegalArgumentException> { call, cause ->
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse.error<Unit>("INVALID_REQUEST", cause.message ?: "invalid request"),
            )
        }
        exception<ProRequiredException> { call, cause ->
            logError("[burp-rest] Pro-required: ${cause.message}")
            call.respond(
                HttpStatusCode.ServiceUnavailable,
                ApiResponse.error<Unit>("PRO_REQUIRED", "this operation requires Burp Suite Professional"),
            )
        }
        exception<IllegalStateException> { call, cause ->
            logError("[burp-rest] State error: ${cause.message}")
            call.respond(
                HttpStatusCode.ServiceUnavailable,
                ApiResponse.error<Unit>("SERVICE_UNAVAILABLE", "service unavailable"),
            )
        }
        status(HttpStatusCode.NotFound) { call, _ ->
            call.respond(
                HttpStatusCode.NotFound,
                ApiResponse.error<Unit>("NOT_FOUND", "route not found"),
            )
        }
        status(HttpStatusCode.MethodNotAllowed) { call, _ ->
            call.respond(
                HttpStatusCode.MethodNotAllowed,
                ApiResponse.error<Unit>("METHOD_NOT_ALLOWED", "method not allowed"),
            )
        }
        exception<Throwable> { call, cause ->
            logError("[burp-rest] Error: ${cause::class.simpleName}: ${cause.message}\n${cause.stackTraceToString().take(2000)}")
            call.respond(
                HttpStatusCode.InternalServerError,
                ApiResponse.error<Unit>("INTERNAL_ERROR", "internal server error"),
            )
        }
    }
}

private fun formatCause(cause: Throwable?): String =
    cause?.let { "; caused by ${it::class.simpleName}: ${it.message}" } ?: ""
