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
        api.burpSuite().version().let { "${it.name()} ${it.major()}.${it.minor()}" }
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
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = false
                isLenient = true
                ignoreUnknownKeys = true
                encodeDefaults = true
            })
        }

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
        routing {
            // Request logging interceptor
            intercept(ApplicationCallPipeline.Monitoring) {
                val start = System.currentTimeMillis()
                proceed()
                val duration = System.currentTimeMillis() - start
                val method = call.request.local.method.value
                val uri = call.request.local.uri
                val status = call.response.status()?.value ?: 0
                val ts = DateTimeFormatter.ISO_INSTANT.format(Instant.now())
                api.logging().logToOutput("[$ts] $method $uri $status ${duration}ms")
            }

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
            }
        }
    }
}

/**
 * Install the ktor StatusPages error handling. Extracted from [RestServer] so it can be unit-tested
 * with a throwing route. Author-controlled errors (IllegalArgumentException from route validation
 * and Pro-gating IllegalStateException) keep their own message because we wrote that text.
 * BadRequestException and SerializationException are sanitised: ktor / kotlinx.serialization
 * populate their messages with fully-qualified Kotlin class names ("Failed to convert request body
 * to class com.burprest.models.XxxRequest") so we log the raw detail to [logError] and send only a
 * generic message to the client. The catch-all maps any *unexpected* error the same way.
 * No stack trace or internal class name ever reaches the HTTP client.
 */
fun Application.installErrorHandling(logError: (String) -> Unit) {
    install(StatusPages) {
        exception<io.ktor.server.plugins.BadRequestException> { call, cause ->
            // Ktor's BadRequestException.message often contains the fully-qualified Kotlin class name
            // ("Failed to convert request body to class com.burprest.models.XxxRequest").
            // Sanitise it: log the raw detail to Burp's error output but send only a generic,
            // resource-name-free message to the client.
            logError("[burp-rest] Bad request: ${cause.message}")
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse.error<Unit>("INVALID_REQUEST", "invalid request body (see Burp extension Errors log)"),
            )
        }
        exception<kotlinx.serialization.SerializationException> { call, cause ->
            // kotlinx.serialization messages can also reference internal class names — log and sanitise.
            logError("[burp-rest] Serialization error: ${cause.message}")
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse.error<Unit>("INVALID_REQUEST", "invalid request body (see Burp extension Errors log)"),
            )
        }
        exception<IllegalArgumentException> { call, cause ->
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse.error<Unit>("INVALID_REQUEST", cause.message ?: "Bad request"),
            )
        }
        exception<IllegalStateException> { call, cause ->
            logError("[burp-rest] State error: ${cause.message}")
            call.respond(
                HttpStatusCode.ServiceUnavailable,
                ApiResponse.error<Unit>("SERVICE_UNAVAILABLE", cause.message ?: "Service unavailable"),
            )
        }
        exception<Throwable> { call, cause ->
            logError("[burp-rest] Error: ${cause::class.simpleName}: ${cause.message}\n${cause.stackTraceToString().take(2000)}")
            call.respond(
                HttpStatusCode.InternalServerError,
                ApiResponse.error<Unit>("INTERNAL_ERROR", "internal server error (see Burp extension Errors log)"),
            )
        }
    }
}
