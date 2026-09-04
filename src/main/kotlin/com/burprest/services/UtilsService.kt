package com.burprest.services

import com.burprest.models.AuthenticatedRequest
import com.burprest.models.BundleFetchFailure
import com.burprest.models.DiffRequest
import com.burprest.models.DiffResponse
import com.burprest.models.DiffTarget
import com.burprest.models.ExtractEndpointsRequest
import com.burprest.models.ExtractEndpointsResponse
import com.burprest.models.HeaderDiff
import com.burprest.models.HttpHeader
import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import kotlin.math.abs

class UtilsService(private val sessionService: SessionService) {

    fun diff(request: DiffRequest): DiffResponse {
        // This operation has two target effects, so validate both arms before sending either.
        validateDiffTarget(request.a, "a")
        validateDiffTarget(request.b, "b")

        val respA = sessionService.send(
            AuthenticatedRequest(
                method = request.a.method,
                url = request.a.url,
                body = request.a.body,
                extraHeaders = request.a.extraHeaders,
            )
        )
        val respB = sessionService.send(
            AuthenticatedRequest(
                method = request.b.method,
                url = request.b.url,
                body = request.b.body,
                extraHeaders = request.b.extraHeaders,
            )
        )

        val lengthA = respA.body.utf8Length()
        val lengthB = respB.body.utf8Length()

        val headersA = groupHeaders(respA.headers)
        val headersB = groupHeaders(respB.headers)
        val names = LinkedHashMap<String, String>()
        headersA.forEach { (key, values) -> names[key] = values.name }
        headersB.forEach { (key, values) -> names.putIfAbsent(key, values.name) }
        val headerDiffs = names.mapNotNull { (key, displayName) ->
            val aValues = headersA[key]?.values?.toList() ?: emptyList()
            val bValues = headersB[key]?.values?.toList() ?: emptyList()
            if (aValues == bValues) {
                null
            } else {
                HeaderDiff(
                    name = displayName,
                    aValue = aValues.firstOrNull(),
                    bValue = bValues.firstOrNull(),
                    aValues = aValues,
                    bValues = bValues,
                )
            }
        }

        val bodyDiff = when {
            respA.body == respB.body -> null
            respA.body == null -> "A: empty, B: $lengthB bytes"
            respB.body == null -> "A: $lengthA bytes, B: empty"
            else -> {
                val linesA = respA.body.lines()
                val linesB = respB.body.lines()
                val onlyA = linesA.toSet() - linesB.toSet()
                val onlyB = linesB.toSet() - linesA.toSet()
                "A: $lengthA bytes (${linesA.size} lines), B: $lengthB bytes (${linesB.size} lines), " +
                    "${onlyA.size} lines only in A, ${onlyB.size} lines only in B"
            }
        }

        return DiffResponse(
            statusMatch = respA.statusCode == respB.statusCode,
            statusA = respA.statusCode,
            statusB = respB.statusCode,
            lengthA = lengthA,
            lengthB = lengthB,
            lengthDiff = abs(lengthA - lengthB),
            headerDiffs = headerDiffs,
            bodyDiff = bodyDiff,
        )
    }

    fun extractEndpoints(request: ExtractEndpointsRequest): ExtractEndpointsResponse {
        // Parse before the first network effect. URI.resolve below then supplies all RFC 3986
        // semantics (directory paths, root paths, network paths, explicit ports, and IPv6).
        val pageUri = requireHttpUri(request.url)
        val response = sessionService.send(AuthenticatedRequest(url = pageUri.toASCIIString()))
        val body = response.body
            ?: return ExtractEndpointsResponse(endpoints = emptyList(), total = 0)

        val bodies = mutableListOf(body)
        val failures = mutableListOf<BundleFetchFailure>()
        var discovered = 0
        var attempted = 0
        var fetched = 0

        if (looksLikeHtml(body)) {
            val scriptReferences = SCRIPT_SRC_PATTERN.findAll(body)
                .map { it.groupValues[1] }
                .toList()
            discovered = scriptReferences.size

            for (reference in scriptReferences.take(MAX_BUNDLE_FETCHES)) {
                attempted++
                val resolved = try {
                    // A URI fragment is client-side state and is never part of an HTTP request.
                    val resolvedReference = pageUri.resolve(reference).toASCIIString().substringBefore('#')
                    requireHttpUri(resolvedReference)
                } catch (failure: Exception) {
                    failures += BundleFetchFailure(
                        url = reference,
                        error = failure.safeMessage(),
                    )
                    continue
                }
                val resolvedUrl = resolved.toASCIIString()

                try {
                    val bundleResponse = if (sameOrigin(pageUri, resolved)) {
                        sessionService.send(AuthenticatedRequest(url = resolvedUrl))
                    } else {
                        // Cross-origin script URLs are discoveries, not authority to forward the
                        // configured session or to let their Set-Cookie response mutate our jar.
                        sessionService.sendUnauthenticated(AuthenticatedRequest(url = resolvedUrl))
                    }
                    fetched++
                    bundleResponse.body?.let(bodies::add)
                } catch (failure: Exception) {
                    failures += BundleFetchFailure(
                        url = resolvedUrl,
                        error = failure.safeMessage(),
                    )
                }
            }
        }

        val endpoints = linkedSetOf<String>()
        for (source in bodies) {
            for (pattern in API_PATTERNS) {
                pattern.findAll(source).forEach { match ->
                    val endpoint = match.groupValues[1]
                    if (endpoint.isNotBlank() &&
                        '\\' !in endpoint &&
                        STATIC_EXTENSIONS.none { extension ->
                            endpoint.substringBefore('?').substringBefore('#')
                                .endsWith(extension, ignoreCase = true)
                        } &&
                        !endpoint.startsWith("http://www.w3.org")
                    ) {
                        endpoints += endpoint
                    }
                }
            }
        }

        val sorted = endpoints.sorted()
        return ExtractEndpointsResponse(
            endpoints = sorted,
            total = sorted.size,
            bundlesDiscovered = discovered,
            bundlesAttempted = attempted,
            bundlesFetched = fetched,
            bundlesFailed = failures.size,
            failures = failures,
        )
    }

    private data class HeaderValues(val name: String, val values: MutableList<String>)

    private fun validateDiffTarget(target: DiffTarget, field: String) {
        requireHttpUri(target.url)
        require(HTTP_TOKEN.matches(target.method)) { "$field.method must be a valid HTTP token" }
        target.extraHeaders.orEmpty().forEach { (name, value) ->
            require(HTTP_TOKEN.matches(name)) { "$field.extraHeaders contains an invalid header name" }
            require(value.none(::isUnsafeHeaderValueCharacter)) {
                "$field.extraHeaders contains an unsafe header value"
            }
        }
    }

    private fun isUnsafeHeaderValueCharacter(character: Char): Boolean =
        character == '\u0000' || character == '\r' || character == '\n' ||
            character.code == 0x7f || (character < ' ' && character != '\t')

    private fun groupHeaders(headers: List<HttpHeader>): LinkedHashMap<String, HeaderValues> {
        val result = LinkedHashMap<String, HeaderValues>()
        headers.forEach { header ->
            val key = header.name.lowercase(Locale.ROOT)
            result.getOrPut(key) { HeaderValues(header.name, mutableListOf()) }.values += header.value
        }
        return result
    }

    private fun String?.utf8Length(): Int = this?.toByteArray(StandardCharsets.UTF_8)?.size ?: 0

    private fun looksLikeHtml(body: String): Boolean =
        body.trimStart().startsWith("<!", ignoreCase = true) ||
            SCRIPT_SRC_PATTERN.containsMatchIn(body)

    private fun requireHttpUri(value: String): URI {
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            throw IllegalArgumentException("Invalid HTTP URL: $value")
        }
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        require(uri.isAbsolute && (scheme == "http" || scheme == "https") && uri.host != null) {
            "Invalid HTTP URL: $value"
        }
        require(uri.port == -1 || uri.port in 1..65535) { "Invalid HTTP URL port: $value" }
        require(uri.rawUserInfo == null) { "HTTP URL must not contain user information" }
        require(uri.rawFragment == null) { "HTTP URL must not contain a fragment" }
        return uri
    }

    private fun sameOrigin(left: URI, right: URI): Boolean =
        left.scheme.equals(right.scheme, ignoreCase = true) &&
            normalizedHost(left) == normalizedHost(right) &&
            effectivePort(left) == effectivePort(right)

    private fun normalizedHost(uri: URI): String {
        val host = requireNotNull(uri.host).removePrefix("[").removeSuffix("]")
        if (':' !in host) {
            val ascii = try {
                IDN.toASCII(host.trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
            } catch (failure: Exception) {
                throw IllegalArgumentException("Invalid HTTP host", failure)
            }
            require(ascii.isNotEmpty()) { "Invalid HTTP host" }
            return ascii.lowercase(Locale.ROOT)
        }
        require('%' !in host) { "Invalid scoped IPv6 URL" }
        val address = try {
            InetAddress.getByName(host)
        } catch (failure: Exception) {
            throw IllegalArgumentException("Invalid IPv6 URL", failure)
        }
        require(address is Inet6Address) { "Invalid IPv6 URL" }
        return address.hostAddress.lowercase(Locale.ROOT)
    }

    private fun effectivePort(uri: URI): Int = when {
        uri.port >= 0 -> uri.port
        uri.scheme.equals("http", ignoreCase = true) -> 80
        uri.scheme.equals("https", ignoreCase = true) -> 443
        else -> -1
    }

    private fun Throwable.safeMessage(): String =
        message?.takeIf { it.isNotBlank() } ?: this::class.simpleName ?: "bundle fetch failed"

    private companion object {
        const val MAX_BUNDLE_FETCHES = 10

        val HTTP_TOKEN = Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

        val SCRIPT_SRC_PATTERN =
            Regex("""<script\b[^>]*\bsrc\s*=\s*["']([^"']+\.js(?:[?#][^"']*)?)["'][^>]*>""", RegexOption.IGNORE_CASE)

        val API_PATTERNS = listOf(
            Regex("""["'`](/api/[^"'`\s?#\)]{2,100})"""),
            Regex("""["'`](/v\d+/[^"'`\s?#\)]{2,100})"""),
            Regex("""fetch\(["'`]([^"'`]+)["'`]\)"""),
            Regex("""axios\.[a-z]+\(["'`]([^"'`]+)["'`]\)"""),
            Regex("""(?:url|path|endpoint|route)\s*[:=]\s*["'`]([^"'`]+)["'`]"""),
        )

        val STATIC_EXTENSIONS = setOf(
            ".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2",
            ".jpg", ".gif", ".map", ".ttf", ".eot",
        )
    }
}
