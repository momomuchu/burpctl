package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.sitemap.SiteMapFilter
import com.burprest.models.*
import com.burprest.server.InvalidParamException
import com.burprest.server.UnsupportedException
import java.net.IDN
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.util.Locale

class TargetService(private val api: MontoyaApi) {

    fun getSitemap(urlPrefix: String? = null): SitemapResponse {
        val validatedPrefix = urlPrefix?.let(::validateHttpUrl)
        val entries = if (validatedPrefix != null) {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(validatedPrefix))
        } else {
            api.siteMap().requestResponses()
        }

        val projected = entries.mapNotNull { entry ->
            try {
                SitemapEntry(
                    url = entry.request().url(),
                    method = entry.request().method(),
                    statusCode = entry.response()?.statusCode()?.toInt(),
                    mimeType = entry.response()?.statedMimeType()?.name,
                )
            } catch (_: MalformedRequestException) {
                // One corrupt stored request must not make every unrelated sitemap row unreadable.
                null
            }
        }
        return SitemapResponse(
            entries = projected,
            total = projected.size,
        )
    }

    /** Montoya can check scope but cannot enumerate the rules that produced that decision. */
    fun getScope(): Nothing = throw UnsupportedException(
        "Montoya 2025.3 cannot list project scope rules",
    )

    /** A replacement cannot be truthful without first enumerating/removing every existing rule. */
    fun setScope(): Nothing = throw UnsupportedException(
        "Montoya 2025.3 cannot replace all project scope rules",
    )

    /** Source-compatible overload; the request is intentionally not inspected for an unsupported operation. */
    fun setScope(@Suppress("UNUSED_PARAMETER") request: SetScopeRequest): Nothing = setScope()

    fun addToScope(request: AddScopeRequest): ScopeCheckResponse {
        val url = validateHttpUrl(request.url)
        val scope = api.scope()
        scope.includeInScope(url)
        return ScopeCheckResponse(url = url, inScope = scope.isInScope(url))
    }

    fun removeFromScope(request: AddScopeRequest): ScopeCheckResponse {
        val url = validateHttpUrl(request.url)
        val scope = api.scope()
        scope.excludeFromScope(url)
        return ScopeCheckResponse(url = url, inScope = scope.isInScope(url))
    }

    fun isInScope(url: String): ScopeCheckResponse {
        val validatedUrl = validateHttpUrl(url)
        return ScopeCheckResponse(url = validatedUrl, inScope = api.scope().isInScope(validatedUrl))
    }

    private fun validateHttpUrl(value: String): String {
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
