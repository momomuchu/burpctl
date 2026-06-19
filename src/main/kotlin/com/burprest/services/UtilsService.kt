package com.burprest.services

import com.burprest.models.*

class UtilsService(private val sessionService: SessionService) {

    fun diff(request: DiffRequest): DiffResponse {
        val respA = sessionService.send(AuthenticatedRequest(
            method = request.a.method, url = request.a.url,
            body = request.a.body, extraHeaders = request.a.extraHeaders,
        ))
        val respB = sessionService.send(AuthenticatedRequest(
            method = request.b.method, url = request.b.url,
            body = request.b.body, extraHeaders = request.b.extraHeaders,
        ))

        val lengthA = respA.body?.length ?: 0
        val lengthB = respB.body?.length ?: 0

        // Header diffs
        val allHeaderNames = (respA.headers.map { it.name } + respB.headers.map { it.name }).distinct()
        val headerDiffs = allHeaderNames.mapNotNull { name ->
            val aVal = respA.headers.find { it.name.equals(name, ignoreCase = true) }?.value
            val bVal = respB.headers.find { it.name.equals(name, ignoreCase = true) }?.value
            if (aVal != bVal) HeaderDiff(name, aVal, bVal) else null
        }

        // Body diff
        val bodyDiff = when {
            respA.body == respB.body -> null
            respA.body == null -> "A: empty, B: $lengthB chars"
            respB.body == null -> "A: $lengthA chars, B: empty"
            else -> {
                val linesA = respA.body.lines()
                val linesB = respB.body.lines()
                val setA = linesA.toSet()
                val setB = linesB.toSet()
                val onlyA = setA - setB
                val onlyB = setB - setA
                "A: $lengthA chars (${linesA.size} lines), B: $lengthB chars (${linesB.size} lines), " +
                    "${onlyA.size} lines only in A, ${onlyB.size} lines only in B"
            }
        }

        return DiffResponse(
            statusMatch = respA.statusCode == respB.statusCode,
            statusA = respA.statusCode,
            statusB = respB.statusCode,
            lengthA = lengthA,
            lengthB = lengthB,
            lengthDiff = kotlin.math.abs(lengthA - lengthB),
            headerDiffs = headerDiffs,
            bodyDiff = bodyDiff,
        )
    }

    fun extractEndpoints(request: ExtractEndpointsRequest): ExtractEndpointsResponse {
        val resp = sessionService.send(AuthenticatedRequest(url = request.url))
        val body = resp.body ?: return ExtractEndpointsResponse(endpoints = emptyList(), total = 0)

        val allBodies = mutableListOf(body)

        // If HTML page, find and fetch JS bundles
        if (body.trimStart().startsWith("<!") || body.contains("<script")) {
            val scriptPattern = Regex("""<script[^>]+src=["']([^"']+\.js[^"']*)["']""")
            val baseUrl = request.url.removeSuffix("/")
            // Resolve + validate the host once, before the loop, so a malformed URL surfaces as a
            // clean 400 (IllegalArgumentException) instead of a URISyntaxException escaping mid-loop.
            val baseHost = try {
                java.net.URI(baseUrl).host
            } catch (_: Exception) {
                throw IllegalArgumentException("Invalid URL: ${request.url}")
            }
            val jsUrls = scriptPattern.findAll(body).map { it.groupValues[1] }.toList()
            for (jsUrl in jsUrls.take(10)) {
                val fullUrl = if (jsUrl.startsWith("http")) jsUrl
                    else if (jsUrl.startsWith("/")) "${baseUrl.substringBefore("://")}//$baseHost$jsUrl"
                    else "$baseUrl/$jsUrl"
                try {
                    val jsResp = sessionService.send(AuthenticatedRequest(url = fullUrl))
                    jsResp.body?.let { allBodies.add(it) }
                } catch (_: Exception) {}
            }
        }

        val apiPatterns = listOf(
            Regex("""["'`](/api/[^"'`\s?#\)]{2,100})"""),
            Regex("""["'`](/v\d+/[^"'`\s?#\)]{2,100})"""),
            Regex("""fetch\(["'`]([^"'`]+)["'`]\)"""),
            Regex("""axios\.[a-z]+\(["'`]([^"'`]+)["'`]\)"""),
            Regex("""(?:url|path|endpoint|route)\s*[:=]\s*["'`]([^"'`]+)["'`]"""),
        )

        val staticExts = setOf(".js", ".css", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg", ".gif", ".map", ".ttf", ".eot")
        val endpoints = mutableSetOf<String>()

        for (src in allBodies) {
            for (pattern in apiPatterns) {
                pattern.findAll(src).forEach { match ->
                    val ep = match.groupValues[1]
                    if (ep.isNotBlank() && !ep.contains("\\") &&
                        staticExts.none { ep.endsWith(it) } &&
                        !ep.startsWith("http://www.w3.org")) {
                        endpoints.add(ep)
                    }
                }
            }
        }

        val sorted = endpoints.sorted()
        return ExtractEndpointsResponse(endpoints = sorted, total = sorted.size)
    }
}
