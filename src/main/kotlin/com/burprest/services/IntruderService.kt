package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.models.AttackOptions
import com.burprest.models.AttackResultEntry
import com.burprest.models.AttackResultsResponse
import com.burprest.models.AttackStatusResponse
import com.burprest.models.CreateAttackRequest
import com.burprest.models.CreateAttackResponse
import com.burprest.models.HttpHeader
import com.burprest.models.HttpRequestData
import com.burprest.models.HttpResponseData
import com.burprest.models.PayloadPosition
import com.burprest.models.QuickFuzzBaseline
import com.burprest.models.QuickFuzzRequest
import com.burprest.models.QuickFuzzResponse
import com.burprest.models.SendRequest
import com.burprest.models.SendResponse
import com.burprest.server.NoResponseException
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.math.abs

/**
 * A bounded server-side fuzz runner.
 *
 * This endpoint intentionally implements only sniper attacks. The Python `bp fuzz` path owns the
 * four-mode matrix expansion; accepting those mode names here would otherwise execute a different
 * attack from the one the caller requested.
 */
class IntruderService(private val api: MontoyaApi, private val repeaterService: RepeaterService) {

    private enum class AttackStatus(val wireName: String) {
        CREATED("created"),
        RUNNING("running"),
        PAUSED("paused"),
        COMPLETED("completed"),
        STOPPED("stopped"),
        ERROR("error"),
    }

    private data class PreparedShot(
        val positionName: String,
        val payload: String,
        val request: HttpRequestData,
    )

    private class AttackState(
        val id: String,
        val shots: List<PreparedShot>,
        val throttleMs: Long,
    ) {
        val monitor = Object()
        var status = AttackStatus.CREATED
        var progress = 0
        var requestCount = 0
        var errorCount = 0
        var error: String? = null
        var errorCode: String? = null
        val results = ArrayList<AttackResultEntry>()
        var worker: Thread? = null
    }

    private data class ResolvedRawRequest(
        val raw: ByteArray,
        val baseUrl: String,
    )

    private data class ByteSubstitution(
        val start: Int,
        val end: Int,
        val payload: ByteArray,
    )

    private val attacks = ConcurrentHashMap<String, AttackState>()

    fun createAttack(request: CreateAttackRequest): CreateAttackResponse {
        val snapshot = snapshot(request)
        validateOptions(snapshot.options)
        require(snapshot.attackType == SUPPORTED_ATTACK_TYPE) {
            "server-side Intruder supports only sniper; use bp fuzz for battering-ram, pitchfork, or cluster-bomb"
        }
        requireExactlyOneSource(snapshot.request, snapshot.requestId)
        require(snapshot.positions.isNotEmpty()) { "positions must not be empty" }
        require(snapshot.payloads.isNotEmpty()) { "payload bindings must not be empty" }

        val resolved = resolveRawRequest(snapshot.request, snapshot.requestId)
        validatePositionsAndBindings(snapshot.positions, snapshot.payloads, resolved.raw)
        val baseProjection = parseRawRequest(resolved.raw, resolved.baseUrl)
        val shotCount = snapshot.positions.fold(0L) { count, position ->
            count + snapshot.payloads.getValue(position.name).size
        }
        require(shotCount in 1..MAX_SHOTS.toLong()) {
            "attack must contain between 1 and 10,000 shots"
        }

        // Materialise and parse every request before publishing the attack. This is deliberately
        // bounded by MAX_SHOTS and guarantees that malformed byte substitutions cause zero sends.
        val shots = ArrayList<PreparedShot>(shotCount.toInt())
        snapshot.positions.forEach { position ->
            snapshot.payloads.getValue(position.name).forEach { payload ->
                val payloadBytes = encodeUtf8(payload, "payload for '${position.name}'")
                val modified = applySubstitutions(
                    resolved.raw,
                    listOf(ByteSubstitution(position.start, position.end, payloadBytes)),
                )
                val concrete = parseRawRequest(modified, resolved.baseUrl)
                val originalBytes = resolved.raw.copyOfRange(position.start, position.end)
                require(payloadBytes.contentEquals(originalBytes) || concrete != baseProjection) {
                    "position '${position.name}' changes raw bytes that the structured Repeater bridge cannot represent"
                }
                shots += PreparedShot(
                    positionName = position.name,
                    payload = payload,
                    request = concrete,
                )
            }
        }

        val immutableShots = Collections.unmodifiableList(shots)
        while (true) {
            val id = UUID.randomUUID().toString().take(8)
            val state = AttackState(id, immutableShots, snapshot.options.throttleMs)
            if (attacks.putIfAbsent(id, state) == null) {
                return CreateAttackResponse(attackId = id, status = AttackStatus.CREATED.wireName)
            }
        }
    }

    fun startAttack(id: String): AttackStatusResponse {
        val attack = getAttack(id)
        val worker = synchronized(attack.monitor) {
            requireState(attack, AttackStatus.CREATED, "start")
            check(attack.worker == null) { "attack worker already exists" }
            Thread({ runAttack(attack) }, "intruder-attack-$id").apply {
                isDaemon = true
                attack.worker = this
                attack.status = AttackStatus.RUNNING
            }
        }

        try {
            worker.start()
        } catch (_: Throwable) {
            synchronized(attack.monitor) {
                attack.status = AttackStatus.ERROR
                attack.errorCount++
                attack.error = ATTACK_FAILED_MESSAGE
                attack.errorCode = ATTACK_FAILED_CODE
                attack.worker = null
                attack.monitor.notifyAll()
            }
        }
        return attackStatus(id)
    }

    private fun runAttack(attack: AttackState) {
        try {
            executeAttack(attack)
        } catch (_: InterruptedException) {
            synchronized(attack.monitor) {
                if (attack.status != AttackStatus.STOPPED) {
                    markAttackError(attack)
                }
            }
        } catch (_: Throwable) {
            synchronized(attack.monitor) {
                markAttackError(attack)
            }
        } finally {
            synchronized(attack.monitor) {
                attack.worker = null
                attack.monitor.notifyAll()
            }
        }
    }

    @Throws(InterruptedException::class)
    private fun executeAttack(attack: AttackState) {
        for ((index, shot) in attack.shots.withIndex()) {
            if (!awaitRunnable(attack, if (index == 0) 0 else attack.throttleMs)) return

            val entry = sendShot(attack, index, shot)
            synchronized(attack.monitor) {
                attack.results += entry
                if (entry.errorCode != null) attack.errorCount++
                attack.progress = (((index + 1).toLong() * 100L) / attack.shots.size).toInt()
            }
        }

        // A pause requested while the final send was in flight must remain observable. Completion is
        // a transition from running, never an implicit paused -> completed edge.
        if (!awaitRunnable(attack, 0)) return
        synchronized(attack.monitor) {
            if (attack.status == AttackStatus.RUNNING) {
                attack.status = AttackStatus.COMPLETED
                attack.progress = 100
                attack.monitor.notifyAll()
            }
        }
    }

    private fun sendShot(attack: AttackState, index: Int, shot: PreparedShot): AttackResultEntry {
        synchronized(attack.monitor) {
            attack.requestCount++
        }

        return try {
            val sent = repeaterService.send(SendRequest(request = shot.request))
            val response = responseOrNull(sent)
            if (response == null) {
                failedEntry(index, shot, NO_RESPONSE_CODE, NO_RESPONSE_MESSAGE, sent.durationMs)
            } else {
                successfulEntry(index, shot, response, sent.durationMs)
            }
        } catch (_: NoResponseException) {
            failedEntry(index, shot, NO_RESPONSE_CODE, NO_RESPONSE_MESSAGE)
        } catch (_: Exception) {
            failedEntry(index, shot, SEND_FAILED_CODE, SEND_FAILED_MESSAGE)
        }
    }

    @Throws(InterruptedException::class)
    private fun awaitRunnable(attack: AttackState, throttleMs: Long): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(throttleMs)
        synchronized(attack.monitor) {
            while (true) {
                when (attack.status) {
                    AttackStatus.STOPPED -> return false
                    AttackStatus.PAUSED -> attack.monitor.wait()
                    AttackStatus.RUNNING -> {
                        val remaining = deadline - System.nanoTime()
                        if (remaining <= 0) return true
                        val millis = TimeUnit.NANOSECONDS.toMillis(remaining)
                        val nanos = (remaining - TimeUnit.MILLISECONDS.toNanos(millis)).toInt()
                        attack.monitor.wait(millis, nanos)
                    }
                    else -> return false
                }
            }
        }
    }

    fun attackStatus(id: String): AttackStatusResponse {
        val attack = getAttack(id)
        return synchronized(attack.monitor) {
            AttackStatusResponse(
                attackId = id,
                status = attack.status.wireName,
                progress = attack.progress,
                requestCount = attack.requestCount,
                errorCount = attack.errorCount,
                isComplete = attack.status in TERMINAL_STATES,
                error = attack.error,
                errorCode = attack.errorCode,
            )
        }
    }

    fun attackResults(id: String, offset: Int = 0, limit: Int = 0): AttackResultsResponse {
        require(offset >= 0) { "offset must be >= 0" }
        require(limit >= 0) { "limit must be >= 0" }
        val attack = getAttack(id)
        return synchronized(attack.monitor) {
            val total = attack.results.size
            val from = offset.coerceAtMost(total)
            val available = total - from
            val count = if (limit == 0) available else minOf(limit, available)
            val snapshot = ArrayList(attack.results.subList(from, from + count))
            AttackResultsResponse(
                attackId = id,
                results = Collections.unmodifiableList(snapshot),
                total = total,
            )
        }
    }

    fun pauseAttack(id: String): AttackStatusResponse {
        val attack = getAttack(id)
        synchronized(attack.monitor) {
            requireState(attack, AttackStatus.RUNNING, "pause")
            attack.status = AttackStatus.PAUSED
            attack.monitor.notifyAll()
        }
        return attackStatus(id)
    }

    fun resumeAttack(id: String): AttackStatusResponse {
        val attack = getAttack(id)
        synchronized(attack.monitor) {
            requireState(attack, AttackStatus.PAUSED, "resume")
            attack.status = AttackStatus.RUNNING
            attack.monitor.notifyAll()
        }
        return attackStatus(id)
    }

    fun stopAttack(id: String): AttackStatusResponse {
        val attack = getAttack(id)
        val worker = synchronized(attack.monitor) {
            require(attack.status == AttackStatus.RUNNING || attack.status == AttackStatus.PAUSED) {
                "cannot stop attack while it is ${attack.status.wireName}"
            }
            attack.status = AttackStatus.STOPPED
            attack.monitor.notifyAll()
            attack.worker
        }
        worker?.interrupt()
        return attackStatus(id)
    }

    fun quickFuzz(request: QuickFuzzRequest): QuickFuzzResponse {
        val startedAt = System.nanoTime()
        val snapshot = request.copy(
            request = request.request?.deepCopy(),
            payloads = request.payloads.toList(),
            options = request.options.copy(),
        )
        requireExactlyOneSource(snapshot.request, snapshot.requestId)
        require(snapshot.param.isNotBlank()) { "param must not be blank" }
        require(snapshot.payloads.isNotEmpty()) { "payloads list must not be empty" }
        require(snapshot.payloads.size <= MAX_SHOTS) { "quick fuzz must contain at most 10,000 payloads" }
        validateOptions(snapshot.options)

        val baseRequest = resolveStructuredRequest(snapshot.request, snapshot.requestId)
        validateStructuredRequest(baseRequest)
        val prepared = snapshot.payloads.map { payload ->
            substitutePayload(baseRequest, snapshot.param, payload).also(::validateStructuredRequest)
        }

        val baselineSend = try {
            repeaterService.send(SendRequest(request = baseRequest))
        } catch (_: NoResponseException) {
            return QuickFuzzResponse(
                results = emptyList(),
                total = 0,
                durationMs = elapsedMillis(startedAt),
                baseline = failedBaseline(NO_RESPONSE_CODE, NO_RESPONSE_MESSAGE),
            )
        } catch (_: Exception) {
            return QuickFuzzResponse(
                results = emptyList(),
                total = 0,
                durationMs = elapsedMillis(startedAt),
                baseline = failedBaseline(SEND_FAILED_CODE, SEND_FAILED_MESSAGE),
            )
        }
        val baselineResponse = responseOrNull(baselineSend)
            ?: return QuickFuzzResponse(
                results = emptyList(),
                total = 0,
                durationMs = elapsedMillis(startedAt),
                baseline = failedBaseline(NO_RESPONSE_CODE, NO_RESPONSE_MESSAGE),
            )
        val baseline = QuickFuzzBaseline(
            statusCode = baselineResponse.statusCode,
            length = bodyByteLength(baselineResponse.body),
            contentType = contentType(baselineResponse),
        )

        val results = ArrayList<AttackResultEntry>(prepared.size)
        prepared.forEachIndexed { index, concrete ->
            if (snapshot.options.throttleMs > 0) interruptibleSleep(snapshot.options.throttleMs)
            val result = try {
                val sent = repeaterService.send(SendRequest(request = concrete))
                val response = responseOrNull(sent)
                if (response == null) {
                    failedEntry(index, snapshot.payloads[index], NO_RESPONSE_CODE, NO_RESPONSE_MESSAGE, sent.durationMs)
                } else {
                    val length = bodyByteLength(response.body)
                    AttackResultEntry(
                        index = index,
                        payload = snapshot.payloads[index],
                        statusCode = response.statusCode,
                        length = length,
                        durationMs = sent.durationMs,
                        contentType = contentType(response),
                        bodyPreview = response.body?.take(BODY_PREVIEW_CHARS),
                        anomalous = isAnomalous(response, length, baseline),
                    )
                }
            } catch (_: NoResponseException) {
                failedEntry(index, snapshot.payloads[index], NO_RESPONSE_CODE, NO_RESPONSE_MESSAGE)
            } catch (_: Exception) {
                failedEntry(index, snapshot.payloads[index], SEND_FAILED_CODE, SEND_FAILED_MESSAGE)
            }
            results += result
        }

        return QuickFuzzResponse(
            results = Collections.unmodifiableList(results),
            total = results.size,
            durationMs = elapsedMillis(startedAt),
            baseline = baseline,
        )
    }

    private fun resolveRawRequest(request: HttpRequestData?, requestId: Int?): ResolvedRawRequest {
        if (request != null) {
            validateStructuredRequest(request)
            return ResolvedRawRequest(buildCanonicalRaw(request), request.url)
        }

        val historical = resolveHistoryRequest(requireNotNull(requestId))
        val raw = try {
            historical.toByteArray().bytesCopy()
        } catch (_: Exception) {
            throw IllegalArgumentException("requestId could not be read from proxy history")
        }
        require(raw.isNotEmpty()) { "requestId contains an empty request" }
        val baseUrl = try {
            historical.url()
        } catch (_: Exception) {
            throw IllegalArgumentException("requestId could not be read from proxy history")
        }
        return ResolvedRawRequest(raw, baseUrl)
    }

    private fun resolveStructuredRequest(request: HttpRequestData?, requestId: Int?): HttpRequestData {
        if (request != null) return request.deepCopy()
        val historical = resolveHistoryRequest(requireNotNull(requestId))
        return try {
            HttpRequestData(
                method = historical.method(),
                url = historical.url(),
                headers = historical.headers().map { HttpHeader(it.name(), it.value()) },
                body = if (historical.body().length() > 0) historical.bodyToString() else null,
            )
        } catch (_: Exception) {
            throw IllegalArgumentException("requestId could not be read from proxy history")
        }
    }

    private fun resolveHistoryRequest(requestId: Int): HttpRequest {
        require(requestId >= 0) { "requestId must be >= 0" }
        val history = try {
            api.proxy().history()
        } catch (_: Exception) {
            throw IllegalArgumentException("proxy history is unavailable")
        }
        require(requestId in history.indices) { "requestId was not found in proxy history" }
        return try {
            history[requestId].finalRequest()
        } catch (_: Exception) {
            throw IllegalArgumentException("requestId could not be read from proxy history")
        }
    }

    private fun validatePositionsAndBindings(
        positions: List<PayloadPosition>,
        payloads: Map<String, List<String>>,
        raw: ByteArray,
    ) {
        positions.forEach { position ->
            require(position.name.isNotBlank()) { "position names must not be blank" }
            require(position.start >= 0 && position.start < position.end && position.end <= raw.size) {
                "position '${position.name}' must be a non-empty byte range within the request"
            }
            require(isUtf8Boundary(raw, position.start) && isUtf8Boundary(raw, position.end)) {
                "position '${position.name}' must start and end on UTF-8 byte boundaries"
            }
        }

        val sorted = positions.sortedWith(compareBy<PayloadPosition> { it.start }.thenBy { it.end })
        sorted.zipWithNext().forEach { (left, right) ->
            require(left.end <= right.start) { "positions must be unique and non-overlapping" }
        }

        val positionNames = positions.map { it.name }.toSet()
        require(payloads.keys == positionNames) { "payload bindings must exactly match position names" }
        payloads.forEach { (name, values) ->
            require(name.isNotBlank()) { "payload binding names must not be blank" }
            require(values.isNotEmpty()) { "payload binding '$name' must not be empty" }
        }
    }

    private fun validateOptions(options: AttackOptions) {
        require(options.followRedirects) { "followRedirects=false is not supported by server-side Intruder" }
        require(options.maxRetries == 0) { "maxRetries is not supported by server-side Intruder" }
        require(options.throttleMs in 0..MAX_THROTTLE_MS) {
            "throttleMs must be between 0 and $MAX_THROTTLE_MS"
        }
    }

    private fun requireExactlyOneSource(request: HttpRequestData?, requestId: Int?) {
        require((request == null) xor (requestId == null)) {
            "exactly one of request or requestId is required"
        }
    }

    private fun validateStructuredRequest(request: HttpRequestData) {
        require(request.method.isNotBlank() && request.method.all(::isHttpTokenChar)) {
            "request method is invalid"
        }
        val uri = parseHttpUri(request.url)
        require(uri.rawFragment == null && uri.rawUserInfo == null) { "request URL is invalid" }
        require(!uri.rawAuthority.orEmpty().endsWith(':')) { "request URL port is invalid" }
        request.headers.forEach { header ->
            require(header.name.isNotBlank() && header.name.all(::isHttpTokenChar)) {
                "request header name is invalid"
            }
            require(header.value.none { it == '\r' || it == '\n' || it == ' ' }) {
                "request header value is invalid"
            }
            encodeUtf8(header.value, "request header value")
        }
        request.body?.let { encodeUtf8(it, "request body") }
    }

    private fun buildCanonicalRaw(request: HttpRequestData): ByteArray {
        val uri = parseHttpUri(request.url)
        val target = buildString {
            append(uri.rawPath?.ifEmpty { "/" } ?: "/")
            uri.rawQuery?.let { append('?').append(it) }
        }
        val headers = ArrayList<HttpHeader>(request.headers.size + 1)
        if (request.headers.none { it.name.equals("Host", ignoreCase = true) }) {
            headers += HttpHeader("Host", requireNotNull(uri.rawAuthority))
        }
        headers += request.headers
        val head = buildString {
            append(request.method).append(' ').append(target).append(" HTTP/1.1\r\n")
            headers.forEach { append(it.name).append(": ").append(it.value).append("\r\n") }
            append("\r\n")
        }
        return encodeUtf8(head, "request headers") + encodeUtf8(request.body.orEmpty(), "request body")
    }

    private fun applySubstitutions(base: ByteArray, substitutions: List<ByteSubstitution>): ByteArray {
        val baseSeparator = findHeaderSeparator(base)
            ?: throw IllegalArgumentException("request is missing the header terminator")
        val baseBodyStart = baseSeparator.first + baseSeparator.second
        val touchesBody = substitutions.any { it.start < base.size && it.end > baseBodyStart }
        var output = base.copyOf()
        substitutions.sortedByDescending { it.start }.forEach { substitution ->
            require(substitution.start >= 0 && substitution.start < substitution.end && substitution.end <= output.size) {
                "substitution byte range is invalid"
            }
            output = output.copyOfRange(0, substitution.start) +
                substitution.payload +
                output.copyOfRange(substitution.end, output.size)
        }
        return if (touchesBody) repairContentLength(output) else output
    }

    private fun repairContentLength(raw: ByteArray): ByteArray {
        val separator = findHeaderSeparator(raw)
            ?: throw IllegalArgumentException("substitution produced a malformed HTTP request")
        val (headerEnd, separatorLength) = separator
        val lineEnding = if (separatorLength == CRLF_SEPARATOR.size) "\r\n" else "\n"
        val head = decodeUtf8(raw.copyOfRange(0, headerEnd), "request headers")
        val lines = head.split(lineEnding)
        require(lines.isNotEmpty()) { "substitution produced a malformed HTTP request" }
        val withoutLengths = lines.drop(1).filterNot { line ->
            line.substringBefore(':').trim().equals("Content-Length", ignoreCase = true)
        }
        val body = raw.copyOfRange(headerEnd + separatorLength, raw.size)
        val repairedHead = buildString {
            append(lines.first()).append(lineEnding)
            withoutLengths.forEach { append(it).append(lineEnding) }
            append("Content-Length: ").append(body.size).append(lineEnding).append(lineEnding)
        }
        return encodeUtf8(repairedHead, "request headers") + body
    }

    private fun parseRawRequest(raw: ByteArray, baseUrl: String): HttpRequestData {
        val separator = findHeaderSeparator(raw)
        require(separator != null) { "substitution produced a malformed HTTP request" }
        val (headerEnd, separatorLength) = separator
        val head = decodeUtf8(raw.copyOfRange(0, headerEnd), "request headers")
        val lineSeparator = if (head.contains("\r\n")) "\r\n" else "\n"
        val lines = head.split(lineSeparator)
        require(lines.isNotEmpty()) { "substitution produced a malformed HTTP request" }

        val requestLine = lines.first()
        val firstSpace = requestLine.indexOf(' ')
        val lastSpace = requestLine.lastIndexOf(' ')
        require(firstSpace > 0 && lastSpace > firstSpace + 1 && lastSpace < requestLine.lastIndex) {
            "substitution produced a malformed request line"
        }
        val method = requestLine.substring(0, firstSpace)
        val target = requestLine.substring(firstSpace + 1, lastSpace)
        val version = requestLine.substring(lastSpace + 1)
        require(method.all(::isHttpTokenChar) && version.startsWith("HTTP/")) {
            "substitution produced a malformed request line"
        }

        val headers = lines.drop(1).map { line ->
            val colon = line.indexOf(':')
            require(colon > 0) { "substitution produced a malformed request header" }
            val name = line.substring(0, colon)
            val value = line.substring(colon + 1).trim(' ', '\t')
            require(name.all(::isHttpTokenChar) && value.none { it == '\r' || it == '\n' || it == ' ' }) {
                "substitution produced a malformed request header"
            }
            HttpHeader(name, value)
        }

        val base = parseHttpUri(baseUrl)
        val host = headers.firstOrNull { it.name.equals("Host", ignoreCase = true) }?.value
            ?: requireNotNull(base.rawAuthority)
        val url = when {
            target.startsWith("http://") || target.startsWith("https://") -> target
            target.startsWith('/') -> "${base.scheme}://$host$target"
            else -> throw IllegalArgumentException("substitution produced an unsupported request target")
        }
        parseHttpUri(url)
        val bodyStart = headerEnd + separatorLength
        val body = if (bodyStart < raw.size) {
            decodeUtf8(raw.copyOfRange(bodyStart, raw.size), "request body")
        } else {
            null
        }

        return HttpRequestData(method = method, url = url, headers = headers, body = body).also(::validateStructuredRequest)
    }

    private fun findHeaderSeparator(raw: ByteArray): Pair<Int, Int>? {
        val crlf = raw.indexOf(CRLF_SEPARATOR)
        if (crlf >= 0) return crlf to CRLF_SEPARATOR.size
        val lf = raw.indexOf(LF_SEPARATOR)
        if (lf >= 0) return lf to LF_SEPARATOR.size
        return null
    }

    private fun substitutePayload(baseRequest: HttpRequestData, param: String, payload: String): HttpRequestData {
        var url = baseRequest.url.replace("{$param}", payload)
        val queryParamRegex = Regex("([?&])${Regex.escape(param)}=([^&#]*)")
        url = queryParamRegex.replace(url) { match -> "${match.groupValues[1]}$param=$payload" }

        var body = baseRequest.body
        if (body != null) {
            body = body.replace("{$param}", payload)
            val bodyParamRegex = Regex("(^|&)${Regex.escape(param)}=([^&]*)")
            body = bodyParamRegex.replace(body) { match -> "${match.groupValues[1]}$param=$payload" }
            val jsonRegex = Regex("\"${Regex.escape(param)}\"\\s*:\\s*\"[^\"]*\"")
            body = jsonRegex.replace(body) { "\"$param\":\"$payload\"" }
        }

        val headers = baseRequest.headers.map { header ->
            if (header.name.equals(param, ignoreCase = true)) HttpHeader(header.name, payload) else header
        }
        return baseRequest.copy(url = url, body = body, headers = headers)
    }

    private fun successfulEntry(
        index: Int,
        shot: PreparedShot,
        response: HttpResponseData,
        durationMs: Long,
    ) = AttackResultEntry(
        index = index,
        payload = shot.payload,
        positionName = shot.positionName,
        statusCode = response.statusCode,
        length = bodyByteLength(response.body),
        durationMs = durationMs,
        contentType = contentType(response),
        bodyPreview = response.body?.take(BODY_PREVIEW_CHARS),
    )

    private fun failedEntry(
        index: Int,
        shot: PreparedShot,
        errorCode: String,
        error: String,
        durationMs: Long = 0,
    ) = failedEntry(index, shot.payload, errorCode, error, durationMs, shot.positionName)

    private fun failedEntry(
        index: Int,
        payload: String,
        errorCode: String,
        error: String,
        durationMs: Long = 0,
        positionName: String? = null,
    ) = AttackResultEntry(
        index = index,
        payload = payload,
        positionName = positionName,
        statusCode = 0,
        length = 0,
        durationMs = durationMs,
        error = error,
        errorCode = errorCode,
        anomalous = false,
    )

    private fun failedBaseline(errorCode: String, error: String) = QuickFuzzBaseline(
        statusCode = 0,
        length = 0,
        contentType = null,
        error = error,
        errorCode = errorCode,
    )

    private fun responseOrNull(response: SendResponse): HttpResponseData? =
        if (response.hasResponse) response.response else null

    private fun contentType(response: HttpResponseData): String? =
        response.headers.firstOrNull { it.name.equals("Content-Type", ignoreCase = true) }?.value

    private fun bodyByteLength(body: String?): Int = body?.toByteArray(UTF_8)?.size ?: 0

    private fun isAnomalous(response: HttpResponseData, length: Int, baseline: QuickFuzzBaseline): Boolean {
        val threshold = (baseline.length * ANOMALY_LENGTH_RATIO).toInt().coerceAtLeast(MIN_ANOMALY_BYTES)
        return response.statusCode != baseline.statusCode ||
            abs(length.toLong() - baseline.length.toLong()) > threshold ||
            contentType(response) != baseline.contentType
    }

    private fun snapshot(request: CreateAttackRequest): CreateAttackRequest = request.copy(
        request = request.request?.deepCopy(),
        positions = request.positions.map { it.copy() },
        payloads = request.payloads.mapValues { (_, values) -> values.toList() }.toMap(),
        options = request.options.copy(),
    )

    private fun HttpRequestData.deepCopy() = copy(
        headers = headers.map { it.copy() },
        body = body,
    )

    private fun parseHttpUri(value: String): URI {
        require(value.none { it.isISOControl() || it.isWhitespace() }) { "request URL is invalid" }
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            throw IllegalArgumentException("request URL is invalid")
        }
        require(uri.scheme == "http" || uri.scheme == "https") { "request URL must use http or https" }
        require(!uri.host.isNullOrBlank() && uri.rawAuthority != null) { "request URL must be absolute" }
        require(uri.port == -1 || uri.port in 1..65_535) { "request URL port is invalid" }
        return uri
    }

    private fun encodeUtf8(value: String, label: String): ByteArray = try {
        val buffer = UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
        val encoded = ByteArray(buffer.remaining())
        buffer.get(encoded)
        encoded
    } catch (_: Exception) {
        throw IllegalArgumentException("$label is not valid UTF-8")
    }

    private fun decodeUtf8(bytes: ByteArray, label: String): String = try {
        UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: Exception) {
        throw IllegalArgumentException("$label is not valid UTF-8")
    }

    private fun isUtf8Boundary(bytes: ByteArray, index: Int): Boolean =
        index == 0 || index == bytes.size || (bytes[index].toInt() and 0xC0) != 0x80

    private fun isHttpTokenChar(char: Char): Boolean =
        char.code in 0x21..0x7e && char !in HTTP_TOKEN_SEPARATORS

    private fun requireState(attack: AttackState, expected: AttackStatus, operation: String) {
        require(attack.status == expected) {
            "cannot $operation attack while it is ${attack.status.wireName}"
        }
    }

    private fun markAttackError(attack: AttackState) {
        if (attack.status !in TERMINAL_STATES) {
            attack.status = AttackStatus.ERROR
            attack.errorCount++
            attack.error = ATTACK_FAILED_MESSAGE
            attack.errorCode = ATTACK_FAILED_CODE
            attack.monitor.notifyAll()
        }
    }

    private fun getAttack(id: String): AttackState =
        attacks[id] ?: throw IllegalArgumentException("attack not found")

    private fun interruptibleSleep(milliseconds: Long) {
        try {
            Thread.sleep(milliseconds)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IllegalStateException("quick fuzz was interrupted")
        }
    }

    private fun elapsedMillis(startedAt: Long): Long =
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)

    private fun burp.api.montoya.core.ByteArray.bytesCopy(): ByteArray =
        ByteArray(length()) { index -> getByte(index) }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        if (needle.isEmpty()) return 0
        if (needle.size > size) return -1
        for (start in 0..size - needle.size) {
            if (needle.indices.all { this[start + it] == needle[it] }) return start
        }
        return -1
    }

    companion object {
        private const val SUPPORTED_ATTACK_TYPE = "sniper"
        private const val MAX_SHOTS = 10_000
        private const val MAX_THROTTLE_MS = 60_000L
        private const val BODY_PREVIEW_CHARS = 200
        private const val ANOMALY_LENGTH_RATIO = 0.2
        private const val MIN_ANOMALY_BYTES = 20
        private const val SEND_FAILED_CODE = "SEND_FAILED"
        private const val SEND_FAILED_MESSAGE = "request send failed"
        private const val NO_RESPONSE_CODE = "NO_RESPONSE"
        private const val NO_RESPONSE_MESSAGE = "request completed without a response"
        private const val ATTACK_FAILED_CODE = "ATTACK_FAILED"
        private const val ATTACK_FAILED_MESSAGE = "attack execution failed"
        private val TERMINAL_STATES = setOf(AttackStatus.COMPLETED, AttackStatus.STOPPED, AttackStatus.ERROR)
        private val CRLF_SEPARATOR = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
        private val LF_SEPARATOR = byteArrayOf('\n'.code.toByte(), '\n'.code.toByte())
        private val HTTP_TOKEN_SEPARATORS = setOf('(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}')
    }
}
