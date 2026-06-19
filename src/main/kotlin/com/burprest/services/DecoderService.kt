package com.burprest.services

import com.burprest.models.*
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Base64

class DecoderService {

    fun encode(request: EncodeRequest): EncodeResponse {
        val result = when (request.encoding.lowercase()) {
            "base64" -> Base64.getEncoder().encodeToString(request.data.toByteArray())
            "url" -> URLEncoder.encode(request.data, Charsets.UTF_8)
            "hex" -> request.data.toByteArray().joinToString("") { "%02x".format(it) }
            "html" -> request.data
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
            else -> throw IllegalArgumentException("Unsupported encoding: ${request.encoding}")
        }
        return EncodeResponse(result = result, encoding = request.encoding.lowercase())
    }

    fun decode(request: DecodeRequest): DecodeResponse {
        val encoding = request.encoding ?: detectEncoding(request.data)
        val result = when (encoding.lowercase()) {
            "base64" -> decodeBase64Flexible(request.data)
            "url" -> try {
                URLDecoder.decode(request.data, Charsets.UTF_8)
            } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("invalid URL-encoded input")
            }
            "hex" -> {
                require(request.data.length % 2 == 0) { "Hex input must have an even number of characters" }
                val bytes = request.data.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                decodeUtf8OrThrow(bytes, "hex")
            }
            "html" -> request.data
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#x27;", "'")
            // "plain" = auto-detect found no encoding: return the input unchanged rather than
            // leaking the internal sentinel as "Unsupported encoding: plain".
            "plain" -> request.data
            else -> throw IllegalArgumentException("Unsupported encoding: $encoding")
        }
        return DecodeResponse(result = result, encoding = encoding.lowercase())
    }

    fun hash(request: HashRequest): HashResponse {
        val digest = try {
            MessageDigest.getInstance(normalizeAlgorithm(request.algorithm))
        } catch (_: java.security.NoSuchAlgorithmException) {
            // Map the JVM exception to a clean client error instead of leaking it via the
            // catch-all handler (md5/sha1/sha256/sha-384/sha-512 are the supported algorithms).
            throw IllegalArgumentException("Unsupported hash algorithm: ${request.algorithm}")
        }
        val hash = digest.digest(request.data.toByteArray())
        return HashResponse(
            result = hash.joinToString("") { "%02x".format(it) },
            algorithm = request.algorithm,
        )
    }

    fun smartDecode(data: String): SmartDecodeResponse {
        val steps = mutableListOf<DecodeStep>()
        var current = data

        for (i in 0 until 10) {
            val encoding = detectEncoding(current)
            if (encoding == "plain") break

            // [15] Wrap each decode step: if decoding throws (binary / non-UTF-8 content)
            // or makes no progress, stop cleanly and return whatever we have so far.
            val decoded = try {
                decode(DecodeRequest(data = current, encoding = encoding))
            } catch (_: IllegalArgumentException) {
                break
            }
            if (decoded.result == current) break

            steps.add(DecodeStep(encoding = encoding, result = decoded.result))
            current = decoded.result
        }

        // [05] Form-urlencoded '+'-as-space layer: if the remaining value contains '+' but no
        // '%XX' percent-encoded sequences, attempt URLDecoder.decode which maps '+' → space.
        // If the decoded result actually differs from the input (at least one '+' was present
        // and substituted), emit a final "url" peel. This is last-resort: it only runs after
        // detectEncoding already returned "plain", so it never competes with the base64/hex/html
        // branches above. It also never fires when '%XX' sequences are present (those are caught
        // by the url branch in detectEncoding and handled in the main loop instead).
        if (current.contains('+') && !current.contains("%[0-9A-Fa-f]{2}".toRegex())) {
            val formDecoded = try {
                URLDecoder.decode(current, Charsets.UTF_8)
            } catch (_: IllegalArgumentException) {
                null
            }
            if (formDecoded != null && formDecoded != current) {
                steps.add(DecodeStep(encoding = "url", result = formDecoded))
                current = formDecoded
            }
        }

        return SmartDecodeResponse(finalResult = current, steps = steps)
    }

    private fun detectEncoding(data: String): String {
        // 1. base64url JSON, i.e. a JWT segment (starts with eyJ = base64url of '{"').
        //    Decoded flexibly below. Low false-positive: plain words don't start with eyJ +
        //    a base64url-only body.
        if (data.startsWith("eyJ") && data.matches(Regex("^[A-Za-z0-9_-]+=*$"))) return "base64"

        // 2. [14][04][05] Hex branch is TERMINAL: an all-hex even-length string is decided here
        //    and never falls through to base64. Without this, a non-UTF-8 hex string like "ff"
        //    would escape the hex guard and be re-interpreted by the base64 branch as garbage
        //    (e.g. "ff" base64-decodes to "}" — a silent mis-classification).
        //    Decision:
        //      - all-hex + even-length + valid UTF-8 decoded bytes → "hex"
        //      - all-hex + even-length + non-UTF-8 decoded bytes  → "plain" (ambiguous binary;
        //        do NOT let base64 reinterpret it)
        //    Explicit decode(encoding="hex") still calls decodeUtf8OrThrow — honest error there.
        if (data.matches(Regex("^[0-9a-fA-F]+$")) && data.length % 2 == 0 && data.length >= 2) {
            return if (isHexDecodableAsUtf8(data)) "hex" else "plain"
        }

        // 3. [13] base64url tokens containing '-' or '_' that are not JWT segments.
        //    Gate: flexible-base64 decode must yield valid UTF-8 text; this prevents classifying
        //    plain hyphenated words (e.g. "foo-bar-baz") as base64.
        if (data.matches(Regex("^[A-Za-z0-9_-]+=*$")) &&
            (data.contains('-') || data.contains('_')) &&
            data.length >= 4 &&
            isBase64UrlDecodableAsUtf8(data)
        ) return "base64"

        // 4. Standard base64 (may contain '+' and '/').
        //    [04] Drop strict length%4==0: decodeBase64Flexible repads internally, so unpadded
        //    standard base64 (e.g. "dGVzdA", length%4==2) was silently classified "plain".
        //    Gate on valid-UTF-8 decode instead (same guard used for the url-safe branch above):
        //    this also fixes the latent inverse where a short all-alpha word like "test" would
        //    previously pass the modulo check, decode to non-UTF-8 bytes, and throw.
        if (data.matches(Regex("^[A-Za-z0-9+/]+=*$")) && data.length >= 2 &&
            isBase64UrlDecodableAsUtf8(data)
        ) return "base64"

        // 5. URL-encoded (contains at least one %XX sequence).
        if (data.contains("%[0-9A-Fa-f]{2}".toRegex())) return "url"

        // 6. HTML entities.
        if (data.contains("&amp;") || data.contains("&lt;") || data.contains("&gt;") ||
            data.contains("&quot;") || data.contains("&#x27;")) return "html"

        return "plain"
    }

    private fun normalizeAlgorithm(algo: String): String = when (algo.lowercase()) {
        "md5" -> "MD5"
        "sha1", "sha-1" -> "SHA-1"
        "sha256", "sha-256" -> "SHA-256"
        "sha384", "sha-384" -> "SHA-384"
        "sha512", "sha-512" -> "SHA-512"
        else -> algo
    }

    private fun decodeBase64Flexible(data: String): String {
        // Accept standard AND URL-safe base64 (JWTs), with or without '=' padding.
        val normalized = data.replace('-', '+').replace('_', '/')
        val padded = normalized.padEnd((normalized.length + 3) / 4 * 4, '=')
        val bytes = try {
            Base64.getDecoder().decode(padded)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 input")
        }
        // [16] Reject non-UTF-8 decoded bytes rather than silently substituting U+FFFD.
        return decodeUtf8OrThrow(bytes, "base64")
    }

    /**
     * Decodes [bytes] as UTF-8. Throws [IllegalArgumentException] if the bytes are not valid
     * UTF-8, so callers never receive silently-corrupted text with U+FFFD replacement chars.
     */
    private fun decodeUtf8OrThrow(bytes: ByteArray, encodingLabel: String): String {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            throw IllegalArgumentException(
                "decoded bytes are not valid UTF-8 (binary data); use a hex/raw view to inspect"
            )
        }
    }

    /**
     * Returns true only if [data] (treated as a hex string) decodes without error AND the
     * resulting bytes are valid UTF-8. Used as a guard in detectEncoding (auto-detect only)
     * so that binary hex strings like "deadbeef" fall through to "plain" rather than being
     * classified as "hex" and then throwing during decode.
     *
     * Precondition: caller has already verified data matches `^[0-9a-fA-F]+$` and even length.
     */
    private fun isHexDecodableAsUtf8(data: String): Boolean {
        val bytes = try {
            data.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (_: NumberFormatException) {
            return false
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(bytes))
            true
        } catch (_: java.nio.charset.CharacterCodingException) {
            false
        }
    }

    /**
     * Returns true only if [data] (treated as URL-safe base64) decodes without error AND the
     * resulting bytes are valid UTF-8. Used as a guard in detectEncoding to avoid classifying
     * plain hyphenated or underscored tokens as base64.
     */
    private fun isBase64UrlDecodableAsUtf8(data: String): Boolean {
        val normalized = data.replace('-', '+').replace('_', '/')
        val padded = normalized.padEnd((normalized.length + 3) / 4 * 4, '=')
        val bytes = try {
            Base64.getDecoder().decode(padded)
        } catch (_: IllegalArgumentException) {
            return false
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(bytes))
            true
        } catch (_: java.nio.charset.CharacterCodingException) {
            false
        }
    }
}
