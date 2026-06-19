package com.burprest.services

import com.burprest.models.*
import java.net.URLDecoder
import java.net.URLEncoder
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
        return EncodeResponse(result = result, encoding = request.encoding)
    }

    fun decode(request: DecodeRequest): DecodeResponse {
        val encoding = request.encoding ?: detectEncoding(request.data)
        val result = when (encoding.lowercase()) {
            "base64" -> String(Base64.getDecoder().decode(request.data))
            "url" -> URLDecoder.decode(request.data, Charsets.UTF_8)
            "hex" -> {
                require(request.data.length % 2 == 0) { "Hex input must have an even number of characters" }
                request.data.chunked(2).map { it.toInt(16).toByte() }.toByteArray().let { String(it) }
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
        return DecodeResponse(result = result, encoding = encoding)
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

            val decoded = decode(DecodeRequest(data = current, encoding = encoding))
            if (decoded.result == current) break

            steps.add(DecodeStep(encoding = encoding, result = decoded.result))
            current = decoded.result
        }

        return SmartDecodeResponse(result = current, steps = steps)
    }

    private fun detectEncoding(data: String): String = when {
        data.matches(Regex("^[A-Za-z0-9+/]+=*$")) && data.length % 4 == 0 && data.length >= 4 -> "base64"
        data.contains("%[0-9A-Fa-f]{2}".toRegex()) -> "url"
        data.matches(Regex("^[0-9a-fA-F]+$")) && data.length % 2 == 0 && data.length >= 4 -> "hex"
        data.contains("&amp;") || data.contains("&lt;") || data.contains("&gt;") -> "html"
        else -> "plain"
    }

    private fun normalizeAlgorithm(algo: String): String = when (algo.lowercase()) {
        "md5" -> "MD5"
        "sha1", "sha-1" -> "SHA-1"
        "sha256", "sha-256" -> "SHA-256"
        "sha384", "sha-384" -> "SHA-384"
        "sha512", "sha-512" -> "SHA-512"
        else -> algo
    }
}
