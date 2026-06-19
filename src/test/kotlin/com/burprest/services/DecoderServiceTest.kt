package com.burprest.services

import com.burprest.models.DecodeRequest
import com.burprest.models.EncodeRequest
import com.burprest.models.HashRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DecoderServiceTest {

    private val service = DecoderService()

    @Test
    fun `encode base64`() {
        val result = service.encode(EncodeRequest(data = "hello", encoding = "base64"))
        assertEquals("aGVsbG8=", result.result)
        assertEquals("base64", result.encoding)
    }

    @Test
    fun `decode base64`() {
        val result = service.decode(DecodeRequest(data = "aGVsbG8=", encoding = "base64"))
        assertEquals("hello", result.result)
    }

    @Test
    fun `encode url`() {
        val result = service.encode(EncodeRequest(data = "hello world&foo=bar", encoding = "url"))
        assertTrue(result.result.contains("%20") || result.result.contains("+"))
    }

    @Test
    fun `decode url`() {
        val result = service.decode(DecodeRequest(data = "hello%20world", encoding = "url"))
        assertEquals("hello world", result.result)
    }

    @Test
    fun `encode hex`() {
        val result = service.encode(EncodeRequest(data = "AB", encoding = "hex"))
        assertEquals("4142", result.result)
    }

    @Test
    fun `decode hex`() {
        val result = service.decode(DecodeRequest(data = "4142", encoding = "hex"))
        assertEquals("AB", result.result)
    }

    @Test
    fun `encode html`() {
        val result = service.encode(EncodeRequest(data = "<script>alert('xss')</script>", encoding = "html"))
        assertTrue(result.result.contains("&lt;"))
        assertTrue(result.result.contains("&gt;"))
    }

    @Test
    fun `hash md5`() {
        val result = service.hash(HashRequest(data = "hello", algorithm = "md5"))
        assertEquals("5d41402abc4b2a76b9719d911017c592", result.result)
    }

    @Test
    fun `hash sha256`() {
        val result = service.hash(HashRequest(data = "hello", algorithm = "sha256"))
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", result.result)
    }

    @Test
    fun `smart decode base64`() {
        val encoded = java.util.Base64.getEncoder().encodeToString("hello".toByteArray())
        val result = service.smartDecode(encoded)
        assertEquals("hello", result.result)
        assertTrue(result.steps.isNotEmpty())
    }

    @Test
    fun `smart decode plain text unchanged`() {
        val result = service.smartDecode("just plain text here nothing to decode")
        assertEquals("just plain text here nothing to decode", result.result)
        assertTrue(result.steps.isEmpty())
    }

    @Test
    fun `roundtrip base64`() {
        val original = "test data 123!@#"
        val encoded = service.encode(EncodeRequest(data = original, encoding = "base64"))
        val decoded = service.decode(DecodeRequest(data = encoded.result, encoding = "base64"))
        assertEquals(original, decoded.result)
    }

    @Test
    fun `roundtrip url`() {
        val original = "param=value&other=test space"
        val encoded = service.encode(EncodeRequest(data = original, encoding = "url"))
        val decoded = service.decode(DecodeRequest(data = encoded.result, encoding = "url"))
        assertEquals(original, decoded.result)
    }

    @Test
    fun `decode auto-detect of unclassifiable input returns it unchanged as plain`() {
        // Was: threw IllegalArgumentException("Unsupported encoding: plain") — a leaked sentinel.
        val result = service.decode(DecodeRequest(data = "not%%%valid", encoding = null))
        assertEquals("not%%%valid", result.result)
        assertEquals("plain", result.encoding)
    }

    @Test
    fun `hash with unknown algorithm throws IllegalArgumentException not NoSuchAlgorithmException`() {
        // Must surface as a clean client error, not a leaked java.security.NoSuchAlgorithmException.
        assertFailsWith<IllegalArgumentException> {
            service.hash(HashRequest(data = "hello", algorithm = "totally-bogus"))
        }
    }

    @Test
    fun `decode odd-length hex is rejected, not silently truncated`() {
        assertFailsWith<IllegalArgumentException> {
            service.decode(DecodeRequest(data = "abc", encoding = "hex"))
        }
    }

    @Test
    fun `decode base64 accepts url-safe chars and missing padding (JWT)`() {
        // "Pz8_" is the URL-safe base64 of "???" (standard would be "Pz8/"), and unpadded.
        assertEquals("???", service.decode(DecodeRequest(data = "Pz8_", encoding = "base64")).result)
    }

    @Test
    fun `auto-detect decodes a JWT segment starting with eyJ`() {
        val r = service.decode(DecodeRequest(data = "eyJzdWIiOiIxIn0", encoding = null))
        assertEquals("base64", r.encoding)
        assertTrue(r.result.contains("sub"))
    }

    // ── [14] RED: all-hex even-length string must auto-detect as hex, not base64 ────────────────

    @Test
    fun `14 -auto-detect of all-hex string that is valid UTF-8 decodes as hex not base64`() {
        // "4865" hex-decodes to bytes [0x48, 0x65] = "He" (valid UTF-8).
        // "4865" is also length%4==0 and all-hex, so it previously matched base64 first.
        // After fix: hex check precedes base64 check → decodes to "He".
        val r = service.decode(DecodeRequest(data = "4865", encoding = null))
        assertEquals("hex", r.encoding)
        assertEquals("He", r.result)
    }

    @Test
    fun `14 -auto-detect of deadbeef routes to hex and then throws for binary content not silent base64 garbage`() {
        // "deadbeef" previously matched base64 first (length%4==0, all base64 chars) and returned
        // garbled replacement-char text. After fix: hex fires first, then [16] rejects the
        // non-UTF-8 bytes with a clean IllegalArgumentException — no silent corruption.
        assertFailsWith<IllegalArgumentException> {
            service.decode(DecodeRequest(data = "deadbeef", encoding = null))
        }
    }

    // ── [16] RED: hex and base64 decode of non-UTF-8 bytes must throw, not silently corrupt ─────

    @Test
    fun `16 -decode hex of non-UTF-8 bytes throws IllegalArgumentException`() {
        // 0xDE 0xAD 0xBE 0xEF are not valid UTF-8 — must not return replacement chars.
        assertFailsWith<IllegalArgumentException> {
            service.decode(DecodeRequest(data = "deadbeef", encoding = "hex"))
        }
    }

    @Test
    fun `16 -decode hex of valid UTF-8 bytes still returns the text`() {
        // 0x41=A, 0x42=B — valid ASCII/UTF-8, must still work.
        val r = service.decode(DecodeRequest(data = "4142", encoding = "hex"))
        assertEquals("AB", r.result)
    }

    @Test
    fun `16 -decode base64 of non-UTF-8 bytes throws IllegalArgumentException`() {
        // Base64 of bytes [0xDE, 0xAD, 0xBE, 0xEF] = "3q2+7w==" — valid base64 but non-UTF-8.
        // Must throw rather than return replacement chars.
        assertFailsWith<IllegalArgumentException> {
            service.decode(DecodeRequest(data = "3q2+7w==", encoding = "base64"))
        }
    }

    @Test
    fun `16 -decode base64 of valid UTF-8 bytes still returns the text`() {
        // "aGVsbG8=" = base64 of "hello" — must still work.
        val r = service.decode(DecodeRequest(data = "aGVsbG8=", encoding = "base64"))
        assertEquals("hello", r.result)
    }

    // ── [13] RED: base64url tokens with - or _ that are not eyJ auto-detect as base64 ──────────

    @Test
    fun `13 -auto-detect of url-safe base64 token with underscore classifies as base64`() {
        // "Pz8_" = URL-safe base64 of "???" (underscore instead of slash), not starting eyJ.
        // Must auto-detect as base64 and decode correctly.
        val r = service.decode(DecodeRequest(data = "Pz8_", encoding = null))
        assertEquals("base64", r.encoding)
        assertEquals("???", r.result)
    }

    @Test
    fun `13 -hyphenated plain word stays plain (false-positive guard)`() {
        // "foo-bar-baz" matches the char set but its flexible-base64 decode is not valid UTF-8,
        // so it must not be classified as base64.
        val r = service.decode(DecodeRequest(data = "foo-bar-baz", encoding = null))
        assertEquals("plain", r.encoding)
    }

    // ── [15] RED: smartDecode stops gracefully rather than propagating binary-decode exception ──

    @Test
    fun `15 -smartDecode of base64-of-hex-string stops at the hex layer without throwing`() {
        // base64("deadbeef") = "ZGVhZGJlZWY=" — first peel decodes to the string "deadbeef".
        // "deadbeef" is then classified as hex; its bytes (0xDE 0xAD 0xBE 0xEF) are not UTF-8,
        // so the hex decode step would throw. smartDecode must catch that and stop cleanly,
        // returning "deadbeef" — no replacement chars, no exception propagated.
        val input = java.util.Base64.getEncoder().encodeToString("deadbeef".toByteArray())
        // sanity: input is "ZGVhZGJlZWY="
        val r = service.smartDecode(input)
        assertEquals("deadbeef", r.result)
        // exactly one step was peeled (base64 → "deadbeef"); the hex step was aborted
        assertEquals(1, r.steps.size)
        assertEquals("base64", r.steps[0].encoding)
    }
}
