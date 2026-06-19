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
        assertEquals("hello", result.finalResult)
        assertTrue(result.steps.isNotEmpty())
    }

    @Test
    fun `smart decode plain text unchanged`() {
        val result = service.smartDecode("just plain text here nothing to decode")
        assertEquals("just plain text here nothing to decode", result.finalResult)
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
    fun `07 -auto-detect of deadbeef falls to plain and returns input unchanged without throwing`() {
        // [07] deadbeef is all-hex and even-length so the hex branch fires first, but its bytes
        // 0xDE 0xAD 0xBE 0xEF are not valid UTF-8. The new isHexDecodableAsUtf8 guard returns
        // false, so detectEncoding falls through to "plain". decode() returns the input unchanged —
        // no IllegalArgumentException, no HTTP 400. Auto-detect is a guess; graceful degradation
        // is the contract.
        val r = service.decode(DecodeRequest(data = "deadbeef", encoding = null))
        assertEquals("plain", r.encoding)
        assertEquals("deadbeef", r.result)
    }

    @Test
    fun `07 -explicit hex decode of deadbeef still throws for binary bytes`() {
        // Explicit --enc hex is an honest request: the caller said "this is hex, decode it".
        // decodeUtf8OrThrow must still reject non-UTF-8 bytes with IllegalArgumentException.
        // This is unchanged from before — only auto-detect (encoding=null) degrades gracefully.
        assertFailsWith<IllegalArgumentException> {
            service.decode(DecodeRequest(data = "deadbeef", encoding = "hex"))
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

    // ── [04] RED: unpadded standard base64 must auto-detect as base64, not plain ─────────────────

    @Test
    fun `04 -auto-detect of unpadded standard base64 dGVzdA classifies as base64 and decodes to test`() {
        // "dGVzdA" is the unpadded standard base64 of "test" (length 6, 6%4==2 != 0).
        // Old branch 4 required length%4==0, so this fell through to "plain" and was returned
        // unchanged. New branch 4 drops the modulo constraint and gates on UTF-8 validity instead.
        val r = service.decode(DecodeRequest(data = "dGVzdA", encoding = null))
        assertEquals("base64", r.encoding)
        assertEquals("test", r.result)
    }

    @Test
    fun `04 -auto-detect of plain word test that is valid base64 alphabet returns plain not an error`() {
        // "test" is length 4, all base64-alphabet chars, 4%4==0 — so old branch 4 classified it
        // as base64. decodeBase64Flexible("test") yields bytes [0xB6,0xEB,0x2F] which are not
        // valid UTF-8, causing decodeUtf8OrThrow to throw. New branch gates on isBase64Url-
        // DecodableAsUtf8 which returns false for "test", so it falls through to "plain".
        val r = service.decode(DecodeRequest(data = "test", encoding = null))
        assertEquals("plain", r.encoding)
        assertEquals("test", r.result)
    }

    // ── [04][05] RED: all-hex non-UTF-8 string must be terminal plain, never base64 ─────────────

    @Test
    fun `04 05 -auto-detect of ff returns plain not base64`() {
        // "ff" is all-hex, even-length. Its byte 0xFF is not valid UTF-8.
        // Old behaviour: hex guard fails, falls through to base64 branch, "ff" base64-decodes
        // to "}" — silent garbage. New behaviour: hex branch is terminal → "plain", result "ff".
        val r = service.decode(DecodeRequest(data = "ff", encoding = null))
        assertEquals("plain", r.encoding)
        assertEquals("ff", r.result)
    }

    @Test
    fun `04 05 -auto-detect of a0 returns plain not base64`() {
        // "a0" hex-decodes to byte 0xA0 (non-UTF-8 in isolation). Same terminal-plain guarantee.
        val r = service.decode(DecodeRequest(data = "a0", encoding = null))
        assertEquals("plain", r.encoding)
        assertEquals("a0", r.result)
    }

    @Test
    fun `05 -smart decode of ZmY stops at ff and does not cascade to base64`() {
        // ZmY= is base64 of "ff". After peeling: current = "ff".
        // detectEncoding("ff") must return "plain" (hex terminal branch), so smartDecode stops.
        // Final result must be "ff", not "}" (which would happen if ff fell through to base64).
        val r = service.smartDecode("ZmY=")
        assertEquals("ff", r.finalResult)
        assertEquals(1, r.steps.size)
        assertEquals("base64", r.steps[0].encoding)
    }

    // ── [B04] RED: decode() must return canonical lowercase encoding, not the raw request casing ──

    @Test
    fun `B04 -decode hex with uppercase encoding HEX returns encoding as hex not HEX`() {
        // Bug: DecodeResponse.encoding echoed the raw request.encoding ("HEX") instead of
        // the normalized lowercase form used for dispatch. Fix: return encoding.lowercase().
        val r = service.decode(DecodeRequest(data = "4142", encoding = "HEX"))
        assertEquals("hex", r.encoding)
        assertEquals("AB", r.result)
    }

    @Test
    fun `B04 -decode base64 with uppercase encoding BASE64 returns encoding as base64`() {
        val r = service.decode(DecodeRequest(data = "aGVsbG8=", encoding = "BASE64"))
        assertEquals("base64", r.encoding)
        assertEquals("hello", r.result)
    }

    // ── [B05] RED: HTML auto-detect must fire on &quot; and &#x27; entities ────────────────────

    @Test
    fun `B05 -auto-detect of string with only quot entity returns html encoding and decodes it`() {
        // encode() emits &quot; for double-quotes; auto-decode must recognise it as html.
        val encoded = "say &quot;hello&quot;"
        val r = service.decode(DecodeRequest(data = encoded, encoding = null))
        assertEquals("html", r.encoding)
        assertEquals("say \"hello\"", r.result)
    }

    @Test
    fun `B05 -auto-detect of string with only apos entity returns html encoding and decodes it`() {
        // encode() emits &#x27; for apostrophes; auto-decode must recognise it as html.
        val encoded = "O&#x27;Reilly"
        val r = service.decode(DecodeRequest(data = encoded, encoding = null))
        assertEquals("html", r.encoding)
        assertEquals("O'Reilly", r.result)
    }

    @Test
    fun `B05 -roundtrip html encode then auto-decode with only apostrophe in input`() {
        val original = "O'Reilly"
        val encoded = service.encode(EncodeRequest(data = original, encoding = "html"))
        // encoded.result = "O&#x27;Reilly"; auto-decode must recover original.
        val decoded = service.decode(DecodeRequest(data = encoded.result, encoding = null))
        assertEquals("html", decoded.encoding)
        assertEquals(original, decoded.result)
    }

    @Test
    fun `B05 -roundtrip html encode then auto-decode with only double-quote in input`() {
        val original = "say \"hello\""
        val encoded = service.encode(EncodeRequest(data = original, encoding = "html"))
        val decoded = service.decode(DecodeRequest(data = encoded.result, encoding = null))
        assertEquals("html", decoded.encoding)
        assertEquals(original, decoded.result)
    }

    @Test
    fun `B05 -existing html auto-detect with amp lt gt still works`() {
        val r = service.decode(DecodeRequest(data = "&amp; &lt; &gt;", encoding = null))
        assertEquals("html", r.encoding)
        assertEquals("& < >", r.result)
    }

    // ── [06] RED: url decode of malformed input must not leak JDK class name ───────────────────

    @Test
    fun `06 -explicit url decode of malformed percent sequence throws without leaking class name`() {
        // URLDecoder throws "URLDecoder: Illegal hex characters in escape (%) pattern..." —
        // leaks the JDK class name. The wrapped catch must rethrow with a clean message.
        val ex = assertFailsWith<IllegalArgumentException> {
            service.decode(DecodeRequest(data = "%GG", encoding = "url"))
        }
        assertTrue(
            !ex.message.orEmpty().contains("URLDecoder"),
            "message must not leak JDK class name but was: ${ex.message}"
        )
        assertEquals("invalid URL-encoded input", ex.message)
    }

    // ── [15] RED: smartDecode stops gracefully rather than propagating binary-decode exception ──

    // ── [05] RED: smartDecode peels form-urlencoded '+'-as-space as a final url layer ────────────

    @Test
    fun `05 -smartDecode of base64 of hello+world yields hello world with steps base64 then url`() {
        // Scenario: the original value "hello+world" was base64-encoded before transit.
        // smartDecode must peel base64 first (→ "hello+world"), then peel the form-url
        // '+'-as-space layer (→ "hello world").
        // Expected: finalResult = "hello world", steps = [base64, url].
        val encoded = java.util.Base64.getEncoder().encodeToString("hello+world".toByteArray())
        val r = service.smartDecode(encoded)
        assertEquals("hello world", r.finalResult)
        assertEquals(2, r.steps.size)
        assertEquals("base64", r.steps[0].encoding)
        assertEquals("url",    r.steps[1].encoding)
    }

    @Test
    fun `05 -smartDecode of plain string without plus is unchanged`() {
        // No '+' present: the post-loop form-url branch must not fire.
        val r = service.smartDecode("hello world")
        assertEquals("hello world", r.finalResult)
        assertTrue(r.steps.isEmpty())
    }

    @Test
    fun `05 -smartDecode of real base64 payload that decodes to valid UTF-8 is not mis-peeled as url`() {
        // A base64 string whose decoded bytes ARE valid UTF-8 is caught by the base64 branch in
        // detectEncoding (branch 4) BEFORE the post-loop form-url check.  The loop peels it
        // correctly as base64; the post-loop branch never sees its original form.
        // Example: base64 of "look here" = "bG9vayBoZXJl" — no '+' in encoded form anyway.
        // Use a payload that produces a '+' in the base64 encoding but decodes to valid UTF-8:
        // base64("no plus here") — the base64 of this string has no '+', so we instead directly
        // verify that a base64 string caught by branch 4 is never mis-peeled.
        // "aGVsbG8=" = base64 of "hello" — detected as base64, decoded to "hello", done.
        // "hello" has no '+' so the post-loop branch does not fire.  finalResult = "hello".
        val r = service.smartDecode("aGVsbG8=")
        assertEquals("hello", r.finalResult)
        assertEquals(1, r.steps.size)
        assertEquals("base64", r.steps[0].encoding)
    }

    @Test
    fun `15 -smartDecode of base64-of-hex-string stops at the hex layer without throwing`() {
        // base64("deadbeef") = "ZGVhZGJlZWY=" — first peel decodes to the string "deadbeef".
        // "deadbeef" is then classified as hex; its bytes (0xDE 0xAD 0xBE 0xEF) are not UTF-8,
        // so the hex decode step would throw. smartDecode must catch that and stop cleanly,
        // returning "deadbeef" — no replacement chars, no exception propagated.
        val input = java.util.Base64.getEncoder().encodeToString("deadbeef".toByteArray())
        // sanity: input is "ZGVhZGJlZWY="
        val r = service.smartDecode(input)
        assertEquals("deadbeef", r.finalResult)
        // exactly one step was peeled (base64 → "deadbeef"); the hex step was aborted
        assertEquals(1, r.steps.size)
        assertEquals("base64", r.steps[0].encoding)
    }
}
