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
}
