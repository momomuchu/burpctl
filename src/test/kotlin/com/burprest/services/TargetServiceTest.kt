package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scope.Scope
import com.burprest.models.AddScopeRequest
import com.burprest.models.SetScopeRequest
import com.burprest.server.InvalidParamException
import com.burprest.server.UnsupportedException
import io.mockk.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TargetServiceTest {

    @Test
    fun `scope listing and replacement are unsupported before Montoya effects`() {
        val api = mockk<MontoyaApi>()
        val service = TargetService(api)

        assertFailsWith<UnsupportedException> { service.getScope() }
        assertFailsWith<UnsupportedException> {
            service.setScope(SetScopeRequest(includes = listOf("https://example.com/")))
        }
        verify(exactly = 0) { api.scope() }
    }

    @Test
    fun `add reports authoritative scope state after mutation rather than assuming true`() {
        val api = mockk<MontoyaApi>()
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.includeInScope("https://example.com/") } just Runs
        every { scope.isInScope("https://example.com/") } returns false
        val service = TargetService(api)

        val result = service.addToScope(AddScopeRequest("https://example.com/"))

        assertFalse(result.inScope)
        verifyOrder {
            scope.includeInScope("https://example.com/")
            scope.isInScope("https://example.com/")
        }
    }

    @Test
    fun `remove reports authoritative scope state after mutation rather than assuming false`() {
        val api = mockk<MontoyaApi>()
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.excludeFromScope("https://example.com/") } just Runs
        every { scope.isInScope("https://example.com/") } returns true
        val service = TargetService(api)

        val result = service.removeFromScope(AddScopeRequest("https://example.com/"))

        assertTrue(result.inScope)
        verifyOrder {
            scope.excludeFromScope("https://example.com/")
            scope.isInScope("https://example.com/")
        }
    }

    @Test
    fun `scope checks use Montoya authority`() {
        val api = mockk<MontoyaApi>()
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.isInScope("https://example.com/") } returns true

        assertTrue(TargetService(api).isInScope("https://example.com/").inScope)
    }

    @Test
    fun `scope mutation canonicalizes Unicode hosts paths and default ports`() {
        val api = mockk<MontoyaApi>()
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.includeInScope("https://xn--bcher-kva.example/next?q=1") } just Runs
        every { scope.isInScope("https://xn--bcher-kva.example/next?q=1") } returns true
        val service = TargetService(api)

        val result = service.addToScope(
            AddScopeRequest("HTTPS://BÜCHER.EXAMPLE.:443/a/../next?q=1"),
        )

        assertEquals("https://xn--bcher-kva.example/next?q=1", result.url)
        assertTrue(result.inScope)
    }

    @Test
    fun `scope mutation canonicalizes IPv6 literals`() {
        val api = mockk<MontoyaApi>()
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.includeInScope("https://[2001:db8:0:0:0:0:0:1]/") } just Runs
        every { scope.isInScope("https://[2001:db8:0:0:0:0:0:1]/") } returns true

        val result = TargetService(api).addToScope(AddScopeRequest("https://[2001:0DB8::1]:443"))

        assertEquals("https://[2001:db8:0:0:0:0:0:1]/", result.url)
    }

    @Test
    fun `invalid scope URLs are rejected before Montoya effects`() {
        val api = mockk<MontoyaApi>()
        val service = TargetService(api)

        listOf(
            "",
            "relative",
            "ftp://example.com/",
            "https://user:pass@example.com/",
            "https://example.com/path#fragment",
            "https://example.com:0/",
            "https://example.com:70000/",
            "https://example.com:-1/",
            "https://example.com:/",
            "https://example.com:+1/",
        ).forEach { url ->
            assertFailsWith<InvalidParamException> { service.addToScope(AddScopeRequest(url)) }
            assertFailsWith<InvalidParamException> { service.removeFromScope(AddScopeRequest(url)) }
            assertFailsWith<InvalidParamException> { service.isInScope(url) }
        }
        verify(exactly = 0) { api.scope() }
    }
}
