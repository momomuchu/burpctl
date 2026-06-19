package com.burprest.services

import com.burprest.models.SetSessionRequest
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertFailsWith

class SessionServiceTest {

    @Test
    fun `setSession rejects a cookie value containing a semicolon (header injection)`() {
        val svc = SessionService(mockk(relaxed = true))
        assertFailsWith<IllegalArgumentException> {
            svc.setSession(SetSessionRequest(cookies = mapOf("sid" to "abc; injected=1")))
        }
    }

    @Test
    fun `setSession rejects a cookie name containing an equals sign`() {
        val svc = SessionService(mockk(relaxed = true))
        assertFailsWith<IllegalArgumentException> {
            svc.setSession(SetSessionRequest(cookies = mapOf("a=b" to "v")))
        }
    }

    @Test
    fun `setSession accepts clean cookies`() {
        val svc = SessionService(mockk(relaxed = true))
        val info = svc.setSession(SetSessionRequest(cookies = mapOf("sid" to "abc123")))
        kotlin.test.assertEquals(1, info.cookieCount)
    }
}
