package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.Proxy
import com.burprest.models.CreateAttackRequest
import com.burprest.models.HttpRequestData
import com.burprest.models.PayloadPosition
import com.burprest.server.UnsupportedException
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class IntruderModeContractTest {
    private val api = mockk<MontoyaApi>()
    private val proxy = mockk<Proxy>()
    private val repeater = mockk<RepeaterService>()

    init {
        every { api.proxy() } returns proxy
    }

    @Test
    fun `create reports matrix attack modes as unsupported with the client alternative`() {
        val service = IntruderService(api, repeater)
        val base = validPlan()

        listOf("battering-ram", "pitchfork", "cluster-bomb").forEach { mode ->
            val failure = assertFailsWith<UnsupportedException> {
                service.createAttack(base.copy(attackType = mode))
            }
            assertTrue(failure.clientMessage.contains("bp fuzz"))
        }

        verify(exactly = 0) { repeater.send(any()) }
        verify(exactly = 0) { proxy.history() }
    }

    private fun validPlan() = CreateAttackRequest(
        request = HttpRequestData(
            method = "POST",
            url = "https://example.test/path",
            body = "value=x",
        ),
        positions = listOf(PayloadPosition(start = 0, end = 1, name = "body")),
        payloads = mapOf("body" to listOf("y")),
    )
}
