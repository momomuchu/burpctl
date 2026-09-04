package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.Collaborator
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.CollaboratorPayload as MontoyaCollaboratorPayload
import burp.api.montoya.collaborator.DnsDetails
import burp.api.montoya.collaborator.HttpDetails
import burp.api.montoya.collaborator.Interaction as MontoyaInteraction
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.collaborator.InteractionId
import burp.api.montoya.collaborator.InteractionType
import burp.api.montoya.collaborator.SmtpDetails
import burp.api.montoya.collaborator.SmtpProtocol
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import java.net.InetAddress
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.Base64
import java.util.Optional
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class CollaboratorServiceTest {

    @Test
    fun `generated payload uses provider interaction id as every public correlation id`() {
        val fixture = fixture()
        val payload = payload("provider-id-123", "provider-id-123.oastify.test")
        every { fixture.client.generatePayload() } returns payload

        val result = fixture.service.generatePayload().payload

        assertEquals("provider-id-123", result.id)
        assertEquals("provider-id-123", result.interactionId)
        assertEquals("provider-id-123.oastify.test", result.payload)
    }

    @Test
    fun `batch validates before provider access and returns requested provider payloads`() {
        listOf(Int.MIN_VALUE, -1, 0, 101, Int.MAX_VALUE).forEach { count ->
            val api = mockk<MontoyaApi>()
            val service = CollaboratorService(api)
            assertFailsWith<IllegalArgumentException>("count=$count") {
                service.generateBatch(count)
            }
            verify(exactly = 0) { api.collaborator() }
        }

        val fixture = fixture()
        every { fixture.client.generatePayload() } returnsMany listOf(
            payload("provider-a", "provider-a.test"),
            payload("provider-b", "provider-b.test"),
        )

        val result = fixture.service.generateBatch(2)

        assertEquals(listOf("provider-a", "provider-b"), result.payloads.map { it.id })
        verify(exactly = 2) { fixture.client.generatePayload() }
    }

    @Test
    fun `scoped poll rejects unknown ids without polling or creating a client`() {
        val api = mockk<MontoyaApi>()
        val service = CollaboratorService(api)

        assertFailsWith<CollaboratorPayloadNotFoundException> {
            service.pollById("never-generated")
        }

        verify(exactly = 0) { api.collaborator() }
    }

    @Test
    fun `scoped poll filters with the provider payload interaction id`() {
        val fixture = fixture()
        val filter = mockk<InteractionFilter>()
        every { fixture.client.generatePayload() } returns payload("provider-scope-id", "scope.test")
        every { fixture.client.getInteractions(filter) } returns emptyList()

        mockkStatic(InteractionFilter::class)
        try {
            every { InteractionFilter.interactionIdFilter("provider-scope-id") } returns filter

            fixture.service.generatePayload()
            val result = fixture.service.pollById("provider-scope-id")

            assertFalse(result.found)
            assertEquals("provider-scope-id", result.queriedPayloadId)
            assertTrue(result.interactions.isEmpty())
            verify(exactly = 1) { InteractionFilter.interactionIdFilter("provider-scope-id") }
            verify(exactly = 1) { fixture.client.getInteractions(filter) }
        } finally {
            unmockkStatic(InteractionFilter::class)
        }
    }

    @Test
    fun `poll maps authoritative identity capture metadata and all protocol details`() {
        val fixture = fixture()
        val capturedAt = ZonedDateTime.of(
            2026, 7, 8, 9, 10, 11, 123_000_000,
            ZoneId.of("Europe/Paris"),
        )
        val sourceIp = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 44))

        val dnsQuery = byteArrayOf(0, 0xff.toByte(), 0x80.toByte(), 0x41)
        val dnsDetails = mockk<DnsDetails>()
        val dnsBytes = montoyaBytes(dnsQuery)
        every { dnsDetails.queryType() } returns burp.api.montoya.collaborator.DnsQueryType.TXT
        every { dnsDetails.query() } returns dnsBytes
        val dns = interaction("dns-id", InteractionType.DNS, capturedAt, sourceIp, 53001)
        every { dns.dnsDetails() } returns Optional.of(dnsDetails)

        val rawRequest = byteArrayOf(0x47, 0x45, 0x54, 0, 0xff.toByte())
        val rawResponse = byteArrayOf(0x48, 0x54, 0x54, 0x50, 0x80.toByte())
        val request = mockk<HttpRequest>()
        val response = mockk<HttpResponse>()
        every { request.toByteArray() } returns montoyaBytes(rawRequest)
        every { response.toByteArray() } returns montoyaBytes(rawResponse)
        val requestResponse = mockk<HttpRequestResponse>()
        every { requestResponse.request() } returns request
        every { requestResponse.hasResponse() } returns true
        every { requestResponse.response() } returns response
        val httpDetails = mockk<HttpDetails>()
        every { httpDetails.protocol() } returns HttpProtocol.HTTPS
        every { httpDetails.requestResponse() } returns requestResponse
        val http = interaction("http-id", InteractionType.HTTP, capturedAt, sourceIp, 443)
        every { http.httpDetails() } returns Optional.of(httpDetails)

        val smtpDetails = mockk<SmtpDetails>()
        every { smtpDetails.protocol() } returns SmtpProtocol.SMTPS
        every { smtpDetails.conversation() } returns "EHLO test\r\nMAIL FROM:<sender@test>\u0000"
        val smtp = interaction("smtp-id", InteractionType.SMTP, capturedAt, sourceIp, 2525)
        every { smtp.smtpDetails() } returns Optional.of(smtpDetails)

        every { fixture.client.getAllInteractions() } returns listOf(dns, http, smtp)

        val result = fixture.service.poll()

        assertTrue(result.found)
        assertEquals(null, result.queriedPayloadId)
        assertEquals(listOf("dns-id", "http-id", "smtp-id"), result.interactions.map { it.id })
        result.interactions.forEach {
            assertEquals(capturedAt.toString(), it.timestamp)
            assertEquals("192.0.2.44", it.clientIp)
        }
        assertEquals(53001, result.interactions[0].clientPort)
        assertEquals(
            mapOf(
                "queryType" to "TXT",
                "query" to Base64.getEncoder().encodeToString(dnsQuery),
            ),
            result.interactions[0].details,
        )
        assertEquals(443, result.interactions[1].clientPort)
        assertEquals(
            mapOf(
                "protocol" to "HTTPS",
                "request" to Base64.getEncoder().encodeToString(rawRequest),
                "response" to Base64.getEncoder().encodeToString(rawResponse),
            ),
            result.interactions[1].details,
        )
        assertEquals(2525, result.interactions[2].clientPort)
        assertEquals(
            mapOf(
                "protocol" to "SMTPS",
                "conversation" to "EHLO test\r\nMAIL FROM:<sender@test>\u0000",
            ),
            result.interactions[2].details,
        )
    }

    @Test
    fun `missing optional protocol details stay empty and an HTTP response is optional`() {
        val fixture = fixture()
        val capturedAt = ZonedDateTime.parse("2026-07-08T09:10:11Z")
        val sourceIp = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val dns = interaction("dns", InteractionType.DNS, capturedAt, sourceIp, 53)
        every { dns.dnsDetails() } returns Optional.empty()

        val request = mockk<HttpRequest>()
        every { request.toByteArray() } returns montoyaBytes(byteArrayOf(1, 2, 3))
        val requestResponse = mockk<HttpRequestResponse>()
        every { requestResponse.request() } returns request
        every { requestResponse.hasResponse() } returns false
        val httpDetails = mockk<HttpDetails>()
        every { httpDetails.protocol() } returns HttpProtocol.HTTP
        every { httpDetails.requestResponse() } returns requestResponse
        val http = interaction("http", InteractionType.HTTP, capturedAt, sourceIp, 80)
        every { http.httpDetails() } returns Optional.of(httpDetails)
        every { fixture.client.getAllInteractions() } returns listOf(dns, http)

        val interactions = fixture.service.poll().interactions

        assertEquals(emptyMap(), interactions[0].details)
        assertEquals(setOf("protocol", "request"), interactions[1].details.keys)
        verify(exactly = 0) { requestResponse.response() }
    }

    @Test
    fun `capability lookup and client creation failures have unavailable type`() {
        val lookupFailure = IllegalStateException("SECRET lookup detail")
        val unavailableApi = mockk<MontoyaApi>()
        every { unavailableApi.collaborator() } throws lookupFailure

        val lookupResult = assertFailsWith<CollaboratorUnavailableException> {
            CollaboratorService(unavailableApi).generatePayload()
        }
        assertSame(lookupFailure, lookupResult.cause)

        val createFailure = IllegalStateException("SECRET create detail")
        val api = mockk<MontoyaApi>()
        val collaborator = mockk<Collaborator>()
        every { api.collaborator() } returns collaborator
        every { collaborator.createClient() } throws createFailure

        val createResult = assertFailsWith<CollaboratorUnavailableException> {
            CollaboratorService(api).poll()
        }
        assertSame(createFailure, createResult.cause)
    }

    @Test
    fun `generation and polling failures have provider type and never become clean results`() {
        val generateFixture = fixture()
        val generateFailure = IllegalStateException("SECRET generation detail")
        every { generateFixture.client.generatePayload() } throws generateFailure

        val generateResult = assertFailsWith<CollaboratorProviderException> {
            generateFixture.service.generatePayload()
        }
        assertSame(generateFailure, generateResult.cause)

        val pollFixture = fixture()
        val pollFailure = IllegalStateException("SECRET polling detail")
        every { pollFixture.client.getAllInteractions() } throws pollFailure

        val pollResult = assertFailsWith<CollaboratorProviderException> {
            pollFixture.service.poll()
        }
        assertSame(pollFailure, pollResult.cause)
    }

    private fun fixture(): Fixture {
        val api = mockk<MontoyaApi>()
        val collaborator = mockk<Collaborator>()
        val client = mockk<CollaboratorClient>()
        every { api.collaborator() } returns collaborator
        every { collaborator.createClient() } returns client
        return Fixture(api, collaborator, client, CollaboratorService(api))
    }

    private fun payload(id: String, value: String): MontoyaCollaboratorPayload {
        val payload = mockk<MontoyaCollaboratorPayload>()
        val interactionId = mockk<InteractionId>()
        every { payload.id() } returns interactionId
        every { interactionId.toString() } returns id
        every { payload.toString() } returns value
        return payload
    }

    private fun interaction(
        id: String,
        type: InteractionType,
        capturedAt: ZonedDateTime,
        sourceIp: InetAddress,
        sourcePort: Int,
    ): MontoyaInteraction {
        val interaction = mockk<MontoyaInteraction>()
        val interactionId = mockk<InteractionId>()
        every { interaction.id() } returns interactionId
        every { interactionId.toString() } returns id
        every { interaction.type() } returns type
        every { interaction.timeStamp() } returns capturedAt
        every { interaction.clientIp() } returns sourceIp
        every { interaction.clientPort() } returns sourcePort
        return interaction
    }

    private fun montoyaBytes(value: kotlin.ByteArray): MontoyaByteArray {
        val bytes = mockk<MontoyaByteArray>()
        every { bytes.getBytes() } returns value
        return bytes
    }

    private data class Fixture(
        val api: MontoyaApi,
        val collaborator: Collaborator,
        val client: CollaboratorClient,
        val service: CollaboratorService,
    )
}
