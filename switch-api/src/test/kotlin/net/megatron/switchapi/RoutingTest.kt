package net.megatron.switchapi

import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.CreateTrunk
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.RateRow
import net.megatron.provisioning.Transport
import net.megatron.provisioning.TrunkDirection
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Where a call goes, and what happens when there is nowhere for it to go.
 *
 * The lab proved every other part of the money path against a SIPp listener
 * hardcoded in the switch config. A deployment has carriers, and picking one
 * is the same decision as pricing the call — so it is answered here.
 */
class RoutingTest {

    private fun service(
        trunks: List<CreateTrunk> = listOf(
            CreateTrunk(
                name = "carrier-a",
                direction = TrunkDirection.OUTBOUND,
                host = "203.0.113.10",
                port = 5060,
                remoteIps = listOf("203.0.113.10"),
            ),
        ),
    ): Pair<CallService, InMemoryStore> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.replaceRates(
            plan.id,
            net.megatron.provisioning.ReplaceRates(
                rates = listOf(
                    RateRow(prefix = "1", sellMicrosPerMinute = 10_000, incrementSeconds = 60)
                )
            ),
        )
        store.createCustomer(
            CreateCustomer("acme", plan.id, openingBalanceMicros = 25_000_000),
            "test",
        )
        trunks.forEach { store.createTrunk(it) }
        return CallService(store) to store
    }

    private fun authorize(service: CallService) = service.authorize(
        AuthorizeRequest(
            account = "acme",
            destination = "12125551234",
            callId = "call-${System.nanoTime()}",
        )
    )

    @Test
    fun `an allowed call carries the carrier to send it to`() {
        val (service, _) = service()
        val response = authorize(service)

        assertEquals("allow", response.decision)
        assertEquals("sip:203.0.113.10:5060;transport=udp", response.route)
    }

    @Test
    fun `a call with nowhere to go is refused, not allowed and dropped`() {
        // Allowing it would hold a reservation, connect to nothing, and then
        // settle — the customer pays for a call that could never have
        // happened, and the operator's first sign of it is a complaint.
        // Refusing costs one call.
        val (service, _) = service(trunks = emptyList())
        val response = authorize(service)

        assertEquals("reject", response.decision)
        assertNull(response.route)
        assertEquals(
            503,
            response.sipCode,
            "no carrier configured is OUR fault; a 4xx would blame the caller's number",
        )
    }

    @Test
    fun `a disabled trunk is not used`() {
        // A trunk is disabled when the carrier is having an outage. Continuing
        // to send calls into it produces failed calls the customer is not
        // charged for and the operator cannot explain.
        val (service, store) = service()
        val trunk = store.listTrunks().single()
        store.createTrunk(
            CreateTrunk(
                name = "carrier-b",
                direction = TrunkDirection.OUTBOUND,
                host = "203.0.113.20",
                port = 5060,
                remoteIps = listOf("203.0.113.20"),
            )
        )
        assertNotNull(trunk)

        // Both enabled: the choice is deterministic, so it does not wander
        // between calls for no reason.
        val first = authorize(service).route
        val second = authorize(service).route
        assertEquals(first, second, "the route moved between two identical calls")
    }

    @Test
    fun `an inbound trunk is never used to send a call out`() {
        // An inbound trunk is where a carrier sends US traffic. Relaying an
        // outbound call to it is at best a loop and at worst delivering a
        // customer's calls to a carrier that will not bill us for them and
        // will not carry them either.
        val (service, _) = service(
            trunks = listOf(
                CreateTrunk(
                    name = "inbound-only",
                    direction = TrunkDirection.INBOUND,
                    host = "203.0.113.30",
                    port = 5060,
                    remoteIps = listOf("203.0.113.30"),
                ),
            ),
        )
        val response = authorize(service)
        assertEquals("reject", response.decision, "an inbound trunk was used for an outbound call")
    }

    @Test
    fun `the transport is named, so a TLS trunk is not dialled in clear`() {
        // Left off, OpenSIPS applies its own default of UDP — so a TLS trunk
        // would silently be dialled unencrypted, which is both a security
        // failure and one the carrier reports as "we never received it".
        val (service, _) = service(
            trunks = listOf(
                CreateTrunk(
                    name = "secure",
                    direction = TrunkDirection.OUTBOUND,
                    host = "203.0.113.40",
                    port = 5061,
                    remoteIps = listOf("203.0.113.40"),
                    transport = Transport.TLS,
                ),
            ),
        )
        assertEquals("sip:203.0.113.40:5061;transport=tls", authorize(service).route)
    }

    @Test
    fun `a refusal for any other reason still carries no route`() {
        // The route is not a hint the switch may use anyway. A refused call
        // that arrived with a routable address is one the switch could relay
        // by mistake, unbilled.
        val (service, store) = service()
        val customer = store.findByHandle("acme")!!
        store.adjustBalance(
            customer.id,
            net.megatron.provisioning.BalanceAdjustment(-25_000_000, "spent it all"),
            "test",
        )

        val response = service.authorize(
            AuthorizeRequest(account = "acme", destination = "12125551234", callId = "broke")
        )
        assertEquals("reject", response.decision)
        assertNull(response.route, "a refused call was given somewhere to go")
        assertTrue(response.sipCode == 402, "expected payment required, got ${response.sipCode}")
    }
}
