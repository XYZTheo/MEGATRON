package net.megatron.switchapi

import net.megatron.provisioning.AssignDid
import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.CreateTrunk
import net.megatron.provisioning.CustomerStatus
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.RateRow
import net.megatron.provisioning.ReplaceRates
import net.megatron.provisioning.SetStatus
import net.megatron.provisioning.TrunkDirection
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Calls ARRIVING from a carrier — the half of the business an operator sells
 * when he tells a provider to point their traffic at this address.
 *
 * Every case here is one an operator hits in the first week: a provider whose
 * address is not on the list, a number nobody owns, a customer whose credit
 * ran out, and the ordinary one that has to work.
 */
class InboundCallTest {

    private val carrierIp = "203.0.113.10"

    private fun setup(
        balanceMicros: Long = 25_000_000,
        maxConcurrent: Int = 2,
        /** Whether the plan prices inbound calls to the DID at all. */
        priceInbound: Boolean = false,
    ): Triple<InMemoryStore, CallService, MutableList<Cdr>> {
        val store = InMemoryStore()
        store.createTrunk(
            CreateTrunk(
                name = "carrier-in",
                direction = TrunkDirection.INBOUND,
                host = carrierIp,
                remoteIps = listOf("203.0.113.0/24"),
            )
        )
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.replaceRates(
            plan.id,
            ReplaceRates(
                rates = buildList {
                    add(RateRow(prefix = "1", sellMicrosPerMinute = 60_000, incrementSeconds = 1))
                    // "44" covers the DID below, so its presence is what makes
                    // inbound priced rather than free.
                    if (priceInbound) {
                        add(RateRow(prefix = "44", sellMicrosPerMinute = 6_000,
                                    incrementSeconds = 60))
                    }
                }
            )
        )
        val customer = store.createCustomer(
            CreateCustomer(
                handle = "bigcorp",
                planId = plan.id,
                openingBalanceMicros = balanceMicros,
                maxConcurrentCalls = maxConcurrent,
            ),
            "test",
        ).first
        store.assignDid(AssignDid(number = "+441632960123", customerId = customer.id), "test")
        val cdrs = mutableListOf<Cdr>()
        return Triple(store, CallService(store, cdrSink = { cdrs += it }), cdrs)
    }

    private fun inbound(
        service: CallService,
        did: String = "+441632960123",
        from: String = carrierIp,
        callId: String = "in-1",
    ) = service.authorizeInbound(
        InboundAuthorizeRequest(sourceIp = from, did = did, callerId = "12125551234", callId = callId)
    )

    // -- the ordinary case ---------------------------------------------------

    @Test
    fun `a call from a carrier to one of our numbers reaches the customer`() {
        val (_, service, _) = setup()
        val decision = inbound(service)
        assertEquals("allow", decision.decision)
        // The HANDLE, not the number. It is what the phone registered as, and
        // what the switch looks up in the location table.
        assertEquals("bigcorp", decision.account)
        assertNotNull(decision.maxSeconds)
    }

    @Test
    fun `an unpriced inbound call is free, and the CDR says so`() {
        val (store, service, cdrs) = setup()
        val before = store.findByHandle("bigcorp")!!.balanceMicros

        inbound(service)
        val settled = service.endSession(
            EndSessionRequest(callId = "in-1", durationSeconds = 120)
        )

        assertEquals(0, settled.chargedMicros)
        assertEquals(before, store.findByHandle("bigcorp")!!.balanceMicros)
        val cdr = cdrs.single()
        assertEquals("inbound", cdr.direction)
        assertEquals(0, cdr.chargedMicros)
        assertEquals(120, cdr.durationSeconds)
        // A free call still produces a record. An operator who cannot see the
        // calls a DID delivered cannot tell a working number from a dead one.
        assertEquals("+441632960123", cdr.destination)
    }

    @Test
    fun `a priced inbound call is reserved and billed like any other`() {
        val (store, service, cdrs) = setup(priceInbound = true)
        val before = store.findByHandle("bigcorp")!!.balanceMicros

        val decision = inbound(service)
        assertEquals("allow", decision.decision)
        assertTrue(decision.charged, "a plan that prices the DID should charge for it")
        assertNotNull(decision.reservedMicros)

        service.endSession(EndSessionRequest(callId = "in-1", durationSeconds = 60))

        // 6000 micros/min for one minute.
        assertEquals(before - 6_000, store.findByHandle("bigcorp")!!.balanceMicros)
        assertEquals("inbound", cdrs.single().direction)
    }

    // -- the refusals --------------------------------------------------------

    @Test
    fun `a stranger's address is refused, and is not treated as a customer call`() {
        val (_, service, _) = setup()
        val decision = inbound(service, from = "198.51.100.9")
        assertEquals("reject", decision.decision)
        assertEquals("source_not_a_trunk", decision.reason)
        assertEquals(403, decision.sipCode)
        // The switch keys off this exact value to decide "this is an ordinary
        // customer INVITE, challenge it" instead of refusing outright. If the
        // string changes, inbound and outbound both break in ways that look
        // like the other one's fault.
        assertNull(decision.account)
    }

    @Test
    fun `an address just outside the allowlist range is refused`() {
        val (_, service, _) = setup()
        // 203.0.113.0/24 is the trunk. 203.0.114.1 differs in the third octet,
        // which a string-prefix match would have accepted.
        assertEquals("reject", inbound(service, from = "203.0.114.1").decision)
        assertEquals("allow", inbound(service, from = "203.0.113.255").decision)
    }

    @Test
    fun `a number nobody owns reaches nobody`() {
        val (_, service, _) = setup()
        val decision = inbound(service, did = "+441632999999")
        assertEquals("reject", decision.decision)
        assertEquals("no_such_did", decision.reason)
        assertEquals(404, decision.sipCode)
    }

    @Test
    fun `a suspended customer does not receive calls`() {
        val (store, service, _) = setup()
        val customer = store.findByHandle("bigcorp")!!
        store.setStatus(customer.id, SetStatus(CustomerStatus.SUSPENDED, "unpaid"), "test")

        val decision = inbound(service)
        assertEquals("reject", decision.decision)
        assertEquals("account_suspended", decision.reason)
        assertEquals(403, decision.sipCode)
    }

    @Test
    fun `a customer with no balance still receives calls`() {
        // THE POINT OF THE FREE PATH. They bought the number; refusing their
        // inbound because their outbound credit ran out is a surprise that
        // costs the operator the customer, and it is what reusing the outbound
        // authorizer unchanged would have done.
        val (_, service, _) = setup(balanceMicros = 0)
        assertEquals("allow", inbound(service).decision)
    }

    @Test
    fun `a customer with no balance is refused an inbound call their plan prices`() {
        // The other side of the same rule: once the operator has decided the
        // customer pays per minute to receive, the balance gates it exactly as
        // it gates an outgoing call.
        val (_, service, _) = setup(balanceMicros = 0, priceInbound = true)
        val decision = inbound(service)
        assertEquals("reject", decision.decision)
        assertEquals("insufficient_balance", decision.reason)
        assertEquals(402, decision.sipCode)
    }

    @Test
    fun `the concurrency cap applies to calls coming in`() {
        val (_, service, _) = setup(maxConcurrent = 1, priceInbound = true)
        assertEquals("allow", inbound(service, callId = "in-1").decision)

        val second = inbound(service, callId = "in-2")
        assertEquals("reject", second.decision)
        assertEquals("concurrent_call_limit", second.reason)
        assertEquals(486, second.sipCode)
    }

    @Test
    fun `a retired carrier stops being able to send us calls`() {
        val (store, service, _) = setup()
        val trunk = store.listTrunks().single { it.direction == TrunkDirection.INBOUND }
        store.deleteTrunk(trunk.id)
        assertEquals("source_not_a_trunk", inbound(service).reason)
    }

    @Test
    fun `an outbound-only trunk does not let calls in`() {
        // A carrier we buy FROM is not automatically a carrier we accept calls
        // from. Treating one direction as both is how a switch ends up
        // delivering traffic it was never asked to carry.
        val store = InMemoryStore()
        store.createTrunk(
            CreateTrunk(
                name = "sell-only",
                direction = TrunkDirection.OUTBOUND,
                host = carrierIp,
                remoteIps = listOf(carrierIp),
            )
        )
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.replaceRates(
            plan.id,
            ReplaceRates(rates = listOf(RateRow(prefix = "1", sellMicrosPerMinute = 1))),
        )
        val customer = store.createCustomer(
            CreateCustomer(handle = "bigcorp", planId = plan.id, openingBalanceMicros = 1_000_000),
            "test",
        ).first
        store.assignDid(AssignDid(number = "+441632960123", customerId = customer.id), "test")

        val service = CallService(store)
        assertEquals("source_not_a_trunk", inbound(service).reason)
    }

    // -- the rate a call was quoted ------------------------------------------

    @Test
    fun `a call is billed at the price it was quoted, not the price at hangup`() {
        // Settlement used to re-read the plan when the BYE arrived. A reprice
        // mid-call then billed against a reservation taken at the old price --
        // and the customer's quote is the honest one.
        val store = InMemoryStore()
        store.createTrunk(
            CreateTrunk(
                name = "carrier", direction = TrunkDirection.OUTBOUND,
                host = "203.0.113.10", remoteIps = listOf("203.0.113.10"),
            )
        )
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.replaceRates(
            plan.id,
            ReplaceRates(rates = listOf(RateRow(prefix = "1", sellMicrosPerMinute = 60_000,
                                                incrementSeconds = 1))),
        )
        store.createCustomer(
            CreateCustomer(handle = "bigcorp", planId = plan.id, openingBalanceMicros = 25_000_000),
            "test",
        )
        val cdrs = mutableListOf<Cdr>()
        val service = CallService(store, cdrSink = { cdrs += it })

        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "c-1"))

        // Ten times the price, while the call is up.
        store.replaceRates(
            plan.id,
            ReplaceRates(rates = listOf(RateRow(prefix = "1", sellMicrosPerMinute = 600_000,
                                                incrementSeconds = 1))),
        )
        service.endSession(EndSessionRequest(callId = "c-1", durationSeconds = 60))

        assertEquals(60_000, cdrs.single().chargedMicros, "billed at the new price")
        assertEquals(60_000, cdrs.single().ratePerMinute)
    }
}
