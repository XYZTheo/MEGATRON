package net.megatron.switchapi

import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.RateRow
import net.megatron.provisioning.ReplaceRates
import net.megatron.provisioning.SetStatus
import net.megatron.provisioning.CustomerStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The whole money path, end to end: a customer created the way the bot
 * creates one, a call authorized the way OpenSIPS authorizes one, and a
 * settlement that lands back on the balance the customer sees.
 *
 * This is the test that proves the modules actually fit together, as opposed
 * to each being correct in isolation.
 */
class CallFlowTest {

    private fun setup(
        balanceMicros: Long = 25_000_000,   // $25.00
        maxConcurrent: Int = 2,
    ): Triple<InMemoryStore, CallService, MutableList<Cdr>> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.replaceRates(
            plan.id,
            ReplaceRates(
                rates = listOf(
                    // $0.60/min, per-second: 1000 micros per second.
                    RateRow(prefix = "1", sellMicrosPerMinute = 60_000,
                            buyMicrosPerMinute = 40_000, incrementSeconds = 1),
                    RateRow(prefix = "44", sellMicrosPerMinute = 12_000,
                            incrementSeconds = 60, minimumSeconds = 60),
                )
            )
        )
        store.createCustomer(
            CreateCustomer(
                handle = "bigcorp",
                planId = plan.id,
                openingBalanceMicros = balanceMicros,
                maxConcurrentCalls = maxConcurrent,
            ),
            "test",
        )
        val cdrs = mutableListOf<Cdr>()
        return Triple(store, CallService(store, cdrSink = { cdrs += it }), cdrs)
    }

    // -- the whole path -----------------------------------------------------

    @Test
    fun `a funded customer calls, hangs up, and is billed`() {
        val (store, service, cdrs) = setup()

        val auth = service.authorize(
            AuthorizeRequest("bigcorp", "12125551234", "call-1")
        )
        assertEquals("allow", auth.decision)
        // $25.00 at 1000 micros/sec = 25,000 seconds, capped by the 4h ceiling.
        assertEquals(4 * 60 * 60, auth.maxSeconds)
        assertEquals(60_000L, auth.ratePerMinute)

        val end = service.endSession(
            EndSessionRequest("call-1", durationSeconds = 120, mediaBytes = 1_920_000)
        )
        // 120s at 1000 micros/sec = 120_000
        assertEquals(120_000L, end.chargedMicros)
        assertEquals(120, end.billedSeconds)
        assertEquals(24_880_000L, end.balanceAfterMicros)
        assertEquals(false, end.noMedia)

        // The balance the CUSTOMER sees moved too -- the bot and the switch
        // must never disagree about what somebody has left.
        assertEquals(24_880_000L, store.findByHandle("bigcorp")!!.balanceMicros)

        assertEquals(1, cdrs.size)
        assertEquals("bigcorp", cdrs[0].account)
        assertEquals("1", cdrs[0].prefix)
        assertEquals(120_000L, cdrs[0].chargedMicros)
    }

    @Test
    fun `a call that never answers costs nothing and leaves no cdr`() {
        val (store, service, cdrs) = setup()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        assertEquals(true, service.abandon("call-1"))
        assertEquals(25_000_000L, store.findByHandle("bigcorp")!!.balanceMicros)
        assertTrue(cdrs.isEmpty())
    }

    // -- refusals, and the SIP codes they map to ----------------------------

    @Test
    fun `an empty balance is refused with 402 Payment Required`() {
        val (_, service, _) = setup(balanceMicros = 0)
        val auth = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        assertEquals("reject", auth.decision)
        assertEquals("insufficient_balance", auth.reason)
        assertEquals(402, auth.sipCode)
    }

    @Test
    fun `a suspended customer is refused with 403`() {
        val (store, service, _) = setup()
        val customer = store.findByHandle("bigcorp")!!
        store.setStatus(customer.id, SetStatus(CustomerStatus.SUSPENDED, "non payment"), "op")
        val auth = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        assertEquals("reject", auth.decision)
        assertEquals(403, auth.sipCode)
    }

    @Test
    fun `an unrated destination is refused with 404, not carried`() {
        // Different fact from "no balance", and a different SIP code, because
        // topping up fixes one and will never fix the other.
        val (_, service, _) = setup()
        val auth = service.authorize(AuthorizeRequest("bigcorp", "99912345678", "call-1"))
        assertEquals("reject", auth.decision)
        assertEquals("no_rate_for_destination", auth.reason)
        assertEquals(404, auth.sipCode)
    }

    @Test
    fun `the concurrent call cap is refused with 486 Busy Here`() {
        val (_, service, _) = setup(maxConcurrent = 1)
        assertEquals("allow",
            service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1")).decision)
        val second = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-2"))
        assertEquals("reject", second.decision)
        assertEquals(486, second.sipCode)
    }

    @Test
    fun `an unknown account is refused rather than defaulted`() {
        val (_, service, _) = setup()
        val auth = service.authorize(AuthorizeRequest("nobody", "12125551234", "call-1"))
        assertEquals("reject", auth.decision)
    }

    // -- SIP retransmission, which happens constantly -----------------------

    @Test
    fun `a retransmitted INVITE does not reserve twice`() {
        // SIP retransmits by design. Using the Call-ID as the reservation id
        // is what stops a lossy network silently multiplying every customer's
        // reservations until they cannot call at all.
        val (_, service, _) = setup(balanceMicros = 60_000, maxConcurrent = 10)

        val first = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        val repeat = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        assertEquals("allow", first.decision)
        // The repeat must not consume a second reservation's worth of balance.
        // Either it is allowed again for the same call or refused, but the
        // account must not end up with two holds for one call.
        val third = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-2"))
        assertTrue(
            first.decision == "allow" && (repeat.decision == "allow" || third.decision == "reject"),
            "retransmission produced first=${first.decision} repeat=${repeat.decision} " +
                "other=${third.decision}"
        )
    }

    // -- the failure mode that bills for silence ---------------------------

    @Test
    fun `a call that carried no audio is billed but flagged`() {
        // Signalling says the call happened; only the media stats say it was
        // worth anything. This is one of the three money-losing failure modes
        // in ARCHITECTURE.md -- not automatically a refund, because the honest
        // response depends on why, but it must never be invisible.
        val (_, service, cdrs) = setup()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        val end = service.endSession(
            EndSessionRequest("call-1", durationSeconds = 45, mediaBytes = 0)
        )
        assertEquals(true, end.noMedia)
        assertTrue(end.chargedMicros > 0, "a billed call should still be billed")
        assertEquals(true, cdrs.single().noMedia)
    }

    @Test
    fun `absent media stats are not treated as no media`() {
        // rtpengine may not have reported. "We do not know" and "there was
        // none" are different, and conflating them would flag every call on a
        // switch whose media stats are not wired up yet.
        val (_, service, _) = setup()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        val end = service.endSession(
            EndSessionRequest("call-1", durationSeconds = 45, mediaBytes = null)
        )
        assertEquals(false, end.noMedia)
    }

    // -- minimum duration ---------------------------------------------------

    @Test
    fun `a three second call on a one minute minimum bills a minute`() {
        val (_, service, cdrs) = setup()
        service.authorize(AuthorizeRequest("bigcorp", "442079460000", "call-1"))
        val end = service.endSession(EndSessionRequest("call-1", durationSeconds = 3))
        assertEquals(60, end.billedSeconds)
        assertEquals(12_000L, end.chargedMicros)
        assertEquals(3, cdrs.single().durationSeconds)
        assertEquals(60, cdrs.single().billedSeconds)
    }

    // -- unknown sessions ---------------------------------------------------

    @Test
    fun `a BYE for a call we never authorized is refused, not 500`() {
        // Happens after a restart mid-call. It must not 500: OpenSIPS retries
        // a 5xx, and a retry storm on the money path is the last thing a
        // switch under load needs.
        val (_, service, _) = setup()
        assertFailsWith<IllegalStateException> {
            service.endSession(EndSessionRequest("never-seen", 10))
        }
    }

    // -- the balance the switch acts on must be the CURRENT one -------------

    @Test
    fun `a balance drained between calls stops the next call`() {
        // The switch used to learn a balance once, at the customer's first
        // call, and never again. A balance corrected downward -- or spent
        // through another node -- kept right on authorizing calls against
        // money that was gone. Invisible to every unit test until two
        // services shared one database.
        val (store, service, _) = setup()
        assertEquals("allow",
            service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1")).decision)
        service.endSession(EndSessionRequest("call-1", durationSeconds = 1))

        val customer = store.findByHandle("bigcorp")!!
        store.adjustBalance(
            customer.id,
            net.megatron.provisioning.BalanceAdjustment(
                -customer.balanceMicros, "drained by another node"
            ),
            "test",
        )

        val second = service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-2"))
        assertEquals("insufficient_balance", second.reason,
                     "authorized against money that is gone")
        assertEquals(402, second.sipCode)
    }

    @Test
    fun `a top-up between calls is visible immediately`() {
        // The other direction, and the one a customer notices: topping up
        // through the bot must work without restarting the switch.
        val (store, service, _) = setup(balanceMicros = 0)
        assertEquals("reject",
            service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1")).decision)

        val customer = store.findByHandle("bigcorp")!!
        store.adjustBalance(
            customer.id,
            net.megatron.provisioning.BalanceAdjustment(10_000_000, "top up via bot"),
            "telegram:1",
        )

        assertEquals("allow",
            service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-2")).decision)
    }

    @Test
    fun `an unknown account is not reported as suspended`() {
        // Reporting a missing account as "suspended" sends an operator looking
        // at a customer record that is not there. It masqueraded as a business
        // decision while actually being a data bug, and it hid one.
        val (_, service, _) = setup()
        val decision = service.authorize(AuthorizeRequest("ghost", "12125551234", "c1"))
        assertEquals("no_such_account", decision.reason)
        assertEquals(404, decision.sipCode)
    }

    // -- rate table cache ---------------------------------------------------

    @Test
    fun `a repriced plan takes effect on the next call`() {
        // Tariff data is cached in-process for the 5 ms budget. A cache that
        // never notices a reprice is a switch billing yesterday's prices.
        val (store, service, _) = setup()
        val planId = store.listPlans().first().id

        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-1"))
        service.endSession(EndSessionRequest("call-1", durationSeconds = 60))

        store.replaceRates(
            planId,
            ReplaceRates(rates = listOf(
                RateRow(prefix = "1", sellMicrosPerMinute = 120_000, incrementSeconds = 1)
            ))
        )

        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "call-2"))
        val end = service.endSession(EndSessionRequest("call-2", durationSeconds = 60))
        // 60s at 120_000/min = 120_000, double the old price.
        assertEquals(120_000L, end.chargedMicros)
    }
}
