package net.megatron.authorizer

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The velocity controls, against the traffic they exist to stop.
 *
 * The clock is injected in every case. A test that sleeps to cross a window
 * boundary is slow, flaky, and — worse — passes whether or not the window
 * actually moves, because a long enough sleep satisfies it either way.
 */
class FraudGuardTest {

    private var now = 1_000_000L
    private val clock = { now }

    /**
     * The default spread limit is high so that a test about CALL RATE trips on
     * the call rate. The first version defaulted it to 5, and the rate tests
     * dialled ten distinct numbers -- so they failed on the spread limit and
     * reported "refused early", which reads as the rate limit being wrong.
     * A fixture that lets a second control fire first tests that one.
     */
    private fun guard(
        calls: Int = 10,
        destinations: Int = 1000,
        spend: Long = 0,
    ) = FraudGuard(
        FraudGuard.Limits(
            maxCallsPerMinute = calls,
            maxDestinationsPerMinute = destinations,
            maxSpendPerHourMicros = spend,
        ),
        clock,
    )

    /** Places [n] allowed calls, failing the test if any is refused. */
    private fun place(g: FraudGuard, n: Int, destination: (Int) -> String, micros: Long = 1000) {
        repeat(n) { i ->
            val dest = destination(i)
            assertNull(g.check("acct", dest, micros), "call $i to $dest was refused early")
            g.record("acct", dest, micros)
        }
    }

    // -- call rate -----------------------------------------------------------

    @Test
    fun `a burst past the call limit is refused`() {
        val g = guard(calls = 10)
        place(g, 10, { "1212555${it}" })

        val trip = g.check("acct", "12125559999", 1000)
        assertNotNull(trip, "the eleventh call in a minute was allowed")
        assertEquals("calls-per-minute", trip.rule)
        assertEquals(10, trip.observed)
    }

    @Test
    fun `the window moves, so the account recovers on its own`() {
        val g = guard(calls = 10)
        place(g, 10, { "1212555${it}" })
        assertNotNull(g.check("acct", "12125559999"))

        // A minute and a second later, the whole burst has aged out.
        now += 61_000
        assertNull(g.check("acct", "12125559999"), "the account never recovered")
    }

    @Test
    fun `the window slides rather than resetting on a boundary`() {
        // A limiter that clears everything on a fixed boundary lets an account
        // place its whole allowance twice across it -- and clients synchronise
        // into exactly that. Half the burst, then half a window, then the rest.
        val g = guard(calls = 10)
        place(g, 5, { "1212555${it}" })
        now += 30_000
        place(g, 5, { "1212556${it}" })

        assertNotNull(g.check("acct", "12125559999"), "twenty calls fitted in one minute")

        // 31s after the first half was placed: those five have aged out and
        // exactly five slots are free again.
        now += 31_000
        place(g, 5, { "1212557${it}" })
        assertNotNull(g.check("acct", "12125558888"))
    }

    @Test
    fun `refusals do not count against the account`() {
        // Otherwise a tripped account stays tripped for a full window on the
        // strength of its own refusals, even after the attack stops.
        val g = guard(calls = 3)
        place(g, 3, { "1212555${it}" })
        repeat(50) { assertNotNull(g.check("acct", "12125559999")) }

        now += 61_000
        assertNull(g.check("acct", "12125559999"), "the refusals kept the account locked out")
    }

    // -- destination spread --------------------------------------------------

    @Test
    fun `dialling many different numbers trips the spread limit first`() {
        val g = guard(calls = 100, destinations = 5)
        place(g, 5, { "121255500$it" })

        val trip = g.check("acct", "12125550099")
        assertNotNull(trip, "a sixth distinct destination was allowed")
        assertEquals("destinations-per-minute", trip.rule)
    }

    @Test
    fun `redialling one number is not a spread`() {
        // A call centre hitting one number repeatedly must not look like a
        // scanner. This is the difference between the two limits.
        val g = guard(calls = 100, destinations = 3)
        place(g, 3, { "121255500$it" })

        repeat(20) {
            assertNull(
                g.check("acct", "1212555001"),
                "redialling a number already in the window was treated as a new destination",
            )
            g.record("acct", "1212555001", 1000)
        }
    }

    // -- spend ---------------------------------------------------------------

    @Test
    fun `no spend cap is configured by default`() {
        val g = guard(calls = 100, destinations = 100, spend = 0)
        place(g, 50, { "121255500$it" }, micros = 10_000_000)
        assertNull(g.check("acct", "12125550099", 10_000_000))
    }

    @Test
    fun `a configured spend cap refuses the call that would cross it`() {
        val g = guard(calls = 100, destinations = 100, spend = 100_000)
        place(g, 9, { "121255500$it" }, micros = 10_000)

        // 90 000 spent; a 20 000 call would reach 110 000.
        val trip = g.check("acct", "12125550099", 20_000)
        assertNotNull(trip)
        assertEquals("spend-per-hour", trip.rule)
        assertEquals(110_000, trip.observed)

        // One that fits is still allowed — the cap refuses the call that
        // crosses it, not every call once the account is near it.
        assertNull(g.check("acct", "12125550099", 10_000))
    }

    @Test
    fun `the spend window is an hour, not a minute`() {
        val g = guard(calls = 100, destinations = 100, spend = 100_000)
        place(g, 9, { "121255500$it" }, micros = 10_000)

        now += 120_000   // two minutes: past the call window, well inside the hour
        assertNotNull(g.check("acct", "12125550099", 20_000), "the hourly spend was forgotten in two minutes")

        now += 3_600_000
        assertNull(g.check("acct", "12125550099", 20_000))
    }

    // -- operating it --------------------------------------------------------

    @Test
    fun `an operator can clear an account that has been dealt with`() {
        val g = guard(calls = 3)
        place(g, 3, { "1212555${it}" })
        assertNotNull(g.check("acct", "12125559999"))

        g.clear("acct")
        assertNull(g.check("acct", "12125559999"), "clearing did not release the account")
    }

    @Test
    fun `one account's burst does not refuse another's calls`() {
        val g = guard(calls = 3)
        place(g, 3, { "1212555${it}" })
        assertNotNull(g.check("acct", "12125559999"))
        assertNull(g.check("someone-else", "12125559999"), "the limit was global, not per account")
    }

    @Test
    fun `a nonsense limit is refused at construction`() {
        // Rather than at 3am, as an account that can never place a call.
        assertFailsWith<IllegalArgumentException> { FraudGuard.Limits(maxCallsPerMinute = 0) }
        assertFailsWith<IllegalArgumentException> { FraudGuard.Limits(maxDestinationsPerMinute = 0) }
        assertFailsWith<IllegalArgumentException> { FraudGuard.Limits(maxSpendPerHourMicros = -1) }
    }

    @Test
    fun `the window does not grow without bound on a busy account`() {
        // The prune is what makes this safe to run per call for the life of the
        // process. Without it a busy account leaks memory on the hot path --
        // reached by being busy, which is exactly when it must not happen.
        val g = guard(calls = 1000, destinations = 1000)
        repeat(20) {
            place(g, 50, { i -> "1212555$i" })
            now += 61_000
        }
        // If nothing were pruned this account would hold 1000 events and the
        // next call would be refused on the call limit.
        assertNull(g.check("acct", "12125559999"))
    }

    @Test
    fun `the trip says enough to act on without saying it to the caller`() {
        val g = guard(calls = 2)
        place(g, 2, { "1212555${it}" })
        val trip = g.check("acct", "12125559999")!!

        assertTrue(trip.detail.contains("acct"), "the operator cannot tell whose account it was")
        assertTrue(trip.detail.contains("calls-per-minute"))
        assertTrue(trip.detail.contains("2"))
    }

    @Test
    fun `the alert names the account the operator knows, not its internal id`() {
        // The first live run printed "cust-1786398571251-4c73 hit
        // destinations-per-minute", which an operator has to go and look up
        // before it means anything -- at the one moment they are in a hurry.
        val g = guard(calls = 1)
        assertNull(g.check("cust-1786398571251-4c73", "12125550001", 0, "bigcorp"))
        g.record("cust-1786398571251-4c73", "12125550001", 0)

        val trip = g.check("cust-1786398571251-4c73", "12125550002", 0, "bigcorp")!!
        assertTrue(trip.detail.startsWith("bigcorp "), "the alert reads: ${trip.detail}")
        // The id is still what it keys on -- a handle can be reassigned.
        assertEquals("cust-1786398571251-4c73", trip.accountId)
    }

    @Test
    fun `an account with no label is still printable`() {
        val g = guard(calls = 1)
        g.record("acct", "12125550001", 0)
        assertTrue(g.check("acct", "12125550002")!!.detail.startsWith("acct "))
    }
}
