package net.megatron.authorizer

import net.megatron.rating.Micros
import net.megatron.rating.Rate
import net.megatron.rating.RateTable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class AuthorizerTest {

    private val rates = RateTable.of(
        listOf(
            // $0.60/min = 1000 micros/second, per-second billing.
            Rate(prefix = "1", sellPerMinute = Micros(60_000), incrementSeconds = 1),
            Rate(prefix = "44", sellPerMinute = Micros(12_000), incrementSeconds = 60,
                 minimumSeconds = 60),
        )
    )

    private fun setup(
        balance: Micros,
        mode: BillingMode = BillingMode.PREPAID,
        maxConcurrent: Int = 2,
        creditLimit: Micros = Micros.ZERO,
        suspended: Boolean = false,
    ): Pair<Ledger, Account> {
        val ledger = Ledger()
        val account = Account("acct-1", balance, mode, creditLimit, maxConcurrent, suspended)
        ledger.open(account.id, balance)
        return ledger to account
    }

    // -- the happy path -----------------------------------------------------

    @Test
    fun `a funded account is allowed and gets a session timer`() {
        val (ledger, account) = setup(Micros.ofUnits(1))   // $1.00
        val decision = Authorizer(ledger).authorize(account, "12125551234", rates, "r1")
        val allow = assertIs<Decision.Allow>(decision)
        // $1.00 at 1000 micros/sec = 1000 seconds.
        assertEquals(1_000, allow.maxSeconds)
        assertEquals("1", allow.prefix)
        assertTrue(allow.reserved.value <= Micros.ofUnits(1).value)
    }

    @Test
    fun `a short call returns the unused reservation`() {
        val (ledger, account) = setup(Micros.ofUnits(1))
        val auth = Authorizer(ledger)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r1"))

        // Talked for 10 seconds of the 1000 granted.
        val settlement = auth.settle("r1", 10, "12125551234", rates)
        assertEquals(10_000L, settlement.charged.value)          // 10s * 1000
        assertEquals(990_000L, settlement.returned.value)        // the rest comes back
        assertEquals(990_000L, settlement.balanceAfter.value)
        assertEquals(false, settlement.overran)
        assertEquals(0, ledger.activeCalls(account.id))
    }

    @Test
    fun `an abandoned call charges nothing and frees the hold`() {
        val (ledger, account) = setup(Micros.ofUnits(1))
        val auth = Authorizer(ledger)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r1"))
        assertEquals(true, auth.abandon("r1"))
        assertEquals(Micros.ofUnits(1).value, ledger.balanceOf(account.id).value)
        assertEquals(0, ledger.activeCalls(account.id))
        assertEquals(Micros.ofUnits(1).value, ledger.availableTo(account).value)
    }

    // -- refusals -----------------------------------------------------------

    @Test
    fun `an empty balance is refused, not carried`() {
        val (ledger, account) = setup(Micros.ZERO)
        val decision = Authorizer(ledger).authorize(account, "12125551234", rates, "r1")
        assertEquals(Refusal.INSUFFICIENT_BALANCE, assertIs<Decision.Reject>(decision).reason)
    }

    @Test
    fun `a suspended account is refused before anything else is computed`() {
        val (ledger, account) = setup(Micros.ofUnits(100), suspended = true)
        val decision = Authorizer(ledger).authorize(account, "12125551234", rates, "r1")
        assertEquals(Refusal.ACCOUNT_SUSPENDED, assertIs<Decision.Reject>(decision).reason)
    }

    @Test
    fun `an unrated destination is refused rather than carried at unknown cost`() {
        // The expensive mistake: carrying traffic you have no price for. This
        // is how a switch discovers it has been terminating satellite calls
        // for a week.
        val (ledger, account) = setup(Micros.ofUnits(100))
        val decision = Authorizer(ledger).authorize(account, "99912345678", rates, "r1")
        assertEquals(Refusal.NO_RATE_FOR_DESTINATION,
                     assertIs<Decision.Reject>(decision).reason)
    }

    @Test
    fun `a destination with no digits is refused`() {
        val (ledger, account) = setup(Micros.ofUnits(100))
        val decision = Authorizer(ledger).authorize(account, "+++", rates, "r1")
        assertEquals(Refusal.INVALID_DESTINATION, assertIs<Decision.Reject>(decision).reason)
    }

    @Test
    fun `the concurrent call limit is enforced`() {
        // Most VoIP fraud is a compromised endpoint placing many simultaneous
        // calls, not one long one. This cap is what bounds the loss.
        val (ledger, account) = setup(Micros.ofUnits(100), maxConcurrent = 2)
        val auth = Authorizer(ledger)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r1"))
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r2"))
        val third = auth.authorize(account, "12125551234", rates, "r3")
        assertEquals(Refusal.CONCURRENT_CALL_LIMIT, assertIs<Decision.Reject>(third).reason)
    }

    // -- the bug this design exists to prevent ------------------------------

    @Test
    fun `simultaneous calls cannot spend the same balance twice`() {
        // A customer with enough for exactly ONE call places six at once.
        // Without reserve-then-debit every one of them sees a sufficient
        // balance and all six are authorized -- and on a stolen account "six"
        // is "six hundred". This is the single most expensive bug available
        // in prepaid telephony, and it is a concurrency bug.
        //
        // $0.06 at 1000 micros/sec, 60s minimum-ish: enough for one 60s call
        // at most. Concurrency cap raised so the LIMIT under test is money.
        val balance = Micros(60_000)
        val (ledger, account) = setup(balance, maxConcurrent = 100)
        val auth = Authorizer(ledger, ceilingSeconds = 60)

        val threads = 6
        val start = CountDownLatch(1)
        val allowed = AtomicInteger()
        val pool = Executors.newFixedThreadPool(threads)
        repeat(threads) { i ->
            pool.submit {
                start.await()
                val d = auth.authorize(account, "12125551234", rates, "r$i")
                if (d is Decision.Allow) allowed.incrementAndGet()
            }
        }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS), "authorize deadlocked")

        assertEquals(1, allowed.get(),
            "six simultaneous calls on a one-call balance authorized ${allowed.get()}")
        assertTrue(ledger.availableTo(account).value >= 0,
            "available balance went negative: ${ledger.availableTo(account).value}")
    }

    @Test
    fun `reserved money is invisible to the next call`() {
        val (ledger, account) = setup(Micros(120_000), maxConcurrent = 10)
        val auth = Authorizer(ledger, ceilingSeconds = 60)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r1"))
        // 60s at 1000/s reserved 60_000, leaving 60_000 available.
        assertEquals(60_000L, ledger.availableTo(account).value)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r2"))
        assertEquals(0L, ledger.availableTo(account).value)
        // Nothing left for a third, even though the raw balance is untouched.
        assertEquals(120_000L, ledger.balanceOf(account.id).value)
        val third = auth.authorize(account, "12125551234", rates, "r3")
        assertEquals(Refusal.INSUFFICIENT_BALANCE, assertIs<Decision.Reject>(third).reason)
    }

    // -- replay safety ------------------------------------------------------

    @Test
    fun `settling twice does not debit twice`() {
        // A BYE can be retransmitted and a CDR can be replayed. Neither may
        // charge the customer a second time.
        val (ledger, account) = setup(Micros.ofUnits(1))
        val auth = Authorizer(ledger)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r1"))

        val first = auth.settle("r1", 10, "12125551234", rates)
        val second = auth.settle("r1", 10, "12125551234", rates)
        assertEquals(first, second)
        assertEquals(990_000L, ledger.balanceOf(account.id).value)
    }

    @Test
    fun `settling something never reserved is refused, not silently charged`() {
        val (ledger, _) = setup(Micros.ofUnits(1))
        assertFailsWith<IllegalStateException> {
            Authorizer(ledger).settle("never-existed", 10, "12125551234", rates)
        }
    }

    // -- overrun ------------------------------------------------------------

    @Test
    fun `a call that outruns its reservation is charged and flagged`() {
        // A session timer can be missed. The customer is still charged what
        // the call cost, and `overran` records it -- a switch that overruns
        // often is one whose timers are not working, which is a leak worth
        // seeing rather than absorbing.
        val (ledger, account) = setup(Micros(60_000), maxConcurrent = 10)
        val auth = Authorizer(ledger, ceilingSeconds = 60)
        assertIs<Decision.Allow>(auth.authorize(account, "12125551234", rates, "r1"))

        val settlement = auth.settle("r1", 90, "12125551234", rates)  // 30s over
        assertEquals(90_000L, settlement.charged.value)
        assertEquals(true, settlement.overran)
        assertEquals(0L, settlement.returned.value)
        assertEquals(-30_000L, settlement.balanceAfter.value)
    }

    // -- postpaid -----------------------------------------------------------

    @Test
    fun `postpaid may run past zero, up to its credit limit`() {
        val (ledger, account) = setup(
            Micros.ZERO,
            mode = BillingMode.POSTPAID,
            creditLimit = Micros.ofUnits(10),
        )
        val decision = Authorizer(ledger).authorize(account, "12125551234", rates, "r1")
        assertIs<Decision.Allow>(decision)
        assertEquals(FailDirection.OPEN, account.failDirection)
    }

    @Test
    fun `postpaid stops at its credit limit`() {
        val (ledger, account) = setup(
            Micros.ZERO,
            mode = BillingMode.POSTPAID,
            creditLimit = Micros.ZERO,
        )
        val decision = Authorizer(ledger).authorize(account, "12125551234", rates, "r1")
        assertEquals(Refusal.INSUFFICIENT_BALANCE, assertIs<Decision.Reject>(decision).reason)
    }

    @Test
    fun `prepaid fails closed and postpaid fails open, explicitly`() {
        // ARCHITECTURE 4.4: this must be explicit and must never happen by
        // accident, so it is asserted rather than assumed.
        assertEquals(
            FailDirection.CLOSED,
            Account("a", Micros.ZERO, BillingMode.PREPAID).failDirection
        )
        assertEquals(
            FailDirection.OPEN,
            Account("b", Micros.ZERO, BillingMode.POSTPAID).failDirection
        )
    }

    // -- minimum-duration plans --------------------------------------------

    @Test
    fun `a plan with a minimum duration reserves the whole minimum`() {
        // 44 is 60s minimum at 12_000/min. A balance of exactly 12_000 buys
        // exactly one 60-second call and nothing more.
        val (ledger, account) = setup(Micros(12_000), maxConcurrent = 10)
        val auth = Authorizer(ledger)
        val allow = assertIs<Decision.Allow>(
            auth.authorize(account, "442079460000", rates, "r1")
        )
        assertEquals(60, allow.maxSeconds)
        assertEquals(12_000L, allow.reserved.value)
        assertEquals(0L, ledger.availableTo(account).value)

        // Hanging up after 3 seconds still bills the 60-second minimum, so
        // nothing comes back.
        val settlement = auth.settle("r1", 3, "442079460000", rates)
        assertEquals(12_000L, settlement.charged.value)
        assertEquals(0L, settlement.returned.value)
    }
}
