package net.megatron.bot

import net.megatron.provisioning.BalanceAdjustment
import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.Customer
import net.megatron.provisioning.CustomerPage
import net.megatron.provisioning.CustomerStatus
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.Store
import net.megatron.provisioning.Transaction
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Second hostile pass on the bot: attacks aimed at the FIXES.
 */
class FixRegressionHostileTest {

    private val operator = 111L

    /** Delegates everything, and fails the next adjustBalance exactly once. */
    private class FlakyStore(private val real: Store) : Store by real {
        var failNextAdjust = false
        var failNextCreate = false

        override fun adjustBalance(
            id: String,
            request: BalanceAdjustment,
            actor: String,
        ): Transaction {
            if (failNextAdjust) {
                failNextAdjust = false
                // A transient store fault: SQLITE_BUSY, a full disk, a dropped
                // connection. Not Invalid, not NotFound — nothing the operator
                // did wrong.
                throw java.sql.SQLException("database is locked")
            }
            return real.adjustBalance(id, request, actor)
        }

        override fun createCustomer(
            request: CreateCustomer,
            actor: String,
        ): Pair<Customer, net.megatron.provisioning.SipCredentials> {
            if (failNextCreate) {
                failNextCreate = false
                throw java.sql.SQLException("disk I/O error")
            }
            return real.createCustomer(request, actor)
        }
    }

    private fun seed(): Pair<InMemoryStore, String> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.createCustomer(CreateCustomer("acme", plan.id, telegramUserId = 222L), "test")
        return store to plan.id
    }

    // -- claimOnce ordering ---------------------------------------------------

    /**
     * THE KEY IS CONSUMED BY A MUTATION THAT DID NOT HAPPEN.
     *
     * Commands.kt:396 claims the key, then calls store.adjustBalance. The
     * claim is committed on its own (SqlStore.claimOnce is a bare autocommit
     * INSERT, outside adjustBalance's transaction), so if the mutation fails
     * the claim survives it.
     *
     * The scenario that matters is the exact one claimOnce was added for: the
     * bot dies before acknowledging the update, so Telegram redelivers the
     * SAME message with the SAME chat/message id, hence the SAME key. On
     * redelivery the claim is already taken and the operator is told "Already
     * done". The credit is dropped permanently and the reply says it was
     * handled before.
     *
     * A claim must be released when the operation it guards fails, or taken
     * inside the same transaction as the mutation.
     */
    @Test
    fun `a credit whose store call failed is not blocked from being retried`() {
        val (real, _) = seed()
        val store = FlakyStore(real)
        val customer = real.findByHandle("acme")!!
        val engine = CommandEngine(store, Roles(setOf(operator)))

        store.failNextAdjust = true
        val first = engine.handle(operator, 500L, 9L, "/credit acme 5.00 lab top-up")
        // Same message, redelivered after the bot restarted.
        val second = engine.handle(operator, 500L, 9L, "/credit acme 5.00 lab top-up")

        assertEquals(
            5_000_000L,
            real.getCustomer(customer.id).balanceMicros,
            "the credit was lost: first reply was \"$first\", the redelivery was " +
                "\"$second\" — the key was consumed by an attempt that changed nothing",
        )
    }

    /** Same hole on the other guarded command. */
    @Test
    fun `a newuser whose store call failed is not blocked from being retried`() {
        val (real, plan) = seed()
        val store = FlakyStore(real)
        val engine = CommandEngine(store, Roles(setOf(operator)))

        store.failNextCreate = true
        engine.handle(operator, 500L, 9L, "/newuser bravo $plan")
        engine.handle(operator, 500L, 9L, "/newuser bravo $plan")

        assertTrue(
            real.findByHandle("bravo") != null,
            "the account was never created and the redelivery was refused as " +
                "\"already done\"",
        )
    }

    /** The claim must still work when the mutation SUCCEEDS. This one passes. */
    @Test
    fun `a successful credit is still claimed exactly once`() {
        val (store, _) = seed()
        val customer = store.findByHandle("acme")!!
        val engine = CommandEngine(store, Roles(setOf(operator)))

        engine.handle(operator, 500L, 9L, "/credit acme 5.00 lab top-up")
        engine.handle(operator, 500L, 9L, "/credit acme 5.00 lab top-up")

        assertEquals(5_000_000L, store.getCustomer(customer.id).balanceMicros)
    }

    // -- the backoff ----------------------------------------------------------

    /**
     * THE SPIN COMES BACK AT pollSeconds = 0.
     *
     * run() calls a poll "suspicious" when `elapsedMs < pollSeconds * 250L`.
     * With pollSeconds = 0 that threshold is 0, so no poll is ever suspicious,
     * backoff is never armed, and the loop is exactly the hot loop the fix
     * removed.
     *
     * bot/Main.kt reads it straight from the environment with no floor:
     *   `System.getenv("MEGATRON_TELEGRAM_POLL_SECONDS")?.toIntOrNull() ?: 30`
     * so MEGATRON_TELEGRAM_POLL_SECONDS=0 — a plausible "turn off long polling"
     * setting — restores it. A negative value does the same.
     */
    @Test
    fun `the backoff still engages when the poll timeout is configured to zero`() {
        // REWRITTEN to be bounded by WALL CLOCK rather than by poll count.
        //
        // The original stopped the loop after 5000 polls, which was reachable
        // only while the defect existed: without a backoff the loop managed
        // 5000 polls in 42ms. Once the backoff works it never reaches that
        // count at all — it widens to 30s per poll — so the test hung instead
        // of passing. A test whose exit condition depends on the bug being
        // present cannot observe the fix.
        //
        // The property is a bound on RATE, so it is measured over a fixed
        // second.
        val polls = java.util.concurrent.atomic.AtomicInteger()
        val fake = object : TelegramApi {
            override fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming> {
                polls.incrementAndGet()
                return emptyList()   // what a 429 looks like from the transport
            }
            override fun sendMessage(chatId: Long, text: String) = true
        }
        val (store, _) = seed()

        val loop = BotLoop(
            fake, CommandEngine(store, Roles(setOf(operator))), pollSeconds = 0, log = { },
        )
        val thread = Thread { loop.run() }
        thread.isDaemon = true
        thread.start()
        Thread.sleep(1_000)
        thread.interrupt()
        thread.join(5_000)

        assertTrue(
            polls.get() in 1..20,
            "${polls.get()} polls in one second at pollSeconds=0: the backoff threshold " +
                "was pollSeconds*250, which is zero, so nothing was ever judged " +
                "suspicious and the loop spun",
        )
    }

    /** The backoff must not sleep through traffic. This one passes. */
    @Test
    fun `a batch of real updates clears the backoff immediately`() {
        val (store, _) = seed()
        var served = 0
        val fake = object : TelegramApi {
            override fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming> {
                served++
                // Three instant empty polls arm the backoff, then real traffic.
                if (served <= 3) return emptyList()
                if (served == 4) {
                    return listOf(Incoming(1, operator, operator, 1, "/help", "private"))
                }
                Thread.currentThread().interrupt()
                return emptyList()
            }
            override fun sendMessage(chatId: Long, text: String) = true
        }

        val started = System.nanoTime()
        BotLoop(fake, CommandEngine(store, Roles(setOf(operator))), pollSeconds = 30, log = { })
            .run()
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        // 250 + 500 + 1000 = 1750ms of backoff before the traffic, then it
        // must reset rather than keep doubling.
        assertTrue(
            elapsedMs < 5_000,
            "the loop spent ${elapsedMs}ms; a batch of real updates did not reset " +
                "the backoff",
        )
    }

    // -- formatMoney ----------------------------------------------------------

    /**
     * formatMoney negates without checking, so Long.MIN_VALUE stays negative
     * and every subsequent division and modulo produces a negative digit
     * group. The result is "--9223372036854.-775808": two minus signs, a minus
     * inside the fraction, and nothing parseMoney will accept.
     *
     * Reachable: a balance of -Long.MAX_VALUE plus one more micro-unit of debit
     * is an EXACT addition, so Math.addExact permits it and the balance becomes
     * Long.MIN_VALUE. /balance then renders garbage to the customer.
     */
    @Test
    fun `formatMoney survives the most negative balance`() {
        val rendered = formatMoney(Long.MIN_VALUE, "USD")
        assertTrue(
            Regex("^-?\\d+\\.\\d{1,6} USD$").matches(rendered),
            "formatMoney(Long.MIN_VALUE) produced '$rendered'",
        )
    }

    /**
     * Everything formatMoney emits must be something parseMoney reads back to
     * the same number, or an operator cannot copy a balance into a /credit.
     * This one PASSES for every ordinary value; it is here so it keeps
     * passing.
     */
    @Test
    fun `formatMoney round-trips through parseMoney`() {
        val values = listOf(
            0L, 1L, 9L, 5_000L, 10_000L, 999_999L, 1_000_000L, 1_000_001L,
            1_000_010L, 25_500_000L, -5_000L, -1L, -25_500_000L,
            Long.MAX_VALUE, -Long.MAX_VALUE,
        )
        values.forEach { micros ->
            val text = formatMoney(micros)
            assertEquals(micros, parseMoney(text), "'$text' did not round-trip from $micros")
        }
    }
}
