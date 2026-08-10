package net.megatron.bot

import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.InMemoryStore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The three defects a hostile review found in how the bot talks to a human:
 * a documented command that did not exist, a money display that reported real
 * movements as nothing, and an error that produced silence.
 */
class RotateAndFormatTest {

    private val operator = 111L
    private val stranger = 999L

    private fun engine(): Pair<CommandEngine, InMemoryStore> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.createCustomer(
            CreateCustomer("acme", plan.id, telegramUserId = 222L, openingBalanceMicros = 0),
            "test",
        )
        return CommandEngine(store, Roles(setOf(operator))) to store
    }

    private var message = 0L
    private fun send(engine: CommandEngine, from: Long, text: String) =
        engine.reply(from, from, ++message, text)

    // -- /rotate ---------------------------------------------------------------

    @Test
    fun `rotate issues a new password that actually replaces the old one`() {
        // SubscriberExport tells customers with no stored credential that
        // "rotation is a Telegram command away". It was not: rotation existed
        // only on the HTTP API, so the documented recovery from "your
        // customers cannot register" was a dead end.
        val (bot, store) = engine()
        val before = store.sipDigestHa1("acme", "sip.megatron.local")

        val reply = send(bot, operator, "/rotate acme")

        assertTrue(reply.text.contains("New password for acme"), reply.text)
        assertTrue(reply.text.contains("Password:"), reply.text)
        assertNotEquals(
            before,
            store.sipDigestHa1("acme", "sip.megatron.local"),
            "the old password would still register",
        )
    }

    @Test
    fun `a rotated password is a secret, so it never goes to a group`() {
        // The reply carries a working login for the switch. If /rotate were
        // left off the secret list it would be the one credential-bearing
        // command that posts into permanent group history.
        val (bot, _) = engine()
        assertTrue(send(bot, operator, "/rotate acme").containsSecret)
    }

    @Test
    fun `rotate is operator-only and indistinguishable from a nonexistent command`() {
        val (bot, _) = engine()
        assertEquals(
            send(bot, stranger, "/nosuchthing").text,
            send(bot, stranger, "/rotate acme").text,
        )
    }

    @Test
    fun `rotate without a handle explains itself rather than crashing`() {
        val (bot, _) = engine()
        assertTrue(send(bot, operator, "/rotate").text.contains("Use:"))
    }

    @Test
    fun `rotate appears in the operator help, since it is now real`() {
        val (bot, _) = engine()
        assertTrue(send(bot, operator, "/help").text.contains("/rotate"))
        assertTrue(!send(bot, 222L, "/help").text.contains("/rotate"))
    }

    // -- money that a human reads ---------------------------------------------

    @Test
    fun `a sub-cent movement is not reported as nothing`() {
        // Telephony rates are routinely fractions of a cent. Truncating to two
        // decimals made a real credit of 5,000 micros reply "0.00 -> balance
        // 0.00" -- the operator's only confirmation saying it did nothing,
        // which invites them to run it again.
        assertEquals("0.005", formatMoney(5_000))
        assertEquals("0.0005", formatMoney(500))
        assertEquals("1.234567", formatMoney(1_234_567))
    }

    @Test
    fun `ordinary amounts still read as ordinary money`() {
        // The precision only appears when two decimals would lie. An everyday
        // balance must not suddenly grow a tail.
        assertEquals("25.00 USD", formatMoney(25_000_000, "USD"))
        assertEquals("0.00", formatMoney(0))
        assertEquals("1.50", formatMoney(1_500_000))
        assertEquals("-4.25", formatMoney(-4_250_000))
        assertEquals("-0.005", formatMoney(-5_000))
    }

    @Test
    fun `a real sub-cent credit shows the movement in the reply`() {
        val (bot, store) = engine()
        val reply = send(bot, operator, "/credit acme 0.005 promo").text
        assertTrue(!reply.contains("0.00 ->"), "the reply says nothing happened: $reply")
        assertEquals(5_000L, store.findByHandle("acme")!!.balanceMicros)
    }

    // -- nothing reaches the operator as silence ------------------------------

    @Test
    fun `an amount too large to handle gets an answer, not silence`() {
        // parseMoney throws ArithmeticException, which used to escape to the
        // transport and be logged as "dropped update" with no reply sent. An
        // operator who gets no answer retries, which on a money command is the
        // worst possible response to an error.
        // Two different overflows, two different exception types, and neither
        // may reach the transport as an unhandled throw: one fails in
        // Long.parseLong, the other in Math.multiplyExact.
        val (bot, store) = engine()
        listOf("99999999999999999999", "9999999999999").forEach { amount ->
            val reply = send(bot, operator, "/credit acme $amount x").text
            assertTrue(reply.isNotBlank(), "the operator got silence for $amount")
            assertTrue(reply.contains("too large", ignoreCase = true), "$amount -> $reply")
        }
        assertEquals(
            0L,
            store.findByHandle("acme")!!.balanceMicros,
            "a rejected amount still moved the balance",
        )
    }

    @Test
    fun `a credit that would overflow the balance is refused with an explanation`() {
        val (bot, store) = engine()
        val customer = store.findByHandle("acme")!!
        store.adjustBalance(
            customer.id,
            net.megatron.provisioning.BalanceAdjustment(Long.MAX_VALUE - 10, "seeding the edge"),
            "test",
        )

        val reply = send(bot, operator, "/credit acme 9000000000 topping up").text

        assertTrue(reply.isNotBlank(), "the operator got silence")
        assertTrue(reply.contains("overflow"), reply)
        assertEquals(
            Long.MAX_VALUE - 10,
            store.getCustomer(customer.id).balanceMicros,
            "a refused credit still moved the balance",
        )
    }
}
