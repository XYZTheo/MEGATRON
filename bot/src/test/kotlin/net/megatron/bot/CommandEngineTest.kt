package net.megatron.bot

import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.InMemoryStore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CommandEngineTest {

    private val OPERATOR = 111L
    private val CUSTOMER = 222L
    private val STRANGER = 333L

    private fun engine(): Pair<CommandEngine, InMemoryStore> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.createCustomer(
            CreateCustomer(
                handle = "bigcorp",
                planId = plan.id,
                telegramUserId = CUSTOMER,
                openingBalanceMicros = 25_000_000,
            ),
            "seed",
        )
        return CommandEngine(store, Roles(setOf(OPERATOR))) to store
    }

    private fun CommandEngine.send(user: Long, text: String, message: Long = 1) =
        handle(user, chatId = user, messageId = message, text = text)

    // -- the authorization boundary ----------------------------------------

    @Test
    fun `a stranger cannot use operator commands`() {
        val (bot, _) = engine()
        val reply = bot.send(STRANGER, "/credit bigcorp 100 free money")
        assertFalse(reply.contains("balance"), reply)
        assertTrue(reply.contains("Unknown command"), reply)
    }

    @Test
    fun `a customer cannot use operator commands either`() {
        // Being a customer is not being an operator. This is the difference
        // between a bot that manages the business and unlimited free credit.
        val (bot, store) = engine()
        bot.send(CUSTOMER, "/credit bigcorp 1000 topping myself up")
        val customer = store.findByHandle("bigcorp")!!
        assertEquals(25_000_000L, customer.balanceMicros, "a customer credited themselves")
    }

    @Test
    fun `an operator-only command is indistinguishable from a nonexistent one`() {
        // Telling a stranger that /credit exists but is not for them is
        // telling them what to go looking for.
        val (bot, _) = engine()
        assertEquals(
            bot.send(STRANGER, "/nosuchthing"),
            bot.send(STRANGER, "/credit bigcorp 100 x"),
        )
    }

    @Test
    fun `help shows operator commands only to operators`() {
        val (bot, _) = engine()
        assertTrue(bot.send(OPERATOR, "/help").contains("/newuser"))
        assertFalse(bot.send(CUSTOMER, "/help").contains("/newuser"))
    }

    // -- the workflow -------------------------------------------------------

    @Test
    fun `an operator creates a login and gets the password once`() {
        val (bot, store) = engine()
        val planId = store.listPlans().first().id
        val reply = bot.send(OPERATOR, "/newuser newco $planId")
        assertTrue(reply.contains("Created newco"), reply)
        assertTrue(reply.contains("Password:"), reply)
        assertTrue(reply.contains("shown once"), reply)

        // And it really is not retrievable afterwards.
        val later = bot.send(OPERATOR, "/who newco")
        assertFalse(later.contains("Password"), later)
    }

    @Test
    fun `an operator credits a customer`() {
        val (bot, store) = engine()
        val reply = bot.send(OPERATOR, "/credit bigcorp 10.50 bank transfer")
        assertTrue(reply.contains("35.50"), reply)
        assertEquals(35_500_000L, store.findByHandle("bigcorp")!!.balanceMicros)
    }

    @Test
    fun `a customer checks their own balance`() {
        val (bot, _) = engine()
        val reply = bot.send(CUSTOMER, "/balance")
        assertTrue(reply.contains("25.00 USD"), reply)
    }

    @Test
    fun `an unlinked telegram account is told so, not shown someone elses balance`() {
        val (bot, _) = engine()
        val reply = bot.send(STRANGER, "/balance")
        assertTrue(reply.contains("not linked"), reply)
        assertFalse(reply.contains("25.00"), reply)
    }

    @Test
    fun `a customer sets their own caller id`() {
        val (bot, store) = engine()
        val reply = bot.send(CUSTOMER, "/cli +441632960123")
        assertTrue(reply.contains("+441632960123"), reply)
        assertEquals("+441632960123", store.findByHandle("bigcorp")!!.callerId?.number)
    }

    @Test
    fun `a bad caller id is refused with an explanation`() {
        val (bot, _) = engine()
        val reply = bot.send(CUSTOMER, "/cli 07700900123")
        assertTrue(reply.contains("E.164"), reply)
    }

    @Test
    fun `suspending stops the customer and says why`() {
        val (bot, store) = engine()
        val reply = bot.send(OPERATOR, "/suspend bigcorp non payment")
        assertTrue(reply.contains("suspended"), reply)
        assertTrue(reply.contains("non payment"), reply)
        // The customer is told plainly, rather than left wondering why calls fail.
        assertTrue(bot.send(CUSTOMER, "/balance").contains("suspended"))
    }

    // -- money parsing, where a typo becomes real money ---------------------

    @Test
    fun `amounts are parsed exactly, without floating point`() {
        assertEquals(25_000_000L, parseMoney("25"))
        assertEquals(25_500_000L, parseMoney("25.50"))
        assertEquals(100_000L, parseMoney("0.1"))     // exact; a Double is not
        assertEquals(1L, parseMoney("0.000001"))
        assertEquals(-5_000_000L, parseMoney("-5"))
        assertEquals(25_000_000L, parseMoney("+25"))
    }

    @Test
    fun `a nonsense amount is refused rather than guessed`() {
        for (bad in listOf("abc", "25,50", "1e6", "25.1234567", "", "£25", "25 50")) {
            val thrown = runCatching { parseMoney(bad) }.isFailure
            assertTrue(thrown, "'$bad' was accepted as an amount")
        }
    }

    @Test
    fun `a credit with a nonsense amount does not move the balance`() {
        val (bot, store) = engine()
        val reply = bot.send(OPERATOR, "/credit bigcorp 1e6 oops")
        assertTrue(reply.contains("not an amount"), reply)
        assertEquals(25_000_000L, store.findByHandle("bigcorp")!!.balanceMicros)
    }

    @Test
    fun `money formatting shows cents, and more when cents would lie`() {
        // REWRITTEN. This previously asserted formatMoney(129_999) == "0.12",
        // pinning truncation as intended behaviour. It is not: telephony rates
        // are routinely fractions of a cent, so truncating made a real credit
        // of 5,000 micros reply "0.00 -> balance 0.00" — the operator's only
        // confirmation of a money command saying nothing happened.
        //
        // Two decimals when they are exact; every digit when they are not.
        assertEquals("25.00 USD", formatMoney(25_000_000, "USD"))
        assertEquals("-3.50", formatMoney(-3_500_000))
        assertEquals("0.129999", formatMoney(129_999))
    }

    // -- command parsing ----------------------------------------------------

    @Test
    fun `commands survive group chat suffixes and extra whitespace`() {
        assertEquals(Command("balance", emptyList()), parseCommand("/balance@MegatronBot"))
        assertEquals(Command("credit", listOf("a", "1")), parseCommand("  /credit   a   1  "))
        assertEquals(null, parseCommand("just talking"))
        assertEquals(null, parseCommand("/"))
    }

    @Test
    fun `a reason with several words survives`() {
        val (bot, _) = engine()
        val reply = bot.send(OPERATOR, "/credit bigcorp 5 paid cash at the shop")
        assertTrue(reply.contains("30.00"), reply)
    }

    // -- missing arguments --------------------------------------------------

    @Test
    fun `missing arguments produce usage, not a crash`() {
        val (bot, _) = engine()
        assertTrue(bot.send(OPERATOR, "/credit").contains("Use:"))
        assertTrue(bot.send(OPERATOR, "/newuser").contains("Use:"))
        assertTrue(bot.send(OPERATOR, "/who").contains("Use:"))
        assertTrue(bot.send(CUSTOMER, "/cli").contains("/cli"))
    }

    @Test
    fun `an unknown customer is reported, not silently ignored`() {
        val (bot, _) = engine()
        assertTrue(bot.send(OPERATOR, "/credit ghost 10 x").contains("Not found"))
    }
}
