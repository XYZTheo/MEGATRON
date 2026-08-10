package net.megatron.bot

import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.Store
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The transport, against a fake Telegram.
 *
 * The previous version of this file did not exist, on the reasoning that a
 * transport cannot be tested without a bot token and a network. That was
 * wrong: what cannot be tested without them is *api.telegram.org*, and that is
 * not where the dangerous behaviour lives. The offset arithmetic below is, and
 * it moves money.
 */
class BotLoopTest {

    private val operator = 111L
    private val stranger = 999L

    /**
     * Records what was sent and serves scripted updates.
     *
     * Deliberately not a mocking library: what these tests need to assert is
     * ordering and repetition, and a recorded list says that plainly.
     */
    private class FakeTelegram(vararg batches: List<Incoming>) : TelegramApi {
        private val queued = batches.toMutableList()
        val sent = mutableListOf<Pair<Long, String>>()

        /** Chats that reject a send. Telegram forbids DMing a user who has
         *  never started the bot, which is the case that matters. */
        val rejects = mutableSetOf<Long>()
        var sendThrows = false
        var lastOffset = -1L

        /** Every update ever handed out, so redelivery is visible. */
        val served = mutableListOf<Long>()

        override fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming> {
            lastOffset = offset
            val batch = queued.removeFirstOrNull() ?: return emptyList()
            // Telegram's real contract: anything below the offset is
            // acknowledged and gone; anything at or above it is delivered
            // again until it is acknowledged.
            val live = batch.filter { it.updateId >= offset }
            served += live.map { it.updateId }
            return live
        }

        override fun sendMessage(chatId: Long, text: String): Boolean {
            if (sendThrows) throw IllegalStateException("telegram exploded")
            sent += chatId to text
            return chatId !in rejects
        }
    }

    private fun seed(): Pair<Store, String> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.createCustomer(
            CreateCustomer("acme", plan.id, telegramUserId = 222L, openingBalanceMicros = 0),
            "test",
        )
        return store to plan.id
    }

    private fun message(
        updateId: Long,
        text: String,
        from: Long = operator,
        chatId: Long = from,
        chatType: String = "private",
    ) = Incoming(updateId, from, chatId, updateId, text, chatType)

    // -- the offset -----------------------------------------------------------

    @Test
    fun `the offset advances past every update taken from the queue`() {
        val telegram = FakeTelegram(listOf(message(7, "/help"), message(8, "/help")))
        val (store, _) = seed()
        val loop = BotLoop(telegram, CommandEngine(store, Roles(setOf(operator))))

        assertEquals(2, loop.pollOnce())
        loop.pollOnce()
        assertEquals(9, telegram.lastOffset, "the next poll would replay update 8")
    }

    @Test
    fun `a command that moves money is never served twice`() {
        // THE TEST THIS FILE EXISTS FOR.
        //
        // Telegram redelivers anything unacknowledged. An offset that does not
        // advance replays the batch forever, and if the batch contains
        // "/credit acme 500" that is not a stuck bot -- it is unbounded free
        // credit, issued once per polling interval, indefinitely.
        val (store, _) = seed()
        val customer = store.findByHandle("acme")!!
        val credit = listOf(message(1, "/credit acme 5.00 lab top-up"))
        // The same batch offered three times, exactly as Telegram would if the
        // offset never moved.
        val telegram = FakeTelegram(credit, credit, credit)
        val loop = BotLoop(telegram, CommandEngine(store, Roles(setOf(operator))))

        repeat(3) { loop.pollOnce() }

        assertEquals(listOf(1L), telegram.served, "the update was redelivered")
        assertEquals(
            5_000_000L,
            store.getCustomer(customer.id).balanceMicros,
            "the credit was applied more than once",
        )
    }

    @Test
    fun `an update whose handling throws still advances the offset`() {
        // Otherwise the poisonous message is served again on every poll and
        // the bot never processes anything else -- the whole business stops
        // because of one message it cannot handle. One lost command beats a
        // wedged bot, and beats an infinite loop of a command that moves
        // money.
        val (store, _) = seed()
        val telegram = FakeTelegram(
            listOf(message(4, "/help")),
            listOf(message(4, "/help"), message(5, "/help")),
        )
        telegram.sendThrows = true
        val loop = BotLoop(telegram, CommandEngine(store, Roles(setOf(operator))), log = { })

        loop.pollOnce()
        loop.pollOnce()

        assertEquals(
            1,
            telegram.served.count { it == 4L },
            "the update that threw was served again: ${telegram.served}",
        )
    }

    // -- secrets --------------------------------------------------------------

    @Test
    fun `a new user's password is never posted in a group`() {
        // Group history is permanent, searchable, and readable by members
        // added later. A SIP password there is a working login for the switch.
        val (store, plan) = seed()
        val telegram = FakeTelegram(
            listOf(message(1, "/newuser bravo $plan", chatId = -100L, chatType = "supergroup")),
        )
        BotLoop(telegram, CommandEngine(store, Roles(setOf(operator)))).pollOnce()

        val group = telegram.sent.filter { it.first == -100L }
        val direct = telegram.sent.filter { it.first == operator }

        assertEquals(1, direct.size, "the credential was not sent privately")
        assertTrue(direct.single().second.contains("bravo"), "the DM is not the credential")
        assertEquals(1, group.size)
        assertTrue(
            group.single().second.contains("privately"),
            "the group was not told where the reply went",
        )
        // The generated password must appear nowhere in the group message.
        val password = direct.single().second
            .lines().firstOrNull { it.contains("password", ignoreCase = true) } ?: ""
        assertTrue(
            password.isBlank() || !group.single().second.contains(password),
            "the password leaked into the group",
        )
    }

    @Test
    fun `when the private message fails the group gets instructions, not the password`() {
        // Telegram forbids a bot messaging a user who has never started it.
        // Falling back to posting the credential would defeat the check at
        // exactly the moment it is doing its job.
        val (store, plan) = seed()
        val telegram = FakeTelegram(
            listOf(message(1, "/newuser charlie $plan", chatId = -100L, chatType = "supergroup")),
        )
        telegram.rejects += operator
        BotLoop(telegram, CommandEngine(store, Roles(setOf(operator)))).pollOnce()

        val group = telegram.sent.single { it.first == -100L }.second
        assertTrue(group.contains("direct chat"), "the group was not told what to do")
        assertTrue(!group.contains("charlie"), "the credential leaked into the group")
    }

    @Test
    fun `a private newuser reply goes straight back`() {
        val (store, plan) = seed()
        val telegram = FakeTelegram(listOf(message(1, "/newuser delta $plan")))
        BotLoop(telegram, CommandEngine(store, Roles(setOf(operator)))).pollOnce()

        assertEquals(1, telegram.sent.size, "a private reply should not be duplicated")
        assertEquals(operator, telegram.sent.single().first)
    }

    @Test
    fun `a stranger's newuser is not treated as a secret`() {
        // It is refused, so there is no credential -- and routing a refusal to
        // a DM would tell a stranger the command exists, which is the same
        // enumeration leak the refusal text was made uniform to avoid.
        val (store, plan) = seed()
        val telegram = FakeTelegram(
            listOf(message(1, "/newuser echo $plan", from = stranger,
                           chatId = -100L, chatType = "supergroup")),
        )
        BotLoop(telegram, CommandEngine(store, Roles(setOf(operator)))).pollOnce()

        assertEquals(1, telegram.sent.size)
        assertEquals(-100L, telegram.sent.single().first, "the refusal was rerouted")
    }

    // -- rate limiting --------------------------------------------------------

    @Test
    fun `a flood from one user is stopped before the store is touched`() {
        val (store, _) = seed()
        val customer = store.findByHandle("acme")!!
        val flood = (1L..10L).map { message(it, "/credit acme 1.00 lab top-up") }
        val telegram = FakeTelegram(flood)
        val loop = BotLoop(
            telegram,
            CommandEngine(store, Roles(setOf(operator))),
            rateLimit = RateLimit(perMinute = 3),
            log = { },
        )
        loop.pollOnce()

        assertEquals(
            3_000_000L,
            store.getCustomer(customer.id).balanceMicros,
            "the limiter ran after the work instead of before it",
        )
    }

    @Test
    fun `the limit is per user, not per chat`() {
        // Otherwise anyone multiplies their allowance by opening more chats.
        val limit = RateLimit(perMinute = 2)
        assertTrue(limit.allow(operator))
        assertTrue(limit.allow(operator))
        assertTrue(!limit.allow(operator), "the same user got a third")
        assertTrue(limit.allow(stranger), "a different user was wrongly limited")
    }

    @Test
    fun `the window slides`() {
        var clock = 0L
        val limit = RateLimit(perMinute = 2, now = { clock })
        assertTrue(limit.allow(operator))
        assertTrue(limit.allow(operator))
        assertTrue(!limit.allow(operator))
        clock += 61_000
        assertTrue(limit.allow(operator), "the window never reopened")
    }

    // -- delivery failures ----------------------------------------------------

    @Test
    fun `a failed reply is loud, because the operator will otherwise retry`() {
        val (store, _) = seed()
        val telegram = FakeTelegram(listOf(message(1, "/help")))
        telegram.rejects += operator
        val logged = mutableListOf<String>()
        BotLoop(telegram, CommandEngine(store, Roles(setOf(operator))), log = { logged += it })
            .pollOnce()

        assertTrue(
            logged.any { it.contains("REPLY FAILED") },
            "a silently failed reply is indistinguishable from an ignored command",
        )
    }

    @Test
    fun `an empty poll is not an error`() {
        val (store, _) = seed()
        val telegram = FakeTelegram()
        assertEquals(0, BotLoop(telegram, CommandEngine(store, Roles(setOf(operator)))).pollOnce())
    }
}
