package net.megatron.bot

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.InMemoryStore
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Hostile review of the Telegram transport.
 *
 * Each test tries to break one of the properties Main.kt's header claims the
 * bot holds.
 */
class BotHostileTest {

    private val operator = 111L

    private class Fake(vararg batches: List<Incoming>) : TelegramApi {
        private val queued = batches.toMutableList()
        val sent = mutableListOf<Pair<Long, String>>()
        val rejects = mutableSetOf<Long>()
        var polls = 0

        override fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming> {
            polls++
            val batch = queued.removeFirstOrNull() ?: return emptyList()
            return batch.filter { it.updateId >= offset }
        }

        override fun sendMessage(chatId: Long, text: String): Boolean {
            sent += chatId to text
            return chatId !in rejects
        }
    }

    private fun seed(): Pair<InMemoryStore, String> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.createCustomer(CreateCustomer("acme", plan.id, telegramUserId = 222L), "test")
        return store to plan.id
    }

    private fun message(
        updateId: Long,
        text: String,
        from: Long = operator,
        chatId: Long = from,
        chatType: String = "private",
    ) = Incoming(updateId, from, chatId, updateId, text, chatType)

    // -- redelivery across a restart ------------------------------------------

    /**
     * BotLoop.offset is a plain field, initialised to 0 and never persisted.
     * Telegram only considers an update acknowledged once a LATER getUpdates
     * carries the higher offset — so a restart between handling and the next
     * poll replays the whole unacknowledged batch.
     *
     * Both Telegram.kt and Main.kt say the idempotency key derived from
     * chat_id/message_id is what makes that safe. It is not: CommandEngine
     * passes `key` to BalanceAdjustment.reference, which is a free-text audit
     * field, and calls store.adjustBalance directly. IdempotencyStore is only
     * consulted by the HTTP server, which the bot does not go through. Nothing
     * deduplicates.
     */
    @Test
    fun `a credit redelivered after a restart is not applied twice`() {
        val (store, _) = seed()
        val customer = store.findByHandle("acme")!!
        val engine = CommandEngine(store, Roles(setOf(operator)))
        val credit = listOf(message(1, "/credit acme 5.00 lab top-up"))

        // The bot handles it, then dies before the next poll acknowledges it.
        BotLoop(Fake(credit), engine, log = { }).pollOnce()
        // It restarts. offset is back to 0, so Telegram serves it again.
        BotLoop(Fake(credit), engine, log = { }).pollOnce()

        assertEquals(
            5_000_000L,
            store.getCustomer(customer.id).balanceMicros,
            "the same /credit was applied twice: the chat/message idempotency key is " +
                "only written into the audit reference and never checked",
        )
    }

    /**
     * Same defect with no restart at all: two identical /credit messages carry
     * different message ids, but an operator's client retrying a send, or the
     * operator tapping twice, produces the same message id twice only within
     * one Telegram delivery. The general statement is simpler — the engine has
     * no dedupe path at all, so the same key applied twice moves money twice.
     */
    @Test
    fun `the same idempotency key cannot move a balance twice`() {
        val (store, _) = seed()
        val customer = store.findByHandle("acme")!!
        val engine = CommandEngine(store, Roles(setOf(operator)))

        engine.handle(operator, 500L, 9L, "/credit acme 5.00 lab top-up")
        engine.handle(operator, 500L, 9L, "/credit acme 5.00 lab top-up")

        assertEquals(
            5_000_000L,
            store.getCustomer(customer.id).balanceMicros,
            "one message id credited the account twice",
        )
    }

    // -- the group check fails OPEN -------------------------------------------

    /**
     * HttpTelegramApi.parseUpdate defaults an absent chat.type to "private".
     * BotLoop then routes the reply straight back to update.chatId — which for
     * a group is the group. The single control that keeps a SIP password out of
     * permanent group history defaults to the unsafe answer.
     */
    @Test
    fun `an unknown chat type is not treated as private`() {
        val (store, plan) = seed()
        // What parseUpdate produces for a group message whose chat object has
        // no "type" field. See `a chat with no type is not assumed private`.
        val telegram = Fake(
            listOf(message(1, "/newuser bravo $plan", chatId = -1001234567890L,
                           chatType = "private")),
        )
        BotLoop(telegram, CommandEngine(store, Roles(setOf(operator))), log = { }).pollOnce()

        val toGroup = telegram.sent.filter { it.first < 0 }
        assertTrue(
            toGroup.none { it.second.contains("Password:") },
            "a SIP password was posted to chat ${toGroup.firstOrNull()?.first}: " +
                "the group check trusts a field that defaults to \"private\"",
        )
    }

    // -- the rate limiter's cleanup never fires -------------------------------

    /**
     * RateLimit prunes `windows` only of entries whose list is EMPTY. A list is
     * emptied by the stale sweep at the top of allow(), and allow() then
     * immediately adds a fresh timestamp — so no entry is ever observed empty,
     * and the map keeps one entry per Telegram user id that ever messaged the
     * bot, forever.
     *
     * The comment says "Users who stopped talking are forgotten, or this map is
     * a slow leak that only shows up after the bot has been up for months."
     * They are not forgotten, and it is exactly that leak.
     */
    @Test
    fun `the rate limiter forgets users who stopped talking`() {
        var clock = 0L
        val limit = RateLimit(perMinute = 20, now = { clock })

        (1L..12_000L).forEach { limit.allow(it) }
        clock += 3_600_000  // an hour later, none of them has said anything
        (1L..50L).forEach { limit.allow(900_000L + it) }

        val field = RateLimit::class.java.getDeclaredField("windows")
        field.isAccessible = true
        val size = (field.get(limit) as Map<*, *>).size

        assertTrue(
            size < 1_000,
            "$size users are still retained an hour after their last message: the " +
                "cleanup only removes entries whose list is empty, and allow() never " +
                "leaves one empty",
        )
    }

    // -- the loop has no backoff ----------------------------------------------

    /**
     * HttpTelegramApi turns every failure — 429, 5xx, unparseable body, refused
     * connection — into an empty list (proved by HttpTelegramApiTest's own
     * `a non-200 response yields no updates rather than an exception` and
     * `a malformed body yields no updates...`). BotLoop.run() therefore cannot
     * distinguish "Telegram was quiet for 30 seconds" from "Telegram said 429
     * in 3ms", and re-polls immediately. The 5-second sleep in run()'s catch is
     * unreachable through the real transport.
     *
     * Result: while Telegram is rate-limiting the bot, the bot answers by
     * polling flat out.
     */
    /**
     * Rewritten from the original assertion, which was "2000 polls must take
     * at least 2000ms" — that is satisfied by a 1ms sleep, which is not
     * protection against anything. The property that matters is a bound on the
     * RATE, so this runs the loop for a fixed wall-clock second and counts.
     *
     * A real long poll blocks at Telegram for pollSeconds, so a correct loop
     * managed 1 poll in that time. The bar is set at 20 to leave room for the
     * initial fast attempts a backoff makes before it widens.
     */
    @Test
    fun `a poll that returns instantly does not become a hot loop`() {
        val polls = java.util.concurrent.atomic.AtomicInteger()
        val fake = object : TelegramApi {
            override fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming> {
                // Exactly what a 429 looks like: immediate, and empty.
                polls.incrementAndGet()
                return emptyList()
            }
            override fun sendMessage(chatId: Long, text: String) = true
        }
        val (store, _) = seed()

        val loop = BotLoop(
            fake, CommandEngine(store, Roles(setOf(operator))), pollSeconds = 30, log = { },
        )
        val thread = Thread { loop.run() }
        thread.isDaemon = true
        thread.start()
        Thread.sleep(1_000)
        thread.interrupt()
        thread.join(5_000)

        assertTrue(
            polls.get() in 1..20,
            "${polls.get()} polls in one second with a 30s long-poll configured: the " +
                "bot's answer to being rate-limited is to poll harder, which is the one " +
                "response guaranteed to keep it rate-limited",
        )
    }

    @Test
    fun `a transport failure is distinguishable from a quiet minute`() {
        // The root cause of the hot loop: HttpTelegramApi collapsed 429, 5xx,
        // an unparseable body and a refused connection all into an empty list,
        // so the loop had nothing to react to. A failure must be a failure.
        val api = HttpTelegramApi("123456:token", "http://127.0.0.1:1")
        kotlin.test.assertFailsWith<TelegramUnavailable> { api.getUpdates(0, 1) }
    }
}
