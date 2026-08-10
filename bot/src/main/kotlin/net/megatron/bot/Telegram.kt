package net.megatron.bot

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * One message, as this bot needs it.
 *
 * Telegram's update object has dozens of fields. Four are business-relevant,
 * and narrowing to them here means the rest cannot accidentally become an
 * input to a decision.
 */
data class Incoming(
    val updateId: Long,
    val telegramUserId: Long,
    val chatId: Long,
    val messageId: Long,
    val text: String,
    /** "private", "group", "supergroup", "channel", or "unknown". */
    val chatType: String,
) {
    /**
     * Whether this is a one-to-one chat with the operator.
     *
     * TWO INDEPENDENT SIGNALS, BOTH REQUIRED, because this is the only thing
     * standing between a SIP password and permanent group history.
     *
     * [chatType] can be absent from a malformed or future update, and an
     * earlier version defaulted it to "private" — a security control whose
     * default was the unsafe answer. The chat id settles it independently:
     * Telegram gives users positive ids and groups, supergroups and channels
     * negative ones. Requiring both means neither a missing field nor an
     * unfamiliar chat type can produce a false "private".
     */
    val isPrivate: Boolean get() = chatType == "private" && chatId > 0
}

/**
 * Telegram could not be reached, or answered with something that was not an
 * answer — 429, 5xx, an unparseable body, a refused connection.
 *
 * Distinct from "there were no updates", and the distinction is load-bearing:
 * collapsing the two leaves the polling loop unable to tell a quiet minute
 * from a rate-limit, so its response to being rate-limited is to poll harder.
 */
class TelegramUnavailable(message: String) : RuntimeException(message)

/**
 * What the transport needs from Telegram, and nothing more.
 *
 * An interface so the loop can be tested against a fake without a bot token, a
 * network, or Telegram being up — which is the difference between a transport
 * with tests and the untested transport this file replaces.
 */
interface TelegramApi {
    /** Long-poll. Returns updates with id > [offset]. */
    fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming>
    fun sendMessage(chatId: Long, text: String): Boolean
}

/**
 * The real one, over java.net.http.
 *
 * Deliberately no HTTP client dependency: the JDK has one, and the licence
 * gate is one fewer thing to argue with for a few hundred lines of request
 * building.
 */
class HttpTelegramApi(
    private val token: String,
    private val baseUrl: String = "https://api.telegram.org",
) : TelegramApi {

    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build()

    private val json = Json { ignoreUnknownKeys = true }

    override fun getUpdates(offset: Long, timeoutSeconds: Int): List<Incoming> {
        // allowed_updates restricts what Telegram sends at the source. Filtering
        // on arrival would work too, but this way an update type nobody has
        // considered never reaches the parser at all.
        val body = buildJsonObject {
            put("offset", offset)
            put("timeout", timeoutSeconds)
            put("allowed_updates", Json.parseToJsonElement("""["message"]"""))
        }
        // The read timeout must exceed the long-poll timeout, or every poll
        // ends in a client-side timeout that looks exactly like Telegram being
        // unreachable.
        val response = call("getUpdates", body, Duration.ofSeconds(timeoutSeconds + 10L))
            ?: throw TelegramUnavailable("getUpdates did not return a usable response")

        // EVERY UPDATE IS PARSED IN ISOLATION.
        //
        // kotlinx's .jsonObject / .jsonPrimitive THROW on a wrong-shaped
        // field. Parsing the batch as one expression meant a single malformed
        // update discarded the whole batch AND left the offset where it was --
        // so the same batch came back, threw again, forever. The guard for
        // that was one layer lower, in dispatch(), which is never reached.
        //
        // One bad update is now one dropped message.
        val result = try {
            response["result"]?.jsonArray.orEmpty()
        } catch (malformed: Exception) {
            throw TelegramUnavailable("getUpdates result was not an array: $malformed")
        }
        return result.mapNotNull { element ->
            try {
                parseUpdate(element.jsonObject)
            } catch (malformed: Exception) {
                System.err.println("telegram: dropped an unparseable update: $malformed")
                null
            }
        }
    }

    override fun sendMessage(chatId: Long, text: String): Boolean {
        val body = buildJsonObject {
            put("chat_id", chatId)
            put("text", text)
        }
        return call("sendMessage", body, Duration.ofSeconds(15)) != null
    }

    private fun call(method: String, body: JsonObject, timeout: Duration): JsonObject? =
        try {
            val request = HttpRequest.newBuilder()
                .uri(URI.create("$baseUrl/bot$token/$method"))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) {
                System.err.println("telegram $method: HTTP ${response.statusCode()}")
                null
            } else {
                json.parseToJsonElement(response.body()).jsonObject
            }
        } catch (failure: Exception) {
            // THE MESSAGE IS SCRUBBED, AND THAT IS NOT PARANOIA.
            //
            // The bot token is IN THE URL, and java.net.http puts the URI in
            // its exception messages. Logging the exception unmodified writes
            // a full bot-token compromise into the log on every network blip
            // -- the most reliably reproducible secret leak available here.
            System.err.println("telegram $method failed: ${scrub(failure.toString())}")
            null
        }

    private fun scrub(message: String) = message.replace(token, "<token>")

    private fun parseUpdate(update: JsonObject): Incoming? {
        val updateId = update["update_id"]?.jsonPrimitive?.longOrNull ?: return null
        val message = update["message"]?.jsonObject ?: return null
        val from = message["from"]?.jsonObject ?: return null
        val chat = message["chat"]?.jsonObject ?: return null
        // No text means a photo, a sticker, someone joining. Not an error, and
        // not a command -- dropped here rather than parsed into an empty one.
        val text = message["text"]?.jsonPrimitive?.contentOrNull ?: return null
        return Incoming(
            updateId = updateId,
            telegramUserId = from["id"]?.jsonPrimitive?.longOrNull ?: return null,
            chatId = chat["id"]?.jsonPrimitive?.longOrNull ?: return null,
            messageId = message["message_id"]?.jsonPrimitive?.longOrNull ?: return null,
            text = text,
            // "unknown", NOT "private". This field gates whether a SIP
            // password may be sent to this chat, and the default of a security
            // control must be the safe answer. See Incoming.isPrivate, which
            // also requires a positive chat id, so a forged or absent type
            // cannot produce a false private on its own.
            chatType = chat["type"]?.jsonPrimitive?.contentOrNull ?: "unknown",
        )
    }
}

/**
 * The polling loop. Three steps and no business logic, as specified.
 *
 * TWO PROPERTIES CARRY THE WHOLE FILE.
 *
 * THE OFFSET MUST ADVANCE PAST EVERY UPDATE THAT WAS TAKEN OUT OF THE QUEUE.
 * Telegram redelivers anything unacknowledged. An offset that fails to advance
 * replays the same batch forever, and one of those messages may be
 * `/credit acme 500` — so the failure is not a stuck bot, it is unbounded free
 * credit issued at the polling interval. The offset therefore advances for
 * every update RECEIVED, including ones that could not be processed: a message
 * that crashes the handler would otherwise crash it again, and again.
 *
 * A REPLY THAT COULD NOT BE SENT MUST NOT UNDO THE WORK. The command has
 * already been executed against the store by the time send fails. Retrying the
 * update would re-run it — and the idempotency key derived from
 * chat_id/message_id is exactly what makes that safe, so the retry is not the
 * danger. The danger is the operator not knowing, which is why a failed send
 * is loud.
 */
class BotLoop(
    private val api: TelegramApi,
    private val engine: CommandEngine,
    private val pollSeconds: Int = 30,
    private val rateLimit: RateLimit = RateLimit(),
    private val log: (String) -> Unit = { System.err.println(it) },
    /**
     * Where the offset is remembered across restarts, if anywhere.
     *
     * NOT the protection against double-processing — [CommandEngine] holds a
     * durable claim per message for that, and it has to, because a crash can
     * land between handling an update and writing this file no matter how
     * carefully it is written.
     *
     * What it buys is that a restart does not replay the last batch at all,
     * so the common case produces no duplicate work and no confusing "Already
     * done" replies to commands the operator only sent once.
     */
    private val offsetFile: java.nio.file.Path? = null,
) {

    private var offset = 0L

    init {
        offsetFile?.let { path ->
            runCatching { java.nio.file.Files.readString(path).trim().toLong() }
                .onSuccess {
                    offset = it
                    log("bot: resuming from offset $it")
                }
        }
    }

    private fun rememberOffset() {
        val path = offsetFile ?: return
        // Best-effort. A failure here costs a replayed batch on the next
        // restart, which claimOnce already makes harmless — it must never stop
        // the bot processing messages.
        runCatching {
            val temporary = path.resolveSibling("${path.fileName}.tmp")
            java.nio.file.Files.writeString(temporary, offset.toString())
            java.nio.file.Files.move(
                temporary, path,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
            )
        }
    }

    /** One poll. Returns how many updates were handled. Exposed for tests. */
    fun pollOnce(): Int {
        val updates = api.getUpdates(offset, pollSeconds)
        var handled = 0
        for (update in updates) {
            // Advance FIRST. If handling throws, this update is not served
            // again -- one lost command beats an infinite loop of a command
            // that moves money.
            offset = maxOf(offset, update.updateId + 1)
            try {
                dispatch(update)
                handled++
            } catch (failure: Exception) {
                log("bot: dropped update ${update.updateId}: $failure")
            }
        }
        if (updates.isNotEmpty()) rememberOffset()
        return handled
    }

    private fun dispatch(update: Incoming) {
        // Rate-limited BEFORE dispatch, not after: the point is to stop the
        // work happening, and a limiter that runs afterwards has already let
        // the store be written to.
        if (!rateLimit.allow(update.telegramUserId)) {
            log("bot: rate-limited ${update.telegramUserId}")
            return
        }

        val reply = engine.reply(
            telegramUserId = update.telegramUserId,
            chatId = update.chatId,
            messageId = update.messageId,
            text = update.text,
        )

        // A SIP PASSWORD NEVER GOES INTO A GROUP.
        //
        // Group history is permanent, searchable, and readable by every member
        // including ones added later. The credential is sent to the operator's
        // private chat instead, and the group is told only that it happened.
        //
        // If the DM fails -- Telegram forbids a bot messaging a user who has
        // never started it -- the group gets an instruction and NOT the
        // password. Falling back to posting it would defeat the entire check
        // at exactly the moment it is doing its job.
        if (reply.containsSecret && !update.isPrivate) {
            val delivered = api.sendMessage(update.telegramUserId, reply.text)
            val notice = if (delivered) {
                "Sent to you privately — a SIP password does not belong in a group."
            } else {
                "I could not message you privately. Open a direct chat with me, " +
                    "send /start, then run that command again."
            }
            api.sendMessage(update.chatId, notice)
            return
        }

        if (!api.sendMessage(update.chatId, reply.text)) {
            // The command already ran. Loud, because the operator's screen
            // showing nothing is indistinguishable from the command having
            // been ignored -- and their next move is to run it again.
            log("bot: COMMAND RAN BUT REPLY FAILED for update ${update.updateId}")
        }
    }

    /**
     * Runs until the thread is interrupted.
     *
     * IT MUST NOT BE POSSIBLE FOR THIS LOOP TO SPIN.
     *
     * A healthy poll blocks at Telegram for [pollSeconds], so iterations are
     * naturally paced and nothing here has to do anything. The dangerous case
     * is a poll that returns IMMEDIATELY and empty — which is exactly what a
     * 429 looks like. Without pacing, the bot's answer to being rate-limited
     * is to poll flat out, which is the one response guaranteed to keep it
     * rate-limited.
     *
     * So consecutive fast, empty polls back off, doubling to a ceiling. A
     * single normal poll resets it, because one quiet minute is not a fault.
     */
    fun run() {
        log("bot: polling")
        var backoffMs = 0L
        while (!Thread.currentThread().isInterrupted) {
            val started = System.nanoTime()
            val suspicious = try {
                val handled = pollOnce()
                val elapsedMs = (System.nanoTime() - started) / 1_000_000
                // A long poll that came back in a fraction of its timeout did
                // not long-poll. Something answered instead of waiting.
                //
                // THE FLOOR IS NOT DECORATION. The threshold was
                // `pollSeconds * 250`, which is ZERO when pollSeconds is 0 —
                // so no poll was ever judged suspicious, the backoff never
                // armed, and the hot loop came straight back. And
                // MEGATRON_TELEGRAM_POLL_SECONDS=0 is exactly what somebody
                // types to "turn off long polling". A negative value did the
                // same. One second is below any real long poll and above any
                // instant answer.
                handled == 0 && elapsedMs < maxOf(1_000L, pollSeconds * 250L)
            } catch (failure: Exception) {
                // Telegram being down must not end the process: the bot is the
                // only way the business is operated, so it has to still be
                // here when Telegram comes back.
                log("bot: poll failed, retrying: $failure")
                true
            }

            backoffMs = if (suspicious) {
                (if (backoffMs == 0L) MIN_BACKOFF_MS else backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
            } else {
                0L
            }

            if (backoffMs > 0) {
                try {
                    Thread.sleep(backoffMs)
                } catch (stop: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
    }

    private companion object {
        const val MIN_BACKOFF_MS = 250L

        /**
         * Long enough that a rate-limited bot stops contributing to the
         * problem; short enough that a returning Telegram is noticed within a
         * minute, since nothing else operates this business.
         */
        const val MAX_BACKOFF_MS = 30_000L
    }
}

/**
 * Per-user token bucket.
 *
 * Keyed on the Telegram user id rather than the chat, so somebody cannot
 * multiply their allowance by opening more chats. Every command reaches the
 * provisioning API and some of them write; without this, one person with a
 * script is a load generator pointed at the business.
 */
class RateLimit(
    private val perMinute: Int = 20,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val windows = HashMap<Long, MutableList<Long>>()

    @Synchronized
    fun allow(telegramUserId: Long): Boolean {
        val cutoff = now() - 60_000
        val seen = windows.getOrPut(telegramUserId) { mutableListOf() }
        seen.removeAll { it < cutoff }
        val allowed = seen.size < perMinute
        if (allowed) seen.add(now())

        // SWEEP EVERY ENTRY, NOT JUST EMPTY ONES.
        //
        // The previous version pruned entries whose list was empty. A list is
        // only emptied by the stale sweep three lines above, after which
        // allow() immediately adds a fresh timestamp — so no entry was ever
        // observed empty and the prune removed nothing, ever. The map kept one
        // entry per Telegram user id that had ever messaged the bot, for the
        // life of the process, which is precisely the leak the old comment
        // claimed to prevent.
        //
        // This walks every entry and drops those with nothing inside the
        // window. It is O(n) and therefore rate-limited itself, by size and by
        // time, so a busy bot does not pay for it on every message.
        if (windows.size > SWEEP_ABOVE && now() - lastSweep > SWEEP_INTERVAL_MS) {
            lastSweep = now()
            windows.values.forEach { it.removeAll { seenAt -> seenAt < cutoff } }
            windows.entries.removeAll { it.value.isEmpty() }
        }
        return allowed
    }

    private var lastSweep = 0L

    /** Visible for tests: how many users are currently remembered. */
    @Synchronized
    fun trackedUsers(): Int = windows.size

    private companion object {
        const val SWEEP_ABOVE = 1_000
        const val SWEEP_INTERVAL_MS = 60_000L
    }
}
