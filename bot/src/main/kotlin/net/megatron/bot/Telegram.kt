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
    /** "private", "group", "supergroup", "channel". */
    val chatType: String,
)

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
            ?: return emptyList()
        return response["result"]?.jsonArray.orEmpty().mapNotNull { parseUpdate(it.jsonObject) }
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
            chatType = chat["type"]?.jsonPrimitive?.contentOrNull ?: "private",
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
) {

    /** Survives restarts only as far as Telegram's own 24h queue does. */
    private var offset = 0L

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
        if (reply.containsSecret && update.chatType != "private") {
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

    /** Runs until the thread is interrupted. */
    fun run() {
        log("bot: polling")
        while (!Thread.currentThread().isInterrupted) {
            try {
                pollOnce()
            } catch (failure: Exception) {
                // Telegram being down must not end the process: the bot is the
                // only way the business is operated, so it has to still be
                // here when Telegram comes back.
                log("bot: poll failed, retrying: $failure")
                try {
                    Thread.sleep(5000)
                } catch (stop: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
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
        if (seen.size >= perMinute) return false
        seen.add(now())

        // Users who stopped talking are forgotten, or this map is a slow leak
        // that only shows up after the bot has been up for months.
        if (windows.size > 10_000) {
            windows.entries.removeAll { it.value.isEmpty() }
        }
        return true
    }
}
