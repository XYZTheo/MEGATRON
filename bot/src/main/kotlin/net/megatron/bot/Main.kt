package net.megatron.bot

import net.megatron.provisioning.InMemoryStore

/**
 * Bot entry point.
 *
 * The transport ([BotLoop] in Telegram.kt) does exactly three things: read
 * updates, call [CommandEngine], send the reply back. It contains no business
 * logic, because the moment it decides anything the bot and the console begin
 * to disagree — which is the failure docs/PRODUCT.md exists to prevent.
 *
 * WHAT IS AND IS NOT VERIFIED. The loop, the offset arithmetic, the rate
 * limiter and the never-post-a-password-in-a-group rule are all tested against
 * a fake Telegram (`BotLoopTest`). What has NOT been exercised is
 * api.telegram.org itself: the JSON shapes in [HttpTelegramApi.parseUpdate]
 * are written from Telegram's documentation and have never seen a real
 * response. That is the remaining risk and it is a narrow one — but it is
 * real, so do not read "the bot is tested" as "the bot has talked to
 * Telegram".
 *
 * SECURITY PROPERTIES THIS FILE AND ITS TRANSPORT HOLD
 * ----------------------------------------------------
 * - The bot token comes from the environment, never the repo. It is also
 *   scrubbed from error messages, because it is IN THE URL and the JDK's HTTP
 *   client puts the URI in its exceptions — otherwise every network blip
 *   writes a full token compromise into the log.
 * - Telegram redelivers anything unacknowledged, so the idempotency key is
 *   derived from chat_id and message_id. Do not replace it with a random one.
 * - Rate limiting happens per Telegram user id, BEFORE dispatch.
 * - A SIP password is never posted into a group chat.
 */
fun main() {
    val token = System.getenv("MEGATRON_TELEGRAM_TOKEN")
        ?: error(
            "MEGATRON_TELEGRAM_TOKEN is not set. The bot will not start without one."
        )
    require(token.length >= 20) { "MEGATRON_TELEGRAM_TOKEN does not look like a bot token" }

    val operators = (System.getenv("MEGATRON_OPERATOR_TELEGRAM_IDS") ?: "")
        .split(",")
        .mapNotNull { it.trim().toLongOrNull() }
        .toSet()
    require(operators.isNotEmpty()) {
        "MEGATRON_OPERATOR_TELEGRAM_IDS must list at least one Telegram user id. " +
            "A bot with no operators cannot run the business; a bot with an empty " +
            "allowlist that defaulted to 'everyone' would hand it to strangers."
    }

    val dbUrl = System.getenv("MEGATRON_DB_URL")
    val store = if (dbUrl.isNullOrBlank()) {
        System.err.println(
            "WARNING: MEGATRON_DB_URL is not set. The bot is running on its own in-memory " +
                "store, which shares NOTHING with the provisioning service — customers " +
                "created here will not exist for the switch, and balances will be lost on " +
                "exit. Set it to the same database provisioning uses."
        )
        InMemoryStore()
    } else {
        net.megatron.provisioning.SqlStore(dbUrl)
    }

    val engine = CommandEngine(store, Roles(operators))
    val poll = System.getenv("MEGATRON_TELEGRAM_POLL_SECONDS")?.toIntOrNull() ?: 30

    System.err.println("MEGATRON bot: ${operators.size} operator(s), polling every ${poll}s")

    BotLoop(
        api = HttpTelegramApi(token),
        engine = engine,
        pollSeconds = poll,
        offsetFile = System.getenv("MEGATRON_BOT_OFFSET_FILE")
            ?.takeIf { it.isNotBlank() }
            ?.let { java.nio.file.Path.of(it) },
    ).run()
}
