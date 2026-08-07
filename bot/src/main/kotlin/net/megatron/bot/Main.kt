package net.megatron.bot

import net.megatron.provisioning.InMemoryStore

/**
 * Bot entry point.
 *
 * STATUS: the command engine is complete and tested. The Telegram TRANSPORT —
 * long-polling getUpdates against api.telegram.org — is not written here, and
 * that gap is deliberate rather than forgotten.
 *
 * Writing an untested transport would be the least valuable code in the
 * repository: it cannot be exercised without a real bot token and a network,
 * both of which arrive with the VPS (#2). What CAN be settled beforehand is
 * every decision the transport does not get to make — who may run which
 * command, how an amount typed by a human becomes integer micros, what a
 * retried message must not do twice — and that is what CommandEngine holds,
 * with tests.
 *
 * When the transport is added, it does exactly three things:
 *
 *   1. read updates, extract (telegram_user_id, chat_id, message_id, text)
 *   2. call CommandEngine.handle(...)
 *   3. send the returned string back
 *
 * It must contain no business logic whatsoever. The moment it decides
 * anything, the bot and the console begin to disagree — which is the failure
 * docs/PRODUCT.md exists to prevent.
 *
 * SECURITY NOTES FOR WHOEVER WRITES IT
 * ------------------------------------
 * - The bot token goes in a mode-0600 secrets file or the environment, never
 *   in the repo. A leaked bot token is a full compromise of this surface.
 * - Telegram delivers the same update again if it is not acknowledged. The
 *   idempotency key is already derived from chat_id and message_id for
 *   exactly that reason — do not replace it with a random one.
 * - Rate-limit per Telegram user id before dispatch, not after.
 * - Never echo a SIP password into a group chat. /newuser replies belong in a
 *   direct message.
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

    val engine = CommandEngine(InMemoryStore(), Roles(operators))

    System.err.println(
        "MEGATRON bot: command engine ready for ${operators.size} operator(s).\n" +
            "The Telegram transport is not implemented yet (issue #20) — see the KDoc " +
            "on this file for what it must and must not do."
    )
    error("Telegram transport not implemented; see issue #20")
}
