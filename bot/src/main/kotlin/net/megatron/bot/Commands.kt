package net.megatron.bot

import net.megatron.provisioning.BalanceAdjustment
import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CustomerStatus
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.Invalid
import net.megatron.provisioning.NotFound
import net.megatron.provisioning.SetStatus
import net.megatron.provisioning.Store

/**
 * Who sent a message, and therefore what they may do.
 *
 * An ALLOWLIST of Telegram user ids for operator commands, not a role field
 * on a record somewhere. The bot can issue credentials and move balance, so a
 * mistake here is unlimited free credit — and Telegram accounts do get taken
 * over, which is why the operator set is small, explicit, and configured out
 * of band rather than editable through the bot itself.
 */
class Roles(private val operatorTelegramIds: Set<Long>) {
    fun isOperator(telegramUserId: Long) = telegramUserId in operatorTelegramIds
}

/** A parsed command with its arguments. */
data class Command(val verb: String, val args: List<String>)

fun parseCommand(text: String): Command? {
    val trimmed = text.trim()
    if (!trimmed.startsWith("/")) return null
    // Telegram appends @botname when a command is used in a group.
    val parts = trimmed.split(Regex("\\s+"))
    val verb = parts[0].removePrefix("/").substringBefore("@").lowercase()
    if (verb.isEmpty()) return null
    return Command(verb, parts.drop(1))
}

/**
 * Money entered by a human, converted to integer micro-units.
 *
 * Accepts "25", "25.00", "0.5". Rejects anything else — including scientific
 * notation and thousands separators, because a top-up amount that has to be
 * guessed at is a top-up amount that will eventually be guessed wrong.
 *
 * Parsed as a decimal STRING rather than through a Double: "0.1" cannot be
 * represented exactly in binary floating point, and this is the function that
 * turns what an operator typed into what a customer is credited.
 */
fun parseMoney(raw: String): Long {
    val text = raw.trim().removePrefix("+")
    if (!Regex("^-?\\d+(\\.\\d{1,6})?$").matches(text)) {
        throw Invalid(
            "'$raw' is not an amount. Use digits with up to six decimal places, " +
                "for example 25 or 25.50"
        )
    }
    val negative = text.startsWith("-")
    val body = text.removePrefix("-")
    val whole = body.substringBefore('.')
    val fraction = body.substringAfter('.', "").padEnd(6, '0')
    // BOTH OVERFLOW PATHS BECOME Invalid, WHICH IS WHAT THIS IS.
    //
    // "99999999999999999999" satisfies the regex above and then fails in
    // whole.toLong() with NumberFormatException; a smaller-but-still-huge
    // number survives that and fails in multiplyExact with
    // ArithmeticException. Neither is an internal fault — the operator typed
    // a number too big to be money — but both used to escape this function
    // unconverted, past the handler that catches Invalid, out to the
    // transport, which logged "dropped update" and SENT NOTHING. The operator
    // saw silence and their next move was to send it again.
    val micros = try {
        Math.addExact(Math.multiplyExact(whole.toLong(), 1_000_000L), fraction.toLong())
    } catch (tooBig: NumberFormatException) {
        throw Invalid("'$raw' is too large to be an amount")
    } catch (tooBig: ArithmeticException) {
        throw Invalid("'$raw' is too large to be an amount")
    }
    return if (negative) -micros else micros
}

/**
 * Money for a human to read.
 *
 * TWO DECIMALS, EXCEPT WHEN TWO DECIMALS WOULD LIE.
 *
 * Balances are micro-units and telephony rates are routinely fractions of a
 * cent, so truncating to 2dp made `/credit acme 0.005 promo` — a real movement
 * of 5,000 micros — reply "0.00 -> balance 0.00". The operator's only
 * confirmation that a money command did anything said it did nothing, which
 * invites them to run it again.
 *
 * So a value that is not exact at 2dp is shown at full micro precision
 * instead. Ugly on those values, and being ugly is the point: an unusual
 * number should look unusual.
 */
fun formatMoney(micros: Long, currency: String = ""): String {
    val negative = micros < 0
    val sign = if (negative) "-" else ""
    val suffix = if (currency.isEmpty()) "" else " $currency"

    // SPLIT FIRST, THEN TAKE ABSOLUTE VALUES OF THE PARTS.
    //
    // `-micros` is a no-op on Long.MIN_VALUE — it stays negative — so negating
    // up front made every division and modulo below produce a negative digit
    // group and rendered "--9223372036854.-775808": two minus signs, a minus
    // inside the fraction, and nothing parseMoney will read back.
    //
    // Reachable without any overflow: a balance of -Long.MAX_VALUE plus one
    // more micro-unit of debit is an exact addition, so Math.addExact permits
    // it and /balance then shows the customer garbage.
    //
    // Both parts are safely negatable: |micros / 1_000_000| and
    // |micros % 1_000_000| are each far below Long.MAX_VALUE even at the
    // extreme.
    val whole = kotlin.math.abs(micros / 1_000_000L)
    val fraction = kotlin.math.abs(micros % 1_000_000L)

    // Exact at 2dp when the remainder is a whole number of cents.
    if (fraction % 10_000L == 0L) {
        val cents = fraction / 10_000L
        return "$sign$whole.${cents.toString().padStart(2, '0')}$suffix"
    }
    // Otherwise show every digit that exists, with trailing zeroes trimmed so
    // 0.0005 does not become 0.000500.
    val digits = fraction.toString().padStart(6, '0').trimEnd('0')
    return "$sign$whole.$digits$suffix"
}

/**
 * The bot's behaviour, with Telegram entirely absent.
 *
 * Everything the bot does is decided here and returned as text. The transport
 * only carries it. That is what makes the business behaviour testable without
 * a bot token, a network, or Telegram being reachable — and it is the reason
 * this class, not the transport, is where the tests are.
 */
class CommandEngine(
    private val store: Store,
    private val roles: Roles,
    private val idempotencyKeyFor: (Long, Long) -> String = { chatId, messageId ->
        // Derived from the message that triggered it, so a user tapping twice
        // is ONE operation and a retry after a timeout is the same one.
        "tg-$chatId-$messageId"
    },
) {

    /**
     * The reply, and whether it is safe to say out loud.
     *
     * [containsSecret] is a decision, not a property of the string, and it
     * belongs here rather than in the transport for the same reason everything
     * else does: a transport that inspects replies to guess which are
     * sensitive is a transport making business decisions, and it will guess
     * differently from this file the first time a message is reworded.
     *
     * The case that matters: an operator runs /newuser in a group chat. The
     * reply carries a SIP password, which is a working login for the switch,
     * and Telegram group history is forever and searchable.
     */
    data class Reply(val text: String, val containsSecret: Boolean = false)

    /** Convenience for callers that do not care about [Reply.containsSecret]. */
    fun handle(telegramUserId: Long, chatId: Long, messageId: Long, text: String): String =
        reply(telegramUserId, chatId, messageId, text).text

    fun reply(telegramUserId: Long, chatId: Long, messageId: Long, text: String): Reply {
        val command = parseCommand(text)
        // Listed by VERB rather than by scanning the reply text: a scan finds
        // whatever it was taught to look for and silently misses the next
        // command that returns a secret. See SECRET_REPLIES.
        val secret = command?.verb in SECRET_REPLIES && roles.isOperator(telegramUserId)
        return Reply(handleText(telegramUserId, chatId, messageId, text), secret)
    }

    private fun handleText(
        telegramUserId: Long,
        chatId: Long,
        messageId: Long,
        text: String,
    ): String {
        val command = parseCommand(text) ?: return help(roles.isOperator(telegramUserId))
        val actor = "telegram:$telegramUserId"
        val key = idempotencyKeyFor(chatId, messageId)

        return try {
            when (command.verb) {
                "start", "help" -> help(roles.isOperator(telegramUserId))

                // -- customer self-service ---------------------------------
                "balance" -> balance(telegramUserId)
                "cli", "callerid" -> setCallerId(telegramUserId, command.args, actor)

                // -- operator ----------------------------------------------
                //
                // These two are wrapped in onlyOnce because they are the two
                // that change the world irreversibly: one moves money, the
                // other creates an account and issues a credential. Everything
                // else in this list is idempotent by nature -- suspending a
                // suspended customer, or reading a balance twice, costs
                // nothing -- so guarding them would add a failure mode without
                // removing one.
                "newuser" -> operatorOnly(telegramUserId) {
                    newUser(command.args, actor, key)
                }
                "credit" -> operatorOnly(telegramUserId) {
                    credit(command.args, actor, key)
                }
                "suspend" -> operatorOnly(telegramUserId) {
                    setStatus(command.args, CustomerStatus.SUSPENDED, actor)
                }
                "enable" -> operatorOnly(telegramUserId) {
                    setStatus(command.args, CustomerStatus.ACTIVE, actor)
                }
                // Not guarded by claimOnce. Rotating twice is not harmful the
                // way crediting twice is -- the second rotation simply wins --
                // and a customer whose password has leaked must never be told
                // "already done" when they ask for a new one.
                "rotate" -> operatorOnly(telegramUserId) { rotate(command.args) }
                "who" -> operatorOnly(telegramUserId) { who(command.args) }
                "users" -> operatorOnly(telegramUserId) { users() }

                // Byte-identical to the operator-only refusal below, on
                // purpose. Echoing the verb back made the two distinguishable,
                // so a stranger could probe /credit, /suspend, /newuser and
                // learn from the reply which ones exist. Caught by a test.
                else -> UNKNOWN_COMMAND
            }
        } catch (e: NotFound) {
            "Not found: ${e.message}"
        } catch (e: Invalid) {
            "That did not work: ${e.message}"
        } catch (e: net.megatron.provisioning.Conflict) {
            "Cannot do that: ${e.message}"
        } catch (e: ArithmeticException) {
            // parseMoney throws this on an amount too large to hold in micros.
            // It used to escape to the transport, which logged "dropped
            // update" and sent NOTHING -- so the operator saw silence,
            // indistinguishable from the bot being down, and their next move
            // was to send it again.
            "That amount is too large to handle."
        } catch (e: Exception) {
            // NOTHING REACHES THE OPERATOR AS SILENCE.
            //
            // Every unhandled type above was a command that ran, or failed to
            // run, with no reply -- and an operator who gets no answer retries,
            // which on a money command is the worst possible response to an
            // error. The detail goes to the log; they get an answer.
            System.err.println("bot: unhandled failure on '${command.verb}': $e")
            "Something went wrong handling that. It has been logged; nothing was changed " +
                "unless you see a confirmation."
        }
    }

    /**
     * Runs the guarded mutation, giving the key back if it fails.
     *
     * A CLAIM AND ITS MUTATION ARE NOT ONE TRANSACTION. The claim commits by
     * itself, so without this a failed mutation left the key taken — and on
     * the redelivery that claimOnce exists to handle, the operator was told
     * "Already done" for a credit that never happened. Losing the operation
     * permanently while reporting success is worse than the double-credit the
     * claim prevents.
     *
     * The release is best-effort and deliberately swallows its own failure:
     * if the store is unwell enough that the mutation failed, it may be too
     * unwell to release, and the original error is the one the operator needs
     * to see.
     */
    private inline fun <T> guarded(key: String, block: () -> T): T =
        try {
            block()
        } catch (failure: Throwable) {
            runCatching { store.releaseClaim(key) }
            throw failure
        }

    private inline fun operatorOnly(telegramUserId: Long, block: () -> String): String =
        if (roles.isOperator(telegramUserId)) block()
        // Deliberately identical to an unknown command. Telling a stranger
        // that /credit exists but is not for them is telling them what to go
        // looking for.
        else UNKNOWN_COMMAND

    private companion object {
        const val UNKNOWN_COMMAND = "Unknown command. Send /help."

        /**
         * Commands whose reply contains a credential.
         *
         * Listed by VERB, never by scanning the reply text for something that
         * looks like a password: a scanner finds what it was taught to look
         * for and silently misses the next command that returns a secret. This
         * list is the one place to update when a command starts handing one
         * out — and forgetting it means a SIP password in permanent group
         * history.
         */
        val SECRET_REPLIES = setOf("newuser", "rotate")

        /**
         * The reply when an operation has already been performed under this
         * message's key.
         *
         * WHY A CLAIM IS NEEDED AT ALL. The key was already derived from
         * chat_id and message_id — stable across a retry, which is the hard
         * part — and then passed to `BalanceAdjustment.reference`, a free-text
         * audit field nothing compares. The HTTP API deduplicates on
         * Idempotency-Key, but the bot reaches the Store directly and never
         * crosses that middleware, so the key was recorded and never checked.
         *
         * The scenario it must survive: an operator sends `/credit acme 500`,
         * the bot handles it, and the process dies before its next poll
         * acknowledges the update. Telegram redelivers anything
         * unacknowledged, and the offset — being per-process — restarts at
         * zero. Without a durable claim that is a second five hundred dollars.
         *
         * It says plainly that nothing changed. Reporting success would be
         * worse than the double-credit it prevents, because the operator would
         * believe a second top-up had landed.
         */
        const val ALREADY_DONE =
            "Already done — that message was handled before, so nothing changed."
    }

    private fun help(operator: Boolean): String = buildString {
        appendLine("MEGATRON")
        appendLine()
        appendLine("/balance            what you have left")
        appendLine("/cli +441632960123  set your caller ID")
        if (operator) {
            appendLine()
            appendLine("Operator:")
            appendLine("/newuser <handle> <plan-id>      create a login")
            appendLine("/credit <handle> <amount> <why>  add balance")
            appendLine("/suspend <handle> <why>          stop their calls")
            appendLine("/enable <handle> <why>           let them call again")
            appendLine("/rotate <handle>                 issue a new password")
            appendLine("/who <handle>                    one account")
            appendLine("/users                           everyone")
        }
    }.trimEnd()

    // -- customer -----------------------------------------------------------

    private fun balance(telegramUserId: Long): String {
        val customer = store.findByTelegramUserId(telegramUserId)
            ?: return "This Telegram account is not linked to a MEGATRON account yet."
        val suspended = if (customer.status == CustomerStatus.SUSPENDED) {
            "\n\nYour account is suspended, so calls will not connect."
        } else ""
        val cli = customer.callerId?.number?.let { "\nCaller ID: $it" } ?: ""
        return "Balance: ${formatMoney(customer.balanceMicros, customer.currency)}$cli$suspended"
    }

    private fun setCallerId(telegramUserId: Long, args: List<String>, actor: String): String {
        val customer = store.findByTelegramUserId(telegramUserId)
            ?: return "This Telegram account is not linked to a MEGATRON account yet."
        val number = args.firstOrNull()
            ?: return "Send the number too, like: /cli +441632960123"
        val callerId = store.setCallerId(customer.id, number, actor)
        return "Caller ID set to ${callerId.number}."
    }

    // -- operator -----------------------------------------------------------

    private fun newUser(args: List<String>, actor: String, key: String): String {
        if (args.size < 2) return "Use: /newuser <handle> <plan-id>"
        // Claimed AFTER validation and immediately before the mutation. An
        // earlier version claimed it in the dispatcher, which meant a mistyped
        // command consumed the key -- so the operator corrected their typo,
        // sent it again, and was told "Already done" while no account existed.
        if (!store.claimOnce(key)) return ALREADY_DONE
        val (customer, credentials) = guarded(key) {
            store.createCustomer(
                CreateCustomer(
                    handle = args[0],
                    planId = args[1],
                    telegramUserId = args.getOrNull(2)?.toLongOrNull(),
                ),
                actor,
            )
        }
        // The password appears here and nowhere else, ever. Said plainly,
        // because the operator needs to know to pass it on now rather than
        // assume they can look it up later.
        return buildString {
            appendLine("Created ${customer.handle}.")
            appendLine()
            appendLine("Server:   ${credentials.sipDomain}")
            appendLine("Username: ${credentials.sipUsername}")
            appendLine("Password: ${credentials.sipPassword}")
            appendLine("Transport: ${credentials.transportHint.name.lowercase()}")
            appendLine()
            append("This password is shown once and cannot be looked up again.")
        }
    }

    /**
     * A new SIP password for an existing customer.
     *
     * IT EXISTS BECAUSE SOMETHING ELSE ALREADY DEPENDED ON IT. SubscriberExport
     * skips any customer with no stored digest credential — every account
     * created before HA1 was stored, and every one migrated into an upgraded
     * database — and told them that "rotation is a Telegram command away". It
     * was not; rotation was reachable only through the HTTP API. The documented
     * recovery from "your customers cannot register" did not exist.
     *
     * The reply carries a password, so it is treated as a secret by the
     * transport and never posted into a group.
     */
    private fun rotate(args: List<String>): String {
        val handle = args.firstOrNull() ?: return "Use: /rotate <handle>"
        val customer = store.findByHandle(handle) ?: throw NotFound("customer '$handle'")
        val credentials = store.rotateCredentials(customer.id)
        return buildString {
            appendLine("New password for ${customer.handle}.")
            appendLine()
            appendLine("Server:   ${credentials.sipDomain}")
            appendLine("Username: ${credentials.sipUsername}")
            appendLine("Password: ${credentials.sipPassword}")
            appendLine()
            appendLine("The old password stops working as soon as the switch reloads.")
            append("This password is shown once and cannot be looked up again.")
        }
    }

    private fun credit(args: List<String>, actor: String, key: String): String {
        if (args.size < 3) return "Use: /credit <handle> <amount> <reason>"
        val customer = store.findByHandle(args[0])
            ?: throw NotFound("customer '${args[0]}'")
        val amount = parseMoney(args[1])
        val reason = args.drop(2).joinToString(" ")
        // Last thing before the money moves, and after every way this command
        // can be rejected. A key consumed by a rejected command is a key that
        // blocks the operator's corrected retry.
        if (!store.claimOnce(key)) return ALREADY_DONE
        val txn = guarded(key) {
            store.adjustBalance(
                customer.id,
                BalanceAdjustment(amount, reason, reference = key),
                actor,
            )
        }
        return "${customer.handle}: ${formatMoney(txn.amountMicros)} -> balance " +
            formatMoney(txn.balanceAfterMicros, customer.currency)
    }

    private fun setStatus(args: List<String>, status: CustomerStatus, actor: String): String {
        if (args.size < 2) {
            return "Use: /${if (status == CustomerStatus.SUSPENDED) "suspend" else "enable"} " +
                "<handle> <reason>"
        }
        val customer = store.findByHandle(args[0]) ?: throw NotFound("customer '${args[0]}'")
        val reason = args.drop(1).joinToString(" ")
        val updated = store.setStatus(
            customer.id,
            SetStatus(status, reason, dropActive = status == CustomerStatus.SUSPENDED),
            actor,
        )
        return "${updated.handle} is now ${updated.status.name.lowercase()}. ($reason)"
    }

    private fun who(args: List<String>): String {
        val handle = args.firstOrNull() ?: return "Use: /who <handle>"
        val customer = store.findByHandle(handle) ?: throw NotFound("customer '$handle'")
        return buildString {
            appendLine("${customer.handle}  (${customer.status.name.lowercase()})")
            appendLine("Balance:  ${formatMoney(customer.balanceMicros, customer.currency)}")
            appendLine("Caller ID: ${customer.callerId?.number ?: "not set"}")
            // NO "Registered:" LINE. It read `customer.registered`, which
            // nothing ever set, so this printed "Registered: no" for every
            // customer including ones with a phone registered and a call up.
            // Registration is live switch state and is answered by
            // GET /v1/customers/{id}/registration, which asks OpenSIPS.
            // Printing a confident wrong answer is worse than printing none.
            append("Max calls: ${customer.maxConcurrentCalls}")
        }
    }

    private fun users(): String {
        val page = store.listCustomers(null, 50, null)
        if (page.items.isEmpty()) return "No customers yet."
        return page.items.joinToString("\n") {
            "${it.handle.padEnd(16)} ${formatMoney(it.balanceMicros, it.currency).padStart(12)}" +
                "  ${it.status.name.lowercase()}"
        }
    }
}
