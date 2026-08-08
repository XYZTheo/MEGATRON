package net.megatron.provisioning

import java.security.MessageDigest

/**
 * Renders the customer list into the `subscriber` table OpenSIPS's auth_db
 * module reads, in db_text format.
 *
 * WHY THIS EXISTS AT ALL. OpenSIPS cannot call an HTTP API to authenticate a
 * REGISTER — auth_db verifies the digest response itself, against a row it
 * reads from a database it is configured to speak to. So either the switch
 * gets credentials to our provisioning database, or provisioning renders the
 * subset the switch needs and hands it over. This is the second, because:
 *
 *  - the switch never gets read access to balances, transactions, or the
 *    Telegram mapping — the blast radius of a compromised switch is the
 *    credentials it needed anyway to route calls, and nothing else;
 *  - a db_text file has no listener, so it cannot be the thing that is
 *    attacked. The reason this project exists is that MagnusBilling keeps
 *    getting attacked, and its database is reachable from its web tier.
 *
 * WHAT IT COSTS. A file is a snapshot. A customer suspended at 14:00 keeps
 * registering until the file is next written and OpenSIPS reloads it. That is
 * acceptable for the CREDENTIAL check and unacceptable for the MONEY check,
 * which is why suspension and balance are enforced live by the authorizer on
 * every single call, not here. Registration proves who you are; it does not
 * buy you anything. See docs/ARCHITECTURE.md.
 *
 * MD5 IS NOT NEGOTIABLE HERE. RFC 2617 digest defines HA1 as MD5, and every
 * softphone MEGATRON targets speaks exactly that. A stronger hash would mean
 * no customer could register.
 */
object SubscriberExport {

    /**
     * The db_text column header.
     *
     * OpenSIPS refuses to load a db_text table whose header does not declare
     * the columns the module asks for, so this list is not decoration and the
     * order is not free — auth_db reads them by name, and a missing one is a
     * startup failure rather than a silent degradation.
     */
    private const val HEADER = "username(str) domain(str) ha1(str)"

    /**
     * Characters db_text uses structurally. A value containing one of these
     * would end the field early and shift every column after it — which for
     * this table means one customer's row bleeding into another's credential.
     *
     * Handles are already constrained to `[a-z0-9._-]` at creation, so this
     * cannot currently trigger. It is checked anyway: the validation lives in
     * a different file from this one, and the day somebody widens it, the
     * failure here would be silent and would hand out working logins for
     * accounts nobody created.
     */
    private val UNSAFE = Regex("[:\\n\\r\\\\]")

    /**
     * What an HA1 may look like: exactly 32 lower-case hex digits.
     *
     * Stricter than "contains nothing structural", because the shape is known
     * exactly. A value that is not an MD5 digest cannot authenticate anyone,
     * so writing it can only ever produce a customer who mysteriously cannot
     * log in — better to refuse loudly at export than to publish a row that
     * looks like a credential and is not.
     */
    private val HEX = Regex("^[0-9a-f]{32}$")

    /**
     * @param realm the SIP domain. It is baked into every HA1, so a file
     *   rendered for one realm authenticates nobody on another.
     */
    fun render(
        customers: List<Customer>,
        ha1For: (handle: String) -> String?,
        realm: String,
    ): String {
        require(realm.isNotBlank()) { "a realm is required: HA1 is meaningless without one" }
        require(!UNSAFE.containsMatchIn(realm)) { "realm '$realm' is not safe for db_text" }

        val rows = customers
            // Suspended and closed accounts are omitted rather than written
            // with a blank credential. A row with an empty ha1 is a row a
            // misconfigured auth module can match on an empty digest; absence
            // cannot be matched by anything.
            .filter { it.status == CustomerStatus.ACTIVE }
            .sortedBy { it.handle }
            .mapNotNull { customer ->
                require(!UNSAFE.containsMatchIn(customer.handle)) {
                    "handle '${customer.handle}' is not safe for db_text"
                }
                // A customer created before HA1 was stored has none, including
                // every row an upgraded database migrated. Skipping is
                // correct: writing a placeholder would be a password shared by
                // everyone in that position.
                //
                // They recover by having their credentials rotated — `/rotate
                // <handle>` in the bot, or POST /v1/customers/{id}/credentials.
                // That command was written because this sentence claimed it
                // existed and it did not, which made the documented recovery
                // from "your customers cannot register" a dead end.
                val ha1 = ha1For(customer.handle)?.takeIf { it.isNotBlank() } ?: return@mapNotNull null

                // THE CREDENTIAL IS CHECKED TOO, not just the handle and the
                // realm. It arrives from a lambda this object does not own —
                // SqlStore hands back the sip_ha1 column unexamined — so it is
                // exactly as untrusted as the other two fields, and the
                // argument written above UNSAFE applies to it word for word.
                //
                // A value containing a newline forges an ENTIRE EXTRA
                // SUBSCRIBER ROW: an account nobody created, with a password
                // the writer chose, holding a working login for the switch.
                // One containing ':' shifts every column after it. Anything
                // with write access to that single column — a bad migration,
                // an operator with sqlite3, a future import path — gets in.
                //
                // HA1 is always generated today, so this is defence in depth.
                // It is also the standard this file set for itself two fields
                // earlier, and the reason given there was that the validation
                // lives somewhere else and the day it moves, the failure here
                // is silent.
                require(!UNSAFE.containsMatchIn(ha1)) {
                    "the stored credential for '${customer.handle}' is not safe for db_text"
                }
                require(HEX.matches(ha1)) {
                    "the stored credential for '${customer.handle}' is not an MD5 digest"
                }

                "${customer.handle}:$realm:$ha1"
            }

        // Trailing newline: OpenSIPS's db_text parser drops a final line with
        // no terminator, which silently loses whichever customer sorts last.
        return (listOf(HEADER) + rows).joinToString("\n", postfix = "\n")
    }

    /*
     * NO ha1b COLUMN, AND THE REASON IS WORTH KEEPING.
     *
     * ha1b = MD5(username@domain:realm:password), the variant some tables
     * carry for phones that put the qualified `user@domain` in the
     * Authorization username. An earlier version of this file emitted the
     * column with an EMPTY value, reasoning that a value the config never
     * consults is inert.
     *
     * It is not inert. db_text validates every declared column on load and
     * rejects a null field, so one empty value did not degrade one login —
     * it made the entire subscriber table fail to parse, which auth_db
     * reports as "table 'subscriber' does not exist" and the customer sees as
     * a 500 on every REGISTER. An unused column is not free.
     *
     * It is also unnecessary: OpenSIPS 3.6's auth_db exposes password_column
     * and no second one, so it never reads ha1b. Emitting it would mean
     * storing a second password-equivalent value for nothing.
     */

    /** MD5, hex, lower case — the only encoding SIP digest accepts. */
    fun md5Hex(input: String): String =
        MessageDigest.getInstance("MD5")
            .digest(input.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
