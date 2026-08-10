package net.megatron.authorizer

import net.megatron.rating.Micros
import java.util.concurrent.ConcurrentHashMap

/**
 * Velocity controls: what a single account may do per unit of TIME.
 *
 * THE ATTACK THIS EXISTS TO STOP
 * ------------------------------
 * The concurrency cap in [Authorizer] bounds how many calls an account has up
 * at once. It does not bound how fast it may place them. A stolen SIP login is
 * monetised by dialling continuously — short calls to premium destinations, one
 * after another, for as long as the credential works. Ten concurrent calls
 * churning every four seconds is nine hundred calls an hour, and every one of
 * them is individually within every limit MEGATRON had.
 *
 * That is the shape of the fraud that empties a prepaid balance overnight and
 * the shape of the traffic that arrives when an operator's customer is
 * compromised. It is also the difference between "the balance ran out" and "the
 * operator owes a carrier for eight hundred calls to Latvia".
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 * --------------------------------
 * It does not suspend the account. A tripped limit refuses the call and records
 * why; a control that locks a customer out on its own judgement will eventually
 * do so wrongly, at night, to a business that then cannot make calls until
 * somebody reads a log. Refusing calls while the burst continues is reversible
 * within seconds and visible immediately. Suspension is the operator's decision,
 * and [tripped] is what they act on.
 *
 * IN-PROCESS AND PER-PROCESS, on purpose. The windows live in memory next to
 * the decision, because this runs on the call-setup path with a 5 ms budget and
 * a database round trip per call to count the previous calls would cost more
 * than the rest of authorization put together. The cost is that a restart
 * starts every window empty. That is a real gap and a small one: an attacker
 * cannot cause the restart, and the concurrency cap and balance are unaffected
 * by it.
 */
class FraudGuard(private val limits: Limits = Limits(), private val clock: () -> Long = System::currentTimeMillis) {

    /**
     * Defaults are GENEROUS BUT ON.
     *
     * A security control whose default is "off" protects nobody, and the
     * standing rule in this codebase is that a control's default must be the
     * safe answer. But a limit set too tight refuses honest traffic on day one,
     * and an operator whose customers cannot call will turn the whole thing off
     * rather than tune it — which is worse than a generous limit.
     *
     * So the two velocity limits are on, set where no human dialling by hand
     * and no ordinary office can reach them, and where a compromised endpoint
     * arrives in seconds.
     *
     * [maxSpendPerHourMicros] is the exception and is OFF unless configured.
     * The right number is a business fact — currency, margins, what a customer
     * pays for — and there is no value that is simultaneously meaningful for a
     * £50/month reseller and a wholesale account. A guessed default here would
     * cut off the operator's biggest customer first. The installer says so out
     * loud rather than picking a number nobody chose.
     */
    data class Limits(
        /** Calls STARTED per account per minute. A human cannot reach 60. */
        val maxCallsPerMinute: Int = 60,
        /**
         * Distinct destinations per account per minute.
         *
         * The signature of a compromised endpoint rather than a busy one: a
         * real office calls a small set of numbers repeatedly, a scanner walks
         * a range. Lower than the call limit on purpose — sixty calls to six
         * numbers is a call centre, sixty calls to sixty numbers is not.
         */
        val maxDestinationsPerMinute: Int = 30,
        /** Zero means unset. See the class comment. */
        val maxSpendPerHourMicros: Long = 0,
    ) {
        init {
            require(maxCallsPerMinute >= 1) { "maxCallsPerMinute must be at least 1" }
            require(maxDestinationsPerMinute >= 1) { "maxDestinationsPerMinute must be at least 1" }
            require(maxSpendPerHourMicros >= 0) { "maxSpendPerHourMicros must not be negative" }
        }
    }

    /** Why an account was refused, and the numbers behind it. */
    data class Trip(
        val accountId: String,
        val rule: String,
        val observed: Long,
        val limit: Long,
        /**
         * What to call the account in the message. See [Account.label] — the
         * first live run printed an internal id, which an operator has to look
         * up before the alert means anything.
         */
        val label: String = accountId,
    ) {
        /** For the operator's log. Never sent on the wire. */
        val detail: String
            get() = "$label hit $rule: $observed against a limit of $limit"
    }

    private class Window(val windowMillis: Long) {
        /** (timestamp, destination, micros) for every call in the window. */
        private val events = ArrayDeque<Triple<Long, String, Long>>()

        @Synchronized
        fun record(now: Long, destination: String, micros: Long) {
            events.addLast(Triple(now, destination, micros))
            prune(now)
        }

        @Synchronized
        fun count(now: Long): Int {
            prune(now)
            return events.size
        }

        @Synchronized
        fun distinctDestinations(now: Long): Int {
            prune(now)
            return events.mapTo(HashSet()) { it.second }.size
        }

        @Synchronized
        fun contains(now: Long, destination: String): Boolean {
            prune(now)
            return events.any { it.second == destination }
        }

        @Synchronized
        fun spend(now: Long): Long {
            prune(now)
            // addExact, not +. Money never silently wraps in this codebase, and
            // a wrapped sum here would read as "well under the limit".
            return events.fold(0L) { total, event -> Math.addExact(total, event.third) }
        }

        /**
         * Drops everything older than the window.
         *
         * From the FRONT only, which is what makes this bounded: events are
         * appended in time order, so the expired ones are always at the head.
         * Without it a busy account's list grows for the life of the process —
         * a memory leak on the hot path, arrived at by an account being busy,
         * which is exactly when it must not happen.
         */
        private fun prune(now: Long) {
            val cutoff = now - windowMillis
            while (events.isNotEmpty() && events.first().first <= cutoff) events.removeFirst()
        }
    }

    private val minute = ConcurrentHashMap<String, Window>()
    private val hour = ConcurrentHashMap<String, Window>()

    /**
     * May this account start a call to [destination] right now?
     *
     * Returns null to allow, or the [Trip] that refuses it. Nothing is recorded
     * by asking — [record] is called only when the call is actually allowed, so
     * a refused call does not deepen the hole it is already in. (An earlier
     * shape counted every attempt, which meant that once an account tripped,
     * the refusals themselves kept it tripped for a full window even if the
     * attacker stopped.)
     */
    fun check(
        accountId: String,
        destination: String,
        estimatedMicros: Long = 0,
        label: String = accountId,
    ): Trip? {
        val now = clock()
        val perMinute = minute.computeIfAbsent(accountId) { Window(60_000) }

        val calls = perMinute.count(now)
        if (calls >= limits.maxCallsPerMinute) {
            return Trip(
                accountId, "calls-per-minute", calls.toLong(),
                limits.maxCallsPerMinute.toLong(), label,
            )
        }

        // Only counted as a NEW destination if it is one. A call to a number
        // already in the window cannot push an account over a diversity limit,
        // which is what makes redialling one number safe at any rate the call
        // limit allows.
        val destinations = perMinute.distinctDestinations(now)
        if (destinations >= limits.maxDestinationsPerMinute && !perMinute.contains(now, destination)) {
            return Trip(
                accountId, "destinations-per-minute",
                destinations.toLong(), limits.maxDestinationsPerMinute.toLong(), label,
            )
        }

        if (limits.maxSpendPerHourMicros > 0) {
            val spent = hour.computeIfAbsent(accountId) { Window(3_600_000) }.spend(now)
            val projected = Math.addExact(spent, estimatedMicros)
            if (projected > limits.maxSpendPerHourMicros) {
                return Trip(
                    accountId, "spend-per-hour", projected,
                    limits.maxSpendPerHourMicros, label,
                )
            }
        }

        return null
    }

    /** Called once a call has actually been allowed. */
    fun record(accountId: String, destination: String, reservedMicros: Long) {
        val now = clock()
        minute.computeIfAbsent(accountId) { Window(60_000) }.record(now, destination, reservedMicros)
        if (limits.maxSpendPerHourMicros > 0) {
            hour.computeIfAbsent(accountId) { Window(3_600_000) }.record(now, destination, reservedMicros)
        }
    }

    /**
     * Forgets an account's history.
     *
     * For the operator who has dealt with a compromise — rotated the password,
     * confirmed the traffic stopped — and wants the customer working again
     * without waiting out a window. Without it the only remedy is to wait, and
     * an operator with an angry customer on the phone will restart the service
     * instead, which clears every account's window at once.
     */
    fun clear(accountId: String) {
        minute.remove(accountId)
        hour.remove(accountId)
    }
}
