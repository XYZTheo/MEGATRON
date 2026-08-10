package net.megatron.authorizer

import net.megatron.rating.Micros
import net.megatron.rating.RateTable
import net.megatron.rating.RatingEngine

/** Why a call was refused. Every reason is one an operator can act on. */
enum class Refusal {
    /**
     * The account does not exist.
     *
     * Distinct from ACCOUNT_SUSPENDED on purpose. Reporting an unknown
     * account as "suspended" sends an operator looking at a customer record
     * that is not there -- it masqueraded as a business decision while
     * actually being a data problem, and it hid a real bug for a while.
     */
    NO_SUCH_ACCOUNT,
    ACCOUNT_SUSPENDED,
    NO_RATE_FOR_DESTINATION,
    INSUFFICIENT_BALANCE,
    CONCURRENT_CALL_LIMIT,
    INVALID_DESTINATION,

    /**
     * The account is placing calls faster than any legitimate use of it does.
     *
     * Distinct from CONCURRENT_CALL_LIMIT, which is about how many calls are up
     * at once. This is about rate, and it is the one that catches a stolen
     * login: ten calls at a time, each lasting four seconds, breaks no other
     * limit here and empties an account overnight.
     */
    FRAUD_VELOCITY,
}

sealed interface Decision {
    /**
     * Proceed, for at most [maxSeconds]. That number becomes the session
     * timer on the call — without it a prepaid call runs until the balance is
     * already negative and the money is gone.
     */
    data class Allow(
        val reservationId: String,
        val maxSeconds: Int,
        val reserved: Micros,
        val ratePerMinute: Micros,
        val prefix: String,
    ) : Decision

    data class Reject(val reason: Refusal, val detail: String) : Decision
}

/**
 * The decision on the call-setup path: may this call proceed, and for how long.
 *
 * Ordered cheapest-check-first, deliberately. Refusing a suspended account
 * costs a boolean; refusing an unrated destination costs a map probe; the
 * reservation is the only one that touches shared state. Under a flood the
 * cheap refusals are the ones doing the work, and the same principle governs
 * the edge tier — cost to reject must stay far below cost to send.
 */
class Authorizer(
    private val ledger: Ledger,
    private val ceilingSeconds: Int = 4 * 60 * 60,
    private val fraud: FraudGuard = FraudGuard(),
    /**
     * Where a tripped velocity limit is reported.
     *
     * A control that silently refuses calls is indistinguishable from a broken
     * switch: the customer says "I cannot call out", the operator sees nothing,
     * and the first explanation anyone finds is the wrong one. The trip carries
     * the account, the rule and the numbers precisely so that conversation is
     * one sentence long.
     */
    private val onTrip: (FraudGuard.Trip) -> Unit = {
        System.err.println("FRAUD GUARD: ${it.detail}")
    },
) {

    fun authorize(
        account: Account,
        destination: String,
        rates: RateTable,
        reservationId: String,
    ): Decision {
        if (account.suspended) {
            return Decision.Reject(
                Refusal.ACCOUNT_SUSPENDED,
                "account ${account.id} is suspended"
            )
        }

        val digits = RateTable.normalise(destination)
        if (digits.isEmpty()) {
            return Decision.Reject(
                Refusal.INVALID_DESTINATION,
                "destination '$destination' contains no digits"
            )
        }

        // Concurrency cap before the rate lookup: it is cheaper, and it is the
        // control that bounds the damage when a customer's credentials have
        // been stolen. Most VoIP fraud is a compromised endpoint placing many
        // simultaneous calls, not one long one.
        if (ledger.activeCalls(account.id) >= account.maxConcurrentCalls) {
            return Decision.Reject(
                Refusal.CONCURRENT_CALL_LIMIT,
                "account ${account.id} already has ${account.maxConcurrentCalls} calls up"
            )
        }

        val rate = rates.lookup(digits)
            ?: return Decision.Reject(
                Refusal.NO_RATE_FOR_DESTINATION,
                "no rate matches '$digits' — refused rather than carried at unknown cost"
            )

        // What this call may cost is computed against what is AVAILABLE, not
        // against the raw balance: money already reserved by calls in progress
        // is money this call cannot have.
        val available = ledger.availableTo(account)
        val seconds = RatingEngine.affordableSeconds(available, rate, ceilingSeconds)
        if (seconds <= 0) {
            return Decision.Reject(
                Refusal.INSUFFICIENT_BALANCE,
                "available ${available.format()} does not cover a call to '$digits'"
            )
        }

        // Reserve exactly what the granted duration will bill, so the
        // settlement can only ever return money, never discover a shortfall.
        val toReserve = RatingEngine.rate(seconds, rate).total

        // VELOCITY, CHECKED LAST AND BEFORE THE RESERVATION.
        //
        // Last, because it is the only check that needs to know what the call
        // would cost, and cost is not known until the rate and the affordable
        // duration are. Before the reservation, because a refused call must not
        // hold money — and because a call that is about to be refused should
        // not appear in the account's own velocity history.
        fraud.check(account.id, digits, toReserve.value, account.label ?: account.id)?.let { trip ->
            onTrip(trip)
            return Decision.Reject(
                Refusal.FRAUD_VELOCITY,
                // The numbers are for the operator. The customer's phone shows
                // a SIP code and nothing else -- an attacker who can read the
                // exact limit knows exactly what rate to stay under.
                trip.detail,
            )
        }

        val reservation = ledger.reserve(account, toReserve, seconds, reservationId)
            ?: return Decision.Reject(
                Refusal.INSUFFICIENT_BALANCE,
                "lost a race for the remaining balance on ${account.id}"
            )

        // Recorded only now, when the call is genuinely going ahead. Counting
        // attempts instead would mean a tripped account stays tripped for a
        // whole window on the strength of its own refusals, even if whatever
        // was hammering it has stopped.
        fraud.record(account.id, digits, toReserve.value)

        return Decision.Allow(
            reservationId = reservation.id,
            maxSeconds = seconds,
            reserved = toReserve,
            ratePerMinute = rate.sellPerMinute,
            prefix = rate.prefix,
        )
    }

    /**
     * Settle a finished call.
     *
     * [durationSeconds] is what actually happened on the wire. The charge is
     * recomputed from it rather than trusting the reservation, because the
     * reservation was a ceiling and almost every call ends before it.
     */
    fun settle(
        reservationId: String,
        durationSeconds: Int,
        destination: String,
        rates: RateTable,
    ): Ledger.Settlement {
        val rate = rates.lookup(destination)
            ?: throw IllegalStateException(
                "settling a call to '$destination' with no rate — it should never have " +
                    "been authorized"
            )
        val charge = RatingEngine.rate(durationSeconds, rate)
        return ledger.settle(reservationId, charge.total)
    }

    /** The call never connected. Release the hold, charge nothing. */
    fun abandon(reservationId: String): Boolean = ledger.release(reservationId)
}
