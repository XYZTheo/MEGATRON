package net.megatron.rating

/**
 * Prices a call, and decides how long a prepaid caller can afford to talk.
 *
 * Pure functions, no I/O, no clock. That is not stylistic: this is the code
 * that decides what a customer is charged, and it has to be testable to the
 * cent without standing up a database. Everything stateful — balance
 * reservation, the ledger — lives outside.
 */
object RatingEngine {

    /**
     * Bill a completed call.
     *
     * The order of operations is the part people get wrong, so it is spelled
     * out: the minimum duration is applied FIRST, then the result is rounded
     * up to the next increment. Doing it the other way round under-bills a
     * short call on a plan with both set — a 3-second call on 60s minimum,
     * 6s increment bills 60 seconds, not 6.
     */
    fun rate(durationSeconds: Int, rate: Rate): CallCharge {
        require(durationSeconds >= 0) { "durationSeconds must not be negative" }

        // An unanswered call is not a call. No connect fee, no duration —
        // charging for a failed call attempt is how a customer stops trusting
        // the bill, and disputes cost more than the fee.
        if (durationSeconds == 0) {
            return CallCharge(
                billedSeconds = 0,
                connectFee = Micros.ZERO,
                durationCharge = Micros.ZERO,
                total = Micros.ZERO,
                rate = rate,
            )
        }

        val afterMinimum = maxOf(durationSeconds, rate.minimumSeconds)
        val billedSeconds = roundUpToIncrement(afterMinimum, rate.incrementSeconds)

        val durationCharge = Micros(
            perMinuteToCharge(billedSeconds.toLong(), rate.sellPerMinute.value)
        )
        return CallCharge(
            billedSeconds = billedSeconds,
            connectFee = rate.connectFee,
            durationCharge = durationCharge,
            total = rate.connectFee + durationCharge,
            rate = rate,
        )
    }

    /**
     * How many seconds this balance can pay for at this rate.
     *
     * This is what the authorizer needs at call setup: not "can they afford a
     * call" but "how long may this one run", which becomes the session timer.
     * Without it a prepaid call runs until the balance is already negative,
     * and the money is gone — one of the failure modes the architecture
     * exists to design out.
     *
     * Returns 0 when the balance cannot even cover the connect fee plus the
     * first billable increment, which is the honest answer: there is no
     * duration this caller can afford, so the call must not be authorized.
     */
    fun affordableSeconds(balance: Micros, rate: Rate, ceilingSeconds: Int = 4 * 60 * 60): Int {
        require(ceilingSeconds >= 0) { "ceilingSeconds must not be negative" }
        if (balance.isZeroOrLess) return 0

        val forDuration = balance.value - rate.connectFee.value
        if (forDuration <= 0) return 0

        // The first increment is charged in full the moment the call is
        // billable, so it has to be affordable before any time is granted.
        val firstBlock = maxOf(rate.minimumSeconds, rate.incrementSeconds)
        val firstBlockCost = perMinuteToCharge(firstBlock.toLong(), rate.sellPerMinute.value)
        if (firstBlockCost > forDuration) return 0

        if (rate.sellPerMinute.value == 0L) return ceilingSeconds

        // seconds = balance * 60 / perMinute, rounded DOWN. Rounding up here
        // would grant a second the caller cannot pay for, which is exactly
        // the leak this function exists to close.
        val seconds = Math.floorDiv(
            Math.multiplyExact(forDuration, 60L),
            rate.sellPerMinute.value
        )

        // Granting a partial increment is granting time that will be rounded
        // up and billed beyond the balance, so trim to whole increments.
        val whole = (seconds / rate.incrementSeconds) * rate.incrementSeconds
        val granted = maxOf(whole, firstBlock.toLong())

        return granted.coerceAtMost(ceilingSeconds.toLong()).toInt()
    }

    /** Rounds up to the next whole increment. */
    internal fun roundUpToIncrement(seconds: Int, incrementSeconds: Int): Int {
        require(incrementSeconds >= 1)
        if (seconds <= 0) return 0
        val blocks = (seconds + incrementSeconds - 1) / incrementSeconds
        return blocks * incrementSeconds
    }

    /**
     * seconds x (micros per minute) / 60, rounded HALF UP.
     *
     * Rounding has to be stated rather than inherited from whatever integer
     * division does, because integer division truncates toward zero and that
     * is a systematic under-charge on every single call. Half-up is the
     * conventional choice in telecoms billing and, more importantly, it is
     * symmetric — it does not quietly favour either party, which is what
     * makes it defensible in a dispute.
     */
    internal fun perMinuteToCharge(seconds: Long, microsPerMinute: Long): Long {
        if (seconds == 0L || microsPerMinute == 0L) return 0
        val numerator = Math.multiplyExact(seconds, microsPerMinute)
        return Math.floorDiv(numerator + 30, 60)
    }
}

/** What a call cost, itemised so a bill can be argued with. */
data class CallCharge(
    val billedSeconds: Int,
    val connectFee: Micros,
    val durationCharge: Micros,
    val total: Micros,
    val rate: Rate,
) {
    /** Our margin on this call, when the buy price is known. */
    fun margin(): Micros? {
        val buy = rate.buyPerMinute ?: return null
        val cost = Micros(RatingEngine.perMinuteToCharge(billedSeconds.toLong(), buy.value))
        return total - cost
    }
}
