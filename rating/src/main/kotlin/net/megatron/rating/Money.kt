package net.megatron.rating

/**
 * Money, as integer micro-units of the account currency.
 *
 * 1 unit = 1/1,000,000 of the currency. $1.00 is 1_000_000 micros.
 *
 * WHY NOT A FLOAT, AND WHY NOT BigDecimal EITHER
 * ----------------------------------------------
 * Floats are excluded because binary floating point cannot represent 0.1, and
 * a switch prices millions of calls a month at fractions of a cent. The error
 * is not theoretical: it accumulates in one direction and it is discovered by
 * a customer who reconciles their bill. `ci/policy_check.py` (MONEY-NOT-FLOAT)
 * fails the build on a `Double` or `Float` anywhere under a billing path.
 *
 * BigDecimal would be correct but is the wrong tool on the hot path. The
 * authorizer has a p99 budget of 5 ms and runs this per call setup; allocating
 * BigDecimals per rate lookup is allocation pressure in the one place the
 * architecture says not to create it. Long arithmetic is exact for our
 * magnitudes and free.
 *
 * MAGNITUDE CHECK, so the choice is justified rather than assumed:
 * Long holds ±9.22e18. A very expensive satellite destination at $50/minute
 * is 50_000_000 micros/minute. A 24-hour call at that rate is 7.2e10 micros —
 * eight orders of magnitude of headroom. Overflow is not reachable with real
 * telephony values, and [checkedPlus] catches it anyway rather than wrapping
 * silently into a negative balance.
 */
@JvmInline
value class Micros(val value: Long) : Comparable<Micros> {

    operator fun plus(other: Micros) = Micros(checkedPlus(value, other.value))
    operator fun minus(other: Micros) = Micros(checkedPlus(value, -other.value))
    operator fun compareTo(other: Long) = value.compareTo(other)
    override fun compareTo(other: Micros) = value.compareTo(other.value)

    val isPositive: Boolean get() = value > 0
    val isZeroOrLess: Boolean get() = value <= 0

    /** Human-readable, for logs and bot replies. Not for arithmetic. */
    fun format(currency: String = ""): String {
        val negative = value < 0
        val abs = if (negative) -value else value
        val whole = abs / MICROS_PER_UNIT
        val frac = abs % MICROS_PER_UNIT
        // Six decimal places, trailing zeros trimmed to at least two, so
        // "1.50" reads as money and "0.000125" keeps its precision.
        var fraction = frac.toString().padStart(6, '0').trimEnd('0')
        if (fraction.length < 2) fraction = fraction.padEnd(2, '0')
        val sign = if (negative) "-" else ""
        val suffix = if (currency.isEmpty()) "" else " $currency"
        return "$sign$whole.$fraction$suffix"
    }

    companion object {
        const val MICROS_PER_UNIT = 1_000_000L
        val ZERO = Micros(0)

        fun ofUnits(units: Long) = Micros(Math.multiplyExact(units, MICROS_PER_UNIT))

        private fun checkedPlus(a: Long, b: Long): Long =
            try {
                Math.addExact(a, b)
            } catch (e: ArithmeticException) {
                // Wrapping here would turn an enormous credit into a negative
                // balance, which is the kind of bug that only shows up once
                // and is catastrophic when it does.
                throw ArithmeticException("money overflow: $a + $b")
            }
    }
}
