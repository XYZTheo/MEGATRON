package net.megatron.rating

/**
 * One row of a rate table: what a destination prefix costs.
 *
 * Matches the `Rate` schema in contracts/provisioning.openapi.yaml. If the two
 * drift, the contract wins — it is what the Telegram bot and the console are
 * written against.
 */
data class Rate(
    /** Destination prefix, digits only. Longest match wins. */
    val prefix: String,

    /** What the customer pays, per minute. */
    val sellPerMinute: Micros,

    /**
     * What the carrier charges us, per minute. Optional, and worth having:
     * without it there is no margin figure and no way to warn that a prefix
     * is selling below cost — which is a thing that happens quietly every
     * time a carrier sends an updated rate file.
     */
    val buyPerMinute: Micros? = null,

    /** Charged once on answer, before any duration is billed. */
    val connectFee: Micros = Micros.ZERO,

    /**
     * Billing granularity. 60 is per-minute, 1 is per-second, 6 is the common
     * "6-second increments after the first minute" shape when combined with
     * [minimumSeconds].
     */
    val incrementSeconds: Int = 60,

    /**
     * Shortest billable duration. A 3-second call on a 60/60 plan bills a
     * full minute. This is normal in wholesale and is the single most common
     * source of "why is my bill higher than my call log" — so it is explicit
     * here rather than implied by the increment.
     */
    val minimumSeconds: Int = 0,

    val description: String = "",
) {
    init {
        require(prefix.isNotEmpty()) { "rate prefix must not be empty" }
        require(prefix.all { it in '0'..'9' }) {
            "rate prefix must be digits only, got '$prefix'"
        }
        require(incrementSeconds >= 1) { "incrementSeconds must be >= 1" }
        require(minimumSeconds >= 0) { "minimumSeconds must be >= 0" }
        require(sellPerMinute.value >= 0) { "sellPerMinute must not be negative" }
        require(connectFee.value >= 0) { "connectFee must not be negative" }
    }

    /**
     * Margin per minute, when the buy price is known.
     *
     * Negative means this prefix sells below cost. That is not always a
     * mistake — loss-leaders exist — but it should never be a surprise, which
     * is why [RateTable] can report them all at load time.
     */
    val marginPerMinute: Micros?
        get() = buyPerMinute?.let { sellPerMinute - it }

    val sellsBelowCost: Boolean
        get() = marginPerMinute?.isZeroOrLess == true
}
