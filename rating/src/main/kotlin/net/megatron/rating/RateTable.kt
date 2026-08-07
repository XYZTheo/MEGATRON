package net.megatron.rating

/**
 * A plan's rate table, indexed for longest-prefix match.
 *
 * WHY A TRIE-SHAPED LOOKUP AND NOT A SCAN
 * ---------------------------------------
 * A real carrier rate table is tens of thousands of prefixes, and this lookup
 * happens on the call-setup path inside a 5 ms p99 budget. Scanning every row
 * per call is O(n) with n in the tens of thousands, per call, forever.
 *
 * The implementation here is deliberately simple: a hash map keyed by prefix,
 * probed from the longest possible prefix down to the shortest. An E.164
 * number is at most 15 digits, so a lookup is at most 15 hash probes
 * regardless of table size — bounded, allocation-free, and about as fast as a
 * real trie without the code.
 *
 * BUILT ONCE, READ MANY. Rate tables are replaced whole (see the provisioning
 * contract), so this is immutable and can be shared across threads without a
 * lock. That matters: the authorizer holds tariff data resident in-process
 * precisely so the hot path never touches PostgreSQL.
 */
class RateTable private constructor(
    private val byPrefix: Map<String, Rate>,
    private val longestPrefix: Int,
    val currency: String,
) {

    val size: Int get() = byPrefix.size

    /**
     * Longest-prefix match against a destination number.
     *
     * Returns null when nothing matches, and the caller must treat that as a
     * refusal rather than as free. A destination with no rate is one we have
     * no price for, and carrying it means carrying it at unknown cost — which
     * is how a switch discovers it has been terminating expensive satellite
     * traffic for a week.
     */
    fun lookup(destination: String): Rate? {
        val digits = normalise(destination)
        if (digits.isEmpty()) return null
        var length = minOf(digits.length, longestPrefix)
        while (length > 0) {
            byPrefix[digits.substring(0, length)]?.let { return it }
            length--
        }
        return null
    }

    /** Every prefix selling at or below the carrier's price. */
    fun sellingBelowCost(): List<Rate> = byPrefix.values.filter { it.sellsBelowCost }

    companion object {
        /**
         * A parenthesised national trunk prefix: the "(0)" in "+44 (0) 7700".
         */
        private val TRUNK_PREFIX_IN_PARENS = Regex("""\(\s*0\s*\)""")

        /**
         * Reduces a dialled or configured number to comparable digits.
         *
         * Non-digits are dropped rather than rejected: numbers arrive from
         * carriers, softphones and rate files in whatever shape each of them
         * felt like, and refusing one at 2am because of a space is not a
         * useful behaviour.
         *
         * THE "(0)" CASE IS NOT COSMETIC, IT IS A MISPRICING.
         * "+44 (0) 7700 900123" is the ordinary way a UK mobile number is
         * written, and the zero is a national trunk prefix that is NOT dialled
         * internationally. Filtering to digits naively keeps it, producing
         * 4407700900123 — which longest-prefix-matches "44" (UK landline)
         * instead of "4477" (UK mobile). Mobile termination is several times
         * the landline rate, so that single retained character is a call
         * billed at a fraction of its cost, silently, on every number written
         * that way.
         *
         * Found by a test whose expectation was wrong, which is the useful
         * kind of wrong.
         *
         * Out of scope here, deliberately: converting national dialling
         * (00 or 011 prefixes, bare national numbers) into E.164. That is
         * dial-plan translation, it depends on which country the customer is
         * in, and it belongs at the edge where the customer's locale is known
         * — not in the rate lookup, which must be handed an already-canonical
         * number.
         */
        fun normalise(destination: String): String =
            destination.replace(TRUNK_PREFIX_IN_PARENS, "").filter { it in '0'..'9' }

        /**
         * @throws IllegalArgumentException on a duplicate prefix. Two prices
         * for one prefix has no correct resolution — picking either silently
         * means the bill depends on map ordering — so it is refused at load
         * time, where somebody can fix the file.
         */
        fun of(rates: List<Rate>, currency: String = "USD"): RateTable {
            val map = HashMap<String, Rate>(rates.size * 2)
            var longest = 0
            for (rate in rates) {
                val existing = map.put(rate.prefix, rate)
                require(existing == null) {
                    "duplicate prefix '${rate.prefix}' in rate table: " +
                        "${existing?.sellPerMinute?.format()} and " +
                        "${rate.sellPerMinute.format()} — a prefix with two prices " +
                        "makes the bill depend on map ordering"
                }
                if (rate.prefix.length > longest) longest = rate.prefix.length
            }
            return RateTable(map, longest, currency)
        }
    }
}
