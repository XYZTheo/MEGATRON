package net.megatron.provisioning

/**
 * Does a trunk's allowlist contain this address?
 *
 * This is the whole authentication for an inbound carrier — they do not log
 * in, the allowlist IS the credential — so it is written once, here, rather
 * than open-coded wherever an inbound call is checked.
 *
 * IPv4 only, matching what [InMemoryStore.CIDR] accepts into an allowlist in
 * the first place. Anything it cannot parse is a **no**: this function guards
 * an accept decision, so the failure direction has to be refusal. An operator
 * whose carrier is on IPv6 gets calls refused, which is visible, rather than
 * accepted, which is not.
 */
object IpAllowlist {

    /** True when [ip] falls inside any entry of [allowed]. */
    fun allows(allowed: List<String>, ip: String): Boolean =
        allowed.any { contains(it, ip) }

    /**
     * True when [ip] falls inside [entry], which is an address or a CIDR.
     *
     * A bare address is treated as a /32 rather than as a string comparison,
     * so `203.0.113.7` and `203.0.113.007` cannot disagree about whether they
     * are the same host.
     */
    fun contains(entry: String, ip: String): Boolean {
        val slash = entry.indexOf('/')
        val network = if (slash < 0) entry else entry.substring(0, slash)
        val bits = if (slash < 0) 32 else entry.substring(slash + 1).toIntOrNull() ?: return false
        if (bits !in 0..32) return false

        val networkValue = toLong(network) ?: return false
        val address = toLong(ip) ?: return false

        // A /0 would shift by 32, which on a 32-bit int is a no-op in the JVM
        // (shifts are taken mod 32) and would silently produce an all-ones
        // mask -- an allowlist entry meaning "everything" that behaves like a
        // single host. Long arithmetic, and the case named.
        if (bits == 0) return true
        val mask = (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
        return (networkValue and mask) == (address and mask)
    }

    /** Dotted quad to a 32-bit value, or null if it is not one. */
    private fun toLong(address: String): Long? {
        val parts = address.split('.')
        if (parts.size != 4) return null
        var value = 0L
        for (part in parts) {
            // Rejects "", "+7", " 7", "007" is fine (still 7) but "1e2" is not.
            if (part.isEmpty() || part.length > 3 || part.any { it !in '0'..'9' }) return null
            val octet = part.toInt()
            if (octet !in 0..255) return null
            value = (value shl 8) or octet.toLong()
        }
        return value
    }
}
