package net.megatron.switchapi

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.SqlStore

/**
 * Runs the switch API.
 *
 * Binds the PRIVATE interface. This service has no authentication by design
 * (see Server.kt) and that is only safe because the core has no route from
 * the internet — so binding it anywhere reachable turns a deliberate omission
 * into a hole.
 *
 * The in-memory store is shared with the provisioning service in this build,
 * which is what makes "create a customer in the bot, then place a call"
 * work end to end today. When PostgreSQL arrives, both point at that instead
 * and nothing else changes.
 */
fun main() {
    val host = System.getenv("MEGATRON_SWITCH_API_HOST") ?: "127.0.0.1"
    val port = System.getenv("MEGATRON_SWITCH_API_PORT")?.toIntOrNull() ?: 8082

    if (!host.startsWith("127.") && host != "::1" && host != "localhost" &&
        !host.startsWith("10.") && !host.startsWith("192.168.")
    ) {
        error(
            "refusing to bind '$host'. The switch API has no authentication because " +
                "the core has no route from the internet; binding a public address " +
                "turns that into an open endpoint that authorizes calls."
        )
    }

    // Same store as the provisioning API, so a customer created through the
    // bot can place a call immediately. MEGATRON_DB_URL points both services
    // at one database; without it, an in-memory store that is useful only for
    // a smoke test and says so.
    val dbUrl = System.getenv("MEGATRON_DB_URL")
    val store = if (dbUrl.isNullOrBlank()) {
        System.err.println(
            "WARNING: MEGATRON_DB_URL is not set, so this is running on an in-memory " +
                "store. Customers, balances and rates are shared with nothing and are " +
                "lost on exit."
        )
        InMemoryStore()
    } else {
        SqlStore(dbUrl)
    }

    // VELOCITY LIMITS, tunable but never off.
    //
    // The two rate limits fall back to the generous defaults in FraudGuard
    // rather than to "unlimited": a control an operator has not yet thought
    // about must still be protecting them, and these are set where no human
    // dialling by hand can reach them. The hourly spend cap is the one that
    // cannot have a sensible default -- the right number depends on what this
    // operator's customers pay for -- so it stays off until chosen, and the
    // absence is announced rather than assumed.
    val fraudDefaults = net.megatron.authorizer.FraudGuard.Limits()
    val spendCap = System.getenv("MEGATRON_FRAUD_MAX_SPEND_PER_HOUR_MICROS")?.toLongOrNull() ?: 0
    if (spendCap <= 0) {
        System.err.println(
            "NOTE: MEGATRON_FRAUD_MAX_SPEND_PER_HOUR_MICROS is not set, so no hourly " +
                "spend cap is enforced. Call-rate and destination-spread limits are " +
                "active. Set it to the most a single customer should ever be able to " +
                "spend in an hour."
        )
    }
    val fraud = net.megatron.authorizer.FraudGuard(
        net.megatron.authorizer.FraudGuard.Limits(
            maxCallsPerMinute = System.getenv("MEGATRON_FRAUD_MAX_CALLS_PER_MINUTE")
                ?.toIntOrNull() ?: fraudDefaults.maxCallsPerMinute,
            maxDestinationsPerMinute = System.getenv("MEGATRON_FRAUD_MAX_DESTINATIONS_PER_MINUTE")
                ?.toIntOrNull() ?: fraudDefaults.maxDestinationsPerMinute,
            maxSpendPerHourMicros = spendCap.coerceAtLeast(0),
        )
    )

    val service = CallService(store, fraud = fraud, cdrSink = { cdr ->
        // STORED, NOT JUST PRINTED. Every charge on the ledger came from a
        // call, and this is the row that says which one, how long it ran, at
        // what rate, and whether audio flowed. Without it "why is my bill this
        // much" has no answer and a disputed charge is settled by whoever
        // sounds more certain.
        //
        // Wrapped, because this runs on the settlement path: a call that has
        // already been charged must not fail because the history could not be
        // written. Loud, though — a CDR that vanishes silently is revenue that
        // cannot be argued for with a carrier either.
        try {
            store.recordCall(cdr.toCallRecord())
        } catch (failure: Throwable) {
            System.err.println("WARNING: could not store the CDR for ${cdr.callId}: $failure")
        }

        println("CDR ${cdr.callId} ${cdr.account} -> ${cdr.destination} " +
            "${cdr.billedSeconds}s ${cdr.chargedMicros}u [${cdr.durationSource}] " +
            "media=${cdr.mediaBytes ?: "unknown"}" +
            (if (cdr.noMedia) " NO-MEDIA" else "") +
            (if (cdr.overran) " OVERRAN" else ""))
    })

    embeddedServer(Netty, port = port, host = host) {
        switchApiModule(service)
    }.start(wait = true)
}
