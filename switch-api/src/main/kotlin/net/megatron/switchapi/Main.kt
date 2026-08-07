package net.megatron.switchapi

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import net.megatron.provisioning.InMemoryStore

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

    val service = CallService(InMemoryStore(), cdrSink = { cdr ->
        // Stand-in for the ClickHouse pipeline (#8). Printed rather than
        // dropped, because a CDR that is silently discarded is revenue that
        // cannot be argued for with a carrier.
        println("CDR ${cdr.callId} ${cdr.account} -> ${cdr.destination} " +
            "${cdr.billedSeconds}s ${cdr.chargedMicros}u" +
            (if (cdr.noMedia) " NO-MEDIA" else "") +
            (if (cdr.overran) " OVERRAN" else ""))
    })

    embeddedServer(Netty, port = port, host = host) {
        switchApiModule(service)
    }.start(wait = true)
}
