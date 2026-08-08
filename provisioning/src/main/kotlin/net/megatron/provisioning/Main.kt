package net.megatron.provisioning

import io.ktor.server.engine.*
import io.ktor.server.netty.*

/**
 * Runs the provisioning API.
 *
 * BINDS LOOPBACK BY DEFAULT, and that is not a development convenience.
 * This service issues credentials and moves balance; on a public interface it
 * is a wire-transfer endpoint on a public interface. The Telegram bot reaches
 * it from the same host or through an authenticated tunnel — the same rule the
 * shield telemetry contract and the setup wizard already apply to the admin
 * console.
 *
 * Tokens come from the environment, never from a config file in the repo. The
 * setup wizard generates them into a mode-0600 secrets file; there is no
 * default and the service refuses to start without them, so there is no
 * equivalent of MagnusBilling's root/magnus to leave in place.
 */
fun main() {
    val host = System.getenv("MEGATRON_PROVISIONING_HOST") ?: "127.0.0.1"
    val port = System.getenv("MEGATRON_PROVISIONING_PORT")?.toIntOrNull() ?: 8081

    val operatorToken = System.getenv("MEGATRON_OPERATOR_TOKEN")
        ?: error(
            "MEGATRON_OPERATOR_TOKEN is not set. This service will not start without " +
                "one — a provisioning API with a default credential is the defect this " +
                "project exists to make impossible."
        )
    require(operatorToken.length >= 32) {
        "MEGATRON_OPERATOR_TOKEN must be at least 32 characters"
    }

    if (host != "127.0.0.1" && host != "::1" && host != "localhost") {
        System.err.println(
            "WARNING: binding $host, not loopback. This API issues credentials and moves " +
                "balance. If this is deliberate, it belongs behind an authenticated proxy."
        )
    }

    // ONE REALM, READ ONCE, PASSED TO BOTH.
    //
    // The store bakes this into every HA1 it generates, and the exporter asks
    // for credentials by it. Reading it in two places let them differ: the
    // store was constructed with its hardcoded default while the exporter read
    // the environment variable, so setting MEGATRON_SIP_REALM to anything else
    // meant every lookup missed and the credential file emptied itself.
    val realm = System.getenv("MEGATRON_SIP_REALM") ?: "sip.megatron.local"

    val dbUrl = System.getenv("MEGATRON_DB_URL")
    val store: Store = if (dbUrl.isNullOrBlank()) {
        System.err.println(
            "WARNING: MEGATRON_DB_URL is not set. Running on an in-memory store -- " +
                "every customer and balance is lost on exit. Set it to something like " +
                "jdbc:sqlite:/var/lib/megatron/megatron.db before this carries real money."
        )
        InMemoryStore(sipDomain = realm)
    } else {
        SqlStore(dbUrl, sipDomain = realm)
    }
    val authenticator = Authenticator { token ->
        if (token == operatorToken) Caller.Operator("operator") else null
    }

    startSubscriberExport(store, realm)

    embeddedServer(Netty, port = port, host = host) {
        provisioningModule(store, IdempotencyStore(), authenticator)
    }.start(wait = true)
}

/**
 * Keeps the switch's credential file in step with the customer list.
 *
 * A poll rather than a hook on every write, deliberately. Rendering inside the
 * request path would put a filesystem write between a customer's top-up and
 * its response, and would fail the request if the disk did — a provisioning
 * API that refuses to take money because a switch's credential file could not
 * be written has the dependency exactly backwards.
 *
 * The interval is what bounds how long a NEW customer waits for a login and
 * how long a CLOSED one keeps registering. Neither is a money question: the
 * authorizer decides on every call whether an account may spend, live, and it
 * is not reading this file. See SubscriberExport for that split.
 */
private fun startSubscriberExport(store: Store, realm: String) {
    val path = System.getenv("MEGATRON_SUBSCRIBER_FILE")
    if (path.isNullOrBlank()) {
        System.err.println(
            "NOTE: MEGATRON_SUBSCRIBER_FILE is not set, so no credential file is being " +
                "written. Customers created here will not be able to register until it is."
        )
        return
    }
    val seconds = System.getenv("MEGATRON_SUBSCRIBER_INTERVAL_SECONDS")?.toLongOrNull() ?: 15L
    val writer = SubscriberFile(java.nio.file.Path.of(path))

    // WRITING THE FILE IS NOT ENOUGH. OpenSIPS's db_text module reads its
    // tables into memory ONCE, at startup, and serves them from there. A file
    // that changes on disk changes nothing until the switch is told to reload.
    //
    // Without this, everything downstream looked correct and did nothing: a
    // new customer's credential reached the file and they still could not
    // register; a rotated password left the OLD one working indefinitely; a
    // suspended account kept registering forever. All silent, because from
    // provisioning's side the write succeeded.
    val publisher = CredentialPublisher(
        file = writer,
        reloader = SwitchReloader(System.getenv("MEGATRON_SWITCH_MI_URL")),
        realm = realm,
    )

    val thread = Thread {
        while (!Thread.currentThread().isInterrupted) {
            // Every failure inside is handled and logged; publish() never
            // throws, so one bad tick cannot end the thread and silently stop
            // every future credential from reaching the switch.
            publisher.publish(store)
            try {
                Thread.sleep(seconds * 1000)
            } catch (stop: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }
    // Daemon: this must never be the thread that keeps a shutting-down process
    // alive.
    thread.isDaemon = true
    thread.name = "subscriber-export"
    thread.start()
    System.err.println("writing $path every ${seconds}s for realm $realm")
}
