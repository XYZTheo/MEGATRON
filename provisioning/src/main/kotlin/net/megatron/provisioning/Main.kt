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

    val store = InMemoryStore()
    val authenticator = Authenticator { token ->
        if (token == operatorToken) Caller.Operator("operator") else null
    }

    embeddedServer(Netty, port = port, host = host) {
        provisioningModule(store, IdempotencyStore(), authenticator)
    }.start(wait = true)
}
