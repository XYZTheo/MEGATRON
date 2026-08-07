package net.megatron.switchapi

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json

// explicitNulls = false keeps absent fields out of the response entirely
// rather than emitting `"max_seconds": null`. OpenSIPS parses this in config
// script; a field that is present-but-null is one more thing for a language
// with no types to get wrong.
private val json = Json { explicitNulls = false; ignoreUnknownKeys = true }

/**
 * The HTTP surface OpenSIPS calls via `rest_client`.
 *
 * NO AUTHENTICATION HERE, AND THAT IS DELIBERATE — but it is only safe
 * because of where it binds. This service listens on the private core
 * network, reachable from allowlisted edge nodes and nothing else
 * (ARCHITECTURE.md §4.5b). Adding a shared secret that lives in an OpenSIPS
 * config file, on a node whose entire security property is holding no
 * credentials, would weaken the design rather than strengthen it.
 *
 * If this ever needs to be reachable from somewhere less trusted, the answer
 * is mutual TLS, not a token in a config file.
 */
fun Application.switchApiModule(service: CallService) {
    install(ContentNegotiation) { json(json) }

    install(StatusPages) {
        exception<IllegalStateException> { call, cause ->
            // A BYE for a call we never authorized. Usually a restart mid-call
            // or a duplicate; it must not 500, because OpenSIPS will retry a
            // 5xx and a retry storm on the money path is the last thing a
            // switch under load needs.
            call.application.log.warn("unusable session: ${cause.message}")
            call.respondProblem(HttpStatusCode.Conflict, "Unknown session", cause.message)
        }
        exception<Throwable> { call, cause ->
            call.application.log.error("switch-api failure", cause)
            call.respondProblem(
                HttpStatusCode.InternalServerError, "Internal error",
                "The request could not be completed."
            )
        }
    }

    routing {
        route("/v1") {

            post("/authorize") {
                call.respond(service.authorize(call.receive<AuthorizeRequest>()))
            }

            post("/session/end") {
                call.respond(service.endSession(call.receive<EndSessionRequest>()))
            }

            post("/session/abandon") {
                val body = call.receive<EndSessionRequest>()
                val released = service.abandon(body.callId)
                call.respond(mapOf("released" to released))
            }

            get("/health") {
                call.respond(
                    mapOf(
                        "status" to "ok",
                        "active_calls" to service.activeCalls().toString(),
                    )
                )
            }
        }
    }
}

private suspend fun ApplicationCall.respondProblem(
    status: HttpStatusCode,
    title: String,
    detail: String?,
) {
    response.status(status)
    respondText(
        json.encodeToString(
            Problem.serializer(),
            Problem(title = title, status = status.value, detail = detail)
        ),
        ContentType("application", "problem+json"),
    )
}
