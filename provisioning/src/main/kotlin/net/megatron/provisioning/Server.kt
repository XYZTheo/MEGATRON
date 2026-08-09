package net.megatron.provisioning

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json

/**
 * Who is calling, and what they are allowed to reach.
 *
 * The operator/customer split is the most important boundary in this service.
 * A customer reaching an operator verb is unlimited free credit, so the
 * separation is structural — customer routes live under /v1/me with no id in
 * the path to tamper with — rather than an ownership check inside a handler
 * somebody may forget to write.
 */
sealed interface Caller {
    data class Operator(val id: String) : Caller
    data class Customer(val customerId: String) : Caller
}

/**
 * Resolves a bearer token to a caller.
 *
 * Deliberately an interface: the real one checks hashed tokens in the
 * database. This is the seam where the Telegram bot's operator token and a
 * customer's self-service token are told apart.
 */
fun interface Authenticator {
    fun resolve(token: String): Caller?
}

class ProvisioningService(
    private val store: Store,
    private val idempotency: IdempotencyStore,
    private val authenticator: Authenticator,
)

private val json = Json {
    prettyPrint = false
    ignoreUnknownKeys = false
    encodeDefaults = true
}

/** Reads and validates the Idempotency-Key the contract requires on mutations. */
private fun ApplicationCall.idempotencyKey(): String {
    val key = request.headers["Idempotency-Key"]
        ?: throw Invalid(
            "Idempotency-Key header is required on this request. A client that retries " +
                "after a timeout must not move money twice."
        )
    if (key.length !in 8..128) {
        throw Invalid("Idempotency-Key must be 8-128 characters")
    }
    return key
}

fun Application.provisioningModule(
    store: Store,
    idempotency: IdempotencyStore = IdempotencyStore(),
    authenticator: Authenticator,
) {
    install(ContentNegotiation) {
        // JSON only, and no HTML anywhere. MagnusBilling's CVE-2025-2609 and
        // CVE-2025-2610 were stored XSS reachable because API responses were
        // served as text/html; an API that cannot emit HTML cannot have that
        // bug at all.
        json(json)
    }

    install(StatusPages) {
        exception<Unauthorized> { call, cause ->
            // 401, not 500. Without this handler an auth failure falls through
            // to the generic one and reports an internal error — which hides a
            // refusal among real faults, and trains whoever is watching the
            // logs to ignore 500s from this service.
            //
            // The detail is deliberately vague to the caller: distinguishing
            // "no token", "unknown token" and "wrong scope" out loud tells an
            // attacker which of the three they achieved.
            call.application.log.info("refused: ${cause.message}")
            call.problem(
                HttpStatusCode.Unauthorized,
                "Unauthorized",
                "A valid bearer token for this operation is required."
            )
        }
        exception<Invalid> { call, cause ->
            call.problem(HttpStatusCode.BadRequest, "Invalid request", cause.message)
        }
        exception<NotFound> { call, cause ->
            call.problem(HttpStatusCode.NotFound, "Not found", cause.message)
        }
        exception<Conflict> { call, cause ->
            call.problem(HttpStatusCode.Conflict, "Conflict", cause.message)
        }
        exception<IdempotencyConflict> { call, cause ->
            call.problem(
                HttpStatusCode.Conflict, "Idempotency-Key reused", cause.message
            )
        }
        exception<io.ktor.server.plugins.BadRequestException> { call, cause ->
            // A BODY WE CANNOT PARSE IS THE CALLER'S MISTAKE, NOT OURS.
            //
            // Without this it fell to the generic handler and came back as
            // "500 Internal error — the request could not be completed",
            // which says the server broke. It had not: the request named an
            // enum value that does not exist.
            //
            // That cost real time in the lab. A trunk was created with
            // "direction":"OUTBOUND" (the wire name is lower case), the 500
            // was ignored by a script that discarded the response, and the
            // only visible symptom was every later call refused with 503 by
            // the no-route guard — which reads like a routing bug rather than
            // a trunk that never existed.
            //
            // The cause is unwrapped because Ktor's own message is just
            // "Failed to convert request body"; the useful sentence is
            // underneath it, and it is about the caller's JSON, not about us.
            val detail = generateSequence(cause as Throwable) { it.cause }
                .mapNotNull { it.message }
                .lastOrNull()
                ?: "the request body could not be read"
            call.problem(HttpStatusCode.BadRequest, "Invalid request", detail)
        }
        exception<Throwable> { call, cause ->
            // Never leak a stack trace or an internal message to a caller.
            // The detail goes to the log; the caller gets a reference.
            call.application.log.error("unhandled failure", cause)
            call.problem(
                HttpStatusCode.InternalServerError,
                "Internal error",
                "The request could not be completed."
            )
        }
    }

    routing {
        route("/v1") {

            // ---- operator scope ------------------------------------------

            route("/customers") {
                post {
                    val caller = call.requireOperator(authenticator)
                    val key = call.idempotencyKey()
                    val body = call.receive<CreateCustomer>()
                    idempotency.replay(key, body.hashCode())?.let {
                        call.respondText(it, ContentType.Application.Json, HttpStatusCode.Created)
                        return@post
                    }
                    val (customer, credentials) = store.createCustomer(body, caller.id)
                    val response = CustomerCreated(customer, credentials)
                    val encoded = json.encodeToString(CustomerCreated.serializer(), response)
                    idempotency.remember(key, body.hashCode(), encoded)
                    call.respondText(encoded, ContentType.Application.Json, HttpStatusCode.Created)
                }

                get {
                    call.requireOperator(authenticator)
                    val status = call.request.queryParameters["status"]?.let {
                        runCatching { CustomerStatus.valueOf(it.uppercase()) }.getOrNull()
                            ?: throw Invalid("unknown status '$it'")
                    }
                    val limit = (call.request.queryParameters["limit"]?.toIntOrNull() ?: 50)
                        .coerceIn(1, 200)
                    val cursor = call.request.queryParameters["cursor"]
                    call.respond(store.listCustomers(status, limit, cursor))
                }

                get("/{customerId}") {
                    call.requireOperator(authenticator)
                    call.respond(store.getCustomer(call.customerId()))
                }

                /**
                 * A customer by the name they are known by, rather than by id.
                 *
                 * Management layers key on the handle — it is what the
                 * operator typed, what the softphone registers with, and what
                 * appears on a CDR — while everything internal keys on the id.
                 * Without this, every by-name call becomes list-and-scan.
                 *
                 * Registered BEFORE "/{customerId}" would be ambiguous, so it
                 * sits under a literal prefix that no id can collide with.
                 */
                get("/by-handle/{handle}") {
                    call.requireOperator(authenticator)
                    val handle = call.parameters["handle"] ?: throw Invalid("handle required")
                    call.respond(
                        store.findByHandle(handle) ?: throw NotFound("customer '$handle'")
                    )
                }

                get("/by-handle/{handle}/calls") {
                    call.requireOperator(authenticator)
                    val handle = call.parameters["handle"] ?: throw Invalid("handle required")
                    store.findByHandle(handle) ?: throw NotFound("customer '$handle'")
                    call.respond(store.callsFor(handle, call.callLimit()))
                }

                /** A customer's own call history, by id. */
                get("/{customerId}/calls") {
                    call.requireOperator(authenticator)
                    val customer = store.getCustomer(call.customerId())
                    call.respond(store.callsFor(customer.handle, call.callLimit()))
                }

                /**
                 * Moves a customer onto another plan.
                 *
                 * PUT, not POST: setting the plan to X twice leaves them on X.
                 * Naming it after the thing being replaced rather than an
                 * action is also what makes that obvious.
                 */
                put("/{customerId}/plan") {
                    val caller = call.requireOperator(authenticator)
                    call.idempotencyKey()
                    val body = call.receive<SetPlan>()
                    call.respond(store.setPlan(call.customerId(), body.planId, caller.id))
                }

                /**
                 * Withdraws a caller ID.
                 *
                 * Distinct from setting a different one. A number withdrawn
                 * because it was never theirs must fall back to the
                 * operator's default, not leave the last authorised number in
                 * place.
                 */
                delete("/{customerId}/caller-id") {
                    val caller = call.requireOperator(authenticator)
                    call.respond(store.clearCallerId(call.customerId(), caller.id))
                }

                put("/{customerId}/status") {
                    val caller = call.requireOperator(authenticator)
                    call.idempotencyKey()
                    val body = call.receive<SetStatus>()
                    call.respond(store.setStatus(call.customerId(), body, caller.id))
                }

                post("/{customerId}/credentials") {
                    call.requireOperator(authenticator)
                    val key = call.idempotencyKey()
                    val id = call.customerId()
                    idempotency.replay(key, id.hashCode())?.let {
                        call.respondText(it, ContentType.Application.Json)
                        return@post
                    }
                    val credentials = store.rotateCredentials(id)
                    val encoded = json.encodeToString(SipCredentials.serializer(), credentials)
                    idempotency.remember(key, id.hashCode(), encoded)
                    call.respondText(encoded, ContentType.Application.Json)
                }

                post("/{customerId}/balance") {
                    val caller = call.requireOperator(authenticator)
                    val key = call.idempotencyKey()
                    val id = call.customerId()
                    val body = call.receive<BalanceAdjustment>()
                    // The body hash includes the customer id, so the same key
                    // cannot be replayed against a different customer.
                    val hash = (id to body).hashCode()
                    idempotency.replay(key, hash)?.let {
                        call.respondText(it, ContentType.Application.Json)
                        return@post
                    }
                    val txn = store.adjustBalance(id, body, caller.id)
                    val encoded = json.encodeToString(Transaction.serializer(), txn)
                    idempotency.remember(key, hash, encoded)
                    call.respondText(encoded, ContentType.Application.Json)
                }

                put("/{customerId}/caller-id") {
                    val caller = call.requireOperator(authenticator)
                    call.idempotencyKey()
                    val body = call.receive<SetCallerId>()
                    call.respond(store.setCallerId(call.customerId(), body.callerId, caller.id))
                }

                /**
                 * Creates a customer with a credential MEGATRON did not
                 * generate.
                 *
                 * THE ONLY ENDPOINT IN THIS API THAT ACCEPTS A PASSWORD, and
                 * it is a separate path rather than a flag on POST /customers
                 * precisely so that is greppable and deliberate.
                 *
                 * It exists for one reason: taking over from an existing
                 * switch must not require every customer to reconfigure a
                 * softphone. A migration that breaks every customer is not one
                 * anybody performs, so the alternative to this endpoint is
                 * that nobody ever moves.
                 *
                 * The plaintext is converted to HA1 and SHA-256 and is not
                 * stored. It is not returned either — the caller already has
                 * it, and echoing it back would put it in one more log.
                 */
                post("/import") {
                    val caller = call.requireOperator(authenticator)
                    val key = call.idempotencyKey()
                    val body = call.receive<ImportCustomer>()
                    val hash = body.hashCode()
                    idempotency.replay(key, hash)?.let {
                        call.respondText(it, ContentType.Application.Json)
                        return@post
                    }
                    val customer = store.importCustomer(
                        CreateCustomer(
                            handle = body.handle,
                            planId = body.planId,
                            displayName = body.displayName,
                            telegramUserId = body.telegramUserId,
                            openingBalanceMicros = body.openingBalanceMicros,
                            maxConcurrentCalls = body.maxConcurrentCalls,
                        ),
                        body.password,
                        caller.id,
                    )
                    val encoded = json.encodeToString(Customer.serializer(), customer)
                    idempotency.remember(key, hash, encoded)
                    call.respondText(encoded, ContentType.Application.Json, HttpStatusCode.Created)
                }
            }

            /**
             * Does this password authenticate this handle?
             *
             * For a management layer that lets a customer prove ownership of a
             * SIP login they already have. Neither service ends up holding a
             * plaintext: the candidate is converted to HA1 and compared
             * against the stored one.
             *
             * THE ANSWER IS THE SAME SHAPE WHATEVER THE REASON. "No such
             * account" and "wrong password" both return valid=false, because
             * distinguishing them is a username oracle — the same one the
             * switch config spends forty lines closing. The store CAN tell
             * them apart and deliberately does not say so here.
             */
            post("/auth/verify") {
                call.requireOperator(authenticator)
                val body = call.receive<VerifyCredentials>()
                val valid = store.verifyPassword(body.handle, body.password) ?: false
                call.respond(CredentialCheck(valid = valid))
            }

            route("/plans") {
                get {
                    call.requireOperator(authenticator)
                    call.respond(store.listPlans())
                }
                post {
                    call.requireOperator(authenticator)
                    call.idempotencyKey()
                    call.respond(HttpStatusCode.Created, store.createPlan(call.receive()))
                }
                put("/{planId}/rates") {
                    call.requireOperator(authenticator)
                    call.idempotencyKey()
                    val planId = call.parameters["planId"] ?: throw Invalid("planId required")
                    call.respond(store.replaceRates(planId, call.receive()))
                }
            }

            route("/trunks") {
                get {
                    call.requireOperator(authenticator)
                    call.respond(store.listTrunks())
                }
                post {
                    call.requireOperator(authenticator)
                    call.idempotencyKey()
                    call.respond(HttpStatusCode.Created, store.createTrunk(call.receive()))
                }
            }

            // ---- customer scope ------------------------------------------
            //
            // No id in the path, on purpose. There is nothing here for a
            // customer to tamper with in order to reach another account.

            get("/me") {
                val caller = call.requireCustomer(authenticator)
                val customer = store.getCustomer(caller.customerId)
                call.respond(
                    SelfView(
                        handle = customer.handle,
                        status = customer.status,
                        balanceMicros = customer.balanceMicros,
                        currency = customer.currency,
                        callerId = customer.callerId,
                        sipUsername = customer.handle,
                        registered = customer.registered,
                        activeCalls = customer.activeCalls,
                    )
                )
            }

            put("/me/caller-id") {
                val caller = call.requireCustomer(authenticator)
                call.idempotencyKey()
                val body = call.receive<SetCallerId>()
                call.respond(
                    store.setCallerId(caller.customerId, body.callerId, "customer:${caller.customerId}")
                )
            }
        }
    }
}

private fun ApplicationCall.customerId(): String =
    parameters["customerId"] ?: throw Invalid("customerId is required")

/**
 * How many calls to return, bounded.
 *
 * Capped because this box is also a switch: a caller asking for a year of call
 * history would pull it all into memory beside the thing carrying live calls.
 */
private fun ApplicationCall.callLimit(): Int =
    (request.queryParameters["limit"]?.toIntOrNull() ?: 20).coerceIn(1, 500)

private suspend fun ApplicationCall.problem(
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

class Unauthorized(message: String) : RuntimeException(message)

private fun ApplicationCall.bearer(): String? {
    val header = request.headers[HttpHeaders.Authorization] ?: return null
    if (!header.startsWith("Bearer ", ignoreCase = true)) return null
    return header.substring(7).trim().ifEmpty { null }
}

private fun ApplicationCall.requireOperator(auth: Authenticator): Caller.Operator {
    val token = bearer() ?: throw Unauthorized("missing bearer token")
    return when (val caller = auth.resolve(token)) {
        is Caller.Operator -> caller
        // A customer token reaching an operator route is the worst failure
        // this service can have. It is refused here and it is also
        // unreachable by URL shape, because the two are separate route trees.
        is Caller.Customer -> throw Unauthorized("customer token cannot reach an operator route")
        null -> throw Unauthorized("unrecognised token")
    }
}

private fun ApplicationCall.requireCustomer(auth: Authenticator): Caller.Customer {
    val token = bearer() ?: throw Unauthorized("missing bearer token")
    return when (val caller = auth.resolve(token)) {
        is Caller.Customer -> caller
        // An operator token on a self-service route would make /v1/me
        // ambiguous — whose "me"? Refused rather than guessed.
        is Caller.Operator -> throw Unauthorized("operator token has no self-service view")
        null -> throw Unauthorized("unrecognised token")
    }
}
