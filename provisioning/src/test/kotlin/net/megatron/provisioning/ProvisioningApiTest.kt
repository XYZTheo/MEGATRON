package net.megatron.provisioning

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The API tested as an API: real routes, real serialisation, real status
 * codes. Not the handlers called as functions.
 *
 * The distinction matters here more than usual, because several of the
 * properties being asserted — the operator/customer boundary, idempotency,
 * JSON-only responses — are properties of the HTTP layer rather than of the
 * business logic underneath it.
 */
class ProvisioningApiTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val operatorToken = "operator-token-that-is-long-enough"
    private val customerToken = "customer-token-that-is-long-enough"

    private fun testApp(block: suspend ApplicationTestBuilder.(InMemoryStore) -> Unit) =
        testApplication {
            val store = InMemoryStore()
            application {
                provisioningModule(
                    store,
                    IdempotencyStore(),
                    Authenticator { token ->
                        when (token) {
                            operatorToken -> Caller.Operator("op-1")
                            customerToken -> Caller.Customer("cust-1")
                            else -> null
                        }
                    },
                )
            }
            block(store)
        }

    private fun HttpRequestBuilder.operator(key: String? = null) {
        header(HttpHeaders.Authorization, "Bearer $operatorToken")
        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        if (key != null) header("Idempotency-Key", key)
    }

    @Test
    fun `an unparseable body is the caller's fault, and says what was wrong`() = testApp {
        // FOUND THE EXPENSIVE WAY. A trunk was created with
        // "direction":"OUTBOUND" — the wire name is lower case — and the API
        // answered "500 Internal error: the request could not be completed",
        // which says the SERVER broke. It had not. A script discarded that
        // response, and the only visible symptom was every later call refused
        // 503 by the no-route guard, which reads like a routing bug rather
        // than a trunk that was never created.
        val response = client.post("/v1/trunks") {
            operator("trunk-bad-enum")
            setBody(
                """{"name":"c","direction":"OUTBOUND","host":"203.0.113.1",
                    "remote_ips":["203.0.113.1"]}"""
            )
        }

        assertEquals(HttpStatusCode.BadRequest, response.status)
        val body = response.bodyAsText()
        assertTrue(
            body.contains("direction") || body.contains("OUTBOUND"),
            "the reply does not say which field was wrong: $body",
        )
    }

    @Test
    fun `a well-formed trunk is accepted, so the check above is about the body`() = testApp {
        val response = client.post("/v1/trunks") {
            operator("trunk-good")
            setBody(
                """{"name":"c","direction":"outbound","host":"203.0.113.1",
                    "port":5060,"remote_ips":["203.0.113.1"],"transport":"udp"}"""
            )
        }
        assertEquals(HttpStatusCode.Created, response.status)
    }

    private suspend fun ApplicationTestBuilder.makePlan(): String {
        val response = client.post("/v1/plans") {
            operator("plan-key-00001")
            setBody("""{"name":"Standard","currency":"USD"}""")
        }
        assertEquals(HttpStatusCode.Created, response.status)
        return json.decodeFromString<Plan>(response.bodyAsText()).id
    }

    private suspend fun ApplicationTestBuilder.makeCustomer(
        handle: String = "acme",
        opening: Long = 0,
        key: String = "cust-key-00001",
    ): CustomerCreated {
        val planId = makePlan()
        val response = client.post("/v1/customers") {
            operator(key)
            setBody(
                """{"handle":"$handle","plan_id":"$planId","opening_balance_micros":$opening}"""
            )
        }
        assertEquals(HttpStatusCode.Created, response.status, response.bodyAsText())
        return json.decodeFromString(response.bodyAsText())
    }

    // -- the workflow -------------------------------------------------------

    @Test
    fun `create a customer and get a login back exactly once`() = testApp {
        val created = makeCustomer(opening = 5_000_000)
        assertEquals("acme", created.customer.handle)
        assertEquals(5_000_000L, created.customer.balanceMicros)
        assertEquals(CustomerStatus.ACTIVE, created.customer.status)
        assertTrue(created.credentials.sipPassword.length >= 20)

        // The password is not readable again. Fetching the customer returns
        // no credential of any kind -- a password the API will re-display is
        // a password living in a Telegram scrollback forever.
        val fetched = client.get("/v1/customers/${created.customer.id}") { operator() }
        assertEquals(HttpStatusCode.OK, fetched.status)
        assertTrue(!fetched.bodyAsText().contains(created.credentials.sipPassword))
    }

    @Test
    fun `credit a balance and see it move`() = testApp {
        val created = makeCustomer()
        val response = client.post("/v1/customers/${created.customer.id}/balance") {
            operator("credit-key-00001")
            setBody("""{"amount_micros":10000000,"reason":"paid by bank transfer"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val txn = json.decodeFromString<Transaction>(response.bodyAsText())
        assertEquals(10_000_000L, txn.amountMicros)
        assertEquals(10_000_000L, txn.balanceAfterMicros)
        assertEquals("op-1", txn.actor)
    }

    @Test
    fun `a customer sees only their own account`() = testApp {
        val response = client.get("/v1/me") {
            header(HttpHeaders.Authorization, "Bearer $customerToken")
        }
        // cust-1 does not exist in this store, so 404 -- but crucially NOT
        // 401 and not somebody else's data. The route resolved to the
        // caller's own id with nothing in the path to tamper with.
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `set a caller id and it is recorded as unverified`() = testApp {
        val created = makeCustomer()
        val response = client.put("/v1/customers/${created.customer.id}/caller-id") {
            operator("cli-key-00001")
            setBody("""{"caller_id":"+441632960123"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val cli = json.decodeFromString<CallerId>(response.bodyAsText())
        assertEquals("+441632960123", cli.number)
        // Asserting ownership is not establishing it. Marking this verified
        // would put a false STIR/SHAKEN attestation on every call.
        assertEquals(false, cli.verified)
    }

    // -- the boundary that matters most -------------------------------------

    @Test
    fun `a customer token cannot reach an operator route`() = testApp {
        // Unlimited free credit, if this ever passes.
        val response = client.post("/v1/customers/cust-1/balance") {
            header(HttpHeaders.Authorization, "Bearer $customerToken")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            header("Idempotency-Key", "attack-key-00001")
            setBody("""{"amount_micros":999999999,"reason":"free money"}""")
        }
        assertNotEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.status.value in 400..499, "got ${response.status}")
    }

    @Test
    fun `an operator token has no self-service view`() = testApp {
        // Whose "me"? Refused rather than guessed.
        val response = client.get("/v1/me") { operator() }
        assertTrue(response.status.value in 400..499, "got ${response.status}")
    }

    @Test
    fun `no token at all is refused`() = testApp {
        assertTrue(client.get("/v1/customers").status.value in 400..499)
    }

    @Test
    fun `an unrecognised token is refused`() = testApp {
        val response = client.get("/v1/customers") {
            header(HttpHeaders.Authorization, "Bearer not-a-real-token")
        }
        assertTrue(response.status.value in 400..499)
    }

    // -- idempotency, the thing that stops double credits -------------------

    @Test
    fun `replaying a credit with the same key does not credit twice`() = testApp {
        // A Telegram bot on a phone network times out after the server
        // committed, then retries. Without this it is a double credit, every
        // time, found later on the balance sheet.
        val created = makeCustomer()
        val body = """{"amount_micros":10000000,"reason":"top up"}"""

        val first = client.post("/v1/customers/${created.customer.id}/balance") {
            operator("retry-key-00001"); setBody(body)
        }
        val second = client.post("/v1/customers/${created.customer.id}/balance") {
            operator("retry-key-00001"); setBody(body)
        }
        assertEquals(HttpStatusCode.OK, first.status)
        assertEquals(HttpStatusCode.OK, second.status)
        assertEquals(first.bodyAsText(), second.bodyAsText())

        val customer = json.decodeFromString<Customer>(
            client.get("/v1/customers/${created.customer.id}") { operator() }.bodyAsText()
        )
        assertEquals(10_000_000L, customer.balanceMicros, "credited twice")
    }

    @Test
    fun `reusing a key with a different body is refused, not guessed`() = testApp {
        val created = makeCustomer()
        client.post("/v1/customers/${created.customer.id}/balance") {
            operator("conflict-key-0001")
            setBody("""{"amount_micros":10000000,"reason":"top up"}""")
        }
        val conflicting = client.post("/v1/customers/${created.customer.id}/balance") {
            operator("conflict-key-0001")
            setBody("""{"amount_micros":99000000,"reason":"top up"}""")
        }
        // The two plausible guesses are "apply it again" and "ignore it", and
        // both are wrong when real money is involved.
        assertEquals(HttpStatusCode.Conflict, conflicting.status)
    }

    @Test
    fun `the same key cannot be replayed against a different customer`() = testApp {
        val planId = makePlan()
        val a = json.decodeFromString<CustomerCreated>(
            client.post("/v1/customers") {
                operator("mk-a-00000001")
                setBody("""{"handle":"alpha","plan_id":"$planId"}""")
            }.bodyAsText()
        )
        val b = json.decodeFromString<CustomerCreated>(
            client.post("/v1/customers") {
                operator("mk-b-00000001")
                setBody("""{"handle":"bravo","plan_id":"$planId"}""")
            }.bodyAsText()
        )
        val body = """{"amount_micros":5000000,"reason":"top up"}"""
        client.post("/v1/customers/${a.customer.id}/balance") {
            operator("shared-key-0001"); setBody(body)
        }
        val crossed = client.post("/v1/customers/${b.customer.id}/balance") {
            operator("shared-key-0001"); setBody(body)
        }
        assertEquals(HttpStatusCode.Conflict, crossed.status)
    }

    @Test
    fun `a mutation without an idempotency key is refused`() = testApp {
        val created = makeCustomer()
        val response = client.post("/v1/customers/${created.customer.id}/balance") {
            header(HttpHeaders.Authorization, "Bearer $operatorToken")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody("""{"amount_micros":1,"reason":"no key"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    // -- validation ---------------------------------------------------------

    @Test
    fun `a duplicate handle is refused`() = testApp {
        val planId = makePlan()
        client.post("/v1/customers") {
            operator("dup-a-00000001"); setBody("""{"handle":"acme","plan_id":"$planId"}""")
        }
        val second = client.post("/v1/customers") {
            operator("dup-b-00000001"); setBody("""{"handle":"acme","plan_id":"$planId"}""")
        }
        assertEquals(HttpStatusCode.Conflict, second.status)
    }

    @Test
    fun `a balance change without a reason is refused`() = testApp {
        val created = makeCustomer()
        val response = client.post("/v1/customers/${created.customer.id}/balance") {
            operator("noreason-000001")
            setBody("""{"amount_micros":1000,"reason":""}""")
        }
        // "Who changed this and why" is the first question asked about any
        // balance, and the answer has to exist before it is asked.
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `a trunk with no remote ips is refused`() = testApp {
        val response = client.post("/v1/trunks") {
            operator("trunk-key-00001")
            setBody(
                """{"name":"carrier-a","direction":"outbound","host":"1.2.3.4",""" +
                    """"remote_ips":[]}"""
            )
        }
        // A trunk that accepts from anywhere is an open relay.
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `a trunk with a real allowlist is created`() = testApp {
        val response = client.post("/v1/trunks") {
            operator("trunk-key-00002")
            setBody(
                """{"name":"carrier-a","direction":"both","host":"sip.carrier.example",""" +
                    """"remote_ips":["203.0.113.0/24"]}"""
            )
        }
        assertEquals(HttpStatusCode.Created, response.status, response.bodyAsText())
        val trunk = json.decodeFromString<Trunk>(response.bodyAsText())
        assertEquals(listOf("203.0.113.0/24"), trunk.remoteIps)
        assertEquals(true, trunk.enabled)
    }

    @Test
    fun `a rate table with a duplicate prefix is refused`() = testApp {
        val planId = makePlan()
        val response = client.put("/v1/plans/$planId/rates") {
            operator("rates-key-00001")
            setBody(
                """{"rates":[""" +
                    """{"prefix":"44","sell_micros_per_minute":12000},""" +
                    """{"prefix":"44","sell_micros_per_minute":13000}]}"""
            )
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `a rate table is replaced whole`() = testApp {
        val planId = makePlan()
        val response = client.put("/v1/plans/$planId/rates") {
            operator("rates-key-00002")
            setBody(
                """{"rates":[""" +
                    """{"prefix":"44","sell_micros_per_minute":12000},""" +
                    """{"prefix":"1","sell_micros_per_minute":9000}]}"""
            )
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertEquals(2, json.decodeFromString<RatesReplaced>(response.bodyAsText()).rateCount)
    }

    @Test
    fun `an unknown customer is a 404 and not a stack trace`() = testApp {
        val response = client.get("/v1/customers/does-not-exist") { operator() }
        assertEquals(HttpStatusCode.NotFound, response.status)
        assertTrue(response.bodyAsText().contains("\"status\":404"))
    }

    // -- responses are JSON, never HTML -------------------------------------

    @Test
    fun `errors are problem json, not html`() = testApp {
        // MagnusBilling's CVE-2025-2609 and CVE-2025-2610 were stored XSS
        // reachable because API responses were served as text/html. An API
        // that never emits HTML cannot have that bug.
        val response = client.get("/v1/customers/does-not-exist") { operator() }
        val contentType = response.headers[HttpHeaders.ContentType].orEmpty()
        assertTrue(contentType.contains("json"), "content-type was '$contentType'")
        assertTrue(!contentType.contains("html"))
    }
}
