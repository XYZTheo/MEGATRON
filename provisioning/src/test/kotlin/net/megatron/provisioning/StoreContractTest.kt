package net.megatron.provisioning

import java.nio.file.Files
import kotlin.io.path.absolutePathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One suite, run against EVERY [Store] implementation.
 *
 * Two implementations that pass different tests are two implementations that
 * behave differently, and the difference will be found in production by
 * whichever one was tested less. Subclassing means a new store cannot be
 * added without meeting the same bar â€” and it is how the SQL store was held
 * to the in-memory one's behaviour rather than to a fresh set of assumptions.
 */
abstract class StoreContractTest {

    abstract fun store(): Store

    private fun seed(store: Store): Pair<Plan, Customer> {
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val (customer, _) = store.createCustomer(
            CreateCustomer(
                handle = "bigcorp",
                planId = plan.id,
                telegramUserId = 4242L,
                openingBalanceMicros = 25_000_000,
            ),
            "test",
        )
        return plan to customer
    }

    // -- customers ----------------------------------------------------------

    @Test
    fun `create and read back a customer`() {
        val store = store()
        val (plan, customer) = seed(store)
        val read = store.getCustomer(customer.id)
        assertEquals("bigcorp", read.handle)
        assertEquals(plan.id, read.planId)
        assertEquals(25_000_000L, read.balanceMicros)
        assertEquals("USD", read.currency)
        assertEquals(CustomerStatus.ACTIVE, read.status)
        assertEquals(4242L, read.telegramUserId)
    }

    @Test
    fun `the password is generated, not supplied, and differs every time`() {
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val a = store.createCustomer(CreateCustomer("alpha", plan.id), "t").second
        val b = store.createCustomer(CreateCustomer("bravo", plan.id), "t").second
        assertNotEquals(a.sipPassword, b.sipPassword)
        assertTrue(a.sipPassword.length >= 20)
    }

    @Test
    fun `rotating credentials produces a different password`() {
        val store = store()
        val (_, customer) = seed(store)
        val first = store.rotateCredentials(customer.id)
        val second = store.rotateCredentials(customer.id)
        assertNotEquals(first.sipPassword, second.sipPassword)
        assertEquals("bigcorp", second.sipUsername)
    }

    @Test
    fun `a duplicate handle is refused`() {
        val store = store()
        val (plan, _) = seed(store)
        assertFailsWith<Conflict> {
            store.createCustomer(CreateCustomer("bigcorp", plan.id), "t")
        }
    }

    @Test
    fun `an invalid handle is refused`() {
        val store = store()
        val (plan, _) = seed(store)
        for (bad in listOf("A", "ab", "Uppercase", "has space", "-leading")) {
            assertFailsWith<Invalid>("'$bad' was accepted") {
                store.createCustomer(CreateCustomer(bad, plan.id), "t")
            }
        }
    }

    @Test
    fun `a customer on a nonexistent plan is refused`() {
        val store = store()
        assertFailsWith<NotFound> {
            store.createCustomer(CreateCustomer("orphan", "plan-nope"), "t")
        }
    }

    @Test
    fun `lookup by handle and telegram id`() {
        val store = store()
        val (_, customer) = seed(store)
        assertEquals(customer.id, store.findByHandle("bigcorp")?.id)
        assertEquals(customer.id, store.findByTelegramUserId(4242L)?.id)
        assertNull(store.findByHandle("nobody"))
        assertNull(store.findByTelegramUserId(9999L))
    }

    @Test
    fun `an unknown customer is a NotFound, not a null`() {
        assertFailsWith<NotFound> { store().getCustomer("cust-nope") }
    }

    // -- balance ------------------------------------------------------------

    @Test
    fun `credits and debits move the balance and record who did it`() {
        val store = store()
        val (_, customer) = seed(store)

        val credit = store.adjustBalance(
            customer.id, BalanceAdjustment(10_000_000, "bank transfer", "ref-1"), "op-1"
        )
        assertEquals(35_000_000L, credit.balanceAfterMicros)
        assertEquals("op-1", credit.actor)
        assertEquals("ref-1", credit.reference)

        val debit = store.adjustBalance(
            customer.id, BalanceAdjustment(-5_000_000, "correction"), "telegram:99"
        )
        assertEquals(30_000_000L, debit.balanceAfterMicros)
        assertEquals("telegram:99", debit.actor)
        assertEquals(30_000_000L, store.getCustomer(customer.id).balanceMicros)
    }

    @Test
    fun `a debit may take a balance negative`() {
        // Refusing would make it impossible to correct an over-credit, and a
        // ledger you cannot correct is one people work around in a spreadsheet.
        val store = store()
        val (_, customer) = seed(store)
        val txn = store.adjustBalance(
            customer.id, BalanceAdjustment(-30_000_000, "clawback"), "op"
        )
        assertEquals(-5_000_000L, txn.balanceAfterMicros)
    }

    @Test
    fun `a balance change without a reason is refused`() {
        val store = store()
        val (_, customer) = seed(store)
        assertFailsWith<Invalid> {
            store.adjustBalance(customer.id, BalanceAdjustment(1000, ""), "op")
        }
    }

    @Test
    fun `concurrent credits do not lose one another`() {
        // Two operators, or an operator and the bot, crediting at the same
        // moment. Read-modify-write loses one of them; this asserts the total.
        val store = store()
        val (_, customer) = seed(store)
        val threads = (1..8).map {
            Thread {
                repeat(10) {
                    store.adjustBalance(customer.id, BalanceAdjustment(1_000, "concurrent"), "op")
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(25_000_000L + 80_000L, store.getCustomer(customer.id).balanceMicros)
    }

    // -- status and caller id ----------------------------------------------

    @Test
    fun `suspending requires a reason and takes effect`() {
        val store = store()
        val (_, customer) = seed(store)
        assertFailsWith<Invalid> {
            store.setStatus(customer.id, SetStatus(CustomerStatus.SUSPENDED, ""), "op")
        }
        val updated = store.setStatus(
            customer.id, SetStatus(CustomerStatus.SUSPENDED, "non payment"), "op"
        )
        assertEquals(CustomerStatus.SUSPENDED, updated.status)
        assertEquals(CustomerStatus.SUSPENDED, store.getCustomer(customer.id).status)
    }

    @Test
    fun `caller id is stored unverified and records who set it`() {
        val store = store()
        val (_, customer) = seed(store)
        val cli = store.setCallerId(customer.id, "+441632960123", "telegram:4242")
        assertEquals("+441632960123", cli.number)
        // Asserting ownership is not establishing it. Marking this verified
        // would put a false STIR/SHAKEN attestation on every call.
        assertEquals(false, cli.verified)
        assertEquals("telegram:4242", cli.setBy)
        assertEquals("+441632960123", store.getCustomer(customer.id).callerId?.number)
    }

    @Test
    fun `a non-E164 caller id is refused`() {
        val store = store()
        val (_, customer) = seed(store)
        for (bad in listOf("07700900123", "+0123", "441632960123", "not a number")) {
            assertFailsWith<Invalid>("'$bad' was accepted") {
                store.setCallerId(customer.id, bad, "op")
            }
        }
    }

    // -- plans and rates ----------------------------------------------------

    @Test
    fun `rate tables are replaced whole`() {
        val store = store()
        val (plan, _) = seed(store)
        store.replaceRates(plan.id, ReplaceRates(rates = listOf(
            RateRow(prefix = "1", sellMicrosPerMinute = 9_000),
            RateRow(prefix = "44", sellMicrosPerMinute = 12_000),
        )))
        val second = store.replaceRates(plan.id, ReplaceRates(rates = listOf(
            RateRow(prefix = "33", sellMicrosPerMinute = 15_000),
        )))
        assertEquals(1, second.rateCount)
        assertEquals(1, store.listPlans().first { it.id == plan.id }.rateCount)
    }

    @Test
    fun `a duplicate prefix in one table is refused`() {
        val store = store()
        val (plan, _) = seed(store)
        assertFailsWith<Invalid> {
            store.replaceRates(plan.id, ReplaceRates(rates = listOf(
                RateRow(prefix = "44", sellMicrosPerMinute = 12_000),
                RateRow(prefix = "44", sellMicrosPerMinute = 13_000),
            )))
        }
    }

    @Test
    fun `an empty rate table is refused`() {
        val store = store()
        val (plan, _) = seed(store)
        assertFailsWith<Invalid> { store.replaceRates(plan.id, ReplaceRates(rates = emptyList())) }
    }

    @Test
    fun `a plan with a bad currency is refused`() {
        assertFailsWith<Invalid> { store().createPlan(CreatePlan("X", "dollars")) }
    }

    // -- trunks -------------------------------------------------------------

    @Test
    fun `a trunk with no allowlist is refused`() {
        assertFailsWith<Invalid> {
            store().createTrunk(
                CreateTrunk("carrier", TrunkDirection.INBOUND, "1.2.3.4", remoteIps = emptyList())
            )
        }
    }

    @Test
    fun `a trunk round-trips its allowlist`() {
        val store = store()
        val trunk = store.createTrunk(
            CreateTrunk(
                name = "carrier-a",
                direction = TrunkDirection.BOTH,
                host = "sip.carrier.example",
                remoteIps = listOf("203.0.113.0/24", "198.51.100.7"),
                transport = Transport.TLS,
            )
        )
        val read = store.listTrunks().single()
        assertEquals(trunk.id, read.id)
        assertEquals(listOf("203.0.113.0/24", "198.51.100.7"), read.remoteIps)
        assertEquals(Transport.TLS, read.transport)
        assertEquals(true, read.enabled)
    }

    @Test
    fun `a trunk with a bogus remote ip is refused`() {
        assertFailsWith<Invalid> {
            store().createTrunk(
                CreateTrunk("x", TrunkDirection.OUTBOUND, "h", remoteIps = listOf("999.1.1.1"))
            )
        }
    }

    // -- paging -------------------------------------------------------------

    @Test
    fun `listing pages without repeating or skipping`() {
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        repeat(25) { store.createCustomer(CreateCustomer("cust%02d".format(it), plan.id), "t") }

        val seen = mutableListOf<String>()
        var cursor: String? = null
        var pages = 0
        do {
            val page = store.listCustomers(null, 10, cursor)
            seen += page.items.map { it.handle }
            cursor = page.nextCursor
            pages++
        } while (cursor != null && pages < 10)

        assertEquals(25, seen.size)
        assertEquals(25, seen.toSet().size, "a handle appeared on two pages")
    }

    @Test
    fun `listing filters by status`() {
        val store = store()
        val (_, customer) = seed(store)
        store.setStatus(customer.id, SetStatus(CustomerStatus.SUSPENDED, "test"), "op")
        assertEquals(1, store.listCustomers(CustomerStatus.SUSPENDED, 50, null).items.size)
        assertEquals(0, store.listCustomers(CustomerStatus.ACTIVE, 50, null).items.size)
    }
}

class InMemoryStoreTest : StoreContractTest() {
    override fun store(): Store = InMemoryStore()
}

class SqlStoreTest : StoreContractTest() {

    private val open = mutableListOf<SqlStore>()
    private val files = mutableListOf<java.nio.file.Path>()

    override fun store(): Store {
        val file = Files.createTempFile("megatron-test-", ".db")
        files.add(file)
        return SqlStore("jdbc:sqlite:${file.absolutePathString()}").also { open.add(it) }
    }

    @AfterTest
    fun cleanup() {
        open.forEach { runCatching { it.close() } }
        files.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    // -- the whole reason this implementation exists ------------------------

    @Test
    fun `data survives a restart`() {
        // InMemoryStore loses every customer and balance on restart, which
        // makes the platform unusable for running a real business. This is the
        // test that says the durable one actually is.
        val file = Files.createTempFile("megatron-restart-", ".db")
        files.add(file)
        val url = "jdbc:sqlite:${file.absolutePathString()}"

        val customerId: String
        SqlStore(url).use { first ->
            val plan = first.createPlan(CreatePlan("Retail", "USD"))
            val (customer, credentials) = first.createCustomer(
                CreateCustomer("survivor", plan.id, openingBalanceMicros = 7_500_000),
                "test",
            )
            customerId = customer.id
            first.adjustBalance(customer.id, BalanceAdjustment(2_500_000, "top up"), "op")
            first.setCallerId(customer.id, "+441632960123", "op")
            first.createTrunk(
                CreateTrunk("carrier", TrunkDirection.BOTH, "h", remoteIps = listOf("10.0.0.0/8"))
            )
            assertTrue(credentials.sipPassword.isNotEmpty())
        }

        SqlStore(url).use { second ->
            val customer = second.getCustomer(customerId)
            assertEquals("survivor", customer.handle)
            assertEquals(10_000_000L, customer.balanceMicros)
            assertEquals("+441632960123", customer.callerId?.number)
            assertEquals(1, second.listTrunks().size)
            assertEquals(1, second.listPlans().size)
            // And the audit trail survived too -- opening balance plus top-up.
            assertEquals(2, second.transactionsFor(customerId).size)
        }
    }

    @Test
    fun `ids are not reissued after a restart`() {
        // Reusing an id after a restart would attach new activity to an old
        // customer's audit trail, which is the one thing an audit trail must
        // never do.
        val file = Files.createTempFile("megatron-ids-", ".db")
        files.add(file)
        val url = "jdbc:sqlite:${file.absolutePathString()}"

        val firstId: String
        SqlStore(url).use { first ->
            val plan = first.createPlan(CreatePlan("Retail", "USD"))
            firstId = first.createCustomer(CreateCustomer("alpha", plan.id), "t").first.id
        }
        SqlStore(url).use { second ->
            val plan = second.listPlans().first()
            val secondId = second.createCustomer(CreateCustomer("bravo", plan.id), "t").first.id
            assertNotEquals(firstId, secondId)
        }
    }

    @Test
    fun `the sip password is not recoverable from the database`() {
        // A provisioning database that can hand back SIP passwords is one whose
        // compromise hands over every customer's ability to place calls at the
        // operator's expense.
        val file = Files.createTempFile("megatron-secret-", ".db")
        files.add(file)
        val url = "jdbc:sqlite:${file.absolutePathString()}"

        val password: String
        SqlStore(url).use { store ->
            val plan = store.createPlan(CreatePlan("Retail", "USD"))
            password = store.createCustomer(CreateCustomer("secret", plan.id), "t")
                .second.sipPassword
        }
        val raw = Files.readAllBytes(file).toString(Charsets.ISO_8859_1)
        assertTrue(!raw.contains(password), "the plaintext SIP password is in the database file")
    }
}
