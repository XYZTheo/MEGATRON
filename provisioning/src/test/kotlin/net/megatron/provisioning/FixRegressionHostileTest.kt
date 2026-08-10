package net.megatron.provisioning

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Second hostile pass: attacks aimed at the FIXES, not the original defects.
 */
class FixRegressionHostileTest {

    private val files = mutableListOf<Path>()
    private val stores = mutableListOf<SqlStore>()
    private val directories = mutableListOf<Path>()

    @AfterTest
    fun cleanUp() {
        stores.forEach { runCatching { it.close() } }
        files.forEach { runCatching { Files.deleteIfExists(it) } }
        directories.forEach { directory ->
            runCatching {
                Files.walk(directory).sorted(Comparator.reverseOrder())
                    .forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun newDbPath(): Path {
        val file = Files.createTempFile("megatron-fix-", ".db").also { files.add(it) }
        Files.deleteIfExists(file)
        return file
    }

    private fun open(path: Path): SqlStore =
        SqlStore("jdbc:sqlite:${path.absolutePathString()}").also { stores.add(it) }

    private fun tempDirectory(): Path =
        Files.createTempDirectory("megatron-fix-").also { directories.add(it) }

    /** The counter segment of an id: `prefix-<counter>-<tag>`. */
    private fun counterOf(id: String): Long =
        id.split('-').getOrNull(1)?.toLongOrNull() ?: error("unparseable id '$id'")

    // -- the per-process id tag ----------------------------------------------

    /**
     * THE RESTART RESCAN STILL DOES NOT LOOK AT `transactions`.
     *
     * SqlStore.init reads `customers UNION ALL plans UNION ALL trunks` and
     * nothing else, so the counter resumes below every transaction id the
     * previous run issued. `transactions.id` is precisely the column that
     * collided in production — aff69f9's own commit message says the symptom
     * was `UNIQUE constraint failed: transactions.id` on a settlement, with
     * the call completed and the customer not billed.
     *
     * What stops the constraint firing again is now ONLY the four-hex process
     * tag. Two runs that draw the same tag — 1 in 65,536 per start, and the
     * installer starts two services on every deploy — reissue the same id and
     * the same failure comes back, with the counter reuse making it certain
     * rather than merely possible.
     */
    @Test
    fun `a restart does not reuse a counter already spent on a transaction id`() {
        val path = newDbPath()

        val before = open(path)
        val plan = before.createPlan(CreatePlan("Retail", "USD"))
        val customer = before.createCustomer(CreateCustomer("bigcorp", plan.id), "t").first
        before.close()

        // The previous process got AHEAD OF THE WALL CLOCK on transaction ids.
        // Two ordinary ways that happens, both without any test trickery:
        //
        //  - throughput. The counter advances once per id and the seed advances
        //    once per millisecond, so any run issuing more than a thousand ids
        //    a second ends above the clock. Settlement writes one per call.
        //  - the clock steps back. An NTP correction, a VM snapshot restore or
        //    a container start on a host with a different clock all do it.
        //
        // Modelled here as a transaction id an hour of counter ahead of now.
        val ahead = System.currentTimeMillis() + 3_600_000
        java.sql.DriverManager.getConnection("jdbc:sqlite:${path.absolutePathString()}")
            .use { connection ->
                connection.createStatement().use {
                    it.execute(
                        "INSERT INTO transactions (id, customer_id, amount_micros, " +
                            "balance_after_micros, reason, created_at, actor) VALUES " +
                            "('txn-$ahead-beef','${customer.id}',1,1,'earlier run','x','t')"
                    )
                }
            }

        val after = open(path)
        val reissued = counterOf(
            after.adjustBalance(customer.id, BalanceAdjustment(1_000, "later"), "t").id
        )

        assertTrue(
            reissued > ahead,
            "the restart resumed the counter at $reissued, below the $ahead already " +
                "spent on a transaction id. init()'s rescan reads customers, plans and " +
                "trunks and NOT transactions — the one table whose UNIQUE constraint " +
                "actually fired in production. Only the random 4-hex process tag now " +
                "stands between this and `UNIQUE constraint failed: transactions.id` " +
                "on a settlement.",
        )
    }

    /**
     * The tag must not break the string cursor. This one PASSES; it is here so
     * it keeps passing.
     */
    @Test
    fun `the process tag keeps ids fixed width so the string cursor totally orders them`() {
        val store = open(newDbPath())
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val created = (1..40).map {
            store.createCustomer(CreateCustomer("cust%03d".format(it), plan.id), "t").first.id
        }

        // Creation order must equal string order, or `id > cursor` skips rows.
        assertEquals(created, created.sorted(), "ids do not sort in creation order")
        assertEquals(1, created.map { it.length }.toSet().size, "ids are not fixed width")

        // Page through in twos and check nothing is skipped or repeated.
        val seen = mutableListOf<String>()
        var cursor: String? = null
        do {
            val page = store.listCustomers(CustomerStatus.ACTIVE, 3, cursor)
            seen += page.items.map { it.id }
            cursor = page.nextCursor
        } while (cursor != null)
        assertEquals(created, seen, "paging skipped or repeated a row")
    }

    /**
     * A database that predates the tag holds untagged ids. Paging must still
     * be a total order across the two formats. This one PASSES.
     */
    @Test
    fun `paging is still total when tagged and untagged ids are mixed`() {
        val path = newDbPath()
        val url = "jdbc:sqlite:${path.absolutePathString()}"

        // Two customers in the OLD `cust-<counter>` format.
        open(path).close()
        java.sql.DriverManager.getConnection(url).use { connection ->
            connection.createStatement().use {
                it.execute(
                    "INSERT INTO plans VALUES ('plan-1000000000000','Retail','USD',NULL,0,'x')"
                )
                for (n in listOf(1000000000001L, 1000000000002L)) {
                    it.execute(
                        "INSERT INTO customers (id, handle, status, plan_id, balance_micros, " +
                            "currency, sip_password_hash, sip_ha1, created_at) VALUES " +
                            "('cust-$n','old$n','ACTIVE','plan-1000000000000',0,'USD','h','','x')"
                    )
                }
            }
        }

        val store = open(path)
        val plan = store.listPlans().single()
        repeat(4) { store.createCustomer(CreateCustomer("new$it", plan.id), "t") }

        val everything = store.listCustomers(null, 1000, null).items.map { it.id }
        val paged = mutableListOf<String>()
        var cursor: String? = null
        do {
            val page = store.listCustomers(null, 2, cursor)
            paged += page.items.map { it.id }
            cursor = page.nextCursor
        } while (cursor != null)

        assertEquals(everything, paged, "mixed-format ids broke cursor paging")
        assertEquals(everything.size, everything.toSet().size, "a row was returned twice")
    }

    // -- the empty-file guard -------------------------------------------------

    /**
     * THE GUARD BLOCKS A LEGITIMATE STATE, AND MISDIAGNOSES IT.
     *
     * Right after the sip_ha1 migration every existing customer has `''` for a
     * credential, so `rows == 0 && active.isNotEmpty()` — the guard throws, on
     * every poll, forever. The subscriber file is therefore never created at
     * all.
     *
     * That is worse than what it replaced. A header-only file makes db_text
     * load an empty table and answer REGISTERs with a clean 401/403. NO FILE
     * makes auth_db report "table 'subscriber' does not exist", which
     * 896780f's own commit message records as a 500 on every REGISTER — the
     * failure that commit was written to remove.
     *
     * The error text also names the wrong cause: it tells the operator to
     * check MEGATRON_SIP_REALM, and the realm is correct. They will chase a
     * mismatch that does not exist while every REGISTER 500s.
     */
    @Test
    fun `a freshly migrated database still gets a subscriber file written`() {
        val path = newDbPath()
        val url = "jdbc:sqlite:${path.absolutePathString()}"

        // A database from before HA1 existed, holding one active customer.
        java.sql.DriverManager.getConnection(url).use { connection ->
            connection.createStatement().use {
                it.execute(
                    """
                    CREATE TABLE customers (
                        id TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE,
                        display_name TEXT, status TEXT NOT NULL, plan_id TEXT NOT NULL,
                        balance_micros INTEGER NOT NULL DEFAULT 0, currency TEXT NOT NULL,
                        caller_id_number TEXT, caller_id_verified INTEGER NOT NULL DEFAULT 0,
                        caller_id_set_at TEXT, caller_id_set_by TEXT,
                        max_concurrent_calls INTEGER NOT NULL DEFAULT 2,
                        telegram_user_id INTEGER, sip_password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL)
                    """.trimIndent()
                )
                it.execute(
                    "INSERT INTO customers (id, handle, status, plan_id, balance_micros, " +
                        "currency, sip_password_hash, created_at) VALUES " +
                        "('cust-1','legacy','ACTIVE','plan-1',0,'USD','h','x')"
                )
            }
        }

        val store = open(path)  // migrate() adds sip_ha1 = ''
        val file = tempDirectory().resolve("subscriber")
        val outcome = runCatching { SubscriberFile(file).writeFrom(store, "sip.megatron.local") }

        assertTrue(
            Files.exists(file),
            "no subscriber file was created at all (writeFrom: " +
                "${outcome.exceptionOrNull()?.message}). db_text then reports " +
                "\"table 'subscriber' does not exist\" and EVERY REGISTER gets a 500, " +
                "which is worse than the empty table this guard replaced.",
        )
    }

    /**
     * The guard's intended case: real credentials exist, the realm is wrong.
     * This one PASSES and must keep passing.
     */
    @Test
    fun `the guard still refuses to blank a populated file on a realm mismatch`() {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.createCustomer(CreateCustomer("alpha", plan.id), "t")

        val file = tempDirectory().resolve("subscriber")
        val writer = SubscriberFile(file)
        writer.writeFrom(store, "sip.megatron.local")

        val outcome = runCatching { writer.writeFrom(store, "sip.megatron.io") }
        assertTrue(outcome.isFailure, "a realm mismatch silently emptied the file again")
        assertTrue(
            Files.readString(file).contains("alpha:"),
            "the good file was overwritten anyway",
        )
    }

    // -- the idempotency table ------------------------------------------------

    /**
     * claimOnce writes a row per guarded bot command and nothing ever removes
     * one. created_at is stored and read by no code.
     *
     * The in-memory IdempotencyStore was bounded by age and size as part of
     * this same round of fixes; its durable counterpart was not, so the
     * unbounded-growth defect moved from the heap to the disk. Low volume, but
     * the table is the one that lives forever.
     */
    @Test
    fun `the durable idempotency table does not grow without bound`() {
        // REWRITTEN, and the original assertion was the unsafe one: it
        // required 500 FRESH claims to be evicted. A claim is what stops a
        // redelivered command from running twice, so dropping recent ones to
        // stay under a count re-enables the double-credit this table exists to
        // prevent — and it would do so exactly when the operator is busiest.
        //
        // The bound that is both real and safe is AGE. What follows pins it:
        // yesterday's claims go, today's stay.
        val path = newDbPath()
        val url = "jdbc:sqlite:${path.absolutePathString()}"

        fun rows() = java.sql.DriverManager.getConnection(url).use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("SELECT COUNT(*) FROM idempotency")
                    .use { rs -> rs.next(); rs.getInt(1) }
            }
        }

        val twoDaysAgo = java.time.Instant.now().minusSeconds(48 * 60 * 60)
        SqlStore(url, clock = { twoDaysAgo }).use { old ->
            repeat(150) { old.claimOnce("stale-$it") }
        }
        assertTrue(rows() >= 150, "the old claims were never written")

        SqlStore(url).use { current ->
            repeat(150) { current.claimOnce("fresh-$it") }

            assertTrue(
                rows() < 150 + 150,
                "${rows()} rows: nothing evicted the claims from two days ago, and " +
                    "created_at is written but read by nothing",
            )
            // And the fresh ones must still guard.
            assertTrue(
                !current.claimOnce("fresh-0"),
                "a claim from moments ago was evicted; a redelivered command would run twice",
            )
        }
    }
}
