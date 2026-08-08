package net.megatron.provisioning

import java.nio.file.Files
import kotlin.io.path.absolutePathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * What the two stores do when a balance runs out of Long.
 *
 * schema.sql says, in capitals: "MONEY IS ALWAYS AN INTEGER OF MICRO-UNITS.
 * There is no NUMERIC, no REAL, no DECIMAL anywhere in this file, and there
 * must never be." SQLite decides otherwise on integer overflow — it converts
 * the result of the arithmetic to REAL — and `balance_micros + ?` is exactly
 * that arithmetic.
 */
class MoneyOverflowHostileTest {

    private val files = mutableListOf<java.nio.file.Path>()
    private val stores = mutableListOf<SqlStore>()

    @AfterTest
    fun cleanUp() {
        stores.forEach { runCatching { it.close() } }
        files.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun sqlStore(): SqlStore {
        val file = Files.createTempFile("megatron-overflow-", ".db").also { files.add(it) }
        Files.deleteIfExists(file)
        return SqlStore("jdbc:sqlite:${file.absolutePathString()}").also { stores.add(it) }
    }

    private fun seed(store: Store): Customer {
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        return store.createCustomer(CreateCustomer("bigcorp", plan.id), "test").first
    }

    /**
     * Two credits, each individually valid, that together do not fit.
     *
     * InMemoryStore uses Math.addExact and throws — the balance is unchanged
     * and the operator is told. SqlStore adds in SQL, gets a REAL back, and
     * writes something that is not the balance and not an error.
     */
    @Test
    fun `both stores refuse a credit that overflows rather than corrupting the balance`() {
        val big = 9_000_000_000_000_000_000L  // ~9.0e18, under Long.MAX (9.22e18)

        val memory = InMemoryStore()
        val memoryCustomer = seed(memory)
        memory.adjustBalance(memoryCustomer.id, BalanceAdjustment(big, "first"), "t")
        val memoryOutcome = runCatching {
            memory.adjustBalance(memoryCustomer.id, BalanceAdjustment(big, "second"), "t")
        }
        val memoryBalance = memory.getCustomer(memoryCustomer.id).balanceMicros

        val sql = sqlStore()
        val sqlCustomer = seed(sql)
        sql.adjustBalance(sqlCustomer.id, BalanceAdjustment(big, "first"), "t")
        val sqlOutcome = runCatching {
            sql.adjustBalance(sqlCustomer.id, BalanceAdjustment(big, "second"), "t")
        }
        val sqlBalance = sql.getCustomer(sqlCustomer.id).balanceMicros

        // The in-memory store gets this right; it is the reference.
        assertTrue(memoryOutcome.isFailure, "InMemoryStore accepted an overflowing credit")
        assertEquals(big, memoryBalance, "InMemoryStore moved the balance anyway")

        assertTrue(
            sqlOutcome.isFailure,
            "SqlStore accepted an overflowing credit and reported balance $sqlBalance " +
                "(expected $big, still held): SQLite converts an overflowing integer " +
                "sum to REAL, so schema.sql's 'no REAL anywhere' guarantee is not one",
        )
        assertEquals(
            big, sqlBalance,
            "SqlStore corrupted the stored balance; the audit row records " +
                "balance_after_micros=$sqlBalance, which is now the number a dispute " +
                "is argued from",
        )
    }

    /**
     * THE COLUMN IS ADDED WITH NO MIGRATION.
     *
     * schema.sql is applied as `CREATE TABLE IF NOT EXISTS`, and 896780f adds
     * `sip_ha1` to `customers`. On a database that already exists — every
     * deployment made from any earlier commit — the CREATE is a no-op, so the
     * column is never added, and there is no ALTER TABLE anywhere.
     *
     * The result is not degraded auth. It is a provisioning service that cannot
     * create a customer at all: the INSERT names a column the table has not
     * got.
     */
    @Test
    fun `an existing database gains the sip_ha1 column on upgrade`() {
        val file = Files.createTempFile("megatron-upgrade-", ".db").also { files.add(it) }
        Files.deleteIfExists(file)
        val url = "jdbc:sqlite:${file.absolutePathString()}"

        // The customers table exactly as it stood before 896780f.
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
            }
        }

        val store = SqlStore(url).also { stores.add(it) }
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val outcome = runCatching { store.createCustomer(CreateCustomer("bigcorp", plan.id), "t") }

        assertTrue(
            outcome.isSuccess,
            "upgrading an existing database bricks provisioning: " +
                "${outcome.exceptionOrNull()}",
        )
    }

    /**
     * Claim 5, against the store that will actually be deployed.
     *
     * SubscriberFileTest only exercises InMemoryStore, whose cursor is a list
     * index. SqlStore's is `id > ?` with BINARY collation over TEXT ids of the
     * form "cust-<millis-counter>", which is a completely different mechanism
     * and could silently truncate the export.
     *
     * This one PASSES; it is here so it keeps passing.
     */
    @Test
    fun `every active SqlStore customer is exported past the page size`() {
        val store = sqlStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        repeat(600) { store.createCustomer(CreateCustomer("cust%04d".format(it), plan.id), "t") }

        val directory = Files.createTempDirectory("megatron-sqlexport-")
        val file = directory.resolve("subscriber")
        SubscriberFile(file).writeFrom(store, "sip.megatron.local")

        val rows = Files.readString(file).lines().filter { it.isNotBlank() }.drop(1)
        assertEquals(600, rows.size, "customers were lost past the first page")

        Files.walk(directory).sorted(Comparator.reverseOrder())
            .forEach { runCatching { Files.deleteIfExists(it) } }
    }
}
