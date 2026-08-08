package net.megatron.provisioning

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Hostile review of the credential export. Every test here is an attempt to
 * violate a property the production comments claim to hold.
 */
class SubscriberExportHostileTest {

    private val realm = "sip.megatron.local"

    private val directories = mutableListOf<Path>()

    @AfterTest
    fun cleanUp() {
        directories.forEach { directory ->
            runCatching {
                Files.walk(directory).sorted(Comparator.reverseOrder())
                    .forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun tempDirectory(): Path =
        Files.createTempDirectory("megatron-hostile-").also { directories.add(it) }

    private fun customer(
        handle: String,
        status: CustomerStatus = CustomerStatus.ACTIVE,
    ) = Customer(
        id = "cust-$handle",
        handle = handle,
        displayName = null,
        status = status,
        planId = "plan-1",
        balanceMicros = 0,
        currency = "USD",
        callerId = null,
        maxConcurrentCalls = 2,
        telegramUserId = null,
        createdAt = "2026-01-01T00:00:00Z",
    )

    // -- injection through the THIRD field ------------------------------------

    /**
     * SubscriberExport validates the handle and the realm and NOT the ha1.
     *
     * The comment on UNSAFE says the check exists because "the validation lives
     * in a different file from this one, and the day somebody widens it, the
     * failure here would be silent". That argument applies word for word to
     * ha1, which arrives from a lambda this file does not own — SqlStore hands
     * back whatever is in the sip_ha1 column, unexamined.
     */
    @Test
    fun `an unsafe stored credential forges an entire extra subscriber row`() {
        val forged = "5f4dcc3b5aa765d61d8327deb882cf99\n" +
            "admin:$realm:5f4dcc3b5aa765d61d8327deb882cf99"

        assertFailsWith<IllegalArgumentException>(
            "an ha1 carrying a newline was rendered instead of refused"
        ) {
            SubscriberExport.render(listOf(customer("victim")), { forged }, realm)
        }
    }

    @Test
    fun `an ha1 carrying a field separator shifts every column after it`() {
        assertFailsWith<IllegalArgumentException>(
            "an ha1 carrying ':' was rendered instead of refused"
        ) {
            SubscriberExport.render(listOf(customer("victim")), { "deadbeef:extra" }, realm)
        }
    }

    // -- the realm the file is rendered for -----------------------------------

    /**
     * Main.kt reads MEGATRON_SIP_REALM and passes it to writeFrom, but
     * constructs SqlStore/InMemoryStore with the DEFAULT sipDomain and no way
     * to override it. Set that environment variable to anything other than
     * "sip.megatron.local" and every sipDigestHa1 lookup returns null, every
     * customer is skipped, and a header-only file is written over a good one —
     * silently, while logging "subscriber file updated".
     *
     * SubscriberFile.writeFrom's own comment says a realm mismatch "produces
     * HA1 values no phone can satisfy". It does not. It produces no rows.
     */
    @Test
    fun `a realm the store holds no credentials for must not silently empty the file`() {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        listOf("alpha", "bravo", "charlie").forEach {
            store.createCustomer(CreateCustomer(it, plan.id), "t")
        }

        val file = tempDirectory().resolve("subscriber")
        val writer = SubscriberFile(file)

        writer.writeFrom(store, "sip.megatron.local")
        assertEquals(4, file.readText().lines().filter { it.isNotBlank() }.size)

        // The operator sets MEGATRON_SIP_REALM and restarts. Nothing else changed.
        val result = runCatching { writer.writeFrom(store, "sip.megatron.io") }

        val rows = file.readText().lines().filter { it.isNotBlank() }.drop(1)
        assertTrue(
            result.isFailure || rows.size == 3,
            "a realm mismatch wrote a header-only file and reported success " +
                "(writeFrom returned ${result.getOrNull()}): every customer just lost " +
                "their login, with no error anywhere",
        )
    }

    // -- the failure path of the writer ---------------------------------------

    /**
     * Claim 4, attacked directly: force the ATOMIC_MOVE to fail and check that
     * the "unchanged" cache is not poisoned and no .tmp is left behind.
     *
     * The destination is made a non-empty DIRECTORY, which is the cheapest
     * reproducible way to make Files.move throw after the temp file has already
     * been created and written.
     *
     * This one PASSES. It is here so it keeps passing.
     */
    @Test
    fun `a failed move leaves no temp file and does not poison the cache`() {
        val directory = tempDirectory()
        val blocked = directory.resolve("subscriber")
        Files.createDirectories(blocked.resolve("occupied"))

        val writer = SubscriberFile(blocked)
        assertFailsWith<Throwable> { writer.write("alpha\n") }

        val leftovers = Files.list(directory).use { paths ->
            paths.map { it.fileName.toString() }.toList()
        }
        assertEquals(listOf("subscriber"), leftovers.sorted(), "a .tmp was left behind")

        // Clear the obstruction; the same content must be written, not skipped.
        Files.delete(blocked.resolve("occupied"))
        Files.delete(blocked)
        assertTrue(
            writer.write("alpha\n"),
            "the failed write poisoned the cache: the retry considered itself unnecessary",
        )
        assertEquals("alpha\n", blocked.readText())
    }

    // -- what is retained in memory -------------------------------------------

    /**
     * InMemoryStore.passwords is written at creation and at rotation and is
     * NEVER READ by anything. It is a live, unbounded, plaintext copy of every
     * SIP password the store ever issued, sitting in a heap dump.
     *
     * The comment on ha1ByHandle claims baking the realm in at creation "is
     * also the second copy of the plaintext password that then does not exist".
     * That copy does exist; it is four lines above the comment.
     */
    @Test
    fun `the in-memory store keeps no plaintext copy of a SIP password`() {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val credentials = store.createCustomer(CreateCustomer("dialer", plan.id), "t").second

        val retained = InMemoryStore::class.java.declaredFields
            .filter { java.util.Map::class.java.isAssignableFrom(it.type) }
            .flatMap { field ->
                field.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                (field.get(store) as Map<Any?, Any?>).values.map { field.name to it.toString() }
            }

        val leaked = retained.filter { it.second == credentials.sipPassword }
        assertTrue(
            leaked.isEmpty(),
            "the plaintext SIP password is retained in ${leaked.map { it.first }}; " +
                "createCustomer and rotateCredentials both write it and nothing ever " +
                "reads it back",
        )
    }
}
