package net.megatron.provisioning

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SubscriberFileTest {

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
        Files.createTempDirectory("megatron-subscriber-").also { directories.add(it) }

    @Test
    fun `an unchanged render does not rewrite the file`() {
        // The writer runs on a timer. Rewriting an identical file makes
        // OpenSIPS reload -- and flush its registrar cache -- for no reason,
        // repeatedly, forever.
        val file = tempDirectory().resolve("subscriber")
        val writer = SubscriberFile(file)

        assertTrue(writer.write("a\n"), "the first write should report a change")
        assertFalse(writer.write("a\n"), "an identical write reported a change")
        assertTrue(writer.write("b\n"), "a genuine change was not reported")
    }

    @Test
    fun `a deleted file is rewritten even when the content is unchanged`() {
        // Otherwise a file removed by a deploy, a tidy-up script, or a fresh
        // container never comes back: the writer remembers writing it and
        // considers itself up to date, and every customer's registration
        // fails until somebody restarts provisioning.
        val file = tempDirectory().resolve("subscriber")
        val writer = SubscriberFile(file)

        writer.write("a\n")
        Files.delete(file)
        assertTrue(writer.write("a\n"), "the deleted file was not recreated")
        assertEquals("a\n", file.readText())
    }

    @Test
    fun `the file is replaced whole, never appended to`() {
        val file = tempDirectory().resolve("subscriber")
        val writer = SubscriberFile(file)

        writer.write("first\nsecond\n")
        writer.write("only\n")
        assertEquals("only\n", file.readText())
    }

    @Test
    fun `no temporary files are left in the directory OpenSIPS reads`() {
        // db_text loads a DIRECTORY. A stray .tmp in it is a table OpenSIPS
        // tries to parse, and a parse failure there takes down the real one.
        val directory = tempDirectory()
        val writer = SubscriberFile(directory.resolve("subscriber"))
        repeat(3) { writer.write("content $it\n") }

        val leftovers = Files.list(directory).use { paths ->
            paths.map { it.fileName.toString() }.toList()
        }
        assertEquals(listOf("subscriber"), leftovers.sorted())
    }

    @Test
    fun `a missing directory is created rather than failing`() {
        val file = tempDirectory().resolve("nested").resolve("deeper").resolve("subscriber")
        SubscriberFile(file).write("x\n")
        assertEquals("x\n", file.readText())
    }

    @Test
    fun `every active customer is exported, past the page size`() {
        // The listing is paged. Exporting one page means that past some
        // customer count, new accounts silently cannot register -- no error,
        // no log line, and the symptom appears long after whoever chose the
        // page size has forgotten it.
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val handles = (1..600).map { "cust%04d".format(it) }
        handles.forEach { store.createCustomer(CreateCustomer(it, plan.id), "t") }

        val file = tempDirectory().resolve("subscriber")
        SubscriberFile(file).writeFrom(store, "sip.megatron.local")

        val written = file.readText().lines().filter { it.isNotBlank() }.drop(1)
        assertEquals(600, written.size, "customers were lost past the first page")
        assertTrue(written.any { it.startsWith("cust0600:") }, "the last customer is missing")
    }

    @Test
    fun `a suspended customer disappears from the file on the next write`() {
        // The credential check is a snapshot; this is how the snapshot moves.
        // Money is NOT enforced here -- the authorizer does that live on every
        // call -- but a closed account should stop being able to register.
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val (customer, _) = store.createCustomer(CreateCustomer("deadbeat", plan.id), "t")

        val file = tempDirectory().resolve("subscriber")
        val writer = SubscriberFile(file)
        writer.writeFrom(store, "sip.megatron.local")
        assertTrue(file.readText().contains("deadbeat:"))

        store.setStatus(customer.id, SetStatus(CustomerStatus.SUSPENDED, "did not pay"), "test")
        assertTrue(writer.writeFrom(store, "sip.megatron.local"), "the change was not written")
        assertFalse(file.readText().contains("deadbeat"), "a suspended customer can still register")
    }

    @Test
    fun `the exported digest is the one the customer was handed`() {
        // End to end, through the file: what a softphone computes from the
        // password in its config must equal what OpenSIPS reads from disk.
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val credentials = store.createCustomer(CreateCustomer("dialer", plan.id), "t").second

        val file = tempDirectory().resolve("subscriber")
        SubscriberFile(file).writeFrom(store, credentials.sipDomain)

        val expected = java.security.MessageDigest.getInstance("MD5")
            .digest("dialer:${credentials.sipDomain}:${credentials.sipPassword}".toByteArray())
            .joinToString("") { "%02x".format(it) }

        assertEquals(
            "dialer:${credentials.sipDomain}:$expected",
            file.readText().lines()[1],
        )
    }
}
