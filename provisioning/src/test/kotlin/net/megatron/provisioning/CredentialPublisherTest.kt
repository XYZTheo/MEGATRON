package net.megatron.provisioning

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Publishing credentials is a STATE, not an event.
 *
 * The first version reloaded the switch only when the file content changed,
 * which is right until a reload fails — after that there is no next change and
 * therefore no next attempt, and the switch serves stale credentials
 * indefinitely. A rotated password left the old one working, which is the
 * failure the reload exists to prevent.
 *
 * None of this could be tested before: the logic lived in a private function
 * inside main(), which is part of why the gap survived a review.
 */
class CredentialPublisherTest {

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

    /** Counts reload attempts and can be told to fail them. */
    private class FakeSwitch : SwitchReloader(null, { }) {
        var attempts = 0
        var succeeds = true
        override fun reloadSubscribers(): Boolean {
            attempts++
            return succeeds
        }
    }

    private fun seeded(): Pair<Store, Customer> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val (customer, _) = store.createCustomer(CreateCustomer("acme", plan.id), "test")
        return store to customer
    }

    private fun publisher(switch: FakeSwitch): Pair<CredentialPublisher, Path> {
        val directory = Files.createTempDirectory("megatron-publish-").also { directories.add(it) }
        val path = directory.resolve("subscriber")
        return CredentialPublisher(SubscriberFile(path) { }, switch, "sip.megatron.local", { }) to path
    }

    @Test
    fun `a changed file is reloaded once, and an unchanged one not at all`() {
        val (store, _) = seeded()
        val switch = FakeSwitch()
        val (publisher, _) = publisher(switch)

        assertTrue(publisher.publish(store))
        assertEquals(1, switch.attempts)

        // Nothing changed. Reloading anyway flushes the switch's registrar
        // cache for no reason, on a timer, forever.
        publisher.publish(store)
        assertEquals(1, switch.attempts, "an unchanged file was reloaded again")
    }

    @Test
    fun `a failed reload is retried on the next tick, not forgotten`() {
        // THE ONE THAT MATTERS. Rotate a leaked password at 14:00, the MI call
        // times out because the switch is busy, and nothing else changes that
        // day: without a retry the leaked password keeps working, and the log
        // line said the file had been updated.
        val (store, _) = seeded()
        val switch = FakeSwitch()
        val (publisher, _) = publisher(switch)

        switch.succeeds = false
        assertFalse(publisher.publish(store))
        assertTrue(publisher.pending, "the failed reload was forgotten")

        // Nothing about the customer list changed, so there is no new write —
        // and that is exactly when the old version stopped trying.
        assertFalse(publisher.publish(store))
        assertEquals(2, switch.attempts, "the reload was not retried")

        switch.succeeds = true
        assertTrue(publisher.publish(store))
        assertFalse(publisher.pending)

        // And once acknowledged it stops asking.
        publisher.publish(store)
        assertEquals(3, switch.attempts, "it kept reloading after the switch caught up")
    }

    @Test
    fun `a rotated password is not published until the switch confirms`() {
        val (store, customer) = seeded()
        val switch = FakeSwitch()
        val (publisher, path) = publisher(switch)

        publisher.publish(store)
        val before = path.readText()

        switch.succeeds = false
        store.rotateCredentials(customer.id)
        publisher.publish(store)

        // The file is correct immediately; it is the SWITCH that is behind,
        // and that is precisely what pending records.
        assertTrue(path.readText() != before, "the new credential never reached the file")
        assertTrue(publisher.pending, "the switch is stale and nothing says so")
    }

    @Test
    fun `a write failure never throws out of publish`() {
        // This runs on a timer inside the provisioning service. An escape
        // would end the thread, and every future credential would silently
        // stop reaching the switch.
        val (store, _) = seeded()
        val switch = FakeSwitch()
        val directory = Files.createTempDirectory("megatron-publish-").also { directories.add(it) }
        // A directory where the file should be: the move cannot succeed.
        val path = directory.resolve("subscriber")
        Files.createDirectory(path)
        Files.createFile(path.resolve("in-the-way"))

        val publisher = CredentialPublisher(SubscriberFile(path) { }, switch, "sip.megatron.local", { })
        assertFalse(publisher.publish(store), "a write failure was reported as success")
        assertEquals(0, switch.attempts, "the switch was told to reload a file that was not written")
    }
}
