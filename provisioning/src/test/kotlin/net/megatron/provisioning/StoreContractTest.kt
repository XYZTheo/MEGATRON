package net.megatron.provisioning

import java.nio.file.Files
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.io.path.absolutePathString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
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

    // -- sip digest credentials ---------------------------------------------
    //
    // These decide whether a customer's softphone can register at all. Every
    // one of them is a failure that presents to the customer as "Zoiper says
    // Forbidden" with nothing in the logs to explain it.

    /**
     * The reference HA1, computed here independently of the production code.
     *
     * Written out longhand rather than by calling the store's own helper: a
     * test that asks the implementation to check itself passes just as
     * happily when the implementation is wrong. The expected values below are
     * what a softphone will compute, which is the only definition that
     * matters.
     */
    private fun referenceHa1(user: String, realm: String, password: String): String =
        java.security.MessageDigest.getInstance("MD5")
            .digest("$user:$realm:$password".toByteArray())
            .joinToString("") { "%02x".format(it) }

    @Test
    fun `the stored digest credential is the one a softphone will compute`() {
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val credentials = store.createCustomer(CreateCustomer("dialer", plan.id), "t").second

        assertEquals(
            referenceHa1("dialer", credentials.sipDomain, credentials.sipPassword),
            store.sipDigestHa1("dialer", credentials.sipDomain),
            "the stored HA1 does not match the password the customer was handed",
        )
    }

    @Test
    fun `rotating the password rotates the digest credential with it`() {
        // A rotation that leaves a stale HA1 behind is a rotation that rotates
        // nothing: the old password still registers, and the customer who
        // asked for a new one because the old leaked is no better off.
        val store = store()
        val (_, customer) = seed(store)

        val before = store.sipDigestHa1("bigcorp", "sip.megatron.local")
        val rotated = store.rotateCredentials(customer.id)
        val after = store.sipDigestHa1("bigcorp", rotated.sipDomain)

        assertNotEquals(before, after, "the old password would still register")
        assertEquals(
            referenceHa1("bigcorp", rotated.sipDomain, rotated.sipPassword),
            after,
            "after rotation the new password does not authenticate",
        )
    }

    @Test
    fun `an unknown handle has no digest credential`() {
        // Must be null, not an empty string or a hash of nothing. Anything
        // that looks like a credential invites the registrar to compare
        // against it, and a comparison against a fixed value is a password
        // every non-existent account shares.
        val store = store()
        seed(store)
        assertNull(store.sipDigestHa1("nobody", "sip.megatron.local"))
    }

    @Test
    fun `the digest credential is bound to its realm`() {
        // HA1 bakes the realm in. Handing back this realm's value for a
        // different one produces a credential that cannot authenticate, and
        // the customer sees a rejected registration with no cause.
        val store = store()
        seed(store)
        assertNull(store.sipDigestHa1("bigcorp", "evil.example.net"))
    }

    @Test
    fun `the digest credential is not exposed on the customer record`() {
        // HA1 is password-equivalent for SIP. The customer read path is the
        // one thing in this service that a customer-facing caller reaches, so
        // it is the one place the value must never appear -- including
        // through a field somebody adds to Customer later without thinking
        // about it.
        val store = store()
        val (_, customer) = seed(store)
        val ha1 = store.sipDigestHa1("bigcorp", "sip.megatron.local")!!

        val serialised = Json.encodeToString(store.getCustomer(customer.id))
        assertTrue(!serialised.contains(ha1), "HA1 is reachable through the customer record")
        assertTrue(
            !serialised.contains(ha1.uppercase()),
            "HA1 is reachable through the customer record",
        )
    }

    @Test
    fun `two racing creations of one handle produce exactly one customer`() {
        // A check-then-act on a shared map is not a check under concurrency.
        // Both callers saw "handle not taken", both inserted, and the result
        // was two customers with one handle — of whom only one can be exported
        // to the switch, so the other holds a password that can never work.
        //
        // SqlStore had a UNIQUE constraint and reported the clash as an
        // internal fault rather than a Conflict; InMemoryStore had nothing at
        // all. Two stores that disagree about whether a duplicate is possible
        // is precisely what this suite exists to catch.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val threads = 6
        val ready = java.util.concurrent.CountDownLatch(threads)
        val go = java.util.concurrent.CountDownLatch(1)
        val created = java.util.concurrent.atomic.AtomicInteger()
        val conflicts = java.util.concurrent.atomic.AtomicInteger()

        val workers = (1..threads).map {
            Thread {
                ready.countDown()
                go.await()
                try {
                    store.createCustomer(CreateCustomer("racer", plan.id), "test")
                    created.incrementAndGet()
                } catch (expected: Conflict) {
                    conflicts.incrementAndGet()
                }
            }.apply { start() }
        }
        ready.await()
        go.countDown()
        workers.forEach { it.join(10_000) }

        assertEquals(1, created.get(), "the handle was issued more than once")
        assertEquals(threads - 1, conflicts.get(), "a racing creation failed as something " +
            "other than a Conflict, which reaches the API as a 500")
    }

    // -- what VOIPX needs -----------------------------------------------------
    //
    // These exist to satisfy PROJECT-VOIPX's VosClient interface so its bot
    // and console can drive MEGATRON in place of VOS3000. See
    // docs/VOIPX-INTEGRATION.md.

    @Test
    fun `a customer can be moved to another plan`() {
        // VosClient calls this setPlan AND setTariff — VOS3000 splits a
        // package from a fee-rate group, MEGATRON has one concept.
        val store = store()
        val (plan, customer) = seed(store)
        val premium = store.createPlan(CreatePlan("Premium", "USD"))

        val moved = store.setPlan(customer.id, premium.id, "operator")

        assertEquals(premium.id, moved.planId)
        assertEquals(premium.id, store.getCustomer(customer.id).planId)
        assertNotEquals(plan.id, moved.planId)
    }

    @Test
    fun `moving to a plan that does not exist is refused`() {
        // Silently accepting it leaves a customer whose calls cannot be rated,
        // which the switch refuses as though their destination were unknown.
        val store = store()
        val (_, customer) = seed(store)
        assertFailsWith<NotFound> { store.setPlan(customer.id, "plan-nope", "operator") }
    }

    @Test
    fun `a caller id can be withdrawn, not just replaced`() {
        // A number withdrawn because it was never theirs must fall back to the
        // operator's default, not keep presenting the last one they were
        // allowed.
        val store = store()
        val (_, customer) = seed(store)
        store.setCallerId(customer.id, "+441632960123", "operator")
        assertNotNull(store.getCustomer(customer.id).callerId)

        store.clearCallerId(customer.id, "operator")
        assertNull(store.getCustomer(customer.id).callerId, "the withdrawn number is still set")
    }

    @Test
    fun `a password can be verified without anybody holding it`() {
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val credentials = store.createCustomer(CreateCustomer("checkme", plan.id), "t").second

        assertEquals(true, store.verifyPassword("checkme", credentials.sipPassword))
        assertEquals(false, store.verifyPassword("checkme", "not-the-password"))
    }

    @Test
    fun `an unknown handle is null, not false`() {
        // The caller may need to tell "no such account" from "wrong password"
        // internally — while what it says OUT LOUD must not distinguish them,
        // which is the enumeration oracle the switch config avoids at length.
        val store = store()
        seed(store)
        assertNull(store.verifyPassword("ghost", "anything"))
    }

    // -- the takeover ---------------------------------------------------------

    @Test
    fun `an imported customer keeps the password they already had`() {
        // THE WHOLE POINT OF THE MIGRATION. Seth's existing Magnus customers
        // must keep working without touching their softphones; a migration
        // that breaks every customer is not one anybody performs.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))

        val imported = store.importCustomer(
            CreateCustomer("legacy", plan.id), "their-old-password", "import",
        )

        assertEquals(true, store.verifyPassword("legacy", "their-old-password"))
        assertEquals(
            java.security.MessageDigest.getInstance("MD5")
                .digest("legacy:sip.megatron.local:their-old-password".toByteArray())
                .joinToString("") { "%02x".format(it) },
            store.sipDigestHa1("legacy", "sip.megatron.local"),
            "the imported credential is not what a softphone will compute",
        )
        assertEquals("legacy", imported.handle)
    }

    @Test
    fun `an imported password is not left recoverable`() {
        // The rule bends for the import, it does not break: the plaintext is
        // converted and dropped, exactly as a generated one is.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.importCustomer(CreateCustomer("legacy", plan.id), "their-old-password", "import")

        val serialised = Json.encodeToString(store.findByHandle("legacy")!!)
        assertTrue(
            !serialised.contains("their-old-password"),
            "the imported plaintext is reachable through the customer record",
        )
    }

    @Test
    fun `a laughably short imported password is refused`() {
        // Importing is not an excuse to carry somebody else's worst
        // credentials onto a switch whose whole purpose is not being the one
        // that gets attacked.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        assertFailsWith<IllegalArgumentException> {
            store.importCustomer(CreateCustomer("weak", plan.id), "1234", "import")
        }
    }

    // -- DIDs -----------------------------------------------------------------
    //
    // The inbound half. A switch that can dial out and cannot be dialled is
    // half a phone service.

    @Test
    fun `a number delivers to the customer it was given to`() {
        val store = store()
        val (_, customer) = seed(store)
        store.assignDid(AssignDid("+441632960123", customer.id), "operator")

        assertEquals(customer.id, store.customerForDid("+441632960123")?.id)
    }

    @Test
    fun `the same number is found however the carrier writes it`() {
        // CARRIERS ARE NOT CONSISTENT. The same DID arrives as +44...,
        // 44..., 0044... and with spaces, sometimes from one carrier on
        // different routes. A number that works on one trunk and silently does
        // not on another is an inbound call rejected for a customer who is
        // definitely paying for that number.
        val store = store()
        val (_, customer) = seed(store)
        store.assignDid(AssignDid("+44 1632 960123", customer.id), "operator")

        listOf("+441632960123", "441632960123", "00441632960123", "+44 1632 960123")
            .forEach { asWritten ->
                assertEquals(
                    customer.id,
                    store.customerForDid(asWritten)?.id,
                    "'$asWritten' did not reach the owner",
                )
            }
    }

    @Test
    fun `a number cannot belong to two customers`() {
        // Two owners means an inbound call is delivered by whichever row is
        // read first — non-deterministic routing, and a customer receiving
        // somebody else's calls.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val first = store.createCustomer(CreateCustomer("first", plan.id), "t").first
        val second = store.createCustomer(CreateCustomer("second", plan.id), "t").first

        store.assignDid(AssignDid("+441632960123", first.id), "operator")
        assertFailsWith<Conflict> {
            store.assignDid(AssignDid("+441632960123", second.id), "operator")
        }
        assertEquals(first.id, store.customerForDid("+441632960123")?.id)
    }

    @Test
    fun `assigning the same number to the same customer again is not an error`() {
        // Idempotent: a retried assignment must not look like a clash with
        // itself.
        val store = store()
        val (_, customer) = seed(store)
        store.assignDid(AssignDid("+441632960123", customer.id), "operator")
        store.assignDid(AssignDid("+441632960123", customer.id), "operator")
        assertEquals(1, store.listDids(customer.id).size)
    }

    @Test
    fun `a released number reaches nobody`() {
        val store = store()
        val (_, customer) = seed(store)
        store.assignDid(AssignDid("+441632960123", customer.id), "operator")
        store.releaseDid("+441632960123", "operator")

        assertNull(store.customerForDid("+441632960123"))
        assertTrue(store.listDids(customer.id).isEmpty())
    }

    @Test
    fun `a number nobody owns reaches nobody`() {
        val store = store()
        seed(store)
        assertNull(store.customerForDid("+441632999999"))
    }

    @Test
    fun `a number for a customer who does not exist is refused`() {
        val store = store()
        seed(store)
        assertFailsWith<NotFound> {
            store.assignDid(AssignDid("+441632960123", "cust-nope"), "operator")
        }
    }

    @Test
    fun `dids are listed per customer, not everybody's`() {
        // A customer's DID list is a list of their numbers. Leaking the whole
        // table tells one customer what every other customer owns.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val mine = store.createCustomer(CreateCustomer("mine", plan.id), "t").first
        val theirs = store.createCustomer(CreateCustomer("theirs", plan.id), "t").first
        store.assignDid(AssignDid("+441632960001", mine.id), "operator")
        store.assignDid(AssignDid("+441632960002", theirs.id), "operator")

        assertEquals(listOf("441632960001"), store.listDids(mine.id).map { it.number })
        assertEquals(2, store.listDids().size)
    }

    // -- call detail records --------------------------------------------------
    //
    // The evidence behind every charge. What is asserted here is what a
    // disputed bill is argued from.

    private fun call(
        id: String,
        account: String = "bigcorp",
        charged: Long = 10_000,
        noMedia: Boolean = false,
        endedAt: String = "2026-08-08T12:00:00Z",
    ) = CallRecord(
        callId = id,
        account = account,
        destination = "12125551234",
        prefix = "1",
        durationSeconds = 42,
        durationSource = "sip",
        billedSeconds = 60,
        chargedMicros = charged,
        ratePerMinute = 10_000,
        mediaBytes = if (noMedia) 0 else 42_084,
        mediaStats = "RTP: 42084 bytes, 167 packets, 167 errors",
        noMedia = noMedia,
        endedAt = endedAt,
    )

    @Test
    fun `a call is recorded and read back whole`() {
        val store = store()
        store.recordCall(call("c-1"))

        val read = store.callsFor("bigcorp").single()
        assertEquals("c-1", read.callId)
        assertEquals(10_000L, read.chargedMicros)
        assertEquals("sip", read.durationSource)
        assertEquals(42_084L, read.mediaBytes)
        assertEquals(60, read.billedSeconds)
        assertTrue(read.mediaStats!!.contains("42084 bytes"), "the raw stats were lost")
    }

    @Test
    fun `the same call recorded twice is one row`() {
        // The switch retransmits settlements — SIP retransmits by design, and
        // a slowly-answered BYE arrives again. A second row doubles the
        // apparent spend on every report while the balance, guarded
        // separately by the reservation id, shows the truth. Two records
        // disagreeing is worse than either being wrong alone.
        val store = store()
        store.recordCall(call("c-dup"))
        store.recordCall(call("c-dup"))

        assertEquals(1, store.callsFor("bigcorp").size, "the retransmission was double-counted")
    }

    @Test
    fun `recording a duplicate does not throw, because it is on the money path`() {
        // Failing a settlement because the history already has the row would
        // turn a harmless duplicate into a lost charge.
        val store = store()
        store.recordCall(call("c-dup"))
        store.recordCall(call("c-dup"))  // must not throw
    }

    @Test
    fun `calls come back most recent first`() {
        val store = store()
        store.recordCall(call("old", endedAt = "2026-08-01T09:00:00Z"))
        store.recordCall(call("new", endedAt = "2026-08-08T09:00:00Z"))
        store.recordCall(call("middle", endedAt = "2026-08-04T09:00:00Z"))

        assertEquals(
            listOf("new", "middle", "old"),
            store.callsFor("bigcorp").map { it.callId },
        )
    }

    @Test
    fun `one customer never sees another's calls`() {
        // Their call history is a list of who they phoned.
        val store = store()
        store.recordCall(call("mine", account = "bigcorp"))
        store.recordCall(call("theirs", account = "rival"))

        assertEquals(listOf("mine"), store.callsFor("bigcorp").map { it.callId })
        assertEquals(listOf("theirs"), store.callsFor("rival").map { it.callId })
    }

    @Test
    fun `silent calls can be listed, because each one is a possible refund`() {
        val store = store()
        store.recordCall(call("talked", noMedia = false))
        store.recordCall(call("silent", noMedia = true))

        assertEquals(listOf("silent"), store.noMediaCalls().map { it.callId })
        assertEquals(2, store.recentCalls().size)
    }

    @Test
    fun `unreadable media stats stay unknown, and are not read back as silence`() {
        // 0 bytes is evidence of silence. Null is evidence of nothing. A store
        // that collapses them turns every unreadable stat into a refund
        // request the day rtpengine changes its wording.
        val store = store()
        store.recordCall(call("unknown").copy(mediaBytes = null, mediaStats = null))

        assertNull(store.callsFor("bigcorp").single().mediaBytes)
    }

    @Test
    fun `a limit is honoured`() {
        val store = store()
        (1..30).forEach { store.recordCall(call("c-%02d".format(it), endedAt = "2026-08-08T12:%02d:00Z".format(it))) }
        assertEquals(5, store.callsFor("bigcorp", limit = 5).size)
        assertEquals("c-30", store.callsFor("bigcorp", limit = 5).first().callId)
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
    fun `a credentialed trunk presents its account name unless told otherwise`() {
        val store = store()
        // A carrier that issues a username matches the call by From user. If we
        // send the customer's handle they answer 403 with the password right,
        // so the account name is the default rather than something to remember.
        val withAuth = store.createTrunk(
            CreateTrunk(
                name = "credentialed", direction = TrunkDirection.OUTBOUND,
                host = "sip.carrier.example", remoteIps = listOf("198.51.100.7"),
                authUsername = "acct7", authPassword = "carrier-password-here",
            )
        )
        assertEquals("acct7", store.listTrunks().single { it.id == withAuth.id }.fromUser)

        // An IP-authenticated carrier wants the originating number, not us.
        val ipAuth = store.createTrunk(
            CreateTrunk(
                name = "ip-authed", direction = TrunkDirection.OUTBOUND,
                host = "sip2.carrier.example", remoteIps = listOf("198.51.100.8"),
            )
        )
        assertNull(store.listTrunks().single { it.id == ipAuth.id }.fromUser)

        // And an explicit value beats both.
        val explicit = store.createTrunk(
            CreateTrunk(
                name = "explicit", direction = TrunkDirection.OUTBOUND,
                host = "sip3.carrier.example", remoteIps = listOf("198.51.100.9"),
                authUsername = "acct9", authPassword = "another-carrier-password",
                fromUser = "441632960999",
            )
        )
        assertEquals("441632960999", store.listTrunks().single { it.id == explicit.id }.fromUser)
    }

    @Test
    fun `a retired carrier is gone, and takes its password with it`() {
        val store = store()
        val trunk = store.createTrunk(
            CreateTrunk(
                name = "old-carrier",
                direction = TrunkDirection.OUTBOUND,
                host = "sip.carrier.example",
                remoteIps = listOf("198.51.100.7"),
                authUsername = "acct",
                authPassword = "s3cret-carrier-pw",
            )
        )
        assertEquals("acct", store.trunkCredentials(trunk.id)?.username)

        store.deleteTrunk(trunk.id)

        assertEquals(emptyList(), store.listTrunks())
        // The point of deleting rather than disabling: the carrier's password
        // is no longer on the box.
        assertNull(store.trunkCredentials(trunk.id))
    }

    @Test
    fun `retiring a carrier that was never there is a NotFound`() {
        assertFailsWith<NotFound> { store().deleteTrunk("trunk-nope") }
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
    fun `two services sharing one database do not issue the same ids`() {
        // THE PRODUCTION TOPOLOGY. provisioning and switch-api each open their
        // own SqlStore against the same file, and both seeded their id counter
        // from System.currentTimeMillis(). Started together — which systemd,
        // the installer and every lab script do — they began at the same
        // number and issued the same ids.
        //
        // It surfaced on a SETTLEMENT: `UNIQUE constraint failed:
        // transactions.id`, so the call completed, the customer was not
        // billed, and the switch got a 500 from the money endpoint. Earlier
        // runs passed only because the two processes happened to start in
        // different milliseconds.
        val file = Files.createTempFile("megatron-shared-", ".db")
        files.add(file)
        val url = "jdbc:sqlite:${file.absolutePathString()}"

        SqlStore(url).use { provisioning ->
            SqlStore(url).use { switch ->
                val plan = provisioning.createPlan(CreatePlan("Retail", "USD"))
                val (customer, _) = provisioning.createCustomer(
                    CreateCustomer("shared", plan.id, openingBalanceMicros = 1_000_000),
                    "provisioning",
                )

                // The second service settles a call against the same customer.
                // Before the fix this threw on the transaction id.
                switch.adjustBalance(
                    customer.id,
                    BalanceAdjustment(-250_000, "a call"),
                    "switch-api",
                )

                assertEquals(
                    750_000L,
                    provisioning.getCustomer(customer.id).balanceMicros,
                    "the settlement did not reach the balance the operator sees",
                )
                assertEquals(
                    2,
                    provisioning.transactionsFor(customer.id).size,
                    "an audit row was lost to an id collision",
                )
            }
        }
    }

    @Test
    fun `ids still order correctly for cursor pagination`() {
        // The cursor compares ids AS STRINGS, so the process tag appended to
        // every id must not disturb their order. Two customers created in
        // sequence must still sort in that sequence, or paging skips or
        // repeats rows.
        val store = store()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        val handles = (1..12).map { "seq%02d".format(it) }
        handles.forEach { store.createCustomer(CreateCustomer(it, plan.id), "t") }

        val seen = mutableListOf<String>()
        var cursor: String? = null
        var empty: Boolean
        do {
            val page = store.listCustomers(null, 5, cursor)
            seen += page.items.map { it.handle }
            cursor = page.nextCursor
            empty = page.items.isEmpty()
        } while (cursor != null && !empty)

        assertEquals(handles.size, seen.size, "paging lost or repeated customers")
        assertEquals(handles.toSet(), seen.toSet())
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
