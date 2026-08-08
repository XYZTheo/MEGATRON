package net.megatron.provisioning

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The exported file IS the login. Everything that can go wrong here goes
 * wrong as "my softphone says Forbidden" with a switch that logs nothing
 * interesting, or — worse — as a login that works for someone it shouldn't.
 */
class SubscriberExportTest {

    private val realm = "sip.megatron.local"

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

    private fun ha1(handle: String, password: String) =
        SubscriberExport.md5Hex("$handle:$realm:$password")

    @Test
    fun `a row is exactly what auth_db expects`() {
        val expected = ha1("bigcorp", "hunter2")
        val out = SubscriberExport.render(
            listOf(customer("bigcorp")),
            { if (it == "bigcorp") expected else null },
            realm,
        )

        assertEquals(
            "username(str) domain(str) ha1(str)\n" +
                "bigcorp:$realm:$expected\n",
            out,
        )
    }

    @Test
    fun `no column is declared that carries no value`() {
        // An earlier version declared ha1b and left it empty, on the theory
        // that a column nothing reads is inert. db_text validates every
        // declared column on load and rejects a null field, so the one empty
        // value did not degrade one login -- the whole table failed to parse,
        // auth_db reported "table 'subscriber' does not exist", and every
        // customer got a 500 on REGISTER.
        val out = SubscriberExport.render(listOf(customer("bigcorp")), { "deadbeef" }, realm)
        val columns = out.lines()[0].split(" ").size
        out.lines().filter { it.isNotBlank() }.drop(1).forEach { row ->
            val fields = row.split(":")
            assertEquals(columns, fields.size, "row '$row' does not fill every column")
            assertTrue(fields.none { it.isBlank() }, "row '$row' has an empty field")
        }
    }

    @Test
    fun `the file ends in a newline`() {
        // OpenSIPS's db_text parser drops an unterminated final line. Without
        // this the last customer alphabetically cannot register, and nothing
        // anywhere reports a problem -- it is simply one specific account
        // that mysteriously does not work.
        val out = SubscriberExport.render(
            listOf(customer("alpha"), customer("zulu")),
            { ha1(it, "pw") },
            realm,
        )
        assertTrue(out.endsWith("\n"))
        assertTrue(out.lines().any { it.startsWith("zulu:") }, "the last customer is missing")
    }

    @Test
    fun `a suspended customer is absent, not blank`() {
        // Absence cannot be matched. A row with an empty credential is one
        // config mistake away from being matchable by an empty digest.
        val out = SubscriberExport.render(
            listOf(customer("paid"), customer("deadbeat", CustomerStatus.SUSPENDED)),
            { ha1(it, "pw") },
            realm,
        )
        assertTrue(out.contains("paid:"))
        assertTrue(!out.contains("deadbeat"), "a suspended customer can still register")
    }

    @Test
    fun `a customer with no stored credential is skipped`() {
        // Predates HA1 storage. They must rotate to get a login; they must
        // NOT get a placeholder, which would be a password shared by everyone
        // in the same position.
        val out = SubscriberExport.render(
            listOf(customer("old"), customer("new")),
            { if (it == "new") ha1(it, "pw") else null },
            realm,
        )
        assertTrue(out.contains("new:"))
        assertTrue(!out.contains("old:"), "a customer with no credential got a row")
    }

    @Test
    fun `a blank stored credential is skipped too`() {
        // The SQL column defaults to '' rather than NULL, so "no credential"
        // arrives as an empty string at least as often as it arrives as null.
        val out = SubscriberExport.render(
            listOf(customer("old")),
            { "" },
            realm,
        )
        assertEquals("username(str) domain(str) ha1(str)\n", out)
    }

    @Test
    fun `a handle carrying a field separator is refused, not written`() {
        // db_text splits on ':'. A handle containing one shifts every column
        // after it, so the attacker's chosen string lands in the ha1 column --
        // a login whose password they picked, for an account nobody created.
        //
        // Handle validation elsewhere makes this unreachable today. It is
        // checked here because that validation lives in another file, and the
        // day it is widened this failure is silent.
        val bad = assertFailsWith<IllegalArgumentException> {
            SubscriberExport.render(
                listOf(customer("evil:sip.megatron.local:deadbeef")),
                { "aaaa" },
                realm,
            )
        }
        assertTrue(bad.message!!.contains("not safe"))
    }

    @Test
    fun `a handle carrying a newline is refused`() {
        // Same attack, one row further: a newline forges an entire additional
        // subscriber line.
        assertFailsWith<IllegalArgumentException> {
            SubscriberExport.render(
                listOf(customer("evil\nadmin:sip.megatron.local:deadbeef")),
                { "aaaa" },
                realm,
            )
        }
    }

    @Test
    fun `an unsafe or empty realm is refused`() {
        assertFailsWith<IllegalArgumentException> {
            SubscriberExport.render(listOf(customer("a")), { "x" }, "")
        }
        assertFailsWith<IllegalArgumentException> {
            SubscriberExport.render(listOf(customer("a")), { "x" }, "evil:realm")
        }
    }

    @Test
    fun `output is ordered so an unchanged customer list produces an unchanged file`() {
        // The file is written on a timer and OpenSIPS reloads when it changes.
        // Unstable ordering means a reload on every write, which means the
        // registrar's cache is churned constantly for no reason.
        val forwards = listOf(customer("charlie"), customer("alpha"), customer("bravo"))
        val backwards = forwards.reversed()
        assertEquals(
            SubscriberExport.render(forwards, { ha1(it, "pw") }, realm),
            SubscriberExport.render(backwards, { ha1(it, "pw") }, realm),
        )
    }

    @Test
    fun `the digest matches what a softphone computes`() {
        // The one value in this file that has to agree with software we do
        // not control. Computed here from the RFC 2617 definition rather than
        // by calling the same helper the exporter uses.
        val expected = java.security.MessageDigest.getInstance("MD5")
            .digest("bigcorp:$realm:hunter2".toByteArray())
            .joinToString("") { "%02x".format(it) }
        assertEquals(expected, SubscriberExport.md5Hex("bigcorp:$realm:hunter2"))
        assertEquals(32, expected.length)
        assertTrue(expected.none { it.isUpperCase() }, "digest hex must be lower case")
    }
}
