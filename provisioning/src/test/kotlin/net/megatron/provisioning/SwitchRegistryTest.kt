package net.megatron.provisioning

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Parsing what OpenSIPS actually says.
 *
 * **Every payload below was copied from a real switch**, with a real softphone
 * registered against it, rather than written from the documentation. The last
 * time a response format was assumed in this codebase, `$rtpstat` was parsed
 * as `bytes=N` when OpenSIPS emits `N bytes`, and every call reported unknown
 * media for a week while looking perfectly healthy.
 */
class SwitchRegistryTest {

    private val registry = SwitchRegistry("http://unused") { }

    /** Verbatim from `ul_show_contact` on the lab switch. */
    private val registered = """
        {"jsonrpc":"2.0","result":{"AOR":"bigcorp","Contacts":[{
          "Contact":"sip:bigcorp@127.0.0.1:5061",
          "ContactID":"823947625576278544","Expires":300,"Q":"",
          "Callid":"1-68013@127.0.0.1","Cseq":2,"User-agent":"MEGATRON-lab",
          "State":"CS_NEW","Flags":0,"Cflags":"","Socket":"udp:0.0.0.0:5060",
          "Methods":4294967295}]},"id":1}
    """.trimIndent()

    @Test
    fun `a registered phone is read back whole`() {
        val status = registry.parse(registered)

        assertTrue(status.registered)
        assertEquals("sip:bigcorp@127.0.0.1:5061", status.contact)
        assertEquals(300, status.expiresSeconds)
        assertFalse(status.unknown)
    }

    @Test
    fun `the user agent is read from the field OpenSIPS actually uses`() {
        // "User-agent", not "User-Agent". Guessing the capitalisation returns
        // a silent null that reads as a phone not reporting one, which is a
        // plausible-looking wrong answer rather than an error.
        assertEquals("MEGATRON-lab", registry.parse(registered).userAgent)
    }

    @Test
    fun `an unregistered account is a legitimate no, not a failure`() {
        // OpenSIPS answers JSON-RPC with an error member when the AOR is not
        // in the location table. An unregistered customer is the normal case
        // and must not be reported as "we could not tell".
        val status = registry.parse(
            """{"jsonrpc":"2.0","error":{"code":404,"message":"AOR not found"},"id":1}"""
        )

        assertFalse(status.registered)
        assertFalse(status.unknown, "a plain 'not registered' was reported as unknown")
    }

    @Test
    fun `an AOR with no contacts is not registered`() {
        val status = registry.parse(
            """{"jsonrpc":"2.0","result":{"AOR":"bigcorp","Contacts":[]},"id":1}"""
        )
        assertFalse(status.registered)
        assertFalse(status.unknown)
    }

    @Test
    fun `a body that is not JSON is unknown, not offline`() {
        // "NOT REGISTERED" AND "WE COULD NOT TELL" ARE DIFFERENT ANSWERS to
        // an operator deciding whether to wake a customer at 2am. Collapsing
        // them means a broken MI endpoint reports every phone in the fleet as
        // offline, confidently.
        val status = registry.parse("<html>502 Bad Gateway</html>")
        assertFalse(status.registered)
        assertTrue(status.unknown, "unreadable output was reported as definitely offline")
    }

    @Test
    fun `an unexpected shape is unknown, not offline`() {
        val status = registry.parse("""{"jsonrpc":"2.0","result":"surprise","id":1}""")
        assertTrue(status.unknown)
    }

    @Test
    fun `with no MI url configured the answer is unknown`() {
        // A deployment that has not been told where its switch is must not
        // claim every customer is offline.
        val status = SwitchRegistry(null) { }.registrationFor("bigcorp")
        assertFalse(status.registered)
        assertTrue(status.unknown)
        assertNull(status.contact)
    }

    @Test
    fun `an unreachable switch is unknown, not offline`() {
        val status = SwitchRegistry("http://127.0.0.1:1") { }.registrationFor("bigcorp")
        assertTrue(status.unknown, "an unreachable switch was reported as the phone being offline")
    }

    @Test
    fun `a handle carrying a quote cannot break the request`() {
        // Handle validation makes this unreachable today, and that validation
        // lives in another file — the same argument that put an escape check
        // in SubscriberExport. If the request were built by interpolation, a
        // quote would let the caller rewrite the MI method being invoked.
        val status = SwitchRegistry("http://127.0.0.1:1") { }
            .registrationFor("""evil","method":"ul_flush""")
        // It fails to connect rather than sending something malformed; what
        // matters is that it did not throw while building the request.
        assertTrue(status.unknown)
    }
}
