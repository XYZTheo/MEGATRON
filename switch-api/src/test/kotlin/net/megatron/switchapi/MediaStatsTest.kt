package net.megatron.switchapi

import net.megatron.provisioning.CreateCustomer
import net.megatron.provisioning.CreatePlan
import net.megatron.provisioning.InMemoryStore
import net.megatron.provisioning.RateRow
import net.megatron.provisioning.ReplaceRates
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Parsing rtpengine's media totals.
 *
 * Every string here was COPIED FROM A REAL CALL on the lab box, not invented.
 * That matters: the first version of this parser only understood `bytes=N`,
 * while OpenSIPS's $rtpstat actually emits `N bytes` — number first. It
 * silently returned "unknown" for every call, which reads exactly like a
 * switch whose media stats are not wired up, so nothing looked wrong.
 */
class MediaStatsTest {

    private fun service(): Pair<InMemoryStore, CallService> {
        val store = InMemoryStore()
        val plan = store.createPlan(CreatePlan("Retail", "USD"))
        store.replaceRates(plan.id, ReplaceRates(rates = listOf(
            RateRow(prefix = "1", sellMicrosPerMinute = 60_000, incrementSeconds = 1)
        )))
        store.createCustomer(
            CreateCustomer("bigcorp", plan.id, openingBalanceMicros = 25_000_000), "t"
        )
        return store to CallService(store)
    }

    // -- the real formats ---------------------------------------------------

    @Test
    fun `parses the rtpstat string OpenSIPS actually produces`() {
        // Verbatim from a call that carried G.711 through rtpengine.
        val real = "RTP: 119448 bytes, 474 packets, 474 errors; " +
            "RTCP: 0 bytes, 0 packets, 0 errors"
        assertEquals(119_448L, CallService(InMemoryStore()).parseMediaBytes(real))
    }

    @Test
    fun `parses a silent call`() {
        val silent = "RTP: 0 bytes, 0 packets, 0 errors; RTCP: 0 bytes, 0 packets, 0 errors"
        assertEquals(0L, CallService(InMemoryStore()).parseMediaBytes(silent))
    }

    @Test
    fun `still parses the key-value shape`() {
        // Other sources report bytes=N. Both are accepted because assuming one
        // was how the first version failed.
        assertEquals(4_096L, CallService(InMemoryStore()).parseMediaBytes("totals bytes=4096"))
        assertEquals(4_096L, CallService(InMemoryStore()).parseMediaBytes("""{"bytes": 4096}"""))
    }

    @Test
    fun `unreadable stats are unknown, never zero`() {
        // "We could not read it" must never become "there was no audio".
        // Guessing zero from an unparseable string turns every healthy call
        // into a refund request the moment rtpengine changes its wording.
        val service = CallService(InMemoryStore())
        assertNull(service.parseMediaBytes(null))
        assertNull(service.parseMediaBytes(""))
        assertNull(service.parseMediaBytes("   "))
        assertNull(service.parseMediaBytes("media session torn down"))
    }

    // -- and what the switch does with them ---------------------------------

    @Test
    fun `a call with audio is billed and not flagged`() {
        val (_, service) = service()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "c1"))
        val end = service.endSession(EndSessionRequest(
            callId = "c1",
            durationSeconds = 5,
            mediaStats = "RTP: 119448 bytes, 474 packets, 474 errors; " +
                "RTCP: 0 bytes, 0 packets, 0 errors",
        ))
        assertEquals(5_000L, end.chargedMicros)
        assertEquals(false, end.noMedia)
    }

    @Test
    fun `a call that carried silence is billed AND flagged`() {
        // The money-losing failure mode: signalling says the call happened,
        // and only the media stats say it was worth anything. Still billed --
        // the honest response depends on why -- but never invisible.
        val (_, service) = service()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "c1"))
        val end = service.endSession(EndSessionRequest(
            callId = "c1",
            durationSeconds = 5,
            mediaStats = "RTP: 0 bytes, 0 packets, 0 errors; RTCP: 0 bytes, 0 packets, 0 errors",
        ))
        assertEquals(5_000L, end.chargedMicros)
        assertEquals(true, end.noMedia)
    }

    @Test
    fun `stats we cannot read do not flag the call`() {
        val (_, service) = service()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "c1"))
        val end = service.endSession(EndSessionRequest(
            callId = "c1", durationSeconds = 5, mediaStats = "session closed",
        ))
        assertEquals(false, end.noMedia)
    }

    @Test
    fun `an explicit media_bytes wins over the raw string`() {
        // If a caller has already done the counting, believe it.
        val (_, service) = service()
        service.authorize(AuthorizeRequest("bigcorp", "12125551234", "c1"))
        val end = service.endSession(EndSessionRequest(
            callId = "c1", durationSeconds = 5, mediaBytes = 0,
            mediaStats = "RTP: 119448 bytes, 474 packets, 0 errors",
        ))
        assertEquals(true, end.noMedia)
    }
}
