package net.megatron.switchapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The wire CDR must reach the stored record whole.
 *
 * Written after `direction` was added to both types and left out of the copy
 * between them: inbound calls were filed as outgoing, nothing threw, and the
 * only way to notice was to place a real call and read the customer's history.
 * A field-by-field mapping fails silently by construction, so it gets a test
 * that fails loudly.
 */
class CdrMappingTest {

    /**
     * Every field set to something distinguishable from its default, so a
     * field that is not carried across shows up as the default rather than
     * accidentally matching.
     */
    private val full = Cdr(
        callId = "call-99",
        account = "bigcorp",
        destination = "+441632960123",
        prefix = "44",
        durationSeconds = 137,
        durationSource = "sip",
        billedSeconds = 180,
        chargedMicros = 36_000,
        ratePerMinute = 12_000,
        mediaBytes = 987_654,
        mediaStats = "RTP: 987654 bytes, 4321 packets",
        noMedia = true,
        overran = true,
        hangupCause = "NORMAL_CLEARING",
        direction = "inbound",
        endedAt = "2026-08-10T21:26:36Z",
    )

    @Test
    fun `every field on the wire cdr reaches the stored record`() {
        val record = full.toCallRecord()

        assertEquals(full.callId, record.callId)
        assertEquals(full.account, record.account)
        assertEquals(full.destination, record.destination)
        assertEquals(full.prefix, record.prefix)
        assertEquals(full.durationSeconds, record.durationSeconds)
        assertEquals(full.durationSource, record.durationSource)
        assertEquals(full.billedSeconds, record.billedSeconds)
        assertEquals(full.chargedMicros, record.chargedMicros)
        assertEquals(full.ratePerMinute, record.ratePerMinute)
        assertEquals(full.mediaBytes, record.mediaBytes)
        assertEquals(full.mediaStats, record.mediaStats)
        assertEquals(full.noMedia, record.noMedia)
        assertEquals(full.overran, record.overran)
        assertEquals(full.hangupCause, record.hangupCause)
        assertEquals(full.direction, record.direction)
        assertEquals(full.endedAt, record.endedAt)
    }

    /**
     * THE POINT OF THE FIXTURE, asserted rather than assumed.
     *
     * The test above is only as good as `full` being genuinely full. If a new
     * field is added to [Cdr] with a default and nobody sets it here, the
     * mapping test passes while proving nothing about it — a default equals a
     * default whether or not it was copied. This counts the fields and fails
     * when one appears that the fixture has not been updated for.
     */
    @Test
    fun `the fixture sets every field the wire cdr has`() {
        // Instance fields only. A @Serializable class also carries a static
        // `Companion`, which is not synthetic and is not a property -- counting
        // it made this fail at 17 the first time it ran, which is the right
        // direction to be wrong in but still wrong.
        val fields = Cdr::class.java.declaredFields.count {
            !it.isSynthetic && !java.lang.reflect.Modifier.isStatic(it.modifiers)
        }
        assertEquals(
            16, fields,
            "Cdr has $fields fields but this test's fixture and assertions cover 16. " +
                "Add the new field to `full`, assert it above, and make sure " +
                "toCallRecord() carries it -- that mapping fails silently.",
        )
    }

    @Test
    fun `an outbound call keeps its direction too`() {
        // Not just a mirror of the inbound case: `outbound` is the DEFAULT on
        // the stored record, so a mapping that dropped the field would still
        // look right here. It is asserted so the pair reads honestly, and the
        // inbound assertion above is the one with teeth.
        assertEquals("outbound", full.copy(direction = "outbound").toCallRecord().direction)
    }

    @Test
    fun `unknown media stays unknown across the mapping`() {
        // "We could not read the stats" and "there was no audio" are different
        // facts, and a mapping that turned null into 0 would flag every healthy
        // call on a switch whose media stats are not wired up.
        val record = full.copy(mediaBytes = null, mediaStats = null, noMedia = false).toCallRecord()
        assertTrue(record.mediaBytes == null, "unknown media became ${record.mediaBytes}")
        assertTrue(record.mediaStats == null)
    }
}
