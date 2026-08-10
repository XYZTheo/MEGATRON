package net.megatron.switchapi

import net.megatron.provisioning.CallRecord

/**
 * The wire CDR, as the row that will be read back in a dispute years later.
 *
 * The two types stay separate on purpose — one is the SHAPE OF A MESSAGE
 * between two services and may gain fields for the switch's convenience, the
 * other is a record — and this function is the price of that. It is a
 * field-by-field copy, which is exactly the shape that silently drops a field:
 * adding `direction` to both types and forgetting this mapping produced calls
 * that arrived from a carrier and were filed as outgoing, with nothing failing
 * anywhere. A live call test caught it; a unit test should have.
 *
 * So it lives here, named and callable, rather than inline in a lambda inside
 * `main()` where nothing could reach it. [CdrMappingTest] fails if a field
 * stops being carried across.
 */
fun Cdr.toCallRecord(): CallRecord = CallRecord(
    callId = callId,
    account = account,
    destination = destination,
    prefix = prefix,
    durationSeconds = durationSeconds,
    durationSource = durationSource,
    billedSeconds = billedSeconds,
    chargedMicros = chargedMicros,
    ratePerMinute = ratePerMinute,
    mediaBytes = mediaBytes,
    mediaStats = mediaStats,
    noMedia = noMedia,
    overran = overran,
    hangupCause = hangupCause,
    direction = direction,
    endedAt = endedAt,
)
