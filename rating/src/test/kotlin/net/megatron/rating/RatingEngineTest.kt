package net.megatron.rating

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * These are the tests that decide whether customers get billed correctly.
 *
 * Written against worked examples with the arithmetic done by hand in the
 * comments, so a future change that "simplifies" the rounding has to argue
 * with a number rather than with a style preference.
 */
class RatingEngineTest {

    private val ukLandline = Rate(
        prefix = "441",
        sellPerMinute = Micros(12_000),      // $0.012/min
        buyPerMinute = Micros(8_000),        // $0.008/min
        incrementSeconds = 60,
        minimumSeconds = 60,
        description = "UK landline",
    )

    private val perSecond = Rate(
        prefix = "1",
        sellPerMinute = Micros(6_000),       // $0.006/min = 100 micros/sec
        incrementSeconds = 1,
        minimumSeconds = 0,
    )

    // -- the basics ---------------------------------------------------------

    @Test
    fun `one minute at twelve tenths of a cent`() {
        // 60s / 60 * 12_000 = 12_000
        val charge = RatingEngine.rate(60, ukLandline)
        assertEquals(60, charge.billedSeconds)
        assertEquals(12_000L, charge.total.value)
    }

    @Test
    fun `a short call bills the minimum, not the duration`() {
        // 3s -> minimum 60s -> increment 60s -> 60s billed.
        // This is the single most common billing complaint in wholesale, so
        // it is pinned rather than left to be discovered.
        val charge = RatingEngine.rate(3, ukLandline)
        assertEquals(60, charge.billedSeconds)
        assertEquals(12_000L, charge.total.value)
    }

    @Test
    fun `sixty one seconds bills two minutes on a per-minute plan`() {
        val charge = RatingEngine.rate(61, ukLandline)
        assertEquals(120, charge.billedSeconds)
        assertEquals(24_000L, charge.total.value)
    }

    @Test
    fun `an unanswered call costs nothing, including the connect fee`() {
        // Charging for a failed attempt is how a customer stops trusting the
        // bill, and the dispute costs more than the fee.
        val withFee = ukLandline.copy(connectFee = Micros(5_000))
        val charge = RatingEngine.rate(0, withFee)
        assertEquals(0, charge.billedSeconds)
        assertEquals(0L, charge.total.value)
        assertEquals(0L, charge.connectFee.value)
    }

    @Test
    fun `connect fee is charged once, on top of duration`() {
        val withFee = ukLandline.copy(connectFee = Micros(5_000))
        val charge = RatingEngine.rate(60, withFee)
        assertEquals(5_000L, charge.connectFee.value)
        assertEquals(12_000L, charge.durationCharge.value)
        assertEquals(17_000L, charge.total.value)
    }

    // -- the order of operations, which is where this goes wrong ------------

    @Test
    fun `minimum is applied before the increment, not after`() {
        // 60s minimum, 6s increment. A 3s call must bill 60s.
        // Applying the increment first would give 6s and under-bill by 90%.
        val sixtySix = Rate(
            prefix = "44",
            sellPerMinute = Micros(60_000),
            incrementSeconds = 6,
            minimumSeconds = 60,
        )
        assertEquals(60, RatingEngine.rate(3, sixtySix).billedSeconds)
        // and past the minimum it rounds to the 6s increment: 61 -> 66
        assertEquals(66, RatingEngine.rate(61, sixtySix).billedSeconds)
    }

    @Test
    fun `per-second billing bills the exact second`() {
        val charge = RatingEngine.rate(37, perSecond)
        assertEquals(37, charge.billedSeconds)
        // 37 * 6000 / 60 = 3700
        assertEquals(3_700L, charge.total.value)
    }

    // -- rounding -----------------------------------------------------------

    @Test
    fun `rounding is half up, not truncation`() {
        // 1s at 1000 micros/min = 16.67 micros. Truncation gives 16 and
        // under-charges on every single call, which is a systematic leak
        // rather than a rounding error.
        assertEquals(17L, RatingEngine.perMinuteToCharge(1, 1_000))
        // exact halves round up: 30s at 1 micro/min = 0.5 -> 1
        assertEquals(1L, RatingEngine.perMinuteToCharge(30, 1))
        // just below a half rounds down: 29s at 1 micro/min = 0.483 -> 0
        assertEquals(0L, RatingEngine.perMinuteToCharge(29, 1))
    }

    @Test
    fun `a free destination is free, not one micro`() {
        val free = Rate(prefix = "800", sellPerMinute = Micros.ZERO, incrementSeconds = 1)
        assertEquals(0L, RatingEngine.rate(120, free).total.value)
    }

    @Test
    fun `increment rounding is exact at the boundaries`() {
        assertEquals(0, RatingEngine.roundUpToIncrement(0, 60))
        assertEquals(60, RatingEngine.roundUpToIncrement(1, 60))
        assertEquals(60, RatingEngine.roundUpToIncrement(60, 60))
        assertEquals(120, RatingEngine.roundUpToIncrement(61, 60))
        assertEquals(6, RatingEngine.roundUpToIncrement(1, 6))
        assertEquals(6, RatingEngine.roundUpToIncrement(6, 6))
        assertEquals(12, RatingEngine.roundUpToIncrement(7, 6))
    }

    // -- prepaid: how long may this call run --------------------------------

    @Test
    fun `affordable seconds for a healthy balance`() {
        // $1.00 at $0.006/min = 166.67 min = 10000s, trimmed to whole
        // 1s increments = 10000s, but capped by the 4h ceiling (14400s).
        val seconds = RatingEngine.affordableSeconds(Micros.ofUnits(1), perSecond)
        assertEquals(10_000, seconds)
    }

    @Test
    fun `affordable seconds never grants a second the caller cannot pay for`() {
        // Exactly enough for 100 seconds and not one more.
        // 100s at 6000 micros/min = 10_000 micros.
        val seconds = RatingEngine.affordableSeconds(Micros(10_000), perSecond)
        assertEquals(100, seconds)
        // and billing that duration must not exceed the balance
        val charge = RatingEngine.rate(seconds, perSecond)
        assertTrue(charge.total.value <= 10_000L, "granted ${charge.total.value} > 10000")
    }

    @Test
    fun `zero balance authorizes nothing`() {
        assertEquals(0, RatingEngine.affordableSeconds(Micros.ZERO, perSecond))
    }

    @Test
    fun `negative balance authorizes nothing`() {
        // Prepaid fails CLOSED. Rejecting loses one call; allowing can lose
        // unbounded money to a fraudster (ARCHITECTURE 4.4).
        assertEquals(0, RatingEngine.affordableSeconds(Micros(-1), perSecond))
    }

    @Test
    fun `balance that cannot cover the minimum duration authorizes nothing`() {
        // 60s minimum at 12_000/min costs 12_000. A balance of 11_999 cannot
        // pay for the shortest possible call, so there is no duration to grant.
        assertEquals(0, RatingEngine.affordableSeconds(Micros(11_999), ukLandline))
        assertEquals(60, RatingEngine.affordableSeconds(Micros(12_000), ukLandline))
    }

    @Test
    fun `balance that cannot cover the connect fee authorizes nothing`() {
        val withFee = perSecond.copy(connectFee = Micros(5_000))
        assertEquals(0, RatingEngine.affordableSeconds(Micros(4_999), withFee))
    }

    @Test
    fun `granted time is whole increments, never a partial one`() {
        // 60s increments, balance good for 100s. Granting 100 would bill 120
        // on hangup and overdraw, so it must grant 60.
        val perMinute = Rate(prefix = "1", sellPerMinute = Micros(6_000), incrementSeconds = 60)
        val seconds = RatingEngine.affordableSeconds(Micros(10_000), perMinute)
        assertEquals(60, seconds)
        assertTrue(RatingEngine.rate(seconds, perMinute).total.value <= 10_000L)
    }

    @Test
    fun `a free destination is capped by the ceiling, not by money`() {
        val free = Rate(prefix = "800", sellPerMinute = Micros.ZERO, incrementSeconds = 1)
        assertEquals(3_600, RatingEngine.affordableSeconds(Micros.ofUnits(1), free, 3_600))
    }

    // -- margin -------------------------------------------------------------

    @Test
    fun `margin is sell minus buy on the billed duration`() {
        val charge = RatingEngine.rate(60, ukLandline)
        // sell 12_000, buy 8_000
        assertEquals(4_000L, charge.margin()?.value)
    }

    @Test
    fun `margin is unknown when the buy price is not recorded`() {
        assertNull(RatingEngine.rate(60, perSecond).margin())
    }

    @Test
    fun `selling below cost is detectable`() {
        val loss = Rate(
            prefix = "44",
            sellPerMinute = Micros(5_000),
            buyPerMinute = Micros(8_000),
        )
        assertTrue(loss.sellsBelowCost)
        assertEquals(-3_000L, loss.marginPerMinute?.value)
    }

    // -- input validation ---------------------------------------------------

    @Test
    fun `a negative duration is refused rather than rated`() {
        assertFailsWith<IllegalArgumentException> { RatingEngine.rate(-1, ukLandline) }
    }

    @Test
    fun `a rate with a non-numeric prefix is refused at construction`() {
        assertFailsWith<IllegalArgumentException> {
            Rate(prefix = "44a", sellPerMinute = Micros(1))
        }
    }

    @Test
    fun `a zero increment is refused`() {
        assertFailsWith<IllegalArgumentException> {
            Rate(prefix = "44", sellPerMinute = Micros(1), incrementSeconds = 0)
        }
    }

    // -- long calls, where overflow would live ------------------------------

    @Test
    fun `a twenty four hour call at a satellite rate does not overflow`() {
        val satellite = Rate(
            prefix = "8816",
            sellPerMinute = Micros.ofUnits(50),   // $50/min
            incrementSeconds = 60,
        )
        val charge = RatingEngine.rate(24 * 60 * 60, satellite)
        assertEquals(86_400, charge.billedSeconds)
        // 1440 minutes * $50 = $72,000
        assertEquals(72_000L * Micros.MICROS_PER_UNIT, charge.total.value)
    }
}
