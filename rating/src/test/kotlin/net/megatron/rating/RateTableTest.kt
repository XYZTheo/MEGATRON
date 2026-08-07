package net.megatron.rating

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class RateTableTest {

    private val table = RateTable.of(
        listOf(
            Rate(prefix = "1", sellPerMinute = Micros(20_000), description = "North America"),
            Rate(prefix = "1212", sellPerMinute = Micros(9_000), description = "New York"),
            Rate(prefix = "44", sellPerMinute = Micros(15_000), description = "UK"),
            Rate(prefix = "4477", sellPerMinute = Micros(90_000), description = "UK mobile"),
            Rate(prefix = "8816", sellPerMinute = Micros.ofUnits(50), description = "satellite"),
        )
    )

    @Test
    fun `longest prefix wins`() {
        // The whole point. 12125551234 must price as New York, not as the
        // generic North America rate -- getting this backwards is a 2x
        // over-charge on every New York call.
        assertEquals("New York", table.lookup("12125551234")?.description)
        assertEquals("North America", table.lookup("13105551234")?.description)
        assertEquals("UK mobile", table.lookup("447700900123")?.description)
        assertEquals("UK", table.lookup("442079460000")?.description)
    }

    @Test
    fun `an unrated destination returns null and must not be treated as free`() {
        // A destination with no rate is one we have no price for. Carrying it
        // means carrying it at unknown cost, which is how a switch discovers
        // it has been terminating satellite traffic for a week.
        assertNull(table.lookup("99912345"))
    }

    @Test
    fun `a leading plus and separators are tolerated`() {
        // Rate files and softphones supply numbers in whatever shape they
        // like. Refusing one at 2am because of a space is not useful.
        assertEquals("New York", table.lookup("+1 212 555 1234")?.description)
        assertEquals("UK mobile", table.lookup("+44-7700-900123")?.description)
    }

    @Test
    fun `an empty or non-numeric destination matches nothing`() {
        assertNull(table.lookup(""))
        assertNull(table.lookup("+"))
        assertNull(table.lookup("abc"))
    }

    @Test
    fun `a destination shorter than any prefix matches nothing`() {
        assertNull(table.lookup("9"))
    }

    @Test
    fun `a destination exactly equal to a prefix matches it`() {
        assertEquals("UK", table.lookup("44")?.description)
    }

    @Test
    fun `duplicate prefixes are refused at load time`() {
        // Two prices for one prefix has no correct resolution: picking either
        // silently makes the bill depend on map ordering. Fail where somebody
        // can still fix the file.
        val ex = assertFailsWith<IllegalArgumentException> {
            RateTable.of(
                listOf(
                    Rate(prefix = "44", sellPerMinute = Micros(15_000)),
                    Rate(prefix = "44", sellPerMinute = Micros(16_000)),
                )
            )
        }
        assertEquals(true, ex.message?.contains("duplicate prefix"))
    }

    @Test
    fun `below-cost prefixes are reportable at load time`() {
        val t = RateTable.of(
            listOf(
                Rate("44", Micros(15_000), buyPerMinute = Micros(8_000)),
                Rate("1", Micros(5_000), buyPerMinute = Micros(9_000)),   // loss
                Rate("33", Micros(7_000), buyPerMinute = Micros(7_000)),  // zero margin
            )
        )
        val bad = t.sellingBelowCost().map { it.prefix }.sorted()
        assertEquals(listOf("1", "33"), bad)
    }

    @Test
    fun `lookup is bounded by e164 length regardless of table size`() {
        // Not a timing test -- a correctness one. A 20k-row table must still
        // resolve the right rate, and it must do so by probing from the
        // longest prefix rather than scanning.
        val many = (10_000..29_999).map {
            Rate(prefix = it.toString(), sellPerMinute = Micros(it.toLong()))
        } + Rate(prefix = "1", sellPerMinute = Micros(1))
        val big = RateTable.of(many)
        assertEquals(20_001, big.size)
        assertEquals(Micros(12_345), big.lookup("123456789")?.sellPerMinute)
        // Falls back to the 1-digit prefix only when no longer one matches.
        // Any 5+ digit number starting with 1 hits the 1xxxx block above, so
        // the fallback has to be probed with a short number -- which is
        // itself the behaviour under test: longest match first, always.
        assertEquals(Micros(1), big.lookup("1234")?.sellPerMinute)
    }

    @Test
    fun `normalise strips everything that is not a digit`() {
        assertEquals("441234", RateTable.normalise("+44 1234"))
        assertEquals("441234", RateTable.normalise("44-12-34"))
        assertEquals("441234", RateTable.normalise(" 44.12.34 "))
        assertEquals("", RateTable.normalise("++"))
        assertEquals("", RateTable.normalise(""))
    }

    @Test
    fun `a parenthesised national trunk prefix is dropped, not kept`() {
        // "+44 (0) 7700 900123" is the ordinary way a UK mobile is written.
        // Keeping that zero yields 4407700900123, which longest-prefix-matches
        // "44" (landline) instead of "4477" (mobile). Mobile termination is
        // several times the landline rate, so one retained character bills the
        // call at a fraction of its cost -- silently, on every number written
        // that way.
        assertEquals("447700900123", RateTable.normalise("+44 (0) 7700 900123"))
        assertEquals("447700900123", RateTable.normalise("+44(0)7700900123"))
        assertEquals("UK mobile", table.lookup("+44 (0) 7700 900123")?.description)
    }

    @Test
    fun `a legitimate zero inside a number is not mistaken for a trunk prefix`() {
        // Only a PARENTHESISED lone zero is a trunk prefix. A zero that is
        // part of the number itself must survive, or we would break every
        // destination containing one.
        assertEquals("442079460000", RateTable.normalise("+44 20 7946 0000"))
        assertEquals("UK", table.lookup("+44 20 7946 0000")?.description)
    }
}
