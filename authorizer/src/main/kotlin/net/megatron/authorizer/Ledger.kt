package net.megatron.authorizer

import net.megatron.rating.Micros
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Reserve-then-debit, which is the only way prepaid survives concurrency.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * ------------------------------
 * A customer with $1 of balance places six simultaneous calls. If each call
 * merely CHECKS the balance at setup and debits at hangup, all six are
 * authorized — every one of them sees $1 and every one of them is satisfied —
 * and the account ends the minute at minus $5. On an account whose credentials
 * have been stolen, "six" is "six hundred" and the loss is unbounded. This is
 * the single most expensive bug available in prepaid telephony and it is a
 * concurrency bug, not a billing one.
 *
 * So money is RESERVED at authorize time, before the call is allowed to
 * proceed. A reservation reduces what the next call can see, immediately and
 * atomically. At hangup the reservation is SETTLED against what the call
 * actually cost, and any difference returns to the balance.
 *
 * The lifecycle mirrors the one in contracts/authorizer.openapi.yaml
 * (Authorize -> Initiate -> Update -> Terminate -> ProcessCDR), which is
 * itself modelled on CGRateS's published design. The model is taken from its
 * documentation; none of its code is used — it is AGPLv3 and MEGATRON is
 * proprietary.
 *
 * WHAT THIS IMPLEMENTATION IS AND IS NOT
 * --------------------------------------
 * This is the reference implementation and the executable specification of the
 * semantics. It is correct and it is in-memory. Production runs the same
 * semantics as a Redis Lua script so the reserve is atomic across processes —
 * see ARCHITECTURE.md §4.4. Keeping the rules here, testable without Redis, is
 * what makes it possible to prove them at all.
 */
class Ledger {

    private data class State(
        val balance: AtomicLong,
        val reserved: AtomicLong,
        val activeCalls: AtomicLong,
    )

    private val accounts = ConcurrentHashMap<String, State>()
    private val reservations = ConcurrentHashMap<String, Reservation>()

    data class Reservation(
        val id: String,
        val accountId: String,
        val amount: Micros,
        val maxSeconds: Int,
    )

    /** Result of settling: what was charged, and what went back. */
    data class Settlement(
        val charged: Micros,
        val returned: Micros,
        val balanceAfter: Micros,
        /**
         * True when the call cost MORE than was reserved. Not an error: a call
         * can outrun its reservation if the session timer is missed or a
         * re-rate lands late. It is recorded because a switch that overruns
         * often is a switch whose session timers are not working, and that is
         * a leak worth seeing.
         */
        val overran: Boolean,
    )

    fun open(accountId: String, balance: Micros) {
        accounts[accountId] = State(
            AtomicLong(balance.value), AtomicLong(0), AtomicLong(0)
        )
    }

    /**
     * Adopt an externally-changed balance while keeping live reservations.
     *
     * THE BUG THIS FIXES was invisible to every unit test and obvious the
     * moment two services ran against one database: the ledger learned an
     * account's balance once, at first call, and never again. So a customer
     * who topped up through the bot could not call until the switch was
     * restarted — and, far worse, a customer whose balance had been drained
     * or corrected downward kept right on calling against money that was no
     * longer there.
     *
     * Reservations are deliberately preserved. They represent calls that are
     * up RIGHT NOW; discarding them on a resync would let the next call spend
     * money already committed to a call in progress, which is the double-spend
     * this whole class exists to prevent.
     */
    fun syncBalance(accountId: String, balance: Micros) {
        val state = accounts[accountId]
        if (state == null) {
            open(accountId, balance)
            return
        }
        state.balance.set(balance.value)
    }

    fun isOpen(accountId: String): Boolean = accounts.containsKey(accountId)

    fun balanceOf(accountId: String): Micros =
        Micros(accounts.getValue(accountId).balance.get())

    /** Balance minus everything currently reserved — what a new call may see. */
    fun availableTo(account: Account): Micros {
        val state = accounts.getValue(account.id)
        val headroom = when (account.mode) {
            BillingMode.PREPAID -> 0L
            BillingMode.POSTPAID -> account.creditLimit.value
        }
        return Micros(state.balance.get() + headroom - state.reserved.get())
    }

    fun activeCalls(accountId: String): Int =
        accounts.getValue(accountId).activeCalls.get().toInt()

    /**
     * Hold [amount] against the account.
     *
     * Returns null when the account cannot cover it — the caller MUST treat
     * that as a refusal. Compare-and-set in a loop rather than a lock: the
     * authorizer's p99 budget is 5 ms and this runs per call setup, so a
     * contended lock across every call on a busy account is exactly the wrong
     * shape.
     */
    fun reserve(account: Account, amount: Micros, maxSeconds: Int, reservationId: String): Reservation? {
        val state = accounts.getValue(account.id)
        val headroom = when (account.mode) {
            BillingMode.PREPAID -> 0L
            BillingMode.POSTPAID -> account.creditLimit.value
        }
        while (true) {
            val currentlyReserved = state.reserved.get()
            val available = state.balance.get() + headroom - currentlyReserved
            if (amount.value > available) return null
            if (state.reserved.compareAndSet(currentlyReserved, currentlyReserved + amount.value)) {
                state.activeCalls.incrementAndGet()
                val reservation = Reservation(reservationId, account.id, amount, maxSeconds)
                reservations[reservationId] = reservation
                return reservation
            }
            // Lost the race to another call on the same account; re-read and
            // try again. The retry is what makes six simultaneous calls on a
            // one-dollar balance resolve to however many actually fit.
        }
    }

    /**
     * Settle a reservation against what the call really cost.
     *
     * Idempotent by reservation id: settling twice returns the first result
     * and moves no money. A BYE can be retransmitted, a CDR can be replayed,
     * and neither may debit the customer a second time.
     */
    fun settle(reservationId: String, actualCost: Micros): Settlement {
        // Replay check first. A retransmitted BYE or a re-delivered CDR must
        // return what happened the first time, not debit the customer again.
        settled[reservationId]?.let { return it }

        val reservation = reservations.remove(reservationId)
            ?: throw IllegalStateException(
                "no reservation '$reservationId' to settle. Settling something that was " +
                    "never reserved would debit a customer for a call nobody authorized."
            )

        val state = accounts.getValue(reservation.accountId)
        state.reserved.addAndGet(-reservation.amount.value)
        state.activeCalls.decrementAndGet()
        val balanceAfter = state.balance.addAndGet(-actualCost.value)

        val returned = reservation.amount - actualCost
        val settlement = Settlement(
            charged = actualCost,
            returned = if (returned.value > 0) returned else Micros.ZERO,
            balanceAfter = Micros(balanceAfter),
            overran = actualCost > reservation.amount,
        )
        settled[reservationId] = settlement
        return settlement
    }

    /**
     * Release a reservation without charging — the call never connected.
     *
     * Distinct from settling at zero so that the two are distinguishable in
     * the audit trail: "never answered" and "answered and cost nothing" are
     * different facts about a call.
     */
    fun release(reservationId: String): Boolean {
        val reservation = reservations.remove(reservationId) ?: return false
        val state = accounts.getValue(reservation.accountId)
        state.reserved.addAndGet(-reservation.amount.value)
        state.activeCalls.decrementAndGet()
        return true
    }

    /**
     * Completed settlements, keyed by reservation id, so a replay returns the
     * original answer instead of moving money twice.
     *
     * In production this is a bounded store with a TTL well past the longest
     * plausible retransmission window — unbounded here because the reference
     * implementation's job is to state the semantics, not to manage memory.
     * Losing an entry early would turn a replay into a double debit, so the
     * TTL is a correctness parameter rather than a tuning one.
     */
    private val settled = ConcurrentHashMap<String, Settlement>()
}
