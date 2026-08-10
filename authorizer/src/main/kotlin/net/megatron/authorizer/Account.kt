package net.megatron.authorizer

import net.megatron.rating.Micros

/**
 * How an account is allowed to fail when the authorizer cannot answer.
 *
 * ARCHITECTURE.md §4.4 is explicit that this is a business decision and must
 * never happen by accident, which is why it has no default anywhere in this
 * codebase — not here, not in the wizard schema, not in the provisioning API.
 */
enum class FailDirection {
    /**
     * Reject the call. Rejecting loses one call; allowing an unauthorized
     * prepaid call can lose unbounded money to a fraudster who has found an
     * account with no balance and a switch that shrugs.
     */
    CLOSED,

    /**
     * Allow the call. Correct for credit-checked, contractually liable
     * postpaid customers: refusing their traffic during OUR outage is worse
     * for both parties than billing them slightly late.
     */
    OPEN,
}

enum class BillingMode {
    /** Pay first. Balance must cover the call before it is authorized. */
    PREPAID,

    /** Bill later, up to a credit limit. */
    POSTPAID,
}

/**
 * The billing state of one customer, as the authorizer needs to see it.
 *
 * Deliberately a value object with no methods that mutate. Balance changes go
 * through [Ledger] so that every one of them is reserved, settled and
 * recorded — a balance that can be assigned to is a balance that will be
 * assigned to from two places at once.
 */
data class Account(
    val id: String,
    val balance: Micros,
    val mode: BillingMode,
    /** Only meaningful for [BillingMode.POSTPAID]. How far below zero they may go. */
    val creditLimit: Micros = Micros.ZERO,
    val maxConcurrentCalls: Int = 2,
    val suspended: Boolean = false,
    /**
     * What to call this account in a message a human reads. NOT an identifier.
     *
     * Everything in here keys on [id], because a handle can be reassigned and a
     * ledger that keyed on one would move money between customers. But an
     * operator reading "cust-1786398571251-4c73 hit destinations-per-minute" has
     * to go and look up which customer that is before they can do anything —
     * which is what the first live run of the fraud guard printed, and it made
     * an otherwise useful alert useless at the moment it mattered.
     *
     * Null falls back to the id: a label is a courtesy, and no message should
     * become unprintable for want of one.
     *
     * LAST IN THE LIST, and that is not cosmetic. Adding it after `mode`
     * silently re-bound every positional `Account(...)` in the test suite —
     * creditLimit became a String, maxConcurrentCalls became a Micros — and the
     * compiler caught it only because the types happened to differ. A new
     * parameter in the middle of a value type with defaults is a change to
     * every caller that did not name its arguments.
     */
    val label: String? = null,
) {
    init {
        require(maxConcurrentCalls >= 1) { "maxConcurrentCalls must be >= 1" }
        require(creditLimit.value >= 0) { "creditLimit must not be negative" }
    }

    /**
     * How much this account may actually spend right now.
     *
     * For prepaid that is the balance. For postpaid it is the balance plus the
     * credit limit, which is what makes a postpaid account able to run past
     * zero and a prepaid one not.
     */
    val spendable: Micros
        get() = when (mode) {
            BillingMode.PREPAID -> balance
            BillingMode.POSTPAID -> balance + creditLimit
        }

    val failDirection: FailDirection
        get() = when (mode) {
            BillingMode.PREPAID -> FailDirection.CLOSED
            BillingMode.POSTPAID -> FailDirection.OPEN
        }
}
