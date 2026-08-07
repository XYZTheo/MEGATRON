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
