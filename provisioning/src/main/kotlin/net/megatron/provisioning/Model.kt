package net.megatron.provisioning

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire types for contracts/provisioning.openapi.yaml.
 *
 * Money crosses the wire as `*_micros`: an integer number of millionths of the
 * account currency. Never a JSON float — a JSON number parsed into a double
 * loses exactness at precisely the magnitudes a switch bills at, and the loss
 * is silent. `ci/policy_check.py` (MONEY-NOT-FLOAT) fails the build on a
 * `Double` in a money path.
 */

@Serializable
enum class CustomerStatus {
    @SerialName("active") ACTIVE,
    @SerialName("suspended") SUSPENDED,
    @SerialName("closed") CLOSED,
}

@Serializable
enum class Transport {
    @SerialName("udp") UDP,
    @SerialName("tcp") TCP,
    @SerialName("tls") TLS,
}

@Serializable
data class CreateCustomer(
    val handle: String,
    @SerialName("plan_id") val planId: String,
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("telegram_user_id") val telegramUserId: Long? = null,
    @SerialName("opening_balance_micros") val openingBalanceMicros: Long = 0,
    @SerialName("max_concurrent_calls") val maxConcurrentCalls: Int = 2,
)

@Serializable
data class SipCredentials(
    @SerialName("sip_username") val sipUsername: String,
    /** Returned exactly once, at creation or rotation. Never readable again. */
    @SerialName("sip_password") val sipPassword: String,
    @SerialName("sip_domain") val sipDomain: String,
    /**
     * What to put in the softphone.
     *
     * Not cosmetic: Zoiper's free tier cannot do TLS at all, so handing a
     * free-tier customer a TLS-only setting produces a phone that will never
     * register and a support call that looks like a platform fault. See
     * contracts/softphone-profiles.yaml.
     */
    @SerialName("transport_hint") val transportHint: Transport,
)

@Serializable
data class CallerId(
    val number: String,
    /**
     * Whether ownership was ESTABLISHED, not whether it was asserted. Drives
     * the STIR/SHAKEN attestation level — you cannot attest a caller ID whose
     * ownership was never verified.
     */
    val verified: Boolean,
    @SerialName("set_at") val setAt: String? = null,
    @SerialName("set_by") val setBy: String? = null,
)

@Serializable
data class Customer(
    val id: String,
    val handle: String,
    @SerialName("display_name") val displayName: String? = null,
    val status: CustomerStatus,
    @SerialName("plan_id") val planId: String,
    @SerialName("balance_micros") val balanceMicros: Long,
    val currency: String,
    @SerialName("caller_id") val callerId: CallerId? = null,
    val registered: Boolean = false,
    @SerialName("active_calls") val activeCalls: Int = 0,
    @SerialName("max_concurrent_calls") val maxConcurrentCalls: Int = 2,
    @SerialName("telegram_user_id") val telegramUserId: Long? = null,
    @SerialName("created_at") val createdAt: String? = null,
)

@Serializable
data class CustomerCreated(
    val customer: Customer,
    val credentials: SipCredentials,
)

@Serializable
data class CustomerPage(
    val items: List<Customer>,
    @SerialName("next_cursor") val nextCursor: String? = null,
)

@Serializable
data class SelfView(
    val handle: String,
    val status: CustomerStatus,
    @SerialName("balance_micros") val balanceMicros: Long,
    val currency: String,
    @SerialName("caller_id") val callerId: CallerId? = null,
    @SerialName("sip_username") val sipUsername: String? = null,
    @SerialName("sip_domain") val sipDomain: String? = null,
    val registered: Boolean = false,
    @SerialName("active_calls") val activeCalls: Int = 0,
)

@Serializable
data class BalanceAdjustment(
    @SerialName("amount_micros") val amountMicros: Long,
    val reason: String,
    val reference: String? = null,
)

@Serializable
data class Transaction(
    val id: String,
    @SerialName("customer_id") val customerId: String,
    @SerialName("amount_micros") val amountMicros: Long,
    @SerialName("balance_after_micros") val balanceAfterMicros: Long,
    val reason: String,
    val reference: String? = null,
    @SerialName("created_at") val createdAt: String,
    /**
     * Who did it. `telegram:<user_id>` when it came through the bot.
     * Append-only and never rewritten — MagnusBilling's audit trail is
     * editable by an admin, which makes it evidence of nothing.
     */
    val actor: String,
)

@Serializable
data class SetStatus(
    val status: CustomerStatus,
    val reason: String,
    @SerialName("drop_active") val dropActive: Boolean = false,
)

@Serializable
data class SetCallerId(@SerialName("caller_id") val callerId: String)

@Serializable
data class CreatePlan(
    val name: String,
    val currency: String,
    val description: String? = null,
)

@Serializable
data class Plan(
    val id: String,
    val name: String,
    val currency: String,
    val description: String? = null,
    @SerialName("rate_count") val rateCount: Int = 0,
    @SerialName("updated_at") val updatedAt: String? = null,
)

@Serializable
data class RateRow(
    val prefix: String,
    val description: String? = null,
    @SerialName("sell_micros_per_minute") val sellMicrosPerMinute: Long,
    @SerialName("buy_micros_per_minute") val buyMicrosPerMinute: Long? = null,
    @SerialName("connect_fee_micros") val connectFeeMicros: Long = 0,
    @SerialName("increment_seconds") val incrementSeconds: Int = 60,
    @SerialName("minimum_seconds") val minimumSeconds: Int = 0,
)

@Serializable
data class ReplaceRates(
    @SerialName("effective_from") val effectiveFrom: String? = null,
    val rates: List<RateRow>,
)

@Serializable
data class RatesReplaced(
    @SerialName("plan_id") val planId: String,
    @SerialName("rate_count") val rateCount: Int,
    @SerialName("effective_from") val effectiveFrom: String,
)

@Serializable
enum class TrunkDirection {
    @SerialName("outbound") OUTBOUND,
    @SerialName("inbound") INBOUND,
    @SerialName("both") BOTH,
}

@Serializable
data class CreateTrunk(
    val name: String,
    val direction: TrunkDirection,
    val host: String,
    val port: Int = 5060,
    /**
     * The carrier's source addresses. Required and non-empty: an inbound trunk
     * that accepts from anywhere is an open relay, which is the classic way a
     * switch ends up carrying somebody else's traffic at its own expense.
     */
    @SerialName("remote_ips") val remoteIps: List<String>,
    val transport: Transport = Transport.UDP,
    @SerialName("max_concurrent_calls") val maxConcurrentCalls: Int? = null,
    val codecs: List<String> = emptyList(),
)

@Serializable
data class Trunk(
    val id: String,
    val name: String,
    val direction: TrunkDirection,
    val host: String,
    val port: Int,
    @SerialName("remote_ips") val remoteIps: List<String>,
    val transport: Transport,
    val enabled: Boolean,
    @SerialName("max_concurrent_calls") val maxConcurrentCalls: Int? = null,
    @SerialName("active_calls") val activeCalls: Int = 0,
)

/** RFC 9457 problem details. The only error shape this API emits. */
@Serializable
data class Problem(
    val type: String = "about:blank",
    val title: String,
    val status: Int,
    val detail: String? = null,
)
