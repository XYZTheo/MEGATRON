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
    // NO `registered` OR `active_calls` HERE, and they were removed rather
    // than left.
    //
    // Both were placeholders that nothing ever set, so every response asserted
    // "not registered, no calls in progress" about every customer — including
    // ones with a phone registered and a call up. A field that is always false
    // does not fail to answer the question, it answers it WRONGLY, and it
    // reads as authoritative because it sits on the customer record.
    //
    // Both are live switch state, not customer attributes. Registration is
    // GET /v1/customers/{id}/registration, which asks OpenSIPS. Calls in
    // progress belong to switch-api, which is holding them.
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
    // Same removal as on Customer, and it matters more here: this is the view
    // a CUSTOMER sees. Telling them "not registered" while their phone is
    // registered sends them to reconfigure a softphone that was working.
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

    // -- credentials, for carriers that challenge instead of allowlisting ----
    //
    // Plenty of carriers do not authenticate by IP: they issue a username and
    // password and challenge every INVITE with a 407. A switch that only does
    // IP-authenticated trunks cannot connect to them at all, which rules out
    // most of the small and mid-size providers an operator actually buys from.
    @SerialName("auth_username") val authUsername: String? = null,
    /**
     * Stored recoverable, and it has to be: digest needs the plaintext or HA1,
     * and here WE are the client answering a challenge whose realm and nonce
     * the carrier chooses. It is an operator secret — it buys calls at the
     * operator's own expense — and it is never returned by the API.
     */
    @SerialName("auth_password") val authPassword: String? = null,
    /**
     * The realm the carrier challenges with. Usually their SIP domain, and not
     * reliably the same as [host] — which is why it is given rather than
     * guessed. Defaults to [host] when omitted.
     */
    @SerialName("auth_realm") val authRealm: String? = null,
    /**
     * Whether to REGISTER to them. Some carriers route inbound calls to
     * wherever you last registered from; others expect a static address and
     * never want a REGISTER.
     */
    val register: Boolean = false,
    /**
     * Lower wins. Default 100, so a trunk added later can be put in front of
     * the existing ones without renumbering them.
     *
     * Selection used to be "the lowest trunk id", which is deterministic and
     * WRONG: it means the first trunk ever created wins forever, so adding a
     * carrier changes nothing and an operator's calls keep going to whatever
     * they set up first. That is indistinguishable from the new trunk being
     * broken.
     */
    val priority: Int = 100,
    /**
     * The user part MEGATRON puts in From on calls to this carrier.
     *
     * WHO WE ARE TO THE CARRIER IS NOT WHO THE CALLER IS TO US. Our From
     * carries the customer's handle, because that is who authenticated. The
     * carrier has never heard of that handle: an Asterisk-based provider looks
     * up the peer by From user, fails to match, and answers 403 Forbidden even
     * though the digest we sent was correct. That was not a hypothesis — it is
     * what a real provider did to this switch, twice, with a valid password.
     *
     * Null means "send what the customer sent". That is right for carriers who
     * authenticate by IP and want to see the originating number; wrong for
     * carriers who authenticate by account, so for those [SqlStore] falls back
     * to [authUsername] rather than leaving the operator to discover 403s.
     *
     * Magnus and VOS3000 both have this field, under other names. Anyone
     * connecting a real carrier needs it.
     */
    @SerialName("from_user") val fromUser: String? = null,
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
    @SerialName("auth_username") val authUsername: String? = null,
    @SerialName("auth_realm") val authRealm: String? = null,
    /**
     * WHETHER there is a password, never what it is.
     *
     * The operator needs to know a trunk is credentialed — an unauthenticated
     * trunk against a carrier that expects a login fails every call — and
     * nobody needs it read back. There is no endpoint that returns it, which
     * is a property worth keeping rather than a convenience worth adding.
     */
    val authenticated: Boolean = false,
    val register: Boolean = false,
    /** Lower wins. See [CreateTrunk.priority]. */
    val priority: Int = 100,
    /**
     * What we present in From to this carrier. See [CreateTrunk.fromUser].
     *
     * Returned, unlike the password: it is not a secret, and an operator
     * debugging a 403 needs to see it without guessing.
     */
    @SerialName("from_user") val fromUser: String? = null,
)

/** RFC 9457 problem details. The only error shape this API emits. */
/**
 * A completed call, as stored.
 *
 * Deliberately a separate type from switch-api's `Cdr` rather than shared.
 * That one is the SHAPE OF A MESSAGE between two services and may gain fields
 * for the switch's convenience; this one is a row that will be read back in a
 * dispute years later. Coupling them means a change made for the wire quietly
 * changes what is on record.
 *
 * Money is integer micro-units, as everywhere.
 */
/**
 * The answer to "are you alive and can you read your own database".
 *
 * No version, no build id, no uptime. Those are useful and they are also a
 * free fingerprint for anyone deciding which exploit to try, and this endpoint
 * is the one thing here that answers without a credential.
 */
@Serializable
data class ServiceHealth(val healthy: Boolean, val service: String)

/**
 * A number a customer receives calls on.
 *
 * [number] is stored WITHOUT a leading `+`, because that is what carriers put
 * in a request URI — and inconsistently. Normalising on the way in means the
 * inbound lookup is an exact match on one representation rather than a set of
 * guesses at call time, when there is a caller waiting.
 */
@Serializable
data class Did(
    val number: String,
    @SerialName("customer_id") val customerId: String,
    val description: String? = null,
    /**
     * A parked DID is owned and not delivering, which is NOT the same as a
     * number nobody owns. The first is a customer's number held back; the
     * second is a call to reject.
     */
    val enabled: Boolean = true,
    @SerialName("assigned_at") val assignedAt: String? = null,
    @SerialName("assigned_by") val assignedBy: String? = null,
)

@Serializable
data class AssignDid(
    val number: String,
    @SerialName("customer_id") val customerId: String,
    val description: String? = null,
)

@Serializable
data class SetPlan(@SerialName("plan_id") val planId: String)

/**
 * Creating a customer with a credential MEGATRON did not generate.
 *
 * Deliberately NOT [CreateCustomer] with an optional password. A separate type
 * means "this request carries a plaintext password" is visible in the type
 * system, greppable in the codebase, and impossible to trigger by accident
 * from the ordinary create path.
 */
@Serializable
data class ImportCustomer(
    val handle: String,
    @SerialName("plan_id") val planId: String,
    /**
     * The customer's EXISTING password, from the switch being replaced.
     *
     * Converted to HA1 and SHA-256 on arrival and not stored. It is never
     * echoed back: the caller already has it, and returning it would put it in
     * one more log.
     */
    val password: String,
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("telegram_user_id") val telegramUserId: Long? = null,
    @SerialName("opening_balance_micros") val openingBalanceMicros: Long = 0,
    @SerialName("max_concurrent_calls") val maxConcurrentCalls: Int = 2,
)

@Serializable
data class VerifyCredentials(val handle: String, val password: String)

/**
 * The answer to "does this password work", and nothing else.
 *
 * No reason, no distinction between an unknown handle and a wrong password.
 * Reporting which would be a username oracle: one request per guess tells an
 * attacker whether an account exists. The store knows the difference; this
 * type is how it is stopped from saying so.
 */
@Serializable
data class CredentialCheck(val valid: Boolean)

@Serializable
data class CallRecord(
    @SerialName("call_id") val callId: String,
    val account: String,
    val destination: String,
    val prefix: String? = null,
    @SerialName("duration_seconds") val durationSeconds: Int,
    /** "sip" or "server-clock" — how the duration was measured. */
    @SerialName("duration_source") val durationSource: String,
    @SerialName("billed_seconds") val billedSeconds: Int,
    @SerialName("charged_micros") val chargedMicros: Long,
    @SerialName("rate_micros_per_minute") val ratePerMinute: Long,
    /**
     * Null means the media stats could not be read, which is NOT zero. Zero is
     * evidence of silence; null is evidence of nothing.
     */
    @SerialName("media_bytes") val mediaBytes: Long? = null,
    @SerialName("media_stats") val mediaStats: String? = null,
    @SerialName("no_media") val noMedia: Boolean = false,
    val overran: Boolean = false,
    @SerialName("hangup_cause") val hangupCause: String? = null,
    @SerialName("ended_at") val endedAt: String,
)

@Serializable
data class Problem(
    val type: String = "about:blank",
    val title: String,
    val status: Int,
    val detail: String? = null,
)
