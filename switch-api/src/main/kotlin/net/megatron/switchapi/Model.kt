package net.megatron.switchapi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire types for contracts/authorizer.openapi.yaml.
 *
 * Kept small on purpose. OpenSIPS builds this JSON in config script via
 * `rest_client`, and every field is one more thing to get wrong in a language
 * with no types — so the request carries what the switch already knows and
 * nothing it would have to look up.
 */

@Serializable
data class AuthorizeRequest(
    /** SIP username of the calling account. */
    val account: String,
    /** Dialled number, as it arrived. Normalised on our side, not the switch's. */
    val destination: String,
    /** Call-ID, used as the reservation id so a retransmitted INVITE is idempotent. */
    @SerialName("call_id") val callId: String,
    @SerialName("source_ip") val sourceIp: String? = null,
)

@Serializable
data class AuthorizeResponse(
    val decision: String,
    /**
     * Seconds. Becomes the session timer on the call.
     *
     * Present on an allow and absent on a reject. Without it a prepaid call
     * runs until the balance is already negative and the money is gone — one
     * of the three money-losing failure modes the architecture exists to
     * design out.
     */
    @SerialName("max_seconds") val maxSeconds: Int? = null,
    @SerialName("rate_micros_per_minute") val ratePerMinute: Long? = null,
    val prefix: String? = null,
    @SerialName("reserved_micros") val reservedMicros: Long? = null,
    /**
     * Where to send the call — a SIP URI like `sip:1.2.3.4:5060`.
     *
     * ROUTING IS DECIDED HERE, NOT IN THE SWITCH CONFIG, and that is
     * deliberate on two counts. Choosing a carrier and pricing a call are the
     * same decision: the cheapest route and the rate charged for it come from
     * one table, and splitting them across a GPL module's database and our
     * rating engine would make "which gateway, at what cost" have two answers.
     * It is also what keeps our business logic on the far side of a network
     * boundary from GPL code — see docs/ARCHITECTURE.md §3.
     *
     * Absent on a refusal. Present on every allow: a call authorized with
     * nowhere to go would be reserved against, connected to nothing, and
     * settled — so the authorizer refuses instead.
     */
    val route: String? = null,
    /** Machine-readable refusal, for the switch to map onto a SIP response. */
    val reason: String? = null,
    /**
     * The SIP response the edge should send. Chosen here rather than in
     * config: "no balance" and "no rate for that destination" are different
     * facts and a customer's softphone should not show the same message for
     * both.
     */
    @SerialName("sip_code") val sipCode: Int? = null,
)

@Serializable
data class EndSessionRequest(
    @SerialName("call_id") val callId: String,
    /** Answered-to-hangup seconds. 0 for a call that never answered. */
    @SerialName("duration_seconds") val durationSeconds: Int,
    /**
     * Bytes rtpengine actually forwarded.
     *
     * Optional but load-bearing: a call that set up and carried no audio is
     * one of the three money-losing failure modes. Signalling says the call
     * happened; only the media stats say it was worth anything.
     */
    @SerialName("media_bytes") val mediaBytes: Long? = null,
    /**
     * rtpengine's raw totals string, exactly as the switch read it.
     *
     * Parsed HERE rather than in OpenSIPS config. Picking numbers out of a
     * string in a language with no types, on the money path, is how a format
     * change in a dependency becomes a silent billing error — and the config
     * has no way to report that it failed. The raw string is also kept on the
     * CDR, so a disputed call can be re-examined against what rtpengine
     * actually said rather than against our interpretation of it.
     */
    @SerialName("media_stats") val mediaStats: String? = null,
    @SerialName("hangup_cause") val hangupCause: String? = null,
)

@Serializable
data class EndSessionResponse(
    @SerialName("call_id") val callId: String,
    @SerialName("charged_micros") val chargedMicros: Long,
    @SerialName("returned_micros") val returnedMicros: Long,
    @SerialName("balance_after_micros") val balanceAfterMicros: Long,
    @SerialName("billed_seconds") val billedSeconds: Int,
    /** True when the call outran its reservation — a sign of a broken timer. */
    val overran: Boolean = false,
    /**
     * True when the call was answered and billed but carried no media.
     *
     * Not an error, and not automatically a refund: it is a FLAG, because the
     * honest response depends on why. What it must never be is invisible —
     * billing a customer for silence is how a switch loses a customer, and
     * being unable to tell is how it loses several.
     */
    @SerialName("no_media") val noMedia: Boolean = false,
)

/** A completed call, ready for the CDR pipeline. */
@Serializable
data class Cdr(
    @SerialName("call_id") val callId: String,
    val account: String,
    val destination: String,
    val prefix: String?,
    @SerialName("duration_seconds") val durationSeconds: Int,
    /**
     * "sip" when the switch reported a duration, "server-clock" when it did
     * not and we measured it ourselves. Never absent: a bill nobody can trace
     * to a source is a bill nobody can defend.
     */
    @SerialName("duration_source") val durationSource: String,
    @SerialName("billed_seconds") val billedSeconds: Int,
    @SerialName("charged_micros") val chargedMicros: Long,
    @SerialName("rate_micros_per_minute") val ratePerMinute: Long,
    @SerialName("media_bytes") val mediaBytes: Long?,
    /** rtpengine's raw totals, kept so a disputed call can be re-examined. */
    @SerialName("media_stats") val mediaStats: String? = null,
    @SerialName("no_media") val noMedia: Boolean,
    val overran: Boolean,
    @SerialName("hangup_cause") val hangupCause: String?,
    @SerialName("ended_at") val endedAt: String,
)

@Serializable
data class Problem(
    val type: String = "about:blank",
    val title: String,
    val status: Int,
    val detail: String? = null,
)
