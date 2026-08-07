package net.megatron.switchapi

import net.megatron.authorizer.Account
import net.megatron.authorizer.Authorizer
import net.megatron.authorizer.BillingMode
import net.megatron.authorizer.Decision
import net.megatron.authorizer.Ledger
import net.megatron.authorizer.Refusal
import net.megatron.provisioning.CustomerStatus
import net.megatron.provisioning.Store
import net.megatron.rating.Micros
import net.megatron.rating.Rate
import net.megatron.rating.RateTable
import net.megatron.rating.RatingEngine
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Joins the pieces into the money path OpenSIPS actually talks to.
 *
 *   INVITE  -> authorize()   balance + rate -> allow with a session timer
 *   BYE     -> endSession()  settle, emit a CDR
 *
 * Rate tables are cached per plan and rebuilt when the plan changes, because
 * the p99 budget for authorize() is 5 ms and rebuilding a twenty-thousand-row
 * table per call would spend all of it. This is the "tariff data resident in
 * the authorizer's process" that ARCHITECTURE.md §4.4 requires.
 */
class CallService(
    private val store: Store,
    private val ledger: Ledger = Ledger(),
    private val ceilingSeconds: Int = 4 * 60 * 60,
    private val cdrSink: (Cdr) -> Unit = {},
) {

    private val authorizer = Authorizer(ledger, ceilingSeconds)

    private data class CachedTable(val version: String?, val table: RateTable)

    private val tables = ConcurrentHashMap<String, CachedTable>()

    /** What a call in progress needs remembered between INVITE and BYE. */
    private data class InFlight(
        val accountId: String,
        val accountHandle: String,
        val destination: String,
        val planId: String,
        /** When we authorized it — the fallback clock. See endSession. */
        val authorizedAtMillis: Long,
    )

    private val inFlight = ConcurrentHashMap<String, InFlight>()

    fun authorize(request: AuthorizeRequest): AuthorizeResponse {
        val customer = store.findByHandle(request.account)
            ?: return reject(Refusal.NO_SUCH_ACCOUNT, "no such account", 404)

        // Re-read the balance from the store on EVERY authorize, not once at
        // first call.
        //
        // The earlier version opened the ledger lazily and never refreshed it,
        // which meant the switch was working from whatever the balance had
        // been the first time that customer ever called. A top-up through the
        // bot did not take effect until a restart, and — the expensive
        // direction — a balance drained or corrected downward kept authorizing
        // calls against money that was gone. No unit test could see it; it
        // showed up the moment two services shared one database.
        //
        // Live reservations survive the sync, because they are calls that are
        // up right now and their money is already committed.
        ledger.syncBalance(customer.id, Micros(customer.balanceMicros))

        val account = Account(
            id = customer.id,
            balance = Micros(customer.balanceMicros),
            mode = BillingMode.PREPAID,
            maxConcurrentCalls = customer.maxConcurrentCalls,
            suspended = customer.status != CustomerStatus.ACTIVE,
        )

        val table = rateTableFor(customer.planId)
            ?: return reject(Refusal.NO_RATE_FOR_DESTINATION, "plan has no rates", 503)

        // The Call-ID is the reservation id. A retransmitted INVITE therefore
        // cannot reserve twice — SIP retransmits by design, and without this
        // a lossy network silently multiplies every customer's reservations.
        return when (val decision =
            authorizer.authorize(account, request.destination, table, request.callId)) {

            is Decision.Allow -> {
                inFlight[request.callId] = InFlight(
                    accountId = customer.id,
                    accountHandle = customer.handle,
                    destination = request.destination,
                    planId = customer.planId,
                    authorizedAtMillis = System.currentTimeMillis(),
                )
                AuthorizeResponse(
                    decision = "allow",
                    maxSeconds = decision.maxSeconds,
                    ratePerMinute = decision.ratePerMinute.value,
                    prefix = decision.prefix,
                    reservedMicros = decision.reserved.value,
                )
            }

            is Decision.Reject -> reject(decision.reason, decision.detail, sipCodeFor(decision.reason))
        }
    }

    fun endSession(request: EndSessionRequest): EndSessionResponse {
        val call = inFlight.remove(request.callId)
            ?: throw IllegalStateException("unknown call '${request.callId}'")

        val table = rateTableFor(call.planId)
            ?: throw IllegalStateException("plan '${call.planId}' lost its rates mid-call")
        val rate = table.lookup(call.destination)
            ?: throw IllegalStateException("rate vanished for '${call.destination}'")

        // BILLED DURATION MUST NOT DEPEND ON THE SIP SIDE GETTING IT RIGHT.
        //
        // On the lab box the switch reported 0 seconds for a call that plainly
        // ran for five, because the dialog had not matched and OpenSIPS had no
        // lifetime to send. A zero-second settlement releases the reservation
        // and bills nothing — every call free, silently, and the only trace is
        // a CDR full of zeroes that looks like a quiet week.
        //
        // So the switch keeps its own clock from the moment it authorized. The
        // SIP-reported duration is preferred when it is present and plausible,
        // because it is measured from ANSWER and therefore excludes ringing;
        // the fallback measures from authorization and will slightly
        // over-count. Over-counting a call nobody could otherwise bill is the
        // right way round, and `duration_source` on the CDR says which was
        // used so the difference is never invisible.
        val serverSeconds = ((System.currentTimeMillis() - call.authorizedAtMillis) / 1000)
            .coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
        val trustSip = request.durationSeconds > 0
        val billedDuration = if (trustSip) request.durationSeconds else serverSeconds
        val durationSource = if (trustSip) "sip" else "server-clock"

        val charge = RatingEngine.rate(billedDuration, rate)
        val settlement = ledger.settle(request.callId, charge.total)

        // Answered, billed, and no audio ever flowed. Flagged rather than
        // silently charged: billing for silence is how a switch loses a
        // customer, and being unable to tell is how it loses several.
        val noMedia = billedDuration > 0 &&
            request.mediaBytes != null &&
            request.mediaBytes == 0L

        // Keep the store's balance in step with the ledger, so the bot and the
        // switch agree about what a customer has left. In production the
        // ledger IS the balance; here the two are reconciled explicitly.
        store.findByHandle(call.accountHandle)?.let { customer ->
            val delta = settlement.balanceAfter.value - customer.balanceMicros
            if (delta != 0L) {
                store.adjustBalance(
                    customer.id,
                    net.megatron.provisioning.BalanceAdjustment(
                        amountMicros = delta,
                        reason = "call ${request.callId} to ${call.destination}",
                        reference = request.callId,
                    ),
                    "switch",
                )
            }
        }

        cdrSink(
            Cdr(
                callId = request.callId,
                account = call.accountHandle,
                destination = call.destination,
                prefix = rate.prefix,
                durationSeconds = billedDuration,
                durationSource = durationSource,
                billedSeconds = charge.billedSeconds,
                chargedMicros = charge.total.value,
                ratePerMinute = rate.sellPerMinute.value,
                mediaBytes = request.mediaBytes,
                noMedia = noMedia,
                overran = settlement.overran,
                hangupCause = request.hangupCause,
                endedAt = Instant.now().toString(),
            )
        )

        return EndSessionResponse(
            callId = request.callId,
            chargedMicros = settlement.charged.value,
            returnedMicros = settlement.returned.value,
            balanceAfterMicros = settlement.balanceAfter.value,
            billedSeconds = charge.billedSeconds,
            overran = settlement.overran,
            noMedia = noMedia,
        )
    }

    /** The call never answered. Release the hold, charge nothing, no CDR. */
    fun abandon(callId: String): Boolean {
        inFlight.remove(callId)
        return ledger.release(callId)
    }

    fun activeCalls(): Int = inFlight.size

    private fun rateTableFor(planId: String): RateTable? {
        val plan = store.listPlans().firstOrNull { it.id == planId } ?: return null
        val cached = tables[planId]
        if (cached != null && cached.version == plan.updatedAt) return cached.table

        val rows = store.ratesFor(planId)
        if (rows.isEmpty()) return null
        val table = RateTable.of(
            rows.map {
                Rate(
                    prefix = it.prefix,
                    sellPerMinute = Micros(it.sellMicrosPerMinute),
                    buyPerMinute = it.buyMicrosPerMinute?.let(::Micros),
                    connectFee = Micros(it.connectFeeMicros),
                    incrementSeconds = it.incrementSeconds,
                    minimumSeconds = it.minimumSeconds,
                    description = it.description.orEmpty(),
                )
            },
            plan.currency,
        )
        tables[planId] = CachedTable(plan.updatedAt, table)
        return table
    }

    private fun reject(reason: Refusal, detail: String, sipCode: Int) =
        AuthorizeResponse(
            decision = "reject",
            reason = reason.name.lowercase(),
            sipCode = sipCode,
        ).also { if (detail.isNotEmpty()) Unit }

    /**
     * SIP response per refusal, decided here rather than in OpenSIPS config.
     *
     * "You have no balance" and "we do not carry that destination" are
     * different facts, and a customer's softphone should not show the same
     * message for both — the first is fixed by topping up and the second
     * never will be.
     */
    private fun sipCodeFor(reason: Refusal): Int = when (reason) {
        Refusal.INSUFFICIENT_BALANCE -> 402   // Payment Required
        Refusal.NO_SUCH_ACCOUNT -> 404        // Not Found -- no such account
        Refusal.ACCOUNT_SUSPENDED -> 403      // Forbidden
        Refusal.NO_RATE_FOR_DESTINATION -> 404 // Not Found
        Refusal.CONCURRENT_CALL_LIMIT -> 486  // Busy Here
        Refusal.INVALID_DESTINATION -> 484    // Address Incomplete
    }
}
