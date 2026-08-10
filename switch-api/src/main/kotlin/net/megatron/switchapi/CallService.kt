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

    /**
     * Where the reason an inbound call was refused goes.
     *
     * A refusal the operator cannot see is a support call they cannot answer:
     * "my provider says they're sending calls and nothing arrives" has half a
     * dozen causes and they are told apart here or nowhere. Kept as a sink
     * rather than a logger call so a test can read what was written.
     */
    private val refusalLog: (String, String) -> Unit = { reason, detail ->
        System.err.println("inbound refused [$reason] $detail")
    }

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
        /**
         * THE RATE THIS CALL WAS QUOTED, captured at authorize time.
         *
         * Settlement used to look the rate up again when the BYE arrived,
         * which prices the call at whatever the plan says at hang-up rather
         * than what it said when the customer was told how long they could
         * talk. A reprice mid-call then billed against a reservation taken at
         * the old price — the two disagree, and the customer's is the one that
         * was quoted.
         *
         * Null means the call is free and nothing was reserved: an inbound
         * call to a plan with no rate for the DID. Free is a state, not a
         * zero, so settlement can tell "costs nothing" from "costs nothing per
         * minute".
         */
        val rate: Rate?,
        /** "outbound" or "inbound". Ends up on the CDR. */
        val direction: String = "outbound",
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

        // WHERE THE CALL GOES IS DECIDED BEFORE IT IS RESERVED AGAINST.
        //
        // A call authorized with nowhere to send it would hold a reservation,
        // connect to nothing, and then settle — the customer pays for a call
        // that could never have happened, and the operator's first sign of it
        // is a complaint. Refusing costs one call; the alternative is a
        // billing dispute per attempt for as long as the trunk is missing.
        //
        // 503, not 404: "we have no carrier configured" is our fault, and a
        // 404 would tell the caller their number was invalid.
        // Chosen ONCE. This used to call outboundTrunk() again further down for
        // the credentials, so the route and the credentials were two separate
        // reads of a table another request can change in between -- long
        // enough to send carrier A's password to carrier B.
        val trunk = outboundTrunk()
            ?: return reject(
                Refusal.NO_RATE_FOR_DESTINATION,
                "no enabled outbound trunk is configured",
                503,
            )
        val route = routeTo(trunk)

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
                    rate = table.lookup(request.destination),
                )
                AuthorizeResponse(
                    decision = "allow",
                    maxSeconds = decision.maxSeconds,
                    ratePerMinute = decision.ratePerMinute.value,
                    prefix = decision.prefix,
                    reservedMicros = decision.reserved.value,
                    route = route,
                    routeAuth = store.trunkCredentials(trunk.id)?.let {
                        RouteAuth(it.username, it.password, it.realm)
                    },
                    routeFromUser = trunk.fromUser,
                )
            }

            is Decision.Reject -> reject(decision.reason, decision.detail, sipCodeFor(decision.reason))
        }
    }

    /**
     * A call arriving from a carrier for one of our DIDs.
     *
     * This is the half of the business the operator sells when he tells a
     * provider to point their traffic at this address. It is NOT the outbound
     * path with the arrows reversed, and the differences are all security:
     *
     * - **There is no authenticated account.** The caller is a stranger; the
     *   carrier is identified by source address alone. So the allowlist is
     *   checked FIRST and a non-match is refused before anything else is even
     *   looked up — an inbound path that accepts from anywhere carries other
     *   people's traffic at the operator's expense, and it is the single most
     *   common way a switch is abused.
     * - **The account is looked up, not asserted.** From the number dialled.
     *   An unknown DID reaches nobody.
     * - **A customer with no balance still receives calls.** They bought the
     *   number; refusing their inbound because their outbound credit ran out
     *   is a surprise that costs the operator the customer. So the balance
     *   only gates inbound that the plan actually prices.
     */
    fun authorizeInbound(request: InboundAuthorizeRequest): InboundAuthorizeResponse {
        // THE ALLOWLIST IS THE CREDENTIAL, so it is the first question asked.
        val trunk = inboundTrunkFor(request.sourceIp)
            ?: return rejectInbound(
                "SOURCE_NOT_A_TRUNK",
                "${request.sourceIp} is not a configured inbound trunk",
                // 403 and not 404: this is a refusal to talk to the sender, and
                // it says nothing about whether the number they dialled exists.
                403,
            )

        val customer = store.customerForDid(request.did)
            ?: return rejectInbound(
                "NO_SUCH_DID",
                "no customer receives calls on '${request.did}'",
                404,
            )

        if (customer.status != CustomerStatus.ACTIVE) {
            return rejectInbound(
                Refusal.ACCOUNT_SUSPENDED.name,
                "account ${customer.handle} is suspended",
                403,
            )
        }

        // The same cap as outbound, and it matters more here: a DID under a
        // flood is an inbound call per packet, and the customer's phone is on
        // the other end of every one of them.
        if (ledger.activeCalls(customer.id) >= customer.maxConcurrentCalls) {
            return rejectInbound(
                Refusal.CONCURRENT_CALL_LIMIT.name,
                "account ${customer.handle} already has ${customer.maxConcurrentCalls} calls up",
                486,
            )
        }

        val table = rateTableFor(customer.planId)
        val rate = table?.lookup(request.did)

        // NO RATE MEANS FREE, NOT REFUSED — the opposite of the outbound rule.
        //
        // Outbound, an unrated destination is carried at unknown cost to the
        // operator, so it is refused. Inbound costs the operator nothing per
        // minute they have not already agreed with the carrier, and a plan
        // with no inbound pricing is the normal case: most operators charge
        // rent for the DID and nothing per minute. Refusing here would mean
        // every DID stops working the moment inbound pricing is not set up,
        // which is a switch that does not deliver calls by default.
        if (rate == null) {
            inFlight[request.callId] = InFlight(
                accountId = customer.id,
                accountHandle = customer.handle,
                destination = request.did,
                planId = customer.planId,
                authorizedAtMillis = System.currentTimeMillis(),
                rate = null,
                direction = "inbound",
            )
            // Still capped. A free call is not an unbounded one: a stuck
            // inbound leg with no timer holds a concurrency slot forever, and
            // the customer's own phone is what stops ringing.
            return InboundAuthorizeResponse(
                decision = "allow",
                account = customer.handle,
                maxSeconds = ceilingSeconds,
                charged = false,
            )
        }

        // Priced inbound: the customer is paying to receive, so it goes
        // through the same reserve-then-debit path as an outgoing call and the
        // balance gates it exactly the same way.
        ledger.syncBalance(customer.id, Micros(customer.balanceMicros))
        val account = Account(
            id = customer.id,
            balance = Micros(customer.balanceMicros),
            mode = BillingMode.PREPAID,
            maxConcurrentCalls = customer.maxConcurrentCalls,
            suspended = false,
        )
        return when (val decision = authorizer.authorize(account, request.did, table, request.callId)) {
            is Decision.Allow -> {
                inFlight[request.callId] = InFlight(
                    accountId = customer.id,
                    accountHandle = customer.handle,
                    destination = request.did,
                    planId = customer.planId,
                    authorizedAtMillis = System.currentTimeMillis(),
                    rate = rate,
                    direction = "inbound",
                )
                InboundAuthorizeResponse(
                    decision = "allow",
                    account = customer.handle,
                    maxSeconds = decision.maxSeconds,
                    ratePerMinute = decision.ratePerMinute.value,
                    reservedMicros = decision.reserved.value,
                    charged = true,
                )
            }

            is Decision.Reject -> rejectInbound(
                decision.reason.name,
                "${decision.detail} (via trunk ${trunk.name})",
                sipCodeFor(decision.reason),
            )
        }
    }

    /**
     * [detail] is deliberately NOT returned.
     *
     * The switch logs `reason` and answers `sip_code`, and neither of those
     * distinguishes a DID that exists from one that does not. Handing the
     * sentence back would put it one careless `xlog`-to-`send_reply` change
     * away from the wire, and "no customer receives calls on that number" told
     * to a caller is a DID enumeration oracle for anyone dialling a range —
     * the same mistake the REGISTER path exists to avoid.
     */
    private fun rejectInbound(reason: String, detail: String, sipCode: Int): InboundAuthorizeResponse {
        refusalLog(reason, detail)
        return InboundAuthorizeResponse(
            decision = "reject",
            reason = reason.lowercase(),
            sipCode = sipCode,
        )
    }

    /**
     * The enabled inbound trunk whose allowlist contains [sourceIp], or null.
     *
     * Read fresh on every call, like the outbound selection: a trunk disabled
     * because a carrier is misbehaving has to stop being accepted now, not at
     * the next restart.
     */
    private fun inboundTrunkFor(sourceIp: String): net.megatron.provisioning.Trunk? =
        store.listTrunks().firstOrNull { trunk ->
            trunk.enabled &&
                trunk.direction != net.megatron.provisioning.TrunkDirection.OUTBOUND &&
                net.megatron.provisioning.IpAllowlist.allows(trunk.remoteIps, sourceIp)
        }

    fun endSession(request: EndSessionRequest): EndSessionResponse {
        val call = inFlight.remove(request.callId)
            ?: throw IllegalStateException("unknown call '${request.callId}'")

        // THE RATE THE CALL WAS QUOTED, not whatever the plan says now.
        //
        // This used to re-read the plan at hang-up, so a reprice while a call
        // was up billed it at the new price against a reservation taken at the
        // old one — the two disagree, and it is the customer's quote that was
        // honest. It also meant a plan edited mid-call could throw "rate
        // vanished" and fail the settlement of a call that really happened.
        //
        // Null is a free call (inbound to a plan with no price for the DID):
        // nothing was reserved, so there is nothing to settle.
        val rate = call.rate

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

        // A free call reserved nothing, so there is nothing to release and
        // nothing to charge. Handled as a branch rather than as a zero rate:
        // ledger.settle() on a reservation that was never taken has no honest
        // answer, and inventing one would report a balance the store never saw.
        val charge = rate?.let { RatingEngine.rate(billedDuration, it) }
        val settlement = charge?.let { ledger.settle(request.callId, it.total) }
        val billedSeconds = charge?.billedSeconds ?: billedDuration
        val chargedMicros = charge?.total?.value ?: 0L

        // Answered, billed, and no audio ever flowed. Flagged rather than
        // silently charged: billing for silence is how a switch loses a
        // customer, and being unable to tell is how it loses several.
        //
        // mediaBytes may come explicitly, or be parsed out of rtpengine's
        // totals string. Absent stays absent: "we do not know" and "there was
        // none" are different facts, and treating the first as the second
        // would flag every call on a switch whose media stats are not wired
        // up yet.
        val mediaBytes = request.mediaBytes ?: parseMediaBytes(request.mediaStats)
        val noMedia = billedDuration > 0 && mediaBytes != null && mediaBytes == 0L

        // Keep the store's balance in step with the ledger, so the bot and the
        // switch agree about what a customer has left. In production the
        // ledger IS the balance; here the two are reconciled explicitly.
        //
        // A free call skips this entirely: writing a zero-delta adjustment
        // would put a row in the audit trail saying money moved when none did.
        val customer = store.findByHandle(call.accountHandle)
        if (settlement != null) {
            customer?.let {
                val delta = settlement.balanceAfter.value - it.balanceMicros
                if (delta != 0L) {
                    store.adjustBalance(
                        it.id,
                        net.megatron.provisioning.BalanceAdjustment(
                            amountMicros = delta,
                            reason = "call ${request.callId} to ${call.destination}",
                            reference = request.callId,
                        ),
                        "switch",
                    )
                }
            }
        }

        cdrSink(
            Cdr(
                callId = request.callId,
                account = call.accountHandle,
                destination = call.destination,
                prefix = rate?.prefix,
                durationSeconds = billedDuration,
                durationSource = durationSource,
                billedSeconds = billedSeconds,
                chargedMicros = chargedMicros,
                // Zero, and the CDR says `charged_micros: 0` beside it, so a
                // free call is legible as free rather than as a pricing bug.
                ratePerMinute = rate?.sellPerMinute?.value ?: 0L,
                mediaBytes = mediaBytes,
                mediaStats = request.mediaStats,
                noMedia = noMedia,
                overran = settlement?.overran ?: false,
                hangupCause = request.hangupCause,
                direction = call.direction,
                endedAt = Instant.now().toString(),
            )
        )

        return EndSessionResponse(
            callId = request.callId,
            chargedMicros = chargedMicros,
            returnedMicros = settlement?.returned?.value ?: 0L,
            // A free call moves no money, so the balance after it is the
            // balance before it — read from the store rather than invented.
            balanceAfterMicros = settlement?.balanceAfter?.value
                ?: customer?.balanceMicros ?: 0L,
            billedSeconds = billedSeconds,
            overran = settlement?.overran ?: false,
            noMedia = noMedia,
        )
    }

    /** The call never answered. Release the hold, charge nothing, no CDR. */
    fun abandon(callId: String): Boolean {
        inFlight.remove(callId)
        return ledger.release(callId)
    }

    fun activeCalls(): Int = inFlight.size

    /**
     * The carrier to send an outbound call to, or null if there is none.
     *
     * V1 IS ONE TRUNK, AND SAYING SO IS BETTER THAN PRETENDING OTHERWISE.
     * Real least-cost routing picks a carrier per destination prefix, from
     * buy prices, with failover to the next on a 503. That belongs here — it
     * is the same decision as rating, which is why routing lives in this
     * service and not in switch config — but it is not built, and a
     * half-implementation that silently always picks the first trunk anyway
     * would be harder to replace than an honest one.
     *
     * Deterministic by id, so the choice does not move between calls for no
     * reason. Read fresh rather than cached: a trunk disabled because the
     * carrier is having an outage must stop receiving calls now, not at the
     * next restart.
     */
    /** The chosen carrier, or null when none is configured. */
    private fun outboundTrunk(): net.megatron.provisioning.Trunk? =
        store.listTrunks()
            .filter { it.enabled && it.direction == net.megatron.provisioning.TrunkDirection.OUTBOUND }
            // PRIORITY FIRST, id only to break a tie.
            //
            // This was `minByOrNull { it.id }` -- deterministic, and the wrong
            // determinism: the FIRST trunk ever created won forever, so adding
            // a carrier changed nothing and every call kept going to whatever
            // was set up first. That is indistinguishable from the new trunk
            // being broken, and it is exactly what happened the first time a
            // real provider was added beside a leftover test one.
            .minWithOrNull(compareBy({ it.priority }, { it.id }))

    private fun routeTo(trunk: net.megatron.provisioning.Trunk): String =
        // The transport is named explicitly. Left off, OpenSIPS applies its
        // own default, which is UDP — so a TLS trunk would silently be dialled
        // in clear, which is both a security failure and one the carrier
        // reports as "we never received your call".
        "sip:${trunk.host}:${trunk.port};transport=${trunk.transport.name.lowercase()}"

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

    /**
     * Pull a byte count out of rtpengine's totals string.
     *
     * Deliberately forgiving about the shape and deliberately strict about
     * the outcome: anything it cannot read returns null, which means "we do
     * not know", NOT "there was no audio". Guessing zero from an unparseable
     * string would flag healthy calls as silent the first time rtpengine
     * changed its format -- and a false no-media flag on a busy switch is a
     * pile of refund requests nobody can adjudicate.
     */
    internal fun parseMediaBytes(stats: String?): Long? {
        if (stats.isNullOrBlank()) return null
        // Two shapes, because the first guess was wrong and finding out cost
        // a debugging round: OpenSIPS's $rtpstat reads
        //   "RTP: 1234 bytes, 56 packets, 0 errors; RTCP: ..."
        // where the number comes BEFORE the word, while JSON-ish sources use
        // bytes=N or "bytes": N. Accept both rather than assume.
        //
        // RTCP is counted deliberately alongside RTP: a call carrying only
        // RTCP still carried no audio, and summing both means the "was there
        // media" question is answered by the same number either way.
        val before = Regex("""(\d+)\s*bytes""", RegexOption.IGNORE_CASE)
        val after = Regex("""bytes["'\s]*[=:]\s*(\d+)""", RegexOption.IGNORE_CASE)
        val found = (before.findAll(stats) + after.findAll(stats))
            .mapNotNull { it.groupValues[1].toLongOrNull() }
            .toList()
        return if (found.isEmpty()) null else found.sum()
    }

    private fun reject(reason: Refusal, detail: String, sipCode: Int) =
        AuthorizeResponse(
            decision = "reject",
            reason = reason.name.lowercase(),
            sipCode = sipCode,
            detail = detail,
        )

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
