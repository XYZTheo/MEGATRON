package net.megatron.provisioning

import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Raised when a caller reuses an Idempotency-Key with a different body.
 *
 * Refused rather than guessed. The two plausible guesses are "apply it again"
 * and "ignore it", and both are wrong when real money is involved.
 */
class IdempotencyConflict(val key: String) : RuntimeException(
    "Idempotency-Key '$key' was already used for a different request"
)

class NotFound(val what: String) : RuntimeException("$what not found")
class Conflict(message: String) : RuntimeException(message)
class Invalid(message: String) : RuntimeException(message)

/**
 * Everything the provisioning API persists.
 *
 * An interface with an in-memory implementation, so the service runs and is
 * testable end to end on a machine with no PostgreSQL — which is the machine
 * it is being written on. Swapping in the real store when the VPS exists is
 * one implementation of this, not a rewrite of the service.
 */
interface Store {
    fun createCustomer(request: CreateCustomer, actor: String): Pair<Customer, SipCredentials>
    fun getCustomer(id: String): Customer
    fun findByHandle(handle: String): Customer?
    fun findByTelegramUserId(telegramUserId: Long): Customer?
    fun listCustomers(status: CustomerStatus?, limit: Int, cursor: String?): CustomerPage
    fun setStatus(id: String, request: SetStatus, actor: String): Customer
    fun rotateCredentials(id: String): SipCredentials
    fun adjustBalance(id: String, request: BalanceAdjustment, actor: String): Transaction
    fun setCallerId(id: String, number: String, actor: String): CallerId
    fun createPlan(request: CreatePlan): Plan
    fun listPlans(): List<Plan>
    fun replaceRates(planId: String, request: ReplaceRates): RatesReplaced

    /**
     * The rate table for a plan.
     *
     * On the interface rather than only on the implementations because the
     * switch API reads it on the call path — it is not an administrative
     * query, it is how a call gets priced.
     */
    fun ratesFor(planId: String): List<RateRow>
    fun createTrunk(request: CreateTrunk): Trunk
    fun listTrunks(): List<Trunk>

    /**
     * The SIP digest credential for a handle, or null if there is no such
     * account.
     *
     * HA1 = MD5(username:realm:password). Every softphone in the target set
     * authenticates with MD5 digest, and a server cannot verify a digest
     * response without either the plaintext password or this.
     *
     * IT IS PASSWORD-EQUIVALENT. Anyone holding it can register and place
     * calls as that customer, at the operator's expense. It must never appear
     * in a response any customer can reach, never cross a public interface,
     * and never be logged. It exists on the Store interface rather than being
     * fetched through the normal customer read specifically so that it cannot
     * be returned by accident as part of a Customer object.
     */
    fun sipDigestHa1(handle: String, realm: String): String?

    /**
     * Claims [key] for a one-time operation. True the first time, false ever
     * after.
     *
     * FOR CALLERS THAT REACH THE STORE DIRECTLY, which the Telegram bot does.
     * The HTTP API gets replay protection from its Idempotency-Key middleware;
     * the bot does not go through HTTP, so before this existed its idempotency
     * key was written into an audit field and never checked. Telegram
     * redelivers any update the bot has not acknowledged, so a restart between
     * handling a `/credit` and the next poll credited the account twice.
     *
     * It must be DURABLE to be worth anything — the restart is the scenario —
     * which is why it is on the Store and not a map in the bot.
     *
     * It must also be ATOMIC: two threads claiming the same key must see one
     * true and one false, or concurrent retries defeat it entirely.
     */
    fun claimOnce(key: String): Boolean

    /**
     * Gives [key] back, so the operation it guarded can be attempted again.
     *
     * NEEDED BECAUSE A CLAIM AND ITS MUTATION ARE NOT ONE TRANSACTION. The
     * claim commits on its own, so if the mutation then fails — a full disk, a
     * lock timeout, a bug — the claim outlives the attempt that changed
     * nothing. On the redelivery that claimOnce exists to handle, the caller
     * is told "already done" and the operation is lost PERMANENTLY, with a
     * reply saying it succeeded. That is worse than the double-credit the
     * claim prevents.
     *
     * Releasing on failure is not perfect: a process that dies between the
     * mutation failing and this call leaves the key claimed. That window is
     * microseconds against a scenario measured in seconds, and the failure it
     * leaves behind is the old one rather than a new one.
     */
    fun releaseClaim(key: String)

    /**
     * Records a completed call.
     *
     * IDEMPOTENT ON call_id, because the switch will send the same settlement
     * twice: SIP retransmits by design, and a BYE that is answered slowly is a
     * BYE that arrives again. A second row for one call would double the
     * apparent spend on every report while the balance — which is guarded
     * separately — showed the truth, and the two disagreeing is worse than
     * either being wrong.
     *
     * Never throws for a duplicate. The caller is the money path and must not
     * fail a settlement because the history already has the row.
     */
    fun recordCall(record: CallRecord)

    /**
     * A customer's calls, most recent first.
     *
     * This is what a disputed bill is argued from, so it is a read the
     * operator and the customer see the same answer to.
     */
    fun callsFor(account: String, limit: Int = 20): List<CallRecord>

    /** Every customer's recent calls, most recent first. */
    fun recentCalls(limit: Int = 20): List<CallRecord>

    /**
     * Calls that connected and carried no audio.
     *
     * A REFUND QUEUE, not a curiosity. Each one is a charge a customer may
     * reasonably challenge, and an operator who cannot list them learns about
     * them from complaints instead.
     */
    fun noMediaCalls(limit: Int = 20): List<CallRecord>

    /**
     * Moves a customer onto a different plan.
     *
     * In MEGATRON a plan IS the rate table, so this is what VOIPX calls both
     * `setPlan` and `setTariff` — VOS3000 splits a recurring package from a
     * fee-rate group and MEGATRON does not. See docs/VOIPX-INTEGRATION.md.
     *
     * Takes effect on the NEXT call, not on one in progress: a call was
     * authorized at a price and gets settled at that price, or a customer's
     * bill changes underneath a conversation they are already having.
     */
    fun setPlan(id: String, planId: String, actor: String): Customer

    /**
     * Stops presenting a caller ID.
     *
     * Distinct from setting a different one. A customer whose number is
     * withdrawn — because it was never theirs, or the attestation lapsed —
     * must fall back to the operator's default, not keep presenting the last
     * number they were allowed.
     */
    fun clearCallerId(id: String, actor: String): Customer

    /**
     * Does this password authenticate this handle?
     *
     * Answers VOIPX's `verifyCredentials` without either service holding a
     * plaintext password: the candidate is converted to HA1 and compared
     * against the stored one.
     *
     * Null for "no such account", false for "wrong password" — the caller may
     * need to tell those apart internally even though what it says OUT LOUD
     * must not distinguish them. That is the enumeration oracle the switch
     * config spends forty lines avoiding.
     */
    fun verifyPassword(handle: String, password: String): Boolean?

    /**
     * Creates a customer with a credential MEGATRON did not generate.
     *
     * THE ONE PLACE THE PASSWORD RULE BENDS, AND IT BENDS FOR A SPECIFIC
     * REASON. Everywhere else a password is generated, returned once and
     * never accepted, because a provisioning API that takes passwords is one
     * that has them to leak. Here the caller supplies one — and the only
     * justification is the takeover: importing an operator's existing
     * customers from Magnus or VOS3000 must not require every one of them to
     * reconfigure a softphone. A migration that breaks every customer is not
     * a migration anyone performs.
     *
     * The plaintext is converted to HA1 and the SHA-256 hash immediately and
     * is not stored. It is a separate method rather than an optional argument
     * on [createCustomer] so that supplying a password is a deliberate,
     * greppable act rather than a parameter somebody sets by accident.
     */
    fun importCustomer(request: CreateCustomer, password: String, actor: String): Customer

    // -- DIDs: the numbers customers receive calls on -------------------------

    /**
     * Gives a number to a customer.
     *
     * Refuses if it already belongs to someone. Reassigning silently would
     * move a working number between customers with no record of it, and the
     * first anyone knows is the previous owner's calls arriving somewhere
     * else.
     */
    fun assignDid(request: AssignDid, actor: String): Did

    /** Takes a number back. */
    fun releaseDid(number: String, actor: String)

    /** Every number, or one customer's. */
    fun listDids(customerId: String? = null): List<Did>

    /**
     * Who should receive a call to this number?
     *
     * THE INBOUND CALL PATH, so it is the one lookup that runs with a caller
     * waiting. Returns null for a number nobody owns AND for a parked one —
     * the switch rejects both, and the difference matters to an operator
     * reading a log, not to the call.
     */
    fun customerForDid(number: String): Customer?
}

/**
 * Replay protection for mutating requests.
 *
 * A Telegram bot runs on a phone network. It WILL time out after the server
 * has already committed, and it WILL retry. Without this, that is a double
 * credit — every time — and the operator finds out from the balance sheet.
 */
class IdempotencyStore(
    /**
     * How long a key is remembered.
     *
     * A retry arrives seconds after the original, not days. Remembering
     * forever bought nothing and cost unbounded memory — see [remember].
     */
    private val retainMillis: Long = 24 * 60 * 60 * 1000L,
    private val maxEntries: Int = 100_000,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private data class Entry(val bodyHash: Int, val response: String, val storedAt: Long)

    private val entries = ConcurrentHashMap<String, Entry>()

    /**
     * Returns the stored response for a repeat of the same request, or null
     * for a first attempt.
     *
     * @throws IdempotencyConflict when the key is reused with a different body.
     */
    fun replay(key: String, bodyHash: Int): String? {
        val existing = entries[key] ?: return null
        if (existing.bodyHash != bodyHash) throw IdempotencyConflict(key)
        return existing.response
    }

    fun remember(key: String, bodyHash: Int, response: String) {
        entries[key] = Entry(bodyHash, response, now())

        // BOUNDED, BECAUSE IT HOLDS FULL RESPONSE BODIES.
        //
        // This was a ConcurrentHashMap with no eviction at all: one entry per
        // mutating request ever made, each carrying the entire response, for
        // the life of the process. On a service that is meant to run for
        // months that is a memory leak with a customer record in every slot.
        //
        // SIZE IS THE TRIGGER; AGE IS THE FIRST THING TRIED ONCE IT FIRES.
        //
        // Said the other way round in an earlier comment, which described a
        // sweep that ran on age regardless — it does not, and nothing here is
        // evicted until the map is over its cap. That is the right shape (a
        // walk of every entry on every request would be absurd for a map this
        // is usually tiny) but the description has to match, because the next
        // person to reason about memory will reason from the comment.
        if (entries.size > maxEntries) {
            val cutoff = now() - retainMillis
            entries.entries.removeAll { it.value.storedAt < cutoff }
            // Still over after the sweep means the traffic is genuinely recent
            // — drop the oldest rather than let the map grow without limit.
            // Losing replay protection on the oldest keys is the right thing
            // to give up: those requests completed long ago.
            if (entries.size > maxEntries) {
                entries.entries
                    .sortedBy { it.value.storedAt }
                    .take(entries.size - maxEntries)
                    .forEach { entries.remove(it.key) }
            }
        }
    }

    val size: Int get() = entries.size
}

/**
 * One representation of a phone number, so an inbound lookup is an exact match
 * rather than a set of guesses.
 *
 * CARRIERS ARE NOT CONSISTENT. The same DID arrives as `+441632960123`,
 * `441632960123`, `00441632960123` or with spaces, sometimes from the same
 * carrier on different routes. Storing whatever arrived and comparing strings
 * means a number that works on one trunk and silently does not on another —
 * an inbound call rejected for a customer who is definitely paying for that
 * number.
 *
 * So everything is reduced to bare digits with the international prefix
 * stripped: `+` and `00` both mean "what follows is international".
 *
 * Deliberately NOT a full E.164 library. Interpreting national dialling
 * without knowing the country is guesswork, and guessing wrong here delivers
 * somebody else's calls. What is not recognised is stored as it arrived and
 * simply will not match — a number that never rings is a support ticket; a
 * number that rings the wrong customer is a breach.
 */
internal fun normaliseDid(raw: String): String {
    val digitsAndPlus = raw.trim().filter { it.isDigit() || it == '+' }
    val withoutPlus = digitsAndPlus.removePrefix("+")
    return if (withoutPlus.startsWith("00")) withoutPlus.removePrefix("00") else withoutPlus
}

/**
 * In-memory reference implementation.
 *
 * Correct, concurrent, and not durable. It exists so the API can be exercised
 * as an API today; nothing here is a claim about production storage.
 */
class InMemoryStore(
    private val sipDomain: String = "sip.megatron.local",
    private val defaultTransport: Transport = Transport.UDP,
) : Store {

    private val customers = ConcurrentHashMap<String, Customer>()
    // NO MAP OF PLAINTEXT PASSWORDS. There used to be one — `passwords`,
    // written at creation and at rotation and READ NOWHERE. An unbounded,
    // live, plaintext copy of every SIP password ever issued, sitting in any
    // heap dump or core file, for no purpose at all.
    //
    // SqlStore has never had an equivalent, and says so: "not recoverable
    // afterwards by anybody — including us". The two stores disagreed about
    // the single most sensitive value in the system, and the doc a few lines
    // below claimed a second copy of the plaintext "does not exist" while it
    // was declared directly above the sentence.
    //
    // A password is generated, returned once, and reduced to HA1. Nothing
    // else keeps it.
    /**
     * handle -> HA1, computed once at creation for THIS store's realm.
     *
     * Deliberately not "handle -> plaintext, hash on demand". Deriving HA1
     * from a realm the caller supplies turns this method into an oracle that
     * mints a working SIP credential for any realm somebody names — the
     * caller does not need to know the password to get a usable one. Baking
     * the realm in at creation is what makes [sipDigestHa1] a lookup rather
     * than a computation, and it is also the second copy of the plaintext
     * password that then does not exist.
     */
    private val ha1ByHandle = ConcurrentHashMap<String, String>()

    /**
     * handle -> customer id, the uniqueness constraint this store lacked.
     *
     * Exists so a handle can be CLAIMED atomically at creation. SqlStore gets
     * the same guarantee from a UNIQUE column; without this the two stores
     * disagreed about whether two customers could share a handle, which is
     * exactly the divergence StoreContractTest exists to prevent.
     */
    private val handles = ConcurrentHashMap<String, String>()
    private val plans = ConcurrentHashMap<String, Plan>()
    private val rates = ConcurrentHashMap<String, List<RateRow>>()
    private val trunks = ConcurrentHashMap<String, Trunk>()
    private val ids = AtomicLong(1)

    /**
     * The audit trail. Append-only by construction: there is no method here
     * that edits or removes a transaction, deliberately. MagnusBilling's is
     * editable by an admin, which makes it evidence of nothing.
     */
    private val transactions = java.util.concurrent.CopyOnWriteArrayList<Transaction>()

    fun transactionsFor(customerId: String): List<Transaction> =
        transactions.filter { it.customerId == customerId }

    private val random = SecureRandom()

    private fun nextId(prefix: String) = "$prefix-${ids.getAndIncrement()}"
    private fun now() = Instant.now().toString()

    /**
     * A generated SIP password.
     *
     * SecureRandom, not Random: this is a credential. The alphabet excludes
     * characters that get mangled when a customer copies a password out of a
     * chat message into a softphone field — the failure mode there is a
     * support call that looks like a platform fault.
     */
    private fun generatePassword(): String {
        val alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return (1..24).map { alphabet[random.nextInt(alphabet.length)] }.joinToString("")
    }

    override fun createCustomer(
        request: CreateCustomer,
        actor: String,
    ): Pair<Customer, SipCredentials> {
        if (!HANDLE.matches(request.handle)) {
            throw Invalid(
                "handle '${request.handle}' must be 3-32 characters of a-z, 0-9, dot, " +
                    "underscore or hyphen, starting with a letter or digit"
            )
        }
        if (request.maxConcurrentCalls < 1) {
            throw Invalid("max_concurrent_calls must be at least 1")
        }
        if (request.openingBalanceMicros < 0) {
            throw Invalid("opening_balance_micros must not be negative")
        }
        val plan = plans[request.planId] ?: throw NotFound("plan '${request.planId}'")

        val id = nextId("cust")
        // CLAIM THE HANDLE ATOMICALLY, rather than checking and then inserting.
        //
        // A check-then-act on a shared map is not a check at all under
        // concurrency: two creations of the same handle both saw "not taken"
        // and both inserted, producing TWO customers with one handle — and
        // since the exporter renders one row per handle, one of them received
        // a password that could never work. SqlStore has a UNIQUE constraint;
        // this store had nothing, so the two implementations disagreed about
        // whether a duplicate was possible.
        if (handles.putIfAbsent(request.handle, id) != null) {
            throw Conflict("a customer with handle '${request.handle}' already exists")
        }
        val password = generatePassword()
        val customer = Customer(
            id = id,
            handle = request.handle,
            displayName = request.displayName,
            status = CustomerStatus.ACTIVE,
            planId = plan.id,
            balanceMicros = request.openingBalanceMicros,
            currency = plan.currency,
            maxConcurrentCalls = request.maxConcurrentCalls,
            telegramUserId = request.telegramUserId,
            createdAt = now(),
        )
        customers[id] = customer
        ha1ByHandle[request.handle] = ha1(request.handle, sipDomain, password)

        if (request.openingBalanceMicros > 0) {
            transactions += Transaction(
                id = nextId("txn"),
                customerId = id,
                amountMicros = request.openingBalanceMicros,
                balanceAfterMicros = request.openingBalanceMicros,
                reason = "opening balance",
                createdAt = now(),
                actor = actor,
            )
        }

        return customer to SipCredentials(
            sipUsername = customer.handle,
            sipPassword = password,
            sipDomain = sipDomain,
            transportHint = defaultTransport,
        )
    }

    override fun getCustomer(id: String): Customer =
        customers[id] ?: throw NotFound("customer '$id'")

    override fun findByHandle(handle: String): Customer? =
        customers.values.firstOrNull { it.handle == handle }

    override fun findByTelegramUserId(telegramUserId: Long): Customer? =
        customers.values.firstOrNull { it.telegramUserId == telegramUserId }

    override fun listCustomers(
        status: CustomerStatus?,
        limit: Int,
        cursor: String?,
    ): CustomerPage {
        val all = customers.values
            .filter { status == null || it.status == status }
            .sortedBy { it.id }
        val start = if (cursor == null) 0 else all.indexOfFirst { it.id > cursor }.let {
            if (it < 0) all.size else it
        }
        val page = all.drop(start).take(limit)
        val next = if (start + page.size < all.size) page.lastOrNull()?.id else null
        return CustomerPage(page, next)
    }

    override fun setStatus(id: String, request: SetStatus, actor: String): Customer {
        if (request.reason.length < 3) {
            throw Invalid(
                "a reason is required: a suspension nobody can explain later is one " +
                    "that gets reversed by the next person on shift"
            )
        }
        val updated = getCustomer(id).copy(status = request.status)
        customers[id] = updated
        return updated
    }

    override fun rotateCredentials(id: String): SipCredentials {
        val customer = getCustomer(id)
        val password = generatePassword()
        // Rotates with the password. A stale HA1 means the old password still
        // registers, which is a rotation that rotates nothing.
        ha1ByHandle[customer.handle] = ha1(customer.handle, sipDomain, password)
        return SipCredentials(customer.handle, password, sipDomain, defaultTransport)
    }

    override fun adjustBalance(
        id: String,
        request: BalanceAdjustment,
        actor: String,
    ): Transaction {
        if (request.reason.length < 3) {
            throw Invalid(
                "a reason is required, including on credits: 'who changed this and why' " +
                    "is the first question asked about any balance"
            )
        }
        // Compare-and-set rather than a lock: two operators, or an operator
        // and the bot, can credit the same customer at the same moment.
        while (true) {
            val current = getCustomer(id)
            // Invalid, not a raw ArithmeticException: the two stores must
            // refuse identically, and an ArithmeticException escapes the API's
            // StatusPages handlers as a 500 — an internal fault, when this is
            // a rejected request. SqlStore does the same.
            val after = try {
                Math.addExact(current.balanceMicros, request.amountMicros)
            } catch (overflow: ArithmeticException) {
                throw Invalid(
                    "that adjustment would overflow the balance " +
                        "(${current.balanceMicros} + ${request.amountMicros} micro-units)"
                )
            }
            val updated = current.copy(balanceMicros = after)
            if (customers.replace(id, current, updated)) {
                val txn = Transaction(
                    id = nextId("txn"),
                    customerId = id,
                    amountMicros = request.amountMicros,
                    balanceAfterMicros = after,
                    reason = request.reason,
                    reference = request.reference,
                    createdAt = now(),
                    actor = actor,
                )
                transactions += txn
                return txn
            }
        }
    }

    override fun setCallerId(id: String, number: String, actor: String): CallerId {
        if (!E164.matches(number)) {
            throw Invalid("caller_id '$number' is not E.164 (for example +441632960123)")
        }
        val callerId = CallerId(
            number = number,
            // Set by an operator or a customer through the bot is an ASSERTION
            // of ownership, not a verification of it. Marking it verified here
            // would put a false attestation on every call.
            verified = false,
            setAt = now(),
            setBy = actor,
        )
        customers[id] = getCustomer(id).copy(callerId = callerId)
        return callerId
    }

    override fun createPlan(request: CreatePlan): Plan {
        if (!CURRENCY.matches(request.currency)) {
            throw Invalid("currency '${request.currency}' must be a 3-letter ISO 4217 code")
        }
        if (request.name.isBlank()) throw Invalid("plan name must not be blank")
        val plan = Plan(
            id = nextId("plan"),
            name = request.name,
            currency = request.currency.uppercase(),
            description = request.description,
            updatedAt = now(),
        )
        plans[plan.id] = plan
        return plan
    }

    override fun listPlans(): List<Plan> = plans.values.sortedBy { it.id }

    override fun replaceRates(planId: String, request: ReplaceRates): RatesReplaced {
        val plan = plans[planId] ?: throw NotFound("plan '$planId'")
        if (request.rates.isEmpty()) throw Invalid("a rate table must not be empty")

        val seen = HashSet<String>()
        for (row in request.rates) {
            if (!DIGITS.matches(row.prefix)) {
                throw Invalid("prefix '${row.prefix}' must be digits only")
            }
            if (!seen.add(row.prefix)) {
                throw Invalid(
                    "duplicate prefix '${row.prefix}': a prefix with two prices makes " +
                        "the bill depend on row ordering"
                )
            }
            if (row.sellMicrosPerMinute < 0) {
                throw Invalid("prefix '${row.prefix}' has a negative sell rate")
            }
            if (row.incrementSeconds < 1) {
                throw Invalid("prefix '${row.prefix}' has an increment below 1 second")
            }
        }

        // Whole-table replacement, not row-by-row editing. Rate tables arrive
        // from carriers as complete files and change as complete files;
        // partial edits are how a plan keeps a prefix nobody meant, selling
        // below cost, discovered at month end.
        rates[planId] = request.rates
        val effective = request.effectiveFrom ?: now()
        plans[planId] = plan.copy(rateCount = request.rates.size, updatedAt = now())
        return RatesReplaced(planId, request.rates.size, effective)
    }

    override fun ratesFor(planId: String): List<RateRow> = rates[planId].orEmpty()

    override fun createTrunk(request: CreateTrunk): Trunk {
        if (request.name.isBlank()) throw Invalid("trunk name must not be blank")
        if (request.remoteIps.isEmpty()) {
            throw Invalid(
                "remote_ips must not be empty: a trunk that accepts from anywhere is " +
                    "an open relay"
            )
        }
        for (ip in request.remoteIps) {
            if (!CIDR.matches(ip)) throw Invalid("remote_ip '$ip' is not an address or CIDR")
        }
        if (request.port !in 1..65535) throw Invalid("port must be 1-65535")

        val trunk = Trunk(
            id = nextId("trunk"),
            name = request.name,
            direction = request.direction,
            host = request.host,
            port = request.port,
            remoteIps = request.remoteIps,
            transport = request.transport,
            enabled = true,
            maxConcurrentCalls = request.maxConcurrentCalls,
        )
        trunks[trunk.id] = trunk
        return trunk
    }

    override fun listTrunks(): List<Trunk> = trunks.values.sortedBy { it.id }

    /**
     * Not durable, because nothing in this store is. It is still atomic, so
     * the concurrency half of the contract holds and the contract suite tests
     * the same behaviour against both implementations.
     */
    private val claimed = ConcurrentHashMap.newKeySet<String>()

    override fun claimOnce(key: String): Boolean = claimed.add(key)

    private val calls = java.util.Collections.synchronizedList(mutableListOf<CallRecord>())

    override fun recordCall(record: CallRecord) {
        synchronized(calls) {
            // Idempotent on call_id: the switch retransmits, and a second row
            // would double the apparent spend on every report while the
            // balance showed the truth.
            if (calls.none { it.callId == record.callId }) calls.add(record)
        }
    }

    /**
     * ORDERED BY WHEN THE CALL ENDED, not by when we happened to record it.
     *
     * The first version reversed insertion order, which is the same thing
     * only while settlements arrive in the order the calls finished — and
     * they do not: a BYE can be retransmitted, delayed behind another
     * settlement, or replayed after a restart. SqlStore orders by ended_at,
     * so the two stores would have disagreed about what "most recent" means,
     * which is exactly the divergence this suite exists to catch.
     *
     * call_id breaks ties so the order is total and a page boundary cannot
     * show the same call twice.
     */
    private fun ordered(from: List<CallRecord>, limit: Int) =
        from.sortedWith(compareByDescending<CallRecord> { it.endedAt }.thenByDescending { it.callId })
            .take(limit)

    override fun callsFor(account: String, limit: Int): List<CallRecord> =
        synchronized(calls) { ordered(calls.filter { it.account == account }, limit) }

    override fun recentCalls(limit: Int): List<CallRecord> =
        synchronized(calls) { ordered(calls.toList(), limit) }

    override fun noMediaCalls(limit: Int): List<CallRecord> =
        synchronized(calls) { ordered(calls.filter { it.noMedia }, limit) }

    override fun releaseClaim(key: String) {
        claimed.remove(key)
    }

    private val dids = ConcurrentHashMap<String, Did>()

    override fun assignDid(request: AssignDid, actor: String): Did {
        val number = normaliseDid(request.number)
        val customer = getCustomer(request.customerId)
        val did = Did(
            number = number,
            customerId = customer.id,
            description = request.description,
            enabled = true,
            assignedAt = now(),
            assignedBy = actor,
        )
        // putIfAbsent, not put: a check followed by a write is not a check
        // under concurrency, and the loser of that race silently steals a
        // working number from another customer.
        val existing = dids.putIfAbsent(number, did)
        if (existing != null && existing.customerId != customer.id) {
            throw Conflict("+$number already belongs to another customer")
        }
        return did
    }

    override fun releaseDid(number: String, actor: String) {
        dids.remove(normaliseDid(number))
    }

    override fun listDids(customerId: String?): List<Did> =
        dids.values.filter { customerId == null || it.customerId == customerId }
            .sortedBy { it.number }

    override fun customerForDid(number: String): Customer? {
        val did = dids[normaliseDid(number)] ?: return null
        if (!did.enabled) return null
        return customers[did.customerId]
    }

    override fun setPlan(id: String, planId: String, actor: String): Customer {
        plans[planId] ?: throw NotFound("plan '$planId'")
        val customer = getCustomer(id)
        val updated = customer.copy(planId = planId)
        customers[id] = updated
        return updated
    }

    override fun clearCallerId(id: String, actor: String): Customer {
        val updated = getCustomer(id).copy(callerId = null)
        customers[id] = updated
        return updated
    }

    override fun verifyPassword(handle: String, password: String): Boolean? {
        val stored = ha1ByHandle[handle] ?: return null
        // Constant-time, because this is a credential check and a timing
        // difference is a slow oracle for the first differing character.
        return java.security.MessageDigest.isEqual(
            stored.toByteArray(),
            ha1(handle, sipDomain, password).toByteArray(),
        )
    }

    override fun importCustomer(
        request: CreateCustomer,
        password: String,
        actor: String,
    ): Customer {
        require(password.length >= 8) {
            "an imported password shorter than 8 characters is not worth importing"
        }
        val (customer, _) = createCustomer(request, actor)
        // Overwrite the generated credential with the supplied one, so the
        // customer's existing softphone keeps working untouched.
        ha1ByHandle[customer.handle] = ha1(customer.handle, sipDomain, password)
        return customer
    }

    override fun sipDigestHa1(handle: String, realm: String): String? {
        // Same rule as SqlStore: this store holds credentials for exactly one
        // realm. Answering for another would return something that cannot
        // authenticate, and a silently wrong credential is a customer who
        // cannot register with no indication why.
        if (!realm.equals(sipDomain, ignoreCase = true)) return null
        return ha1ByHandle[handle]
    }

    /**
     * HA1 = MD5(username:realm:password), the SIP digest credential.
     *
     * MD5 is not a choice here and must not be "fixed": RFC 2617 digest
     * defines HA1 this way, and every softphone MEGATRON targets speaks it.
     * Replacing it with something stronger would simply mean no customer
     * could register. The mitigation is that this value never leaves the
     * private network -- see the Store interface.
     */
    private fun ha1(username: String, realm: String, password: String): String =
        MessageDigest.getInstance("MD5")
            .digest("$username:$realm:$password".toByteArray())
            .joinToString("") { "%02x".format(it) }


    private companion object {
        val HANDLE = Regex("^[a-z0-9][a-z0-9._-]{2,31}$")
        val E164 = Regex("^\\+[1-9][0-9]{6,14}$")
        val CURRENCY = Regex("^[A-Za-z]{3}$")
        val DIGITS = Regex("^[0-9]{1,15}$")
        val CIDR = Regex(
            "^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])" +
                "(/(3[0-2]|[12]?[0-9]))?$"
        )
    }
}
