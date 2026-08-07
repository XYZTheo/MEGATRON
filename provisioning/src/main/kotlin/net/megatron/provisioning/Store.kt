package net.megatron.provisioning

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
    fun createTrunk(request: CreateTrunk): Trunk
    fun listTrunks(): List<Trunk>
}

/**
 * Replay protection for mutating requests.
 *
 * A Telegram bot runs on a phone network. It WILL time out after the server
 * has already committed, and it WILL retry. Without this, that is a double
 * credit — every time — and the operator finds out from the balance sheet.
 */
class IdempotencyStore {
    private data class Entry(val bodyHash: Int, val response: String)

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
        entries[key] = Entry(bodyHash, response)
    }

    val size: Int get() = entries.size
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
    private val passwords = ConcurrentHashMap<String, String>()
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
        if (findByHandle(request.handle) != null) {
            throw Conflict("a customer with handle '${request.handle}' already exists")
        }

        val id = nextId("cust")
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
        passwords[id] = password

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
        passwords[id] = password
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
            val after = Math.addExact(current.balanceMicros, request.amountMicros)
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

    fun ratesFor(planId: String): List<RateRow> = rates[planId].orEmpty()

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
