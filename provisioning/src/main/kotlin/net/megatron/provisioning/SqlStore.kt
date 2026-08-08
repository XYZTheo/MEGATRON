package net.megatron.provisioning

import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * Durable storage.
 *
 * WHY THIS EXISTS AT ALL: [InMemoryStore] loses every customer and every
 * balance on restart, which makes the platform unusable for the thing it is
 * for — the owner running his own business on it (docs/PRODUCT.md). Durability
 * is not a later concern; it is the difference between a demo and a product.
 *
 * WHY SQLITE, WHEN THE ARCHITECTURE SAYS POSTGRESQL: because SQLite is the
 * only database that can be tested on the machine this was written on, and an
 * untested storage layer is worse than none — it is a storage layer everyone
 * believes. The SQL is deliberately portable (see schema.sql) so PostgreSQL is
 * a schema variant and a JDBC URL, not a rewrite. docs/STORAGE.md states what
 * that does and does not buy.
 *
 * SQLite is also genuinely adequate for the provisioning data of a v1
 * deployment: hundreds of customers and a few thousand transactions is not a
 * scale problem. CDR volume is, which is why CDRs go to ClickHouse and are not
 * in this schema.
 */
class SqlStore(
    private val jdbcUrl: String,
    /** Also the digest realm: HA1 bakes the realm in, so it is fixed here. */
    private val sipDomain: String = "sip.megatron.local",
    private val defaultTransport: Transport = Transport.UDP,
) : Store, AutoCloseable {

    private val connection: Connection = DriverManager.getConnection(jdbcUrl).apply {
        // PRAGMAS FIRST, THEN autoCommit = false. Order matters and getting it
        // wrong is not subtle: SQLite refuses to change journal mode inside a
        // transaction ("cannot change into wal mode from within a
        // transaction"), so setting autoCommit false first makes every
        // constructor throw. Found by running the tests on Linux.
        //
        // Foreign keys and durable writes are both OFF by default in SQLite —
        // a reasonable default for a file format, and a poor one for money.
        //
        // The foreign_keys pragma had nothing to enforce for a while:
        // schema.sql declared no FOREIGN KEY at all, so this line read as
        // protection and provided none. They are declared now.
        //
        // CAVEAT: SQLite cannot add a foreign key to an existing table, and
        // schema.sql is CREATE TABLE IF NOT EXISTS, so a database created
        // before those declarations keeps its unconstrained tables. See
        // migrate() — adding a column is safe, rebuilding a table to add a
        // constraint is not, and a migration that can destroy data will
        // eventually meet a database somebody cared about.
        createStatement().use { it.execute("PRAGMA foreign_keys = ON") }
        createStatement().use { it.execute("PRAGMA journal_mode = WAL") }
        createStatement().use { it.execute("PRAGMA synchronous = FULL") }

        // autoCommit STAYS ON. Turning it off globally was a real bug and a
        // nasty one: with autoCommit off, every SELECT silently opens a
        // transaction that is never ended, so the connection pins a snapshot
        // and NEVER SEES ANOTHER PROCESS'S COMMITS AGAIN.
        //
        // The symptom was not a database error. The switch API simply could
        // not find a customer the provisioning API had just created, and
        // reported it as "no such account" — a data bug wearing the costume
        // of a business decision. Found by running the two services against
        // one database, which no unit test would have done.
        //
        // Multi-statement work uses transaction {} below, which turns
        // autoCommit off for exactly its own duration.
        autoCommit = true
    }

    /**
     * Brings an EXISTING database up to the current schema.
     *
     * schema.sql is entirely `CREATE TABLE IF NOT EXISTS`, which does exactly
     * nothing to a table that already exists. So adding a column to the file
     * added it only for databases created afterwards — and every deployment
     * that had ever run before was left without it. The first `INSERT INTO
     * customers (... sip_ha1 ...)` then failed with
     *
     *     table customers has no column named sip_ha1
     *
     * which is not degraded behaviour: no customer could be created at all.
     * An upgrade that bricks the database on start is worse than a feature
     * that is missing from it.
     *
     * Deliberately additive only. Nothing here drops or rewrites a column,
     * because a migration that can destroy data will eventually be run against
     * a database somebody cared about.
     */
    private fun migrate() {
        val existing = query("PRAGMA table_info(customers)") { rs ->
            buildSet { while (rs.next()) add(rs.getString("name").lowercase()) }
        }
        // Matches the DEFAULT in schema.sql, so a migrated row and a freshly
        // created one are indistinguishable. A blank HA1 means "no working
        // login yet", and SubscriberExport skips those rather than writing a
        // credential everybody in that position would share.
        if ("sip_ha1" !in existing) {
            update("ALTER TABLE customers ADD COLUMN sip_ha1 TEXT NOT NULL DEFAULT ''")
            System.err.println(
                "migrated: added customers.sip_ha1. Existing customers have no SIP digest " +
                    "credential until their password is rotated, and cannot register until " +
                    "then — rotate via POST /v1/customers/{id}/credentials."
            )
        }
    }

    /**
     * Runs [block] as one atomic unit.
     *
     * Scoped rather than global, for the reason above. `finally` restores
     * autoCommit even on the exception paths, because a store that leaves the
     * connection in manual-commit mode after a failure goes permanently blind
     * to other writers.
     */
    private fun <T> transaction(block: () -> T): T = synchronized(connection) {
        connection.autoCommit = false
        try {
            val result = block()
            connection.commit()
            result
        } catch (e: Throwable) {
            runCatching { connection.rollback() }
            throw e
        } finally {
            connection.autoCommit = true
        }
    }

    private val ids = AtomicLong(System.currentTimeMillis())
    private val random = SecureRandom()

    init {
        val schema = SqlStore::class.java.getResourceAsStream("/schema.sql")
            ?.bufferedReader()?.readText()
            ?: error("schema.sql is missing from the jar")
        transaction {
            connection.createStatement().use { statement ->
                for (ddl in schema.split(";")) {
                    if (ddl.isBlank()) continue
                    statement.execute(ddl)
                }
            }
        }
        migrate()
        // Continue ids past anything already stored, so a restart cannot
        // reissue an id that is already in the audit trail.
        query("SELECT id FROM customers UNION ALL SELECT id FROM plans " +
            "UNION ALL SELECT id FROM trunks") { rs ->
            while (rs.next()) {
                rs.getString(1).substringAfterLast('-').toLongOrNull()?.let { existing ->
                    while (true) {
                        val current = ids.get()
                        if (current > existing) break
                        if (ids.compareAndSet(current, existing + 1)) break
                    }
                }
            }
        }
    }

    override fun close() = connection.close()

    // -- helpers ------------------------------------------------------------

    private fun nextId(prefix: String) = "$prefix-${ids.getAndIncrement()}"
    private fun now() = Instant.now().toString()

    private fun <T> query(sql: String, vararg args: Any?, read: (ResultSet) -> T): T =
        synchronized(connection) {
            connection.prepareStatement(sql).use { statement ->
                args.forEachIndexed { i, arg -> statement.setObject(i + 1, arg) }
                statement.executeQuery().use(read)
            }
        }

    private fun update(sql: String, vararg args: Any?): Int =
        synchronized(connection) {
            connection.prepareStatement(sql).use { statement ->
                args.forEachIndexed { i, arg -> statement.setObject(i + 1, arg) }
                statement.executeUpdate()
            }
        }

    private fun generatePassword(): String {
        // Excludes characters that get mangled when a customer copies a
        // password out of a chat message into a softphone field.
        val alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return (1..24).map { alphabet[random.nextInt(alphabet.length)] }.joinToString("")
    }

    /**
     * Stores a hash, never the password.
     *
     * A provisioning database that can hand back SIP passwords is one whose
     * compromise hands over every customer's ability to place calls at the
     * operator's expense. The password is returned once, at creation or
     * rotation, and is not recoverable afterwards by anybody — including us.
     *
     * NOTE FOR THE SIP SIDE: HTTP digest authentication needs the HA1 value
     * (MD5 of user:realm:password), not a modern password hash. That is why
     * sip_ha1 is stored alongside this column and written by the same code
     * paths — see ha1() below. Neither replaces the other: this one is the
     * strong hash nothing on the call path reads, and HA1 is the weak one SIP
     * forces on us. Do not "fix" the mismatch by deleting either.
     */
    private fun hash(password: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(password.toByteArray())
            .joinToString("") { "%02x".format(it) }

    private fun ResultSet.toCustomer() = Customer(
        id = getString("id"),
        handle = getString("handle"),
        displayName = getString("display_name"),
        status = CustomerStatus.valueOf(getString("status")),
        planId = getString("plan_id"),
        balanceMicros = getLong("balance_micros"),
        currency = getString("currency"),
        callerId = getString("caller_id_number")?.let {
            CallerId(
                number = it,
                verified = getInt("caller_id_verified") == 1,
                setAt = getString("caller_id_set_at"),
                setBy = getString("caller_id_set_by"),
            )
        },
        maxConcurrentCalls = getInt("max_concurrent_calls"),
        telegramUserId = getLong("telegram_user_id").let { if (wasNull()) null else it },
        createdAt = getString("created_at"),
    )

    // -- customers ----------------------------------------------------------

    override fun createCustomer(
        request: CreateCustomer,
        actor: String,
    ): Pair<Customer, SipCredentials> {
        if (!HANDLE.matches(request.handle)) {
            throw Invalid(
                "handle '${request.handle}' must be 3-32 characters of a-z, 0-9, dot, " +
                    "underscore or hyphen"
            )
        }
        if (request.maxConcurrentCalls < 1) throw Invalid("max_concurrent_calls must be >= 1")
        if (request.openingBalanceMicros < 0) throw Invalid("opening balance must not be negative")

        val plan = listPlans().firstOrNull { it.id == request.planId }
            ?: throw NotFound("plan '${request.planId}'")

        val id = nextId("cust")
        val password = generatePassword()

        // ONE TRANSACTION, for the same reason adjustBalance is one: the
        // opening balance and its audit row commit together or not at all.
        //
        // These were two separate autocommitting statements, so a crash
        // between them produced a customer holding money with no record of
        // where it came from — and the opening balance is the FIRST money
        // movement on every account, the one most likely to be asked about.
        // adjustBalance's comment has always insisted on this; creation was
        // the one path that did not do it.
        //
        // It also closes the check-then-act gap on the handle: findByHandle
        // above and this INSERT now happen inside one transaction, so two
        // concurrent creations cannot both pass the check. If one still slips
        // through at the database level the UNIQUE constraint catches it, and
        // it is reported as the Conflict it is rather than as a 500.
        return transaction {
            if (findByHandle(request.handle) != null) {
                throw Conflict("a customer with handle '${request.handle}' already exists")
            }
            try {
                update(
                    "INSERT INTO customers (id, handle, display_name, status, plan_id, " +
                        "balance_micros, currency, max_concurrent_calls, telegram_user_id, " +
                        "sip_password_hash, sip_ha1, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    id, request.handle, request.displayName, CustomerStatus.ACTIVE.name,
                    plan.id, request.openingBalanceMicros, plan.currency,
                    request.maxConcurrentCalls, request.telegramUserId, hash(password),
                    ha1(request.handle, sipDomain, password), now(),
                )
            } catch (clash: java.sql.SQLException) {
                if (clash.message?.contains("UNIQUE", ignoreCase = true) == true) {
                    throw Conflict("a customer with handle '${request.handle}' already exists")
                }
                throw clash
            }

            if (request.openingBalanceMicros > 0) {
                update(
                    "INSERT INTO transactions (id, customer_id, amount_micros, " +
                        "balance_after_micros, reason, created_at, actor) VALUES (?,?,?,?,?,?,?)",
                    nextId("txn"), id, request.openingBalanceMicros,
                    request.openingBalanceMicros, "opening balance", now(), actor,
                )
            }

            getCustomer(id) to SipCredentials(
                request.handle, password, sipDomain, defaultTransport
            )
        }
    }

    override fun getCustomer(id: String): Customer =
        query("SELECT * FROM customers WHERE id = ?", id) { rs ->
            if (rs.next()) rs.toCustomer() else throw NotFound("customer '$id'")
        }

    override fun findByHandle(handle: String): Customer? =
        query("SELECT * FROM customers WHERE handle = ?", handle) { rs ->
            if (rs.next()) rs.toCustomer() else null
        }

    override fun findByTelegramUserId(telegramUserId: Long): Customer? =
        query("SELECT * FROM customers WHERE telegram_user_id = ?", telegramUserId) { rs ->
            if (rs.next()) rs.toCustomer() else null
        }

    override fun listCustomers(
        status: CustomerStatus?,
        limit: Int,
        cursor: String?,
    ): CustomerPage {
        val items = query(
            "SELECT * FROM customers WHERE (? IS NULL OR status = ?) " +
                "AND (? IS NULL OR id > ?) ORDER BY id LIMIT ?",
            status?.name, status?.name, cursor, cursor, limit + 1,
        ) { rs ->
            buildList { while (rs.next()) add(rs.toCustomer()) }
        }
        // One extra row is fetched purely to know whether there IS a next
        // page. Reporting a cursor when the page happens to be exactly full
        // sends the caller round again for nothing.
        val page = items.take(limit)
        val next = if (items.size > limit) page.lastOrNull()?.id else null
        return CustomerPage(page, next)
    }

    override fun setStatus(id: String, request: SetStatus, actor: String): Customer {
        if (request.reason.length < 3) throw Invalid("a reason is required")
        getCustomer(id)
        update("UPDATE customers SET status = ? WHERE id = ?", request.status.name, id)
        return getCustomer(id)
    }

    override fun rotateCredentials(id: String): SipCredentials {
        val customer = getCustomer(id)
        val password = generatePassword()
        // Both credentials rotate together. Leaving a stale HA1 behind would
        // mean the old password still registers -- a rotation that rotates
        // nothing, which is worse than not offering one.
        update(
            "UPDATE customers SET sip_password_hash = ?, sip_ha1 = ? WHERE id = ?",
            hash(password), ha1(customer.handle, sipDomain, password), id,
        )
        return SipCredentials(customer.handle, password, sipDomain, defaultTransport)
    }

    override fun adjustBalance(
        id: String,
        request: BalanceAdjustment,
        actor: String,
    ): Transaction = transaction {
        if (request.reason.length < 3) {
            throw Invalid("a reason is required, including on credits")
        }
        getCustomer(id)

        // THE ARITHMETIC HAPPENS IN KOTLIN, NOT IN SQL, AND THAT IS THE POINT.
        //
        // This was `SET balance_micros = balance_micros + ?`, which reads well
        // and is wrong for money: SQLITE SILENTLY CONVERTS AN OVERFLOWING
        // INTEGER SUM TO A FLOAT. Two large credits produced a balance of
        // 9223372036854775807 with no error, and wrote that number into the
        // append-only audit row — the row a dispute is argued from. schema.sql
        // says in capitals that there is no REAL anywhere in it; SQLite put
        // one there anyway.
        //
        // It was also a divergence: InMemoryStore used Math.addExact and
        // refused. Two stores that disagree about whether a credit succeeded
        // is exactly what StoreContractTest exists to catch, and it did not,
        // because nothing tested the boundary.
        //
        // Math.addExact throws rather than wrapping. Refusing a credit is
        // recoverable; a corrupted balance is not.
        //
        // Read-modify-write is safe here despite appearances: the whole method
        // runs inside transaction {}, which is synchronized on the single
        // connection, and SQLite serialises writers between processes. A
        // concurrent writer makes this transaction wait or fail — never lose a
        // credit silently. The contract test with six racing credits pins it.
        val before = connection.prepareStatement(
            "SELECT balance_micros FROM customers WHERE id = ?"
        ).use { statement ->
            statement.setString(1, id)
            statement.executeQuery().use { rs -> rs.next(); rs.getLong(1) }
        }
        val after = try {
            Math.addExact(before, request.amountMicros)
        } catch (overflow: ArithmeticException) {
            throw Invalid(
                "that adjustment would overflow the balance " +
                    "($before + ${request.amountMicros} micro-units)"
            )
        }
        connection.prepareStatement(
            "UPDATE customers SET balance_micros = ? WHERE id = ?"
        ).use { statement ->
            statement.setLong(1, after)
            statement.setString(2, id)
            statement.executeUpdate()
        }
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
        connection.prepareStatement(
            "INSERT INTO transactions (id, customer_id, amount_micros, " +
                "balance_after_micros, reason, reference, created_at, actor) " +
                "VALUES (?,?,?,?,?,?,?,?)"
        ).use { statement ->
            statement.setString(1, txn.id)
            statement.setString(2, txn.customerId)
            statement.setLong(3, txn.amountMicros)
            statement.setLong(4, txn.balanceAfterMicros)
            statement.setString(5, txn.reason)
            statement.setString(6, txn.reference)
            statement.setString(7, txn.createdAt)
            statement.setString(8, txn.actor)
            statement.executeUpdate()
        }
        // The balance change and its audit row commit together or not at all.
        // A balance that moved with no record of who moved it is exactly the
        // state that cannot be argued about later.
        txn
    }

    override fun setCallerId(id: String, number: String, actor: String): CallerId {
        if (!E164.matches(number)) {
            throw Invalid("caller_id '$number' is not E.164 (for example +441632960123)")
        }
        getCustomer(id)
        val callerId = CallerId(number, verified = false, setAt = now(), setBy = actor)
        update(
            "UPDATE customers SET caller_id_number = ?, caller_id_verified = 0, " +
                "caller_id_set_at = ?, caller_id_set_by = ? WHERE id = ?",
            number, callerId.setAt, actor, id,
        )
        return callerId
    }

    fun transactionsFor(customerId: String): List<Transaction> =
        query(
            "SELECT * FROM transactions WHERE customer_id = ? ORDER BY created_at, id",
            customerId,
        ) { rs ->
            buildList {
                while (rs.next()) add(
                    Transaction(
                        id = rs.getString("id"),
                        customerId = rs.getString("customer_id"),
                        amountMicros = rs.getLong("amount_micros"),
                        balanceAfterMicros = rs.getLong("balance_after_micros"),
                        reason = rs.getString("reason"),
                        reference = rs.getString("reference"),
                        createdAt = rs.getString("created_at"),
                        actor = rs.getString("actor"),
                    )
                )
            }
        }

    // -- plans and rates ----------------------------------------------------

    override fun createPlan(request: CreatePlan): Plan {
        if (!CURRENCY.matches(request.currency)) throw Invalid("currency must be ISO 4217")
        if (request.name.isBlank()) throw Invalid("plan name must not be blank")
        val plan = Plan(
            id = nextId("plan"),
            name = request.name,
            currency = request.currency.uppercase(),
            description = request.description,
            updatedAt = now(),
        )
        update(
            "INSERT INTO plans (id, name, currency, description, rate_count, updated_at) " +
                "VALUES (?,?,?,?,?,?)",
            plan.id, plan.name, plan.currency, plan.description, 0, plan.updatedAt,
        )
        return plan
    }

    override fun listPlans(): List<Plan> =
        query("SELECT * FROM plans ORDER BY id") { rs ->
            buildList {
                while (rs.next()) add(
                    Plan(
                        id = rs.getString("id"),
                        name = rs.getString("name"),
                        currency = rs.getString("currency"),
                        description = rs.getString("description"),
                        rateCount = rs.getInt("rate_count"),
                        updatedAt = rs.getString("updated_at"),
                    )
                )
            }
        }

    override fun replaceRates(planId: String, request: ReplaceRates): RatesReplaced =
        transaction {
            listPlans().firstOrNull { it.id == planId } ?: throw NotFound("plan '$planId'")
            if (request.rates.isEmpty()) throw Invalid("a rate table must not be empty")

            val seen = HashSet<String>()
            for (row in request.rates) {
                if (!DIGITS.matches(row.prefix)) {
                    throw Invalid("prefix '${row.prefix}' must be digits only")
                }
                if (!seen.add(row.prefix)) {
                    throw Invalid("duplicate prefix '${row.prefix}'")
                }
                if (row.sellMicrosPerMinute < 0) throw Invalid("negative sell rate")
                if (row.incrementSeconds < 1) throw Invalid("increment below one second")
            }

            // Whole-table replacement in ONE transaction. A rate load that
            // half-applied would leave a plan pricing some destinations from
            // the old file and some from the new, which is worse than either.
            connection.prepareStatement("DELETE FROM rates WHERE plan_id = ?").use {
                it.setString(1, planId); it.executeUpdate()
            }
            connection.prepareStatement(
                "INSERT INTO rates (plan_id, prefix, description, sell_micros_per_minute, " +
                    "buy_micros_per_minute, connect_fee_micros, increment_seconds, " +
                    "minimum_seconds) VALUES (?,?,?,?,?,?,?,?)"
            ).use { statement ->
                for (row in request.rates) {
                    statement.setString(1, planId)
                    statement.setString(2, row.prefix)
                    statement.setString(3, row.description)
                    statement.setLong(4, row.sellMicrosPerMinute)
                    if (row.buyMicrosPerMinute != null) {
                        statement.setLong(5, row.buyMicrosPerMinute)
                    } else {
                        statement.setNull(5, java.sql.Types.BIGINT)
                    }
                    statement.setLong(6, row.connectFeeMicros)
                    statement.setInt(7, row.incrementSeconds)
                    statement.setInt(8, row.minimumSeconds)
                    statement.addBatch()
                }
                statement.executeBatch()
            }
            val effective = request.effectiveFrom ?: now()
            connection.prepareStatement(
                "UPDATE plans SET rate_count = ?, updated_at = ? WHERE id = ?"
            ).use {
                it.setInt(1, request.rates.size); it.setString(2, now())
                it.setString(3, planId); it.executeUpdate()
            }
            RatesReplaced(planId, request.rates.size, effective)
        }

    override fun ratesFor(planId: String): List<RateRow> =
        query("SELECT * FROM rates WHERE plan_id = ? ORDER BY prefix", planId) { rs ->
            buildList {
                while (rs.next()) add(
                    RateRow(
                        prefix = rs.getString("prefix"),
                        description = rs.getString("description"),
                        sellMicrosPerMinute = rs.getLong("sell_micros_per_minute"),
                        buyMicrosPerMinute = rs.getLong("buy_micros_per_minute")
                            .let { if (rs.wasNull()) null else it },
                        connectFeeMicros = rs.getLong("connect_fee_micros"),
                        incrementSeconds = rs.getInt("increment_seconds"),
                        minimumSeconds = rs.getInt("minimum_seconds"),
                    )
                )
            }
        }

    // -- trunks -------------------------------------------------------------

    override fun createTrunk(request: CreateTrunk): Trunk {
        if (request.name.isBlank()) throw Invalid("trunk name must not be blank")
        if (request.remoteIps.isEmpty()) {
            throw Invalid("remote_ips must not be empty: a trunk that accepts from " +
                "anywhere is an open relay")
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
        update(
            "INSERT INTO trunks (id, name, direction, host, port, remote_ips, transport, " +
                "enabled, max_concurrent_calls) VALUES (?,?,?,?,?,?,?,?,?)",
            trunk.id, trunk.name, trunk.direction.name, trunk.host, trunk.port,
            trunk.remoteIps.joinToString(","), trunk.transport.name, 1,
            trunk.maxConcurrentCalls,
        )
        return trunk
    }

    /**
     * Backed by the `idempotency` table, which until now was declared in the
     * schema and read by nothing — the comment there claimed it was a table
     * rather than a cache precisely so it would "survive the restart that a
     * retry may well be reacting to", which was true of the schema and of no
     * code. It is now true of both.
     *
     * Atomicity comes from the PRIMARY KEY: two concurrent claims cannot both
     * insert, and the loser sees the constraint violation rather than a
     * check-then-act race.
     */
    override fun claimOnce(key: String): Boolean =
        try {
            update(
                "INSERT INTO idempotency (key, body_hash, response, created_at) " +
                    "VALUES (?,?,?,?)",
                key, 0, "", now(),
            )
            true
        } catch (duplicate: java.sql.SQLException) {
            // Only a duplicate key may be swallowed. Anything else — the table
            // missing, the disk full — must not be reported as "already done",
            // because that silently DROPS the operation instead of repeating
            // it, and a dropped /credit is a customer who paid and got
            // nothing.
            if (duplicate.message?.contains("UNIQUE", ignoreCase = true) == true ||
                duplicate.message?.contains("PRIMARY KEY", ignoreCase = true) == true
            ) {
                false
            } else {
                throw duplicate
            }
        }

    override fun sipDigestHa1(handle: String, realm: String): String? {
        // The stored HA1 is bound to this store's realm. Asking for a
        // different one cannot be satisfied from storage and must fail rather
        // than return something that will not authenticate -- a silently
        // wrong credential is a customer who cannot register and no
        // indication why.
        if (!realm.equals(sipDomain, ignoreCase = true)) return null
        return query(
            "SELECT sip_ha1 FROM customers WHERE handle = ?", handle
        ) { rs -> if (rs.next()) rs.getString(1)?.ifBlank { null } else null }
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

    override fun listTrunks(): List<Trunk> =
        query("SELECT * FROM trunks ORDER BY id") { rs ->
            buildList {
                while (rs.next()) add(
                    Trunk(
                        id = rs.getString("id"),
                        name = rs.getString("name"),
                        direction = TrunkDirection.valueOf(rs.getString("direction")),
                        host = rs.getString("host"),
                        port = rs.getInt("port"),
                        remoteIps = rs.getString("remote_ips").split(",").filter { it.isNotBlank() },
                        transport = Transport.valueOf(rs.getString("transport")),
                        enabled = rs.getInt("enabled") == 1,
                        maxConcurrentCalls = rs.getInt("max_concurrent_calls")
                            .let { if (rs.wasNull()) null else it },
                    )
                )
            }
        }

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
