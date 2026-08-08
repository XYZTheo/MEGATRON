-- MEGATRON — provisioning schema
--
-- Deliberately portable SQL. It runs on SQLite today, because that is the only
-- database that can be tested on the machine this was written on, and it is
-- written so PostgreSQL is a schema variant and a JDBC URL rather than a
-- rewrite. See docs/STORAGE.md for what that costs and what it does not.
--
-- MONEY IS ALWAYS AN INTEGER OF MICRO-UNITS. There is no NUMERIC, no REAL, no
-- DECIMAL anywhere in this file, and there must never be. ci/policy_check.py
-- (MONEY-NOT-FLOAT) enforces the same rule in the Kotlin.

CREATE TABLE IF NOT EXISTS plans (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    currency     TEXT NOT NULL,
    description  TEXT,
    rate_count   INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rates (
    plan_id                 TEXT NOT NULL,
    prefix                  TEXT NOT NULL,
    description             TEXT,
    sell_micros_per_minute  INTEGER NOT NULL,
    buy_micros_per_minute   INTEGER,
    connect_fee_micros      INTEGER NOT NULL DEFAULT 0,
    increment_seconds       INTEGER NOT NULL DEFAULT 60,
    minimum_seconds         INTEGER NOT NULL DEFAULT 0,
    -- One price per prefix per plan, enforced by the database rather than only
    -- by the application. Two prices for one prefix makes the bill depend on
    -- row ordering, and a constraint is the only thing that survives somebody
    -- loading rates by a route nobody thought of.
    PRIMARY KEY (plan_id, prefix)
);

CREATE TABLE IF NOT EXISTS customers (
    id                    TEXT PRIMARY KEY,
    handle                TEXT NOT NULL UNIQUE,
    display_name          TEXT,
    status                TEXT NOT NULL,
    plan_id               TEXT NOT NULL,
    balance_micros        INTEGER NOT NULL DEFAULT 0,
    currency              TEXT NOT NULL,
    caller_id_number      TEXT,
    caller_id_verified    INTEGER NOT NULL DEFAULT 0,
    caller_id_set_at      TEXT,
    caller_id_set_by      TEXT,
    max_concurrent_calls  INTEGER NOT NULL DEFAULT 2,
    telegram_user_id      INTEGER,
    sip_password_hash     TEXT NOT NULL,
    -- HA1 = MD5(username:realm:password), which is what SIP digest
    -- authentication requires. It is NOT a second, weaker password hash by
    -- choice: RFC 8760 notwithstanding, every softphone in the target set
    -- (MicroSIP, Zoiper, PortSIP) authenticates with MD5 digest, and the
    -- server cannot verify a digest response without either the plaintext
    -- password or this value.
    --
    -- HA1 IS PASSWORD-EQUIVALENT for SIP: anyone holding it can register and
    -- place calls as that customer. It therefore never leaves the private
    -- network, never appears in an API response a customer can reach, and is
    -- the reason the switch API binds loopback. Storing it is a constraint of
    -- the protocol, not a relaxation of the credential rules -- which is why
    -- sip_password_hash (SHA-256) is kept alongside rather than replaced.
    sip_ha1               TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL
);

-- Self-service lookup path: the bot resolves a Telegram user to an account on
-- every /balance.
CREATE INDEX IF NOT EXISTS customers_telegram
    ON customers (telegram_user_id);

-- The audit trail.
--
-- APPEND-ONLY BY INTENTION. There is no UPDATE or DELETE against this table
-- anywhere in the codebase, and there must never be. MagnusBilling's
-- equivalent is editable by an admin, which makes it evidence of nothing —
-- and "who moved this balance, and why" is the first question asked about any
-- disputed account.
CREATE TABLE IF NOT EXISTS transactions (
    id                    TEXT PRIMARY KEY,
    customer_id           TEXT NOT NULL,
    amount_micros         INTEGER NOT NULL,
    balance_after_micros  INTEGER NOT NULL,
    reason                TEXT NOT NULL,
    reference             TEXT,
    created_at            TEXT NOT NULL,
    actor                 TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS transactions_customer
    ON transactions (customer_id, created_at);

CREATE TABLE IF NOT EXISTS trunks (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    direction             TEXT NOT NULL,
    host                  TEXT NOT NULL,
    port                  INTEGER NOT NULL,
    remote_ips            TEXT NOT NULL,
    transport             TEXT NOT NULL,
    enabled               INTEGER NOT NULL DEFAULT 1,
    max_concurrent_calls  INTEGER
);

-- Replay protection for mutating API calls.
--
-- A Telegram bot on a phone network times out after the server has committed
-- and then retries. Without this that is a double credit, every time. It is a
-- TABLE rather than a cache because it has to survive the restart that a
-- retry may well be reacting to.
CREATE TABLE IF NOT EXISTS idempotency (
    key        TEXT PRIMARY KEY,
    body_hash  INTEGER NOT NULL,
    response   TEXT NOT NULL,
    created_at TEXT NOT NULL
);
