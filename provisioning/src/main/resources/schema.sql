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
    -- A rate for a plan that does not exist is a price nothing can charge.
    FOREIGN KEY (plan_id) REFERENCES plans (id),
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
    created_at            TEXT NOT NULL,
    -- A customer on a plan that does not exist has no prices, so every call
    -- they make is unrated — which the switch refuses, correctly, as though
    -- the destination were unknown. Better to make the state unreachable.
    FOREIGN KEY (plan_id) REFERENCES plans (id)
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
    actor                 TEXT NOT NULL,
    -- An audit row for a customer who does not exist is evidence about
    -- nobody, and it is how a deletion elsewhere would quietly orphan the
    -- money trail.
    FOREIGN KEY (customer_id) REFERENCES customers (id)
);

CREATE INDEX IF NOT EXISTS transactions_customer
    ON transactions (customer_id, created_at);

-- DIDs: the numbers customers RECEIVE calls on.
--
-- A carrier sends an inbound call to a number, and the only question that
-- matters is which customer owns it. Without this table a switch can dial out
-- and cannot be dialled, which is half a phone service.
--
-- ONE CUSTOMER PER NUMBER, enforced by the primary key rather than only by the
-- application. Two owners for one number means an inbound call is delivered by
-- whichever row is read first — non-deterministic call routing, and a customer
-- receiving somebody else's calls.
CREATE TABLE IF NOT EXISTS dids (
    -- E.164, normalised on the way in. Stored without the leading + so it
    -- matches what carriers actually send in the request URI, which varies.
    number       TEXT PRIMARY KEY,
    customer_id  TEXT NOT NULL,
    description  TEXT,
    -- A DID can be parked: owned by a customer, not currently delivering. That
    -- is different from not existing, which is a number to reject.
    enabled      INTEGER NOT NULL DEFAULT 1,
    assigned_at  TEXT NOT NULL,
    assigned_by  TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers (id)
);

CREATE INDEX IF NOT EXISTS dids_customer
    ON dids (customer_id);

-- Call detail records.
--
-- THIS IS THE EVIDENCE. Every charge on the transactions table above came from
-- a call, and this is the row that says which one, how long it ran, at what
-- rate, and whether audio actually flowed. Without it "why is my bill this
-- much" has no answer, and a disputed charge is decided by whoever is more
-- confident.
--
-- APPEND-ONLY, like transactions, and for the same reason: a call history an
-- operator can edit proves nothing about the calls.
--
-- SQLite here is a deliberate v1 choice and a known ceiling. CDR volume is the
-- one thing in this schema that genuinely grows without bound, and the design
-- (docs/ARCHITECTURE.md) puts it in ClickHouse at scale. Hundreds of calls a
-- day is not scale, a million is. The read paths below are indexed so the
-- switch never waits on this table.
--
-- NOTE FOR ANYONE EDITING THIS FILE: it is loaded by splitting on the
-- semicolon, so a semicolon inside a COMMENT cuts the statement in half and
-- every table after it silently fails to create. That is how this very block
-- broke the whole schema once.
CREATE TABLE IF NOT EXISTS cdrs (
    call_id                 TEXT PRIMARY KEY,
    account                 TEXT NOT NULL,
    destination             TEXT NOT NULL,
    prefix                  TEXT,
    duration_seconds        INTEGER NOT NULL,
    -- 'sip' or 'server-clock'. NEVER absent: a bill nobody can trace to a
    -- source is a bill nobody can defend.
    duration_source         TEXT NOT NULL,
    billed_seconds          INTEGER NOT NULL,
    charged_micros          INTEGER NOT NULL,
    rate_micros_per_minute  INTEGER NOT NULL,
    -- NULL means "we could not read the media stats", which is NOT the same as
    -- zero. Zero is evidence of silence, null is evidence of nothing.
    media_bytes             INTEGER,
    media_stats             TEXT,
    no_media                INTEGER NOT NULL DEFAULT 0,
    overran                 INTEGER NOT NULL DEFAULT 0,
    hangup_cause            TEXT,
    ended_at                TEXT NOT NULL
);

-- "What did this customer spend, most recently first" — the question the bot
-- asks and the one a dispute starts from.
CREATE INDEX IF NOT EXISTS cdrs_account
    ON cdrs (account, ended_at DESC);

-- Calls that connected and carried no audio, across all customers. This is a
-- refund queue: each one is a charge a customer may reasonably challenge, and
-- an operator who cannot list them finds out from the complaints.
CREATE INDEX IF NOT EXISTS cdrs_no_media
    ON cdrs (no_media, ended_at DESC);

CREATE TABLE IF NOT EXISTS trunks (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    direction             TEXT NOT NULL,
    host                  TEXT NOT NULL,
    port                  INTEGER NOT NULL,
    remote_ips            TEXT NOT NULL,
    transport             TEXT NOT NULL,
    enabled               INTEGER NOT NULL DEFAULT 1,
    max_concurrent_calls  INTEGER,

    -- CREDENTIALS FOR TRUNKS THAT CHALLENGE US.
    --
    -- Plenty of carriers do not authenticate by IP: they hand you a username
    -- and password and challenge every INVITE with a 407. A switch that can
    -- only do IP-authenticated trunks cannot connect to them at all, which
    -- rules out most of the small and mid-size providers an operator actually
    -- buys from.
    --
    -- THIS PASSWORD IS STORED RECOVERABLE, AND HAS TO BE. Digest requires
    -- either the plaintext or HA1, and unlike a customer credential we are the
    -- CLIENT here — we must be able to answer a challenge whose nonce and
    -- realm we do not choose. It is an operator secret, not a customer's: it
    -- buys calls at the operator's own expense on a carrier they contracted
    -- with.
    --
    -- It is therefore never returned by the API. See Trunk.authPassword.
    auth_username         TEXT,
    auth_password         TEXT,
    -- The realm the carrier challenges with. Usually their SIP domain, and
    -- NOT always the same as `host` — which is why it is stored rather than
    -- derived.
    auth_realm            TEXT,
    -- Whether to REGISTER to them. Some carriers route inbound to wherever
    -- you last registered from; others expect a static IP and never want a
    -- REGISTER at all.
    register              INTEGER NOT NULL DEFAULT 0,
    -- Lower wins. Selection was "the lowest trunk id", which means the FIRST
    -- trunk ever created wins forever -- so adding a carrier changed nothing
    -- and the operator's calls kept going to whatever they set up first,
    -- which is indistinguishable from the new trunk being broken.
    priority              INTEGER NOT NULL DEFAULT 100,
    -- The user part we put in From on calls to this carrier. NULL means pass
    -- the customer's own through. Carriers that authenticate by account match
    -- the peer on this and answer 403 when it names somebody they have never
    -- heard of -- a correct password does not save you.
    from_user             TEXT
);

-- Replay protection for mutating API calls.
--
-- A Telegram bot on a phone network times out after the server has committed
-- and then retries. Without this that is a double credit, every time. It is a
-- TABLE rather than a cache because it has to survive the restart that a
-- retry may well be reacting to.
--
-- That claim was aspirational for a while: the table was declared here and
-- read by no code, while the only replay protection in the system was an
-- in-memory map in front of the HTTP API. SqlStore.claimOnce now uses this
-- table, which is what makes the bot's idempotency survive a restart — and
-- the restart is the whole scenario, since Telegram redelivers anything the
-- bot did not acknowledge before it died.
CREATE TABLE IF NOT EXISTS idempotency (
    key        TEXT PRIMARY KEY,
    body_hash  INTEGER NOT NULL,
    response   TEXT NOT NULL,
    created_at TEXT NOT NULL
);
