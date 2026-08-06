# PROJECT MEGATRON — Secure VoIP Softswitch + Billing Engine

**Framework &amp; architecture plan · 2026-08-06**

---

## Context

Seth is building a new Class-4 + Class-5 VoIP softswitch with integrated realtime
billing — in the lineage of **MagnusBilling** (leaning that way) and **VOS3000**, but
engineered so that the security defects those platforms are notorious for are
*impossible by construction* rather than merely discouraged.

This is grounded in direct experience, not speculation. PROJECT-VOIPX originally
integrated **MagnusBilling** (PRs #18/#19, security audit → issues #13–#17), then
ripped it out for **VOS3000** (PR #20) — which turned out to have **no authentication
at all** on its third-party HTTP interface, relying on a source-IP allowlist in a
Tomcat config file, with `Modify*` calls that silently reset omitted fields and
security-critical guards (min-profit %, max-rate) that are write-only and therefore
unpreservable. VOIPX had to refuse gateway edits outright as a result.

**Both available platforms are structurally unsafe.** MEGATRON is the answer.

### The market window (this is why now)

Seth, 2026-08-06: *"right now there is a magnus issue where people are getting ddos
very easy, whole servers overloaded… this would be a good time for magnus users to
switch."*

MagnusBilling operators are being knocked offline **today**. That converts DDoS
resilience from a hardening task into the **headline feature and the wedge**, and it
sets the delivery sequence in §7.

### Intended outcome

A softswitch that (a) cannot be trivially owned, (b) does not fall over under attack,
(c) an existing Magnus operator can migrate onto in an afternoon, and (d) feels like a
considered product rather than a PHP panel from 2014.

---

## 1. Decisions locked with Seth

| Question | Decision | Consequence |
|---|---|---|
| Switch class | **Class-4 + Class-5** | IP-authenticated carrier trunks *and* digest-authenticated retail registrations. Two auth models, two fraud profiles, LCR engine required. |
| Relation to VOS3000/VOIPX | **Greenfield** | No VOS3000 interop or migration shim. Biggest schedule win available. (Distinct from Magnus migration — see below.) |
| v1 scale | **<500 concurrent, <10 CPS** | Single-node v1 is legitimate. But interfaces must not *foreclose* growth: no in-process-only call-path state, no single-writer assumptions in rating. |
| Product model | **Operate it AND license it** | Hard multi-tenancy in v1, not v2. Installer, upgrade path, licensing are first-class deliverables. |
| Dev/lab target | **Dedicated Linux VPS** | Real public IP and real SIP/RTP reachability from day one. **Not** `147.79.78.77` — 1 vCPU, already runs production VOIPX. |
| License | **Proprietary / closed source** | A binding *technical* constraint — see §3. It decides the engine choice. |
| Magnus migration | **First-class product feature** | Seth: *"so we can just ditch magnus, and other people could do the same."* This is the go-to-market, see §6. |
| DDoS resilience | **Headline feature** | See §5. Drives the wedge product in §7. |

**Note on "small scale":** that sets the *deployment* target, not the *design* target.
v1 runs on one box; nothing may assume it always will.

---

## 2. Environment findings (verified on this box)

- Windows Server 2022, 8 GB RAM, 4 logical CPUs.
- **WSL installed but no distribution.** Moot — decision is a dedicated VPS.
- **Missing:** `docker`, `node`, `go`, `rustc`, `psql`. **Present:** `git`, `python` 3.11.
- **No system Java** — JDK 21 Temurin at `C:\Users\Administrator\tools\jdk-21.0.11+10`
  (from VOIPX; `JAVA_HOME` must be set manually). **JDK 25 will be needed** for the
  hot path (Generational ZGC + JEP 491).
- `gh` authenticated as **XYZTheo**, scopes `gist, read:org, repo, workflow`.

**Consequence:** Kamailio/OpenSIPS/rtpengine are Linux-only in any production sense.
The VPS is a prerequisite to the first line of switch code, not a later concern.

---

## 3. ⚠️ Copyleft — the constraint that decides the architecture

**Read before the stack table.** "Proprietary" + the standard VoIP stack is a real
tension, and getting it wrong is expensive *after* you have licensees.

| Component | License | Implication for a proprietary, distributed product |
|---|---|---|
| **OpenSIPS / Kamailio** | GPLv2 | Separate process + network IPC → not a derivative work. A **custom C module would be**, and would have to ship GPL. |
| **rtpengine** | GPLv3 | As above, plus a kernel module. Strictest of the set. |
| **CGRateS** | **AGPLv3** | **Blocker — see below.** |
| **Asterisk** | GPLv2 + purchasable commercial licence | The escape hatch if in-process integration is ever unavoidable. |
| **FreeSWITCH** | MPL 2.0 | *File-level* copyleft — materially friendlier. Preferred B2BUA for this reason. |

**The fortunate convergence:** the architecturally correct design — *keep the SIP
config thin and dumb, push every decision out to our own service over async HTTP* —
**is also the licence-clean design.** Good architecture and legal safety point the
same way. Lean on it.

**Rules this imposes:**

1. **Never write a custom OpenSIPS/Kamailio C module.** Every decision goes over the
   network to our proprietary service. (Also the better design.)
2. **Minimise embedded scripting** in the SIP engine. Async HTTP keeps the boundary
   unambiguous.
3. **Do not redistribute GPL binaries.** The installer pulls OpenSIPS and rtpengine
   from **upstream distro packages** at install time. MEGATRON ships as proprietary
   software that *depends on* separately-installed GPL software — far cleaner than
   bundling and arguing "mere aggregation."
4. **No GPL/AGPL libraries linked into our binaries** — a CI licence-scan gate, not a
   code-review hope.
5. FreeSWITCH (MPL 2.0) is the fallback if in-process media control is ever needed.

### CGRateS: the decision this forces

CGRateS (Go) is the only credible open-source realtime rating engine, and it is
genuinely good — balance reservation, derived charging for reseller margin stacking,
engine-agnostic agents, active development through 2026-08.

**But it is AGPLv3, and we are shipping proprietary software to other operators.**
That is disqualifying for both embedding *and* sidecar-shipping. It also has **no
tagged release since v0.10.5 (2024-07)** — everyone runs master, which is a
supply-chain problem for a commercial product.

**Decision: build our own rating engine in Kotlin. Do not ship CGRateS in any form.**

What we *do* take is the **model**, which is worth more than the code and carries a
decade of telecom domain knowledge: tariff-plan structure, reserve-then-debit balance
semantics, derived charging, the
`Authorize → Initiate → Update → Terminate → ProcessCDR` session lifecycle.

> **Permitted use:** stand CGRateS up in the lab in month one as a *reference
> implementation* to learn the model against. Never in production, never shipped,
> never in the SaaS we operate (the AGPL network clause reaches that too).

> **I am not a lawyer.** Since you intend to *sell* MEGATRON, have a telecom/OSS
> attorney review the redistribution posture before first customer ship. Architecting
> to rules 1–5 now costs nothing and keeps every option open. **Flagging, not blocking.**

---

## 4. Architecture

### 4.1 Topology

```
                    Internet / carrier peers
                              │
              ┌───────────────┴───────────────┐
              │                               │
     ┌────────▼─────────┐           ┌─────────▼──────────┐
     │  HONEYPOT (§5)   │           │  TIER 1 — EDGE     │
     │  decoy SIP on    │           │  OpenSIPS 3.6 LTS  │
     │  unused IPs      │           │  XDP/eBPF drop     │
     │  zero-false-     │──intel──► │  nftables ACL      │
     │  positive signal │           │  pike/htable/      │
     └──────────────────┘           │  ratelimit/secfilter│
                                    │  topoh, TLS term   │
                                    │  STIR/SHAKEN       │
                                    └─────────┬──────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │ TIER 2 — CORE      │
                                    │ registrar (usrloc) │
                                    │ drouting LCR       │
                                    │ dialog + limits    │
                                    │ fraud_detection    │
                                    └──┬──────────────┬──┘
                        async HTTP     │              │  ng protocol
                    ┌──────────────────▼───┐   ┌──────▼─────────┐
                    │ AUTHORIZER (Kotlin)  │   │  rtpengine     │
                    │ authorize + rate     │   │  kernel-mode   │
                    │ + max-duration       │   │  SRTP/DTLS/ICE │
                    │ <5ms, in-memory      │   │  media stats   │
                    └──┬────────────┬──────┘   └──────┬─────────┘
                       │            │                 │
              ┌────────▼───┐  ┌─────▼──────┐   ┌──────▼─────────┐
              │ Redis      │  │ PostgreSQL │   │ TIER 3 — B2BUA │
              │ reserve/   │  │ ledger of  │   │ FreeSWITCH     │
              │ debit, TTL │  │ record, RLS│   │ class-5 only   │
              └────────────┘  └────────────┘   └────────────────┘
                       │
              ┌────────▼──────────────────────────────────────┐
              │ ClickHouse — immutable raw CDR events         │
              │ = the replay log for rerating + fraud analytics│
              └───────────────────────────────────────────────┘
```

### 4.2 Component choices

| Layer | Choice | Why |
|---|---|---|
| **SIP edge + core** | **OpenSIPS 3.6 LTS** (support → 2028-05) | `drouting` is a purpose-built carrier LCR engine (failover, GW probing, weighting) — Kamailio's `lcr`/`carrierroute` are weaker and `carrierroute` has no cost concept. **`fraud_detection` is a native module** monitoring CPM, duration, total calls, concurrency and sequential-call patterns per-user *and* per-prefix with time-of-day windows — Kamailio has no equivalent, and given §5 that is decisive. `clusterer` + bridge replication beats DMQ (whose same-major-version constraint is a real upgrade hazard). |
| | *Not Kamailio* | Its main edge is KEMI (routing logic in Lua/Python) — which we're **deliberately not using** for licence reasons (§3). That removes the principal argument for it. Defensible either way; **pick one and commit** — running both doubles operational surface for nothing. |
| | *Not OpenSIPS 4.0* | Not LTS, support ends 2027-12, and carries the largest core rewrite in project history. Revisit at 4.1/4.2. |
| **Media** | **rtpengine** (mr26.x) + kernel module | No real alternative. Kernel forwarding: **10,000+ concurrent calls at ~30% CPU**. SRTP (SDES + DTLS), full ICE, T.38, SIPREC, recording, and — critically — **bridges encrypted↔cleartext**, which you need because carriers won't do SRTP and WebRTC clients must. |
| **B2BUA** | **FreeSWITCH**, behind the proxy, class-5 features only | MPL 2.0 (licence-friendly), better threading and WebRTC than Asterisk. **Never on the edge.** |
| **Authorizer (hot path)** | **Kotlin/Ktor**, JDK 25, Generational ZGC | §4.4 |
| **Business API** | **Kotlin + Spring Boot 4.1** | ~70% of the code; direct reuse of VOIPX expertise |
| **Node agents** | **Go** static binary | §4.3 |
| **UI** | **TypeScript + React** (Vite, TanStack Router/Query, shadcn/ui) | §6.3 |
| **Ledger + config** | **PostgreSQL 17+** with RLS | ACID for money; RLS as tenancy backstop |
| **Hot state** | **Redis** + Lua atomics | Reserve-then-debit; TTL auto-releases stranded credit |
| **CDR + analytics** | **ClickHouse** | 15–30× compression, sub-second aggregation over billions of rows |
| **Observability** | **Homer/HEP + heplify**, OpenTelemetry, Prometheus/Grafana | Day one. Debugging carrier interconnect without SIP capture is malpractice. |
| **STIR/SHAKEN** | **secsipidx** as a REST sidecar | Decouples signing from the call path; cert rotation without touching SIP |

**Deliberately deferred: Kafka.** At v1 volumes it is install-burden for no gain. The
**immutable raw CDR event table in ClickHouse *is* the replay log** that rerating
needs. Add Kafka as an optional scale-out component when volume demands — behind the
same emit interface.

### 4.3 The empirical numbers that justify this shape

From OpenSIPS's own lab (i7-7700, 4c/8t — deliberately modest hardware):

| Scenario | CPS |
|---|---|
| Stateful transactions only | 13,000 |
| Dialog module + routing | 10,000 |
| Auth, 1k users, **MySQL** | 6,000 (54% CPU — **I/O bound**) |
| Auth **with caching** | 6,000 (MySQL CPU → **0%**) |
| **B2BUA** | **900–1,000** |

Three conclusions that drive the whole design:

1. **B2BUA mode costs an order of magnitude** (13,000 → 900 CPS). This is the
   empirical proof of "proxy everywhere, B2BUA only where required."
2. **Synchronous DB auth halves throughput** and is I/O-bound, not CPU-bound. Cache
   aggressively — or better, keep the data in-process.
3. **Dialog tracking costs ~25% of ceiling** — and we need it for billing. Budget it.

**Transcoding is a separate economy:** the kernel module gives *no benefit* when
transcoding, and capacity collapses to ~400–1,000 concurrent (a **25× reduction**).
Plan transcoding as a separately-scaled pool, never mixed into passthrough capacity.

### 4.4 The hot path — the hardest engineering in the project

**Latency budget.** SIP Timer T1 = 500 ms; a UAC with no response retransmits INVITE.
`100 Trying` exists to buy time — send it **immediately**, before any lookup.

| Step | Budget |
|---|---|
| Send `100 Trying` | immediately, before anything |
| Synchronous in-worker lookup | **<5 ms p99**, hard ceiling 50 ms |
| Anything that could exceed 50 ms | **must be async** (`async` statement / `rest_client` async) |
| Total added post-dial delay | **<100 ms** |

Why synchronous calls are fatal: a SIP worker is **blocked** for the duration. At 5,000
CPS with 64 workers, a 20 ms blocking lookup caps you at 3,200 CPS and one slow query
stalls the node.

**The JVM verdict.** The GC objection is *obsolete*: Generational ZGC (default since
JDK 23) holds pauses at 0.1–0.5 ms regardless of heap — noise against a 10 ms budget.
JEP 491 (JDK 24) removed `synchronized` pinning, clearing the last structural argument
against virtual threads here.

The **real** JVM risks are different, and each has a mandatory mitigation:

| Risk | Mitigation — non-negotiable |
|---|---|
| **JIT warmup** — a cold instance visibly misses SLA for its first minute | Synthetic warmup traffic before the instance joins the dispatcher pool. **In the deploy pipeline**, not a runbook step. |
| **Allocation pressure** — low pause ≠ free allocation | Zero-allocation hot path: preloaded tariff tries, primitive-keyed maps (fastutil), no `Stream`/boxing in the rating loop |
| **Any synchronous DB call** | Tariff/routing/LCR data **resident in-process**, rebuilt from a change stream. Balance reservation = one Redis Lua script. |

> Done right, 10 ms p99.9 is comfortable. Done with Spring MVC + JPA and a JDBC call
> per request, you'll see 80 ms p99 and blame the JVM.

**The escape hatch — build this in deliberately.** Keep the authorizer a small
(~3–5k LOC) single-purpose service behind a strict gRPC/protobuf contract: no shared
libraries with the Spring app, no JVM-specific serialization on the wire. If load
testing says Kotlin can't hold the SLA, rewriting *this one service* in Rust or Go is
a two-month project, not a platform rewrite. **That optionality is worth more than
picking "the fastest language" today** — and it's why we're not reaching for Rust now
(its SIP crates — EZK, rsipstack, rvoip — are all pre-1.0 regardless).

### 4.5 Billing correctness — the three failure modes that lose money

Magnus loses money on all three. These are design requirements, not nice-to-haves.

1. **Lost BYE → infinite dialog → unbilled or over-billed call.** Use *all* of:
   RFC 4028 session timers, in-dialog OPTIONS keepalive, **rtpengine media timeout**
   (the only mechanism that catches media death), and a `dialog` default_timeout
   backstop lowered from 12h to ~4h.
2. **Proxy CDRs don't know media state.** A call can be "answered" with zero audio and
   bill for an hour. **CDR truth = proxy signalling reconciled against rtpengine media
   stats** — design the reconciliation *before* the CDR schema.
3. **Synchronous CDR writes lose money when the DB blinks.** Never write CDRs
   synchronously from the proxy. Emit to a durable queue; a consumer persists.
   Unbillable calls must **fail closed or alarm loudly** — never silently vanish, which
   is Magnus's characteristic failure.

**Zero-balance teardown — layered, complementary:**

| Layer | Mechanism |
|---|---|
| Pre-call | Redis-cached auth + `drouting` LCR — reject unfundable calls at INVITE, <5 ms |
| Setup | `dlg_set_timeout()` = MaxUsage from the authorizer — hard billable bound, **zero ongoing cost** |
| Concurrency | `dialog` profiles per account, cluster-replicated |
| Mid-call | Authorizer-pushed `dlg_bye()` on exhaustion — for what can't be predicted at setup |
| Safety net | Session timers + keepalive + media timeout |

**Money handling:** integer micro-units (`Long`) internally, `BigDecimal` at
boundaries, **never `Double`** — enforced by a detekt rule banning floats in billing
packages. Redis holds *reservations* (TTL-bounded, so a crashed call releases credit
automatically); **PostgreSQL is the ledger of record.** Never let Redis be the only
record of a customer's money.

**Decide explicitly and write it down:** authorizer unreachable → **prepaid fails
closed, trusted postpaid fails open.** Established calls must survive control-plane
restart. Not deciding is not an option.

---

## 5. DDoS &amp; attack resilience — the headline feature

### 5.1 The honest distinction

Two different attacks; only one is solvable on the box:

| | What it is | Solvable by us? |
|---|---|---|
| **Volumetric flood** | Saturating the pipe (10–100 Gbps) | **No — and no software can.** Needs provider scrubbing (OVH/Voxility/Path.net) or BGP blackhole. **Say so plainly in our docs** rather than implying otherwise. |
| **Application/protocol flood** | REGISTER storms, INVITE floods, scanner sweeps, malformed SIP — often only a few thousand pps | **Yes, decisively.** |

**The insight that makes this a winning pitch:** the attacks killing Magnus boxes are
mostly *not* huge. Magnus collapses at low volume because of **architecture** — a PHP
process spawned per call, MySQL write contention, and fail2ban log-scraping that reacts
seconds too late. A few thousand pps of INVITE/REGISTER is enough.

> **MEGATRON survives, on identical hardware, what kills Magnus.** That is
> benchmarkable — and it's the most persuasive thing we can show an operator who got
> paged at 3am last week.

### 5.2 The defence stack — cheapest filter first

Design rule: **cost to reject must be far below cost to send.**

1. **XDP/eBPF at the NIC driver** — drop known-bad before the kernel allocates an
   `sk_buff`. Millions of pps on commodity hardware. **The layer Magnus entirely
   lacks.** Blocklist is a BPF map updated live by the Go agent.
2. **nftables** — trunk IP allowlists, connection limits, geo-blocking.
3. **OpenSIPS, pre-transaction** — reject **before** `t_relay`, before any DB lookup,
   before transaction state is allocated. A rejected packet must never cost a malloc.
   - `secfilter` — User-Agent/domain/header blacklists, SQLi patterns (cheap first pass)
   - `sanity` — malformed SIP dropped immediately
   - `pike` + `htable` — per-source rate tracking → auto-expiring in-memory blocklist
   - `ratelimit` — **cluster-aware** global CPS ceiling; shed load rather than collapse
   - Scanner fingerprinting — `friendly-scanner`, sipvicious, sipcli dropped silently
4. **Never become an amplifier.** Replying to spoofed sources makes us a reflection
   vector *and* doubles our load. **Silently drop** anything already classified hostile.
   Magnus's instinct to politely `403` everything is actively harmful.
5. **Raise attacker cost structurally.**
   - **TLS/TCP-preferred signalling** — a spoofed-source UDP flood cannot complete a
     TCP/TLS handshake. Eliminates the entire spoofed-source class.
   - Registration required before INVITE (retail); trunks IP-allowlisted at nftables.
   - **mTLS from day one** — required for Teams Direct Routing and steadily replacing
     IP allowlists as the carrier trust boundary. Retrofitting cert lifecycle management
     into a live carrier platform is painful; build it in now.
6. **APIBan feed → htable.** Free, curated known-bad SIP sources, trivial to wire. Turn
   it on.
7. **`fraud_detection`** (native OpenSIPS) — CPM, call duration, total calls,
   concurrency and sequential-call patterns, per-user *and* per-prefix, with warning and
   critical thresholds and time-of-day windows. "50 CPM to +234 at 03:00 Sunday" is a
   first-class expressible rule.

**Why this beats fail2ban:** fail2ban parses logs and reacts in *seconds*, misses PJSIP
TLS auth failures entirely, and loses races at high CPS. Rate limiting belongs in the
kernel and signalling planes, reacting in microseconds.

### 5.3 The honeypot — a sensor, not a shield

Seth's instinct is good and we should build it — but the framing needs correcting,
because it determines what we promise.

**It will not absorb a DDoS.** A flood saturating the uplink hits every IP on that
uplink; a decoy listening on one changes nothing about the pipe. We should not ship
that claim.

**What it's genuinely excellent at is better than the original idea.** A decoy SIP
endpoint on unused IPs that *no legitimate traffic has any reason to touch* means **any
packet arriving is malicious with essentially zero false positives.** Clean signal is
exactly what blocklists normally lack. That gives:

- **Pre-emptive blocking.** Attackers sweep IP ranges sequentially — they hit the decoy
  *before* the real SIP edge. We push them into the XDP map **seconds ahead of the
  attack landing.**
- **Zero false positives.** No risk of blocking a real customer — which is the failure
  mode that makes operators disable automated blocking entirely.
- **Live threat intel:** new tooling, credential dictionaries, targeted extension ranges.

**And this is where it becomes a moat.** Because MEGATRON runs at *many* operators, we
offer an **opt-in shared reputation feed**: every installation's honeypot contributes,
every installation gets protection. An attacker burns their infrastructure on the first
MEGATRON box they touch and is blocked fleet-wide before reaching the second.

That is a genuine network effect that compounds with every customer — and
**MagnusBilling architecturally cannot replicate it.** Design it **opt-in**, anonymised
(attacker IPs and signatures only — *never* customer identifiers, numbers, or CDR data),
with an explicit privacy stance. We are asking licensees to trust us with telemetry from
their production switch.

### 5.4 Provable, not asserted

Resilience claims get benchmarked, published, and re-run in CI: SIPp flood scenarios
plus sipvicious/sippts sweeps against a reference box, recording pps absorbed and the
point at which legitimate calls degrade. **"Here is the benchmark, here is the same test
against Magnus"** is the sales asset — and it keeps us honest.

---

## 6. Making Magnus operators switch

### 6.1 The threat model we're inverting

Magnus's real CVE record, and the design rule each one produces:

| CVE | Root cause | MEGATRON's structural answer |
|---|---|---|
| **CVE-2023-30258** — unauth **RCE**, CISA-KEV, mass-exploited | `lib/icepay/icepay.php` ships leftover demo code: `exec("touch " . $_GET['democ'] . '.txt')`. In the web root, **outside the router** — no auth, no CSRF | Kotlin `ProcessBuilder(listOf(...))` takes an **argv vector** — no shell, no metacharacter to escape. detekt bans `Runtime.exec`. Better: **the API never shells out at all** — provisioning goes to the Go agent as typed messages with a closed verb set. The web tier *cannot express* "run this command." |
| **CVE-2025-2609** — unauth stored XSS (8.2) | Username from *failed* logins stored unsanitised, rendered to admins at `/logUsers/read` | Output-encode by default; never trust data because its request was rejected |
| **CVE-2025-2610** — stored XSS (7.6) | Alarm message unencoded, amplified because **APIs return `text/html` not `application/json`** | JSON-only + `nosniff` |
| Default creds `root`/`magnus` | Ships bootable with known credentials | Forced credential set at install; no shipped default can boot |
| fail2ban → root | `asterisk` has `NOPASSWD` sudo for `fail2ban-client`; rewrite `actionban` → SUID shell. **Shipped config**, not a CTF artifact | No NOPASSWD sudo for anything that executes configured commands |

*(CVE-2023-30259 is LibreCAD, not Magnus — several roundups conflate them. Don't repeat
that error in our docs.)*

**The systemic rules**, beyond individual CVEs:

- Single front controller; **nothing executable under the web root**
- **jOOQ + Flyway**, not JPA/Hibernate — types generated from the live schema, so a
  renamed column is a compile error; build fails on plain SQL outside an allowlist
- **Spring Security deny-by-default** (`anyRequest().denyAll()`) plus a build-time test
  walking `RequestMappingHandlerMapping` asserting every endpoint carries explicit
  `@PreAuthorize`. ~40 lines; **highest-ROI security artifact in the project**
- **kotlinx.serialization** — compile-time serializers, sealed hierarchies, no
  reflective type resolution, no gadget chains; Java native serialization off
- **Vault/OpenBao dynamic DB credentials**; `value class Secret<T>` whose `toString()`
  returns `"****"`. **The SIP edge holds no DB credential** — its only capability is
  asking the authorizer a question. Assume the edge can be compromised.
- **Tenancy in four layers:** `TenantId` value class (there is no `findAll()`) → jOOQ
  DAOs with non-optional tenant predicates → **Postgres RLS** (applies even when a dev
  forgets the `WHERE`) → auto-generated cross-tenant probe suite. Reseller hierarchies
  as `ltree`/closure table so RLS evaluates ancestry rather than special-casing in app
  code, where it *will* be forgotten.
- Two identity systems, deliberately **not** unified: OIDC (Zitadel/Keycloak) for
  portal/admin; SIP digest against the subscriber store for endpoints. Merging them ends
  with SIP passwords stored reversibly in the IdP.

**On memory safety, honestly:** ~half of Asterisk's active CVEs are memory-related and
port 5060 is scanned continuously — but we don't fix that by choosing a memory-safe
language, because **we are not rewriting OpenSIPS.** The mitigation is architectural: run
the edge unprivileged and seccomp-confined on a dedicated host, give it no credentials,
and keep 90% of the platform in memory-safe Kotlin/Go/TypeScript. Memory safety is a
reason to write *less C*, not to pick Rust where Kotlin is already safe.

### 6.1b Clean-room — Magnus is a requirements source, never a design source

Seth, 2026-08-06: *"researching based on magnus probably is a bad start since their
code is shit — I just want all the functionality of what they offer plus more without
all the headache of their terrible infrastructure and code."*

**Agreed, and this is already how the plan is built.** Magnus is used for exactly two
things, neither of which is architectural:

1. **A feature checklist** — what functionality operators actually depend on (§6.2.2).
2. **A threat model** — an inventory of what *not* to do (§6.1).

Nothing in §4 derives from Magnus. The architecture comes from the carrier-grade
reference designs: the OpenSIPS/rtpengine topology, **Sipwise NGCP** (the reference
open-source class-5 platform, which validates this exact shape), and **Yeti-Switch**
(the closest existing class-4 analogue). Those are the systems worth studying.

**And the quality instinct coincides with the correct legal posture.** Magnus's core
is LGPL-3.0; ASTPP and CGRateS are AGPL. For a **proprietary** product, deriving
implementation from any of them would contaminate our licence position. So the rule is
firm and serves both goals at once:

- **Do not read their PHP for implementation guidance.** Not their AGI script, not
  their rating logic, not their controllers.
- **The one permitted exception is their database *schema*** — needed to write the
  importer (§6.2). A schema you must read to parse a customer's own data export is a
  data format, not borrowed design. Confine that knowledge to the importer module and
  document why.
- Same rule for CGRateS: take the *model* from documentation (§3), never the code.

### 6.1c Beyond parity — what Magnus structurally cannot do

"All their functionality **plus more**." Parity is the price of entry; these are the
things our architecture makes possible and theirs forbids:

| Capability | Why Magnus can't |
|---|---|
| **Survives application-layer DDoS** | PHP-process-per-call + MySQL contention + log-scraping fail2ban. Architectural, not tunable. (§5) |
| **Fleet-wide shared threat intel** | No multi-install telemetry fabric, and no reason for operators to trust one. (§5.3) |
| **Mid-call credit enforcement** | Charges computed at hangup, so simultaneous long calls blow past credit limits before any debit lands. (§4.5) |
| **Billing that knows about media** | Signalling-only CDRs bill zero-audio calls at full rate. We reconcile against rtpengine media stats. (§4.5) |
| **Safe, idempotent, auditable rerating** | Manual and error-prone there; a first-class operation here. (Phase 4) |
| **True multi-tenant isolation** | Bolted-on user types vs. RLS + type-level tenancy + generated probe suite. (§6.1) |
| **Sub-second reporting over years of CDRs** | MySQL with archive tables vs. ClickHouse. |
| **Carrier-grade capacity per box** | ~13,000 CPS proxy ceiling vs. a per-call PHP process. (§4.3) |
| **mTLS / STIR-SHAKEN as first-class** | Retrofitted at best; regulatory table stakes for US transit. (§5.2) |
| **An install that works first time** | (§6.3) |

### 6.2 The migration path — this is the go-to-market

Magnus's schema is a known, flat set of `pkg_*` tables. An importer is entirely
tractable and is **the single highest-leverage adoption feature we can build.**

1. **Importer** — ingest a `mysqldump`, map `pkg_user`, `pkg_sip`, `pkg_trunk`,
   `pkg_rate`, `pkg_prefix`, `pkg_did`, `pkg_plan`, `pkg_refill`, `pkg_cdr` onto our
   model. Must produce a **reconciliation report** — what mapped, what didn't, what
   needs a human decision — never silently drop rows. An operator's rate deck *is* their
   business.
2. **Feature-parity matrix** — a tracked, published checklist (trunks, LCR, tariffs,
   billing increments, DIDs, calling cards/PIN, vouchers/refills, resellers &amp; agents,
   SMS, IVR/queues, recording, invoicing/taxes, payment gateways, prepaid/postpaid,
   credit limits, concurrency caps, ASR/ACD, CDR reporting, portal, API). Nobody
   switches if one feature they depend on is missing. Gaps must be **known and
   published**, not discovered by a customer.
3. **Shadow/cutover mode** — point a fraction of traffic at MEGATRON and diff billing
   output against Magnus before committing. **Nobody moves live telephony revenue on
   faith.**

### 6.2b The setup wizard — "easy as pie"

Seth, 2026-08-06: *"make a setup wizard that makes deploying this easy as pie."*

This is the right instinct and it belongs at the centre of the product, not at the end.
**Install day is where MagnusBilling is worst** — a pile of shell scripts, manual
Asterisk config, hand-edited `manager.conf`, and default credentials nobody changes.
The wizard is simultaneously our best adoption lever and our strongest security control.

**Design:**

- **One command to start.** `curl … | sh` fetches a signed installer binary (Go, static)
  — no runtime prerequisites on a fresh Debian/Ubuntu box.
- **Preflight checks that actually help.** Verify CPU/RAM, kernel version (XDP support),
  public IPv4, DNS, that ports 5060/5061/RTP range are reachable *from outside*, and that
  nothing else is bound to them. **Report what's wrong and how to fix it** — the single
  biggest source of "it doesn't work" support load in this industry is a switch behind a
  NAT or firewall nobody checked.
- **Guided TUI, plus a non-interactive mode.** Interactive for humans; `--config
  answers.yml` for repeatable/automated installs. The wizard *writes* the answers file
  so a manual install becomes a reproducible one.
- **It installs the GPL components from distro repos** (per §3), never from us.
- **Security is enforced, not suggested.** The wizard *cannot* complete with a default
  password. It generates strong credentials, provisions TLS certs (Let's Encrypt or
  supplied), binds admin interfaces to localhost by default, sets up the nftables/XDP
  baseline, and prints a one-time recovery code. **There is no path through the wizard
  that produces an insecure install** — that is the direct structural answer to Magnus's
  `root`/`magnus` default.
- **Magnus migration is a wizard step**, not a separate manual chore: "Do you have an
  existing MagnusBilling install? Point me at a dump." → importer → reconciliation
  report → shadow mode offered. This is how §6.2 actually reaches operators.
- **Ends with verification, not a prompt.** The wizard places a real test call through
  the new stack, confirms media flowed, and shows a green check — so the operator's
  first experience is *proof it works*, not a login screen and a hope.
- **Same wizard upgrades.** `megatron upgrade` uses the same engine, with backup and
  rollback. Upgrade pain is a top-three operator complaint about Magnus.

**Deliverable in Phase 2** (with the shield, so the wedge product installs itself
cleanly) and extended in Phase 8.

### 6.3 "Designed nicely"

Seth wants the platform to *feel* considered. Concretely:

- Magnus's admin is **ExtJS 6** — heavy, dated, visibly 2014. The UI is how MEGATRON
  signals it's a different class of product, and where a switching operator forms their
  first impression.
- A **design system** (tokens, components, density, light/dark) defined *before* screens
  are built, not retrofitted.
- Beyond the UI: coherent API naming, predictable error envelopes, real documentation,
  and an installer that works the first time. **"Designed nicely" includes install
  day** — precisely where Magnus is worst.
- API client **generated from OpenAPI**, so a tariff field rename breaks the build
  rather than a customer's invoice.

---

## 7. Build sequence

**Phase 0 — Foundation.** Create `XYZTheo/MEGATRON` (private) via `gh`; local path
`C:\Users\Administrator\MEGATRON`. Provision the Linux VPS. Commit this document as
`docs/ARCHITECTURE.md`. Inherit VOIPX conventions: to-dos as **GitHub Issues**, ship on
`feature/*` → PR, never straight to `main`. Set up CI with the licence-scan gate (§3)
and the endpoint-auth enumeration test (§6.1) from the very first commit — these are
cheap now and retrofit badly.

**Phase 1 — One call, end to end.** OpenSIPS + rtpengine + a stub authorizer on the
VPS. A SIP call in one side and out the other, media anchored, CDR emitted. Homer
capturing from day one. Edge hardening (§5.2 layers 2–4, 6) lands here because it is
mostly config and costs almost nothing at this stage.

**Phase 2 — ⭐ The DDoS Shield (the wedge).** *This is the strategic recommendation of
this plan and the reason to sequence it here rather than last.*

Package the §5 defence stack as a **standalone product that sits in front of an existing
MagnusBilling install** — no migration, no data movement, no risk to their switch. It
solves the problem they have **this week**.

Why this is the right move:
- It is **months faster to ship** than the full platform, and the market window is open now.
- It gets MEGATRON **installed at their site** and creates the relationship.
- It starts the **threat-intel network effect** (§5.3) before the platform even exists —
  every shield deployed makes every other one better.
- It de-risks everything: revenue and real production traffic feedback long before v1.
- **Their pain becomes our proof.** An operator who watched the shield absorb an attack
  needs no convincing about the switch.

The shield is the wedge; the importer (§6.2) is the conversion.

**Phase 3 — Rating engine.** Kotlin authorizer per §4.4: in-process tariff tries,
Redis reserve-then-debit Lua atomics, Postgres ledger, `dlg_set_timeout()` max-duration.
Property-based tests (cost monotonic in duration, no negative cost, rerating idempotent
under unchanged tariff) plus golden-file tests from anonymised real CDRs.

**Phase 4 — CDR pipeline + reconciliation.** ClickHouse raw immutable event table,
signalling↔media reconciliation (§4.5), rerating as a first-class idempotent auditable
operation — not the manual, error-prone thing it is in Magnus.

**Phase 5 — Provisioning API + tenancy.** Spring Boot 4.1, jOOQ, the four-layer tenancy
model, reseller hierarchy, Go node agents with a closed verb set.

**Phase 6 — UI + portal.** Design system first, then admin console and customer portal
against the generated OpenAPI client.

**Phase 7 — Magnus importer + parity + shadow mode.** §6.2 in full.

**Phase 8 — Packaging.** Installer (pulling GPL components from distro repos per §3),
upgrade path, licensing, documentation.

---

## 8. Verification

Telephony testing is not ordinary testing.

| What | How |
|---|---|
| **Functional + load** | **SIPp** scenarios checked into the repo as XML, run in CI against an ephemeral OpenSIPS + rtpengine + authorizer stack via Testcontainers. Every routing change ships with a scenario. |
| **Capacity** | Load at target CPS *and* target concurrent calls — they stress different things (transaction rate vs dialog memory). Measure **p99.9**, never mean. |
| **Security regression** | **sipvicious** (svmap/svwar/svcrack) and **sippts** on every build — extension enumeration and digest cracking must *fail* against our build. |
| **DDoS resilience** | Flood scenarios per §5.4, published as benchmarks, re-run in CI. Head-to-head against a reference Magnus install. |
| **Rating correctness** | Kotest property-based tests + golden files from anonymised real CDRs |
| **Tenancy** | Auto-generated cross-tenant probe suite: authenticate as A, request B's IDs, assert 403/404. New endpoints covered automatically. |
| **Chaos** | Kill the authorizer mid-call; assert the configured fail direction (§4.5). Assert established calls survive control-plane restart. |
| **Migration** | Import a real anonymised Magnus dump; diff billing output call-for-call against the source system. |

---

## 9. Open items

- **VPS provisioning** — needs a provider and spec. Suggest 8+ cores, public IPv4, and
  a provider with DDoS protection (relevant given §5.1 — we can't solve volumetric
  ourselves, so the host must).
- **Legal review** of the §3 redistribution posture before first customer ship.
- **Shared-intel privacy stance** — needs to be written before the first shield ships,
  not after.
- JDK 25 needs installing alongside the existing JDK 21 (VOIPX pins 21).
