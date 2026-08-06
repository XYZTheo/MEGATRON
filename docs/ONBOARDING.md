# MEGATRON — Developer Onboarding

**Start here.** This explains what the system is, how a call actually flows
through it, and why it is shaped the way it is.

Reading order:

1. This document — the mental model
2. [`CONTRIBUTING.md`](../CONTRIBUTING.md) — the rules, several CI-enforced
3. [`ARCHITECTURE.md`](ARCHITECTURE.md) — the full design and its reasoning
4. [`../edge/README.md`](../edge/README.md) — the shield tier

---

## 1. What MEGATRON is

A **Class-4 + Class-5 VoIP softswitch with integrated realtime billing.**

- **Class-4** = wholesale carrier transit. IP-authenticated trunks, least-cost
  routing, rate decks, margin control. No end users.
- **Class-5** = retail. Customers register softphones, buy DIDs and minutes,
  get hosted-PBX features.

MEGATRON does both, which means **two authentication models and two fraud
profiles** coexisting in one platform. Most of the apparent complexity traces
back to that.

It replaces **MagnusBilling** and **VOS3000**. It is **proprietary**, and it is
built both to be operated by us and licensed to other operators.

## 2. Why it exists

Not a greenfield preference — a response to specific, documented failures.

**MagnusBilling** carries an unauthenticated RCE (CVE-2023-30258, CISA-KEV
listed, mass-exploited by botnets) caused by leftover *demo code* calling
`exec()` on a raw GET parameter, in a file sitting outside its auth framework.
Plus two stored-XSS CVEs, shipped default credentials (`root`/`magnus`), and a
`NOPASSWD` sudo rule that turns web-user RCE into root. Its architecture invites
all of this: a PHP process spawned per call, a web root full of executable
vendor code, secrets in world-readable config.

**VOS3000** has **no authentication at all** on its third-party HTTP interface —
a source-IP allowlist in a Tomcat config file is the entire security model.

And right now, **MagnusBilling operators are being knocked offline by DDoS.**
Not because the attacks are large — because a PHP-process-per-call architecture
with log-scraping `fail2ban` collapses under a few thousand packets per second.

That last point is the commercial thesis: **MEGATRON survives, on identical
hardware, what kills Magnus.** It is benchmarkable, and it is why the DDoS
shield ships before the switch itself.

## 3. The mental model: four tiers, two trust domains

```
      Internet ──────────────────────────── PUBLIC TRUST DOMAIN
         │                                  (assume compromised)
    ┌────┴─────┐         ┌──────────────┐
    │ HONEYPOT │         │ EDGE / SHIELD│   stateless · no credentials
    │  decoy   │──intel─▶│  OpenSIPS    │   disposable · cattle
    └──────────┘         └──────┬───────┘
                                │
    ═══════════════════ private network, allowlisted ════════════
                                │
                         ┌──────┴───────┐
                         │     CORE     │   PRIVATE TRUST DOMAIN
                         │   OpenSIPS   │   (no internet route)
                         │  registrar   │
                         │  LCR/dialog  │
                         └──────┬───────┘
                                │ async HTTP
                         ┌──────┴───────┐
                         │  AUTHORIZER  │   Kotlin/Ktor · the hot path
                         │ authorize +  │   <5ms · all data in-process
                         │ rate + limit │
                         └──┬────────┬──┘
                            │        │
                    ┌───────┴──┐  ┌──┴──────────┐
                    │  Redis   │  │ PostgreSQL  │
                    │reservation│ │   ledger    │
                    └──────────┘  └─────────────┘
```

**The single most important thing to understand:** the core has **no route from
the public internet**. It binds a private interface and accepts traffic only
from allowlisted edge IPs. An attacker cannot flood it, scan it, or reach a
port — not because we filter well, but because there is no path.

The edge, correspondingly, **holds nothing worth stealing**: no database
credential, no customer data, no tariffs, no authorization logic. Its only
capability is asking the core a narrow question. A fully compromised edge is
destroyed and reprovisioned; it is cattle.

That split is what makes an attack a bad hour for one operator instead of a
platform-wide outage with billing corruption.

## 4. How a call actually flows

### 4.1 An INVITE arrives at the edge

Checks run **cheapest-first**, and every rejection happens **before
`t_relay()`** — before transaction state is allocated, before any lookup. The
governing rule is *cost to reject must be far below cost to send*: a rejected
packet must never cost us a `malloc`.

| Order | Check | On failure |
|---|---|---|
| 1 | `max-forwards` | drop |
| 2 | **Blocklist** (`cachedb_local`, O(1)) | **drop, silently** |
| 3 | `sipmsg_validate()` — malformed SIP | `400`, one diagnostic |
| 4 | Scanner fingerprint (`sipvicious`, `friendly-scanner`…) | blocklist 1h, **drop silently** |
| 5 | `pike` per-source flood detection | blocklist 10m, **drop silently** |
| 6 | `ratelimit` global CPS ceiling (SBT) | `503` — shed, don't collapse |

**Why silent drops matter:** replying to a spoofed source makes us a
reflection/amplification vector *against a third party*, and doubles our own
work per hostile packet. Magnus politely `403`s everything, which under attack
is actively harmful. A scanner that gets nothing at all cannot distinguish us
from an unused IP.

Survivors are record-routed, topology-hidden, and relayed to the core.

### 4.2 The core decides

The core authenticates (digest for retail, IP for trunks), then asks the
**authorizer** one question over async HTTP:

> *May this call proceed, at what rate, and for how long at most?*

### 4.3 The authorizer answers — in under 5 ms

This is the hardest engineering in the project, and the latency budget explains
most of its design.

SIP Timer T1 is 500 ms: a caller with no response retransmits the INVITE. `100
Trying` exists to buy time and is sent **immediately**, before any lookup. After
that:

| Step | Budget |
|---|---|
| Synchronous in-worker lookup | **< 5 ms p99**, hard ceiling 50 ms |
| Anything that could exceed 50 ms | **must be async** |
| Total added post-dial delay | < 100 ms |

**Why a synchronous database call is fatal:** a SIP worker is *blocked* for the
duration. At 5,000 CPS with 64 workers, a 20 ms blocking lookup caps you at
3,200 CPS, and one slow query stalls the entire node. OpenSIPS's own lab data
shows auth against MySQL is I/O-bound and roughly halves throughput; with
caching, database CPU drops to zero.

So the authorizer holds **tariff, routing and LCR data resident in-process**,
rebuilt from a change stream. It does not query Postgres on the call path.

Balance is handled as **reserve-then-debit**: a Redis Lua script atomically
reserves a slice of credit rather than decrementing a balance. The reservation
carries a TTL, so a crashed call or a dead node releases the credit
automatically instead of stranding it. **PostgreSQL remains the ledger of
record** — Redis holds working state, never the only record of a customer's
money.

The answer includes a **max duration**, which the core sets via
`dlg_set_timeout()`. That is a hard billable bound enforced by the proxy at
**zero ongoing cost** — no polling. Mid-call teardown (`dlg_bye()`) is reserved
for what genuinely cannot be predicted at setup.

### 4.4 Media

Media is anchored at **rtpengine**, which forwards RTP in a kernel module —
10,000+ concurrent calls at roughly 30% CPU.

Anchoring is the default, not an optimisation to avoid. Skipping it costs you
NAT traversal, recording, SRTP↔RTP bridging, transcoding, topology hiding, and —
critically for billing — **any knowledge of whether audio actually flowed**.
Direct RTP is a per-route opt-in for trusted public carrier transit only.

> Transcoding is a different economy: the kernel module gives **no benefit**
> when transcoding, and capacity collapses from 10,000+ to a few hundred
> concurrent. Plan it as a separately scaled pool. Never mix it into
> passthrough capacity planning.

### 4.5 The call ends

CDRs are **never written synchronously from the proxy**. They are emitted to a
durable path and persisted by a consumer, so a database blip cannot lose
revenue.

Three failure modes are designed against explicitly, because Magnus loses money
on all three:

1. **Lost BYE → infinite dialog.** Mitigated with *all* of: RFC 4028 session
   timers, in-dialog OPTIONS keepalive, rtpengine media timeout, and a lowered
   dialog timeout backstop.
2. **Signalling doesn't know about media.** A call can be "answered" with zero
   audio and bill for an hour. **CDR truth = signalling reconciled against
   rtpengine media stats.** Design the reconciliation before the CDR schema.
3. **Silent CDR loss.** Unbillable calls must **fail closed or alarm loudly**,
   never vanish — Magnus's characteristic failure ("call completed, no CDR").

## 5. The stack, and why

| Layer | Choice | The reason |
|---|---|---|
| SIP edge + core | **OpenSIPS 3.6 LTS** | `drouting` is a real carrier LCR engine; **`fraud_detection` is a native module** (Kamailio has no equivalent) — decisive given our threat model. LTS to May 2028. |
| Media | **rtpengine** | Kernel-mode forwarding. No real alternative. |
| B2BUA | **FreeSWITCH**, behind the proxy | MPL 2.0 (licence-friendly). **Never on the edge** — B2BUA mode costs an order of magnitude (13,000 → ~900 CPS). |
| Hot path | **Kotlin/Ktor**, JDK 25 | See below |
| Business API | **Kotlin + Spring Boot 4.1** | ~70% of the code; reuses existing team expertise |
| Node agents | **Go** static binary | A JVM per switch node is 200–400 MB competing with rtpengine for page cache, plus a JRE to patch everywhere |
| UI | **TypeScript + React** | Data-dense admin console |
| Ledger | **PostgreSQL** + RLS | ACID for money; RLS as the tenancy backstop |
| Hot state | **Redis** + Lua | Atomic reserve-then-debit |
| CDR / analytics | **ClickHouse** | The immutable raw event table *is* the rerating replay log |
| SIP observability | **Homer / HEP** | Debugging carrier interconnect without SIP capture is malpractice |

**On the JVM for a hot path** — the usual objection is obsolete. Generational
ZGC (default since JDK 23) holds pauses at 0.1–0.5 ms regardless of heap size,
which is noise against a 10 ms budget, and JEP 491 removed `synchronized`
pinning for virtual threads.

The *real* risks are different, and each has a mandatory mitigation:

- **JIT warmup** — a cold instance visibly misses SLA for its first minute.
  Synthetic warmup traffic before it joins the dispatcher pool. **In the deploy
  pipeline**, not a runbook step.
- **Allocation pressure** — low pause does not mean free allocation. Zero-alloc
  hot path: preloaded tariff tries, primitive-keyed maps, no streams or boxing
  in the rating loop.
- **Any synchronous DB call** — see §4.3.

The authorizer is deliberately kept small (~3–5k LOC) behind a strict contract,
with no shared libraries with the Spring app. If measurement ever says Kotlin
cannot hold the SLA, rewriting *that one service* in Rust or Go is a two-month
project rather than a platform rewrite. **That optionality is worth more than
picking the fastest language up front.**

## 6. Things that will surprise you

**OpenSIPS is not Kamailio.** Most SIP advice online is Kamailio-flavoured and
will not load. No `htable`, no `sanity`, no `secfilter`. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md#verifying-claims-before-you-write-config).

**We cannot solve volumetric DDoS, and we say so.** If the uplink is saturated,
packets die upstream of our NIC. That needs provider scrubbing or BGP
blackholing. What we solve — decisively — is *application-layer* floods, which
is what actually kills Magnus boxes. Our documentation must state this plainly
rather than implying otherwise.

**The honeypot is a sensor, not a shield.** It cannot absorb a flood. Its value
is that a decoy SIP endpoint on unused IPs means **any packet arriving is
malicious with essentially zero false positives** — and because attackers sweep
ranges sequentially, they hit the decoy *before* the real edge, letting us block
them seconds ahead of the attack landing.

**CGRateS is disqualified despite being good.** It is the only credible
open-source realtime rating engine, but it is AGPLv3 and we ship proprietary
software to licensees. We take the *model* from its documentation and build our
own. See [`CONTRIBUTING.md`](../CONTRIBUTING.md#licence-discipline).

**Fail direction is a business decision.** Authorizer unreachable → prepaid
fails **closed**, trusted postpaid fails **open**. Explicit in config, never
accidental.

## 7. Where the project actually is

**Early.** Phase 0 complete, Phase 2 started.

| Phase | State |
|---|---|
| 0 — Foundation | ✅ repo, licence, architecture, contributing |
| 1 — One call end to end | ⬜ **blocked on VPS provisioning** |
| 2 — DDoS shield (the wedge) + setup wizard | 🟡 edge config written, unvalidated |
| 3 — Rating engine | ⬜ |
| 4 — CDR pipeline + reconciliation | ⬜ |
| 5 — Provisioning API + tenancy | ⬜ |
| 6 — UI + portal | ⬜ |
| 7 — Magnus importer + shadow mode | ⬜ |
| 8 — Packaging + installer | ⬜ |

⚠️ **Nothing has been run yet.** No Linux host exists for the project. The
OpenSIPS and nftables configs were written against verified 3.6 documentation
but have never been loaded by a live binary. Files carrying this caveat say so
explicitly.

**The blocker is a VPS** — 8+ cores, public IPv4, and a provider that includes
DDoS protection (since we cannot solve volumetric ourselves, the host must).

## 8. Why Phase 2 comes before the switch

Counterintuitive, deliberate, and commercially the most important decision in
the plan.

Magnus operators are being attacked **now**. The shield can be packaged as a
**standalone product that sits in front of an existing MagnusBilling install** —
no migration, no data movement, no risk to their switch.

- It ships **months** before the full platform, while the window is open.
- It gets MEGATRON **installed at their site** and builds the relationship.
- It starts the **fleet-wide threat-intel network effect** before the platform
  exists — every shield deployed makes every other one better, which is a moat
  Magnus architecturally cannot replicate.
- It de-risks everything: real production traffic and revenue long before v1.
- **Their pain becomes our proof.** An operator who watched the shield absorb an
  attack needs no convincing about the switch.

The shield gets us in the door. The Magnus importer converts them.
