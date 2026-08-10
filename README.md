# MEGATRON

**A secure, carrier-grade Class-4 + Class-5 VoIP softswitch with integrated realtime billing.**

Proprietary. © 2026. All rights reserved. See [LICENSE](LICENSE).

---

> **New here? Read [`docs/PRODUCT.md`](docs/PRODUCT.md) first.** It is short, and it
> is the only document that describes the business this has to serve on day one.
> Everything below is what the platform grows into; PRODUCT.md is what it must do
> in v1 and who for. Where they disagree, PRODUCT.md wins.
>
> The whole v1 business in one line: **trunk in → rate → authenticate → trunk out
> → bill**, operated through a **Telegram bot**, built this way because the owner's
> MagnusBilling keeps getting attacked.

---

## What this is

MEGATRON is a VoIP softswitch and billing platform built to replace **MagnusBilling**
and **VOS3000** — matching their functionality while eliminating, by construction, the
classes of security defect that make both platforms dangerous to operate.

It is designed to be **operated by us** and **licensed to other operators**.

## Why it exists

The two incumbent platforms are structurally unsafe:

- **MagnusBilling** carries an unauthenticated RCE (CVE-2023-30258, CISA-KEV listed,
  mass-exploited by botnets) caused by leftover demo code calling `exec()` on a raw GET
  parameter from a file sitting outside the auth framework — plus two stored-XSS CVEs,
  shipped default credentials, and a `NOPASSWD` sudo rule that turns web-user RCE into
  root. Its architecture invites this: a per-call PHP process, a web root full of
  executable vendor code, and secrets in world-readable config.
- **VOS3000** has **no authentication at all** on its third-party HTTP interface,
  relying on a source-IP allowlist in a Tomcat config file.

Beyond security, MagnusBilling operators are currently being knocked offline by
application-layer DDoS — not because the attacks are large, but because a
PHP-process-per-call architecture with log-scraping fail2ban collapses under a few
thousand packets per second.

## Design principles

1. **Dangerous things are impossible, not discouraged.** No shell-out on any request
   path. No raw SQL. Deny-by-default routing. Tenancy enforced at the type, query, and
   database layers.
2. **Don't rebuild solved problems.** SIP signalling, media relay, and packet capture
   are 25-year-old solved problems. We build the rating engine, the fraud layer, the
   provisioning model, and the operator experience — which is where the incumbents are
   actually weak.
3. **Defensible by default.** Velocity caps, destination allowlists, mid-call credit
   enforcement, and TLS are on out of the box, not opt-in.
4. **Prove it, don't claim it.** Resilience and rating correctness are benchmarked in
   CI, not asserted in marketing.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design, including the
threat model, stack selection rationale, and licensing constraints.

**Summary of the stack:**

| Layer | Technology |
|---|---|
| SIP edge + core proxy | OpenSIPS 3.6 LTS |
| Media relay | rtpengine (kernel module) |
| B2BUA (class-5 features only) | FreeSWITCH |
| Realtime authorizer / rating hot path | Kotlin + Ktor, JDK 25 |
| Business API | Kotlin + Spring Boot 4.1 |
| Switch-node agents | Go |
| Admin UI + customer portal | TypeScript + React |
| Ledger + provisioning | PostgreSQL (RLS) |
| Hot state (balance reservation) | Redis |
| CDR + analytics | ClickHouse |
| SIP observability | Homer / HEP |

## Status

**Phase 0 — foundation.** Not yet functional. See the build sequence in
`docs/ARCHITECTURE.md` §7.

## Development conventions

- To-do list is **GitHub Issues**. No ROADMAP file.
- Ship on a `feature/*` branch → PR. Never straight to `main`.
- CI enforces the licence-scan gate and the endpoint-authorization enumeration test
  from the first commit.

## A note on MagnusBilling source

**Do not read MagnusBilling, ASTPP, or CGRateS source code for implementation
guidance.** Those projects are LGPL/AGPL; MEGATRON is proprietary, and derivation would
contaminate our licence position. Magnus is used only as (a) a feature checklist and
(b) a threat model.

The single permitted exception is MagnusBilling's **database schema**, which is
required to write the migration importer. That knowledge is confined to the importer
module and documented there.
