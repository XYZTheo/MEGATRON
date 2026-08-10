# Contributing to MEGATRON

Read this before your first commit. Most of it is short.

MEGATRON exists because the two incumbent platforms in this space are
structurally unsafe. Everything below is a rule that keeps us from becoming a
third one. These are not style preferences — several are enforced by CI, and
the rest are the difference between this project having a point and not.

---

## The five hard rules

### 1. Never shell out on a request path

MagnusBilling's flagship CVE ([CVE-2023-30258](https://nvd.nist.gov/vuln/detail/CVE-2023-30258),
CISA-KEV listed, mass-exploited by botnets) is one line:

```php
exec("touch " . $_GET['democ'] . '.txt');
```

Unauthenticated remote code execution, because PHP's `exec()` takes a *string*
and hands it to `/bin/sh`, and because the file sat in the web root outside the
auth framework.

In MEGATRON:

- Kotlin's `ProcessBuilder(listOf("cmd", arg))` takes an **argument vector**.
  There is no shell and therefore no metacharacter to escape.
- **Better: the API layer never shells out at all.** Anything that must happen
  on a switch node goes to the Go node agent as a **typed message with a closed
  verb set**. The web tier physically cannot express "run this command", because
  no such verb exists.

`Runtime.exec` is banned by a detekt rule. `ProcessBuilder` is confined to one
audited class. If you need a new node-side operation, **add a verb to the agent
protocol** — do not add a shell call.

### 2. No raw SQL, ever

Use **jOOQ**. Types are generated from the live schema, so a renamed column is a
compile error rather than a runtime surprise in an invoice.

The build fails on `DSL.field(String)` and other plain-SQL escape hatches
outside an allowlisted package. If you think you need one, you almost certainly
need a better jOOQ expression — ask first.

**We deliberately do not use JPA/Hibernate.** JPQL string building reintroduces
injection, and lazy loading makes hot-path latency unpredictable.

### 3. Endpoints are deny-by-default

Spring Security is configured with a terminal `anyRequest().denyAll()`. A new
controller is **unreachable until you explicitly authorize it**.

A build-time test walks `RequestMappingHandlerMapping` and asserts every mapped
endpoint carries an explicit `@PreAuthorize` or sits on a short reviewed
allowlist. It is about forty lines and it is the **highest-ROI security artifact
in the project**. Do not weaken it, and do not add to the allowlist without
review.

### 4. Money is never a floating-point number

- **Integer micro-units (`Long`) internally.**
- `BigDecimal` at system boundaries.
- **Never `Double` or `Float`.** A detekt rule bans them in billing packages.

Rates, balances, reservations, invoice lines — all micro-units. When in doubt,
smaller unit.

### 5. Clean-room: do not read the incumbents' source

**Do not read MagnusBilling, ASTPP, or CGRateS source code for implementation
guidance.** Not their AGI script, not their rating logic, not their controllers.

Two independent reasons:

- **Legal.** MagnusBilling's core is LGPL-3.0; ASTPP and CGRateS are AGPL.
  MEGATRON is proprietary. Derivation contaminates our licence position, and we
  intend to sell this.
- **Quality.** Their architecture is what produced the CVE record we are
  designing against. It is not a model worth copying.

They are used as a **feature checklist** and a **threat model**, nothing more.

**The single permitted exception** is MagnusBilling's *database schema*, which
is required to write the migration importer. A schema you must read to parse a
customer's own data export is a data format, not borrowed design. Confine that
knowledge to the importer module and document why it is there.

For CGRateS, take the **model** from its documentation (tariff plans,
reserve-then-debit, the session lifecycle) — never the code.

---

## Licence discipline

MEGATRON is **proprietary and distributed to licensees**. The open-source VoIP
stack is copyleft: OpenSIPS GPLv2, rtpengine GPLv3, CGRateS AGPLv3.

Three rules follow, and CI enforces the third:

1. **Never write a custom OpenSIPS/Kamailio/rtpengine module.** It would be a
   derivative work and would have to ship GPL. Every decision goes over the
   network to our own service instead.

   Conveniently, that is also the better architecture — the licence-clean path
   and the correct design coincide here, which is why the SIP config is
   deliberately thin and dumb.

2. **We never redistribute GPL binaries.** The installer pulls OpenSIPS and
   rtpengine from **upstream distro packages** at install time. MEGATRON ships
   as proprietary software that *depends on* separately-installed GPL software.

3. **No GPL/AGPL library is linked into any MEGATRON binary.** A licence-scan
   gate in CI enforces this. If it fails, find another dependency — do not
   suppress it.

> Not legal advice, and a formal review is still outstanding before first
> customer ship. Architecting to these rules costs nothing and keeps every
> option open.

---

## Workflow

- **The to-do list is GitHub Issues.** There is no ROADMAP file.
- **Ship on a `feature/*` branch → PR.** Never commit straight to `main`.
- Reference the issue in the PR.

### Commit messages

Conventional-commit prefix, then *why* rather than *what* — the diff already
says what.

```
feat(edge): shield tier — OpenSIPS config + nftables baseline

Hostile traffic is dropped silently rather than replied to, so we never
become a reflection/amplification vector. Magnus 403s everything, which
under attack is actively harmful.
```

---

## Verifying claims before you write config

**OpenSIPS is not Kamailio.** Most SIP advice online is Kamailio-flavoured and
will not load. OpenSIPS 3.6 has **no `htable`, no `sanity`, no `secfilter`**.

| Kamailio | OpenSIPS |
|---|---|
| `htable` | `cachedb_local` |
| `sanity` | `sipmsg_validate()` in `sipmsgops` |
| `secfilter` | `textops`/`sipmsgops` matching + `permissions` |

Always check <https://docs.opensips.org/docs/modules/3.6.x/> before writing
config. (`opensips.org/docs/...` 301-redirects there.)

Also: a named route is called as `route(name)`, not `name()`.

---

## Testing

Telephony testing is not ordinary testing.

| What | How |
|---|---|
| Functional + load | **SIPp** scenarios checked in as XML, run in CI against an ephemeral stack |
| Capacity | Test CPS **and** concurrent calls — they stress different things (transaction rate vs dialog memory). Measure **p99.9**, never mean. |
| Security regression | **sipvicious** and **sippts** on every build. Extension enumeration and digest cracking must *fail* against our build. |
| Rating correctness | Property-based (Kotest): cost monotonic in duration, never negative, rerating idempotent under an unchanged tariff. Plus golden files from anonymised real CDRs. |
| Tenancy | Auto-generated cross-tenant probe suite: authenticate as A, request B's IDs, assert 403/404 |
| Chaos | Kill the authorizer mid-call; assert the configured fail direction. Established calls must survive a control-plane restart. |

**Every routing change ships with a SIPp scenario.** No exceptions.

---

## Two things that will bite you

**Fail direction is a business decision, not a default.** When the authorizer is
unreachable: **prepaid fails closed, trusted postpaid fails open.** This must be
explicit in config and must never happen by accident. If you touch this path,
say in the PR which direction you chose and why.

**The edge holds no credentials.** If you find yourself wanting a database
connection on an edge node, stop — you are about to dissolve the trust boundary
that makes edge compromise survivable. The edge asks the core a narrow question;
it does not look things up.
