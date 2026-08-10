# MEGATRON — Core Tier

Where trust lives. Registrar, dialog state, call authorization, media control,
and the connection to the authorizer.

**This tier has no route from the public internet.**

That is the single most important structural property in the design, and it is
worth being precise about what it means. The core is not *hardened* against
internet traffic; it is *unreachable* from it. It binds a private interface,
and the only sources permitted to reach its SIP ports are allowlisted edge
nodes. An attacker cannot flood it, scan it, or touch a single one of its ports,
because there is no path — not because the filtering is good.

See [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §4.5b and the
[edge tier README](../edge/README.md) for the other half of the boundary.

## What enforces that claim

Three independent mechanisms, because the claim is load-bearing enough that no
single one of them should be trusted alone:

| | Where | What it does |
|---|---|---|
| Network | [`nftables/megatron-core.nft`](nftables/megatron-core.nft) | `policy drop` on input, forward **and** output. SIP accepted only from `@megatron_edge_v4`. |
| Bind address | [`opensips/opensips.cfg`](opensips/opensips.cfg) | `socket=` names a private address. The setup wizard refuses to write a public one. |
| SIP | [`opensips/opensips.cfg`](opensips/opensips.cfg) | `check_source_address("1")` re-checks the source, and drops silently otherwise. |

The SIP check is deliberate duplication of what nftables already does. It costs
one lookup, and it means a firewall misconfiguration during a provisioning
change degrades to *calls rejected* rather than to *core exposed*. Those are
very different bad days.

CI asserts the `policy drop` property on every push
([`.github/workflows/validate.yml`](../.github/workflows/validate.yml)), because
a future edit that relaxed one chain would dissolve the guarantee while every
other check still passed.

## Why the output chain is also default-deny

The edge counts its egress; the core restricts it. The difference is what each
tier holds.

An edge node holds no credentials and no customer data, so egress filtering
there buys **detection** — an edge suddenly talking to somewhere unexpected is
a compromise signal. The core holds the ledger, the tariff data and every
tenant's records, so egress filtering there buys **prevention**: it is the
control that turns "an attacker read the database" into "an attacker read the
database and could not get the contents off the box."

Stated honestly: this is not airtight. Exfiltration over an allowlisted path —
DNS being the classic — remains possible, which is why the resolver is a core
node rather than a public one. It raises the cost and narrows the channel; it
does not close it.

## Why there is no LCR in this config

There is no `drouting`, no `lcr`, no `carrierroute`. Route selection happens
inside the authorizer, which returns the chosen gateway in its response.

Two reasons that happen to coincide:

- **Architecture.** Rating and routing are the same decision. "Which gateway"
  and "at what cost" cannot be answered independently without creating two
  sources of truth that will drift. The authorizer already holds tariff and
  gateway data in memory to meet its 5 ms budget, so it is the only component
  that can answer both in one pass.
- **Licence.** MEGATRON is proprietary; OpenSIPS is GPLv2. Keeping business
  logic on the far side of a network boundary — rather than inside module
  configuration or, worse, a custom C module — keeps that boundary clean. See
  [`CONTRIBUTING.md`](../CONTRIBUTING.md).

This is the general shape of the whole system: **the SIP config is thin and
dumb, and every decision is asked of our own service over async HTTP.** The
licence-clean path and the correct architecture point the same way.

## Why the authorizer call must be async

`async(rest_post(...), resume_route)` suspends the SIP transaction and frees
the worker. A synchronous call blocks that worker for the whole round trip.

The arithmetic is unforgiving: at 5,000 CPS with 64 workers, a 20 ms blocking
lookup caps the node at 3,200 CPS, and a single slow response stalls
everything behind it. OpenSIPS's own lab numbers show synchronous DB auth
halving throughput for exactly this reason (§4.3).

`100 Trying` is sent *before* the authorizer is consulted, because the caller
retransmits the INVITE after 500 ms (SIP Timer T1) and the round trip has to
fit inside that budget.

## The three mechanisms against a lost BYE

A lost BYE is one of the three ways this class of platform loses money
(§4.5). Each mechanism below catches cases the others miss, so all three run:

1. **`dlg_set_timeout()`** with the authorizer's `maxDurationSeconds` — the
   hard billable bound, enforced by the proxy at zero ongoing cost. No polling,
   no timers of ours. This is what makes prepaid safe without a mid-call
   heartbeat on every session.
2. **`options_ping_interval`** — in-dialog OPTIONS keepalive detects an endpoint
   that vanished.
3. **rtpengine media timeout** — the only mechanism that catches *media* death
   on a dialog that still looks alive at the signalling layer.

Plus a `dialog` `default_timeout` backstop of 4 hours. OpenSIPS defaults that
to 12 hours, which is how a lost BYE becomes a call billed all night.

## Fail direction

**Prepaid fails closed. Trusted postpaid fails open.**

Refusing a prepaid call loses one call; allowing it when we cannot check the
balance can lose unbounded money to a fraudster. Trusted postpaid customers are
credit-checked and contractually liable, so refusing their traffic during *our*
outage is worse than billing them slightly late.

This is a business decision written down deliberately, not a default that fell
out of the code. If you touch this path, say in the PR which direction you chose
and why.

## Status

**Executed for the first time on 2026-08-07**, against real OpenSIPS 3.6.7 on an
Ubuntu 24.04 lab box.

| Check | State |
|---|---|
| `ci/policy_check.py` structural rules | ✅ Runs and passes |
| `opensips -C` against real OpenSIPS 3.6.7 | ✅ **PASSES** — 2026-08-07 |
| `nft -c` on the ruleset | ✅ **PASSES** — 2026-08-07 |
| All three chains are `policy drop` | ✅ Asserted by the firewall CI job |
| A call actually completing | ❌ Still needs a real SIP call — #3 |

It did not pass first time. Alongside the defects listed in
[`edge/README.md`](../edge/README.md), the core config carried four of its own,
every one a **Kamailio idiom that OpenSIPS does not have** — which is the trap
this project has now hit repeatedly, and the reason the policy gate has a rule
group dedicated to it:

| Written | Correct for OpenSIPS 3.6 |
|---|---|
| `db_check_to()` / `db_check_from()` | No such module. The property — that the From/To user is the account that authenticated — is asserted directly with `$fU != $au`. |
| `dlg_set_timeout(x)` | Not a function. The dialog module exposes a **writable pseudo-variable**: `$DLG_timeout = x;` |
| `$pr` | `$socket_in(proto)`. `$proto` does not exist either — that was the second guess, and it was also wrong. |
| `if (status =~ …)` | `$rs`. A bare word is refused outright: *"bare word `status` found, command calls need `()`"*. |

`auth.so` and `auth_db.so` also needed a package that was not in the install
list at all — `opensips-auth-modules`. The CI job now installs it.

### What passing `-C` does and does not prove

It proves the config **parses**, every `loadmodule` resolves, and every function
exists with that arity. That is exactly the class of defect listed above, and it
is worth having.

It does **not** prove the addresses are right, that routing behaves correctly,
that the database schema matches, or that a call completes. Those need a real
call ([#3](https://github.com/XYZTheo/MEGATRON/issues/3)).

Local checks:

```sh
opensips -C -f opensips/opensips.cfg      # needs the addresses to exist locally
nft -c -f nftables/megatron-core.nft
python3 ../ci/policy_check.py
```
