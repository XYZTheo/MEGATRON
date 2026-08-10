# Connecting PROJECT-VOIPX to MEGATRON

**VOIPX is the management layer. MEGATRON is the switch it manages.** Today
VOIPX drives a VOS3000/Magnus box; the work here is to let it drive MEGATRON
instead, so Seth points his providers' IPs at his own server and carries on.

## The whole integration is one interface

VOIPX already abstracts the switch behind `VosClient`
(`service/vos/VosClient.kt`), selected at runtime by `vos.mode`, with
`Vos3000Client` and `MockVosClient` as the existing implementations. Adding
`MegatronClient` is the integration.

That is a genuinely good piece of design on Seth's part and it is why this is
tractable: **nothing in VOIPX's bot, console, plan or balance code has to
change.** If `MegatronClient` answers the same questions, the management layer
cannot tell the difference.

```
   Telegram bot ─┐
   admin console ─┼─→ VOIPX services ─→ VosClient ─┬─→ Vos3000Client  (today)
   web UI        ─┘                                └─→ MegatronClient (this work)
                                                            │
                                                            ▼
                                                   MEGATRON provisioning API
                                                     127.0.0.1:8081
```

## What VosClient asks for, and whether MEGATRON can answer

| `VosClient` method | MEGATRON today | Gap |
|---|---|---|
| `listPlans()` | `GET /v1/plans` | **Shape.** VOIPX's `VosPlan` is a VOS3000 *package*: a recurring rent that buys gift money/minutes. MEGATRON plans are *tariffs* (per-prefix rates). See "Packages vs tariffs" below. |
| `getAccount(user)` | `GET /v1/customers/{id}` | none — balance, currency, plan id, status |
| `provisionUser(user)` | `POST /v1/customers` | none — returns generated SIP credentials |
| `provisionAccount(account, e164, password)` | — | **Caller supplies the password.** MEGATRON generates them and never accepts one. Needs a decision, not just an endpoint. |
| `deprovisionAccount(...)` | `POST /v1/customers/{id}/status` | **No delete.** Suspension removes them from the credential file, which is the property that matters, but it is not deletion. |
| `creditAccount(account, amount)` | `POST /v1/customers/{id}/balance` | **Keyed by handle, not id.** Needs a by-handle lookup or a handle-keyed endpoint. |
| `setPlan(user, plan)` | — | **Missing.** No endpoint changes a customer's plan. |
| `setTariff(user, feeRateGroup)` | — | **Missing**, and in MEGATRON the plan *is* the tariff. |
| `accountTariff(user)` | `GET /v1/customers/{id}` | maps to `plan_id` |
| `authorizeCallerId(user, number)` | `POST /v1/customers/{id}/caller-id` | none |
| `revokeCallerId(user, number)` | — | **Missing.** |
| `creditBalance(user, amount)` | `POST /v1/customers/{id}/balance` | none |
| `setAccountLocked(user, locked)` | `POST /v1/customers/{id}/status` | none |
| `registrationStatus(user)` | — | **Missing.** The switch knows (OpenSIPS `ul_dump` over MI); nothing exposes it. |
| `originateCall(user, from, to)` | — | **Missing.** Click-to-call needs OpenSIPS `uac` / MI `t_uac_dlg`. |
| `verifyCredentials(user, pass)` | — | **Missing**, and easy: MEGATRON holds HA1 and can check a password without storing one. |
| `supportsCalling` / `supportsRegistration` / `backendName` | — | trivial |

Eight gaps. Six are endpoints. Two are decisions.

## The two decisions

### Packages vs tariffs

VOS3000 splits pricing in a way MEGATRON does not: a **package** is a rent that
buys gift credit, and a **fee-rate group** is the per-prefix pricing. VOIPX
mirrors both — `VosPlan.perMinuteRate` is documented as always zero because
"per-minute pricing is NOT a property of a package on VOS3000".

MEGATRON has one concept: a plan *is* a rate table. That is simpler and it is
the right model for reselling trunks, which is the actual business.

**Recommendation: keep MEGATRON's model and map.** `listPlans()` returns
MEGATRON plans with `monthlyPrice = 0`, `billingPeriod = "none"` and the real
`perMinuteRate` populated — the inverse of the VOS3000 case. Recurring rent is
a billing feature MEGATRON can add later if Seth wants it; inventing a package
abstraction to mirror VOS3000's would import a distinction that exists only
because VOS3000 made it.

### Passwords MEGATRON did not generate

`provisionAccount(account, e164, password)` hands the switch a chosen password,
and MEGATRON's whole credential story is that passwords are generated, returned
once, and never accepted or recoverable.

**This is the one place that story has to bend, and it should — for exactly one
reason.** The takeover test is that Seth's *existing* Magnus customers keep
working without touching their softphones. That is only possible if MEGATRON
can be handed a credential it did not mint.

So: accept a supplied password on a **clearly-named import path**, never on the
ordinary create path, with the constraint that it is converted straight to HA1
and the plaintext is not stored. Generated stays the default; supplied is an
explicit, auditable act.

## What to build, in order

**Items 1–6 are built and proven against a running switch.** The table above is
kept as the record of what the gaps were; `MegatronClientLiveTest` is what says
whether they are still gaps, because it is the only thing that talks to a real
MEGATRON. Field names, verbs and status codes disagreed three times, and every
one of those was invisible from the VOIPX side.

1. ~~`GET /v1/customers/by-handle/{handle}`~~ — done.
2. ~~`PUT /v1/customers/{id}/plan`~~ — done. **PUT**, not POST: setting the plan
   to X twice leaves them on X.
3. ~~`PUT /v1/customers/{id}/caller-id`~~ — done; an empty value withdraws it.
4. ~~`POST /v1/auth/verify`~~ — done, against stored HA1.
5. ~~`GET /v1/customers/{id}/registration`~~ — done, via MI `ul_show_contact`.
   Distinguishes "not registered" from "the switch could not be asked".
6. ~~Import path accepting a supplied credential~~ — done.
7. **`POST /v1/calls/originate`** — click-to-call, via MI. Still open, and still
   last: it is the only one that is not needed to run the business.

## Carriers: what connecting a real one actually took

The trunk half of the admin console is not symmetric with the customer half, and
a live provider is what showed why.

| `VosAdminClient` method | MEGATRON | Note |
|---|---|---|
| `listRoutes()` / `listInboundGateways()` | `GET /v1/trunks`, split by direction | `priority` is real and is reported: MEGATRON picks a carrier by it. |
| `createRoute(spec)` / `createInboundGateway(spec)` | `POST /v1/trunks` | `priority` is passed through. Dropping it would put every console-created trunk on one value, where the tie-break by id sends all traffic to whichever was added first — so adding a carrier appears to do nothing. |
| `deleteRoute(name)` / `deleteInboundGateway(name)` | `DELETE /v1/trunks/{id}` | VOIPX names a gateway, MEGATRON keys a trunk by id, so the name is looked up. A name matching nothing is refused **locally** — a 404 from the switch reads to an operator as "the switch is broken". |
| `setRoute*` / `setInbound*` | — | Still refused locally. MEGATRON has no partial update for a trunk; retire and re-add. |

Three things a carrier needs that were not obvious until one was connected:

- **`auth_realm` is what they challenge with, not their domain.** A real
  provider handed over the domain `privatesip.com` and then challenged with
  `realm="asterisk"` — the Asterisk default, which nobody documents because
  nobody looks. A wrong realm produces a digest the carrier reads as a bad
  password. Read it off the wire; do not infer it.
- **`from_user` decides whether the call is theirs to accept.** MEGATRON's From
  carries the customer's handle, because that is who authenticated and who gets
  billed. A carrier that authenticates by account looks up the peer by From
  user, finds nothing, and answers **403 Forbidden with the digest perfectly
  correct**. Defaults to the account name on a credentialed trunk.
- **Trunks must be removable.** Without that, test carriers accumulate, tie on
  priority, and the oldest wins every call.

## VOIPX drives EITHER backend. Both stay working.

Seth, 2026-08-08:

> "nah im not connecting my magnus to this - u can make it so it can accept
> magnus (voipx) but the system megatron u are suppose to be making is suppose
> to be used in place of magnus so make it work for magnus/vos and megatron"

**The live Magnus is not a test target and must not become one.** It is the
running business. Nothing in this repo connects to it, reads its database, or
requires it to be reachable.

What that means concretely:

- `vos.mode` keeps selecting the backend, and **`Vos3000Client` is not
  touched**. VOIPX against Magnus/VOS3000 must work exactly as it does today
  after this change, or the change is wrong.
- `MegatronClient` is added beside it. Same interface, same screens, different
  switch.
- Both are exercised the same way: VOIPX's existing tests keep covering the
  VOS3000 path, and `MegatronClient` gets its own against a real MEGATRON.

The point of the abstraction is that Seth can run one, the other, or both, and
move when *he* decides — not when a migration tool says he must.

### Importing existing customers, when he wants it

`Store.importCustomer` exists and works: it takes a credential MEGATRON did not
generate, converts it to HA1, and the customer's softphone keeps working
untouched. That is what makes a switchover a takeover rather than a migration.

It runs from a **dump or an export the operator chooses to give it** — never
from a live connection to a production Magnus. The importer that reads Magnus's
schema is future work (issue #11) and is gated on Seth wanting it, not on
MEGATRON needing it.
