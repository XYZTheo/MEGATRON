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

1. **`GET /v1/customers/by-handle/{handle}`** — unblocks every by-name call.
2. **`POST /v1/customers/{id}/plan`** — `setPlan` / `setTariff`.
3. **`DELETE /v1/customers/{id}/caller-id`** — `revokeCallerId`.
4. **`POST /v1/auth/verify`** — `verifyCredentials`, against stored HA1.
5. **`GET /v1/customers/{id}/registration`** — via OpenSIPS MI `ul_dump`.
6. **Import path accepting a supplied credential** — the takeover.
7. **`POST /v1/calls/originate`** — click-to-call, via MI. Last: it is the only
   one that is not needed to run the business.

Then `MegatronClient` in VOIPX, which becomes mostly mechanical.

## The takeover test

Seth's proposal, and it is the right one: point VOIPX/MEGATRON at his real
Magnus data and see whether his actual customers can register.

MagnusBilling stores SIP credentials in a way that allows the server to
authenticate them, which means they can be converted to HA1 and imported. If
that works, the switchover is: import, point the providers' IPs at the new box,
done — **no customer reconfigures anything.**

Reading Magnus's **database schema** for this is the one clean-room exception
in this project (`CONTRIBUTING.md`): the importer needs it, and it is confined
to the importer. Magnus's *source* remains off limits.

What is needed to run it:

- read-only access to the Magnus database, or a dump of `pkg_user` and the
  plan/rate tables;
- one real account to test registration with, ideally a spare rather than a
  customer's.
