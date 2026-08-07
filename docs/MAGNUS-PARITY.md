# MagnusBilling feature parity

> **Generated from [`magnus-parity.yaml`](magnus-parity.yaml).**
> Edit that file, then run `python ci/check_parity.py --write`.
> CI fails if this file has drifted from it.

An operator asking "does it do everything Magnus does?" deserves a real
answer, and a project claiming it deserves something that checks. Every
module MagnusBilling documents has a row here, a status, and an owner.

**The inventory cannot shrink.** `ci/check_parity.py` fails the build if it
drops below the count taken from Magnus's own documentation tree, which is
the usual way a parity matrix becomes parity-with-the-convenient-bits.

| Total | shipped | specified | planned | **gap** | superseded |
|---|---|---|---|---|---|
| 78 | 1 | 4 | 70 | **0** | 3 |

**0 gaps.** That number has to reach zero — or each
row has to become a deliberate `superseded` with an argument attached —
before anyone writes "feature parity" on a sales page.

`superseded` means MEGATRON deliberately does not copy the feature and does
something else instead. Copying a feature that exists only because of an
Asterisk implementation detail, or one whose Magnus implementation *is* the
vulnerability, would be replicating the thing being replaced. Every such row
says what we do instead, so the answer to "do you have X?" is never just
"no".

## Provenance

- Inventory: `magnussolution/magnusbilling7 — wiki/en/modules (documentation tree)`, read 2026-08-07.
- **documentation only; no MagnusBilling source code has been read.** ARCHITECTURE.md §3 makes MagnusBilling a
  feature checklist and a threat model, nothing else. Listing the pages in
  a documentation tree is exactly that; opening a PHP file to see how a
  feature works is not, and is not permitted. The one documented exception
  elsewhere is Magnus's DB schema, needed by the importer and confined to
  that module.

## Customers, resellers and access control

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `user` | Customer/account records, balance, credit limit | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) — Multi-tenant from v1 rather than bolted on: PostgreSQL row-level security, not application-layer filtering. |
| `userHistory` | Audit of changes to a customer | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) — Append-only. Magnus's is mutable by an admin, which makes it evidence of nothing. |
| `userRate` | Per-customer rate overrides | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `logUsers` | Login/activity log | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `groupUser` | User groups | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `groupUserGroup` | Group membership | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `groupModule` | Per-group module permissions | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) — Deny-by-default. Enumerating every endpoint's authorization is already a CI gate requirement (issue #13). |
| `module` | Registry of admin modules for permissioning | superseded | Permissions attach to API scopes, not to UI screens. A permission model that describes menus cannot protect an API, which is how admin panels grow endpoints nobody authorised. |
| `gAuthenticator` | Google Authenticator 2FA | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) — TOTP plus WebAuthn. Magnus's default root/magnus is the reason MFA is not optional here. |

## SIP endpoints and registration

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `sip` | SIP account definitions (username/password or IP auth) | specified | Class-5 registrar. See contracts/softphone-profiles.yaml for the per-client behaviour this has to get right. |
| `iax` | IAX2 accounts | superseded | Not implemented. IAX2 is effectively dead outside legacy Asterisk estates, it is a second attack surface, and no softphone on the target list speaks it. Revisit only if a paying customer needs it. |
| `sipuras` | Sipura/Linksys ATA auto-provisioning | superseded | A generic provisioning API keyed by MAC and model, rather than one vendor's XML. Sipura-specific provisioning is a 2006 artifact. |
| `sipTrace` | SIP packet trace per call | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) — Homer/HEP, which is a real capture pipeline rather than a text field. |
| `servers` | Multi-server / node registry | specified | Edge and core tiers exist as separate configs already; the node agent is issue #4. |

## Rating, plans and offers

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `Plan` | Rate plans grouping rates | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `rate` | Selling rates, prefix-based | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) — Integer micro-units end to end. MONEY-NOT-FLOAT is already enforced by ci/policy_check.py before the code exists. |
| `rateProvider` | Buying rates per provider | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `prefix` | Destination prefix catalogue | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `offer` | Bundles/packages (included minutes) | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `offerCdr` | Calls consumed against an offer | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `offerUse` | Offer consumption counters | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |

## Routing, providers and trunks

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `provider` | Upstream carrier records | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `providerCNL` | Provider code/national list | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) |
| `trunk` | Outbound trunk definitions | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) |
| `trunkGroup` | Trunk groups for failover/LCR | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) — LCR lives in the authorizer, not in a GPL routing module — rating and routing are the same decision and splitting them creates two sources of truth for 'which gateway, at what cost'. |
| `trunkSipCodes` | Per-trunk SIP response code handling | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) — Failover on response code is where most 'why did that call fail' tickets come from. |

## DIDs

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `did` | DID inventory, setup and monthly cost | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `didHistory` | DID assignment history | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `didUse` | DID usage/billing records | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `diddestination` | Where an inbound DID call goes | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) |

## Payments, credit and vouchers

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `refill` | Manual/automatic customer top-up | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `refillprovider` | Provider-side credit records | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `voucher` | Prepaid voucher codes | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `methodPay` | Payment gateways (PayPal, PagSeguro, Moip, GerenciaNet...) | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) — Gateway integrations are per-market and go behind one internal interface, so adding a country is not a code change in the ledger. |
| `services` | Recurring non-call services | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `servicesUse` | Recurring service consumption | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `sendCreditProducts` | Mobile top-up / airtime products | planned | [#19](https://github.com/XYZTheo/MEGATRON/issues/19) — No owner yet. Real revenue line for some Magnus operators; needs a decision on whether v1 carries it. |
| `sendCreditRates` | Airtime product pricing | planned | [#19](https://github.com/XYZTheo/MEGATRON/issues/19) |
| `sendCreditSummary` | Airtime sales reporting | planned | [#19](https://github.com/XYZTheo/MEGATRON/issues/19) |

## CDR and reporting

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `call` | CDR browser | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) — ClickHouse. The immutable raw-event table is also the rerating replay log, which is why Kafka is deliberately deferred. |
| `callArchive` | Archived CDR | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callOnLine` | Live calls in progress | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryPerDay` | Daily summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryPerMonth` | Monthly summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryPerTrunk` | Per-trunk summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryPerUser` | Per-customer summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryDayAgent` | Daily per-agent summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryDayTrunk` | Daily per-trunk summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryDayUser` | Daily per-customer summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryMonthDid` | Monthly per-DID summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryMonthTrunk` | Monthly per-trunk summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) |
| `callSummaryMonthUser` | Monthly per-customer summary | planned | [#8](https://github.com/XYZTheo/MEGATRON/issues/8) — Magnus ships these as fourteen separate screens. MEGATRON does one report surface with dimensions, because fourteen screens is a symptom of not having a query model. |

## Telephony features

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `ivr` | IVR menus | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) — FreeSWITCH behind the proxy, class-5 only. |
| `queue` | Call queues | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) |
| `queueMember` | Queue agents | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) |
| `callBack` | Callback / CID callback | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) — A real revenue feature in several Magnus markets, not a curiosity. |
| `holidays` | Holiday routing calendars | planned | [#3](https://github.com/XYZTheo/MEGATRON/issues/3) |
| `sms` | SMS send/receive and billing | planned | [#16](https://github.com/XYZTheo/MEGATRON/issues/16) — No owner. Needs a decision: SMS is a different billing model and a different compliance surface. |
| `phoneBook` | Per-customer phonebook | planned | [#10](https://github.com/XYZTheo/MEGATRON/issues/10) |
| `callerid` | Caller ID management per customer | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) — Also the STIR/SHAKEN attestation boundary — you cannot attest a CLI you never verified the customer owns. |
| `phoneNumber` | Number catalogue | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |

## Outbound campaigns / dialer

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `campaign` | Voice broadcast campaigns | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) — No owner. Also the highest regulatory-risk feature in the product — a dialer is how a platform ends up carrying someone else's robocalls. |
| `campaignDashboard` | Campaign monitoring | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) |
| `campaignLog` | Campaign call log | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) |
| `campaignPoll` | Poll/survey campaigns | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) |
| `campaignPollInfo` | Poll results | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) |
| `campaignReport` | Campaign reporting | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) |
| `campaignRestrictPhone` | Do-not-call list for campaigns | planned | [#17](https://github.com/XYZTheo/MEGATRON/issues/17) — If campaigns ship, this ships first, not later. A dialer without a DNC list is a liability. |

## Call shop

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `callShopCdr` | Call shop booth CDR | planned | [#18](https://github.com/XYZTheo/MEGATRON/issues/18) — No owner. Regional feature — real in some markets, dead weight in others. |
| `callSummaryCallShop` | Call shop reporting | planned | [#18](https://github.com/XYZTheo/MEGATRON/issues/18) |
| `rateCallshop` | Call shop specific rates | planned | [#18](https://github.com/XYZTheo/MEGATRON/issues/18) |

## Security, operations and integration

| Magnus module | What it does there | Status | MEGATRON |
|---|---|---|---|
| `firewall` | IP blocking / fail2ban-style controls | **shipped** | The shield tier already exceeds this: nftables baseline, pike/ratelimit, scanner fingerprinting, plus the operator dashboard and telemetry contract. This is the wedge product. |
| `alarm` | Threshold alarms and notifications | planned | [#4](https://github.com/XYZTheo/MEGATRON/issues/4) |
| `restrictedPhonenumber` | Blocked destination numbers | planned | [#7](https://github.com/XYZTheo/MEGATRON/issues/7) — Fraud control. Belongs in the authorizer so it is enforced on the money path, not in a UI list somebody forgets to apply. |
| `configuration` | Global settings | specified | contracts/wizard-answers.schema.json — and settings that can produce an insecure system are not expressible there at all. |
| `smtps` | Outbound mail server settings | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `templateMail` | Email templates | planned | [#9](https://github.com/XYZTheo/MEGATRON/issues/9) |
| `api` | REST API | specified | API-first, not API-as-afterthought. CVE-2025-2609/2610 were Magnus APIs served as text/html; MEGATRON is JSON-only with nosniff, and that is already a policy-gate rule. |

