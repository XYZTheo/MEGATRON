# What MEGATRON is actually for

**Read this before `ARCHITECTURE.md`.** That document describes what the platform
can grow into. This one describes the business it has to serve on day one, and
who it has to serve it for. When the two disagree, this one wins.

---

## In the owner's words

Seth, 2026-08-07, verbatim — this is the ground truth for the whole project:

> "all i know is a resell sips from providers using magnus, i give them my ip,
> they give me theirs, i connect it, make a plan, set a price then give out a
> login then boom, i use a telegram bot to generate logins manage balances and
> users use same bot to add balance and load caller id, thats all it is, boom
> they login on softphone with same login and they make calls, easy for
> everyone. idc whats going on, all i know is my magnus keeps getting attacked
> and magnus isnt very secure so thats why we doing this."
>
> "i want to use this myself first then sell it to others."

### Corrected and sharpened, 2026-08-08

That description was right about the *business* and misled the build in one
important way — it made the Telegram bot sound like the product. Seth's
correction, verbatim:

> "nah u dont need to make a bot for the megatron i already made that, i
> already use magnus so u was suppose to make a magnus clone type shit that is
> secure, I want u to use the voipx github repo on my github to do the UI and
> other features, that should be linked to that from the softphone magnus clone
> thing so i can tell my providers point the ip at the magnus clone server and
> go bout business as usuual in a more secure way"
>
> "for megatron u just making the magnus/vos3000 type interface so i can have a
> service made like that so i can use one made myself instead of their flawed
> shit"
>
> "its not a magnus billing clone, i want all the features and functionality
> magnus and vos3000 offer, that system"

**So: MEGATRON is the switch and the platform — the thing Magnus and VOS3000
are — with their feature surface and none of their defects. It is not a
literal clone of MagnusBilling's code or its screens, and it is not a Telegram
bot.**

Three consequences, and they override anything below that contradicts them:

1. **PROJECT-VOIPX is the management layer, and it already exists.** Seth's own
   repo (Kotlin + Spring Boot) already has the bot, the admin console, plans,
   balances, caller IDs, DIDs, teams, support and licensing. MEGATRON does not
   re-implement any of it.

2. **The seam is `VosClient`.** VOIPX talks to a switch through that one
   interface, swappable by config (`vos.mode`). Implementing it against
   MEGATRON is what connects the two — see `docs/VOIPX-INTEGRATION.md`. That is
   the integration, and it is *one class* plus whatever MEGATRON has to grow to
   satisfy it.

3. **The test that matters is the takeover.** Seth points his providers' IPs at
   the MEGATRON box and carries on. His existing customers keep their existing
   SIP credentials. Anything that forces a customer to reconfigure a softphone
   is a migration, not a takeover, and it is the wrong answer.

**MEGATRON's own Telegram bot (`bot/`) is therefore not the product.** It is
kept because `CommandEngine` holds tested decisions the management layer needs
anyway — who may run what, how a typed amount becomes integer micros, what a
retried message must not do twice — but no further work goes into its
transport.

Two things follow from the original description, and they still govern every
decision in this repo.

### 1. The motive is security, not features

MEGATRON does not exist because MagnusBilling lacks features. **It exists
because Magnus keeps getting attacked and is not secure enough to keep
running.** Every roadmap argument resolves against that: a feature that
does not survive contact with an attacker is not a feature, and a
"nice to have" that widens the attack surface is a cost, not a bonus.

This is why the DDoS shield is Phase 2 rather than Phase 8, why the edge holds
no credentials, why the setup wizard cannot produce an insecure install, and
why the policy gate refuses code patterns that produced Magnus's CVEs before
that code has even been written.

### 2. The first customer is the owner

Seth runs this himself before anyone else touches it. That is a gift, and it
should be treated as one:

- **Every defect is found by the person who cares most**, months before a
  paying operator sees it.
- **"Would Seth's own traffic survive this?" is a better test than any
  spec.** If it cannot carry his business, it cannot carry anybody's.
- It means v1 is allowed to be *narrow*. It has to be excellent at his
  workflow, not adequate at everyone's.

---

## The actual workflow, step by step

This is the entire business. Anything not on this list is not v1.

| # | Step | What the platform must do |
|---|---|---|
| 1 | **Buy trunks from providers** | Seth exchanges IPs with a wholesale carrier: he gives them his, they give him theirs. |
| 2 | **Connect the trunk** | IP-authenticated SIP trunk, both directions. No registration, no password — the allowlist *is* the auth. |
| 3 | **Make a plan, set a price** | A rate table: destination prefix → price per minute. Buy price from the carrier, sell price to the customer. |
| 4 | **Give out a login** | A SIP username and password for a customer. |
| 5 | **Customer logs in on a softphone** | MicroSIP, Zoiper, PortSIP. They register and start dialling. |
| 6 | **Calls get rated against a balance** | Prepaid. When the balance is gone, the calls stop. |
| 7 | **Customer tops up and sets their caller ID** | Through the Telegram bot, themselves, without involving Seth. |

That is it. Trunk in, rate, authenticate, trunk out, bill.

---

## The Telegram bot is the product's interface

This is the single most commonly missed thing about this project, so it is
stated as plainly as possible:

> **There is no web panel in the owner's workflow. The Telegram bot is how the
> business is operated and how customers self-serve.**

The bot does, today, in his Magnus setup:

- **generate logins** (provision a SIP account)
- **manage balances** (credit a customer)
- **let customers add balance themselves**
- **let customers load their caller ID themselves**

A dev arriving from the architecture document will assume the React admin
console is the primary surface. It is not. It is a *reporting and
configuration* surface that matters when MEGATRON is sold to other operators —
and even then, most day-to-day operation will still be the bot, because that is
what the market this serves actually uses.

**Design consequence:** every operation above must exist as an API call first,
with the bot as its first client. Not a bot that scrapes a panel. Not a panel
with a bot bolted on. The provisioning API is the product; the bot and the
console are two clients of it.

Seth already runs a Kotlin/Spring Telegram bot against VOS3000 in another
project, so the pattern is proven and the shape is known.

---

## What this means for scope

### On the critical path for v1

- IP-authenticated carrier trunks, in and out
- Prefix rate tables, buy and sell price
- SIP account provisioning — the "login"
- Prepaid balance, and calls that stop when it runs out
- Per-customer caller ID (CLI), set by the customer
- **Telegram bot** covering provisioning, balance top-up and CLI
- CDR good enough to bill from and to argue with a carrier about
- **The shield.** This is the reason the project exists.
- Softphone interoperability — see `contracts/softphone-profiles.yaml`

### Deliberately NOT v1

These are real MagnusBilling features and they are tracked in
`docs/MAGNUS-PARITY.md`, but **they are not in the owner's workflow** and must
not be allowed to delay a working switch:

IVR · call queues · voicemail · call recording · outbound campaign dialer ·
call shop · mobile airtime top-up · SMS · invoicing and PDF billing runs ·
payment gateway integrations · reseller hierarchies

Some of these become necessary the day MEGATRON is sold to an operator who
needs them. **None of them are necessary for the platform to carry Seth's own
traffic**, which is the only bar that matters first.

The parity matrix exists so that "we don't have that yet" is always an
informed, deliberate answer rather than a discovery. It is not a to-do list to
be worked top to bottom.

---

## The one-line test for any proposed work

> **Does this help the owner's own traffic run, or stop it being attacked?**

If neither, it is not v1 — no matter how prominent it is in MagnusBilling, and
no matter how much of the architecture document it occupies.

---

## Notes for whoever picks this up

- **The security posture is not paranoia, it is the requirement.** The
  constraints in `CONTRIBUTING.md` and the rules in `ci/policy_check.py` are
  there because Magnus's specific failures — default `root`/`magnus`, an
  `exec()` in web-root demo code, APIs served as `text/html` — are the exact
  reasons this project exists. Do not work around a gate; change it
  deliberately and say why.
- **The owner is not a SIP engineer and does not need to be.** Explanations
  aimed at him should be in terms of trunks, plans, logins, balance and
  attacks. Technical depth belongs in these documents, for you.
- **Narrow and working beats broad and pending.** He has a business running on
  Magnus right now. The migration target is a switch that carries it more
  safely, not a platform that does everything Magnus does.
