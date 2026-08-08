# The lab — one call, end to end

**A real SIP call was authorized, routed and billed on 2026-08-07.** This
directory is what did it, kept so the result is repeatable rather than a story.

```
CDR 1-9535@127.0.0.1 bigcorp -> 12125551234 5s 5000u [server-clock]
balance: 25.000000 -> 24.995000 USD
```

SIPp placed a call as `bigcorp` to `12125551234`. OpenSIPS asked the switch
API whether it could proceed, got an allow with a session timer, relayed it to
a second SIPp acting as the carrier, and on BYE settled it. Five seconds
billed at $0.60/minute is 5,000 micro-units, and the customer's balance moved
by exactly that.

That is Phase 1 ([#3](https://github.com/XYZTheo/MEGATRON/issues/3)): one call
in, one call out, CDR emitted.

**And then it carried audio.** With rtpengine anchoring the media:

```
CDR  bigcorp -> 12125551234  5s  5000u [server-clock]  media=4989852
rtpstat: RTP: 119448 bytes, 474 packets ...
```

**And then a customer logged in and paid for it.** On 2026-08-08, with digest
authentication on both the registration and the call:

```
CDR 1-23086@127.0.0.1 labdialer -> 12125551234 60s 10000u [sip] media=0 NO-MEDIA
balance: 5.000000 -> 4.990000 USD
```

Provisioning generated the password, exported it, the softphone registered
with it, the switch challenged the INVITE, and the bill went to **the account
that answered the challenge** — not the one the `From` header claimed. Note
`[sip]`: the duration now comes from the dialog, not the fallback clock.

That is the whole of v1 in one line: *trunk in, rate, authenticate, trunk out,
bill.*

| File | What it is |
|---|---|
| [`opensips-lab.cfg`](opensips-lab.cfg) | Signalling only — the switch API wired to SIP |
| [`opensips-lab-media.cfg`](opensips-lab-media.cfg) | The same, plus rtpengine anchoring |
| [`opensips-lab-auth.cfg`](opensips-lab-auth.cfg) | The same, plus registration and digest auth |
| [`sipp-customer.xml`](sipp-customer.xml) | A softphone placing one call as `bigcorp` |
| [`sipp-customer-audio.xml`](sipp-customer-audio.xml) | The same, sending real G.711 |
| [`sipp-register.xml`](sipp-register.xml) · [`sipp-register-denied.xml`](sipp-register-denied.xml) | A login, expecting success / expecting 403 |
| [`sipp-call-authenticated.xml`](sipp-call-authenticated.xml) | A registered customer placing a call, answering a 407 |
| [`dbtext-setup.sh`](dbtext-setup.sh) | Seeds the credential file OpenSIPS reads |
| [`one-call.sh`](one-call.sh) · [`one-call-with-audio.sh`](one-call-with-audio.sh) | Build, start everything, place the call, check the balance |
| [`register-test.sh`](register-test.sh) | 8 checks: a login, three forgeries, and the enumeration oracle |
| [`authenticated-call.sh`](authenticated-call.sh) | The whole business: create a customer, log in, call, bill |

```sh
scp lab/* ubuntu@<box>:~/lab/
ssh ubuntu@<box> 'sudo bash ~/lab/dbtext-setup.sh && bash ~/lab/register-test.sh'
ssh ubuntu@<box> 'bash ~/lab/authenticated-call.sh'
```

## The login, and the oracle it nearly shipped with

`register-test.sh` runs four SIP exchanges and four assertions about them. The
one worth reading is check 5.

The obvious implementation refuses a **wrong password** with 403 and
re-challenges an **unknown handle**, because `auth_db` reports them as
different failures and it seems only honest to pass that on. That difference is
a username enumeration oracle: one packet per guess, no credential needed,
tells an attacker exactly which handles are real — and then brute force has
somewhere to point. It is what the scanners hitting MagnusBilling installs are
looking for.

Now one question decides the wire answer: **did the request carry
credentials?** Never whether they named a real account. The cause is logged,
where an attacker cannot read it. The test asserts both — that the two
responses are byte-identical, *and* that the log still tells them apart. A
uniform response with no log entry is just a blind spot.

An earlier version re-challenged a stale nonce, so a slow phone would not be
locked out. It was dropped. Measured on 3.6.7, a wrong password returns `-2`
and an unknown account returns `-1`, which is also the generic error code;
branching on those reintroduces the oracle inverted. `is_nonce_stale()` would
have settled it, but in 3.6 it exists only as a C symbol and is not callable
from config — **the symbol table lists more than the config language exposes.**

## The account takeover the tests could not see

`register-test.sh` passed 8/8 while the config contained a working
account-takeover, and the reason is worth more than the bug.

The REGISTER identity check compared `$au` (who authenticated) against `$fU`
(the From user), with a comment above it describing exactly the attack it was
supposed to stop. But **OpenSIPS's registrar takes the address-of-record from
the `To` header** (RFC 3261 §10.2), not From. So this, with a completely valid
credential:

```
From: <sip:bigcorp@sip.megatron.local>   ← matches $au, passes the check
To:   <sip:victim@sip.megatron.local>    ← this is what save() registers
Contact: <sip:bigcorp@attacker.ip:5060>
```

registered a binding for **victim** pointing at the attacker, and every
inbound call for victim went to them. Every credential valid, no protocol
violation anywhere.

**The suite could not catch it because both scenario files used one injection
field for From and To.** The "from-spoof" case set both to `victim`, so it only
ever exercised the From branch — the To path had no test at all. A negative
test that cannot distinguish two code paths is a test of one of them.

To is its own field now, and the two cases are deliberately separated so each
reaches its own branch: with To *also* spoofed, the AOR check fires first and
the From branch is never reached. That is checked too — the suite asserts both
log lines appear, not just that the requests were refused.

## Four failures worth keeping

**`opensips -C` is not validation.** The auth config passed it and then refused
to start: `auth_db`'s table version check runs at fixup, not at parse. A config
that validates can still be unrunnable. (It does say what it wants, precisely:
*"invalid version 7 for table subscriber found, expected 8"*.)

**The packaged `opensips.service` was shadowing the lab.** Ubuntu's package
ships an enabled unit running the stock config on `127.0.0.1:5060`. A more
specific bind beats a wildcard, so the lab instance started cleanly on
`0.0.0.0:5060`, reported exactly that, and received none of the loopback
traffic — the stock proxy answered instead. Four identical *476 Unresolvable
destination* failures that looked like a bug in the config under test. The
runner now masks the unit and asserts who owns the port.

**An unused column is not free.** The export declared `ha1b` and left it empty,
on the reasoning that a column nothing reads is inert. `db_text` validates every
declared column on load and rejects a null field, so one empty value did not
degrade one login — the whole table failed to parse, `auth_db` reported *"table
'subscriber' does not exist"*, and every REGISTER got a 500.

**`rtpengine --daemon` is not a flag.** It daemonises by default; `--foreground`
is the opposite one. Passing `--daemon` makes it exit immediately, and with
stderr discarded that is indistinguishable from a clean start.

## The two media bugs, both silent

**`onreply_route` was declared but never armed.** OpenSIPS only runs a named
reply route for transactions that asked for it with `t_on_reply()`. Without
that one line `rtpengine_answer()` never ran, so rtpengine never learned the
callee's media address and forwarded nothing.

The failure is completely invisible from the outside: the call sets up, both
parties believe they are connected, and the stats read `RTP: 0 bytes`. On a
real switch that is *every call carrying silence, billed in full* — the exact
failure mode the media check exists to catch, caused by the check's own
plumbing.

**The parser did not match the format.** It understood `bytes=N`; OpenSIPS's
`$rtpstat` emits `N bytes`, number first. So it returned "unknown" for every
call — which reads exactly like a switch whose media stats are not wired up
yet, so nothing looked wrong. It now accepts both, and the tests use strings
copied verbatim from real calls rather than invented ones.

Unreadable stats stay **unknown**, never zero. Guessing zero turns every
healthy call into a refund request the day rtpengine changes its wording.

## This is NOT the production config

`edge/` and `core/` are. This one exists to answer a question no amount of
config review can: **does `rest_client` actually reach our Kotlin service,
parse its JSON, and act on it.** It does.

## What it proved, including the parts that were wrong

**The `From` user is the account.** The built-in SIPp `uac` scenario sends
`From: sipp@…`, which the switch correctly refused as `no_such_account`. Not a
bug — the first evidence the identity path works.

**Settling must happen after `loose_route()`, not before.** The first attempt
settled first, on the theory that getting paid should not depend on onward
routing. That reasoning is right and the ordering was still wrong: the dialog
is matched *during* `loose_route()`, so settling before it meant
`$DLG_lifetime` was always empty and **every call billed zero seconds**. The
safe-looking order was strictly worse.

**Billing cannot depend on the SIP side reporting duration.** Even after
reordering, the dialog does not match in this lab and OpenSIPS sends no
lifetime. A zero-second settlement releases the reservation and charges
nothing — every call free, silently, leaving only a CDR full of zeroes that
looks like a quiet week.

So the switch keeps **its own clock** from the moment it authorized. The
SIP-reported duration is preferred when present, because it is measured from
answer and excludes ringing; the fallback measures from authorization and will
slightly over-count. Over-counting a call nobody could otherwise bill is the
right way round, and every CDR carries `duration_source` (`sip` or
`server-clock`) so the difference is never invisible.

## Dialog matching — fixed, by fixing the test

The CDR now says `[sip]`, not `[server-clock]`. Nothing in the switch changed
to achieve that: the **scenario** was wrong.

SIPp only saves a Record-Route set when the `<recv>` is marked `rrs="true"`,
and only follows it when the in-dialog requests carry `[routes]`. Without
both, the BYE arrived with no Route header, `loose_route()` did not match, and
no dialog meant no `$DLG_lifetime` — so the switch fell back to its own clock
on every single call and said so honestly in every CDR. A real softphone
honours Record-Route, so this was a defect in the measurement, dressed as a
limitation of the system.

The in-dialog requests also target `[next_url]` — the remote party's Contact —
rather than the number originally dialled. The dialled number was never a
routable destination; it was a number to be rated.

**A BYE for a call we never routed no longer settles.** Found because SIPp
sends a BYE when it aborts a scenario, which produced settlement attempts for
REGISTERs. Every authorized call is `record_route()`d, so a genuine BYE
matches; one that does not belongs to no call of ours, and settling it posts a
CDR for a call that never happened — which anyone who can reach 5060 could do
at will. Deliberately *not* the same test as "no dialog found": a matched call
with a missing dialog still needs settling from the server clock. The
distinction is **"I cannot measure this call"** versus **"this is not a
call"**.

## What is still missing

- **Media on the authenticated path.** The CDR above reads `NO-MEDIA`, which
  is correct — that scenario sends no RTP — and it is the first time the flag
  has fired on a live call rather than in a unit test. Combining audio with
  authentication is one scenario away.
- **rtpengine kernel forwarding.** It runs in userspace here (*"FAILED TO
  CREATE KERNEL TABLE"*), which is a throughput concern for
  [#4](https://github.com/XYZTheo/MEGATRON/issues/4), not a correctness one.
- **The production configs.** `edge/` and `core/` still authenticate against
  PostgreSQL rather than this exported file, and have passed `opensips -C` but
  never carried a call — and `opensips -C` is exactly what this lab has just
  finished demonstrating is not enough.
