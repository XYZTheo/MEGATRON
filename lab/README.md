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

| File | What it is |
|---|---|
| [`opensips-lab.cfg`](opensips-lab.cfg) | Signalling only — the switch API wired to SIP |
| [`opensips-lab-media.cfg`](opensips-lab-media.cfg) | The same, plus rtpengine anchoring |
| [`sipp-customer.xml`](sipp-customer.xml) | A softphone placing one call as `bigcorp` |
| [`sipp-customer-audio.xml`](sipp-customer-audio.xml) | The same, sending real G.711 |
| [`one-call.sh`](one-call.sh) · [`one-call-with-audio.sh`](one-call-with-audio.sh) | Build, start everything, place the call, check the balance |

```sh
scp lab/* ubuntu@<box>:/tmp/
ssh ubuntu@<box> 'bash /tmp/one-call-with-audio.sh'
```

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

## What is still missing

- **Dialog matching**, so the duration comes from SIP rather than the fallback.
  The CDR above says `server-clock`, which is the system telling the truth
  about itself.
- **rtpengine.** No media is anchored, so `media_bytes` is absent and the
  no-audio check cannot fire. Signalling worked; audio is untested.
- **Registration and authentication.** The lab trusts the `From` user. The
  core config does digest auth against the database; that path has passed
  `opensips -C` but has never carried a call.
