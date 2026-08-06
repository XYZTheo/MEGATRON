# MEGATRON — Edge / Shield Tier

The **only** publicly reachable surface in a MEGATRON deployment.

This tier exists to absorb hostile traffic so the core never sees it. It is a
stateless filter and relay — nothing more.

## The trust boundary

These are hard rules, enforced by configuration and verified in CI:

| | Edge tier | Core tier |
|---|---|---|
| Reachable from internet | **Yes — the only tier that is** | **No route at all** |
| Holds DB credentials | **No** | Yes |
| Holds customer data / PII / tariffs | **No** | Yes |
| Holds call authorization logic | **No** | Yes |
| Disposable | **Yes — cattle** | No |

A **total compromise of an edge node yields an attacker nothing** beyond the
ability to relay SIP into a core that will independently authorize it. There
is no credential to steal, no data to exfiltrate, and no state to lose. The
correct response to a compromised edge is to destroy and reprovision it.

The core binds to a private interface and accepts traffic only from
allowlisted edge IPs. It has **no route from the public internet**. That is
not mitigation — it is genuine unreachability, and it is the single most
important structural decision in the resilience design.

See [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §4.5b.

## The governing design rule

> **Cost to reject must be far below cost to send.**

Every check is ordered cheapest-first, and every rejection happens *before*
`t_relay()` — before transaction state is allocated, before any lookup, before
memory is committed to the attacker's packet.

## Defence layers

| Layer | Where | Handles |
|---|---|---|
| 1. XDP / eBPF | NIC driver | Known-bad sources dropped before the kernel allocates an `sk_buff`. Millions of pps. *(Go node agent — not yet built.)* |
| 2. nftables | Kernel | [`nftables/megatron-edge.nft`](nftables/megatron-edge.nft) — trunk allowlists, rate ceilings, connection limits |
| 3. OpenSIPS | Userspace, pre-transaction | [`opensips/opensips.cfg`](opensips/opensips.cfg) — blocklist, `sipmsg_validate()`, scanner fingerprinting, `pike`, `ratelimit` |

## Why we drop silently

Replying to a spoofed source does two harmful things at once: it makes us a
**reflection/amplification vector** against a third party, and it **doubles our
own work** per hostile packet.

MagnusBilling's instinct is to politely `403` everything. Under attack that is
actively harmful. Once traffic is classified hostile, MEGATRON sends nothing at
all — an attacker scanning us gets the same result as scanning an unused
address.

We *do* reply to traffic that is malformed but not yet classified hostile (a
real broken client deserves a diagnostic), and to load-shed `503`s (a real
customer arriving during an attack deserves to know to retry).

## Why TLS/TCP is priced better than UDP

A spoofed-source flood **cannot complete a TCP or TLS handshake** — the
attacker never receives the SYN-ACK. Connection-oriented SIP is therefore
structurally immune to the entire spoofed-source attack class.

Both the firewall rate limits and the deployment guidance deliberately favour
TLS to push customers onto it. This is policy, not tuning.

## What populates the blocklist

Four sources, all feeding the same `cachedb_local` collection and nftables set:

1. **`pike`** — the source flooded us.
2. **Scanner fingerprinting** — the source identified itself in `User-Agent`
   (`sipvicious`, `friendly-scanner`, `sipcli`, …).
3. **The honeypot sensor** — the source touched a decoy IP that no legitimate
   traffic has any reason to touch. **Zero false positives**, and because
   attackers sweep ranges sequentially, they hit the decoy *before* they reach
   this node. *(Not yet built.)*
4. **The opt-in fleet-wide reputation feed** — the source burned its
   infrastructure on some other operator's MEGATRON install. *(Not yet built.)*

Entries carry a TTL, so blocks expire on their own and a transient false
positive self-heals without operator action. That property is what stops
operators from disabling automated blocking entirely — the failure mode that
makes most blocklists useless in practice.

## Module-name note

OpenSIPS has **no** `htable`, `sanity`, or `secfilter` module — those are
Kamailio names and appear in a lot of copy-pasted advice. The OpenSIPS
equivalents used here:

| Kamailio | OpenSIPS (used here) |
|---|---|
| `htable` | `cachedb_local` (collections with TTL) |
| `sanity` | `sipmsg_validate()` in `sipmsgops` |
| `secfilter` | `textops` / `sipmsgops` matching + `permissions` |

## Status

⚠️ **Neither file has been validated against a running system** — no Linux host
exists for the project yet. Module names, function signatures and parameters
were verified against the OpenSIPS 3.6 documentation, but nothing here has been
loaded by a live binary.

Before first deployment:

```sh
opensips -C -f /etc/opensips/opensips.cfg   # config check
nft -c -f megatron-edge.nft                 # syntax check
```

Then the Phase 1 goal: one call in, one call out, media anchored, CDR emitted.
