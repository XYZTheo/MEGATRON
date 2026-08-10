#!/usr/bin/env python3
"""Hold the MagnusBilling parity inventory to its claims.

WHY THIS EXISTS
---------------
"It should have every single feature Magnus has so we aren't missing
anything" is a requirement, and a requirement that lives only in a markdown
table is a requirement that quietly erodes. Every feature matrix in every
migration project in history has been edited down to what was convenient by
month four, and nobody noticed because nothing was watching the list.

So the list is watched. This fails the build if:

  * the inventory SHRINKS below the count recorded when it was taken from
    MagnusBilling's own documentation tree — the single most likely way
    "parity" quietly becomes "parity with the bits we felt like doing"
  * a module id is duplicated or missing
  * a status outside the closed vocabulary appears
  * a `planned` row has no owning issue
  * a `superseded` row does not say what MEGATRON does instead — refusing to
    copy a feature is a legitimate decision, but only if it is argued
  * docs/MAGNUS-PARITY.md has drifted from this file

It also prints the gap count, which is the number that has to reach zero
before anyone writes "feature parity" on a sales page.

Regenerate the markdown after editing the YAML:

    python ci/check_parity.py --write

Needs PyYAML, so it runs in the CI `contract` job rather than the stdlib-only
policy gate.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    print(f"missing dependency: {exc}\n  pip install pyyaml", file=sys.stderr)
    raise SystemExit(2)

REPO = Path(os.environ.get("MEGATRON_REPO_ROOT",
                           Path(__file__).resolve().parent.parent)).resolve()
SOURCE = REPO / "docs" / "magnus-parity.yaml"
RENDERED = REPO / "docs" / "MAGNUS-PARITY.md"

STATUSES = {"shipped", "specified", "planned", "gap", "superseded"}

# The inventory, verbatim, as listed in MagnusBilling's own documentation tree
# (magnussolution/magnusbilling7, wiki/en/modules) on 2026-08-07.
#
# Pinned as an exact SET rather than a count, which catches the failure that
# matters most given the requirement is "not missing anything": a count floor
# notices a deletion but happily accepts a row invented to pad the total, and
# it never notices a module we simply forgot to inventory. Set equality
# catches all three.
#
# When MagnusBilling ships a new module, add it here AND give it a row. That
# order is deliberate — this list is the record of what they have, and the
# YAML is the record of what we intend to do about it.
MAGNUS_MODULES = {
    "Plan", "alarm", "api", "call", "callArchive", "callBack", "callOnLine",
    "callShopCdr", "callSummaryCallShop", "callSummaryDayAgent",
    "callSummaryDayTrunk", "callSummaryDayUser", "callSummaryMonthDid",
    "callSummaryMonthTrunk", "callSummaryMonthUser", "callSummaryPerDay",
    "callSummaryPerMonth", "callSummaryPerTrunk", "callSummaryPerUser",
    "callerid", "campaign", "campaignDashboard", "campaignLog", "campaignPoll",
    "campaignPollInfo", "campaignReport", "campaignRestrictPhone",
    "configuration", "did", "didHistory", "didUse", "diddestination",
    "firewall", "gAuthenticator", "groupModule", "groupUser", "groupUserGroup",
    "holidays", "iax", "ivr", "logUsers", "methodPay", "module", "offer",
    "offerCdr", "offerUse", "phoneBook", "phoneNumber", "prefix", "provider",
    "providerCNL", "queue", "queueMember", "rate", "rateCallshop",
    "rateProvider", "refill", "refillprovider", "restrictedPhonenumber",
    "sendCreditProducts", "sendCreditRates", "sendCreditSummary", "servers",
    "services", "servicesUse", "sip", "sipTrace", "sipuras", "sms", "smtps",
    "templateMail", "trunk", "trunkGroup", "trunkSipCodes", "user",
    "userHistory", "userRate", "voucher",
}

BADGE = {
    "shipped": "**shipped**",
    "specified": "specified",
    "planned": "planned",
    "gap": "**GAP**",
    "superseded": "superseded",
}


def load() -> dict:
    return yaml.safe_load(SOURCE.read_text(encoding="utf-8"))


def rows(data: dict):
    for group in data["groups"]:
        for module in group["modules"]:
            yield group["name"], module


def render(data: dict) -> str:
    meta = data["meta"]
    counts: dict[str, int] = {}
    for _, module in rows(data):
        counts[module["status"]] = counts.get(module["status"], 0) + 1
    total = sum(counts.values())

    out: list[str] = []
    add = out.append

    v1_total = sum(1 for _, m in rows(data) if m.get("v1"))
    v1_done = sum(1 for _, m in rows(data)
                  if m.get("v1") and m["status"] in ("shipped", "specified"))

    add("# MagnusBilling feature parity")
    add("")
    add("> **Generated from [`magnus-parity.yaml`](magnus-parity.yaml).**")
    add("> Edit that file, then run `python ci/check_parity.py --write`.")
    add("> CI fails if this file has drifted from it.")
    add("")
    add("An operator asking \"does it do everything Magnus does?\" deserves a real")
    add("answer, and a project claiming it deserves something that checks. Every")
    add("module MagnusBilling documents has a row here, a status, and an owner.")
    add("")
    add("## ⚠️ This is not the v1 to-do list")
    add("")
    add("**Read [`PRODUCT.md`](PRODUCT.md) first.** The owner's business is")
    add("`trunk in → rate → authenticate → trunk out → bill`, operated through a")
    add("Telegram bot. Most of MagnusBilling's surface is not in that workflow, and")
    add("building it first would delay the switch that exists to stop his platform")
    add("being knocked offline.")
    add("")
    add(f"**{v1_total} of {total} modules are on the v1 critical path** — the `v1`")
    add("column below. The other rows are roadmap: real features, tracked so that")
    add("\"we don't have that yet\" is always a deliberate answer rather than a")
    add("discovery, and worked when a paying operator actually needs them.")
    add("")
    add("**The inventory cannot shrink.** `ci/check_parity.py` fails the build if it")
    add("drops below the count taken from Magnus's own documentation tree, which is")
    add("the usual way a parity matrix becomes parity-with-the-convenient-bits.")
    add("")
    add(f"| Total | shipped | specified | planned | **gap** | superseded |")
    add("|---|---|---|---|---|---|")
    add(f"| {total} | {counts.get('shipped', 0)} | {counts.get('specified', 0)} "
        f"| {counts.get('planned', 0)} | **{counts.get('gap', 0)}** "
        f"| {counts.get('superseded', 0)} |")
    add("")
    add(f"**{counts.get('gap', 0)} gaps.** That number has to reach zero — or each")
    add("row has to become a deliberate `superseded` with an argument attached —")
    add("before anyone writes \"feature parity\" on a sales page.")
    add("")
    add("`superseded` means MEGATRON deliberately does not copy the feature and does")
    add("something else instead. Copying a feature that exists only because of an")
    add("Asterisk implementation detail, or one whose Magnus implementation *is* the")
    add("vulnerability, would be replicating the thing being replaced. Every such row")
    add("says what we do instead, so the answer to \"do you have X?\" is never just")
    add("\"no\".")
    add("")
    add("## Provenance")
    add("")
    add(f"- Inventory: `{meta['source']}`, read {meta['read_on']}.")
    add(f"- **{meta['clean_room']}.** ARCHITECTURE.md §3 makes MagnusBilling a")
    add("  feature checklist and a threat model, nothing else. Listing the pages in")
    add("  a documentation tree is exactly that; opening a PHP file to see how a")
    add("  feature works is not, and is not permitted. The one documented exception")
    add("  elsewhere is Magnus's DB schema, needed by the importer and confined to")
    add("  that module.")
    add("")

    for group in data["groups"]:
        add(f"## {group['name']}")
        add("")
        add("| Magnus module | What it does there | v1 | Status | MEGATRON |")
        add("|---|---|---|---|---|")
        for module in group["modules"]:
            status = BADGE[module["status"]]
            v1 = "**yes**" if module.get("v1") else "—"
            detail = module.get("note") or module.get("instead") or ""
            if module["status"] == "planned" and module.get("issue"):
                detail = (f"[#{module['issue']}](https://github.com/XYZTheo/MEGATRON/"
                          f"issues/{module['issue']})" + (f" — {detail}" if detail else ""))
            add(f"| `{module['id']}` | {module['magnus']} | {v1} | {status} | {detail} |")
        add("")

    return "\n".join(out) + "\n"


def main() -> int:
    data = load()
    problems: list[str] = []

    seen: set[str] = set()
    total = 0
    gaps: list[str] = []
    for group_name, module in rows(data):
        total += 1
        mid = module.get("id")
        if not mid:
            problems.append(f"{group_name}: a module has no id")
            continue
        if mid in seen:
            problems.append(f"duplicate module id '{mid}'")
        seen.add(mid)

        if "v1" not in module:
            problems.append(
                f"'{mid}': no v1 flag. Every module has to be explicitly on or off the "
                f"critical path for the owner's own workflow (docs/PRODUCT.md). "
                f"Unclassified is how Magnus's whole feature surface quietly becomes "
                f"the v1 scope and delays the switch that is meant to stop his platform "
                f"being knocked offline.")

        status = module.get("status")
        if status not in STATUSES:
            problems.append(
                f"'{mid}': status {status!r} is not one of {sorted(STATUSES)}. The "
                f"vocabulary is closed so that 'in progress' cannot become a place "
                f"rows go to be forgotten.")
            continue
        if status == "planned" and not module.get("issue"):
            problems.append(
                f"'{mid}': planned with no owning issue. Planned-with-no-owner is "
                f"the same thing as a gap, wearing a better word.")
        if status == "superseded" and not module.get("instead"):
            problems.append(
                f"'{mid}': superseded without saying what MEGATRON does instead. "
                f"Refusing to copy a feature is legitimate; refusing to argue for it "
                f"is not.")
        if status == "gap":
            gaps.append(mid)

    missing = sorted(MAGNUS_MODULES - seen)
    if missing:
        problems.append(
            f"{len(missing)} MagnusBilling module(s) have no row at all: "
            f"{', '.join(missing)}. Rows may be re-statused, never removed — deleting "
            f"one is how a parity claim quietly stops being true, and never adding one "
            f"is how it was never true to begin with.")

    invented = sorted(seen - MAGNUS_MODULES)
    if invented:
        problems.append(
            f"{len(invented)} row(s) name a module MagnusBilling does not document: "
            f"{', '.join(invented)}. A parity matrix padded with things the other "
            f"product does not have is worse than an honest short one. If Magnus has "
            f"shipped something new, add it to MAGNUS_MODULES in this file first.")

    rendered = render(data)
    if "--write" in sys.argv:
        RENDERED.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {RENDERED.relative_to(REPO).as_posix()}")
    elif not RENDERED.is_file():
        problems.append(f"{RENDERED.name} does not exist — run with --write")
    elif RENDERED.read_text(encoding="utf-8").replace("\r\n", "\n") != rendered:
        problems.append(
            f"{RENDERED.name} has drifted from magnus-parity.yaml. Regenerate it: "
            f"python ci/check_parity.py --write")

    if problems:
        print(f"FAIL — {len(problems)} problem(s) with the parity inventory:\n")
        for p in problems:
            print(f"  {p}")
        return 1

    print(f"OK: all {len(MAGNUS_MODULES)} documented Magnus modules have a row, "
          f"and no row invents one ({total} rows)")
    print(f"OK: every status in the closed vocabulary; every 'planned' has an issue; "
          f"every 'superseded' argues its case")
    print(f"OK: {RENDERED.name} is in sync")

    v1 = [m for _, m in rows(data) if m.get("v1")]
    v1_pending = [m["id"] for m in v1 if m["status"] == "planned"]
    print(f"\nv1 critical path (docs/PRODUCT.md): {len(v1)} of {total} modules")
    print(f"  shipped or specified: {len(v1) - len(v1_pending)}")
    print(f"  still to build:       {len(v1_pending)}")
    print("\nThe other "
          f"{total - len(v1)} are roadmap, not v1. Working them first would delay the "
          "switch that exists to stop the owner's platform being attacked.")
    if gaps:
        print(f"\n{len(gaps)} GAP(s) with no owner yet:")
        for mid in gaps:
            print(f"  - {mid}")
        print("\nThese are not failures. They are the work remaining before "
              "'feature parity' can be written down, and they are visible on purpose.")
    else:
        print("\nNo gaps. Every Magnus module is shipped, specified, owned, or "
              "deliberately superseded with an argument.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
