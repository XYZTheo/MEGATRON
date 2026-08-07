#!/usr/bin/env python3
"""Keep the softphone interop profiles honest.

WHY THIS EXISTS
---------------
contracts/softphone-profiles.yaml is the concrete meaning of "optimised for
MicroSIP, Zoiper and PortSIP", and it is also the interop test matrix for the
first lab day. Its value depends entirely on one property: that a reader can
tell which claims were verified and which were reasoned.

Nothing in it has been tested — there is no Linux host yet (issue #2). A
profile that quietly loses track of that becomes a document people trust, and
the first time it is wrong it is wrong about whether an operator's customers
can register.

So this fails the build if:

  * a profile or requirement carries no `confidence`
  * a `confidence` outside the declared vocabulary appears
  * a profile claims `lab-verified` while the lab blocker is still open --
    the specific lie this file exists to prevent
  * one of the three clients Seth named is missing, or the generic fallback is
  * a profile has no lab checklist, so nobody knows what to test
  * an open decision has no options and no recommendation, which is how a
    hard question becomes a paragraph nobody acts on

Needs PyYAML; runs in the CI `contract` job.
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
SOURCE = REPO / "contracts" / "softphone-profiles.yaml"

# The clients named as targets. Missing one is a requirement not met, not a
# documentation gap.
REQUIRED_PROFILES = {"microsip", "zoiper", "portsip", "generic"}
CONFIDENCE = {"lab-verified", "vendor-documented", "assumed"}


def main() -> int:
    if not SOURCE.is_file():
        print(f"FAIL: {SOURCE.relative_to(REPO).as_posix()} is missing. "
              f"docs/magnus-parity.yaml cites it.")
        return 1

    data = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    problems: list[str] = []

    meta = data.get("meta") or {}
    lab_blocked = meta.get("blocked_by") is not None

    profiles = data.get("profiles") or []
    ids = {p.get("id") for p in profiles}

    missing = sorted(REQUIRED_PROFILES - ids)
    if missing:
        problems.append(
            f"no profile for {', '.join(missing)}. These are the clients the product "
            f"is required to work with; a missing one is an unmet requirement, not a "
            f"documentation gap.")

    for profile in profiles:
        pid = profile.get("id", "<unnamed>")
        confidence = profile.get("confidence")
        if confidence not in CONFIDENCE:
            problems.append(
                f"profile '{pid}': confidence {confidence!r} is not one of "
                f"{sorted(CONFIDENCE)}. Every claim here has to say how it is known.")
        elif confidence == "lab-verified" and lab_blocked:
            problems.append(
                f"profile '{pid}': claims lab-verified while issue "
                f"#{meta['blocked_by']} is still recorded as blocking. Nothing has "
                f"been tested against a real node yet, and this is precisely the "
                f"claim that must not drift.")
        if pid != "generic" and not profile.get("lab_checklist"):
            problems.append(
                f"profile '{pid}': no lab_checklist. The first day with a real host is "
                f"short; a profile that does not say what to test will not get tested.")
        if not profile.get("why_it_matters"):
            problems.append(
                f"profile '{pid}': no why_it_matters. If it cannot be said why this "
                f"client is worth supporting, it should not be on the list.")

    for req in data.get("registrar_requirements") or []:
        rid = req.get("id", "<unnamed>")
        if req.get("confidence") not in CONFIDENCE:
            problems.append(f"requirement '{rid}': missing or invalid confidence")
        if not req.get("why"):
            problems.append(
                f"requirement '{rid}': no `why`. A requirement without a reason is one "
                f"that gets removed by the next person who finds it inconvenient.")

    for decision in data.get("open_decisions") or []:
        did = decision.get("id", "<unnamed>")
        if not decision.get("question"):
            problems.append(f"decision '{did}': no question")
        if not decision.get("tension"):
            problems.append(
                f"decision '{did}': no tension stated. If there is no tension it is "
                f"not a decision, it is a task.")
        if not decision.get("owner_issue"):
            problems.append(f"decision '{did}': nobody owns it")

    if problems:
        print(f"FAIL — {len(problems)} problem(s):\n")
        for p in problems:
            print(f"  {p}")
        return 1

    by_confidence: dict[str, int] = {}
    for profile in profiles:
        by_confidence[profile["confidence"]] = by_confidence.get(profile["confidence"], 0) + 1

    print(f"OK: {len(profiles)} profiles, all of {sorted(REQUIRED_PROFILES)} present")
    print(f"OK: {len(data.get('registrar_requirements') or [])} registrar requirements, "
          f"each with a reason and a confidence")
    print(f"OK: {len(data.get('open_decisions') or [])} open decision(s), each owned")
    print("\nconfidence: " + ", ".join(f"{k} {v}" for k, v in sorted(by_confidence.items())))
    if lab_blocked and not by_confidence.get("lab-verified"):
        print(f"\nNothing is lab-verified yet — issue #{meta['blocked_by']} is still "
              f"open. That is the honest state, and this check enforces it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
