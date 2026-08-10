#!/usr/bin/env python3
"""Prove that the wizard's answers schema makes an insecure install unrepresentable.

WHY THIS EXISTS
---------------
ARCHITECTURE.md 6.2b makes a strong promise: "there is no path through the
wizard that produces an insecure install." A promise like that is worth
exactly as much as the thing that checks it, and "the schema looks strict" is
not a check.

So this file is the check. It validates the shipped example, and then attempts
a battery of insecure installs — every one drawn from something that has
actually gone wrong in this product's problem space, mostly in MagnusBilling —
and asserts that the schema REJECTS each one. If any insecure variant
validates, this fails the build and names it.

The direction that matters is the second. A schema that accepts the good
example proves almost nothing; a schema that accepts `admin_password: magnus`
proves the promise is false.

Needs PyYAML and jsonschema, so it runs in the CI `contract` job rather than
in the always-on stdlib-only policy gate — same split as ci/check_fixtures.py.

Run: python ci/check_wizard_answers.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover - environment, not a defect
    print(f"missing dependency: {exc}\n  pip install pyyaml jsonschema", file=sys.stderr)
    raise SystemExit(2)

REPO = Path(os.environ.get("MEGATRON_REPO_ROOT",
                           Path(__file__).resolve().parent.parent)).resolve()

SCHEMA = REPO / "contracts" / "wizard-answers.schema.json"
EXAMPLE = REPO / "install" / "answers.example.yml"


def drop(answers: dict, *path: str) -> dict:
    """Return a copy with a nested key removed."""
    out = copy.deepcopy(answers)
    node = out
    for key in path[:-1]:
        node = node[key]
    node.pop(path[-1], None)
    return out


def put(answers: dict, value, *path: str) -> dict:
    """Return a copy with a nested key set."""
    out = copy.deepcopy(answers)
    node = out
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value
    return out


def insecure_variants(ok: dict) -> list[tuple[str, dict, str]]:
    """(name, answers, why it must be refused).

    Each of these is something an operator, an integrator under time pressure,
    or a copy-pasted blog post would plausibly produce.
    """
    return [
        ("a password field at the top level",
         put(ok, "magnus", "admin_password"),
         "MagnusBilling shipped root/magnus. If the file can carry a password, "
         "some install somewhere ships the example one."),

        ("a password nested inside admin",
         put(ok, "changeme", "admin", "password"),
         "Same defect, one level down, where a permissive schema would miss it."),

        ("an API token in the file",
         put(ok, "sk-live-abc123", "admin", "api_token"),
         "A secret in a committable file is a secret in git history."),

        ("admin console bound to every interface",
         put(ok, "0.0.0.0", "admin", "bind"),
         "The console reachable from the internet is how a switch gets owned "
         "without anyone touching SIP at all."),

        ("admin console bound to the public address",
         put(ok, "203.0.113.10", "admin", "bind"),
         "Same, written the way someone who thinks they are being specific "
         "would write it."),

        ("TLS omitted entirely",
         drop(ok, "sip", "tls"),
         "A spoofed-source flood cannot complete a TLS handshake. Dropping TLS "
         "removes the one transport property that is structurally immune to the "
         "attack class this product is sold against."),

        ("UDP enabled with no trunk allowlist",
         drop(put(ok, True, "sip", "udp", "enabled"), "sip", "udp", "trunks"),
         "Open 5060 to the internet is the MagnusBilling deployment being "
         "replaced."),

        ("UDP enabled with an empty allowlist",
         put(ok, [], "sip", "udp", "trunks"),
         "An empty allowlist that still opens the port is the worst of both."),

        ("UDP restriction switched off",
         put(ok, False, "sip", "udp", "restrict_to_trunks"),
         "The setting exists to have exactly one value."),

        ("private key pasted into the answers file",
         put(ok, {"source": "supplied",
                  "certificate_path": "/etc/ssl/megatron.crt",
                  "private_key": "-----BEGIN PRIVATE KEY-----"},
             "sip", "tls", "certificate"),
         "The supplied-certificate case takes PATHS. A key in this file would "
         "end up in the operator's configuration repository."),

        ("prepaid failing open",
         put(ok, "open", "billing", "fail_direction", "prepaid"),
         "Prepaid must fail closed. Allowing unauthorized prepaid calls during "
         "an outage can lose unbounded money to a fraudster."),

        ("fail direction left unspecified",
         drop(ok, "billing", "fail_direction"),
         "ARCHITECTURE.md 4.4: explicit in configuration, never by accident. "
         "A default here would be a business decision made silently."),

        ("transparent shield with nowhere to relay to",
         drop(ok, "shield", "upstream"),
         "A black hole that drops every legitimate call while looking exactly "
         "like a shield that is working."),

        ("test call disabled but claimed complete",
         put(ok, {"enabled": True}, "verification", "test_call"),
         "enabled with no destination cannot verify anything; the wizard must "
         "not be able to report success without placing a real call."),

        ("test call not requiring media",
         put(ok, False, "verification", "test_call", "require_media"),
         "Signalling-only success is one of the three money-losing failure "
         "modes this platform exists to design out."),

        ("unknown top-level key",
         put(ok, True, "disable_security"),
         "additionalProperties:false everywhere is what stops the schema being "
         "outgrown by whatever the next person decides to add."),

        ("RTP range in the privileged port space",
         put(ok, 100, "network", "rtp_port_range", "start"),
         "Media in the privileged range means the media process needs "
         "privileges it should never hold."),

        ("hostname missing",
         drop(ok, "deployment", "hostname"),
         "TLS certificates are issued against it. An operator who cannot name "
         "their switch cannot be given a certificate."),
    ]


def main() -> int:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    print(f"OK: {SCHEMA.relative_to(REPO).as_posix()} is a valid JSON Schema 2020-12")

    answers = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    errors = sorted(validator.iter_errors(answers), key=lambda e: list(e.absolute_path))
    if errors:
        print(f"FAIL: {EXAMPLE.relative_to(REPO).as_posix()} does not satisfy the schema:")
        for err in errors:
            where = "/".join(str(p) for p in err.absolute_path) or "(root)"
            print(f"  {where}: {err.message}")
        return 1
    print(f"OK: {EXAMPLE.relative_to(REPO).as_posix()} satisfies it")

    # The half that matters.
    accepted: list[str] = []
    variants = insecure_variants(answers)
    for name, variant, why in variants:
        if validator.is_valid(variant):
            accepted.append(name)
            print(f"\nFAIL: the schema ACCEPTS an insecure install — {name}")
            print(f"      {why}")

    if accepted:
        print(f"\n{len(accepted)} insecure variant(s) accepted. ARCHITECTURE.md 6.2b claims "
              f"there is no path through the wizard that produces an insecure install; "
              f"while this is true, that claim is false.")
        return 1

    print(f"OK: all {len(variants)} insecure variants rejected")

    # Guard against this file's own worst failure mode: a battery that has
    # quietly stopped testing anything still prints a row of OKs.
    if len(variants) < 15:
        print("FAIL: the insecure-variant battery has shrunk. It is the only thing "
              "here that can prove the promise; do not let it erode.")
        return 1

    print("\nPASS — an insecure install is not expressible in this schema.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
