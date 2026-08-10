#!/usr/bin/env python3
"""Check that the dashboard's fixture data actually conforms to the contract.

WHY THIS EXISTS
---------------
ui/shield/index.html renders from an inline fixture and says, in a comment,
that the fixture is shaped to contracts/shield-telemetry.openapi.yaml. Left
there, that is a promise. The whole point of the UI existing before the Go
node agent does is to pin down what the agent must serve — and a fixture that
has quietly drifted from the contract pins down nothing, while looking like it
does. Worse, the drift would only surface the day the real agent is wired in
and the dashboard renders blanks.

So the claim is executable. This extracts the fixture out of the page and
validates it against the schemas in the contract.

UNLIKE ci/policy_check.py, THIS IS NOT STDLIB-ONLY. It needs PyYAML and
jsonschema, which is why it lives in the `contracts` CI job (which already
installs a validator) rather than in the always-on policy gate. The policy
gate's dependency-free property is deliberate and is not being spent here.

Run: python ci/check_fixtures.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover - environment problem, not a defect
    print(f"missing dependency: {exc}. Install with:\n"
          f"  pip install pyyaml jsonschema", file=sys.stderr)
    raise SystemExit(2)

REPO = Path(os.environ.get("MEGATRON_REPO_ROOT",
                           Path(__file__).resolve().parent.parent)).resolve()

CONTRACT = REPO / "contracts" / "shield-telemetry.openapi.yaml"
PAGE = REPO / "ui" / "shield" / "index.html"

FIXTURE_RE = re.compile(
    r'<script[^>]*type="application/json"[^>]*id="fixture"[^>]*>(.*?)</script>',
    re.S | re.I)


def load_schemas() -> dict:
    spec = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    return spec["components"]["schemas"]


def validator_for(name: str, schemas: dict) -> Draft202012Validator:
    """Build a validator for one component schema.

    OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so no translation is needed —
    only a resolution root, so that "#/components/schemas/X" refs resolve.
    """
    root = {"$ref": f"#/components/schemas/{name}",
            "components": {"schemas": schemas}}
    return Draft202012Validator(root)


def extract_fixture() -> dict:
    match = FIXTURE_RE.search(PAGE.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"FAIL: no fixture <script> found in {PAGE.name}. If the page "
                         f"stopped carrying one, this check must be updated or removed "
                         f"deliberately — not left passing vacuously.")
    return json.loads(match.group(1))


def main() -> int:
    schemas = load_schemas()
    fixture = extract_fixture()

    # The fixture is the two responses the page fetches, combined into one
    # object for offline rendering: GET /v1/overview plus GET /v1/blocks under
    # a "blocks" key. Overview declares additionalProperties: false, so it is
    # validated WITHOUT that key rather than by loosening the contract to
    # accommodate a convenience of the demo harness.
    blocks = fixture.pop("blocks", None)
    if blocks is None:
        print("FAIL: fixture has no 'blocks' — the blocklist panel would be empty")
        return 1

    failures = 0
    schema_clean = True
    for name, instance in (("Overview", fixture), ("BlockPage", blocks)):
        errors = sorted(validator_for(name, schemas).iter_errors(instance),
                        key=lambda e: list(e.absolute_path))
        if errors:
            failures += len(errors)
            schema_clean = False
            print(f"FAIL: fixture does not conform to {name}:")
            for err in errors:
                where = "/".join(str(p) for p in err.absolute_path) or "(root)"
                print(f"  {where}: {err.message}")
        else:
            print(f"OK: fixture conforms to {name}")

    # The checks below index fields the schema has just guaranteed. Running
    # them on a fixture that FAILED validation buries the useful message
    # under a KeyError traceback, which in a CI log is how a clear diagnosis
    # becomes ten minutes of scrolling. Stop here and report what we know.
    if not schema_clean:
        print(f"\n{failures} problem(s). Later checks skipped — they assume a "
              f"schema-valid fixture.")
        return 1

    # The dashboard renders reason labels from a closed set. A value the page
    # does not know shows as a raw string, which is survivable, but a value in
    # the page that the CONTRACT does not allow is a straightforward lie about
    # what the agent can send.
    allowed = set(schemas["BlockReason"]["enum"])
    seen = {b["reason"] for b in blocks["items"]}
    seen |= {s["reason"] for s in fixture["top_sources"]}
    unknown = sorted(seen - allowed)
    if unknown:
        failures += 1
        print(f"FAIL: fixture uses reason(s) not in the contract enum: {unknown}")
    else:
        print(f"OK: all {len(seen)} reason value(s) are in the contract enum")

    # Uniform, gap-free buckets. The contract states a gap means the AGENT was
    # down rather than that traffic was zero, so a fixture with a hole in it
    # would be teaching the reader the wrong thing about the chart.
    times = [b["t"] for b in fixture["series"]]
    if len(times) >= 3:
        from datetime import datetime
        stamps = [datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times]
        deltas = {(stamps[i + 1] - stamps[i]).total_seconds() for i in range(len(stamps) - 1)}
        if len(deltas) != 1:
            failures += 1
            print(f"FAIL: series buckets are not uniform — widths {sorted(deltas)}s")
        else:
            print(f"OK: {len(times)} uniform {int(deltas.pop())}s buckets, no gaps")

    if failures:
        print(f"\n{failures} problem(s).")
        return 1
    print("\nPASS — the dashboard fixture matches the contract it cites.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
