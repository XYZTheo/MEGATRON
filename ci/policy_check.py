#!/usr/bin/env python3
"""
MEGATRON structural policy gate.

This enforces the rules in CONTRIBUTING.md that can be checked by reading the
repository. It is deliberately stdlib-only and dependency-free so that it runs
identically on a developer's box and on a CI runner, and so that it can never
itself become a supply-chain concern in a project whose entire pitch is not
being MagnusBilling.

The rules here are not style. Each one corresponds to a specific way the
incumbent platforms failed, or to a mistake this project has already made once:

  KAMAILIO-NAMES   OpenSIPS has no htable/sanity/secfilter. Copy-pasted
                   Kamailio advice does not load, and it cost this project
                   real time. Never again silently.
  EDGE-CREDENTIALS The edge holds no database credential. This is the property
                   that makes an edge compromise survivable.
  CORE-PRIVATE     The core binds a private address. A public address there
                   dissolves the "no route from the internet" guarantee.
  ROUTE-TARGETS    A named route is called as route(name), not name().
  NO-SHELL-OUT     CVE-2023-30258 was one exec() with a concatenated string.
  MONEY-NOT-FLOAT  Money is integer micro-units. Never a float.
  LICENCE          No GPL/AGPL code linked into a MEGATRON binary.

Exit code 0 = clean, 1 = at least one violation.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Overridable so that ci/test_policy_check.py can point the gate at fixture
# trees containing deliberate violations. A gate nobody has ever seen fail is
# indistinguishable from a gate that cannot fail.
REPO = Path(os.environ.get("MEGATRON_REPO_ROOT", Path(__file__).resolve().parent.parent)).resolve()


@dataclass
class Findings:
    violations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, rule: str, path: Path, line_no: int | None, message: str) -> None:
        where = path.relative_to(REPO).as_posix()
        if line_no is not None:
            where = f"{where}:{line_no}"
        self.violations.append(f"[{rule}] {where}: {message}")

    def note(self, message: str) -> None:
        self.notes.append(message)


def sip_configs() -> list[Path]:
    return sorted(REPO.glob("*/opensips/*.cfg"))


def read_lines(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return list(enumerate(text.splitlines(), start=1))


def strip_comment(line: str) -> str:
    """OpenSIPS config comments start with '#'. There is no string literal in
    which a '#' is meaningful for the checks below, so this is sufficient and
    avoids matching rules inside explanatory prose."""
    return line.split("#", 1)[0]


# ---------------------------------------------------------------------------
# KAMAILIO-NAMES
# ---------------------------------------------------------------------------

KAMAILIO_ONLY = {
    "htable": "use cachedb_local (collections via cache_collections; cache_store/cache_fetch are core script functions)",
    "sanity": "use sipmsg_validate() from sipmsgops",
    "secfilter": "use textops/sipmsgops matching plus permissions",
    "sht_": "htable pseudo-variable family does not exist in OpenSIPS",
    "sanity_check": "use sipmsg_validate() from sipmsgops",
}


def check_kamailio_names(f: Findings) -> None:
    for cfg in sip_configs():
        for n, raw in read_lines(cfg):
            line = strip_comment(raw)
            if not line.strip():
                continue
            for name, remedy in KAMAILIO_ONLY.items():
                # loadmodule "htable.so" / sanity_check() / $sht(...)
                pattern = rf'(loadmodule\s*"{name}|[^\w]{name}\s*\(|\${name})'
                if re.search(pattern, line):
                    f.fail(
                        "KAMAILIO-NAMES", cfg, n,
                        f"'{name}' is a Kamailio name and does not exist in OpenSIPS 3.6 — {remedy}",
                    )


# ---------------------------------------------------------------------------
# EDGE-CREDENTIALS
#
# The single most load-bearing security property in the topology. If the edge
# can reach a database, a compromised edge yields tariff data, PII and ledger
# access, and the whole edge/core split stops buying anything.
# ---------------------------------------------------------------------------

CREDENTIAL_MARKERS = [
    (re.compile(r"\b(postgres|postgresql|mysql)://", re.I), "a database connection string"),
    (re.compile(r'loadmodule\s*"db_(postgres|mysql|sqlite|unixodbc)\.so"'), "a database driver module"),
    (re.compile(r'loadmodule\s*"auth_db\.so"'), "auth_db, which requires database credentials"),
]

# A modparam setting db_url to a NON-EMPTY value. Several modules the edge does
# legitimately use (permissions, dispatcher) accept a db_url and are told to run
# in file/static mode by being given an empty one. Flagging the parameter itself
# would flag exactly the lines that prove the property holds; what matters is
# whether a value was supplied.
DB_URL_RE = re.compile(r'modparam\s*\(\s*"[^"]+"\s*,\s*"db_url"\s*,\s*"([^"]*)"')


def check_edge_holds_no_credentials(f: Findings) -> None:
    edge = REPO / "edge"
    if not edge.is_dir():
        f.note("no edge/ directory yet — EDGE-CREDENTIALS not exercised")
        return
    for cfg in sorted(edge.rglob("*.cfg")):
        asserted_empty = 0
        for n, raw in read_lines(cfg):
            line = strip_comment(raw)
            for pattern, what in CREDENTIAL_MARKERS:
                if pattern.search(line):
                    f.fail(
                        "EDGE-CREDENTIALS", cfg, n,
                        f"edge config references {what}. The edge asks the core a narrow "
                        f"question; it does not look things up. See CONTRIBUTING.md.",
                    )
            m = DB_URL_RE.search(line)
            if m:
                if m.group(1).strip():
                    f.fail(
                        "EDGE-CREDENTIALS", cfg, n,
                        f"edge config sets a non-empty db_url ({m.group(1)!r}). The edge "
                        f"holds no database credential — that is the property that makes "
                        f"an edge compromise survivable. See CONTRIBUTING.md.",
                    )
                else:
                    asserted_empty += 1
        if asserted_empty:
            f.note(f"{cfg.relative_to(REPO).as_posix()}: {asserted_empty} module(s) pinned "
                   f"to file/static mode via an empty db_url")


# ---------------------------------------------------------------------------
# CORE-PRIVATE
# ---------------------------------------------------------------------------

SOCKET_RE = re.compile(r"^\s*socket\s*=\s*\w+:\[?([0-9a-fA-F:.]+)\]?:", re.M)


def is_private_v4(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )


def check_core_binds_private(f: Findings) -> None:
    core = REPO / "core" / "opensips"
    if not core.is_dir():
        f.note("no core/opensips directory yet — CORE-PRIVATE not exercised")
        return
    for cfg in sorted(core.glob("*.cfg")):
        found_any = False
        for n, raw in read_lines(cfg):
            line = strip_comment(raw)
            m = SOCKET_RE.match(line)
            if not m:
                continue
            found_any = True
            addr = m.group(1)
            if ":" in addr:  # IPv6: only loopback and unique-local are acceptable
                if not (addr.startswith("fd") or addr.startswith("fc") or addr == "::1"):
                    f.fail("CORE-PRIVATE", cfg, n,
                           f"core binds non-private IPv6 address {addr}")
                continue
            if not is_private_v4(addr):
                f.fail("CORE-PRIVATE", cfg, n,
                       f"core binds {addr}, which is not a private address. The core "
                       f"must have no route from the public internet "
                       f"(ARCHITECTURE.md 4.5b).")
        if not found_any:
            f.fail("CORE-PRIVATE", cfg, None,
                   "core config declares no socket= line, so the bind address is "
                   "unconstrained and defaults to every interface")


# ---------------------------------------------------------------------------
# ROUTE-TARGETS
#
# opensips -C catches a call to a route that does not exist, but only once the
# config parses far enough. Catching it here gives a precise line number and
# runs on machines with no OpenSIPS installed.
# ---------------------------------------------------------------------------

ROUTE_DEF_RE = re.compile(r"^\s*(route|failure_route|onreply_route|branch_route|local_route|startup_route|timer_route|event_route)\s*\[\s*([A-Za-z_][\w]*)\s*\]")
ROUTE_CALL_RE = re.compile(r"[^\w](route)\s*\(\s*([A-Za-z_][\w]*)\s*\)")


def check_route_targets(f: Findings) -> None:
    for cfg in sip_configs():
        defined: set[str] = set()
        calls: list[tuple[int, str]] = []
        for n, raw in read_lines(cfg):
            line = strip_comment(raw)
            m = ROUTE_DEF_RE.match(line)
            if m:
                defined.add(m.group(2))
            for cm in ROUTE_CALL_RE.finditer(" " + line):
                calls.append((n, cm.group(2)))
        for n, target in calls:
            if target not in defined:
                f.fail("ROUTE-TARGETS", cfg, n,
                       f"route({target}) has no matching route[{target}] block in this file")


# ---------------------------------------------------------------------------
# NO-SHELL-OUT and MONEY-NOT-FLOAT
#
# No Kotlin or Go exists in the repository yet. These checks are written now
# rather than later precisely because they are cheap now: the first time
# somebody adds a service, the gate is already standing. A check that only
# appears after the code it governs has never once prevented anything.
# ---------------------------------------------------------------------------

SOURCE_GLOBS = ("**/*.kt", "**/*.kts", "**/*.go", "**/*.java", "**/*.ts", "**/*.tsx")

SHELL_OUT_PATTERNS = [
    (re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b"), "Runtime.exec"),
    (re.compile(r"\bProcessBuilder\s*\(\s*\"" ), "ProcessBuilder with a single string (use an argv list)"),
    (re.compile(r"\bexec\.Command\s*\(\s*\"(sh|bash|/bin/sh|/bin/bash|cmd)\b"), "exec.Command invoking a shell"),
    (re.compile(r"\bchild_process\b"), "child_process"),
]

FLOAT_MONEY_PATTERNS = [
    (re.compile(r"\b(Double|Float)\b"), "a floating-point type"),
    (re.compile(r"\bfloat(32|64)\b"), "a floating-point type"),
]

MONEY_PATH_HINTS = ("billing", "rating", "ledger", "tariff", "invoice", "money")


def source_files() -> list[Path]:
    out: list[Path] = []
    for pattern in SOURCE_GLOBS:
        for p in REPO.glob(pattern):
            if ".git" in p.parts or "node_modules" in p.parts or "build" in p.parts:
                continue
            out.append(p)
    return sorted(out)


def check_source_rules(f: Findings) -> None:
    files = source_files()
    if not files:
        f.note("no Kotlin/Go/TypeScript source yet — NO-SHELL-OUT and MONEY-NOT-FLOAT "
               "are armed but not yet exercised")
        return
    for path in files:
        rel = path.relative_to(REPO).as_posix().lower()
        is_money = any(hint in rel for hint in MONEY_PATH_HINTS)
        for n, line in read_lines(path):
            code = line.split("//", 1)[0]
            for pattern, what in SHELL_OUT_PATTERNS:
                if pattern.search(code):
                    f.fail("NO-SHELL-OUT", path, n,
                           f"{what}. Node-side operations go to the Go agent as a typed "
                           f"message with a closed verb set.")
            if is_money:
                for pattern, what in FLOAT_MONEY_PATTERNS:
                    if pattern.search(code):
                        f.fail("MONEY-NOT-FLOAT", path, n,
                               f"{what} in a money path. Use Long micro-units internally "
                               f"and BigDecimal at boundaries.")


# ---------------------------------------------------------------------------
# LICENCE
#
# The gate that CONTRIBUTING.md promises exists. Two halves:
#
#  (a) Nothing copyleft is vendored into the tree. MEGATRON depends on GPL
#      software installed separately from distro repositories; it never
#      redistributes it.
#
#  (b) Dependency manifests are scanned. There are none yet. Rather than
#      quietly passing, this FAILS when a manifest type appears that it does
#      not know how to scan — so the gate cannot be silently outgrown by the
#      first person to add a build file. That is the failure mode that makes
#      most licence gates worthless by month six.
# ---------------------------------------------------------------------------

COPYLEFT_MARKERS = re.compile(
    r"(GNU GENERAL PUBLIC LICENSE|GNU AFFERO GENERAL PUBLIC LICENSE|"
    r"GNU LESSER GENERAL PUBLIC LICENSE|SPDX-License-Identifier:\s*(A?GPL|LGPL))",
    re.I,
)

KNOWN_MANIFESTS = {
    "build.gradle.kts": False,   # scanner not written yet
    "build.gradle": False,
    "pom.xml": False,
    "go.mod": False,
    "package.json": False,
    "Cargo.toml": False,
}

# Files that legitimately discuss copyleft without being copyleft: our own
# licence, the documents that explain the copyleft posture, this gate, and the
# gate's tests (which must contain a GPL header as a fixture in order to prove
# the gate detects one).
#
# Keep this list short and specific. Every entry is a place the scanner is
# blind, so a new one belongs in a PR that says why.
LICENCE_DISCUSSION_ALLOWLIST = {
    "docs/ARCHITECTURE.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "ci/policy_check.py",
    "ci/test_policy_check.py",
    "docs/ONBOARDING.md",
    "README.md",
}


def check_licence(f: Findings) -> None:
    for path in REPO.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = path.relative_to(REPO).as_posix()
        if rel in LICENCE_DISCUSSION_ALLOWLIST:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".gif", ".zip", ".jar", ".gz", ".ico"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        if COPYLEFT_MARKERS.search(text):
            f.fail("LICENCE", path, None,
                   "file carries a copyleft licence header. MEGATRON is proprietary and "
                   "must not vendor GPL/AGPL/LGPL code — depend on it via distro packages "
                   "instead.")

    unscannable = []
    for name, have_scanner in KNOWN_MANIFESTS.items():
        for found in REPO.rglob(name):
            if ".git" in found.parts or "build" in found.parts:
                continue
            if not have_scanner:
                unscannable.append(found.relative_to(REPO).as_posix())

    if unscannable:
        for rel in unscannable:
            f.violations.append(
                f"[LICENCE] {rel}: a dependency manifest exists but this gate has no "
                f"scanner for it. Dependencies are entering the build unscanned. Add a "
                f"scanner to ci/policy_check.py before merging this."
            )
    else:
        f.note("no dependency manifests yet — licence scanning is header-only so far, "
               "and this gate will fail the moment a manifest appears without a scanner")


# ---------------------------------------------------------------------------

CHECKS = (
    check_kamailio_names,
    check_edge_holds_no_credentials,
    check_core_binds_private,
    check_route_targets,
    check_source_rules,
    check_licence,
)


def main() -> int:
    f = Findings()
    for check in CHECKS:
        check(f)

    print(f"MEGATRON policy gate — {len(CHECKS)} rule groups, repo at {REPO}")
    print()

    for note in f.notes:
        print(f"  note: {note}")
    if f.notes:
        print()

    if not f.violations:
        print("PASS — no policy violations.")
        return 0

    print(f"FAIL — {len(f.violations)} violation(s):")
    print()
    for v in f.violations:
        print(f"  {v}")
    print()
    print("These rules exist because the incumbent platforms failed in exactly these")
    print("ways. If one is genuinely wrong, change the rule deliberately in")
    print("ci/policy_check.py and say why in the PR — do not work around it.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
