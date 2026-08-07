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

# The three blocks that must agree, keyed by the normalised selector. The
# @media wrapper is not part of the selector — the block regex below skips
# any construct whose body is another block, which is exactly the at-rule.
BASE_SELECTOR = ":root"
DARK_SELECTORS = (':root:not([data-theme="light"])', ':root[data-theme="dark"]')
LIGHT_SELECTOR = ':root[data-theme="light"]'


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

    blocks = parse_css_tokens(path.read_text(encoding="utf-8"))
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

    for base in (REPO / "ui", Path(__file__).resolve().parent.parent / "ui"):
        candidate = base / "validate_palette.py"
        if not candidate.is_file():
            continue
        spec = importlib.util.spec_from_file_location("megatron_validate_palette", candidate)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
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
# ---------------------------------------------------------------------------

UI_DIR = "ui"
TOKENS_BASENAME = "tokens.css"

# SVG and XHTML namespace URIs are identifiers, not fetches — createElementNS
# requires the literal string and nothing is ever requested from it.
URL_ALLOWLIST = (
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
)

EXTERNAL_URL_RE = re.compile(r"https?://[^\s\"'()<>]+")
PROTOCOL_RELATIVE_RE = re.compile(r"""(?:src|href)\s*=\s*["']//""", re.I)
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

    JS `//` comments are deliberately NOT stripped here. Doing so would eat
    everything after the "//" in a string like "https://cdn.example/x", which
    is precisely the string this rule needs to see.
    """
    return BLOCK_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def ui_files() -> list[Path]:
    ui = REPO / UI_DIR
    if not ui.is_dir():
        return []
    return sorted(p for p in ui.rglob("*")
                  if p.is_file() and p.suffix.lower() in {".html", ".htm", ".css", ".js"})


def check_ui_self_contained(f: Findings) -> None:
    files = ui_files()
    if not files:
        f.note("no ui/ files yet — UI-SELF-CONTAINED not exercised")
        return

    checked = 0
    for path in files:
        rel = path.relative_to(REPO).as_posix()
        is_tokens = path.name == TOKENS_BASENAME
        checked += 1
        source = blank_block_comments(path.read_text(encoding="utf-8", errors="replace"))
        for n, line in enumerate(source.splitlines(), start=1):
            for match in EXTERNAL_URL_RE.finditer(line):
                url = match.group(0)
                if any(url.startswith(allowed) for allowed in URL_ALLOWLIST):
                    continue
                f.fail("UI-SELF-CONTAINED", path, n,
                       f"references {url}. The shield console is served from the edge "
                       f"node and must load nothing from the internet — an operator "
                       f"opens it when things are already going wrong.")
            if PROTOCOL_RELATIVE_RE.search(line):
                f.fail("UI-SELF-CONTAINED", path, n,
                       "protocol-relative URL. Same rule: no external resources.")

            # tokens.css is where colours are allowed to be literal; that is
            # the whole point of it, and the PALETTE rule reads it there.
            if is_tokens:
                continue
            code = line.split("//", 1)[0]
            if HEX_LITERAL_RE.search(code) or COLOUR_FN_RE.search(code):
                f.fail("UI-SELF-CONTAINED", path, n,
                       f"colour literal outside {UI_DIR}/{TOKENS_BASENAME}. Use a "
                       f"--mg-* token: literals here are invisible to the PALETTE "
                       f"contrast and colour-vision checks.")

    f.note(f"{checked} ui/ file(s) checked for external requests and colour literals")


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
