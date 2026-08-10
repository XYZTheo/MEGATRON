#!/usr/bin/env python3
"""Validate a categorical chart palette against the computable colour checks.

WHY THIS FILE EXISTS
--------------------
`ui/tokens.css` claims its chart series colours were "validated, not chosen by
eye". A claim that cannot be re-run is a claim that quietly rots the first time
someone nudges a hex. This is the re-runnable form of it, and CI executes it
(`ci/policy_check.py`, rule group PALETTE-VALIDATED) so the claim cannot go
stale without failing the build.

It is deliberately a *Python* port. The canonical implementation is a Node
script, and this repository's only guaranteed toolchain is Python 3.11 — see
docs/ONBOARDING.md. A check that requires a runtime we do not have is a check
that never runs.

WHAT IT MEASURES
----------------
Five things that are computable from colour alone. It does not have opinions
about taste:

  2.  Lightness band    — OKLCH L inside the mode's band
  3.  Chroma floor      — OKLCH C >= floor (below it, a hue reads as grey and
                          stops doing identity work)
  4.  CVD separation    — OKLab dE (x100) between slots under simulated
                          protanopia/deuteranopia (tritan reported, not gated)
  4b. Normal-vision floor — worst dE on the same pairlist, unsimulated. Full-
                          colour readers must be able to tell neighbours apart
                          too. Hard gate: secondary encoding does not excuse it.
  5.  Contrast vs surface — WCAG ratio of each mark against the chart surface

Checks 1 (fixed hue order) and 6 (values come from the documented palette) are
structural and are not measurable from hexes.

Exit codes: 0 = no hard failure, 1 = at least one FAIL, 2 = bad usage. WARN
bands do not fail the run: floor-band CVD (6-8) and sub-3:1 contrast are each
legal *only* alongside secondary encoding — direct labels, gaps, or texture.

USAGE
-----
    python ui/validate_palette.py "#2C7CBF,#9A6614" --mode light  --surface "#F5F7F7"
    python ui/validate_palette.py "#4A98D8,#B87C2A" --mode dark   --surface "#0E1418"
    python ui/validate_palette.py "#86B6EF,#5598E7,#256ABF" --ordinal
"""

from __future__ import annotations

import argparse
import math
import re
import sys
from typing import Iterable, Sequence

# ── thresholds ───────────────────────────────────────────────────────────────
BAND = {"light": (0.43, 0.77), "dark": (0.48, 0.67)}  # OKLCH L
CHROMA_FLOOR = 0.10  # OKLCH C
# dE throughout is Euclidean distance in OKLab x100. The CVD thresholds are
# calibrated to the Machado-Oliveira-Fernandes (2009) severity-1.0 simulation
# below; the simulation model is part of the standard, not an implementation
# detail. Swapping in a different model (e.g. Vienot 1999) moves borderline
# pairs and would require recalibrating these numbers.
CVD_TARGET, CVD_FLOOR = 8.0, 6.0  # min(protan, deutan) over the pairlist
NORMAL_FLOOR = 15.0  # worst pair, unsimulated vision — hard gate
CONTRAST_MIN = 3.0  # WCAG, mark vs surface
DEFAULT_SURFACE = {"light": "#fcfcfb", "dark": "#1a1a19"}
ORDINAL_MIN_DL = 0.06  # min OKLCH dL between adjacent ramp steps
ORDINAL_LIGHT_FLOOR = 2.0  # lightest step: WCAG contrast vs surface

# Machado, Oliveira & Fernandes (2009), severity 1.0, applied in linear RGB.
MACHADO = {
    "protan": ((0.152286, 1.052583, -0.204868),
               (0.114503, 0.786281, 0.099216),
               (-0.003882, -0.048116, 1.051998)),
    "deutan": ((0.367322, 0.860646, -0.227968),
               (0.280085, 0.672501, 0.047413),
               (-0.011820, 0.042940, 0.968881)),
    "tritan": ((1.255528, -0.076749, -0.178779),
               (-0.078411, 0.930809, 0.147602),
               (0.004733, 0.691367, 0.303900)),
}

# ── input boundary ───────────────────────────────────────────────────────────
# Every caller-supplied colour string (palette entries AND the surface) passes
# through these before any arithmetic. Unguarded, int(x, 16) raises deep inside
# a check and the run fails open — which is the worst possible outcome for a
# gate. Normalisation is spelled out rather than left to str.strip() because
# the Node twin uses String.trim(), and the two disagree at the edges: trim()
# strips U+FEFF, str.strip() strips U+001C-U+001F and U+0085. The set below is
# their intersection — ASCII whitespace plus the Unicode separators both strip
# — which also covers the NBSP/em-space padding you pick up pasting a hex list
# out of a rendered page. Keep these three definitions in lockstep with the JS.
_WS = ("[ \\t\\n\\v\\f\\r\\u00a0\\u1680\\u2000-\\u200a"
       "\\u2028\\u2029\\u202f\\u205f\\u3000]+")
_WS_RE = re.compile(rf"^{_WS}|{_WS}$")
_HEX_RE = re.compile(r"^#?[0-9a-fA-F]{6}$")


def strip_ws(value: str) -> str:
    return _WS_RE.sub("", value)


def split_colors(raw: str | None) -> list[str]:
    return [c for c in (strip_ws(p) for p in (raw or "").split(",")) if c]


def is_hex_color(value: str) -> bool:
    return bool(_HEX_RE.match(value))


# ── colour conversions ───────────────────────────────────────────────────────
def _hex_to_srgb(h: str) -> tuple[float, float, float]:
    h = strip_ws(h).lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def _s2lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _lin(h: str) -> tuple[float, float, float]:
    return tuple(_s2lin(c) for c in _hex_to_srgb(h))  # type: ignore[return-value]


def _rel_lum(h: str) -> float:
    r, g, b = _lin(h)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    """WCAG contrast ratio. Exported for one-off status/text-colour checks."""
    hi, lo = sorted((_rel_lum(a), _rel_lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _oklab_from_lin(rgb: Sequence[float]) -> tuple[float, float, float]:
    r, g, b = rgb
    l = math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
    m = math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
    s = math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
    return (
        0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,  # L
        1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,  # a
        0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,  # b
    )


def _oklab(h: str) -> tuple[float, float, float]:
    return _oklab_from_lin(_lin(h))


def oklch(h: str) -> tuple[float, float]:
    """Return (L, C). Hue is only needed by the ordinal checks."""
    L, a, b = _oklab(h)
    return L, math.hypot(a, b)


def okhue(h: str) -> float:
    _, a, b = _oklab(h)
    return math.degrees(math.atan2(b, a)) % 360


def _simulate(h: str, kind: str) -> tuple[float, float, float]:
    r, g, b = _lin(h)
    M = MACHADO[kind]
    return tuple(min(1.0, max(0.0, row[0] * r + row[1] * g + row[2] * b)) for row in M)  # type: ignore[return-value]


def delta_e(h1: str, h2: str, kind: str | None = None) -> float:
    """Euclidean distance in OKLab, x100. kind=None is unsimulated vision."""
    a = _oklab_from_lin(_simulate(h1, kind) if kind else _lin(h1))
    b = _oklab_from_lin(_simulate(h2, kind) if kind else _lin(h2))
    return 100 * math.dist(a, b)


def _pairlist(n: int, pairs: str) -> list[tuple[int, int]]:
    if pairs == "all":
        return [(i, j) for i in range(n) for j in range(i + 1, n)]
    return [(i, i + 1) for i in range(n - 1)]


# ── checks ───────────────────────────────────────────────────────────────────
Report = list[tuple[str, object, str]]


def validate(palette: Sequence[str], mode: str = "light", surface: str | None = None,
             pairs: str = "adjacent") -> tuple[Report, bool]:
    """The categorical checks. Returns (report rows, ok)."""
    surface = surface or DEFAULT_SURFACE[mode]
    lo, hi = BAND[mode]
    report: Report = []
    ok = True

    # 2. lightness band
    offband = [(c, round(oklch(c)[0], 3)) for c in palette if not lo <= oklch(c)[0] <= hi]
    if offband:
        ok = False
    report.append(("Lightness band", not offband,
                   f"outside band: {offband}" if offband
                   else f"all {len(palette)} inside L {lo}-{hi}"))

    # 3. chroma floor
    lowc = [(c, round(oklch(c)[1], 3)) for c in palette if oklch(c)[1] < CHROMA_FLOOR]
    if lowc:
        ok = False
    report.append(("Chroma floor", not lowc,
                   f"below floor (reads grey): {lowc}" if lowc
                   else f"all {len(palette)} >= {CHROMA_FLOOR}"))

    # 4. CVD separation. Adjacent pairs for stacks/bars/lines, where only
    #    neighbours ever touch; ALL pairs for scatter/bubble/choropleth/small
    #    multiples, where any two marks can end up side by side.
    plist = _pairlist(len(palette), pairs)
    label = "all-pairs" if pairs == "all" else "adjacent"
    worst = None
    for kind in ("protan", "deutan"):
        for i, j in plist:
            d = delta_e(palette[i], palette[j], kind)
            if worst is None or d < worst[0]:
                worst = (d, kind, palette[i], palette[j])
    tri = min((delta_e(palette[i], palette[j], "tritan") for i, j in plist), default=99.0)
    wd = worst[0] if worst else 99.0
    cvd_state = "pass" if wd >= CVD_TARGET else "floor" if wd >= CVD_FLOOR else "fail"
    if cvd_state == "fail":
        ok = False
    report.append(("CVD separation", cvd_state,
                   f"worst {label} {worst[3]}<->{worst[2]} dE {wd:.1f} ({worst[1]})"
                   f" - tritan {tri:.1f}" if worst else "n/a"))

    # 4b. Normal-vision floor. The CVD gate protects dichromat readers; this
    #     one protects everyone else. Hard gate — a weak pair here gets
    #     re-stepped, never excused with a label.
    nworst = None
    for i, j in plist:
        d = delta_e(palette[i], palette[j])
        if nworst is None or d < nworst[0]:
            nworst = (d, palette[i], palette[j])
    nd = nworst[0] if nworst else 99.0
    nor_state = "pass" if nd >= NORMAL_FLOOR else "fail"
    if nor_state == "fail":
        ok = False
    report.append(("Normal-vision floor", nor_state,
                   (f"worst {label} {nworst[2]}<->{nworst[1]} dE {nd:.1f} (normal)"
                    + ("" if nd >= NORMAL_FLOOR else
                       f" - below {NORMAL_FLOOR:.0f}, hard to tell apart even with"
                       " full colour vision")) if nworst else "n/a"))

    # 5. contrast vs surface — sub-3:1 is a documented conditional relief
    #    (visible labels or a table view), not a hard failure.
    low = [(c, round(contrast(c, surface), 2)) for c in palette
           if contrast(c, surface) < CONTRAST_MIN]
    report.append(("Contrast vs surface", "relief" if low else "pass",
                   f"below {CONTRAST_MIN}:1 - relief required (visible labels or table"
                   f" view): {low}" if low else f"all {len(palette)} >= {CONTRAST_MIN}:1"))

    return report, ok


def validate_ordinal(palette: Sequence[str], mode: str = "light",
                     surface: str | None = None) -> tuple[Report, bool]:
    """Ordered categories (funnel stages, size tiers, time buckets) take a
    one-hue ramp, not categorical hues. The categorical checks FAIL a correct
    ramp by design — it spans the lightness band, and its light steps drop
    below the chroma floor. These checks instead verify it reads *as a ramp*."""
    surface = surface or DEFAULT_SURFACE[mode]
    report: Report = []
    ok = True
    Ls = [oklch(c)[0] for c in palette]

    # Monotone lightness — sorted by L must match input order, or its reverse.
    order = sorted(range(len(Ls)), key=lambda i: Ls[i])
    mono = order == list(range(len(Ls))) or order == list(reversed(range(len(Ls))))
    if not mono:
        ok = False
    report.append(("Lightness monotone", mono,
                   "steps read light->dark" if mono
                   else f"out of order - L values {[round(l, 3) for l in Ls]}"))

    # Adjacent dL — each step must be visibly distinct from its neighbour.
    # Filter on the RAW gap and round only for display: filtering the rounded
    # value would pass raw gaps in [0.0595, 0.06) that the Node twin fails.
    gaps = [abs(Ls[i + 1] - Ls[i]) for i in range(len(Ls) - 1)]
    thin = [(palette[i], palette[i + 1], round(g, 3))
            for i, g in enumerate(gaps) if g < ORDINAL_MIN_DL]
    if thin:
        ok = False
    report.append(("Adjacent dL", not thin,
                   f"steps too close: {thin}" if thin else f"all gaps >= {ORDINAL_MIN_DL}"))

    # Lightest step vs surface — the pale end must still read as a mark.
    by_l = sorted(palette, key=lambda c: oklch(c)[0])
    lightest = by_l[-1] if mode == "light" else by_l[0]
    cr = contrast(lightest, surface)
    if cr < ORDINAL_LIGHT_FLOOR:
        ok = False
    report.append(("Light-end contrast", cr >= ORDINAL_LIGHT_FLOOR,
                   f"{lightest} at {cr:.2f}:1 vs surface"
                   + ("" if cr >= ORDINAL_LIGHT_FLOOR
                      else f" - below {ORDINAL_LIGHT_FLOOR}:1 floor")))

    # Single hue — an ordinal ramp is one hue; a hue jump means it is
    # categorical and was validated with the wrong set of checks.
    hues = [okhue(c) for c in palette]
    spread = (max(hues) - min(hues)) if hues else 0.0
    if spread > 180:
        spread = 360 - spread
    one_hue = spread <= 40
    if not one_hue:
        ok = False
    report.append(("Single hue", one_hue,
                   f"hue spread {spread:.0f}deg"
                   + ("" if one_hue else " - >40deg, not a one-hue ramp")))

    return report, ok


# ── CLI ──────────────────────────────────────────────────────────────────────
_GLYPH = {True: "PASS", False: "FAIL", "pass": "PASS", "floor": "WARN",
          "fail": "FAIL", "relief": "WARN"}


def _print_report(report: Report, ok: bool, mode: str, surface: str,
                  ordinal: bool, n: int) -> None:
    kind = "ordinal ramp" if ordinal else "categorical"
    print(f"\nPalette ({mode}, surface {surface}, {kind}): {n} slots")
    for name, state, detail in report:
        print(f"  [{_GLYPH.get(state, state):<4}] {name:<22} {detail}")
    verdict = "ALL CHECKS PASS" if ok else "FAILED - fix the marked checks"
    if ordinal:
        print(f"\n  -> {verdict}  (ordinal: one hue, monotone L, visible step gaps,"
              " light end clears surface)\n")
    else:
        print(f"\n  -> {verdict}  (CVD in the 6-8 floor band is legal ONLY with"
              " secondary encoding: direct labels, gaps, or texture)")
        print("  scope: categorical palettes only. For a lone status/text colour check"
              " WCAG text contrast; for a sequential ramp, lightness monotonicity.\n")


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="validate_palette.py", add_help=True,
        description="Validate a categorical chart palette (or an ordinal ramp).")
    p.add_argument("palette", nargs="?", help='comma-separated hexes, e.g. "#2C7CBF,#9A6614"')
    p.add_argument("--mode", choices=("light", "dark"), default="light")
    p.add_argument("--surface", default=None, help="chart surface hex; defaults per mode")
    p.add_argument("--pairs", choices=("adjacent", "all"), default="adjacent",
                   help="'all' for scatter/bubble/map/small-multiples")
    p.add_argument("--ordinal", action="store_true",
                   help="validate as a one-hue ramp instead of categorical hues")
    args = p.parse_args(list(argv) if argv is not None else None)

    palette = split_colors(args.palette)
    if not palette:
        p.error('a palette is required, e.g. "#2C7CBF,#9A6614"')  # exits 2

    # An empty or whitespace-only --surface counts as absent, so it falls back
    # to the mode default rather than failing the hex check.
    raw_surface = strip_ws(args.surface) if args.surface is not None else ""
    surface = raw_surface or DEFAULT_SURFACE[args.mode]

    bad = [c for c in [*palette, surface] if not is_hex_color(c)]
    if bad:
        p.error(f"invalid hex value(s): {', '.join(bad)} - expected #rrggbb")  # exits 2

    if args.ordinal:
        report, ok = validate_ordinal(palette, args.mode, surface)
    else:
        report, ok = validate(palette, args.mode, surface, args.pairs)
    _print_report(report, ok, args.mode, surface, args.ordinal, len(palette))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
