#!/usr/bin/env python3
"""Tests for ui/validate_palette.py.

Run: python ui/test_validate_palette.py     (no third-party dependencies)

The point of these is the same as ci/test_policy_check.py: prove each check
actually FIRES. A validator that passes everything is indistinguishable from a
validator that is broken, and the failure mode is silent — you keep shipping,
the gate keeps saying PASS, and nobody finds out until a colourblind operator
cannot tell absorbed traffic from accepted traffic during an attack.

So every check gets a pair: a palette that must pass, and a palette that must
fail *for that specific reason*.
"""

from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import validate_palette as vp  # noqa: E402

# The two colours ui/tokens.css actually ships, per mode.
SHIPPED_LIGHT = ["#2C7CBF", "#9A6614"]
SHIPPED_DARK = ["#4A98D8", "#B87C2A"]
SURFACE_LIGHT, SURFACE_DARK = "#F5F7F7", "#0E1418"


def state_of(report: vp.Report, name: str) -> object:
    for row_name, state, _ in report:
        if row_name == name:
            return state
    raise AssertionError(f"no check named {name!r} in report")


class ShippedPalette(unittest.TestCase):
    """The palette in tokens.css must keep validating. This is the test that
    fails when somebody nudges a hex 'to make it pop'."""

    def test_light_mode_passes(self):
        report, ok = vp.validate(SHIPPED_LIGHT, "light", SURFACE_LIGHT)
        self.assertTrue(ok, report)

    def test_dark_mode_passes(self):
        report, ok = vp.validate(SHIPPED_DARK, "dark", SURFACE_DARK)
        self.assertTrue(ok, report)

    def test_dark_is_not_a_naive_inversion(self):
        # ARCHITECTURE 6.3: dark is a designed mode, re-stepped from the same
        # ramps. Note what is NOT asserted here: that the light steps fail the
        # dark checks. They don't, and they can't be made to -- the dark
        # lightness band (0.48-0.67) sits inside the light one (0.43-0.77), so
        # a light palette validating under --mode dark is arithmetic, not
        # evidence. The real designed property is that each dark step is
        # LIGHTER than its light counterpart, because the surface it has to
        # out-contrast got darker.
        self.assertNotEqual(SHIPPED_LIGHT, SHIPPED_DARK)
        for light, dark in zip(SHIPPED_LIGHT, SHIPPED_DARK):
            with self.subTest(light=light, dark=dark):
                self.assertGreater(vp.oklch(dark)[0], vp.oklch(light)[0])
                # ...and that the re-step actually bought contrast on the
                # surface it was picked for. This is the assertion that fails
                # if someone "simplifies" tokens.css by reusing one palette.
                self.assertGreater(vp.contrast(dark, SURFACE_DARK),
                                   vp.contrast(light, SURFACE_DARK))

    def test_series_colours_are_not_status_colours(self):
        # Status is reserved and must never impersonate a series.
        status = {"#127A4E", "#8A5D00", "#BE302C",
                  "#48B57F", "#DDA63F", "#E4665F"}
        self.assertFalse(status & set(SHIPPED_LIGHT + SHIPPED_DARK))


class LightnessBand(unittest.TestCase):
    def test_too_light_fails(self):
        report, ok = vp.validate(["#EAF3FB", "#9A6614"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertFalse(state_of(report, "Lightness band"))

    def test_too_dark_fails(self):
        report, ok = vp.validate(["#0A1B2A", "#9A6614"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertFalse(state_of(report, "Lightness band"))

    def test_bands_differ_by_mode(self):
        self.assertNotEqual(vp.BAND["light"], vp.BAND["dark"])


class ChromaFloor(unittest.TestCase):
    def test_grey_fails(self):
        # A desaturated step reads as grey and stops carrying identity.
        report, ok = vp.validate(["#808080", "#9A6614"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertFalse(state_of(report, "Chroma floor"))


class CVDSeparation(unittest.TestCase):
    def test_red_green_pair_collapses(self):
        # The classic mistake: red vs green as the two series. Under protan
        # simulation they converge. This is exactly the pair the shield
        # dashboard would have used if the palette were eyeballed.
        report, ok = vp.validate(["#C0392B", "#2E8B57"], "light", SURFACE_LIGHT)
        self.assertIn(state_of(report, "CVD separation"), ("floor", "fail"))
        del ok

    def test_identical_colours_fail_hard(self):
        report, ok = vp.validate(["#2C7CBF", "#2C7CBF"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertEqual(state_of(report, "CVD separation"), "fail")

    def test_all_pairs_is_strictly_harder_than_adjacent(self):
        # Three slots where 1<->2 and 2<->3 are fine but 1<->3 collide, so
        # adjacent passes and all-pairs must not. Guards against --pairs being
        # silently ignored, which would hide a real collapse on scatter/maps.
        pal = ["#2C7CBF", "#9A6614", "#2E82C4"]
        adj = min(vp.delta_e(pal[i], pal[i + 1]) for i in range(2))
        allp = min(vp.delta_e(pal[i], pal[j])
                   for i in range(3) for j in range(i + 1, 3))
        self.assertLess(allp, adj)
        _, ok_all = vp.validate(pal, "light", SURFACE_LIGHT, pairs="all")
        self.assertFalse(ok_all)

    def test_pairlist_shapes(self):
        self.assertEqual(vp._pairlist(4, "adjacent"), [(0, 1), (1, 2), (2, 3)])
        self.assertEqual(len(vp._pairlist(4, "all")), 6)

    def test_single_slot_has_no_pairs(self):
        # Degenerate but reachable: one series. Must not crash or divide by
        # zero, and must not claim a separation it never measured.
        report, ok = vp.validate(["#2C7CBF"], "light", SURFACE_LIGHT)
        self.assertTrue(ok)
        self.assertEqual(state_of(report, "CVD separation"), "pass")


class NormalVisionFloor(unittest.TestCase):
    def test_near_identical_fails_even_with_normal_vision(self):
        report, ok = vp.validate(["#2C7CBF", "#2E82C4"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertEqual(state_of(report, "Normal-vision floor"), "fail")

    def test_is_a_hard_gate_not_a_warning(self):
        # Distinct from the CVD floor band, which only WARNs. If this ever
        # softens to a WARN the run would exit 0 on an unreadable palette.
        report, ok = vp.validate(["#2C7CBF", "#2E82C4"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertNotEqual(state_of(report, "Normal-vision floor"), "floor")


class ContrastVsSurface(unittest.TestCase):
    def test_low_contrast_warns_but_does_not_fail(self):
        # Sub-3:1 is a documented relief case, not a hard failure -- it
        # obligates visible labels or a table view instead.
        report, ok = vp.validate(["#9A6614", "#2C7CBF"], "light", "#8A5D00")
        self.assertEqual(state_of(report, "Contrast vs surface"), "relief")
        self.assertTrue(ok, "contrast relief must not fail the run")

    def test_contrast_is_symmetric_and_known(self):
        self.assertAlmostEqual(vp.contrast("#000000", "#FFFFFF"), 21.0, places=2)
        self.assertAlmostEqual(vp.contrast("#FFFFFF", "#000000"), 21.0, places=2)
        self.assertAlmostEqual(vp.contrast("#123456", "#123456"), 1.0, places=6)


class UIInkContrast(unittest.TestCase):
    """tokens.css ink steps carry text, so they take WCAG *text* contrast --
    a different gate from the categorical checks (see the module docstring's
    scope note).

    Each step is measured against the WORST surface it can land on, not the
    friendliest: --mg-sunken in light mode (the row-hover fill) and
    --mg-raised in dark. Measuring ink against white is how the original
    --mg-ink-faint shipped at 2.70:1 on --mg-ground while looking fine in
    isolation."""

    # (name, light hex, dark hex)
    INK = (("ink", "#0F1719", "#E6EDEF"),
           ("ink-muted", "#46545B", "#9AABB3"),
           ("ink-faint", "#5F6D74", "#7C8C94"))
    LIGHT_SURFACES = ("#FFFFFF", "#F5F7F7", "#ECEFEF")  # raised, ground, sunken
    DARK_SURFACES = ("#151D21", "#0E1418", "#0A0F12")

    def test_every_ink_step_clears_body_text_on_every_surface(self):
        # Including --mg-ink-faint. It carries 10px axis labels and 11px
        # timestamps: small text, which takes 4.5:1, full stop. "Faint" is
        # carried by size, weight and tracking -- never by going illegible.
        for name, light, dark in self.INK:
            for surface in self.LIGHT_SURFACES:
                with self.subTest(step=name, mode="light", surface=surface):
                    self.assertGreaterEqual(vp.contrast(light, surface), 4.5)
            for surface in self.DARK_SURFACES:
                with self.subTest(step=name, mode="dark", surface=surface):
                    self.assertGreaterEqual(vp.contrast(dark, surface), 4.5)

    def test_ink_steps_stay_visibly_apart(self):
        # All three clearing 4.5:1 is necessary but not sufficient -- if they
        # converge, the hierarchy silently disappears while every contrast
        # check still passes. Pin the lightness gaps that carry it.
        for mode, idx in (("light", 1), ("dark", 2)):
            Ls = [vp.oklch(step[idx])[0] for step in self.INK]
            with self.subTest(mode=mode):
                self.assertEqual(Ls, sorted(Ls, reverse=(mode == "dark")))
                gaps = [abs(Ls[i + 1] - Ls[i]) for i in range(len(Ls) - 1)]
                self.assertTrue(all(g >= 0.06 for g in gaps), gaps)

    def test_accent_clears_non_text_contrast(self):
        # Focus rings and link underlines are non-text: 3:1 on any surface.
        for surface in self.LIGHT_SURFACES:
            self.assertGreaterEqual(vp.contrast("#26699F", surface), 3.0)
        for surface in self.DARK_SURFACES:
            self.assertGreaterEqual(vp.contrast("#4A98D8", surface), 3.0)

    def test_status_text_on_its_own_tinted_background(self):
        for fg, bg in (("#127A4E", "#E2F1E9"), ("#8A5D00", "#F6EEDC"),
                       ("#BE302C", "#F8E5E4"), ("#48B57F", "#12261D"),
                       ("#DDA63F", "#2A2113"), ("#E4665F", "#2C1717")):
            with self.subTest(fg=fg, bg=bg):
                self.assertGreaterEqual(vp.contrast(fg, bg), 4.5)


class OrdinalRamp(unittest.TestCase):
    def test_good_ramp_passes(self):
        report, ok = vp.validate_ordinal(["#76A8E4", "#4A88D0", "#256ABF", "#104281"],
                                         "light", SURFACE_LIGHT)
        self.assertTrue(ok, report)

    def test_non_monotone_fails(self):
        report, ok = vp.validate_ordinal(["#5598E7", "#86B6EF", "#256ABF"],
                                         "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertFalse(state_of(report, "Lightness monotone"))

    def test_hue_jump_fails(self):
        report, ok = vp.validate_ordinal(["#86B6EF", "#9A6614"], "light", SURFACE_LIGHT)
        self.assertFalse(ok)
        self.assertFalse(state_of(report, "Single hue"))

    def test_categorical_checks_would_fail_a_correct_ramp(self):
        # Documented in the docstring, and worth pinning: running the wrong
        # validator produces a confident, wrong FAIL. Someone will do it.
        _, ok = vp.validate(["#76A8E4", "#4A88D0", "#256ABF", "#104281"],
                            "light", SURFACE_LIGHT)
        self.assertFalse(ok)


class InputBoundary(unittest.TestCase):
    """Malformed input must fail LOUD, never fail open. A gate that throws
    or silently skips is worse than no gate -- it reports success."""

    def test_unicode_padding_is_stripped(self):
        self.assertEqual(vp.split_colors(" #2C7CBF ,　#9A6614 "),
                         ["#2C7CBF", "#9A6614"])

    def test_empty_entries_are_dropped(self):
        self.assertEqual(vp.split_colors("#2C7CBF,,  ,#9A6614"),
                         ["#2C7CBF", "#9A6614"])
        self.assertEqual(vp.split_colors(""), [])
        self.assertEqual(vp.split_colors(None), [])

    def test_hex_recogniser(self):
        for good in ("#2C7CBF", "2c7cbf", "#FFFFFF"):
            self.assertTrue(vp.is_hex_color(good), good)
        for bad in ("#2C7CB", "#2C7CBFF", "rgb(1,2,3)", "#GGGGGG", "", "#12 34 56"):
            self.assertFalse(vp.is_hex_color(bad), bad)

    def test_hex_parses_with_or_without_hash(self):
        self.assertAlmostEqual(vp.contrast("2C7CBF", "#FFFFFF"),
                               vp.contrast("#2C7CBF", "#FFFFFF"), places=9)


class CLI(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = vp.main(argv)
        except SystemExit as e:  # argparse errors exit 2
            code = e.code
        return code, out.getvalue() + err.getvalue()

    def test_shipped_light_exits_zero(self):
        code, text = self._run(["#2C7CBF,#9A6614", "--mode", "light",
                                "--surface", "#F5F7F7"])
        self.assertEqual(code, 0)
        self.assertIn("ALL CHECKS PASS", text)

    def test_shipped_dark_exits_zero(self):
        code, _ = self._run(["#4A98D8,#B87C2A", "--mode", "dark",
                             "--surface", "#0E1418"])
        self.assertEqual(code, 0)

    def test_bad_palette_exits_one(self):
        code, _ = self._run(["#2C7CBF,#2E82C4"])
        self.assertEqual(code, 1)

    def test_invalid_hex_exits_two(self):
        code, text = self._run(["#2C7CBF,nope"])
        self.assertEqual(code, 2)
        self.assertIn("invalid hex", text)

    def test_invalid_surface_exits_two(self):
        # The surface is caller-supplied too, and an unguarded one would
        # propagate through every contrast computation.
        code, _ = self._run(["#2C7CBF,#9A6614", "--surface", "nope"])
        self.assertEqual(code, 2)

    def test_blank_surface_falls_back_to_the_mode_default(self):
        code, text = self._run(["#2C7CBF,#9A6614", "--surface", "   "])
        self.assertEqual(code, 0)
        self.assertIn(vp.DEFAULT_SURFACE["light"], text)

    def test_missing_palette_exits_two(self):
        code, _ = self._run([])
        self.assertEqual(code, 2)

    def test_unknown_mode_exits_two(self):
        # Must not reach BAND[mode] and raise KeyError.
        code, _ = self._run(["#2C7CBF,#9A6614", "--mode", "sepia"])
        self.assertEqual(code, 2)

    def test_unknown_pairs_exits_two(self):
        # Silently downgrading to the weaker adjacent check would hide a real
        # collapse, so an unrecognised value has to be refused, not defaulted.
        code, _ = self._run(["#2C7CBF,#9A6614", "--pairs", "some"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
