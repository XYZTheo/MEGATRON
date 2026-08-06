#!/usr/bin/env python3
"""
Tests for the structural policy gate.

The point of these is narrow and important: prove that each rule in
ci/policy_check.py actually fires on the thing it claims to detect. A gate that
has only ever been observed passing is indistinguishable from a gate with a
typo in its regex, and this project's whole argument is that we do not ship
security controls on the assumption that they work.

Each test builds a throwaway repository containing one deliberate violation,
runs the real gate against it as a subprocess, and asserts both the exit code
and which rule fired.

Run: python ci/test_policy_check.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GATE = Path(__file__).resolve().parent / "policy_check.py"


class GateFixture:
    """A minimal repository tree the gate can be pointed at."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def write(self, relpath: str, content: str) -> None:
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run(self) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, MEGATRON_REPO_ROOT=str(self.root))
        return subprocess.run(
            [sys.executable, str(GATE)],
            env=env, capture_output=True, text=True,
        )


class PolicyGateTest(unittest.TestCase):
    def fixture(self) -> GateFixture:
        tmp = tempfile.mkdtemp(prefix="megatron-gate-")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        return GateFixture(Path(tmp))

    # -- a tree with nothing wrong in it must pass -------------------------

    def test_clean_tree_passes(self) -> None:
        fx = self.fixture()
        fx.write("core/opensips/opensips.cfg",
                 'socket=udp:10.0.0.10:5060\n'
                 'route { route(relay); }\n'
                 'route[relay] { t_relay(); }\n')
        fx.write("edge/opensips/opensips.cfg",
                 'socket=udp:203.0.113.10:5060\n'
                 'modparam("permissions", "db_url", "")\n'
                 'route { drop; }\n')
        r = fx.run()
        self.assertEqual(r.returncode, 0, f"clean tree should pass:\n{r.stdout}")
        self.assertIn("PASS", r.stdout)

    # -- KAMAILIO-NAMES ----------------------------------------------------

    def test_kamailio_module_name_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg", 'loadmodule "htable.so"\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("KAMAILIO-NAMES", r.stdout)
        self.assertIn("cachedb_local", r.stdout)

    def test_kamailio_function_name_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg", 'route { if (!sanity_check()) { drop; } }\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("KAMAILIO-NAMES", r.stdout)

    def test_kamailio_name_inside_a_comment_is_ignored(self) -> None:
        """The configs explain at length why htable does not exist here. Prose
        about a trap must not itself trip the trap."""
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg",
                 '# This is the OpenSIPS equivalent of Kamailio htable.so; there is no\n'
                 '# htable module and sanity_check() does not exist either.\n'
                 'loadmodule "cachedb_local.so"\n')
        r = fx.run()
        self.assertNotIn("KAMAILIO-NAMES", r.stdout)

    # -- EDGE-CREDENTIALS --------------------------------------------------

    def test_edge_with_a_real_db_url_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg",
                 'modparam("permissions", "db_url", "postgres://opensips@10.0.0.20/megatron")\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("EDGE-CREDENTIALS", r.stdout)

    def test_edge_with_an_empty_db_url_is_accepted(self) -> None:
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg", 'modparam("dispatcher", "db_url", "")\n')
        r = fx.run()
        self.assertNotIn("EDGE-CREDENTIALS", r.stdout)

    def test_edge_loading_a_db_driver_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg", 'loadmodule "db_postgres.so"\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("EDGE-CREDENTIALS", r.stdout)

    # -- CORE-PRIVATE ------------------------------------------------------

    def test_core_binding_a_public_address_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("core/opensips/opensips.cfg", 'socket=udp:203.0.113.7:5060\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("CORE-PRIVATE", r.stdout)

    def test_core_with_no_socket_line_is_rejected(self) -> None:
        """Omitting socket= makes OpenSIPS listen on every interface, which on a
        dual-homed core node means the public one."""
        fx = self.fixture()
        fx.write("core/opensips/opensips.cfg", 'log_level=2\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("CORE-PRIVATE", r.stdout)

    def test_core_binding_rfc1918_is_accepted(self) -> None:
        fx = self.fixture()
        for addr in ("10.0.0.10", "172.16.4.9", "192.168.1.5", "127.0.0.1"):
            with self.subTest(addr=addr):
                fx.write("core/opensips/opensips.cfg", f"socket=udp:{addr}:5060\n")
                r = fx.run()
                self.assertNotIn("CORE-PRIVATE", r.stdout)

    def test_core_binding_172_32_is_rejected(self) -> None:
        """172.32/16 is public. The RFC1918 block is 172.16/12, and getting that
        boundary wrong is a classic way to believe an address is private."""
        fx = self.fixture()
        fx.write("core/opensips/opensips.cfg", 'socket=udp:172.32.0.1:5060\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("CORE-PRIVATE", r.stdout)

    # -- ROUTE-TARGETS -----------------------------------------------------

    def test_call_to_undefined_route_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("core/opensips/opensips.cfg",
                 'socket=udp:10.0.0.10:5060\n'
                 'route { route(does_not_exist); }\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("ROUTE-TARGETS", r.stdout)

    # -- NO-SHELL-OUT / MONEY-NOT-FLOAT ------------------------------------

    def test_runtime_exec_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("api/src/main/kotlin/Provision.kt",
                 'fun go() { Runtime.getRuntime().exec(cmd) }\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("NO-SHELL-OUT", r.stdout)

    def test_float_in_a_billing_path_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("rating/src/main/kotlin/Tariff.kt", 'val rate: Double = 0.01\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("MONEY-NOT-FLOAT", r.stdout)

    def test_float_outside_a_billing_path_is_allowed(self) -> None:
        """Latency histograms and load factors are legitimately floating point.
        The ban is about money, not about the type."""
        fx = self.fixture()
        fx.write("edge/agent/metrics.go", 'var loadFactor float64 = 0.75\n')
        r = fx.run()
        self.assertNotIn("MONEY-NOT-FLOAT", r.stdout)

    # -- LICENCE -----------------------------------------------------------

    def test_vendored_gpl_source_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("vendor/thing.c",
                 '/* SPDX-License-Identifier: GPL-2.0 */\nint main(void){return 0;}\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("LICENCE", r.stdout)

    def test_unscannable_dependency_manifest_is_rejected(self) -> None:
        """The gate must fail closed when the build grows a dependency surface it
        cannot yet inspect, rather than passing and creating the impression that
        dependencies were checked."""
        fx = self.fixture()
        fx.write("authorizer/build.gradle.kts", 'dependencies { implementation("io.ktor:ktor-server-core") }\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("LICENCE", r.stdout)
        self.assertIn("no scanner", r.stdout)

    # -- THEME-SYNC and PALETTE --------------------------------------------
    #
    # These two guard ui/tokens.css. Both rules exist because of mistakes
    # already made in this repository, not because of a style preference:
    # --mg-ink-faint shipped at 2.70:1 against --mg-ground, and the commit
    # that fixed it updated two of the three theme blocks.

    # A correct tokens.css in the same shape as the real one: four blocks, the
    # dark palette written twice. Every block is substitutable so a test can
    # mutate exactly one and nothing else -- which is the whole point, since
    # the bug being guarded against is one block differing from the others.
    GOOD_TOKENS = """:root {
%(root)s  --mg-radius: 3px;
  --mg-font-ui: system-ui, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
%(dark1)s  }
}
:root[data-theme="dark"] {
%(dark2)s}
:root[data-theme="light"] {
%(light)s}
"""

    DARK_BODY = """  --mg-ground: #0E1418; --mg-raised: #151D21; --mg-sunken: #0A0F12;
  --mg-ink: #E6EDEF; --mg-ink-muted: #9AABB3; --mg-ink-faint: #7C8C94;
  --mg-accent: #4A98D8;
  --mg-series-1: #4A98D8; --mg-series-2: #B87C2A;
  --mg-good: #48B57F; --mg-warning: #DDA63F; --mg-critical: #E4665F;
  --mg-good-bg: #12261D; --mg-warning-bg: #2A2113; --mg-critical-bg: #2C1717;
"""

    LIGHT_BODY = """  --mg-ground: #F5F7F7; --mg-raised: #FFFFFF; --mg-sunken: #ECEFEF;
  --mg-ink: #0F1719; --mg-ink-muted: #46545B; --mg-ink-faint: #5F6D74;
  --mg-accent: #26699F;
  --mg-series-1: #2C7CBF; --mg-series-2: #9A6614;
  --mg-good: #127A4E; --mg-warning: #8A5D00; --mg-critical: #BE302C;
  --mg-good-bg: #E2F1E9; --mg-warning-bg: #F6EEDC; --mg-critical-bg: #F8E5E4;
"""

    def tokens(self, *, root: str | None = None, dark1: str | None = None,
               dark2: str | None = None, light: str | None = None,
               light_all: str | None = None, dark_all: str | None = None) -> str:
        """Build a tokens.css. light_all/dark_all change every block of that
        mode at once (an intentional palette change); the per-block arguments
        change exactly one (a drift bug)."""
        light_body = light_all if light_all is not None else self.LIGHT_BODY
        dark_body = dark_all if dark_all is not None else self.DARK_BODY
        return self.GOOD_TOKENS % {
            "root": root if root is not None else light_body,
            "dark1": dark1 if dark1 is not None else dark_body,
            "dark2": dark2 if dark2 is not None else dark_body,
            "light": light if light is not None else light_body,
        }

    def with_tokens(self, css: str) -> subprocess.CompletedProcess[str]:
        fx = self.fixture()
        fx.write("ui/tokens.css", css)
        return fx.run()

    def test_correct_tokens_file_passes(self) -> None:
        r = self.with_tokens(self.tokens())
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("THEME-SYNC", r.stdout)
        self.assertNotIn("PALETTE", r.stdout.split("note:")[0])

    def test_palette_rule_actually_runs_on_the_fixture(self) -> None:
        """Guards the guard. If the validator failed to import, or the CSS
        parser found nothing, every other test in this section would pass
        vacuously -- the exact failure mode these tests exist to prevent."""
        r = self.with_tokens(self.tokens())
        self.assertIn("chart series pass the categorical checks", r.stdout)

    def test_theme_block_drift_is_rejected(self) -> None:
        """The mistake that actually happened: one theme block updated, the
        others left stale."""
        stale = self.DARK_BODY.replace("--mg-ink-faint: #7C8C94", "--mg-ink-faint: #6A7A82")
        r = self.with_tokens(self.tokens(dark1=stale))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)
        self.assertIn("--mg-ink-faint", r.stdout)

    def test_explicit_light_diverging_from_root_is_rejected(self) -> None:
        drifted = self.LIGHT_BODY.replace("--mg-accent: #26699F", "--mg-accent: #1A4E7A")
        r = self.with_tokens(self.tokens(light=drifted))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)

    def test_missing_token_in_a_theme_block_is_rejected(self) -> None:
        """A token omitted from a theme block keeps the other theme's value --
        white-on-white, and only in one of the two dark code paths."""
        short = self.DARK_BODY.replace("--mg-ink-faint: #7C8C94;", "")
        r = self.with_tokens(self.tokens(dark_all=short))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)
        self.assertIn("--mg-ink-faint", r.stdout)

    def test_missing_theme_block_is_rejected(self) -> None:
        css = self.tokens()
        css = css[:css.index(':root[data-theme="light"]')]
        r = self.with_tokens(css)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)

    def test_illegible_ink_is_rejected(self) -> None:
        """The original --mg-ink-faint, restored as a fixture: 2.70:1 against
        --mg-ground while carrying 10px axis labels. Applied to every light
        block, so THEME-SYNC stays quiet and this can only be PALETTE firing."""
        bad = self.LIGHT_BODY.replace("--mg-ink-faint: #5F6D74", "--mg-ink-faint: #8B9AA0")
        r = self.with_tokens(self.tokens(light_all=bad))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("PALETTE", r.stdout)
        self.assertIn("--mg-ink-faint", r.stdout)
        self.assertNotIn("THEME-SYNC", r.stdout)

    def test_colour_blind_series_collapse_is_rejected(self) -> None:
        """Red vs green as the two series: the pair a human picks by instinct
        and the pair a protanope cannot separate. On the shield dashboard that
        is exactly the difference between accepted and absorbed traffic."""
        bad = self.LIGHT_BODY.replace("--mg-series-1: #2C7CBF; --mg-series-2: #9A6614",
                                      "--mg-series-1: #C0392B; --mg-series-2: #2E8B57")
        r = self.with_tokens(self.tokens(light_all=bad))
        self.assertIn("PALETTE", r.stdout)
        self.assertIn("CVD separation", r.stdout)
        self.assertNotIn("THEME-SYNC", r.stdout)

    def test_series_wearing_a_status_colour_is_rejected(self) -> None:
        bad = self.LIGHT_BODY.replace("--mg-series-2: #9A6614", "--mg-series-2: #BE302C")
        r = self.with_tokens(self.tokens(light_all=bad))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("PALETTE", r.stdout)
        self.assertIn("impersonates an alarm", r.stdout)

    def test_absent_tokens_file_is_a_note_not_a_failure(self) -> None:
        """Most of the repository has no UI. The rule must stay quiet there
        rather than failing every tree that has not grown a design system."""
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg", "route { drop; }\n")
        r = fx.run()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("not exercised", r.stdout)

    # -- the CSS parser itself ---------------------------------------------

    def test_parser_ignores_declarations_inside_comments(self) -> None:
        sys.path.insert(0, str(GATE.parent))
        try:
            import policy_check
        finally:
            sys.path.pop(0)
        blocks = policy_check.parse_css_tokens(
            ":root {\n"
            "  /* --mg-ink: #BADBAD; a comment describing the token */\n"
            "  --mg-ink: #0F1719;\n"
            "}\n")
        self.assertEqual(blocks[":root"], {"--mg-ink": "#0F1719"})

    def test_parser_reads_the_inner_block_of_an_at_rule(self) -> None:
        sys.path.insert(0, str(GATE.parent))
        try:
            import policy_check
        finally:
            sys.path.pop(0)
        blocks = policy_check.parse_css_tokens(
            '@media (prefers-color-scheme: dark) {\n'
            '  :root:not([data-theme="light"]) { --mg-ink: #E6EDEF; }\n'
            '}\n')
        self.assertIn(':root:not([data-theme="light"])', blocks)
        self.assertEqual(blocks[':root:not([data-theme="light"])'],
                         {"--mg-ink": "#E6EDEF"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
