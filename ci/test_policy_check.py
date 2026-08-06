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


if __name__ == "__main__":
    unittest.main(verbosity=2)
