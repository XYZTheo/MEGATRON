#!/usr/bin/env python3
"""Proof that ci/check_ui_markup.py can fail.

Same reasoning as ci/test_policy_check.py: a checker only ever observed
passing is indistinguishable from a checker with a typo in its regex. That
concern is sharper here than usual — this script exists specifically because
ui/README.md claimed a check was "verified by execution" when nothing
executed it. A check written to retire an overclaim, which itself silently
did nothing, would be worse than the overclaim.

Run: python ci/test_check_ui_markup.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECK = Path(__file__).resolve().parent / "check_ui_markup.py"


class MarkupCheckTest(unittest.TestCase):
    def run_on(self, page: str | None) -> subprocess.CompletedProcess[str]:
        tmp = tempfile.mkdtemp(prefix="megatron-markup-")
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        root = Path(tmp)
        (root / "ui" / "shield").mkdir(parents=True)
        if page is not None:
            (root / "ui" / "shield" / "index.html").write_text(page, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECK)],
            env=dict(os.environ, MEGATRON_REPO_ROOT=tmp),
            capture_output=True, text=True)

    GOOD = '<div id="a"></div><script>$("a");</script>'

    def test_clean_page_passes(self) -> None:
        r = self.run_on(self.GOOD)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_id_looked_up_but_absent_is_rejected(self) -> None:
        """The defect this whole script is for: no browser and no Node on the
        build machine, so a typo'd id is a TypeError nothing else catches."""
        r = self.run_on('<div id="a"></div><script>$("a"); $("ghost");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("ghost", r.stdout)

    def test_duplicate_id_is_rejected(self) -> None:
        """getElementById returns the first match silently, so the second
        element simply never updates and nothing anywhere reports it."""
        r = self.run_on('<div id="a"></div><div id="a"></div><script>$("a");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("duplicate", r.stdout)

    def test_unclosed_tag_is_rejected(self) -> None:
        r = self.run_on('<div id="a"><span></div><script>$("a");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_dangling_aria_controls_is_rejected(self) -> None:
        r = self.run_on('<button id="a" aria-controls="nope"></button>'
                        '<script>$("a");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("aria-controls", r.stdout)

    def test_dangling_label_for_is_rejected(self) -> None:
        r = self.run_on('<label for="nope">x</label><div id="a"></div>'
                        '<script>$("a");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_dead_id_is_rejected(self) -> None:
        r = self.run_on('<div id="a"></div><div id="orphan"></div>'
                        '<script>$("a");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("orphan", r.stdout)

    def test_external_url_is_rejected(self) -> None:
        r = self.run_on('<div id="a"></div>'
                        '<script src="https://cdn.example.com/x.js"></script>'
                        '<script>$("a");</script>')
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_svg_namespace_is_allowed(self) -> None:
        r = self.run_on('<div id="a"></div>'
                        '<script>const NS="http://www.w3.org/2000/svg";$("a");</script>')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_no_pages_at_all_does_not_pass_vacuously(self) -> None:
        """A renamed or moved page must not turn this into a no-op that keeps
        reporting success. ui/README.md cites this check by name."""
        r = self.run_on(None)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("vacuously", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
