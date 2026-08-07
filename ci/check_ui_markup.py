#!/usr/bin/env python3
"""Structural checks on the shipped UI pages.

WHY THIS EXISTS
---------------
ui/README.md listed "every getElementById target exists in the markup" under
"Verified by execution". It was not. It was true — checked by hand, once — but
nothing executed it, which makes it exactly the kind of claim this project
keeps telling itself not to make. A reviewer caught it. This is the check that
makes the sentence honest, rather than deleting the sentence.

It matters more here than it would elsewhere. There is no browser and no Node
runtime on the machine this UI is built on (docs/ONBOARDING.md), so the page's
JavaScript has never run. A typo'd id is a TypeError on the first line that
touches it and a blank dashboard for the operator — and nothing else in the
pipeline would notice.

WHAT IT CHECKS
--------------
  * the markup is well-formed: tags nest and close
  * every id looked up in script actually exists in the markup
  * every id in the markup is either looked up or clearly presentational,
    so dead ids do not accumulate
  * no duplicate ids (getElementById silently returns the first)
  * every aria-controls / <label for> target exists
  * no external resource URLs (belt and braces with the policy gate)

Stdlib only, so it can run anywhere the policy gate can.

Run: python ci/check_ui_markup.py
"""

from __future__ import annotations

import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(os.environ.get("MEGATRON_REPO_ROOT",
                           Path(__file__).resolve().parent.parent)).resolve()

# Elements that never have a closing tag; not tracking them as open would
# report every <meta> and <br> as unclosed.
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}

# Ids that exist for CSS or for humans reading the markup, not for script.
PRESENTATIONAL_IDS: set[str] = set()

ID_LOOKUP_RE = re.compile(r'\$\(\s*["\']([^"\']+)["\']\s*\)')
GET_BY_ID_RE = re.compile(r'getElementById\(\s*["\']([^"\']+)["\']\s*\)')
EXTERNAL_URL_RE = re.compile(r"https?:\s*//\s*[^\s\"'()<>]+")
URL_ALLOWLIST = ("http://www.w3.org/",)


class Structure(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.stack: list[tuple[str, tuple[int, int]]] = []
        self.errors: list[str] = []
        self.ids: list[str] = []
        self.aria_controls: list[str] = []
        self.label_for: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        d = dict(attrs)
        if d.get("id"):
            self.ids.append(d["id"])
        if d.get("aria-controls"):
            self.aria_controls.extend(d["aria-controls"].split())
        if tag == "label" and d.get("for"):
            self.label_for.append(d["for"])
        if tag not in VOID:
            self.stack.append((tag, self.getpos()))

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}> at line {self.getpos()[0]}")
            return
        top, pos = self.stack.pop()
        if top != tag:
            self.errors.append(
                f"</{tag}> at line {self.getpos()[0]} closes <{top}> opened at line {pos[0]}")


def check_page(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(REPO).as_posix()
    problems: list[str] = []

    parser = Structure()
    parser.feed(text)
    if parser.stack:
        for tag, pos in parser.stack:
            problems.append(f"{rel}: <{tag}> opened at line {pos[0]} is never closed")
    problems.extend(f"{rel}: {e}" for e in parser.errors)

    markup_ids = parser.ids
    seen: set[str] = set()
    for ident in markup_ids:
        if ident in seen:
            problems.append(
                f"{rel}: duplicate id '{ident}'. getElementById returns the first match "
                f"silently, so the second element simply never updates.")
        seen.add(ident)

    looked_up = set(ID_LOOKUP_RE.findall(text)) | set(GET_BY_ID_RE.findall(text))

    for ident in sorted(looked_up - seen):
        problems.append(
            f"{rel}: script looks up id '{ident}', which is not in the markup. That is a "
            f"TypeError on the first line that touches it, and a blank dashboard.")

    for ident in sorted(seen - looked_up - PRESENTATIONAL_IDS):
        problems.append(
            f"{rel}: id '{ident}' is in the markup but never looked up. Remove it, or add "
            f"it to PRESENTATIONAL_IDS if CSS or a fragment link needs it.")

    for ident in sorted(set(parser.aria_controls) - seen):
        problems.append(
            f"{rel}: aria-controls points at '{ident}', which does not exist. Screen "
            f"readers announce a relationship to nothing.")

    for ident in sorted(set(parser.label_for) - seen):
        problems.append(f"{rel}: <label for='{ident}'> has no matching element")

    for match in EXTERNAL_URL_RE.finditer(text):
        url = " ".join(match.group(0).split())
        if not any(url.startswith(a) for a in URL_ALLOWLIST):
            line = text.count("\n", 0, match.start()) + 1
            problems.append(f"{rel}:{line}: external URL {url}")

    return problems


def main() -> int:
    pages = sorted((REPO / "ui").rglob("*.html")) if (REPO / "ui").is_dir() else []
    if not pages:
        # Fail rather than pass vacuously: this script existing and checking
        # nothing is worse than it not existing, because ui/README.md cites it.
        print("FAIL: no ui/**/*.html found — this check would have passed vacuously")
        return 1

    problems: list[str] = []
    for page in pages:
        problems.extend(check_page(page))

    for problem in problems:
        print(f"  {problem}")

    if problems:
        print(f"\nFAIL — {len(problems)} problem(s) in {len(pages)} page(s).")
        return 1

    print(f"PASS — {len(pages)} page(s): well-formed, ids consistent, no external URLs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
