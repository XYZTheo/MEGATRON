#!/usr/bin/env python3
"""
Render an OpenSIPS config so that `opensips -C` can check it on a build runner.

WHY THIS EXISTS
---------------
The checked-in configs contain real deployment addresses: the core binds
10.0.0.10, the edge binds its public address, and datastores live at fixed
private addresses. A CI runner has none of those interfaces, and OpenSIPS
refuses to start — including under -C — when a socket= line names an address
the host does not own.

So this script rewrites *only the addresses* to loopback and leaves every other
byte alone. Everything that makes a config wrong in an interesting way survives
the rewrite: module names, exported function signatures, parameter names,
route structure, pseudo-variable syntax.

WHAT THE CHECK THEREFORE PROVES, AND WHAT IT DOES NOT
-----------------------------------------------------
It proves:  the config parses; every loadmodule resolves against real OpenSIPS
            3.6 binaries; every function called exists with that arity; every
            modparam is a parameter the module actually exports; every named
            route that is called exists.

That is the entire class of error that has cost this project time so far — the
Kamailio-vs-OpenSIPS module trap is exactly a "this does not exist in 3.6"
error, and it is caught here.

It does NOT prove: that the addresses are right, that routing behaves
correctly, that the database schema matches, or that a call completes. Those
need the lab VPS (issue #2) and SIPp scenarios. Do not let a green check here
be mistaken for "the switch works".
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# socket=udp:10.0.0.10:5060  ->  socket=udp:127.0.0.1:5060
# Handles the bracketed IPv6 form too. The transport and port are preserved
# because both can independently make a config invalid.
SOCKET_RE = re.compile(
    r"^(\s*socket\s*=\s*[a-z]+:)(?:\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})(:\d+.*)$",
    re.M,
)

# Datastore hosts. Only relevant if a module tries to connect during the check;
# pointing them at loopback keeps any such attempt local and fast-failing
# rather than hanging on an unroutable address until the job times out.
DB_HOST_RE = re.compile(r"(postgres(?:ql)?://[^@\"]*@)[^/\"]+(/)")

# The management FIFO lives under /run/opensips, which does not exist on a
# runner and which OpenSIPS may try to create.
FIFO_RE = re.compile(r'("fifo_name"\s*,\s*")[^"]*(")')


def render(text: str, fifo_dir: str) -> tuple[str, list[str]]:
    changes: list[str] = []

    def socket_sub(m: re.Match[str]) -> str:
        changes.append("socket bind address -> 127.0.0.1")
        return f"{m.group(1)}127.0.0.1{m.group(2)}"

    text, n = SOCKET_RE.subn(socket_sub, text)
    if not n:
        # Not fatal for the check itself, but worth surfacing: a config with no
        # socket= line listens on everything, which the policy gate rejects for
        # the core tier.
        changes.append("WARNING: no socket= line found")

    text, n = DB_HOST_RE.subn(r"\g<1>127.0.0.1\g<2>", text)
    if n:
        changes.append(f"{n} database host(s) -> 127.0.0.1")

    text, n = FIFO_RE.subn(rf"\g<1>{fifo_dir}/opensips_fifo\g<2>", text)
    if n:
        changes.append(f"management FIFO -> {fifo_dir}/opensips_fifo")

    return text, changes


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"usage: {argv[0]} <src.cfg> <dst.cfg> <fifo-dir>", file=sys.stderr)
        return 2

    src, dst, fifo_dir = Path(argv[1]), Path(argv[2]), argv[3]
    text, changes = render(src.read_text(encoding="utf-8"), fifo_dir)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")

    print(f"rendered {src} -> {dst}")
    for c in changes:
        print(f"  {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
