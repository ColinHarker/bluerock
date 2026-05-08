#!/usr/bin/env python
"""Deliberately-vulnerable MCP demo server.

This server exists ONLY as a detection target so users can run it under
``bluepython --oss`` and see BlueRock catch realistic attack signatures
(shell injection, path traversal, SQL injection, secret exfiltration).

The vulnerabilities are real but the blast radius is intentionally limited:

* ``run_shell``        — shell=True subprocess, but cwd is locked to a
  per-invocation tempdir and a 5-second wall clock.
* ``read_text``        — naive ``open()`` without sanitization. The "sandbox"
  is just a starting cwd; path traversal succeeds, which is the point.
* ``lookup_user``      — string-concat SQL into an in-memory sqlite DB
  containing a fixed demo dataset.
* ``debug_token``      — returns a fake API key shaped like a real one to
  trigger the analyzer's secret-leak heuristic.

Run with::

    python -m bluepython --oss examples/mcp/vulnerable_server.py --i-know-this-is-vulnerable

Then point the bundled client at it and the spool analyzer's ``anomalies``
command will flag every malicious-looking call.

DO NOT expose this server on a network. The argparse flag is a speed bump,
not a security control.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP


mcp = FastMCP(name="vulnerable-demo")


# In-memory SQLite seeded once on import. The lookup_user tool concatenates
# user input straight into a query — classic SQLi target.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT);
    INSERT INTO users (name, email, role) VALUES
      ('alice', 'alice@example.com', 'user'),
      ('bob',   'bob@example.com',   'user'),
      ('root',  'root@example.com',  'admin');
    """
)


@mcp.tool()
async def run_shell(cmd: str) -> dict[str, Any]:
    """Run ``cmd`` in a shell. Intentionally accepts arbitrary input."""
    with tempfile.TemporaryDirectory(prefix="bluerock-demo-") as cwd:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            return {"stdout": "", "stderr": "timeout", "rc": -1}
    return {
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "rc": proc.returncode,
    }


@mcp.tool()
def read_text(path: str) -> str:
    """Read a UTF-8 text file at ``path``. No sanitization on purpose."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def lookup_user(name: str) -> list[dict[str, Any]]:
    """Look up users by name. Intentionally vulnerable to SQL injection."""
    query = f"SELECT id, name, email, role FROM users WHERE name = '{name}'"
    cur = _DB.execute(query)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


@mcp.tool()
def debug_token() -> dict[str, str]:
    """Return a 'debug' API token. Triggers the secret-leak heuristic."""
    return {
        "api_key": "sk-DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "note": "fake credential for BlueRock demo only",
    }


@mcp.resource("file://demo/{filename}")
def demo_file(filename: str) -> str:
    """Resource read with no path normalization. Path traversal works."""
    return Path(filename).read_text(encoding="utf-8", errors="replace")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--i-know-this-is-vulnerable",
        action="store_true",
        help="Required acknowledgement before the server will start.",
    )
    p.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if not args.i_know_this_is_vulnerable:
        print(
            "refusing to start: pass --i-know-this-is-vulnerable to confirm "
            "you understand this server is a demo target with intentional flaws.",
            file=sys.stderr,
        )
        return 2
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
