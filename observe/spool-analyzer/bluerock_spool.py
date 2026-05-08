#!/usr/bin/env python3
"""bluerock-spool: a stdlib-only analyzer for BlueRock NDJSON event spools.

Reads NDJSON files emitted by the bluepython sensor (see acoustic/python/EVENTS.md)
and produces summaries, filtered views, and anomaly flags. Default input path is
~/.bluerock/event-spool/, falling back to ~/.bluerock/oss-events/.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


DEFAULT_SPOOL_DIRS = (
    "~/.bluerock/event-spool",
    "~/.bluerock/oss-events",
)

# Sub-events on python_mcp_event that represent an actual tool/resource/prompt
# request crossing the wire (vs. lifecycle notifications).
MCP_REQUEST_SUBEVENTS = {
    "server_received_request",
    "client_send_request",
}
MCP_RESPONSE_SUBEVENTS = {
    "server_send_response",
    "client_received_response",
}

# Heuristic patterns that flag suspicious tool-call arguments. These are
# intentionally conservative — the goal is to surface candidates for review,
# not to make a verdict.
SHELL_METACHARS = re.compile(r"[;&|`$<>]|\$\(|\.\./|/etc/(passwd|shadow)|rm\s+-rf")
SECRET_LIKE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|aws_access|bearer\s+[A-Za-z0-9._-]{8,})"
)


# --- I/O ---------------------------------------------------------------------


def resolve_inputs(paths: list[str]) -> list[Path]:
    """Expand user-supplied paths (files or dirs) into a flat list of NDJSON files.

    If no paths are given, fall back to the default spool directories.
    """
    if not paths:
        for candidate in DEFAULT_SPOOL_DIRS:
            d = Path(os.path.expanduser(candidate))
            if d.is_dir():
                paths = [str(d)]
                break
        else:
            raise SystemExit(
                "No paths given and no default spool directory found. "
                "Tried: " + ", ".join(DEFAULT_SPOOL_DIRS)
            )

    out: list[Path] = []
    for raw in paths:
        p = Path(os.path.expanduser(raw))
        if p.is_dir():
            for match in sorted(glob.glob(str(p / "*.ndjson"))):
                out.append(Path(match))
        elif p.is_file():
            out.append(p)
        else:
            # Allow shell-glob patterns the caller didn't pre-expand.
            expanded = sorted(glob.glob(raw))
            if not expanded:
                raise SystemExit(f"Path not found: {raw}")
            out.extend(Path(m) for m in expanded)
    if not out:
        raise SystemExit("No .ndjson files matched the given paths.")
    return out


def iter_events(files: Iterable[Path]) -> Iterator[dict[str, Any]]:
    """Yield decoded events from one or more NDJSON files.

    Malformed lines are skipped silently — partial writes can happen on a live
    spool and we don't want one bad line to abort an analysis. The caller can
    detect drops via the source_event_id sequence if needed.
    """
    for f in files:
        try:
            handle = f.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"warning: cannot open {f}: {exc}", file=sys.stderr)
            continue
        with handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


# --- Aggregation -------------------------------------------------------------


@dataclass
class Stats:
    total: int = 0
    by_name: Counter = field(default_factory=Counter)
    by_pid: Counter = field(default_factory=Counter)
    first_ts: str | None = None
    last_ts: str | None = None
    sensor_startups: int = 0
    internal_exceptions: list[dict[str, Any]] = field(default_factory=list)


def collect_stats(events: Iterable[dict[str, Any]]) -> Stats:
    s = Stats()
    for env in events:
        ts = env.get("ts")
        ev = env.get("event") or {}
        name = (ev.get("meta") or {}).get("name", "<unknown>")
        s.total += 1
        s.by_name[name] += 1
        pid = ev.get("pid") or ((ev.get("context") or {}).get("process") or {}).get("pid")
        if pid is not None:
            s.by_pid[pid] += 1
        if ts:
            if s.first_ts is None or ts < s.first_ts:
                s.first_ts = ts
            if s.last_ts is None or ts > s.last_ts:
                s.last_ts = ts
        if name == "sensor_startup":
            s.sensor_startups += 1
        elif name == "python_internal_exception":
            s.internal_exceptions.append(ev)
    return s


# --- Subcommands -------------------------------------------------------------


def _print_table(rows: list[tuple[str, ...]], headers: tuple[str, ...]) -> None:
    if not rows:
        print("  (no rows)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  " + "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*row))


def cmd_summary(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    s = collect_stats(iter_events(files))
    print(f"Files scanned: {len(files)}")
    for f in files:
        print(f"  - {f}")
    print()
    print(f"Total events:        {s.total}")
    print(f"Sensor startups:     {s.sensor_startups}")
    print(f"Internal exceptions: {len(s.internal_exceptions)}")
    print(f"Distinct PIDs:       {len(s.by_pid)}")
    if s.first_ts and s.last_ts:
        print(f"Time range:          {s.first_ts}  ->  {s.last_ts}")
    print()
    print("Event types:")
    rows = [(name, str(count)) for name, count in s.by_name.most_common()]
    _print_table(rows, ("event", "count"))
    if s.internal_exceptions:
        print()
        print("Internal exceptions (first 5):")
        for ev in s.internal_exceptions[:5]:
            print(f"  - {ev.get('type', '<no type>')}")
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    server_inits: list[dict[str, Any]] = []
    registrations: Counter[tuple[str, str]] = Counter()  # (element_type, name)
    sub_events: Counter[str] = Counter()
    tool_calls: Counter[str] = Counter()
    sessions: dict[str, dict[str, Any]] = {}  # session_id -> {created, terminated, source}

    for env in iter_events(files):
        ev = env.get("event") or {}
        meta = ev.get("meta") or {}
        name = meta.get("name")

        if name == "python_mcp_server_init":
            server_inits.append(ev.get("server", {}))
        elif name == "python_mcp_server_add":
            element = ev.get("element") or {}
            registrations[(element.get("type", "?"), element.get("name", "?"))] += 1
        elif name == "python_mcp_event":
            sub = ev.get("event", "?")
            sub_events[sub] += 1
            if sub in MCP_REQUEST_SUBEVENTS:
                msg = ev.get("message") or {}
                method = msg.get("method")
                params = msg.get("params") or {}
                if method == "tools/call":
                    tool_calls[params.get("name", "?")] += 1
        elif name == "python_mcp_session_created":
            sid = ev.get("session_id", "?")
            sessions.setdefault(sid, {"source": ev.get("source")})
            sessions[sid]["created"] = env.get("ts")
        elif name == "python_mcp_session_terminated":
            sid = ev.get("session_id", "?")
            sessions.setdefault(sid, {"source": ev.get("source")})
            sessions[sid]["terminated"] = env.get("ts")

    print(f"MCP server inits: {len(server_inits)}")
    for s in server_inits:
        bits = [s.get("name", "?")]
        if s.get("version"):
            bits.append(f"v{s['version']}")
        if s.get("title"):
            bits.append(f"title={s['title']!r}")
        print("  - " + " ".join(bits))

    print()
    print("Registered elements:")
    rows = [(t, n, str(c)) for (t, n), c in registrations.most_common()]
    _print_table(rows, ("type", "name", "count"))

    print()
    print("MCP sub-events:")
    rows = [(sub, str(c)) for sub, c in sub_events.most_common()]
    _print_table(rows, ("sub-event", "count"))

    print()
    print("tools/call invocations by tool name:")
    rows = [(name, str(c)) for name, c in tool_calls.most_common()]
    _print_table(rows, ("tool", "count"))

    print()
    print(f"Sessions: {len(sessions)}")
    for sid, info in list(sessions.items())[: args.max_sessions]:
        src = "client" if info.get("source") == 1 else "server"
        created = info.get("created", "?")
        terminated = info.get("terminated", "(open)")
        print(f"  - {sid[:8]}  {src:>6}  created={created}  ended={terminated}")
    if len(sessions) > args.max_sessions:
        print(f"  ... {len(sessions) - args.max_sessions} more")
    return 0


def cmd_imports(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    by_pkg: Counter[str] = Counter()
    versions: dict[str, set[str]] = defaultdict(set)
    hash_changes: list[tuple[str, str]] = []  # (fullname, sha256)
    seen_modules: set[str] = set()

    for env in iter_events(files):
        ev = env.get("event") or {}
        if (ev.get("meta") or {}).get("name") != "python_import":
            continue
        fullname = ev.get("fullname", "?")
        seen_modules.add(fullname)
        pkg = ev.get("pkg") or fullname.split(".", 1)[0]
        by_pkg[pkg] += 1
        ver = ev.get("version")
        if ver:
            versions[pkg].add(ver)
        if ev.get("hash_changed"):
            hash_changes.append((fullname, (ev.get("sha256") or "")[:16]))

    print(f"Distinct modules imported: {len(seen_modules)}")
    print(f"Distinct packages:         {len(by_pkg)}")
    print()
    top_n = args.top
    print(f"Top {top_n} packages by import count:")
    rows = []
    for pkg, count in by_pkg.most_common(top_n):
        v = ",".join(sorted(versions[pkg])) if versions[pkg] else "-"
        rows.append((pkg, v, str(count)))
    _print_table(rows, ("package", "version(s)", "imports"))

    if hash_changes:
        print()
        print(f"!! Hash changes detected ({len(hash_changes)}):")
        for fullname, h in hash_changes:
            print(f"  - {fullname}  sha256={h}...")
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    interesting = {
        "sensor_startup",
        "python_mcp_server_init",
        "python_mcp_server_add",
        "python_mcp_session_created",
        "python_mcp_session_terminated",
        "python_mcp_client_connect",
        "python_mcp_event",
        "python_internal_exception",
        "python_ctypes_dlopen",
    }
    rows: list[tuple[str, str, str]] = []
    for env in iter_events(files):
        ev = env.get("event") or {}
        name = (ev.get("meta") or {}).get("name", "")
        if name not in interesting:
            continue
        ts = env.get("ts", "")
        detail = _summarize_event(name, ev)
        rows.append((ts, name, detail))
        if len(rows) >= args.limit:
            break
    _print_table(rows, ("ts", "event", "detail"))
    return 0


def _summarize_event(name: str, ev: dict[str, Any]) -> str:
    if name == "python_mcp_server_init":
        s = ev.get("server", {})
        return f"server={s.get('name')!r} v{s.get('version', '?')}"
    if name == "python_mcp_server_add":
        e = ev.get("element", {})
        return f"{e.get('type')}={e.get('name')!r}"
    if name == "python_mcp_event":
        sub = ev.get("event")
        msg = ev.get("message") or {}
        method = msg.get("method") or ""
        params = msg.get("params") or {}
        target = params.get("name") or params.get("uri") or ""
        return f"{sub} {method} {target}".strip()
    if name == "python_mcp_client_connect":
        st = ev.get("server", {})
        return f"transport={st.get('type')} url={st.get('url') or st.get('command') or ''}"
    if name == "python_mcp_session_created":
        return f"session={(ev.get('session_id') or '')[:8]} src={ev.get('source')}"
    if name == "python_mcp_session_terminated":
        return f"session={(ev.get('session_id') or '')[:8]} src={ev.get('source')}"
    if name == "python_internal_exception":
        return ev.get("type", "?")
    if name == "python_ctypes_dlopen":
        return ev.get("name", "?")
    if name == "sensor_startup":
        return f"pid={ev.get('pid')}"
    return ""


def cmd_anomalies(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    findings: list[tuple[str, str, str]] = []  # (severity, ts, message)

    last_id_by_pid: dict[int, int] = {}
    gaps: list[tuple[int, int, int]] = []  # (pid, prev_id, this_id)

    for env in iter_events(files):
        ev = env.get("event") or {}
        meta = ev.get("meta") or {}
        name = meta.get("name")
        ts = env.get("ts", "")

        # Sensor-internal exceptions are always worth surfacing.
        if name == "python_internal_exception":
            findings.append(("high", ts, f"sensor internal exception: {ev.get('type', '?')}"))

        # Native library loads bypass Python-level controls.
        if name == "python_ctypes_dlopen":
            lib = ev.get("name", "?")
            if not lib.startswith("/opt/bluerock/"):
                findings.append(("medium", ts, f"ctypes.dlopen of non-bluerock lib: {lib}"))

        # Imports whose on-disk hash changed since the last run.
        if name == "python_import" and ev.get("hash_changed"):
            findings.append(
                ("medium", ts, f"import hash change: {ev.get('fullname')} sha256={(ev.get('sha256') or '')[:16]}...")
            )

        # MCP tool-call arguments that look like shell injection or secret leakage.
        if name == "python_mcp_event" and ev.get("event") in MCP_REQUEST_SUBEVENTS:
            msg = ev.get("message") or {}
            if msg.get("method") == "tools/call":
                params = msg.get("params") or {}
                tool = params.get("name", "?")
                # The arguments key is an object; flatten it to a string for matching.
                args_blob = json.dumps(params.get("arguments") or {})
                if SHELL_METACHARS.search(args_blob):
                    findings.append(
                        ("high", ts, f"mcp tools/call {tool!r} arg looks like shell injection: {args_blob[:120]}")
                    )
                if SECRET_LIKE.search(args_blob):
                    findings.append(
                        ("medium", ts, f"mcp tools/call {tool!r} arg contains secret-like value")
                    )

        # Detect dropped events via gaps in the per-pid source_event_id sequence.
        sid = meta.get("source_event_id")
        pid = ev.get("pid") or ((ev.get("context") or {}).get("process") or {}).get("pid")
        if isinstance(sid, int) and isinstance(pid, int):
            prev = last_id_by_pid.get(pid)
            if prev is not None and sid != prev + 1:
                gaps.append((pid, prev, sid))
            last_id_by_pid[pid] = sid

    for pid, prev, sid in gaps[:20]:
        findings.append(
            ("low", "", f"event sequence gap on pid {pid}: {prev} -> {sid} (missed {sid - prev - 1})")
        )
    if len(gaps) > 20:
        findings.append(("low", "", f"... {len(gaps) - 20} more sequence gaps"))

    if not findings:
        print("No anomalies found.")
        return 0

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda r: (severity_order.get(r[0], 3), r[1]))
    rows = [(sev.upper(), ts, msg) for sev, ts, msg in findings]
    _print_table(rows, ("sev", "ts", "finding"))
    return 0


# --- CLI ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bluerock-spool",
        description="Analyze BlueRock NDJSON event spools.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_paths(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "paths",
            nargs="*",
            help="NDJSON files or directories. Defaults to ~/.bluerock/event-spool/.",
        )

    sp = sub.add_parser("summary", help="High-level event counts and time range.")
    add_paths(sp)
    sp.set_defaults(func=cmd_summary)

    sp = sub.add_parser("mcp", help="MCP server, registrations, sessions, tool calls.")
    add_paths(sp)
    sp.add_argument("--max-sessions", type=int, default=20, help="Max sessions to list.")
    sp.set_defaults(func=cmd_mcp)

    sp = sub.add_parser("imports", help="Import volume by package and hash changes.")
    add_paths(sp)
    sp.add_argument("--top", type=int, default=20, help="Top N packages to show.")
    sp.set_defaults(func=cmd_imports)

    sp = sub.add_parser("timeline", help="Chronological view of MCP and lifecycle events.")
    add_paths(sp)
    sp.add_argument("--limit", type=int, default=200, help="Maximum rows to print.")
    sp.set_defaults(func=cmd_timeline)

    sp = sub.add_parser("anomalies", help="Heuristic flags for review.")
    add_paths(sp)
    sp.set_defaults(func=cmd_anomalies)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
