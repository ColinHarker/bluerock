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
import html as _html
import json
import os
import re
import sys
import time
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
    r"(?i)(api[_-]?key|secret|token|password|aws_access|bearer\s+[A-Za-z0-9._-]{8,}|sk-[A-F0-9]{16,})"
)
SQL_INJECTION = re.compile(
    r"(?i)('\s*(or|and)\s+'?\d|'\s*--|\bunion\s+select\b|\bdrop\s+table\b|;\s*--|1\s*=\s*1)"
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


@dataclass
class AnomalyState:
    """Mutable state carried across events while scanning for anomalies."""

    last_id_by_pid: dict[int, int] = field(default_factory=dict)


def evaluate_event(env: dict[str, Any], state: AnomalyState) -> list[tuple[str, str, str]]:
    """Apply the anomaly heuristics to a single envelope.

    Returns a list of (severity, ts, message) tuples. State is mutated in place
    so callers can reuse it across an entire stream (live or batch).
    """
    findings: list[tuple[str, str, str]] = []
    ev = env.get("event") or {}
    meta = ev.get("meta") or {}
    name = meta.get("name")
    ts = env.get("ts", "")

    if name == "python_internal_exception":
        findings.append(("high", ts, f"sensor internal exception: {ev.get('type', '?')}"))

    if name == "python_ctypes_dlopen":
        lib = ev.get("name", "?")
        if not lib.startswith("/opt/bluerock/"):
            findings.append(("medium", ts, f"ctypes.dlopen of non-bluerock lib: {lib}"))

    if name == "python_import" and ev.get("hash_changed"):
        findings.append(
            ("medium", ts, f"import hash change: {ev.get('fullname')} sha256={(ev.get('sha256') or '')[:16]}...")
        )

    if name == "python_mcp_event" and ev.get("event") in MCP_REQUEST_SUBEVENTS:
        msg = ev.get("message") or {}
        if msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            tool = params.get("name", "?")
            args_blob = json.dumps(params.get("arguments") or {})
            if SHELL_METACHARS.search(args_blob):
                findings.append(
                    ("high", ts, f"mcp tools/call {tool!r} arg looks like shell injection: {args_blob[:120]}")
                )
            if SQL_INJECTION.search(args_blob):
                findings.append(
                    ("high", ts, f"mcp tools/call {tool!r} arg looks like SQL injection: {args_blob[:120]}")
                )
            if SECRET_LIKE.search(args_blob):
                findings.append(
                    ("medium", ts, f"mcp tools/call {tool!r} arg contains secret-like value")
                )

    # Secrets appearing in tool-call *responses* are exfiltration candidates.
    if name == "python_mcp_event" and ev.get("event") in MCP_RESPONSE_SUBEVENTS:
        msg = ev.get("message") or {}
        if "result" in msg:
            blob = json.dumps(msg.get("result"))
            if SECRET_LIKE.search(blob):
                findings.append(
                    ("high", ts, "mcp tool response contains secret-like value (possible leak)")
                )

    sid = meta.get("source_event_id")
    pid = ev.get("pid") or ((ev.get("context") or {}).get("process") or {}).get("pid")
    if isinstance(sid, int) and isinstance(pid, int):
        prev = state.last_id_by_pid.get(pid)
        if prev is not None and sid != prev + 1:
            findings.append(
                ("low", ts, f"event sequence gap on pid {pid}: {prev} -> {sid} (missed {sid - prev - 1})")
            )
        state.last_id_by_pid[pid] = sid

    return findings


def cmd_anomalies(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    state = AnomalyState()
    findings: list[tuple[str, str, str]] = []
    for env in iter_events(files):
        findings.extend(evaluate_event(env, state))

    if not findings:
        print("No anomalies found.")
        return 0

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda r: (severity_order.get(r[0], 3), r[1]))
    rows = [(sev.upper(), ts, msg) for sev, ts, msg in findings]
    _print_table(rows, ("sev", "ts", "finding"))
    return 0


# --- Live tail ---------------------------------------------------------------


# Map severity to ANSI color when stdout is a TTY.
_ANSI = {
    "high": "\x1b[1;31m",   # bold red
    "medium": "\x1b[33m",   # yellow
    "low": "\x1b[36m",      # cyan
    "reset": "\x1b[0m",
    "dim": "\x1b[2m",
    "bold": "\x1b[1m",
}


def _color(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI[key]}{text}{_ANSI['reset']}"


def _tail_render(env: dict[str, Any], findings: list[tuple[str, str, str]], color: bool) -> str:
    ev = env.get("event") or {}
    name = (ev.get("meta") or {}).get("name", "?")
    ts = env.get("ts", "")
    detail = _summarize_event(name, ev)
    line = f"{_color(ts, 'dim', color)}  {_color(name, 'bold', color)}  {detail}"
    if findings:
        worst = min(findings, key=lambda r: {"high": 0, "medium": 1, "low": 2}.get(r[0], 3))
        sev = worst[0]
        msgs = "; ".join(f[2] for f in findings)
        line += "  " + _color(f"[{sev.upper()}] {msgs}", sev, color)
    return line


def _follow_files(files: list[Path], from_start: bool, poll: float) -> Iterator[dict[str, Any]]:
    """Tail one or more NDJSON files. Yields decoded events as new lines arrive.

    Each file is opened once and held; we seek to end (unless from_start) and
    then poll for new bytes. Files added to a directory after launch are not
    picked up — that would need watchdog/inotify. Re-run if you rotate.
    """
    handles: list[tuple[Path, Any]] = []
    for f in files:
        try:
            h = f.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"warning: cannot open {f}: {exc}", file=sys.stderr)
            continue
        if not from_start:
            h.seek(0, os.SEEK_END)
        handles.append((f, h))
    try:
        while True:
            got_any = False
            for _, h in handles:
                while True:
                    line = h.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                        got_any = True
                    except json.JSONDecodeError:
                        continue
            if not got_any:
                time.sleep(poll)
    finally:
        for _, h in handles:
            try:
                h.close()
            except Exception:
                pass


def cmd_tail(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    color = sys.stdout.isatty() and not args.no_color
    state = AnomalyState()
    print(_color(f"# tailing {len(files)} file(s); Ctrl+C to stop", "dim", color), file=sys.stderr)
    try:
        for env in _follow_files(files, args.from_start, args.poll):
            findings = evaluate_event(env, state)
            if args.only_anomalies and not findings:
                continue
            print(_tail_render(env, findings, color), flush=True)
    except KeyboardInterrupt:
        return 0
    return 0


# --- HTML report -------------------------------------------------------------


_HTML_CSS = """
body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #222; max-width: 1100px; }
h1 { border-bottom: 2px solid #2b6cb0; padding-bottom: 0.3rem; }
h2 { color: #2b6cb0; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; font-size: 0.92rem; }
th, td { border-bottom: 1px solid #e2e8f0; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f7fafc; }
tr:hover td { background: #fafafa; }
.bar { background: #2b6cb0; height: 14px; border-radius: 2px; }
.sev-high { color: #c53030; font-weight: 600; }
.sev-medium { color: #b7791f; font-weight: 600; }
.sev-low { color: #2c5282; }
.meta { color: #666; font-size: 0.9rem; }
code { background: #f1f5f9; padding: 0 0.25rem; border-radius: 2px; font-size: 0.88em; }
.kv td:first-child { width: 18rem; color: #4a5568; }
"""


def _html_table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    th = "".join(f"<th>{_html.escape(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{c}</td>" for c in row)
        body.append(f"<tr>{cells}</tr>")
    cls_attr = f' class="{cls}"' if cls else ""
    return f"<table{cls_attr}><thead><tr>{th}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _html_bar_row(label: str, count: int, total: int) -> list[str]:
    pct = (100.0 * count / total) if total else 0.0
    bar = f'<div class="bar" style="width:{pct:.1f}%"></div>'
    return [_html.escape(label), str(count), f"{pct:.1f}%", bar]


def cmd_html(args: argparse.Namespace) -> int:
    files = resolve_inputs(args.paths)
    # Single pass collecting everything we need.
    s = Stats()
    state = AnomalyState()
    findings: list[tuple[str, str, str]] = []
    server_inits: list[dict[str, Any]] = []
    registrations: Counter[tuple[str, str]] = Counter()
    sub_events: Counter[str] = Counter()
    tool_calls: Counter[str] = Counter()
    by_pkg: Counter[str] = Counter()
    versions: dict[str, set[str]] = defaultdict(set)
    hash_changes: list[tuple[str, str]] = []

    for env in iter_events(files):
        ev = env.get("event") or {}
        name = (ev.get("meta") or {}).get("name", "<unknown>")
        ts = env.get("ts")
        s.total += 1
        s.by_name[name] += 1
        if ts:
            if s.first_ts is None or ts < s.first_ts:
                s.first_ts = ts
            if s.last_ts is None or ts > s.last_ts:
                s.last_ts = ts
        findings.extend(evaluate_event(env, state))

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
                if msg.get("method") == "tools/call":
                    tool_calls[(msg.get("params") or {}).get("name", "?")] += 1
        elif name == "python_import":
            pkg = ev.get("pkg") or ev.get("fullname", "").split(".", 1)[0]
            by_pkg[pkg] += 1
            if ev.get("version"):
                versions[pkg].add(ev["version"])
            if ev.get("hash_changed"):
                hash_changes.append((ev.get("fullname", "?"), (ev.get("sha256") or "")[:16]))

    parts: list[str] = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append("<title>BlueRock spool report</title>")
    parts.append(f"<style>{_HTML_CSS}</style></head><body>")
    parts.append("<h1>BlueRock spool report</h1>")
    parts.append(
        f"<p class='meta'>Generated {_dt.datetime.now().isoformat(timespec='seconds')} from "
        f"{len(files)} file(s).</p>"
    )

    parts.append("<h2>Summary</h2>")
    kv_rows = [
        ["Total events", str(s.total)],
        ["Distinct event types", str(len(s.by_name))],
        ["First event", _html.escape(s.first_ts or "-")],
        ["Last event", _html.escape(s.last_ts or "-")],
        ["Anomaly findings", str(len(findings))],
    ]
    parts.append(_html_table(["", ""], kv_rows, cls="kv"))

    parts.append("<h2>Event types</h2>")
    rows = [_html_bar_row(name, c, s.total) for name, c in s.by_name.most_common()]
    parts.append(_html_table(["event", "count", "%", "share"], rows))

    if server_inits or registrations or sub_events or tool_calls:
        parts.append("<h2>MCP</h2>")
        if server_inits:
            si_rows = [
                [
                    _html.escape(si.get("name", "?")),
                    _html.escape(si.get("version", "")),
                    _html.escape(si.get("title", "")),
                ]
                for si in server_inits
            ]
            parts.append("<h3>Servers</h3>")
            parts.append(_html_table(["name", "version", "title"], si_rows))
        if registrations:
            reg_rows = [[_html.escape(t), _html.escape(n), str(c)] for (t, n), c in registrations.most_common()]
            parts.append("<h3>Registered elements</h3>")
            parts.append(_html_table(["type", "name", "count"], reg_rows))
        if tool_calls:
            tc_rows = [[_html.escape(n), str(c)] for n, c in tool_calls.most_common()]
            parts.append("<h3>tools/call invocations</h3>")
            parts.append(_html_table(["tool", "count"], tc_rows))
        if sub_events:
            se_rows = [[_html.escape(n), str(c)] for n, c in sub_events.most_common()]
            parts.append("<h3>Sub-event mix</h3>")
            parts.append(_html_table(["sub-event", "count"], se_rows))

    if by_pkg:
        parts.append("<h2>Imports</h2>")
        pkg_rows = []
        for pkg, c in by_pkg.most_common(args.top_packages):
            v = ",".join(sorted(versions[pkg])) if versions[pkg] else "-"
            pkg_rows.append([_html.escape(pkg), _html.escape(v), str(c)])
        parts.append(_html_table(["package", "version(s)", "imports"], pkg_rows))
        if hash_changes:
            hc_rows = [[_html.escape(fn), f"<code>{_html.escape(h)}...</code>"] for fn, h in hash_changes]
            parts.append("<h3>Hash changes</h3>")
            parts.append(_html_table(["module", "sha256"], hc_rows))

    parts.append("<h2>Anomalies</h2>")
    if findings:
        order = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda r: (order.get(r[0], 3), r[1]))
        rows = []
        for sev, ts, msg in findings:
            rows.append(
                [
                    f"<span class='sev-{sev}'>{sev.upper()}</span>",
                    _html.escape(ts),
                    _html.escape(msg),
                ]
            )
        parts.append(_html_table(["sev", "ts", "finding"], rows))
    else:
        parts.append("<p>No anomalies found.</p>")

    parts.append("</body></html>")
    out = "".join(parts)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"wrote {args.output} ({len(out)} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(out)
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

    sp = sub.add_parser("tail", help="Live tail of the spool with inline anomaly tags.")
    add_paths(sp)
    sp.add_argument("--from-start", action="store_true", help="Start at the beginning of each file.")
    sp.add_argument("--poll", type=float, default=0.5, help="Polling interval in seconds.")
    sp.add_argument("--no-color", action="store_true", help="Disable ANSI color even on a TTY.")
    sp.add_argument("--only-anomalies", action="store_true", help="Print only events that trigger a finding.")
    sp.set_defaults(func=cmd_tail)

    sp = sub.add_parser("html", help="Render a self-contained HTML report.")
    add_paths(sp)
    sp.add_argument("--output", "-o", help="Write to file (default: stdout).")
    sp.add_argument("--top-packages", type=int, default=25, help="Top N packages to include.")
    sp.set_defaults(func=cmd_html)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
