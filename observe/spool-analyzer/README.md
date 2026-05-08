# bluerock-spool

A stdlib-only Python CLI for analyzing BlueRock NDJSON event spools without
running Loki, Grafana, or any external service. Useful for quick local
inspection, post-incident triage, and CI assertions on captured events.

The tool reads the same NDJSON format produced by `bluepython` and documented in
[`acoustic/python/EVENTS.md`](../../acoustic/python/EVENTS.md).

## Requirements

- Python >= 3.10
- No third-party dependencies

## Quick start

```bash
# Default: read ~/.bluerock/event-spool/ (falls back to ~/.bluerock/oss-events/)
python observe/spool-analyzer/bluerock_spool.py summary

# Or point at a file or directory explicitly
python observe/spool-analyzer/bluerock_spool.py summary path/to/spool/
python observe/spool-analyzer/bluerock_spool.py mcp some-events.ndjson
```

## Subcommands

| Command | What it does |
|---------|--------------|
| `summary` | Total events, time range, distinct PIDs, count per event type, sensor exceptions. |
| `mcp` | MCP server inits, registered tools/resources/prompts, sub-event mix, `tools/call` invocations by tool name, session timeline. |
| `imports` | Top packages by import count with installed versions, modules whose SHA-256 changed since the last run (`hash_changed=true`). |
| `timeline` | Chronological view restricted to interesting events (lifecycle + MCP + dlopen). `--limit N` to cap rows. |
| `anomalies` | Heuristic flags suitable for triage. See below. |

### Anomaly heuristics

The flags here are intentionally conservative — they surface candidates for a
human to look at, not automated verdicts.

- `HIGH` &nbsp;`sensor internal exception` — the sensor itself raised. Usually
  indicates a hook bug or unsupported runtime.
- `HIGH` &nbsp;`mcp tools/call ... shell injection` — the JSON-encoded
  arguments of a `tools/call` request match shell metacharacters, path
  traversal, or `rm -rf` patterns.
- `MEDIUM` `mcp tools/call ... secret-like value` — arguments contain strings
  that look like API keys, bearer tokens, or AWS access keys.
- `MEDIUM` `import hash change` — a module's on-disk SHA-256 differs from the
  previously-recorded hash. Could indicate a legitimate upgrade, a tampered
  install, or a switched virtualenv.
- `MEDIUM` `ctypes.dlopen of non-bluerock lib` — native library loaded outside
  `/opt/bluerock/`. Native loads bypass Python-level controls.
- `LOW` &nbsp;`event sequence gap` — the per-pid `source_event_id` sequence
  skipped a value. Indicates the spool was rotated or events were dropped.

## Examples

```bash
# What MCP traffic happened?
python observe/spool-analyzer/bluerock_spool.py mcp ~/.bluerock/event-spool/

# Did any imports change since last run?
python observe/spool-analyzer/bluerock_spool.py imports ~/.bluerock/event-spool/

# Quick triage of a captured spool
python observe/spool-analyzer/bluerock_spool.py anomalies suspicious-run.ndjson

# Replay against the bundled sample
python observe/spool-analyzer/bluerock_spool.py summary observe/deploy/spool/
```

## Tests

```bash
python observe/spool-analyzer/tests/test_analyzer.py -v
# or
python -m pytest observe/spool-analyzer/tests/
```

The tests run against a small synthetic fixture (`tests/fixture_mcp.ndjson`)
that exercises every subcommand, plus a regression check against the bundled
`observe/deploy/spool/` sample.

## Relationship to `spoolfile2loki`

`spoolfile2loki` ships events to Loki for long-term querying and Grafana
dashboards. `bluerock-spool` is the local complement: zero infrastructure,
useful when you just want to look at a single capture file.
