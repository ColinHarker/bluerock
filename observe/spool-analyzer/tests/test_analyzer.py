"""Smoke tests for the spool analyzer.

Run with: python -m pytest observe/spool-analyzer/tests/
or:       python observe/spool-analyzer/tests/test_analyzer.py
"""
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bluerock_spool as bs  # noqa: E402

FIXTURE = Path(__file__).parent / "fixture_mcp.ndjson"
VULN_FIXTURE = Path(__file__).parent / "fixture_vulnerable.ndjson"
SAMPLE = ROOT.parent / "deploy" / "spool" / "acoustic-lite-42911-42911.ndjson"


def _run(argv: list[str]) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = bs.main(argv)
    assert rc == 0, f"command failed: {argv}"
    return buf.getvalue()


class FixtureTests(unittest.TestCase):
    def test_summary_counts_event_types(self) -> None:
        out = _run(["summary", str(FIXTURE)])
        self.assertIn("Total events:", out)
        self.assertIn("python_mcp_event", out)
        self.assertIn("python_mcp_server_init", out)
        self.assertIn("python_import", out)

    def test_mcp_lists_server_and_tool_calls(self) -> None:
        out = _run(["mcp", str(FIXTURE)])
        self.assertIn("weather v1.0.0", out)
        self.assertIn("get_forecast", out)
        self.assertIn("shell_exec", out)
        self.assertIn("server_received_request", out)
        # tools/call invocations should appear with counts
        self.assertRegex(out, r"get_forecast\s+1")
        self.assertRegex(out, r"shell_exec\s+1")

    def test_imports_flags_hash_change(self) -> None:
        out = _run(["imports", str(FIXTURE)])
        self.assertIn("Hash changes detected", out)
        self.assertIn("urllib3", out)
        self.assertIn("requests", out)

    def test_anomalies_flag_shell_injection_and_secret(self) -> None:
        out = _run(["anomalies", str(FIXTURE)])
        self.assertIn("shell injection", out)
        self.assertIn("secret-like", out)
        self.assertIn("import hash change", out)
        # The fixture intentionally skips source_event_id 11 to create a gap.
        self.assertIn("event sequence gap", out)
        # libcrypto.so is outside /opt/bluerock/, should be flagged.
        self.assertIn("ctypes.dlopen of non-bluerock lib", out)

    def test_timeline_orders_events(self) -> None:
        out = _run(["timeline", str(FIXTURE)])
        self.assertIn("sensor_startup", out)
        self.assertIn("python_mcp_server_init", out)
        # First non-header line should be the sensor_startup event.
        body = out.splitlines()[2:]  # skip header + separator
        self.assertTrue(any("sensor_startup" in line for line in body[:1]))


class HtmlReportTests(unittest.TestCase):
    def test_html_report_contains_expected_sections(self) -> None:
        out = _run(["html", str(FIXTURE)])
        # Stdout output should be a complete HTML doc.
        self.assertIn("<!doctype html>", out)
        self.assertIn("BlueRock spool report", out)
        self.assertIn("Anomalies", out)
        self.assertIn("Imports", out)
        # Severity labels should be styled, not plain.
        self.assertIn("sev-high", out)
        # HTML escaping should kick in for findings.
        self.assertNotIn("<script", out.lower().replace("<scripted", ""))


class TailRenderTests(unittest.TestCase):
    """Exercise the per-event tail renderer without touching files."""

    def test_render_picks_highest_severity_color(self) -> None:
        env = {
            "ts": "2026-04-02T00:00:00Z",
            "event": {
                "meta": {"name": "python_mcp_event", "source_event_id": 1},
                "event": "server_received_request",
                "message": {
                    "method": "tools/call",
                    "params": {"name": "x", "arguments": {"cmd": "ls; rm -rf /"}},
                },
            },
        }
        state = bs.AnomalyState()
        findings = bs.evaluate_event(env, state)
        # Should produce a HIGH (shell injection) finding.
        self.assertTrue(any(f[0] == "high" for f in findings))
        line_color = bs._tail_render(env, findings, color=True)
        line_plain = bs._tail_render(env, findings, color=False)
        self.assertIn("[HIGH]", line_plain)
        # The colored line must include the bold-red ANSI sequence.
        self.assertIn("\x1b[1;31m", line_color)


class VulnerableFixtureTests(unittest.TestCase):
    """Verify the analyzer flags every vector in the demo server fixture."""

    def test_anomalies_cover_every_vector(self) -> None:
        out = _run(["anomalies", str(VULN_FIXTURE)])
        # Shell injection on run_shell.
        self.assertIn("'run_shell' arg looks like shell injection", out)
        # Path traversal on read_text reuses the shell-meta rule (../).
        self.assertIn("'read_text' arg looks like shell injection", out)
        # SQL injection on lookup_user.
        self.assertIn("'lookup_user' arg looks like SQL injection", out)
        # Secret-shaped value in a tool response.
        self.assertIn("response contains secret-like value", out)
        # MCP listing should include all the registered tools.
        mcp_out = _run(["mcp", str(VULN_FIXTURE)])
        for tool in ("run_shell", "read_text", "lookup_user"):
            self.assertIn(tool, mcp_out)


class SampleTests(unittest.TestCase):
    """Run against the real bundled sample to catch regressions on shape."""

    def test_sample_summary_runs(self) -> None:
        if not SAMPLE.exists():
            self.skipTest(f"sample not present: {SAMPLE}")
        out = _run(["summary", str(SAMPLE)])
        self.assertIn("python_builtins_exec", out)
        self.assertIn("sensor_startup", out)


if __name__ == "__main__":
    unittest.main()
