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
