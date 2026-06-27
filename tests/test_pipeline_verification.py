#!/usr/bin/env python3
"""
Tests for pipeline_verification.py

Verifies:
  - Module imports cleanly
  - Report dataclass works correctly
  - HTTP client handles failures gracefully
  - Stage checkers run without crashing (even against unreachable hosts)
  - Dry-run mode produces valid output
  - JSON output is parseable
  - Text output is non-empty
"""

import json
import sys
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from typing import Dict, Any

# Import the module under test
sys.path.insert(0, "..")
from pipeline_verification import (
    PipelineReport,
    Finding,
    Severity,
    Stage,
    http_get,
    run_verification,
    format_text,
    format_json,
)


class TestPipelineReport(unittest.TestCase):
    """Test the PipelineReport dataclass."""

    def setUp(self):
        self.report = PipelineReport(
            run_id="test_run_001",
            started_at=datetime.now(timezone.utc).isoformat(),
            base_url="http://localhost:8766",
        )

    def test_initial_counts(self):
        """Empty report has zero counts."""
        self.assertEqual(self.report.pass_count, 0)
        self.assertEqual(self.report.fail_count, 0)
        self.assertEqual(self.report.warn_count, 0)
        self.assertEqual(self.report.skip_count, 0)

    def test_counting(self):
        """Counts increment correctly."""
        self.report.findings = [
            {"severity": "PASS"},
            {"severity": "PASS"},
            {"severity": "FAIL"},
            {"severity": "WARN"},
            {"severity": "SKIP"},
        ]
        self.assertEqual(self.report.pass_count, 2)
        self.assertEqual(self.report.fail_count, 1)
        self.assertEqual(self.report.warn_count, 1)
        self.assertEqual(self.report.skip_count, 1)

    def test_json_serializable(self):
        """Report serializes to JSON without errors."""
        self.report.findings = [
            {"severity": "PASS", "message": "ok"},
            {"severity": "FAIL", "message": "broken"},
        ]
        json_str = json.dumps({
            "pass": self.report.pass_count,
            "fail": self.report.fail_count,
        })
        parsed = json.loads(json_str)
        self.assertEqual(parsed["pass"], 1)
        self.assertEqual(parsed["fail"], 1)


class TestFinding(unittest.TestCase):
    """Test the Finding dataclass."""

    def test_default_details(self):
        """Details defaults to empty dict."""
        f = Finding(
            stage="test",
            check_name="check1",
            severity="PASS",
            message="ok",
        )
        self.assertEqual(f.details, {})

    def test_custom_details(self):
        """Custom details preserved."""
        f = Finding(
            stage="test",
            check_name="check1",
            severity="PASS",
            message="ok",
            details={"key": "value"},
        )
        self.assertEqual(f.details["key"], "value")


class TestHttpGet(unittest.TestCase):
    """Test the HTTP client with mocked connections."""

    def test_connection_failure_returns_zero_status(self):
        """Unreachable host returns (0, error_body, elapsed_ms)."""
        status, body, ms = http_get("http://localhost:19999", "/api/health", timeout=1)
        self.assertEqual(status, 0)
        self.assertIn("error", body)
        self.assertGreater(ms, 0)

    def test_http_error_handling(self):
        """HTTP error (e.g. 404) returns the status code."""
        # Mock urlopen to raise HTTPError
        from urllib.error import HTTPError
        import io

        error = HTTPError("http://localhost:8766/api/nonexistent", 404, "Not Found", {}, io.BytesIO(b'{"error": "not found"}'))
        with patch("pipeline_verification.urlopen", side_effect=error):
            status, body, ms = http_get("http://localhost:8766", "/api/nonexistent")
            self.assertEqual(status, 404)

    def test_success_response(self):
        """Successful response returns 200 and parsed JSON."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"status": "ok"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("pipeline_verification.urlopen", return_value=mock_resp):
            status, body, ms = http_get("http://localhost:8766", "/api/health")
            self.assertEqual(status, 200)
            self.assertEqual(body["status"], "ok")
            self.assertGreater(ms, 0)


class TestDryRun(unittest.TestCase):
    """Test dry-run mode."""

    def test_dry_run_produces_report(self):
        """Dry run returns a report without making network calls."""
        report = run_verification("http://localhost:8766", dry_run=True)
        self.assertEqual(report.base_url, "http://localhost:8766")
        self.assertIn("dry_run", report.summary)
        self.assertEqual(report.summary["dry_run"], "true")

    def test_dry_run_format_json(self):
        """Dry run report formats as valid JSON."""
        report = run_verification("http://localhost:8766", dry_run=True)
        json_str = format_json(report)
        parsed = json.loads(json_str)
        self.assertIn("summary", parsed)
        self.assertIn("run_id", parsed)

    def test_dry_run_format_text(self):
        """Dry run report formats as non-empty text."""
        report = run_verification("http://localhost:8766", dry_run=True)
        text = format_text(report)
        self.assertGreater(len(text), 0)
        self.assertIn("Pipeline Health Verification", text)


class TestOutputFormat(unittest.TestCase):
    """Test output formatting functions."""

    def setUp(self):
        self.report = PipelineReport(
            run_id="fmt_test",
            started_at="2026-06-26T12:00:00+00:00",
            completed_at="2026-06-26T12:00:01+00:00",
            base_url="http://localhost:8766",
            findings=[
                {
                    "stage": "source",
                    "check_name": "health",
                    "severity": "PASS",
                    "message": "healthy",
                },
                {
                    "stage": "api",
                    "check_name": "stats",
                    "severity": "FAIL",
                    "message": "stats endpoint down",
                },
                {
                    "stage": "database",
                    "check_name": "schema",
                    "severity": "WARN",
                    "message": "pending migration",
                },
            ],
        )

    def test_format_json_parseable(self):
        """JSON output is valid and contains all findings."""
        json_str = format_json(self.report)
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed["findings"]), 3)
        self.assertEqual(parsed["counts"]["pass"], 1)
        self.assertEqual(parsed["counts"]["fail"], 1)
        self.assertEqual(parsed["counts"]["warn"], 1)

    def test_format_text_contains_status(self):
        """Text output includes summary status."""
        text = format_text(self.report)
        self.assertIn("PASS", text)
        self.assertIn("FAIL", text)
        self.assertIn("WARN", text)
        self.assertIn("Summary:", text)
        self.assertIn("Status:", text)

    def test_format_text_groups_by_stage(self):
        """Text output groups findings by stage."""
        text = format_text(self.report)
        self.assertIn("SOURCE", text)
        self.assertIn("API", text)
        self.assertIn("DATABASE", text)


class TestStageEnum(unittest.TestCase):
    """Test Stage enum values."""

    def test_all_stages_present(self):
        """All expected stages are defined."""
        expected = {"source", "parser", "agent", "database", "anomaly", "baseline", "api", "ui_data"}
        actual = {s.value for s in Stage}
        self.assertEqual(actual, expected)

    def test_stage_count(self):
        """Correct number of stages."""
        self.assertEqual(len(Stage), 8)


class TestSeverityEnum(unittest.TestCase):
    """Test Severity enum values."""

    def test_all_severities_present(self):
        """All expected severities are defined."""
        expected = {"PASS", "WARN", "FAIL", "SKIP", "INFO"}
        actual = {s.value for s in Severity}
        self.assertEqual(actual, expected)


class TestMarkerConfig(unittest.TestCase):
    """Test marker IP configuration matches test_data_seeder."""

    def test_marker_ip_base(self):
        """Marker IP base matches seeder."""
        from pipeline_verification import MARKER_IP_BASE
        self.assertEqual(MARKER_IP_BASE, "192.168.100")

    def test_marker_prefix(self):
        """Test marker prefix matches seeder."""
        from pipeline_verification import TEST_MARKER_PREFIX
        self.assertEqual(TEST_MARKER_PREFIX, "TEST_SEED")


class TestRunVerification(unittest.TestCase):
    """Integration-style tests for run_verification against unreachable host."""

    def test_unreachable_host_produces_report(self):
        """Even when host is unreachable, we get a valid report (source stage only)."""
        report = run_verification("http://localhost:19999", stages=["source"], timeout=1)
        self.assertIsNotNone(report)
        self.assertEqual(report.base_url, "http://localhost:19999")
        # Should have at least some findings (likely FAIL for connection)
        self.assertGreater(len(report.findings), 0)
        self.assertIsNotNone(report.completed_at)
        # Cross-stage should NOT run when only source is selected
        stages_seen = {f["stage"] for f in report.findings}
        self.assertNotIn("cross_stage", stages_seen)

    def test_specific_stage_filter(self):
        """Passing a specific stage only runs that stage."""
        report = run_verification("http://localhost:19999", stages=["source"], timeout=1)
        # Should only have source findings
        stages_seen = {f["stage"] for f in report.findings}
        self.assertIn("source", stages_seen)
        # Other stages should NOT be present
        for s in ["parser", "agent", "database", "anomaly", "baseline", "api", "ui_data"]:
            self.assertNotIn(s, stages_seen, f"Stage {s} should not be present when only 'source' is selected")


if __name__ == "__main__":
    unittest.main()
