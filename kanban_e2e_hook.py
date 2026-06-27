#!/usr/bin/env python3
"""
Kanban E2E Verification Hook for OPNsense Anomaly Agent.
=========================================================

Integrates E2E verification into kanban task completion workflow.
Workers import this module and call `gate_before_complete()` before
calling kanban_complete(). If E2E checks fail, the gate blocks and
returns structured failure info for the worker to kanban_block() with.

Usage from a kanban worker (conceptual):

    from kanban_e2e_hook import E2ECompletionGate

    gate = E2ECompletionGate(
        base_url="http://192.168.1.50:8766",
        workspace_path="/path/to/workspace",
    )
    result = gate.run()

    if result.passed:
        kanban_complete(
            summary=result.summary_text(),
            metadata=result.metadata_dict(),
            artifacts=[result.report_path],
        )
    else:
        kanban_comment(body=result.failure_comment())
        kanban_block(reason=result.block_reason())

The gate:
  1. Runs e2e_reporter.py (pipeline health + API + empty state + optional UI)
  2. Writes e2e-report.json to the workspace
  3. Returns pass/fail with structured summary text and metadata
  4. Generates kanban-ready summary, metadata dict, and block reason

This module is the bridge between the E2E test suite and the kanban lifecycle.
It does NOT import kanban_* tools directly — it returns data the worker uses.

Usage as standalone script:
    python3 kanban_e2e_hook.py --base http://192.168.1.50:8766
    python3 kanban_e2e_hook.py --base http://192.168.1.50:8766 --skip-ui
    python3 kanban_e2e_hook.py --base http://192.168.1.50:8766 --workspace /tmp/ws
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_BASE = "http://localhost:8766"
REPORT_FILENAME = "e2e-report.json"
REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Result dataclass — what the worker gets back
# ---------------------------------------------------------------------------


@dataclass
class E2EGateResult:
    """Structured result from running the E2E gate."""

    passed: bool
    report_path: str
    report_data: dict
    duration_seconds: float
    total_checks: int = 0
    passed_checks: int = 0
    warning_checks: int = 0
    failed_checks: int = 0
    skipped_checks: int = 0
    pipeline_status: str = "unknown"
    failure_details: list = field(default_factory=list)

    def __post_init__(self):
        s = self.report_data.get("summary", {})
        if self.total_checks == 0:
            self.total_checks = s.get("total_checks", 0)
        if self.passed_checks == 0:
            self.passed_checks = s.get("passed", 0)
        if self.warning_checks == 0:
            self.warning_checks = s.get("warnings", 0)
        if self.failed_checks == 0:
            self.failed_checks = s.get("failures", 0)
        if self.skipped_checks == 0:
            self.skipped_checks = s.get("skipped", 0)
        if self.pipeline_status == "unknown":
            self.pipeline_status = self.report_data.get("pipeline_health", {}).get(
                "status", "unknown"
            )
        # Collect failure details
        if not self.failure_details:
            self.failure_details = [
                iss
                for iss in self.report_data.get("issues", [])
                if iss.get("severity") in ("FAIL", "WARN")
            ]

    # ---- Kanban-ready output helpers ----

    def summary_text(self) -> str:
        """Human-readable summary for kanban_complete(summary=...)."""
        status = "PASS" if self.passed else "FAIL"
        lines = [
            f"E2E verification: {status} — "
            f"{self.passed_checks}/{self.total_checks} checks passed, "
            f"{self.warning_checks} warnings, {self.failed_checks} failures, "
            f"{self.skipped_checks} skipped ({self.duration_seconds:.1f}s)",
            f"Pipeline: {self.pipeline_status}",
        ]
        if self.failure_details:
            lines.append(
                f"Issues: {'; '.join(i['message'] for i in self.failure_details[:5])}"
            )
        lines.append(f"Report: {self.report_path}")
        return " ".join(lines)

    def metadata_dict(self) -> dict:
        """Structured metadata for kanban_complete(metadata=...)."""
        meta = {
            "e2e_verification": {
                "status": "pass" if self.passed else "fail",
                "total_checks": self.total_checks,
                "passed": self.passed_checks,
                "warnings": self.warning_checks,
                "failures": self.failed_checks,
                "skipped": self.skipped_checks,
                "duration_seconds": round(self.duration_seconds, 1),
                "pipeline_status": self.pipeline_status,
                "report_path": self.report_path,
            },
        }
        # Per-module summaries
        for mod_name in ("api_verification", "empty_state_verification", "ui_verification"):
            mod = self.report_data.get(mod_name, {})
            if mod:
                meta[f"e2e_{mod_name}"] = mod.get("summary", {})
        return meta

    def block_reason(self) -> str:
        """Reason string for kanban_block(reason=...) when E2E fails."""
        fail_msgs = [
            i["message"] for i in self.failure_details if i.get("severity") == "FAIL"
        ]
        if fail_msgs:
            primary = fail_msgs[0]
            return (
                f"e2e-gate-blocked: {self.failed_checks} E2E check(s) failed. "
                f"Primary: {primary}. Report: {self.report_path}"
            )
        return (
            f"e2e-gate-blocked: E2E verification returned FAIL status. "
            f"Report: {self.report_path}"
        )

    def failure_comment(self) -> str:
        """Markdown comment body for kanban_comment before blocking."""
        lines = [
            "## E2E Verification Failed",
            "",
            f"**Status**: FAIL | {self.passed_checks}/{self.total_checks} passed",
            f"**Pipeline**: {self.pipeline_status}",
            f"**Duration**: {self.duration_seconds:.1f}s",
            f"**Report**: `{self.report_path}`",
            "",
            "### Failures",
            "",
        ]
        for issue in self.failure_details:
            sev = issue.get("severity", "UNKNOWN")
            mod = issue.get("module", "unknown")
            msg = issue.get("message", "")
            lines.append(f"- [{sev}] [{mod}] {msg}")
        lines.append("")
        lines.append(
            json.dumps(
                self.metadata_dict()["e2e_verification"], indent=2, default=str
            )
        )
        return "\n".join(lines)

    def console_summary(self) -> str:
        """Compact one-liner for terminal output."""
        status = "PASS" if self.passed else "FAIL"
        return (
            f"E2E Gate [{status}] {self.passed_checks}/{self.total_checks} checks | "
            f"{self.warning_checks}W {self.failed_checks}F {self.skipped_checks}S | "
            f"pipeline={self.pipeline_status} | "
            f"{self.duration_seconds:.1f}s | report={self.report_path}"
        )


# ---------------------------------------------------------------------------
# Gate — runs the E2E reporter and returns structured result
# ---------------------------------------------------------------------------


class E2ECompletionGate:
    """Run E2E verification and gate kanban task completion."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE,
        workspace_path: str | None = None,
        skip_ui: bool = False,
        skip_api: bool = False,
        skip_empty_state: bool = False,
        seed: bool = False,
        clean: bool = False,
        verbose: bool = False,
    ):
        self.base_url = base_url
        self.workspace_path = workspace_path or os.getcwd()
        self.skip_ui = skip_ui
        self.skip_api = skip_api
        self.skip_empty_state = skip_empty_state
        self.seed = seed
        self.clean = clean
        self.verbose = verbose

    def run(self) -> E2EGateResult:
        """Execute E2E verification and return gated result."""
        report_path = os.path.join(self.workspace_path, REPORT_FILENAME)
        project_root = Path(__file__).resolve().parent
        reporter_script = project_root / "e2e_reporter.py"

        if not reporter_script.exists():
            # Fast-fail: reporter missing
            err_report = {
                "report": {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "base_url": self.base_url,
                    "overall_status": "FAIL",
                },
                "pipeline_health": {"status": "unhealthy"},
                "summary": {
                    "total_checks": 1,
                    "passed": 0,
                    "warnings": 0,
                    "failures": 1,
                    "skipped": 0,
                },
                "issues": [
                    {
                        "module": "gate",
                        "severity": "FAIL",
                        "message": f"E2E reporter not found at {reporter_script}",
                    }
                ],
            }
            with open(report_path, "w") as f:
                json.dump(err_report, f, indent=2)
            return E2EGateResult(
                passed=False,
                report_path=report_path,
                report_data=err_report,
                duration_seconds=0,
            )

        # Build command
        cmd = [
            sys.executable,
            str(reporter_script),
            "--base",
            self.base_url,
            "--output",
            report_path,
        ]
        if self.skip_ui:
            cmd.append("--skip-ui")
        if self.skip_api:
            cmd.append("--skip-api")
        if self.skip_empty_state:
            cmd.append("--skip-empty-state")
        if self.seed:
            cmd.append("--seed")
        if self.clean:
            cmd.append("--clean")
        if self.verbose:
            cmd.append("--verbose")

        if self.verbose:
            print(f"Running: {' '.join(cmd)}", file=sys.stderr)

        start = time.time()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(project_root),
        )
        duration = time.time() - start

        # Read report
        report_data: dict = {}
        if os.path.exists(report_path):
            with open(report_path) as f:
                report_data = json.load(f)
        else:
            # Runner crashed — reconstruct from stderr
            report_data = {
                "report": {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "base_url": self.base_url,
                    "overall_status": "FAIL",
                },
                "pipeline_health": {"status": "unhealthy"},
                "summary": {
                    "total_checks": 1,
                    "passed": 0,
                    "warnings": 0,
                    "failures": 1,
                    "skipped": 0,
                },
                "issues": [
                    {
                        "module": "gate",
                        "severity": "FAIL",
                        "message": f"e2e_reporter crashed (exit {proc.returncode}): {proc.stderr[-500:]}",
                    }
                ],
            }
            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=2)

        # Determine pass/fail from report + exit code
        overall = report_data.get("report", {}).get("overall_status", "FAIL")
        passed = overall == "PASS" and proc.returncode == 0

        return E2EGateResult(
            passed=passed,
            report_path=report_path,
            report_data=report_data,
            duration_seconds=duration,
        )


# ---------------------------------------------------------------------------
# CLI — standalone verification gate
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Kanban E2E completion gate — runs E2E verification and blocks on failure"
    )
    parser.add_argument(
        "--base", default=DEFAULT_BASE, help="Dashboard base URL"
    )
    parser.add_argument(
        "--workspace",
        default=os.getcwd(),
        help="Workspace path for report output (default: cwd)",
    )
    parser.add_argument(
        "--skip-ui", action="store_true", help="Skip UI verification"
    )
    parser.add_argument(
        "--skip-api", action="store_true", help="Skip API verification"
    )
    parser.add_argument(
        "--skip-empty-state",
        action="store_true",
        help="Skip empty-state verification",
    )
    parser.add_argument(
        "--seed", action="store_true", help="Seed test data before verification"
    )
    parser.add_argument(
        "--clean", action="store_true", help="Clean test data after verification"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print JSON metadata only (for scripting)",
    )

    args = parser.parse_args()

    gate = E2ECompletionGate(
        base_url=args.base,
        workspace_path=args.workspace,
        skip_ui=args.skip_ui,
        skip_api=args.skip_api,
        skip_empty_state=args.skip_empty_state,
        seed=args.seed,
        clean=args.clean,
        verbose=args.verbose,
    )

    result = gate.run()

    if args.json_only:
        print(json.dumps(result.metadata_dict(), indent=2, default=str))
    else:
        print(result.console_summary())
        if not result.passed:
            print(f"\nBLOCK REASON: {result.block_reason()}")
            print(f"\nFailure details:")
            for issue in result.failure_details:
                sev = issue.get("severity", "?")
                mod = issue.get("module", "?")
                msg = issue.get("message", "")
                print(f"  [{sev}] [{mod}] {msg}")

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
