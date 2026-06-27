#!/usr/bin/env python3
"""
End-to-End E2E Reporter for OPNsense Anomaly Agent.
====================================================

Orchestrates all verification modules into a single structured JSON report:
  1. Pipeline health (syslog, DB, Discord, Redis)
  2. API trace verification (all endpoints)
  3. Empty state verification (all tabs)
  4. UI trace verification (all tabs via Playwright)
  5. Test data seeder (optional: seed + cleanup)
  6. Consolidated summary with per-tab PASS/FAIL status

JSON report structure:
{
  "report": {
    "generated_at": "ISO-8601 timestamp",
    "base_url": "target dashboard URL",
    "duration_seconds": float,
    "overall_status": "PASS" | "FAIL" | "WARN"
  },
  "pipeline_health": {
    "status": "ok" | "degraded" | "unhealthy",
    "subsystems": { "syslog": {...}, "discord": {...}, ... }
  },
  "test_data": {
    "seeded": bool,
    "seed_counts": {...} | null,
    "cleaned": bool,
    "cleanup_counts": {...} | null
  },
  "api_verification": {
    "summary": { "total": N, "passed": N, "warnings": N, "failures": N, "skipped": N },
    "results": [ ... ]
  },
  "empty_state_verification": {
    "summary": { "total": N, "pass": N, "warn": N, "fail": N },
    "results": [ ... ]
  },
  "ui_verification": {
    "summary": { "total": N, "passed": N, "warnings": N, "failures": N, "skipped": N },
    "results": [ ... ]
  },
  "per_tab_status": {
    "<tab_name>": { "api": "PASS" | "FAIL", "empty_state": "PASS" | "FAIL", "ui": "PASS" | "FAIL" }
  },
  "issues": [
    { "module": "api_verification" | "empty_state" | "ui", "severity": "FAIL" | "WARN", "message": "..." }
  ],
  "summary": {
    "total_checks": N,
    "passed": N,
    "warnings": N,
    "failures": N,
    "skipped": N,
    "overall": "PASS" | "FAIL"
  }
}

Usage:
  # Full report (no seeding, JSON to stdout)
  python3 e2e_reporter.py

  # Full report with test data seeding + cleanup
  python3 e2e_reporter.py --seed --clean

  # Write JSON report to file
  python3 e2e_reporter.py --output e2e-report.json

  # Run against remote deployment
  python3 e2e_reporter.py --base http://192.168.1.50:8766

  # Skip UI verification (saves ~30s, no Playwright needed)
  python3 e2e_reporter.py --skip-ui

  # Skip API verification
  python3 e2e_reporter.py --skip-api

  # Skip empty-state verification
  python3 e2e_reporter.py --skip-empty-state

  # Verbose: print progress as it runs
  python3 e2e_reporter.py --verbose

Exit codes:
  0  All checks passed
  1  One or more checks failed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

# ---------------------------------------------------------------------------
# Add project root to path so we can import sibling modules
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


class Severity(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class PipelineStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


DEFAULT_BASE = "http://localhost:8766"
REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Pipeline Health Check
# ---------------------------------------------------------------------------

def check_pipeline_health(base_url: str, verbose: bool = False) -> Dict[str, Any]:
    """Hit /api/health and /api/resources to assess pipeline status."""
    result: Dict[str, Any] = {
        "status": "healthy",
        "subsystems": {},
        "details": {},
    }

    # --- /api/health ---
    try:
        req = urlopen(f"{base_url}/api/health", timeout=REQUEST_TIMEOUT)
        health = json.loads(req.read().decode())
        result["subsystems"]["health_endpoint"] = {"status": "ok", "response": health.get("status", "unknown")}

        # Extract subsystems from health response
        if "subsystems" in health:
            for sub_name, sub_info in health["subsystems"].items():
                status = "ok"
                if isinstance(sub_info, dict):
                    status = sub_info.get("status", "unknown")
                result["subsystems"][sub_name] = {"status": status}
                if verbose:
                    print(f"  Subsystem {sub_name}: {status}")

        # Check for degraded/unhealthy subsystems
        for sub_name, sub_info in result["subsystems"].items():
            if sub_info["status"] in ("unhealthy", "critical", "error", "disabled"):
                result["status"] = "unhealthy"
            elif sub_info["status"] in ("warning", "degraded", "questionable"):
                if result["status"] != "unhealthy":
                    result["status"] = "degraded"
    except Exception as e:
        result["status"] = "unhealthy"
        result["subsystems"]["health_endpoint"] = {"status": "error", "error": str(e)}
        if verbose:
            print(f"  Health check FAILED: {e}")

    # --- /api/stats ---
    try:
        req = urlopen(f"{base_url}/api/stats", timeout=REQUEST_TIMEOUT)
        stats = json.loads(req.read().decode())
        total_events = stats.get("total_events", 0)
        result["subsystems"]["stats"] = {
            "status": "ok",
            "total_events": total_events,
        }
        result["details"]["total_events"] = total_events
        if verbose:
            print(f"  Stats: {total_events} total events")
    except Exception as e:
        result["subsystems"]["stats"] = {"status": "error", "error": str(e)}
        if result["status"] == "healthy":
            result["status"] = "degraded"

    # --- /api/resources ---
    try:
        req = urlopen(f"{base_url}/api/resources", timeout=REQUEST_TIMEOUT)
        resources = json.loads(req.read().decode())
        cpu = resources.get("cpu_percent", 0)
        mem = resources.get("memory", {})
        mem_pct = mem.get("percent", 0) if isinstance(mem, dict) else 0
        result["subsystems"]["resources"] = {
            "status": "ok",
            "cpu_percent": cpu,
            "memory_percent": mem_pct,
        }
        if verbose:
            print(f"  Resources: CPU {cpu}%, Memory {mem_pct}%")
    except Exception as e:
        result["subsystems"]["resources"] = {"status": "error", "error": str(e)}

    # --- /api/version ---
    try:
        req = urlopen(f"{base_url}/api/version", timeout=REQUEST_TIMEOUT)
        version = json.loads(req.read().decode())
        result["details"]["version"] = version.get("version", "unknown")
        result["details"]["commit"] = version.get("commit", "unknown")
        result["details"]["build_time"] = version.get("build_time", "unknown")
        if verbose:
            print(f"  Version: {version.get('version', 'unknown')} ({version.get('commit', 'unknown')})")
    except Exception as e:
        result["subsystems"]["version"] = {"status": "error", "error": str(e)}

    # --- /api/health version fallback ---
    if result["details"].get("version") == "unknown":
        try:
            # version may be nested in health response
            req = urlopen(f"{base_url}/api/health", timeout=REQUEST_TIMEOUT)
            health_data = json.loads(req.read().decode())
            for key in ("version", "agent_version", "app_version"):
                if key in health_data:
                    result["details"]["version"] = health_data[key]
                    break
        except Exception:
            pass  # Already logged

    return result


# ---------------------------------------------------------------------------
# API Verification Runner
# ---------------------------------------------------------------------------

def run_api_verification(base_url: str, verbose: bool = False) -> Dict[str, Any]:
    """Run api_verification module and return structured results."""
    try:
        # Import and run api_verification programmatically
        from api_verification import ApiClient, ApiVerifier, _define_endpoints

        client = ApiClient(base_url=base_url, timeout=REQUEST_TIMEOUT)
        verifier = ApiVerifier(client, verbose=verbose)

        results = verifier.run_all()
        error_results = verifier.verify_error_handling()
        results.extend(error_results)

        # Classify results
        passes = sum(1 for r in results if r.severity.value == "PASS")
        warns = sum(1 for r in results if r.severity.value == "WARN")
        fails = sum(1 for r in results if r.severity.value == "FAIL")
        skips = sum(1 for r in results if r.severity.value == "SKIP")

        return {
            "summary": {
                "total": len(results),
                "passed": passes,
                "warnings": warns,
                "failures": fails,
                "skipped": skips,
            },
            "results": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "check": r.check_name,
                    "severity": r.severity.value,
                    "message": r.message,
                    "response_time_ms": round(r.response_time_ms, 1),
                    "details": r.details,
                }
                for r in results
            ],
        }
    except ImportError as e:
        return {
            "summary": {"total": 0, "passed": 0, "warnings": 0, "failures": 1, "skipped": 0},
            "results": [{"endpoint": "*", "method": "*", "check": "import", "severity": "FAIL", "message": f"Cannot import api_verification: {e}"}],
            "error": str(e),
        }




# ---------------------------------------------------------------------------
# Empty State Verification Runner
# ---------------------------------------------------------------------------

def run_empty_state_verification(base_url: str, verbose: bool = False) -> Dict[str, Any]:
    """Run empty_state_verification module and return structured results."""
    try:
        from empty_state_verification import TAB_SPECS, analyze_tab, Severity as ESSeverity, DataSourceStatus

        results = []
        for spec in TAB_SPECS:
            result = analyze_tab(spec, base_url, verbose=verbose)
            results.append(result)

        passes = sum(1 for r in results if r.severity == ESSeverity.PASS)
        warns = sum(1 for r in results if r.severity == ESSeverity.WARN)
        fails = sum(1 for r in results if r.severity == ESSeverity.FAIL)

        return {
            "summary": {
                "total": len(results),
                "pass": passes,
                "warn": warns,
                "fail": fails,
            },
            "results": [
                {
                    "tab": r.tab_name,
                    "endpoint": r.endpoint,
                    "description": r.description,
                    "severity": r.severity.value,
                    "message": r.message,
                    "data_source_status": r.data_source_status.value,
                    "has_contextual_message": r.has_contextual_message,
                    "has_zero_without_context": r.has_zero_without_context,
                    "expected_empty_message": r.expected_empty_message,
                    "response_time_ms": round(r.response_time_ms, 1),
                }
                for r in results
            ],
        }
    except ImportError as e:
        return {
            "summary": {"total": 0, "pass": 0, "warn": 0, "fail": 1},
            "results": [{"tab": "*", "endpoint": "*", "description": "import", "severity": "FAIL", "message": f"Cannot import empty_state_verification: {e}"}],
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# UI Verification Runner
# ---------------------------------------------------------------------------

def run_ui_verification(base_url: str, verbose: bool = False) -> Dict[str, Any]:
    """Run ui_verification module and return structured results."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {
            "summary": {"total": 0, "passed": 0, "warnings": 0, "failures": 0, "skipped": 1},
            "results": [{"tab_id": "*", "tab_name": "*", "check": "playwright", "severity": "SKIP", "message": "Playwright not installed — UI verification skipped"}],
        }

    try:
        from ui_verification import UiVerifier, _define_tabs, Severity as UISeverity

        verifier = UiVerifier(base_url=base_url, verbose=verbose, screenshot_on="fail")
        tabs = _define_tabs()

        results = verifier.run_all(tabs)

        if not results:
            return {
                "summary": {"total": 0, "passed": 0, "warnings": 0, "failures": 1, "skipped": 0},
                "results": [{"tab_id": "*", "tab_name": "*", "check": "browser", "severity": "FAIL", "message": "Browser launch failed — no results returned"}],
            }

        passes = sum(1 for r in results if r.severity == UISeverity.PASS)
        warns = sum(1 for r in results if r.severity == UISeverity.WARN)
        fails = sum(1 for r in results if r.severity == UISeverity.FAIL)
        skips = sum(1 for r in results if r.severity == UISeverity.SKIP)

        return {
            "summary": {
                "total": len(results),
                "passed": passes,
                "warnings": warns,
                "failures": fails,
                "skipped": skips,
            },
            "results": [
                {
                    "tab_id": r.tab_id,
                    "tab_name": r.tab_name,
                    "check": r.check_name,
                    "severity": r.severity.value,
                    "message": r.message,
                    "details": r.details,
                    "screenshot": r.screenshot,
                }
                for r in results
            ],
        }
    except ImportError as e:
        return {
            "summary": {"total": 0, "passed": 0, "warnings": 0, "failures": 1, "skipped": 0},
            "results": [{"tab_id": "*", "tab_name": "*", "check": "import", "severity": "FAIL", "message": f"Cannot import ui_verification: {e}"}],
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Test Data Seeder Runner
# ---------------------------------------------------------------------------

def seed_test_data(verbose: bool = False) -> Dict[str, Any]:
    """Seed test data via test_data_seeder. Returns seeding result."""
    try:
        from test_data_seeder import TestSeeder

        seeder = TestSeeder()
        counts = seeder.seed_all(hours_ago=1.0)

        if verbose:
            print(f"  Seeded: {json.dumps(counts, indent=2)}")

        return {
            "seeded": True,
            "seed_counts": counts,
            "error": None,
        }
    except Exception as e:
        return {
            "seeded": False,
            "seed_counts": None,
            "error": str(e),
        }


def cleanup_test_data(verbose: bool = False) -> Dict[str, Any]:
    """Clean up test data via test_data_seeder. Returns cleanup result."""
    try:
        from test_data_seeder import TestSeeder

        seeder = TestSeeder()
        counts = seeder.cleanup()

        if verbose:
            print(f"  Cleaned: {json.dumps(counts, indent=2)}")

        return {
            "cleaned": True,
            "cleanup_counts": counts,
            "error": None,
        }
    except Exception as e:
        return {
            "cleaned": False,
            "cleanup_counts": None,
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Issue extraction
# ---------------------------------------------------------------------------

def extract_issues(api_results: Dict, empty_results: Dict, ui_results: Dict) -> List[Dict[str, str]]:
    """Extract FAIL/WARN issues from all modules into a flat list."""
    issues: List[Dict[str, str]] = []

    for r in api_results.get("results", []):
        if r["severity"] in ("FAIL", "WARN"):
            issues.append({
                "module": "api_verification",
                "severity": r["severity"],
                "message": f"{r['endpoint']} [{r['check']}]: {r['message']}",
            })

    for r in empty_results.get("results", []):
        if r["severity"] in ("FAIL", "WARN"):
            issues.append({
                "module": "empty_state",
                "severity": r["severity"],
                "message": f"{r['tab']} ({r['endpoint']}): {r['message']}",
            })

    for r in ui_results.get("results", []):
        if r["severity"] in ("FAIL", "WARN"):
            issues.append({
                "module": "ui_verification",
                "severity": r["severity"],
                "message": f"{r['tab_name']} [{r['check']}]: {r['message']}",
            })

    return issues


# ---------------------------------------------------------------------------
# Per-tab status aggregation
# ---------------------------------------------------------------------------

def build_per_tab_status(api_results: Dict, empty_results: Dict, ui_results: Dict) -> Dict[str, Dict[str, str]]:
    """Build per-tab PASS/FAIL aggregation across all modules."""
    # Collect all unique tab names from all modules
    all_tabs: set[str] = set()

    # From empty state verification (has tab names)
    for r in empty_results.get("results", []):
        all_tabs.add(r["tab"])

    # From UI verification (has tab names)
    for r in ui_results.get("results", []):
        all_tabs.add(r["tab_name"])

    per_tab: Dict[str, Dict[str, str]] = {}

    for tab in sorted(all_tabs):
        tab_status: Dict[str, str] = {}

        # API status: check if any API endpoint related to this tab failed
        tab_api_status = "PASS"
        for r in api_results.get("results", []):
            if r["severity"] == "FAIL":
                tab_api_status = "FAIL"
                break
        tab_status["api"] = tab_api_status

        # Empty state status
        tab_empty_status = "PASS"
        for r in empty_results.get("results", []):
            if r["tab"] == tab and r["severity"] == "FAIL":
                tab_empty_status = "FAIL"
                break
            elif r["tab"] == tab and r["severity"] == "WARN":
                tab_empty_status = "WARN"
        tab_status["empty_state"] = tab_empty_status

        # UI status
        tab_ui_status = "PASS"
        for r in ui_results.get("results", []):
            if r["tab_name"] == tab and r["severity"] == "FAIL":
                tab_ui_status = "FAIL"
                break
            elif r["tab_name"] == tab and r["severity"] == "WARN":
                tab_ui_status = "WARN"
        tab_status["ui"] = tab_ui_status

        per_tab[tab] = tab_status

    return per_tab


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    base_url: str,
    pipeline_health: Dict[str, Any],
    api_results: Dict[str, Any],
    empty_results: Dict[str, Any],
    ui_results: Dict[str, Any],
    test_data: Dict[str, Any],
    duration_seconds: float,
) -> Dict[str, Any]:
    """Generate the consolidated E2E report."""

    # Extract issues
    issues = extract_issues(api_results, empty_results, ui_results)

    # Per-tab status
    per_tab = build_per_tab_status(api_results, empty_results, ui_results)

    # Overall summary
    total_checks = (
        api_results["summary"]["total"] +
        empty_results["summary"]["total"] +
        ui_results["summary"]["total"]
    )
    passed = (
        api_results["summary"]["passed"] +
        empty_results["summary"]["pass"] +
        ui_results["summary"]["passed"]
    )
    warnings = (
        api_results["summary"]["warnings"] +
        empty_results["summary"]["warn"] +
        ui_results["summary"]["warnings"]
    )
    failures = (
        api_results["summary"]["failures"] +
        empty_results["summary"]["fail"] +
        ui_results["summary"]["failures"]
    )
    skipped = (
        api_results["summary"]["skipped"] +
        0 +  # empty_state doesn't track skips in summary
        ui_results["summary"]["skipped"]
    )

    overall = "PASS" if failures == 0 else "FAIL"

    report = {
        "report": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "base_url": base_url,
            "duration_seconds": round(duration_seconds, 2),
            "overall_status": overall,
        },
        "pipeline_health": pipeline_health,
        "test_data": test_data,
        "api_verification": api_results,
        "empty_state_verification": empty_results,
        "ui_verification": ui_results,
        "per_tab_status": per_tab,
        "issues": issues,
        "summary": {
            "total_checks": total_checks,
            "passed": passed,
            "warnings": warnings,
            "failures": failures,
            "skipped": skipped,
            "overall": overall,
        },
    }

    return report


# ---------------------------------------------------------------------------
# Terminal-friendly text report
# ---------------------------------------------------------------------------

def print_text_report(report: Dict[str, Any], verbose: bool = False) -> None:
    """Print a human-readable summary to terminal."""

    rpt = report["report"]
    summary = report["summary"]
    health = report["pipeline_health"]

    print()
    print(f"{'='*72}")
    print(f"  E2E REPORT — OPNsense Anomaly Agent")
    print(f"{'='*72}")
    print(f"  Generated:    {rpt['generated_at']}")
    print(f"  Base URL:     {rpt['base_url']}")
    print(f"  Duration:     {rpt['duration_seconds']:.1f}s")
    print(f"  Version:      {health.get('details', {}).get('version', 'unknown')}")
    print(f"  Overall:      {'PASS' if summary['overall'] == 'PASS' else 'FAIL'}")
    print()

    # Pipeline health
    print(f"  Pipeline Health: {health['status'].upper()}")
    for sub, info in health.get("subsystems", {}).items():
        status_icon = "OK" if info["status"] in ("ok", "active", "configured") else info["status"].upper()
        print(f"    {sub:20s} {status_icon}")
    print()

    # Module summaries
    modules = [
        ("API Verification", report["api_verification"]["summary"]),
        ("Empty State", report["empty_state_verification"]["summary"]),
        ("UI Verification", report["ui_verification"]["summary"]),
    ]

    print(f"  Module Results:")
    for name, mod_summary in modules:
        total = mod_summary.get("total", 0)
        passed = mod_summary.get("passed", mod_summary.get("pass", 0))
        warns = mod_summary.get("warnings", mod_summary.get("warn", 0))
        fails = mod_summary.get("failures", mod_summary.get("fail", 0))
        skips = mod_summary.get("skipped", 0)
        status = "PASS" if fails == 0 else f"FAIL({fails})"
        print(f"    {name:22s} {status:10s}  ({passed}P/{warns}W/{fails}F/{skips}S of {total})")
    print()

    # Per-tab status
    print(f"  Per-Tab Status:")
    per_tab = report.get("per_tab_status", {})
    for tab, status in per_tab.items():
        api_s = status.get("api", "-")
        empty_s = status.get("empty_state", "-")
        ui_s = status.get("ui", "-")
        # Mark with symbol
        api_sym = "." if api_s == "PASS" else "F"
        empty_sym = "." if empty_s == "PASS" else ("W" if empty_s == "WARN" else "F")
        ui_sym = "." if ui_s == "PASS" else ("W" if ui_s == "WARN" else "F")
        print(f"    {tab:25s}  api={api_sym}  empty={empty_sym}  ui={ui_sym}")
    print()

    # Issues
    if report["issues"]:
        print(f"  Issues ({len(report['issues'])}):")
        for issue in report["issues"][:20]:
            sev = issue["severity"]
            mod = issue["module"]
            msg = issue["message"]
            print(f"    [{sev}] [{mod}] {msg}")
        if len(report["issues"]) > 20:
            print(f"    ... and {len(report['issues']) - 20} more (see JSON)")
        print()

    # Test data
    td = report.get("test_data", {})
    if td.get("seeded"):
        print(f"  Test Data: SEEDED  (counts: {json.dumps(td.get('seed_counts', {}))})")
    if td.get("cleaned"):
        print(f"  Test Data: CLEANED (counts: {json.dumps(td.get('cleanup_counts', {}))})")
    if td.get("error"):
        print(f"  Test Data: ERROR   ({td['error']})")

    # Total summary
    print()
    print(f"  TOTAL: {summary['total_checks']} checks | {summary['passed']} passed | "
          f"{summary['warnings']} warnings | {summary['failures']} failures | "
          f"{summary['skipped']} skipped")
    print(f"{'='*72}")
    print()


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="E2E Reporter — orchestrates all verification modules into a JSON report"
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help="Dashboard base URL")
    parser.add_argument("--output", "-o", default=None, help="Write JSON report to file (default: stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print progress to stderr")
    parser.add_argument("--seed", action="store_true", help="Seed test data before verification")
    parser.add_argument("--clean", action="store_true", help="Clean up test data after verification")
    parser.add_argument("--skip-ui", action="store_true", help="Skip UI verification (no Playwright needed)")
    parser.add_argument("--skip-api", action="store_true", help="Skip API verification")
    parser.add_argument("--skip-empty-state", action="store_true", help="Skip empty-state verification")
    parser.add_argument("--text-only", action="store_true", help="Print text report only, no JSON")
    args = parser.parse_args()

    log = lambda msg: print(msg, file=sys.stderr) if args.verbose else None

    start_time = time.time()

    # --- Phase 0: Pipeline Health ---
    log("[1/5] Checking pipeline health...")
    pipeline_health = check_pipeline_health(args.base, verbose=args.verbose)

    # --- Phase 1: Test Data Seeding (optional) ---
    test_data: Dict[str, Any] = {"seeded": False, "seed_counts": None, "cleaned": False, "cleanup_counts": None, "error": None}

    if args.seed:
        log("[2/5] Seeding test data...")
        seed_result = seed_test_data(verbose=args.verbose)
        test_data["seeded"] = seed_result["seeded"]
        test_data["seed_counts"] = seed_result["seed_counts"]
        test_data["error"] = seed_result.get("error")
        if seed_result["seeded"]:
            # Wait for agent to process seeded data
            log("  Waiting 5s for agent to process seeded data...")
            time.sleep(5)
    else:
        # Shift phase numbers
        log("[2/5] Skipping test data seeding (--seed not set)")

    # --- Phase 2: API Verification ---
    if args.skip_api:
        log("[3/5] Skipping API verification")
        api_results = {
            "summary": {"total": 0, "passed": 0, "warnings": 0, "failures": 0, "skipped": 0},
            "results": [{"endpoint": "*", "method": "*", "check": "skipped", "severity": "SKIP", "message": "API verification skipped via --skip-api"}],
        }
    else:
        log("[3/5] Running API verification...")
        api_results = run_api_verification(args.base, verbose=args.verbose)

    # --- Phase 3: Empty State Verification ---
    if args.skip_empty_state:
        log("[4/5] Skipping empty-state verification")
        empty_results = {
            "summary": {"total": 0, "pass": 0, "warn": 0, "fail": 0},
            "results": [{"tab": "*", "endpoint": "*", "description": "skipped", "severity": "SKIP", "message": "Empty-state verification skipped"}],
        }
    else:
        log("[4/5] Running empty-state verification...")
        empty_results = run_empty_state_verification(args.base, verbose=args.verbose)

    # --- Phase 4: UI Verification ---
    if args.skip_ui:
        log("[5/5] Skipping UI verification")
        ui_results = {
            "summary": {"total": 0, "passed": 0, "warnings": 0, "failures": 0, "skipped": 0},
            "results": [{"tab_id": "*", "tab_name": "*", "check": "skipped", "severity": "SKIP", "message": "UI verification skipped via --skip-ui"}],
        }
    else:
        log("[5/5] Running UI verification...")
        ui_results = run_ui_verification(args.base, verbose=args.verbose)

    # --- Phase 5: Test Data Cleanup (optional) ---
    if args.clean:
        log("Cleaning up test data...")
        cleanup_result = cleanup_test_data(verbose=args.verbose)
        test_data["cleaned"] = cleanup_result["cleaned"]
        test_data["cleanup_counts"] = cleanup_result["cleanup_counts"]
        if cleanup_result.get("error"):
            test_data["error"] = cleanup_result["error"]

    # --- Generate Report ---
    duration = time.time() - start_time

    report = generate_report(
        base_url=args.base,
        pipeline_health=pipeline_health,
        api_results=api_results,
        empty_results=empty_results,
        ui_results=ui_results,
        test_data=test_data,
        duration_seconds=duration,
    )

    # --- Output ---
    if not args.text_only:
        json_str = json.dumps(report, indent=2, default=str)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(json_str)
            print(f"JSON report written to: {output_path}", file=sys.stderr)
        else:
            print(json_str)

    # Always print text summary to stderr
    print_text_report(report, verbose=args.verbose)

    # Exit code
    return 1 if report["summary"]["failures"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
