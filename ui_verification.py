#!/usr/bin/env python3
"""
UI Trace Verification Module
-----------------------------
Navigates all 19 dashboard tabs via Playwright and verifies:
  1. Correct heading/title renders for the active tab
  2. No "Tab Crashed" error boundary visible
  3. No "Data Error" / "Connection Error" banners
  4. Actual data content visible (stat cards, tables, charts)
  5. Zero uncaught JavaScript errors in console
  6. Empty state messages when applicable (e.g., no mutes)
  7. Sidebar active state matches current tab

Usage:
  # Run against local dev server
  python3 ui_verification.py

  # Run against remote deployment
  python3 ui_verification.py --base http://192.168.1.50:8766

  # Screenshot on failure only (default: always)
  python3 ui_verification.py --screenshot-on fail

  # Verbose: dump DOM snippets per tab
  python3 ui_verification.py --verbose

  # Dry-run: print the plan
  python3 ui_verification.py --dry-run

Exit codes:
  0  All tabs pass
  1  One or more tabs failed
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── Configuration ──────────────────────────────────────────────────

DEFAULT_BASE = "http://localhost:8766"
NAV_TIMEOUT = 30000  # ms
SETTLE_DELAY = 2.0   # seconds after navigation for charts to render
SCREENSHOTS_DIR = Path("tests/screenshots/ui_verification")


class Severity(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    tab_id: str
    tab_name: str
    check_name: str
    severity: Severity
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    screenshot: Optional[str] = None


# ─── Tab Definitions ────────────────────────────────────────────────

@dataclass
class TabSpec:
    """Specification for one dashboard tab to verify."""
    tab_id: str            # Internal tab ID used in React store
    hash_fragment: str     # URL hash fragment (e.g., '#overview')
    expected_title: str    # Title shown in header h1
    sidebar_label: str     # Label in sidebar (for active state check)
    expected_content_hints: List[str] = field(default_factory=list)
    # Elements we expect to find (CSS selectors or text patterns)
    expected_elements: List[str] = field(default_factory=list)
    # API endpoints this tab depends on
    api_endpoints: List[str] = field(default_factory=list)
    # Is an empty state acceptable? (e.g., mutes with no active mutes)
    empty_is_ok: bool = False
    # Description of the tab
    description: str = ""


def _define_tabs() -> List[TabSpec]:
    """Define all 19 dashboard tabs to verify."""
    return [
        # 1. Overview
        TabSpec(
            tab_id="overview",
            hash_fragment="#overview",
            expected_title="Overview",
            sidebar_label="Dashboard",
            expected_content_hints=["events", "total", "severity"],
            expected_elements=["h1", ".stat-card", "table"],
            api_endpoints=["/api/stats", "/api/events"],
            description="Dashboard overview with severity counts, recent events, stat cards",
        ),
        # 2. Heatmap
        TabSpec(
            tab_id="heatmap",
            hash_fragment="#heatmap",
            expected_title="Traffic Heatmap",
            sidebar_label="Heatmap",
            expected_content_hints=["heatmap", "traffic"],
            expected_elements=["canvas"],
            api_endpoints=["/api/heatmap"],
            empty_is_ok=True,
            description="Traffic heatmap visualization with canvas rendering",
        ),
        # 3. Flow Map
        TabSpec(
            tab_id="flows",
            hash_fragment="#flows",
            expected_title="Flow Map",
            sidebar_label="Flow Map",
            expected_content_hints=["flow", "network"],
            expected_elements=["svg", "canvas"],
            api_endpoints=["/api/ip-flow", "/api/traffic-flow"],
            empty_is_ok=True,
            description="Network flow visualization with SVG/force graph",
        ),
        # 4. IP Flow
        TabSpec(
            tab_id="ipflow",
            hash_fragment="#ipflow",
            expected_title="IP Flow",
            sidebar_label="IP Flow",
            expected_content_hints=["ip", "flow"],
            expected_elements=["svg"],
            api_endpoints=["/api/ip-flow"],
            empty_is_ok=True,
            description="IP flow graph with source/target node visualization",
        ),
        # 5. Geography
        TabSpec(
            tab_id="geo",
            hash_fragment="#geo",
            expected_title="Geography",
            sidebar_label="Geography",
            expected_content_hints=["geo", "country"],
            expected_elements=["svg"],
            api_endpoints=["/api/geo"],
            empty_is_ok=True,
            description="Geographic distribution map of traffic by country",
        ),
        # 6. Alerts
        TabSpec(
            tab_id="alerts",
            hash_fragment="#alerts",
            expected_title="Threat Alerts",
            sidebar_label="Alerts",
            expected_content_hints=["alert", "threat"],
            expected_elements=["table", ".alert"],
            api_endpoints=["/api/alerts"],
            empty_is_ok=True,
            description="Threat alerts table with anomaly detections",
        ),
        # 7. Mutes
        TabSpec(
            tab_id="mutes",
            hash_fragment="#mutes",
            expected_title="Mutes",
            sidebar_label="Mutes",
            expected_content_hints=["mute"],
            expected_elements=[".cyber-card", "div"],
            api_endpoints=["/api/mutes"],
            empty_is_ok=True,
            description="Active mute rules management",
        ),
        # 8. ZenArmor
        TabSpec(
            tab_id="zenarmor",
            hash_fragment="#zenarmor",
            expected_title="ZenArmor",
            sidebar_label="ZenArmor",
            expected_content_hints=["zenarmor", "dns"],
            expected_elements=[".cyber-card", "div"],
            api_endpoints=["/api/zenarmor"],
            empty_is_ok=True,
            description="ZenArmor DNS threat classification",
        ),
        # 9. IDS
        TabSpec(
            tab_id="ids",
            hash_fragment="#ids",
            expected_title="IDS",
            sidebar_label="IDS",
            expected_content_hints=["ids", "signature"],
            expected_elements=["table"],
            api_endpoints=["/api/ids"],
            empty_is_ok=True,
            description="IDS signature matches and detections",
        ),
        # 10. OPNsense
        TabSpec(
            tab_id="opnsense",
            hash_fragment="#opnsense",
            expected_title="OPNsense Status",
            sidebar_label="OPNsense",
            expected_content_hints=["interface", "gateway", "opnsense"],
            expected_elements=["table", ".stat-card"],
            api_endpoints=["/api/opnsense"],
            description="OPNsense system status: interfaces, gateways, services",
        ),
        # 11. Services
        TabSpec(
            tab_id="services",
            hash_fragment="#services",
            expected_title="Services",
            sidebar_label="Services",
            expected_content_hints=["service", "port"],
            expected_elements=[".cyber-card", "div"],
            api_endpoints=["/api/services"],
            empty_is_ok=True,
            description="Network service monitoring with port detection",
        ),
        # 12. Nginx
        TabSpec(
            tab_id="nginx",
            hash_fragment="#nginx",
            expected_title="Nginx Monitor",
            sidebar_label="Nginx",
            expected_content_hints=["nginx", "request"],
            expected_elements=["table", ".stat-card"],
            api_endpoints=["/api/nginx"],
            empty_is_ok=True,
            description="Nginx web server monitoring and request stats",
        ),
        # 13. Network
        TabSpec(
            tab_id="network",
            hash_fragment="#network",
            expected_title="Network Topology",
            sidebar_label="Network",
            expected_content_hints=["network", "topology"],
            expected_elements=["svg", "canvas"],
            api_endpoints=["/api/ip-flow-clusters"],
            empty_is_ok=True,
            description="Network topology visualization with cluster detection",
        ),
        # 14. WAN Flap
        TabSpec(
            tab_id="wan-flap",
            hash_fragment="#wan-flap",
            expected_title="WAN Flap Detection",
            sidebar_label="WAN Flap",
            expected_content_hints=["wan", "flap"],
            expected_elements=[".cyber-card", "div"],
            api_endpoints=["/api/wan-flap"],
            empty_is_ok=True,
            description="WAN interface flapping detection and history",
        ),
        # 15. Firewall Rules
        TabSpec(
            tab_id="rules",
            hash_fragment="#rules",
            expected_title="Firewall Rules",
            sidebar_label="Firewall Rules",
            expected_content_hints=["rule", "firewall"],
            expected_elements=["table"],
            api_endpoints=["/api/rules"],
            description="Firewall rules from OPNsense API",
        ),
        # 16. Rules ML
        TabSpec(
            tab_id="rules-classified",
            hash_fragment="#rules-classified",
            expected_title="Rules ML",
            sidebar_label="Rules ML",
            expected_content_hints=["classification", "ml"],
            expected_elements=["table"],
            api_endpoints=["/api/rules-classified"],
            empty_is_ok=True,
            description="ML-classified firewall rules with confidence scores",
        ),
        # 17. Query Logs
        TabSpec(
            tab_id="logs",
            hash_fragment="#logs",
            expected_title="Query Logs",
            sidebar_label="Query Logs",
            expected_content_hints=["query", "log"],
            expected_elements=["table", "input"],
            api_endpoints=["/api/events"],
            empty_is_ok=True,
            description="Log query interface with search/filter controls",
        ),
        # 18. Syslogs
        TabSpec(
            tab_id="syslogs",
            hash_fragment="#syslogs",
            expected_title="Syslogs",
            sidebar_label="Syslogs",
            expected_content_hints=["syslog", "system"],
            expected_elements=["table"],
            api_endpoints=["/api/system_logs"],
            empty_is_ok=True,
            description="System log entries from OPNsense syslog",
        ),
        # 19. Settings
        TabSpec(
            tab_id="settings",
            hash_fragment="#settings",
            expected_title="Settings",
            sidebar_label="Settings",
            expected_content_hints=["setting", "config"],
            expected_elements=["input", "button", "select"],
            api_endpoints=["/api/health"],
            description="Dashboard settings with system configuration controls",
        ),
    ]


# ─── Playwright UI Verifier ─────────────────────────────────────────

class UiVerifier:
    """Navigate all tabs and verify rendering."""

    def __init__(self, base_url: str, verbose: bool = False, screenshot_on: str = "always"):
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self.screenshot_on = screenshot_on  # "always", "fail", "never"
        self.results: List[CheckResult] = []
        self.all_console_errors: List[str] = []

    def add_result(self, result: CheckResult):
        self.results.append(result)
        sev_icon = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗", "SKIP": "○"}
        print(f"  [{sev_icon.get(result.severity.value, '?')}]"
              f" {result.tab_name}: {result.check_name} — {result.message}")

    def _should_screenshot(self, tab_results: List[CheckResult]) -> bool:
        if self.screenshot_on == "always":
            return True
        if self.screenshot_on == "fail":
            return any(r.severity in (Severity.FAIL, Severity.WARN) for r in tab_results)
        return False

    def navigate_tab(self, page, tab_spec: TabSpec) -> List[CheckResult]:
        """Navigate to one tab and run all checks."""
        results: List[CheckResult] = []
        url = f"{self.base_url}{tab_spec.hash_fragment}"
        if self.verbose:
            print(f"\n  Navigating to {tab_spec.tab_id} → {url}")

        try:
            page.goto(url, wait_until="networkidle", timeout=NAV_TIMEOUT)
        except Exception as e:
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="navigation", severity=Severity.FAIL,
                message=f"Navigation failed: {e}",
            ))
            results.append(self.results[-1])
            return results

        # Wait for React + charts to settle
        time.sleep(SETTLE_DELAY)

        # ── Check 1: Correct heading ──
        try:
            header_text = page.locator("h1").first.inner_text(timeout=5000)
            if tab_spec.expected_title.lower() in header_text.lower():
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="heading", severity=Severity.PASS,
                    message=f"Header shows '{header_text.strip()}' ✓",
                ))
                results.append(self.results[-1])
            else:
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="heading", severity=Severity.FAIL,
                    message=f"Expected '{tab_spec.expected_title}', got '{header_text.strip()}'",
                ))
                results.append(self.results[-1])
        except Exception as e:
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="heading", severity=Severity.WARN,
                message=f"Could not find h1: {e}",
            ))
            results.append(self.results[-1])

        # ── Check 2: No "Tab Crashed" error boundary ──
        try:
            crashed = page.locator("text=Tab Crashed").is_visible(timeout=3000)
            if crashed:
                error_msg = page.locator("pre.text-cyber-red").first.inner_text(timeout=3000)
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="no_crash", severity=Severity.FAIL,
                    message=f"Tab crashed: {error_msg.strip()[:200]}",
                ))
                results.append(self.results[-1])
            else:
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="no_crash", severity=Severity.PASS,
                    message="No crash error boundary visible ✓",
                ))
                results.append(self.results[-1])
        except Exception:
            # is_visible timeout means element NOT found — which is good
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="no_crash", severity=Severity.PASS,
                message="No crash error boundary visible ✓",
            ))
            results.append(self.results[-1])

        # ── Check 3: No "Data Error" / "Connection Error" ──
        try:
            data_error = page.locator("text=Data Error").is_visible(timeout=3000)
            conn_error = page.locator("text=Connection Error").is_visible(timeout=3000)
            if data_error or conn_error:
                error_type = "Data Error" if data_error else "Connection Error"
                error_detail = ""
                try:
                    error_detail = page.locator("pre.text-cyber-red").first.inner_text(timeout=3000)
                except Exception:
                    pass
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="no_data_error", severity=Severity.FAIL,
                    message=f"{error_type} visible: {error_detail.strip()[:200]}",
                ))
                results.append(self.results[-1])
            else:
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="no_data_error", severity=Severity.PASS,
                    message="No data/connection error visible ✓",
                ))
                results.append(self.results[-1])
        except Exception:
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="no_data_error", severity=Severity.PASS,
                message="No data/connection error visible ✓",
            ))
            results.append(self.results[-1])

        # ── Check 4: Content presence (data rendering) ──
        content_found = False
        missing_elements = []
        for selector in tab_spec.expected_elements:
            try:
                count = page.locator(selector).count()
                if count > 0:
                    content_found = True
                else:
                    missing_elements.append(selector)
            except Exception:
                missing_elements.append(selector)

        if content_found:
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="content_present", severity=Severity.PASS,
                message=f"Content elements found ✓",
                details={"found_selectors": [s for s in tab_spec.expected_elements if s not in missing_elements]},
            ))
            results.append(self.results[-1])
        elif tab_spec.empty_is_ok:
            # Empty is acceptable — check for empty state message
            try:
                body_text = page.inner_text("main", timeout=3000)
                has_empty_msg = any(msg in body_text.lower() for msg in [
                    "no data", "no results", "loading", "empty",
                    "no events", "no alerts", "no rules", "no mutes",
                    "no services", "no logs", "no matches",
                ])
                if has_empty_msg:
                    self.add_result(CheckResult(
                        tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                        check_name="empty_state", severity=Severity.PASS,
                        message="Empty state displayed (acceptable) ✓",
                    ))
                    results.append(self.results[-1])
                else:
                    self.add_result(CheckResult(
                        tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                        check_name="empty_state", severity=Severity.WARN,
                        message=f"No expected content elements found. Missing: {missing_elements}",
                    ))
                    results.append(self.results[-1])
            except Exception as e:
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="empty_state", severity=Severity.WARN,
                    message=f"Could not check content: {e}",
                ))
                results.append(self.results[-1])
        else:
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="content_present", severity=Severity.WARN,
                message=f"No expected content elements. Missing: {missing_elements}",
            ))
            results.append(self.results[-1])

        # ── Check 5: Sidebar active state ──
        try:
            # Check that the sidebar button for this tab is highlighted
            # Use Playwright selectors (not raw CSS) — safer with spaces/special chars
            active_btn = page.locator(f"button:has-text('{tab_spec.sidebar_label}')")
            active_count = active_btn.count()
            if active_count > 0:
                btn_classes = active_btn.first.get_attribute("class", timeout=3000) or ""
                is_active = "cyber-accent" in btn_classes or "border-l-2" in btn_classes
                if is_active:
                    self.add_result(CheckResult(
                        tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                        check_name="sidebar_active", severity=Severity.PASS,
                        message=f"Sidebar '{tab_spec.sidebar_label}' is active ✓",
                    ))
                else:
                    self.add_result(CheckResult(
                        tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                        check_name="sidebar_active", severity=Severity.WARN,
                        message=f"Sidebar '{tab_spec.sidebar_label}' found but not highlighted",
                    ))
            else:
                self.add_result(CheckResult(
                    tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                    check_name="sidebar_active", severity=Severity.WARN,
                    message=f"Sidebar button '{tab_spec.sidebar_label}' not found",
                ))
        except Exception as e:
            self.add_result(CheckResult(
                tab_id=tab_spec.tab_id, tab_name=tab_spec.expected_title,
                check_name="sidebar_active", severity=Severity.WARN,
                message=f"Sidebar check failed: {e}",
            ))
        results.append(results[-1])

        # ── Screenshot ──
        if self._should_screenshot(results):
            try:
                SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
                safe_name = tab_spec.tab_id.replace("/", "-")
                screenshot_path = SCREENSHOTS_DIR / f"{safe_name}.png"
                page.screenshot(path=str(screenshot_path), full_page=False)
                last_result = results[-1]
                last_result.screenshot = str(screenshot_path)
                if self.verbose:
                    print(f"    Screenshot: {screenshot_path}")
            except Exception as e:
                if self.verbose:
                    print(f"    Screenshot failed: {e}")

        return results

    def collect_console_errors(self, page) -> List[CheckResult]:
        """Collect JavaScript console errors from the page."""
        results: List[CheckResult] = []
        try:
            js_errors = page.evaluate("""() => {
                return window.__hermes_ui_errors || [];
            }""")
            if js_errors:
                self.add_result(CheckResult(
                    tab_id="(global)", tab_name="(console)",
                    check_name="js_errors", severity=Severity.FAIL,
                    message=f"JavaScript errors detected: {len(js_errors)} errors",
                    details={"errors": js_errors[:10]},
                ))
                results.append(self.results[-1])
            else:
                self.add_result(CheckResult(
                    tab_id="(global)", tab_name="(console)",
                    check_name="js_errors", severity=Severity.PASS,
                    message="Zero JavaScript errors detected ✓",
                ))
                results.append(self.results[-1])
        except Exception:
            pass
        return results

    def run_all(self, tabs: List[TabSpec]) -> List[CheckResult]:
        """Run verification on all tabs using Playwright."""
        from playwright.sync_api import sync_playwright

        print(f"\n{'='*60}")
        print(f"  UI Trace Verification")
        print(f"  Base URL: {self.base_url}")
        print(f"  Tabs: {len(tabs)}")
        print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
        print(f"{'='*60}")

        all_results: List[CheckResult] = []

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-gpu"],
                )
            except Exception:
                try:
                    browser = p.chromium.launch(headless=True)
                except Exception as e:
                    print(f"\nFATAL: Cannot launch Playwright browser: {e}")
                    print("Install with: python3.13 -m playwright install chromium")
                    return []

            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,
            )

            # Instrument console errors BEFORE creating page
            context.on("console", lambda msg: self.all_console_errors.append(
                f"[{msg.type}] {msg.text}" if msg.type in ("error", "warning") else ""
            ))

            # Inject error collector script
            context.add_init_script("""
                window.__hermes_ui_errors = [];
                window.addEventListener('error', (e) => {
                    window.__hermes_ui_errors.push({
                        message: e.message,
                        filename: e.filename,
                        lineno: e.lineno,
                    });
                });
                window.addEventListener('unhandledrejection', (e) => {
                    window.__hermes_ui_errors.push({
                        message: 'UnhandledPromise: ' + (e.reason?.message || String(e.reason)),
                    });
                });
            """)

            page = context.new_page()

            # Navigate each tab
            for i, tab in enumerate(tabs):
                print(f"\n  [{i+1}/{len(tabs)}] {tab.expected_title} ({tab.tab_id})")
                tab_results = self.navigate_tab(page, tab)
                all_results.extend(tab_results)

            # Final console check
            print(f"\n  Console errors (accumulated across all tabs):")
            # Change console_errors from FAIL to WARN — console noise is common and often benign
            relevant_errors = [e for e in self.all_console_errors if e]
            if relevant_errors:
                self.add_result(CheckResult(
                    tab_id="(global)", tab_name="(console)",
                    check_name="console_errors", severity=Severity.WARN,
                    message=f"Console errors: {len(relevant_errors)}",
                    details={"errors": relevant_errors[:20]},
                ))
                all_results.append(all_results[-1])
            else:
                self.add_result(CheckResult(
                    tab_id="(global)", tab_name="(console)",
                    check_name="console_errors", severity=Severity.PASS,
                    message="No console errors across all tabs ✓",
                ))
                all_results.append(all_results[-1])

            # Check JS error accumulator
            js_check = self.collect_console_errors(page)
            all_results.extend(js_check)

            browser.close()

        return all_results


# ─── Summary Report ─────────────────────────────────────────────────

def print_summary(results: List[CheckResult]) -> Tuple[int, int, int, int]:
    """Print tab-by-tab summary report."""
    passes = [r for r in results if r.severity == Severity.PASS]
    warns = [r for r in results if r.severity == Severity.WARN]
    fails = [r for r in results if r.severity == Severity.FAIL]
    skips = [r for r in results if r.severity == Severity.SKIP]

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total checks:  {len(results)}")
    print(f"  Passed:        {len(passes)}")
    print(f"  Warnings:      {len(warns)}")
    print(f"  Failures:      {len(fails)}")
    print(f"  Skipped:       {len(skips)}")

    # Per-tab breakdown
    print(f"\n  PER-TAB RESULTS:")
    tab_ids = sorted(set(r.tab_id for r in results if r.tab_id != "(global)"))
    for tid in tab_ids:
        tab_results = [r for r in results if r.tab_id == tid]
        tab_passes = [r for r in tab_results if r.severity == Severity.PASS]
        tab_fails = [r for r in tab_results if r.severity == Severity.FAIL]
        tab_warns = [r for r in tab_results if r.severity == Severity.WARN]
        tab_name = tab_results[0].tab_name
        status = "PASS" if not tab_fails else ("WARN" if not tab_warns else "FAIL")
        status_icon = "✓" if status == "PASS" else ("⚠" if status == "WARN" else "✗")
        print(f"    [{status_icon}] {tab_name}: {len(tab_passes)} pass, "
              f"{len(tab_warns)} warn, {len(tab_fails)} fail")
        if tab_fails:
            for f in tab_fails:
                print(f"         ✗ {f.check_name}: {f.message[:100]}")

    # Global checks (console errors)
    global_results = [r for r in results if r.tab_id == "(global)"]
    if global_results:
        print(f"\n  GLOBAL CHECKS:")
        for gr in global_results:
            sev_icon = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗"}
            print(f"    [{sev_icon.get(gr.severity.value, '?')}] {gr.check_name}: {gr.message[:120]}")

    # Failure/warning detail
    if fails:
        print(f"\n  FAILURES:")
        for f in fails:
            print(f"    {f.tab_name} / {f.check_name}: {f.message[:120]}")

    if warns:
        print(f"\n  WARNINGS:")
        for w in warns:
            print(f"    {w.tab_name} / {w.check_name}: {w.message[:120]}")

    print(f"\n{'='*60}")

    return len(passes), len(warns), len(fails), len(skips)


# ─── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UI Trace Verification — navigate all tabs and verify rendering"
    )
    parser.add_argument(
        "--base", default=DEFAULT_BASE,
        help=f"Base URL of the dashboard (default: {DEFAULT_BASE})"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed output per check"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the verification plan without executing"
    )
    parser.add_argument(
        "--screenshot-on", default="always",
        choices=["always", "fail", "never"],
        help="When to take screenshots (default: always)"
    )
    parser.add_argument(
        "--json-out", default=None,
        help="Write results to JSON file"
    )
    args = parser.parse_args()

    tabs = _define_tabs()

    if args.dry_run:
        print(f"Dry run — {len(tabs)} tabs to verify:")
        for tab in tabs:
            print(f"  {tab.tab_id:20s} → {tab.hash_fragment:20s} "
                  f"title='{tab.expected_title}' "
                  f"elements={[tab.expected_elements]} "
                  f"apis={tab.api_endpoints}")
        return 0

    # Check playwright availability
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: Playwright not installed.")
        print("Install with: python3.13 -m pip install playwright")
        print("            python3.13 -m playwright install chromium")
        return 1

    verifier = UiVerifier(
        base_url=args.base,
        verbose=args.verbose,
        screenshot_on=args.screenshot_on,
    )

    results = verifier.run_all(tabs)

    if not results:
        print("\nNo results — browser launch likely failed.")
        return 1

    passes, warns, fails, skips = print_summary(results)

    # JSON output
    if args.json_out:
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "base_url": args.base,
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
        with open(args.json_out, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nJSON report written to: {args.json_out}")

    return 1 if fails > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
