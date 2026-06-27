#!/usr/bin/env python3
"""
Empty State Verification Module
--------------------------------
Checks all dashboard tabs for proper empty-state messaging.

Problems this catches:
  - Tabs that show "0" without explaining WHAT the zero means
  - Tabs that don't distinguish "no data yet" from "data source not configured"
  - Tabs that crash or return malformed responses when empty

Good empty state (example):
  Nginx tab -> "No Nginx stub_status endpoint configured"
  
Bad empty state (example):
  Nginx tab -> "0 requests" [user has no idea if this is normal or broken]

Verification levels:
  CONFIGURED    - Data source is wired up, data flows
  NO_DATA       - Data source configured, but no events collected yet
  NOT_CONFIGURED - Data source not set up (missing credentials, endpoint, etc.)
  UNKNOWN       - Cannot determine status from response

Usage:
  # Run against local dev server
  python3 empty_state_verification.py

  # Run against remote deployment
  python3 empty_state_verification.py --base http://192.168.1.50:8766

  # Verbose: show response previews
  python3 empty_state_verification.py --verbose

  # JSON output (for CI/parsing)
  python3 empty_state_verification.py --json

Exit codes:
  0  All checks passed
  1  One or more tabs have inadequate empty state messaging
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# ─── Configuration ──────────────────────────────────────────────────

DEFAULT_BASE = "http://localhost:8766"
REQUEST_TIMEOUT = 15  # seconds


class Severity(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"


class DataSourceStatus(Enum):
    """What the empty state should communicate."""
    CONFIGURED = "configured"          # Data source wired up + has data
    NO_DATA = "no_data"                # Configured but no events yet
    NOT_CONFIGURED = "not_configured"  # Missing credentials/endpoint/setup
    UNKNOWN = "unknown"                # Cannot determine from response


@dataclass
class EmptyStateCheck:
    """Result of checking one tab's empty state."""
    tab_name: str
    endpoint: str
    description: str
    severity: Severity
    message: str
    data_source_status: DataSourceStatus = DataSourceStatus.UNKNOWN
    has_contextual_message: bool = False
    has_zero_without_context: bool = False
    expected_empty_message: str = ""
    actual_response_keys: List[str] = field(default_factory=list)
    response_preview: str = ""
    response_time_ms: float = 0


# ─── Tab/Endpoint Definitions ──────────────────────────────────────
# Each entry maps a tab to its API endpoint(s), expected empty behavior,
# and the contextual message users SHOULD see when empty.

TAB_SPECS = [
    {
        "tab": "Overview",
        "endpoint": "/api/stats",
        "description": "Overall dashboard statistics",
        "data_key": "total_events",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No events collected yet. Syslog pipeline must be feeding the agent.",
        "zero_without_context_keys": ["total_events", "events_24h", "blocked_24h", "passed_24h"],
        "configured_indicator": "total_events",  # > 0 means configured
    },
    {
        "tab": "Traffic Heatmap",
        "endpoint": "/api/heatmap",
        "description": "IP x Hour activity heatmap",
        "data_key": "data",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No traffic data yet. Heatmap populates as syslog events arrive.",
        "zero_without_context_keys": ["data", "labels_y"],
        "configured_indicator": "labels_y",  # non-empty list means configured
    },
    {
        "tab": "Flow Map",
        "endpoint": "/api/ip-flow",
        "description": "IP communication flow graph",
        "data_key": "nodes",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No flow data yet. Flows appear once events are parsed.",
        "zero_without_context_keys": ["nodes", "links"],
        "configured_indicator": "nodes",
    },
    {
        "tab": "IP Flow",
        "endpoint": "/api/ip-flow",
        "description": "Detailed IP communication table",
        "data_key": "nodes",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No IP flow data available yet.",
        "zero_without_context_keys": ["nodes", "links"],
        "configured_indicator": "nodes",
    },
    {
        "tab": "IP Flow Clusters",
        "endpoint": "/api/ip-flow-clusters",
        "description": "Clustered IP flow visualization",
        "data_key": "nodes",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No cluster data yet. Requires IP flow data.",
        "zero_without_context_keys": ["nodes", "edges"],
        "configured_indicator": "nodes",
    },
    {
        "tab": "Threat Alerts",
        "endpoint": "/api/alerts",
        "description": "Volume-based threat alerts",
        "data_key": None,  # array response
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No alerts detected. Alerts trigger when attack thresholds are exceeded.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "Threat Alerts (ML)",
        "endpoint": "/api/anomalies",
        "description": "ML-detected anomalies",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No anomalies detected. ML detection runs on accumulated event data.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "Mutes",
        "endpoint": "/api/mutes",
        "description": "Active IP mutes",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No active mutes. Mutes silence alerts for specific IPs.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
        "empty_is_legitimate": True,  # Empty mutes list is a valid configured state
    },
    {
        "tab": "ZenArmor",
        "endpoint": "/api/zenarmor-summary",
        "description": "ZenArmor security gateway summary",
        "data_key": "total_events",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No ZenArmor events. ZenArmor data requires ZenArmor syslog entries in the pipeline.",
        "zero_without_context_keys": ["total_events", "policies_count", "anomalies_detected"],
        "configured_indicator": "total_events",
    },
    {
        "tab": "ZenArmor Policies",
        "endpoint": "/api/zenarmor-policies",
        "description": "ZenArmor security policies",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No ZenArmor policies detected. Requires ZenArmor syslog data.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "IDS",
        "endpoint": "/api/ids-summary",
        "description": "Intrusion Detection System summary",
        "data_key": "total_events",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No IDS events. IDS data requires Suricata/Snort entries in the syslog pipeline.",
        "zero_without_context_keys": ["total_events", "signatures", "anomalies_detected"],
        "configured_indicator": "total_events",
    },
    {
        "tab": "IDS Signatures",
        "endpoint": "/api/ids-signatures",
        "description": "IDS signature list",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No IDS signatures detected. Requires Suricata/Snort syslog data.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "Geography",
        "endpoint": "/api/geo",
        "description": "Geographic distribution of traffic",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No geographic data yet. Geo enrichment requires IP events with reverse DNS/geo lookup.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "OPNsense Status",
        "endpoint": "/api/opnsense",
        "description": "OPNsense firewall status and interfaces",
        "data_key": "version",
        "expected_status": DataSourceStatus.NOT_CONFIGURED,
        "expected_empty_message": "OPNsense API not configured. Set OPNSENSE_API_URL and credentials in .env.",
        "zero_without_context_keys": ["cpu_usage", "memory_usage", "firewall_rules"],
        "configured_indicator": "version",
        "not_configured_value": "unknown",  # version == "unknown" means not configured
    },
    {
        "tab": "Firewall Rules",
        "endpoint": "/api/rules-classified",
        "description": "ML-classified firewall rules",
        "data_key": "total_rules",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No firewall rules loaded. Rules are pulled from OPNsense API.",
        "zero_without_context_keys": ["total_rules"],
        "configured_indicator": "total_rules",
    },
    {
        "tab": "Rules ML",
        "endpoint": "/api/rules-classified",
        "description": "Machine learning rule classification",
        "data_key": "total_rules",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No classified rules. Requires OPNsense API access + rule classification training.",
        "zero_without_context_keys": ["total_rules", "events_processed"],
        "configured_indicator": "total_rules",
    },
    {
        "tab": "Syslogs",
        "endpoint": "/api/events",
        "description": "Raw event/syslog viewer",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No events logged yet. Syslog pipeline must be feeding the agent.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "Services",
        "endpoint": "/api/service-status",
        "description": "Service monitoring (DNS, DHCP, NTP)",
        "data_key": "services",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No services monitored yet. Services are auto-discovered from syslog data.",
        "zero_without_context_keys": [],
        "configured_indicator": "services",
    },
    {
        "tab": "Query Logs",
        "endpoint": "/api/events",
        "description": "Log query interface",
        "data_key": None,
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No logs to query. Data appears once syslog events arrive.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "Network Topology",
        "endpoint": "/api/ip-flow",
        "description": "Interactive network topology visualization",
        "data_key": "nodes",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No network topology data. Requires IP flow events.",
        "zero_without_context_keys": ["nodes", "links"],
        "configured_indicator": "nodes",
    },
    {
        "tab": "WAN Flap",
        "endpoint": "/api/wan-flap",
        "description": "WAN interface flap detection",
        "data_key": "flaps",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No WAN flaps detected. Monitoring requires interface status events in syslog.",
        "zero_without_context_keys": ["total_flaps"],
        "configured_indicator": "flaps",
    },
    {
        "tab": "Nginx Monitor",
        "endpoint": "/api/nginx-summary",
        "description": "Nginx web server traffic monitoring",
        "data_key": "total_requests",
        "expected_status": DataSourceStatus.NOT_CONFIGURED,
        "expected_empty_message": "No Nginx stub_status endpoint configured. Configure NGINX_STUB_STATUS_URL in .env.",
        "zero_without_context_keys": ["total_requests", "unique_ips", "status_ok"],
        "configured_indicator": "total_requests",
    },
    {
        "tab": "Nginx Anomalies",
        "endpoint": "/api/nginx-anomalies",
        "description": "Nginx anomaly detection",
        "data_key": None,
        "expected_status": DataSourceStatus.NOT_CONFIGURED,
        "expected_empty_message": "No Nginx anomaly data. Requires nginx events from stub_status monitoring.",
        "zero_without_context_keys": [],
        "configured_indicator": None,
        "is_array": True,
    },
    {
        "tab": "Traffic Flow",
        "endpoint": "/api/traffic-flow",
        "description": "Traffic flow metrics",
        "data_key": "total",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No traffic flow data. Requires events in the database.",
        "zero_without_context_keys": ["total"],
        "configured_indicator": "total",
    },
    {
        "tab": "Protocol Distribution",
        "endpoint": "/api/protocols",
        "description": "Protocol distribution chart",
        "data_key": "protocols",
        "expected_status": DataSourceStatus.NO_DATA,
        "expected_empty_message": "No protocol data. Populates as events with protocol info arrive.",
        "zero_without_context_keys": [],
        "configured_indicator": "protocols",
    },
    {
        "tab": "System Health",
        "endpoint": "/api/health",
        "description": "System health check",
        "data_key": "status",
        "expected_status": DataSourceStatus.CONFIGURED,
        "expected_empty_message": "",  # Health always returns something
        "zero_without_context_keys": [],
        "configured_indicator": "status",
        "never_empty": True,  # This endpoint should always return data
    },
]


# ─── HTTP Helper ───────────────────────────────────────────────────

def fetch_json(base_url: str, path: str, timeout: int = REQUEST_TIMEOUT) -> Tuple[Any, float, Optional[str]]:
    """Fetch JSON from base_url + path. Returns (data, response_time_ms, error)."""
    url = f"{base_url}{path}"
    req = Request(url, headers={"Accept": "application/json"})
    start = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:
            elapsed = (time.time() - start) * 1000
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return None, elapsed, f"Non-JSON response: {body[:200]}"
            return data, elapsed, None
    except HTTPError as e:
        elapsed = (time.time() - start) * 1000
        return None, elapsed, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        elapsed = (time.time() - start) * 1000
        return None, elapsed, f"Connection error: {e.reason}"
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return None, elapsed, f"Error: {e}"


# ─── Analysis Logic ────────────────────────────────────────────────

def _is_empty_value(val: Any, data_key: Optional[str], is_array: bool) -> bool:
    """Check if a response represents an empty state."""
    if is_array:
        return isinstance(val, list) and len(val) == 0
    if isinstance(val, dict):
        if data_key and data_key in val:
            key_val = val[data_key]
            if isinstance(key_val, (int, float)):
                return key_val == 0
            if isinstance(key_val, list):
                return len(key_val) == 0
            if isinstance(key_val, str):
                return key_val in ("unknown", "error", "")
    return False


def _check_zero_without_context(response: Any, spec: dict) -> List[str]:
    """Find keys that have zero/empty values without contextual explanation."""
    problematic = []
    if not isinstance(response, dict):
        return problematic
    for key in spec.get("zero_without_context_keys", []):
        if key in response:
            val = response[key]
            if val == 0 or val == [] or val == {} or val == "unknown":
                # Check if there's a contextual message nearby
                context_keys = ["message", "status", "reason", "data_source_status",
                                "empty_state", "empty_message", "configured", "data_status"]
                has_context = any(k in response for k in context_keys)
                if not has_context:
                    problematic.append(key)
    return problematic


def _determine_actual_status(response: Any, spec: dict) -> DataSourceStatus:
    """Determine the actual data source status from the response."""
    is_array = spec.get("is_array", False)
    data_key = spec.get("data_key")
    configured_indicator = spec.get("configured_indicator")
    not_configured_value = spec.get("not_configured_value")
    never_empty = spec.get("never_empty", False)

    # If the response has an explicit status field, trust it
    if isinstance(response, dict):
        if "data_source_status" in response:
            return DataSourceStatus(response["data_source_status"])
        if "configured" in response:
            return DataSourceStatus.CONFIGURED if response["configured"] else DataSourceStatus.NOT_CONFIGURED

    # Check configured_indicator
    if configured_indicator and isinstance(response, dict):
        indicator_val = response.get(configured_indicator)
        if not_configured_value and indicator_val == not_configured_value:
            return DataSourceStatus.NOT_CONFIGURED
        if isinstance(indicator_val, (int, float)) and indicator_val > 0:
            return DataSourceStatus.CONFIGURED
        if isinstance(indicator_val, list) and len(indicator_val) > 0:
            return DataSourceStatus.CONFIGURED
        if isinstance(indicator_val, str) and indicator_val not in ("unknown", "error", ""):
            return DataSourceStatus.CONFIGURED
        # Indicator exists but is zero/empty -> NO_DATA (source configured, no events)
        if configured_indicator in response:
            return DataSourceStatus.NO_DATA

    # Array endpoints: empty array = NO_DATA (endpoint works, no data)
    if is_array and isinstance(response, list):
        return DataSourceStatus.NO_DATA if len(response) == 0 else DataSourceStatus.CONFIGURED

    if never_empty:
        return DataSourceStatus.CONFIGURED

    return DataSourceStatus.NO_DATA


def _has_contextual_messaging(response: Any, spec: dict) -> bool:
    """Check if the response includes contextual messaging for empty states."""
    if not isinstance(response, dict):
        return False
    context_keys = ["message", "empty_message", "data_source_status",
                    "configured", "status_message", "reason", "empty_reason"]
    return any(k in response for k in context_keys)


def analyze_tab(spec: dict, base_url: str, verbose: bool = False) -> EmptyStateCheck:
    """Analyze one tab's empty state handling."""
    data, elapsed, error = fetch_json(base_url, spec["endpoint"])
    
    result = EmptyStateCheck(
        tab_name=spec["tab"],
        endpoint=spec["endpoint"],
        description=spec["description"],
        severity=Severity.PASS,
        message="",
        data_source_status=DataSourceStatus.UNKNOWN,
        response_time_ms=elapsed,
    )

    # Handle fetch errors
    if error:
        result.severity = Severity.FAIL
        result.message = f"Endpoint unreachable: {error}"
        result.data_source_status = DataSourceStatus.UNKNOWN
        return result

    # Determine actual status
    result.data_source_status = _determine_actual_status(data, spec)

    # Store response info
    if isinstance(data, dict):
        result.actual_response_keys = list(data.keys())
        result.response_preview = json.dumps(data)[:300]
    elif isinstance(data, list):
        result.actual_response_keys = ["array"]
        result.response_preview = f"[...({len(data)} items)]"

    # Check if data is empty
    is_empty = _is_empty_value(data, spec.get("data_key"), spec.get("is_array", False))

    # Check for zero values without context
    zero_keys = _check_zero_without_context(data, spec) if isinstance(data, dict) else []
    result.has_zero_without_context = len(zero_keys) > 0

    # Check for contextual messaging
    result.has_contextual_message = _has_contextual_messaging(data, spec)

    # ─── Evaluation ────────────────────────────────────────────────
    issues = []

    # If the tab marks empty as legitimate (e.g. mutes), skip empty-state messaging checks
    empty_is_legitimate = spec.get("empty_is_legitimate", False)

    if is_empty and not empty_is_legitimate:
        # Data IS empty - check messaging quality
        if not result.has_contextual_message:
            issues.append(
                f"Empty response has no contextual messaging. "
                f"User sees raw zeros/empty arrays without explanation."
            )

        if zero_keys:
            issues.append(
                f"Zero/empty values without context: {', '.join(zero_keys)}. "
                f"User cannot tell if this means 'not configured' or 'no data yet'."
            )

        # Check if actual status matches expected
        expected = spec.get("expected_status", DataSourceStatus.NO_DATA)
        if result.data_source_status != expected:
            issues.append(
                f"Expected status '{expected.value}' but determined '{result.data_source_status.value}'. "
                f"Tab may mislead users about the state of the data source."
            )

        if result.data_source_status == DataSourceStatus.UNKNOWN:
            issues.append(
                "Cannot determine data source status from response. "
                f"Add 'data_source_status' or 'configured' field to API response."
            )
    elif empty_is_legitimate and is_empty:
        # Legitimate empty state (e.g., no active mutes) - no action needed
        pass
    else:
        # Data is present - still check for structural completeness
        if zero_keys:
            issues.append(
                f"Some fields still show zero without context despite other data being present: {', '.join(zero_keys)}"
            )

    # Set result
    if not issues:
        result.severity = Severity.PASS
        result.message = "OK" if not is_empty else "Empty with acceptable handling"
    elif len(issues) == 1 and "zero values" in issues[0]:
        result.severity = Severity.WARN
        result.message = issues[0]
    else:
        result.severity = Severity.FAIL
        result.message = "; ".join(issues)

    result.expected_empty_message = spec.get("expected_empty_message", "")

    return result


# ─── Reporting ─────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    Severity.PASS: "\033[32m",    # green
    Severity.WARN: "\033[33m",    # yellow
    Severity.FAIL: "\033[31m",    # red
    Severity.INFO: "\033[36m",    # cyan
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _colored(text: str, severity: Severity) -> str:
    return f"{_SEVERITY_COLORS.get(severity, '')}{text}{_RESET}"


def print_report(results: List[EmptyStateCheck], verbose: bool = False) -> None:
    """Print human-readable report to stdout."""
    print(f"\n{'='*72}")
    print(f"  EMPTY STATE VERIFICATION REPORT")
    print(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*72}\n")

    # Summary
    passes = [r for r in results if r.severity == Severity.PASS]
    warns = [r for r in results if r.severity == Severity.WARN]
    fails = [r for r in results if r.severity == Severity.FAIL]

    print(f"  Summary: {_colored(f'{len(passes)} PASS', Severity.PASS)}  "
          f"{_colored(f'{len(warns)} WARN', Severity.WARN)}  "
          f"{_colored(f'{len(fails)} FAIL', Severity.FAIL)}  "
          f"(total: {len(results)})")
    print()

    # Failures first
    if fails:
        print(f"  {_BOLD}── FAILURES ──{_RESET}")
        for r in fails:
            print(f"\n  {_colored(f'[FAIL] {r.tab_name}', Severity.FAIL)}")
            print(f"    Endpoint:    {r.endpoint}")
            print(f"    Description: {r.description}")
            print(f"    Status:      {r.data_source_status.value}")
            print(f"    Response:    keys={r.actual_response_keys}")
            print(f"    Issue:       {r.message}")
            if r.expected_empty_message:
                print(f"    Expected msg: {r.expected_empty_message}")
            if verbose and r.response_preview:
                print(f"    Preview:     {r.response_preview}")

    # Warnings
    if warns:
        print(f"\n  {_BOLD}── WARNINGS ──{_RESET}")
        for r in warns:
            print(f"\n  {_colored(f'[WARN] {r.tab_name}', Severity.WARN)}")
            print(f"    Endpoint:    {r.endpoint}")
            print(f"    Issue:       {r.message}")
            if verbose and r.response_preview:
                print(f"    Preview:     {r.response_preview}")

    # Passes
    if passes:
        print(f"\n  {_BOLD}── PASSED ──{_RESET}")
        for r in passes:
            status_str = r.data_source_status.value
            ctx = " (has context)" if r.has_contextual_message else ""
            print(f"  {_colored(f'[PASS] {r.tab_name}', Severity.PASS)} — {status_str}{ctx}")

    # ─── Recommendations ───────────────────────────────────────────
    print(f"\n\n  {_BOLD}── RECOMMENDATIONS ──{_RESET}")
    print()
    
    # Group recommendations by data source status
    not_configured_tabs = [r for r in results if r.data_source_status == DataSourceStatus.NOT_CONFIGURED]
    no_data_tabs = [r for r in results if r.data_source_status == DataSourceStatus.NO_DATA]
    unknown_tabs = [r for r in results if r.data_source_status == DataSourceStatus.UNKNOWN]

    if not_configured_tabs:
        print(f"  Data sources NOT CONFIGURED ({len(not_configured_tabs)}):")
        for r in not_configured_tabs:
            print(f"    • {r.tab_name}: {r.expected_empty_message}")
        print()

    if no_data_tabs:
        print(f"  Data sources with NO DATA ({len(no_data_tabs)}):")
        for r in no_data_tabs:
            print(f"    • {r.tab_name}: {r.expected_empty_message}")
        print()

    if unknown_tabs:
        print(f"  Data sources with UNKNOWN status ({len(unknown_tabs)}):")
        for r in unknown_tabs:
            print(f"    • {r.tab_name}: {r.endpoint} — cannot determine status")
        print()

    # Structural recommendations
    zero_context_issues = [r for r in results if r.has_zero_without_context]
    if zero_context_issues:
        print(f"  Tabs showing ZERO without context ({len(zero_context_issues)}):")
        print(f"  These show raw '0' values without explaining what it means:")
        for r in zero_context_issues:
            print(f"    • {r.tab_name} ({r.endpoint})")
        print()
        print(f"  FIX: Add 'data_source_status' field to API responses that indicates:")
        print(f"    - 'not_configured' → data source not set up")
        print(f"    - 'no_data'       → configured but no events yet")
        print(f"    - 'configured'    → has data")
        print()

    # Empty messaging recommendations
    no_context_tabs = [r for r in results if r.data_source_status != DataSourceStatus.CONFIGURED and not r.has_contextual_message]
    if no_context_tabs:
        print(f"  Tabs missing contextual empty-state messages ({len(no_context_tabs)}):")
        for r in no_context_tabs:
            if r.expected_empty_message:
                print(f"    • {r.tab_name}")
                print(f"      → Should show: \"{r.expected_empty_message}\"")
        print()

    print(f"{'='*72}\n")


def print_json_report(results: List[EmptyStateCheck]) -> None:
    """Print JSON report for CI/parsing."""
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "pass": len([r for r in results if r.severity == Severity.PASS]),
            "warn": len([r for r in results if r.severity == Severity.WARN]),
            "fail": len([r for r in results if r.severity == Severity.FAIL]),
        },
        "results": [],
    }
    for r in results:
        output["results"].append({
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
        })
    print(json.dumps(output, indent=2))


# ─── Main ──────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Empty State Verification Module")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Dashboard base URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show response previews")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    parser.add_argument("--tab", help="Check only this tab (by name)")
    parser.add_argument("--endpoint", help="Check only this endpoint")
    args = parser.parse_args()

    # Filter specs
    specs = TAB_SPECS
    if args.tab:
        specs = [s for s in specs if s["tab"] == args.tab]
        if not specs:
            print(f"Error: No tab named '{args.tab}'", file=sys.stderr)
            return 1
    if args.endpoint:
        specs = [s for s in specs if s["endpoint"] == args.endpoint]
        if not specs:
            print(f"Error: No endpoint '{args.endpoint}'", file=sys.stderr)
            return 1

    print(f"Checking {len(specs)} tab(s) against {args.base}...")
    
    results = []
    for spec in specs:
        result = analyze_tab(spec, args.base, verbose=args.verbose)
        results.append(result)

    if args.json:
        print_json_report(results)
    else:
        print_report(results, verbose=args.verbose)

    # Exit code
    has_failures = any(r.severity == Severity.FAIL for r in results)
    return 1 if has_failures else 0


if __name__ == "__main__":
    sys.exit(main())
