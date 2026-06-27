#!/usr/bin/env python3
"""
API Trace Verification Module
------------------------------
Hits every dashboard API endpoint and verifies:
  1. HTTP status (200/401 expected, 4xx/5xx flagged)
  2. JSON parsability
  3. Required structural keys present
  4. Data presence (distinguishes expected empty from pipeline failure)
  5. Error handling (invalid params return structured errors, not crashes)

Usage:
  # Run against local dev server
  python3 api_verification.py

  # Run against remote deployment
  python3 api_verification.py --base http://192.168.1.50:8766

  # Run with auth (basic auth endpoints)
  python3 api_verification.py --user admin --pass secret

  # Dry-run: just print the plan
  python3 api_verification.py --dry-run

  # Verbose: show response previews
  python3 api_verification.py --verbose

Exit codes:
  0  All checks passed
  1  One or more checks failed
"""

import argparse
import json
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
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
    SKIP = "SKIP"


@dataclass
class CheckResult:
    endpoint: str
    method: str
    check_name: str
    severity: Severity
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    response_time_ms: float = 0


@dataclass
class EndpointSpec:
    """Specification for one API endpoint to verify."""
    path: str
    method: str = "GET"
    # Required top-level keys in response JSON
    required_keys: List[str] = field(default_factory=list)
    # Keys that must be arrays
    required_arrays: List[str] = field(default_factory=list)
    # Keys that must be objects (dicts)
    required_objects: List[str] = field(default_factory=list)
    # Keys that must be numbers
    required_numbers: List[str] = field(default_factory=list)
    # Keys that must be strings
    required_strings: List[str] = field(default_factory=list)
    # If the array has 0 items, is that expected? (e.g., mutes can be legitimately empty)
    empty_is_ok: bool = False
    # Query params to append
    params: Dict[str, str] = field(default_factory=dict)
    # Custom validator: (response_json, base_url) -> List[CheckResult]
    custom_validator: Optional[Callable] = None
    # Description
    description: str = ""
    # Expected HTTP status (default 200)
    expected_status: int = 200
    # Body for POST requests
    body: Optional[Dict[str, Any]] = None


# ─── Endpoint Definitions ──────────────────────────────────────────

def _define_endpoints() -> List[EndpointSpec]:
    """Define all API endpoints to verify."""
    return [
        # ── Core health & status ──
        EndpointSpec(
            path="/api/health",
            description="System health check",
            required_keys=["status"],
            required_objects=["health"] if False else [],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/stats",
            description="Overall statistics",
            required_keys=["total_events"],
            required_numbers=["total_events"],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/version",
            description="Server version",
            required_keys=["version"],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/heartbeat",
            description="Agent heartbeat",
            required_keys=["ok"],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/resources",
            description="System resources (CPU, memory, disk)",
            required_keys=["cpu_percent"],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/metrics",
            description="Agent metrics (JSON)",
            required_keys=["events_processed"],
            empty_is_ok=False,
        ),

        # ── Visualization data ──
        EndpointSpec(
            path="/api/heatmap",
            description="Heatmap time-series data",
            required_keys=["data", "labels_x", "labels_y"],
            required_arrays=["data"],
            empty_is_ok=True,  # heatmap can be empty if no events yet
        ),
        EndpointSpec(
            path="/api/ip-flow",
            description="IP flow graph data",
            required_keys=["nodes", "links"],
            required_arrays=["nodes", "links"],
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/ip-flow-clusters",
            description="IP flow clusters",
            required_keys=["nodes", "edges"],
            required_arrays=["nodes", "edges"],
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/traffic-flow",
            description="Traffic flow metrics",
            required_keys=[],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/protocols",
            description="Protocol distribution",
            required_arrays=[],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/actions",
            description="Action distribution (pass/block)",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/timeline",
            description="Event timeline",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/blocked-ips",
            description="Blocked IP list",
            empty_is_ok=True,  # legitimately empty if nothing blocked
        ),
        EndpointSpec(
            path="/api/top-ports",
            description="Top destination ports",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/rule-heatmap",
            description="Rule heatmap",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/directions",
            description="Direction distribution",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/rule-actions",
            description="Rule action breakdown",
            empty_is_ok=False,
        ),

        # ── Events & alerts ──
        EndpointSpec(
            path="/api/events",
            params={"limit": "50"},
            description="Recent events",
            empty_is_ok=True,  # events list can be empty if DB is fresh
        ),
        EndpointSpec(
            path="/api/alerts",
            description="High-activity IP alerts",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/anomalies",
            description="ML-detected anomalies",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/flows",
            description="Network flows",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/logs",
            description="Raw logs",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/system_logs",
            description="System logs",
            empty_is_ok=True,
        ),

        # ── Geo ──
        EndpointSpec(
            path="/api/geo",
            description="Country-level geo stats",
            empty_is_ok=True,
        ),

        # ── Mutes ──
        EndpointSpec(
            path="/api/mutes",
            description="Active mute rules",
            empty_is_ok=True,  # legitimately empty if nothing muted
        ),

        # ── OPNsense integration ──
        EndpointSpec(
            path="/api/opnsense",
            description="OPNsense status (interfaces, gateways, services)",
            required_keys=["status"],
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/rules",
            description="Firewall rules",
            empty_is_ok=True,
        ),

        # ── ML / Classification ──
        EndpointSpec(
            path="/api/rules-classified",
            description="ML-classified firewall rules",
            required_keys=["summary", "rules"],
            required_arrays=["rules"],
            required_objects=["summary"],
            empty_is_ok=True,  # rules list can be empty if classifier hasn't run
        ),
        EndpointSpec(
            path="/api/ml-summary",
            description="ML model summary",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/ml-model",
            description="ML model state",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/ml-classifications",
            description="ML classifications",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/drift",
            description="Model drift detection",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/threshold",
            description="Threshold configuration",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/active-learning-queue",
            description="Active learning queue",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/active-learning-queue/items",
            description="Active learning queue items",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/sse-stats",
            description="SSE connection stats",
            empty_is_ok=False,
        ),

        # ── ZenArmor ──
        EndpointSpec(
            path="/api/zenarmor-summary",
            description="ZenArmor summary",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/zenarmor-policies",
            description="ZenArmor policies",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/zenarmor-events",
            params={"limit": "50"},
            description="ZenArmor events",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/zenarmor-anomalies",
            description="ZenArmor anomalies",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/zenarmor",
            description="ZenArmor combined",
            empty_is_ok=False,
        ),

        # ── IDS ──
        EndpointSpec(
            path="/api/ids-summary",
            description="IDS summary",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/ids-signatures",
            description="IDS signatures",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/ids-events",
            params={"limit": "50"},
            description="IDS events",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/ids-anomalies",
            description="IDS anomalies",
            empty_is_ok=True,
        ),

        # ── Nginx ──
        EndpointSpec(
            path="/api/nginx-summary",
            description="Nginx web server summary",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/nginx-anomalies",
            description="Nginx anomalies",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/nginx-top-paths",
            description="Nginx top paths",
            empty_is_ok=True,
        ),
        EndpointSpec(
            path="/api/nginx-timeline",
            description="Nginx timeline",
            empty_is_ok=True,
        ),

        # ── Drain / maintenance ──
        EndpointSpec(
            path="/api/drain",
            description="Graceful drain status",
            empty_is_ok=False,
        ),
        EndpointSpec(
            path="/api/schema-migrations",
            description="Schema migration status",
            empty_is_ok=False,
        ),
    ]


# ─── HTTP Client ────────────────────────────────────────────────────

class ApiClient:
    """Lightweight HTTP client for API verification."""

    def __init__(self, base_url: str, user: Optional[str] = None,
                 password: Optional[str] = None, timeout: int = REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user = user
        self.password = password
        # Create SSL context that allows self-signed certs (common on deploy hosts)
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.user and self.password:
            import base64
            creds = base64.b64encode(
                f"{self.user}:{self.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        return headers

    def request(self, method: str, path: str,
                params: Optional[Dict[str, str]] = None,
                body: Optional[Dict[str, Any]] = None
                ) -> Tuple[int, Any, float, Optional[str]]:
        """Execute HTTP request. Returns (status, json_body, elapsed_ms, error_msg)."""
        url = self.base_url + path
        if params:
            url += "?" + urlencode(params)

        data = None
        if body and method in ("POST", "PUT", "PATCH"):
            data = json.dumps(body).encode("utf-8")

        req = Request(url, data=data, method=method)
        for k, v in self._headers().items():
            req.add_header(k, v)
        if data:
            req.add_header("Content-Type", "application/json")

        start = time.monotonic()
        try:
            with urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                elapsed = (time.monotonic() - start) * 1000
                raw = resp.read().decode("utf-8", errors="replace")
                status = resp.getcode()
                # Try to parse JSON; fall back to string
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = raw
                return status, parsed, elapsed, None
        except HTTPError as e:
            elapsed = (time.monotonic() - start) * 1000
            raw = e.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = raw
            return e.code, parsed, elapsed, str(e)
        except URLError as e:
            elapsed = (time.monotonic() - start) * 1000
            return 0, None, elapsed, f"URLError: {e.reason}"
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return 0, None, elapsed, f"{type(e).__name__}: {e}"


# ─── Verification Engine ────────────────────────────────────────────

class ApiVerifier:
    """Runs verification checks against all defined endpoints."""

    def __init__(self, client: ApiClient, verbose: bool = False):
        self.client = client
        self.verbose = verbose
        self.results: List[CheckResult] = []
        self.endpoints: List[EndpointSpec] = _define_endpoints()

    def add_result(self, result: CheckResult):
        self.results.append(result)
        icon = {"PASS": "+", "WARN": "~", "FAIL": "x", "SKIP": "-"}[result.severity.value]
        line = f"  [{icon}] {result.endpoint} {result.method} | {result.check_name}: {result.message}"
        if result.response_time_ms > 0:
            line += f" ({result.response_time_ms:.0f}ms)"
        print(line)
        if self.verbose and result.details:
            for k, v in result.details.items():
                print(f"         {k}: {v}")

    # ── Individual checks ──

    def _check_status(self, spec: EndpointSpec, status: int,
                       elapsed: float) -> CheckResult:
        if status == spec.expected_status:
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="http_status", severity=Severity.PASS,
                message=f"HTTP {status} (expected {spec.expected_status})",
                response_time_ms=elapsed,
            )
        elif 400 <= status < 500:
            # Client error - could be auth issue
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="http_status", severity=Severity.WARN,
                message=f"HTTP {status} (expected {spec.expected_status}) — possible auth/config issue",
                response_time_ms=elapsed,
            )
        else:
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="http_status", severity=Severity.FAIL,
                message=f"HTTP {status} (expected {spec.expected_status})",
                response_time_ms=elapsed,
            )

    def _check_connectivity(self, spec: EndpointSpec, error_msg: Optional[str],
                             elapsed: float) -> CheckResult:
        return CheckResult(
            endpoint=spec.path, method=spec.method,
            check_name="connectivity", severity=Severity.FAIL,
            message=f"Connection failed: {error_msg}",
            response_time_ms=elapsed,
        )

    def _check_json(self, spec: EndpointSpec, body: Any,
                     elapsed: float) -> CheckResult:
        if isinstance(body, str):
            # Non-JSON response (e.g., HTML error page)
            snippet = body[:120].replace("\n", " ")
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="json_parse", severity=Severity.FAIL,
                message=f"Non-JSON response (string): {snippet}",
                response_time_ms=elapsed,
            )
        if body is None:
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="json_parse", severity=Severity.WARN,
                message="Null/empty response body",
                response_time_ms=elapsed,
            )
        return CheckResult(
            endpoint=spec.path, method=spec.method,
            check_name="json_parse", severity=Severity.PASS,
            message="Valid JSON",
            response_time_ms=elapsed,
        )

    def _check_required_keys(self, spec: EndpointSpec, body: Any,
                               elapsed: float) -> List[CheckResult]:
        results = []
        if not spec.required_keys:
            return results
        if not isinstance(body, dict):
            results.append(CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="required_keys", severity=Severity.WARN,
                message=f"Response is not an object (got {type(body).__name__}), skipping key checks",
                response_time_ms=elapsed,
            ))
            return results
        missing = [k for k in spec.required_keys if k not in body]
        if missing:
            results.append(CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="required_keys", severity=Severity.FAIL,
                message=f"Missing required keys: {missing}",
                details={"present_keys": list(body.keys())},
                response_time_ms=elapsed,
            ))
        else:
            results.append(CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="required_keys", severity=Severity.PASS,
                message=f"All required keys present: {spec.required_keys}",
                response_time_ms=elapsed,
            ))
        return results

    def _check_array_types(self, spec: EndpointSpec, body: Any,
                             elapsed: float) -> List[CheckResult]:
        results = []
        if not isinstance(body, dict):
            return results
        for key in spec.required_arrays:
            val = body.get(key)
            if val is None:
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"array[{key}]", severity=Severity.WARN,
                    message=f"Key '{key}' is None",
                    response_time_ms=elapsed,
                ))
            elif not isinstance(val, list):
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"array[{key}]", severity=Severity.FAIL,
                    message=f"'{key}' is {type(val).__name__}, expected array",
                    response_time_ms=elapsed,
                ))
            else:
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"array[{key}]", severity=Severity.PASS,
                    message=f"'{key}' is array with {len(val)} items",
                    response_time_ms=elapsed,
                ))
        return results

    def _check_object_types(self, spec: EndpointSpec, body: Any,
                              elapsed: float) -> List[CheckResult]:
        results = []
        if not isinstance(body, dict):
            return results
        for key in spec.required_objects:
            val = body.get(key)
            if not isinstance(val, dict):
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"object[{key}]", severity=Severity.FAIL,
                    message=f"'{key}' is {type(val).__name__}, expected object",
                    response_time_ms=elapsed,
                ))
            else:
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"object[{key}]", severity=Severity.PASS,
                    message=f"'{key}' is object with {len(val)} keys",
                    response_time_ms=elapsed,
                ))
        return results

    def _check_number_types(self, spec: EndpointSpec, body: Any,
                              elapsed: float) -> List[CheckResult]:
        results = []
        if not isinstance(body, dict):
            return results
        for key in spec.required_numbers:
            val = body.get(key)
            if not isinstance(val, (int, float)):
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"number[{key}]", severity=Severity.FAIL,
                    message=f"'{key}' is {type(val).__name__} ({val!r}), expected number",
                    response_time_ms=elapsed,
                ))
            else:
                results.append(CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name=f"number[{key}]", severity=Severity.PASS,
                    message=f"'{key}' = {val}",
                    response_time_ms=elapsed,
                ))
        return results

    def _check_data_presence(self, spec: EndpointSpec, body: Any,
                               elapsed: float) -> CheckResult:
        """Distinguish expected empty from pipeline failure.

        Expected empty: empty_is_ok=True AND response is well-formed (empty array/object)
        Pipeline failure: required_keys missing, OR response is malformed,
                         OR empty_is_ok=False and data arrays are empty when they shouldn't be
        """
        # If response is not parseable, this is a pipeline failure
        if body is None or body == "":
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="data_presence", severity=Severity.FAIL,
                message="No data — possible pipeline failure",
                response_time_ms=elapsed,
            )

        # If response is a string (non-JSON), pipeline failure
        if isinstance(body, str):
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="data_presence", severity=Severity.FAIL,
                message=f"Non-JSON string response — pipeline failure: {body[:100]}",
                response_time_ms=elapsed,
            )

        # For array-type endpoints (events, alerts, mutes, etc.)
        if isinstance(body, list):
            if len(body) == 0:
                if spec.empty_is_ok:
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.PASS,
                        message="Empty array — expected (no data yet or legitimately empty)",
                        response_time_ms=elapsed,
                    )
                else:
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.WARN,
                        message="Empty array — data expected but none present",
                        response_time_ms=elapsed,
                    )
            else:
                return CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name="data_presence", severity=Severity.PASS,
                    message=f"Array with {len(body)} items",
                    response_time_ms=elapsed,
                )

        # For object-type endpoints, check if core data fields are populated
        if isinstance(body, dict):
            # Check arrays within the object
            array_keys = spec.required_arrays
            if array_keys:
                empty_arrays = []
                populated_arrays = []
                for key in array_keys:
                    val = body.get(key)
                    if isinstance(val, list):
                        if len(val) == 0:
                            empty_arrays.append(key)
                        else:
                            populated_arrays.append((key, len(val)))

                if populated_arrays:
                    detail = ", ".join(f"{k}: {v} items" for k, v in populated_arrays)
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.PASS,
                        message=f"Data present: {detail}",
                        details={"empty_arrays": empty_arrays} if empty_arrays else {},
                        response_time_ms=elapsed,
                    )
                elif empty_arrays and not spec.empty_is_ok:
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.WARN,
                        message=f"Data arrays empty when data expected: {empty_arrays}",
                        response_time_ms=elapsed,
                    )
                elif empty_arrays and spec.empty_is_ok:
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.PASS,
                        message="Data arrays empty — expected (no data yet)",
                        response_time_ms=elapsed,
                    )

            # For simple object responses (stats, health, etc.), check if non-empty
            if body and len(body) > 0:
                # Check for a clear error indicator
                if body.get("error") or body.get("message") and not body.get("ok"):
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.WARN,
                        message=f"Response indicates error: {body.get('error') or body.get('message')}",
                        response_time_ms=elapsed,
                    )
                return CheckResult(
                    endpoint=spec.path, method=spec.method,
                    check_name="data_presence", severity=Severity.PASS,
                    message=f"Object with {len(body)} keys",
                    response_time_ms=elapsed,
                )
            else:
                if spec.empty_is_ok:
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.PASS,
                        message="Empty object — expected",
                        response_time_ms=elapsed,
                    )
                else:
                    return CheckResult(
                        endpoint=spec.path, method=spec.method,
                        check_name="data_presence", severity=Severity.WARN,
                        message="Empty object — data expected",
                        response_time_ms=elapsed,
                    )

        return CheckResult(
            endpoint=spec.path, method=spec.method,
            check_name="data_presence", severity=Severity.WARN,
            message=f"Unexpected response type: {type(body).__name__}",
            response_time_ms=elapsed,
        )

    def _check_response_time(self, spec: EndpointSpec, elapsed: float) -> CheckResult:
        if elapsed < 200:
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="response_time", severity=Severity.PASS,
                message=f"{elapsed:.0f}ms (< 200ms)",
                response_time_ms=elapsed,
            )
        elif elapsed < 1000:
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="response_time", severity=Severity.WARN,
                message=f"{elapsed:.0f}ms (slow, < 1s)",
                response_time_ms=elapsed,
            )
        else:
            return CheckResult(
                endpoint=spec.path, method=spec.method,
                check_name="response_time", severity=Severity.FAIL,
                message=f"{elapsed:.0f}ms (> 1s, very slow)",
                response_time_ms=elapsed,
            )

    # ── Custom validators ──

    def _check_custom(self, spec: EndpointSpec, body: Any, elapsed: float) -> List[CheckResult]:
        if not spec.custom_validator:
            return []
        return spec.custom_validator(body, self.client.base_url)

    # ── Main verification ──

    def verify_endpoint(self, spec: EndpointSpec) -> List[CheckResult]:
        """Run all checks for a single endpoint."""
        endpoint_results: List[CheckResult] = []

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"  {spec.path} ({spec.method})")
            if spec.description:
                print(f"  {spec.description}")

        # 1. Make the request
        status, body, elapsed, error = self.client.request(
            spec.method, spec.path, params=spec.params, body=spec.body
        )

        # 2. Connectivity check
        if error:
            conn_result = self._check_connectivity(spec, error, elapsed)
            self.add_result(conn_result)
            endpoint_results.append(conn_result)
            return endpoint_results

        # 3. HTTP status check
        status_result = self._check_status(spec, status, elapsed)
        self.add_result(status_result)
        endpoint_results.append(status_result)

        # 4. JSON parse check
        json_result = self._check_json(spec, body, elapsed)
        self.add_result(json_result)
        endpoint_results.append(json_result)

        # 5. Required keys check
        for kr in self._check_required_keys(spec, body, elapsed):
            self.add_result(kr)
            endpoint_results.append(kr)

        # 6. Type checks
        for ar in self._check_array_types(spec, body, elapsed):
            self.add_result(ar)
            endpoint_results.append(ar)
        for or_ in self._check_object_types(spec, body, elapsed):
            self.add_result(or_)
            endpoint_results.append(or_)
        for nr in self._check_number_types(spec, body, elapsed):
            self.add_result(nr)
            endpoint_results.append(nr)

        # 7. Data presence check (expected empty vs pipeline failure)
        dp_result = self._check_data_presence(spec, body, elapsed)
        self.add_result(dp_result)
        endpoint_results.append(dp_result)

        # 8. Response time check
        rt_result = self._check_response_time(spec, elapsed)
        self.add_result(rt_result)
        endpoint_results.append(rt_result)

        # 9. Custom validators
        for cr in self._check_custom(spec, body, elapsed):
            self.add_result(cr)
            endpoint_results.append(cr)

        return endpoint_results

    def run_all(self) -> List[CheckResult]:
        """Run verification on all endpoints."""
        print(f"\n{'='*60}")
        print(f"  API Trace Verification")
        print(f"  Base URL: {self.client.base_url}")
        print(f"  Endpoints: {len(self.endpoints)}")
        print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
        print(f"{'='*60}")

        all_results: List[CheckResult] = []
        for spec in self.endpoints:
            results = self.verify_endpoint(spec)
            all_results.extend(results)

        return all_results

    # ── Error handling verification ──

    def verify_error_handling(self) -> List[CheckResult]:
        """Verify that error cases return structured responses, not crashes."""
        print(f"\n{'='*60}")
        print(f"  Error Handling Verification")
        print(f"{'='*60}")

        results: List[CheckResult] = []

        # Test 1: Non-existent endpoint should return 404 with JSON
        status, body, elapsed, error = self.client.request("GET", "/api/nonexistent-endpoint")
        if error:
            results.append(CheckResult(
                endpoint="/api/nonexistent", method="GET",
                check_name="error_404", severity=Severity.WARN,
                message=f"Connection error on 404 (may be expected): {error}",
                response_time_ms=elapsed,
            ))
        elif status == 404:
            if isinstance(body, dict) or isinstance(body, str):
                results.append(CheckResult(
                    endpoint="/api/nonexistent", method="GET",
                    check_name="error_404", severity=Severity.PASS,
                    message=f"404 returned cleanly (HTTP {status})",
                    response_time_ms=elapsed,
                ))
            else:
                results.append(CheckResult(
                    endpoint="/api/nonexistent", method="GET",
                    check_name="error_404", severity=Severity.WARN,
                    message=f"404 but unusual body type: {type(body).__name__}",
                    response_time_ms=elapsed,
                ))
        else:
            results.append(CheckResult(
                endpoint="/api/nonexistent", method="GET",
                check_name="error_404", severity=Severity.WARN,
                message=f"Expected 404, got HTTP {status}",
                response_time_ms=elapsed,
            ))
        self.add_result(results[-1]) if results else None

        # Test 2: Invalid query params on /api/events
        status, body, elapsed, error = self.client.request(
            "GET", "/api/events", params={"limit": "not-a-number"}
        )
        if error:
            result = CheckResult(
                endpoint="/api/events?limit=invalid", method="GET",
                check_name="error_invalid_params", severity=Severity.WARN,
                message=f"Error on invalid params: {error}",
                response_time_ms=elapsed,
            )
        elif status == 200:
            # Graceful degradation — returned something even with bad params
            result = CheckResult(
                endpoint="/api/events?limit=invalid", method="GET",
                check_name="error_invalid_params", severity=Severity.PASS,
                message="Handled invalid params gracefully (returned data)",
                response_time_ms=elapsed,
            )
        elif 400 <= status < 500:
            result = CheckResult(
                endpoint="/api/events?limit=invalid", method="GET",
                check_name="error_invalid_params", severity=Severity.PASS,
                message=f"Returned client error {status} for invalid params",
                response_time_ms=elapsed,
            )
        else:
            result = CheckResult(
                endpoint="/api/events?limit=invalid", method="GET",
                check_name="error_invalid_params", severity=Severity.WARN,
                message=f"Unexpected status {status} for invalid params",
                response_time_ms=elapsed,
            )
        self.add_result(result)
        results.append(result)

        # Test 3: POST to GET-only endpoint
        status, body, elapsed, error = self.client.request(
            "POST", "/api/health", body={"test": True}
        )
        if status == 405 or status == 400 or status == 200:
            result = CheckResult(
                endpoint="/api/health", method="POST",
                check_name="error_method_not_allowed", severity=Severity.PASS,
                message=f"Handled POST to GET endpoint: HTTP {status}",
                response_time_ms=elapsed,
            )
        elif error:
            result = CheckResult(
                endpoint="/api/health", method="POST",
                check_name="error_method_not_allowed", severity=Severity.WARN,
                message=f"Error on POST: {error}",
                response_time_ms=elapsed,
            )
        else:
            result = CheckResult(
                endpoint="/api/health", method="POST",
                check_name="error_method_not_allowed", severity=Severity.WARN,
                message=f"Unexpected status {status} for POST to GET endpoint",
                response_time_ms=elapsed,
            )
        self.add_result(result)
        results.append(result)

        return results


# ─── Summary Report ─────────────────────────────────────────────────

def print_summary(results: List[CheckResult]) -> Tuple[int, int, int, int]:
    """Print summary and return (pass, warn, fail, skip) counts."""
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

    # Group failures by endpoint
    if fails:
        print(f"\n  FAILURES BY ENDPOINT:")
        fail_by_ep: Dict[str, List[CheckResult]] = {}
        for f in fails:
            fail_by_ep.setdefault(f.endpoint, []).append(f)
        for ep, errs in sorted(fail_by_ep.items()):
            print(f"    {ep}:")
            for e in errs:
                print(f"      - {e.check_name}: {e.message}")

    # Group warnings by endpoint
    if warns:
        print(f"\n  WARNINGS BY ENDPOINT:")
        warn_by_ep: Dict[str, List[CheckResult]] = {}
        for w in warns:
            warn_by_ep.setdefault(w.endpoint, []).append(w)
        for ep, errs in sorted(warn_by_ep.items()):
            print(f"    {ep}:")
            for e in errs:
                print(f"      - {e.check_name}: {e.message}")

    # Slowest endpoints
    sorted_by_time = sorted(results, key=lambda r: r.response_time_ms, reverse=True)
    if sorted_by_time:
        print(f"\n  SLOWEST ENDPOINTS:")
        for r in sorted_by_time[:5]:
            print(f"    {r.response_time_ms:>8.0f}ms  {r.endpoint}")

    # Endpoints with no data (warnings)
    empty_warns = [w for w in warns if "empty" in w.message.lower() or "no data" in w.message.lower()]
    if empty_warns:
        print(f"\n  ENDPOINTS WITH NO DATA (may be expected on fresh deployment):")
        for w in empty_warns:
            print(f"    {w.endpoint}: {w.message}")

    print(f"\n{'='*60}")

    return len(passes), len(warns), len(fails), len(skips)


# ─── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="API Trace Verification — hit every endpoint and verify data integrity"
    )
    parser.add_argument(
        "--base", default=DEFAULT_BASE,
        help=f"Base URL of the dashboard server (default: {DEFAULT_BASE})"
    )
    parser.add_argument("--user", default=None, help="Basic auth username")
    parser.add_argument("--pass", dest="password", default=None, help="Basic auth password")
    parser.add_argument(
        "--timeout", type=int, default=REQUEST_TIMEOUT,
        help=f"Request timeout in seconds (default: {REQUEST_TIMEOUT})"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed response info"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the verification plan without executing"
    )
    parser.add_argument(
        "--json-out", default=None,
        help="Write results to JSON file"
    )
    args = parser.parse_args()

    if args.dry_run:
        endpoints = _define_endpoints()
        print(f"Dry run — {len(endpoints)} endpoints to verify:")
        for ep in endpoints:
            flags = []
            if ep.params:
                flags.append(f"params={ep.params}")
            if ep.required_keys:
                flags.append(f"keys={ep.required_keys}")
            if ep.required_arrays:
                flags.append(f"arrays={ep.required_arrays}")
            flag_str = f"  [{', '.join(flags)}]" if flags else ""
            print(f"  {ep.method:4s} {ep.path}  --  {ep.description}{flag_str}")
        return 0

    # Build client
    client = ApiClient(
        base_url=args.base,
        user=args.user,
        password=args.password,
        timeout=args.timeout,
    )

    # Run verification
    verifier = ApiVerifier(client, verbose=args.verbose)

    # Phase 1: Endpoint verification
    results = verifier.run_all()

    # Phase 2: Error handling verification
    error_results = verifier.verify_error_handling()
    results.extend(error_results)

    # Summary
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
        with open(args.json_out, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nJSON report written to: {args.json_out}")

    # Exit code
    return 1 if fails > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
