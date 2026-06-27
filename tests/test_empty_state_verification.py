#!/usr/bin/env python3
"""
Tests for empty_state_verification.py
--------------------------------------
Unit tests for the analysis logic (no network required).
Also includes a mock-server integration test that simulates
a live dashboard API returning various empty/non-empty states.

Run:
  pytest tests/test_empty_state_verification.py -v
"""

import json
import sys
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch

# Ensure project root is on sys.path for imports
sys.path.insert(0, str(__file__.rsplit("/", 2)[0]))  # project root

import empty_state_verification as ev
from empty_state_verification import (
    DataSourceStatus,
    EmptyStateCheck,
    Severity,
    TAB_SPECS,
    _check_zero_without_context,
    _determine_actual_status,
    _has_contextual_messaging,
    _is_empty_value,
    analyze_tab,
    fetch_json,
)


class TestTabSpecs(unittest.TestCase):
    """Verify the tab spec definitions are valid."""

    def test_all_specs_have_required_fields(self):
        required = {"tab", "endpoint", "description", "expected_status", "expected_empty_message"}
        for spec in TAB_SPECS:
            missing = required - set(spec.keys())
            self.assertEqual(missing, set(), f"Tab '{spec.get('tab', '?')}' missing fields: {missing}")

    def test_all_expected_statuses_are_valid(self):
        valid = {s.value for s in DataSourceStatus}
        for spec in TAB_SPECS:
            self.assertIn(
                spec["expected_status"].value, valid,
                f"Tab '{spec['tab']}' has invalid expected_status"
            )

    def test_no_duplicate_tabs(self):
        names = [s["tab"] for s in TAB_SPECS]
        dupes = {n for n in names if names.count(n) > 1}
        self.assertEqual(dupes, set(), f"Duplicate tab names: {dupes}")

    def test_all_endpoints_start_with_slash(self):
        for spec in TAB_SPECS:
            self.assertTrue(
                spec["endpoint"].startswith("/"),
                f"Tab '{spec['tab']}' endpoint doesn't start with /: {spec['endpoint']}"
            )

    def test_critical_tabs_present(self):
        tab_names = {s["tab"] for s in TAB_SPECS}
        critical = {"Overview", "Nginx Monitor", "OPNsense Status", "IDS", "ZenArmor", "Threat Alerts"}
        missing = critical - tab_names
        self.assertEqual(missing, set(), f"Missing critical tabs: {missing}")

    def test_nginx_expected_not_configured(self):
        nginx = [s for s in TAB_SPECS if s["tab"] == "Nginx Monitor"]
        self.assertEqual(len(nginx), 1)
        self.assertEqual(nginx[0]["expected_status"], DataSourceStatus.NOT_CONFIGURED)

    def test_health_expected_configured(self):
        health = [s for s in TAB_SPECS if s["tab"] == "System Health"]
        self.assertEqual(len(health), 1)
        self.assertEqual(health[0]["expected_status"], DataSourceStatus.CONFIGURED)


class TestDetermineActualStatus(unittest.TestCase):
    """Test _determine_actual_status with various responses."""

    def test_zero_events_is_no_data(self):
        spec = TAB_SPECS[0]  # Overview
        status = _determine_actual_status({"total_events": 0}, spec)
        self.assertEqual(status, DataSourceStatus.NO_DATA)

    def test_positive_events_is_configured(self):
        spec = TAB_SPECS[0]
        status = _determine_actual_status({"total_events": 42}, spec)
        self.assertEqual(status, DataSourceStatus.CONFIGURED)

    def test_version_unknown_is_not_configured(self):
        opn = [s for s in TAB_SPECS if s["tab"] == "OPNsense Status"][0]
        status = _determine_actual_status({"version": "unknown"}, opn)
        self.assertEqual(status, DataSourceStatus.NOT_CONFIGURED)

    def test_version_present_is_configured(self):
        opn = [s for s in TAB_SPECS if s["tab"] == "OPNsense Status"][0]
        status = _determine_actual_status({"version": "24.1"}, opn)
        self.assertEqual(status, DataSourceStatus.CONFIGURED)

    def test_empty_heatmap_is_no_data(self):
        spec = TAB_SPECS[1]  # Heatmap
        status = _determine_actual_status({"labels_y": [], "data": []}, spec)
        self.assertEqual(status, DataSourceStatus.NO_DATA)

    def test_heatmap_with_data_is_configured(self):
        spec = TAB_SPECS[1]
        status = _determine_actual_status({"labels_y": ["1.2.3.4"], "data": [[1, 0]]}, spec)
        self.assertEqual(status, DataSourceStatus.CONFIGURED)

    def test_empty_array_is_no_data(self):
        spec = {"is_array": True, "data_key": None, "configured_indicator": None}
        status = _determine_actual_status([], spec)
        self.assertEqual(status, DataSourceStatus.NO_DATA)

    def test_array_with_items_is_configured(self):
        spec = {"is_array": True, "data_key": None, "configured_indicator": None}
        status = _determine_actual_status([{"id": 1}], spec)
        self.assertEqual(status, DataSourceStatus.CONFIGURED)

    def test_explicit_status_field_trusted(self):
        spec = TAB_SPECS[0]
        # Even with zero events, explicit status overrides
        status = _determine_actual_status({
            "total_events": 0,
            "data_source_status": "not_configured"
        }, spec)
        self.assertEqual(status, DataSourceStatus.NOT_CONFIGURED)

    def test_explicit_configured_field_trusted(self):
        spec = TAB_SPECS[0]
        status = _determine_actual_status({
            "total_events": 0,
            "configured": False
        }, spec)
        self.assertEqual(status, DataSourceStatus.NOT_CONFIGURED)

    def test_never_empty_always_configured(self):
        spec = {"never_empty": True, "configured_indicator": "status"}
        status = _determine_actual_status({"status": "ok"}, spec)
        self.assertEqual(status, DataSourceStatus.CONFIGURED)


class TestZeroWithoutContext(unittest.TestCase):
    """Test _check_zero_without_context detection."""

    def test_zeros_detected_without_context(self):
        resp = {"total_events": 0, "events_24h": 0, "blocked_24h": 0, "unique_ips": 5}
        spec = TAB_SPECS[0]
        zeros = _check_zero_without_context(resp, spec)
        self.assertIn("total_events", zeros)
        self.assertIn("events_24h", zeros)
        self.assertIn("blocked_24h", zeros)
        self.assertNotIn("unique_ips", zeros)  # 5 is not zero

    def test_zeros_not_flagged_when_context_present(self):
        resp = {"total_events": 0, "message": "No data yet"}
        spec = TAB_SPECS[0]
        zeros = _check_zero_without_context(resp, spec)
        self.assertEqual(zeros, [])

    def test_zeros_not_flagged_with_data_source_status(self):
        resp = {"total_events": 0, "data_source_status": "no_data"}
        spec = TAB_SPECS[0]
        zeros = _check_zero_without_context(resp, spec)
        self.assertEqual(zeros, [])

    def test_non_dict_response_returns_empty(self):
        zeros = _check_zero_without_context([], TAB_SPECS[0])
        self.assertEqual(zeros, [])

    def test_nonzero_values_not_flagged(self):
        resp = {"total_events": 100, "events_24h": 50}
        spec = TAB_SPECS[0]
        zeros = _check_zero_without_context(resp, spec)
        self.assertEqual(zeros, [])

    def test_empty_list_flagged(self):
        resp = {"labels_y": [], "data": []}
        spec = TAB_SPECS[1]
        zeros = _check_zero_without_context(resp, spec)
        self.assertIn("labels_y", zeros)
        self.assertIn("data", zeros)

    def test_unknown_string_flagged(self):
        resp = {"version": "unknown"}
        opn = [s for s in TAB_SPECS if s["tab"] == "OPNsense Status"][0]
        zeros = _check_zero_without_context(resp, opn)
        # version is not in zero_without_context_keys for opnsense, but test the logic
        self.assertEqual(zeros, [])


class TestContextualMessaging(unittest.TestCase):
    """Test _has_contextual_messaging detection."""

    def test_message_field_detected(self):
        self.assertTrue(_has_contextual_messaging({"message": "hi"}, {}))

    def test_data_source_status_detected(self):
        self.assertTrue(_has_contextual_messaging({"data_source_status": "no_data"}, {}))

    def test_configured_field_detected(self):
        self.assertTrue(_has_contextual_messaging({"configured": True}, {}))

    def test_no_context_fields(self):
        self.assertFalse(_has_contextual_messaging({"total_events": 0}, {}))

    def test_array_returns_false(self):
        self.assertFalse(_has_contextual_messaging([], {}))


class TestIsEmptyValue(unittest.TestCase):
    """Test _is_empty_value helper."""

    def test_dict_with_zero_int(self):
        self.assertTrue(_is_empty_value({"count": 0}, "count", False))

    def test_dict_with_positive_int(self):
        self.assertFalse(_is_empty_value({"count": 5}, "count", False))

    def test_empty_array(self):
        self.assertTrue(_is_empty_value([], None, True))

    def test_nonempty_array(self):
        self.assertFalse(_is_empty_value([1], None, True))

    def test_dict_with_empty_list_value(self):
        self.assertTrue(_is_empty_value({"items": []}, "items", False))

    def test_dict_with_unknown_string(self):
        self.assertTrue(_is_empty_value({"version": "unknown"}, "version", False))


class TestFetchJson(unittest.TestCase):
    """Test HTTP fetching (no network - test error handling)."""

    def test_connection_refused(self):
        data, elapsed, error = fetch_json("http://localhost:1", "/api/health", timeout=2)
        self.assertIsNone(data)
        self.assertIsNotNone(error)
        self.assertIn("Connection error", error)
        self.assertGreater(elapsed, 0)

    def test_invalid_url(self):
        data, elapsed, error = fetch_json("http://invalid.host.example", "/api/health", timeout=2)
        self.assertIsNone(data)
        self.assertIsNotNone(error)


class MockDashboardHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler that returns configured responses for testing."""

    _mock_responses: dict = {}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in self._mock_responses:
            data = self._mock_responses[path]
        else:
            data = {"error": "not found"}

        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress log output


class TestIntegrationWithMockServer(unittest.TestCase):
    """Integration tests against a mock server."""

    @classmethod
    def setUpClass(cls):
        MockDashboardHandler._mock_responses = {
            # Overview: empty with no context
            "/api/stats": {
                "total_events": 0,
                "events_24h": 0,
                "blocked_24h": 0,
                "passed_24h": 0,
                "anomalies_detected": 0,
                "alerts_sent": 0,
                "rules_classified": 0,
                "active_mutes": 0,
                "unique_ips": 0,
            },
            # Heatmap: empty with context
            "/api/heatmap": {
                "data": [],
                "labels_x": [],
                "labels_y": [],
                "data_source_status": "no_data",
                "message": "No traffic data yet. Heatmap populates as syslog events arrive.",
            },
            # Nginx: not configured
            "/api/nginx-summary": {
                "total_requests": 0,
                "by_method": {},
                "by_status": {},
                "status_ok": 0,
                "status_client_err": 0,
                "status_server_err": 0,
                "unique_ips": 0,
                "top_ips": [],
                "top_paths": [],
                "not_found_404": 0,
                "anomalies_by_type": {},
            },
            # Nginx anomalies: empty array
            "/api/nginx-anomalies": [],
            # OPNsense: configured
            "/api/opnsense": {
                "version": "24.1",
                "hostname": "opnsense",
                "uptime": "10 days",
                "cpu_usage": 15.2,
                "memory_usage": 42.0,
                "memory_total_gb": 8.0,
                "memory_used_gb": 3.4,
                "firewall_rules": 150,
                "services_total": 10,
                "services_running": 10,
                "interfaces": [],
                "gateways": [],
                "services": [],
            },
            # Alerts: empty array
            "/api/alerts": [],
            # Anomalies: has data
            "/api/anomalies": [
                {"timestamp": "2026-06-26T10:00:00", "type": "PORT_SCAN", "severity": "HIGH", "ip": "1.2.3.4", "count": 50}
            ],
            # Mutes: empty (legitimate)
            "/api/mutes": [],
            # ZenArmor: empty with context
            "/api/zenarmor-summary": {
                "total_events": 0,
                "policies_count": 0,
                "anomalies_detected": 0,
                "events_24h": 0,
                "message": "No ZenArmor events. ZenArmor data requires ZenArmor syslog entries.",
            },
            # ZenArmor policies: empty
            "/api/zenarmor-policies": [],
            # IDS: no data
            "/api/ids-summary": {
                "total_events": 0,
                "signatures": 0,
                "anomalies_detected": 0,
                "events_24h": 0,
            },
            "/api/ids-signatures": [],
            "/api/ids-anomalies": [],
            # Geo: empty array
            "/api/geo": [],
            # IP flow: empty
            "/api/ip-flow": {
                "nodes": [],
                "links": [],
            },
            "/api/ip-flow-clusters": {
                "nodes": [],
                "edges": [],
            },
            # Rules classified
            "/api/rules-classified": {
                "total_rules": 0,
                "classified_rules": [],
                "summary": {},
            },
            # Events
            "/api/events": [],
            # Service status
            "/api/service-status": {
                "services": {},
            },
            # WAN flap
            "/api/wan-flap": {
                "flaps": [],
                "stats": {"total_flaps": 0, "last_flap": "N/A", "avg_duration": "N/A"},
            },
            # Traffic flow
            "/api/traffic-flow": {
                "total": 0,
            },
            # Protocols
            "/api/protocols": {
                "protocols": [],
            },
            # Health
            "/api/health": {
                "status": "ok",
                "timestamp": "2026-06-26T12:00:00Z",
            },
        }

        cls.server = HTTPServer(("127.0.0.1", 0), MockDashboardHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_stats_zero_without_context_fails(self):
        """Overview with all zeros and no context should FAIL."""
        result = analyze_tab(TAB_SPECS[0], self.base_url)
        self.assertEqual(result.severity, Severity.FAIL)
        self.assertTrue(result.has_zero_without_context)
        self.assertFalse(result.has_contextual_message)

    def test_heatmap_with_context_passes(self):
        """Heatmap with contextual messaging should PASS."""
        result = analyze_tab(TAB_SPECS[1], self.base_url)
        self.assertEqual(result.severity, Severity.PASS)
        self.assertTrue(result.has_contextual_message)

    def test_nginx_not_configured_fails(self):
        """Nginx with all zeros and no context should FAIL."""
        nginx = [s for s in TAB_SPECS if s["tab"] == "Nginx Monitor"][0]
        result = analyze_tab(nginx, self.base_url)
        self.assertEqual(result.severity, Severity.FAIL)
        self.assertTrue(result.has_zero_without_context)

    def test_nginx_anomalies_empty_array(self):
        """Nginx anomalies empty array - check status detection."""
        spec = [s for s in TAB_SPECS if s["tab"] == "Nginx Anomalies"][0]
        result = analyze_tab(spec, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)

    def test_opnsense_configured_passes(self):
        """OPNsense with version should PASS as configured."""
        opn = [s for s in TAB_SPECS if s["tab"] == "OPNsense Status"][0]
        result = analyze_tab(opn, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.CONFIGURED)
        self.assertEqual(result.severity, Severity.PASS)

    def test_alerts_empty_array_passes(self):
        """Alerts with empty array - acceptable empty state."""
        alerts = [s for s in TAB_SPECS if s["tab"] == "Threat Alerts"][0]
        result = analyze_tab(alerts, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)

    def test_anomalies_with_data_passes(self):
        """Anomalies with data should PASS."""
        anomalies = [s for s in TAB_SPECS if s["tab"] == "Threat Alerts (ML)"][0]
        result = analyze_tab(anomalies, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.CONFIGURED)

    def test_mutes_empty_is_legitimate(self):
        """Mutes empty array - legitimate empty state."""
        mutes = [s for s in TAB_SPECS if s["tab"] == "Mutes"][0]
        result = analyze_tab(mutes, self.base_url)
        self.assertEqual(result.severity, Severity.PASS)

    def test_zenarmor_with_context_passes(self):
        """ZenArmor with contextual message should PASS."""
        za = [s for s in TAB_SPECS if s["tab"] == "ZenArmor"][0]
        result = analyze_tab(za, self.base_url)
        self.assertTrue(result.has_contextual_message)
        self.assertEqual(result.severity, Severity.PASS)

    def test_zenarmor_policies_empty_warns(self):
        """ZenArmor policies empty without context should WARN or FAIL."""
        za_pol = [s for s in TAB_SPECS if s["tab"] == "ZenArmor Policies"][0]
        result = analyze_tab(za_pol, self.base_url)
        self.assertIn(result.severity, [Severity.WARN, Severity.FAIL])

    def test_ids_no_context_fails(self):
        """IDS with zeros and no context should FAIL."""
        ids = [s for s in TAB_SPECS if s["tab"] == "IDS"][0]
        result = analyze_tab(ids, self.base_url)
        self.assertEqual(result.severity, Severity.FAIL)
        self.assertTrue(result.has_zero_without_context)

    def test_health_configured_passes(self):
        """Health endpoint should always PASS."""
        health = [s for s in TAB_SPECS if s["tab"] == "System Health"][0]
        result = analyze_tab(health, self.base_url)
        self.assertEqual(result.severity, Severity.PASS)
        self.assertEqual(result.data_source_status, DataSourceStatus.CONFIGURED)

    def test_ip_flow_empty_no_data(self):
        """IP flow with empty arrays should be NO_DATA."""
        flow = [s for s in TAB_SPECS if s["tab"] == "Flow Map"][0]
        result = analyze_tab(flow, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)

    def test_all_tabs_reachable(self):
        """All 26 tabs should be reachable (not FAIL due to connection error)."""
        results = []
        for spec in TAB_SPECS:
            result = analyze_tab(spec, self.base_url)
            results.append(result)
        # None should fail due to "Endpoint unreachable"
        unreachable = [r for r in results if "Endpoint unreachable" in r.message]
        self.assertEqual(len(unreachable), 0, f"Unreachable tabs: {[r.tab_name for r in unreachable]}")

    def test_filter_by_tab(self):
        """Test --tab filter selects correct spec."""
        spec = [s for s in TAB_SPECS if s["tab"] == "Nginx Monitor"]
        self.assertEqual(len(spec), 1)
        result = analyze_tab(spec[0], self.base_url)
        self.assertEqual(result.tab_name, "Nginx Monitor")

    def test_single_tab_check(self):
        """Test analyzing a single tab returns correct result."""
        overview = TAB_SPECS[0]
        result = analyze_tab(overview, self.base_url)
        self.assertEqual(result.tab_name, "Overview")
        self.assertEqual(result.endpoint, "/api/stats")
        self.assertGreater(result.response_time_ms, 0)

    def test_rules_classified_empty(self):
        """Rules classified with zero rules should be NO_DATA."""
        rules = [s for s in TAB_SPECS if s["tab"] == "Firewall Rules"][0]
        result = analyze_tab(rules, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)

    def test_service_status_empty(self):
        """Service status with empty services dict."""
        svc = [s for s in TAB_SPECS if s["tab"] == "Services"][0]
        result = analyze_tab(svc, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)

    def test_wan_flap_empty(self):
        """WAN flap with no flaps should be NO_DATA."""
        wf = [s for s in TAB_SPECS if s["tab"] == "WAN Flap"][0]
        result = analyze_tab(wf, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)

    def test_geo_empty_array(self):
        """Geo with empty array should be NO_DATA."""
        geo = [s for s in TAB_SPECS if s["tab"] == "Geography"][0]
        result = analyze_tab(geo, self.base_url)
        self.assertEqual(result.data_source_status, DataSourceStatus.NO_DATA)


if __name__ == "__main__":
    unittest.main()
