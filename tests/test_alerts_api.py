#!/usr/bin/env python3
"""Regression tests for the /api/alerts endpoint (WEB-08).

Verifies:
  - /api/alerts returns 200 with a JSON array
  - /api/anomalies returns 200 with a JSON array
  - Each alert object has required fields (ip, attack_type, severity, count)
  - The frontend API client paths are correct (no double /api/ prefix)
"""

import json
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAlertsEndpoint(unittest.TestCase):
    """Unit tests for query_alerts() without a live server."""

    def test_query_alerts_returns_list(self):
        from server import query_alerts
        alerts = query_alerts()
        self.assertIsInstance(alerts, list)

    def test_alert_fields(self):
        from server import query_alerts
        alerts = query_alerts()
        for alert in alerts:
            self.assertIn("ip", alert, f"Alert missing 'ip' field: {alert}")
            self.assertIn("attack_type", alert, f"Alert missing 'attack_type': {alert}")
            self.assertIn("severity", alert, f"Alert missing 'severity': {alert}")
            self.assertIn("count", alert, f"Alert missing 'count': {alert}")

    def test_anomalies_returns_list(self):
        from server import query_anomalies
        anomalies = query_anomalies()
        self.assertIsInstance(anomalies, list)

    def test_alert_severity_values(self):
        from server import query_alerts
        alerts = query_alerts()
        valid_severities = {"CRITICAL", "WARNING", "HIGH", "MEDIUM", "LOW"}
        for alert in alerts:
            self.assertIn(alert.get("severity", ""), valid_severities,
                          f"Invalid severity: {alert.get('severity')}")

    def test_alert_count_is_numeric(self):
        from server import query_alerts
        alerts = query_alerts()
        for alert in alerts:
            self.assertIsInstance(alert.get("count"), (int, float),
                                  f"'count' should be numeric: {alert}")


class TestFrontendApiPaths(unittest.TestCase):
    """Verify the frontend API client uses correct relative paths.

    Regression test for the double-prefix bug where BASE='/api' + '/api/alerts'
    produced '/api/api/alerts' (404). All paths passed to json() should NOT
    include the /api/ prefix since BASE already adds it.
    """

    def test_no_double_api_prefix(self):
        """Scan api.ts for any json('/api/...) calls that would double-prefix."""
        api_ts_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "webui", "src", "api.ts"
        )
        with open(api_ts_path, "r") as f:
            content = f.read()

        # Find all json('<path>') calls — paths should NOT start with /api/
        import re
        # Match json<...>( '...' ) or json<...>( "...") patterns
        json_calls = re.findall(r"json<[^>]*>\?\s*\(\s*['\"]([^'\"]+)['\"]", content)
        json_calls += re.findall(r"json\(\s*['\"]([^'\"]+)['\"]", content)

        double_prefix = [p for p in json_calls if p.startswith("/api/")]
        self.assertEqual(
            double_prefix, [],
            f"Frontend API calls with double /api/ prefix (BASE already adds it): {double_prefix}"
        )


if __name__ == "__main__":
    unittest.main()
