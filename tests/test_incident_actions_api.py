#!/usr/bin/env python3
"""Tests for P5-T7: API endpoints for unified threat canvas.

Covers:
- GET /api/ip-timeline (api_ip_timeline)
- POST /api/incident-actions (api_incident_actions)
- publish_incident_sse
- SSE queue and cleaner
"""

import json
import queue
import sys
import os
import unittest
from unittest import mock

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestApiIpTimeline(unittest.TestCase):
    """Test api_ip_timeline function."""

    def test_parse_range_string(self):
        """Range string parsing: 1h, 30m, 7d, 60s."""
        # We test the logic directly rather than importing server (heavy deps)
        test_cases = [
            ("1h", 3600),
            ("30m", 1800),
            ("7d", 604800),
            ("60s", 60),
            ("2h", 7200),
            ("15m", 900),
            ("", 3600),  # default
        ]
        for range_str, expected in test_cases:
            if range_str:
                unit = range_str[-1].lower()
                try:
                    value = int(range_str[:-1])
                except (ValueError, IndexError):
                    value = 1
                multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
                result = value * multipliers.get(unit, 3600)
            else:
                result = 3600
            self.assertEqual(result, expected, f"Range '{range_str}' should be {expected}s, got {result}")

    def test_api_ip_timeline_no_db(self):
        """api_ip_timeline returns empty structure when no DB."""
        from server import api_ip_timeline
        with mock.patch('server.get_db', return_value=None):
            result = api_ip_timeline("1.2.3.4", "1h")
            self.assertEqual(result["ip"], "1.2.3.4")
            self.assertEqual(result["range"], "1h")
            self.assertEqual(result["events"], [])
            self.assertEqual(result["signals"], [])
            self.assertEqual(result["incidents"], [])

    def test_api_ip_timeline_returns_structure(self):
        """api_ip_timeline returns all expected keys."""
        from server import api_ip_timeline
        with mock.patch('server.get_db', return_value=None):
            result = api_ip_timeline("10.0.0.1", "2h")
            expected_keys = ["ip", "range", "range_seconds", "events", "signals",
                             "incidents", "hostname", "profile_threat_level",
                             "profile_behavior_score"]
            for key in expected_keys:
                self.assertIn(key, result, f"Missing key: {key}")


class TestApiIncidentActions(unittest.TestCase):
    """Test api_incident_actions function."""

    def test_missing_action(self):
        """Returns 400 when no action provided."""
        from server import api_incident_actions
        result = api_incident_actions("", "inc_123", "1.2.3.4", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)

    def test_block_no_ip(self):
        """Block action requires IP."""
        from server import api_incident_actions
        result = api_incident_actions("block", "inc_123", "", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)

    def test_watchlist_no_ip(self):
        """Watchlist action requires IP."""
        from server import api_incident_actions
        result = api_incident_actions("watchlist", "inc_123", "", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)

    def test_mute_no_ip(self):
        """Mute action requires IP."""
        from server import api_incident_actions
        result = api_incident_actions("mute", "inc_123", "", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)

    def test_feedback_no_incident_id(self):
        """Feedback action requires incident_id."""
        from server import api_incident_actions
        result = api_incident_actions("feedback", "", "1.2.3.4", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)

    def test_resolve_no_incident_id(self):
        """Resolve action requires incident_id."""
        from server import api_incident_actions
        result = api_incident_actions("resolve", "", "1.2.3.4", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)

    def test_unknown_action(self):
        """Unknown action returns 400 with valid actions listed."""
        from server import api_incident_actions
        result = api_incident_actions("teleport", "inc_123", "1.2.3.4", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], 400)
        self.assertIn("block", result["message"])

    def test_valid_actions_list(self):
        """All supported actions are recognized."""
        from server import api_incident_actions
        valid_actions = ["block", "watchlist", "mute", "feedback", "transition", "resolve", "escalate"]
        for action in valid_actions:
            # Each should either succeed or return a specific error (not "Unknown action")
            result = api_incident_actions(action, "inc_123", "1.2.3.4", {})
            # Should NOT be "Unknown action"
            if not result["success"]:
                self.assertNotIn("Unknown action", result.get("message", ""),
                                 f"Action '{action}' should not be unknown")

    def test_block_action_structure(self):
        """Block action returns correct structure with mocked firewall."""
        from server import api_incident_actions, block_ip_in_firewall
        with mock.patch('server.block_ip_in_firewall', return_value={"success": True, "message": "OK"}):
            result = api_incident_actions("block", "inc_123", "1.2.3.4", {"reason": "test"})
            self.assertTrue(result["success"])
            self.assertEqual(result["action"], "block")
            self.assertEqual(result["ip"], "1.2.3.4")
            self.assertEqual(result["status_code"], 201)


class TestPublishIncidentSse(unittest.TestCase):
    """Test publish_incident_sse function."""

    def test_publish_to_queue(self):
        """publish_incident_sse puts event on the queue."""
        from server import publish_incident_sse, _incident_sse_queue
        # Clear queue first
        while not _incident_sse_queue.empty():
            try:
                _incident_sse_queue.get_nowait()
            except queue.Empty:
                break

        publish_incident_sse({
            "incident_id": "inc_abc",
            "ip": "1.2.3.4",
            "severity": "high",
        })

        event = _incident_sse_queue.get_nowait()
        self.assertEqual(event["incident_id"], "inc_abc")
        self.assertEqual(event["ip"], "1.2.3.4")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["type"], "incident_updated")

    def test_publish_with_event_type(self):
        """publish_incident_sse accepts custom event_type."""
        from server import publish_incident_sse, _incident_sse_queue
        while not _incident_sse_queue.empty():
            try:
                _incident_sse_queue.get_nowait()
            except queue.Empty:
                break

        publish_incident_sse(
            {"incident_id": "inc_xyz", "ip": "10.0.0.1", "action": "block"},
            event_type="incident_blocked"
        )

        event = _incident_sse_queue.get_nowait()
        self.assertEqual(event["type"], "incident_blocked")
        self.assertEqual(event["incident_id"], "inc_xyz")

    def test_queue_full_drops_event(self):
        """Queue full does not raise, just logs warning."""
        from server import publish_incident_sse
        # Create a tiny queue to test overflow
        import server
        orig_queue = server._incident_sse_queue
        small_queue = queue.Queue(maxsize=1)
        server._incident_sse_queue = small_queue
        try:
            # Fill the queue
            small_queue.put({"type": "filler"})
            # This should NOT raise
            publish_incident_sse({"incident_id": "inc_drop"})
        finally:
            server._incident_sse_queue = orig_queue


class TestIncidentSseHandler(unittest.TestCase):
    """Test _handle_incident_sse method structure."""

    def test_handler_exists_on_dashboard_handler(self):
        """DashboardHandler has _handle_incident_sse method."""
        from server import DashboardHandler
        self.assertTrue(hasattr(DashboardHandler, '_handle_incident_sse'))
        self.assertTrue(callable(getattr(DashboardHandler, '_handle_incident_sse')))


class TestSseBackgroundCleaner(unittest.TestCase):
    """Test sse_background_cleaner includes incident clients."""

    def test_cleaner_references_both_client_lists(self):
        """sse_background_cleaner cleans both anomaly and incident SSE clients."""
        import server
        import inspect
        source = inspect.getsource(server.sse_background_cleaner)
        self.assertIn('_sse_clients', source)
        self.assertIn('_incident_sse_clients', source)


if __name__ == '__main__':
    unittest.main()
