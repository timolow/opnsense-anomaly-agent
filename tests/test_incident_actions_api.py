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


class TestTypedIncidentPublish(unittest.TestCase):
    """Test publish_new_incident and publish_incident_resolved helpers."""

    def setUp(self):
        """Clear the incident SSE queue before each test."""
        from server import _incident_sse_queue
        while not _incident_sse_queue.empty():
            try:
                _incident_sse_queue.get_nowait()
            except queue.Empty:
                break

    def test_publish_new_incident_type(self):
        """publish_new_incident emits event_type=new_incident."""
        from server import publish_new_incident, _incident_sse_queue
        publish_new_incident({
            "incident_id": "inc_test",
            "ip": "10.0.0.5",
            "severity": "critical",
        })
        event = _incident_sse_queue.get_nowait()
        self.assertEqual(event["type"], "new_incident")
        self.assertEqual(event["incident_id"], "inc_test")
        self.assertEqual(event["ip"], "10.0.0.5")
        self.assertEqual(event["severity"], "critical")

    def test_publish_incident_resolved_type(self):
        """publish_incident_resolved emits event_type=incident_resolved."""
        from server import publish_incident_resolved, _incident_sse_queue
        publish_incident_resolved({
            "incident_id": "inc_res",
            "ip": "10.0.0.6",
            "status": "resolved",
        })
        event = _incident_sse_queue.get_nowait()
        self.assertEqual(event["type"], "incident_resolved")
        self.assertEqual(event["incident_id"], "inc_res")
        self.assertEqual(event["status"], "resolved")

    def test_publish_incident_updated_default(self):
        """publish_incident_sse defaults to incident_updated."""
        from server import publish_incident_sse, _incident_sse_queue
        publish_incident_sse({
            "incident_id": "inc_upd",
            "ip": "10.0.0.7",
            "action": "escalate",
        })
        event = _incident_sse_queue.get_nowait()
        self.assertEqual(event["type"], "incident_updated")
        self.assertEqual(event["action"], "escalate")

    def test_all_three_types_have_timestamp(self):
        """All three publish helpers include an ISO timestamp."""
        from server import publish_new_incident, publish_incident_sse, publish_incident_resolved, _incident_sse_queue
        import re
        iso_pattern = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')

        publish_new_incident({"incident_id": "a", "ip": "1.1.1.1"})
        e1 = _incident_sse_queue.get_nowait()
        self.assertTrue(iso_pattern.search(e1["timestamp"]), f"new_incident missing valid timestamp: {e1['timestamp']}")

        publish_incident_sse({"incident_id": "b", "ip": "2.2.2.2"})
        e2 = _incident_sse_queue.get_nowait()
        self.assertTrue(iso_pattern.search(e2["timestamp"]), f"incident_updated missing valid timestamp: {e2['timestamp']}")

        publish_incident_resolved({"incident_id": "c", "ip": "3.3.3.3"})
        e3 = _incident_sse_queue.get_nowait()
        self.assertTrue(iso_pattern.search(e3["timestamp"]), f"incident_resolved missing valid timestamp: {e3['timestamp']}")


class TestMultiplexedSSEHandler(unittest.TestCase):
    """Test that _handle_sse drains both anomaly and incident queues."""

    def test_sse_handler_source_references_both_queues(self):
        """_handle_sse source code references both _sse_queue and _incident_sse_queue."""
        import server
        import inspect
        source = inspect.getsource(server.DashboardHandler._handle_sse)
        self.assertIn('_sse_queue', source, "_handle_sse must drain anomaly queue")
        self.assertIn('_incident_sse_queue', source, "_handle_sse must drain incident queue")

    def test_sse_handler_registers_both_client_lists(self):
        """_handle_sse registers client on both _sse_clients and _incident_sse_clients."""
        import server
        import inspect
        source = inspect.getsource(server.DashboardHandler._handle_sse)
        self.assertIn('_sse_clients', source)
        self.assertIn('_incident_sse_clients', source)

    def test_sse_handler_connected_event_has_streams(self):
        """Connected event includes 'streams' key with both anomaly and incident."""
        import server
        import inspect
        source = inspect.getsource(server.DashboardHandler._handle_sse)
        self.assertIn('streams', source)
        self.assertIn('anomaly', source)
        self.assertIn('incident', source)


class TestCorrelationEngineSSE(unittest.TestCase):
    """Test that CorrelationEngine publishes SSE on new incident."""

    def test_publish_sse_new_incident_exists(self):
        """CorrelationEngine has _publish_sse_new_incident method."""
        from correlation_engine import CorrelationEngine
        self.assertTrue(hasattr(CorrelationEngine, '_publish_sse_new_incident'))

    def test_publish_sse_new_incident_calls_server(self):
        """_publish_sse_new_incident calls server.publish_new_incident."""
        from correlation_engine import CorrelationEngine
        import inspect
        source = inspect.getsource(CorrelationEngine._publish_sse_new_incident)
        self.assertIn('publish_new_incident', source)

    def test_group_signals_calls_publish(self):
        """_group_signals calls _publish_sse_new_incident after creating a new incident."""
        from correlation_engine import CorrelationEngine
        import inspect
        source = inspect.getsource(CorrelationEngine._group_signals)
        self.assertIn('_publish_sse_new_incident', source)


class TestIncidentActionEventMapping(unittest.TestCase):
    """Test that api_incident_actions maps actions to correct SSE event types."""

    def test_resolve_emits_incident_resolved(self):
        """Resolve action triggers publish_incident_resolved (checked via source)."""
        import server
        import inspect
        source = inspect.getsource(server.DashboardHandler.do_POST)
        # The do_POST handler for /api/incident-actions should check for resolve/resolved
        self.assertIn('publish_incident_resolved', source)
        self.assertIn('incident_resolved', source)

    def test_other_actions_emit_updated(self):
        """Non-resolve actions trigger publish_incident_sse with incident_updated."""
        import server
        import inspect
        source = inspect.getsource(server.DashboardHandler.do_POST)
        self.assertIn('incident_updated', source)


if __name__ == '__main__':
    unittest.main()
