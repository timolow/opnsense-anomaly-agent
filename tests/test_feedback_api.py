"""P6-T2: Tests for IP-level feedback API endpoints."""
import os
import sys
import unittest
from datetime import datetime as _dt, timezone as _tz
from importlib.util import find_spec
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# server.py imports psycopg2 at the top level — skip if unavailable
psycopg2_available = find_spec("psycopg2") is not None


@unittest.skipUnless(psycopg2_available, "psycopg2 not installed (Docker-only dep)")
class TestApiIpFeedback(unittest.TestCase):
    """Test POST /api/incident-feedback API function."""

    @patch("server._get_behavioral_engine")
    def test_attack_feedback(self, mock_get_engine):
        mock_engine = MagicMock()
        mock_get_engine.return_value = mock_engine

        from server import api_ip_feedback

        result = api_ip_feedback({
            "ip": "10.0.0.1",
            "label": "attack",
            "signal_types": ["port_scan", "syn_flood"],
            "notes": "confirmed attacker",
        })

        payload, status_code = result
        self.assertEqual(status_code, 201)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["ip"], "10.0.0.1")
        mock_engine.record_true_positive.assert_called_once_with(
            "10.0.0.1", ["port_scan", "syn_flood"], notes="confirmed attacker"
        )

    @patch("server._get_behavioral_engine")
    def test_benign_feedback(self, mock_get_engine):
        mock_engine = MagicMock()
        mock_get_engine.return_value = mock_engine

        from server import api_ip_feedback

        result = api_ip_feedback({
            "ip": "10.0.0.2",
            "label": "benign",
            "signal_types": [],
        })

        payload, status_code = result
        self.assertEqual(status_code, 201)
        self.assertTrue(payload["success"])
        mock_engine.record_false_positive.assert_called_once_with(
            "10.0.0.2", None, notes=None
        )

    @patch("server._get_behavioral_engine")
    def test_attack_feedback_no_signal_types(self, mock_get_engine):
        mock_engine = MagicMock()
        mock_get_engine.return_value = mock_engine

        from server import api_ip_feedback

        result = api_ip_feedback({
            "ip": "10.0.0.3",
            "label": "ATTACK",
        })

        payload, status_code = result
        self.assertEqual(status_code, 201)
        mock_engine.record_true_positive.assert_called_once_with(
            "10.0.0.3", None, notes=None
        )

    def test_missing_ip_returns_400(self):
        from server import api_ip_feedback

        result = api_ip_feedback({"label": "attack"})
        payload, status_code = result
        self.assertEqual(status_code, 400)
        self.assertFalse(payload["success"])

    def test_invalid_label_returns_400(self):
        from server import api_ip_feedback

        result = api_ip_feedback({"ip": "10.0.0.1", "label": "invalid"})
        payload, status_code = result
        self.assertEqual(status_code, 400)
        self.assertFalse(payload["success"])

    @patch("server._get_behavioral_engine")
    def test_engine_none_returns_503(self, mock_get_engine):
        mock_get_engine.return_value = None

        from server import api_ip_feedback

        result = api_ip_feedback({
            "ip": "10.0.0.1",
            "label": "attack",
        })

        payload, status_code = result
        self.assertEqual(status_code, 503)
        self.assertFalse(payload["success"])


@unittest.skipUnless(psycopg2_available, "psycopg2 not installed (Docker-only dep)")
class TestApiFeedbackHistory(unittest.TestCase):
    """Test GET /api/feedback-history API function."""

    @patch("server.get_db")
    def test_feedback_history_no_ip(self, mock_get_db):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_get_db.return_value = mock_conn

        from server import api_feedback_history

        mock_cur.fetchall.return_value = [{
            "id": 1, "incident_id": 10, "ip": "10.0.0.1",
            "feedback_type": "true_positive", "confidence": 1.0,
            "timestamp": _dt(2026, 6, 30, 12, 0, 0, tzinfo=_tz.utc),
            "notes": "test", "severity": "high",
            "signal_types": ["port_scan"], "signal_count": 1,
        }]

        result = api_feedback_history()
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["feedback"][0]["ip"], "10.0.0.1")
        mock_cur.execute.assert_called_once()
        # Verify LIMIT parameter
        call_args = mock_cur.execute.call_args
        self.assertEqual(call_args[0][1], (50,))

    @patch("server.get_db")
    def test_feedback_history_with_ip(self, mock_get_db):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_cur.fetchall.return_value = []
        mock_get_db.return_value = mock_conn

        from server import api_feedback_history

        result = api_feedback_history(ip="10.0.0.1", limit=10)
        self.assertEqual(result["count"], 0)
        call_args = mock_cur.execute.call_args
        # IP-filtered query uses (ip, limit) params
        self.assertEqual(call_args[0][1], ("10.0.0.1", 10))

    @patch("server.get_db")
    def test_feedback_history_no_db(self, mock_get_db):
        mock_get_db.return_value = None

        from server import api_feedback_history

        result = api_feedback_history()
        self.assertIn("error", result)
        self.assertEqual(result["count"], 0)


if __name__ == "__main__":
    unittest.main()
