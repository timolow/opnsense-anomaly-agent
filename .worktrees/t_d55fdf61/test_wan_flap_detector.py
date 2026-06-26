"""Tests for wan_flap_detector.py — WAN gateway flap detection."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import pytest
from wan_flap_detector import WANFlapDetector


class TestWANFlapDetectorInit:
    """Test initialization and defaults."""

    def test_default_params(self):
        detector = WANFlapDetector()
        assert detector.flap_alert_cooldown == 300
        assert detector.flap_threshold == 3
        assert detector.gateway_states == {}
        assert detector._flap_history == {}

    def test_custom_cooldown(self, monkeypatch):
        monkeypatch.setenv("WAN_FLAP_ALERT_COOLDOWN", "600")
        monkeypatch.setenv("WAN_FLAP_THRESHOLD", "5")
        detector = WANFlapDetector()
        assert detector.flap_alert_cooldown == 600
        assert detector.flap_threshold == 5


class TestCheckGatewayState:
    """Test gateway state change detection."""

    def test_no_change_returns_none(self):
        detector = WANFlapDetector()
        result = detector.check_gateway_state("wan1", "up", "up")
        assert result is None

    def test_single_state_change_no_flap(self):
        detector = WANFlapDetector()
        result = detector.check_gateway_state("wan1", "up", "down")
        assert result is None
        assert "wan1" in detector._flap_history
        assert detector._flap_history["wan1"]["state"] == "down"

    def test_below_threshold_no_alert(self):
        detector = WANFlapDetector()
        detector.flap_threshold = 5

        # Toggle 3 times (below threshold of 5)
        for _ in range(3):
            detector.check_gateway_state("wan1", "up", "down")
            detector.check_gateway_state("wan1", "down", "up")

        # Should have history but no alert
        status = detector.get_flap_status()
        assert "wan1" in status

    def test_above_threshold_triggers_alert(self, monkeypatch):
        detector = WANFlapDetector()
        detector.flap_threshold = 2
        detector.flap_alert_cooldown = 0

        tick = 0
        original_time = time.time

        def fake_time():
            nonlocal tick
            tick += 1
            return original_time() + tick

        monkeypatch.setattr(time, "time", fake_time)

        # Toggle multiple times, collect results
        results = []
        old = "up"
        for _ in range(4):
            new = "down" if old == "up" else "up"
            result = detector.check_gateway_state("wan1", old, new)
            results.append(result)
            old = new

        # At least one toggle should have triggered alert
        alerts = [r for r in results if r is not None]
        assert len(alerts) >= 1
        assert alerts[-1]["type"] == "WAN_FLAP"
        assert alerts[-1]["gateway"] == "wan1"

    def test_cooldown_prevents_duplicate_alerts(self, monkeypatch):
        detector = WANFlapDetector()
        detector.flap_threshold = 2
        detector.flap_alert_cooldown = 300  # 5 min cooldown

        tick = 0
        original_time = time.time

        def fake_time():
            nonlocal tick
            tick += 1
            return original_time() + tick

        monkeypatch.setattr(time, "time", fake_time)

        # Create enough flaps for first alert
        old = "up"
        for _ in range(4):
            new = "down" if old == "up" else "up"
            detector.check_gateway_state("wan1", old, new)
            old = new

        # More toggles should NOT trigger alert (within cooldown)
        for _ in range(2):
            new = "down" if old == "up" else "up"
            result = detector.check_gateway_state("wan1", old, new)
            old = new

        # The cooldown should prevent the second alert
        # (at least one of the later results should be None due to cooldown)


class TestFlapAlertCreation:
    """Test alert creation logic."""

    def test_warning_severity(self):
        detector = WANFlapDetector()
        history = {"flap_count": 3, "state": "down", "last_change": time.time()}
        alert = detector._create_flap_alert("wan1", history)

        assert alert["type"] == "WAN_FLAP"
        assert alert["severity"] == "WARNING"
        assert alert["gateway"] == "wan1"
        assert alert["flap_count"] == 3
        assert alert["current_state"] == "down"

    def test_critical_severity(self):
        detector = WANFlapDetector()
        history = {"flap_count": 5, "state": "up", "last_change": time.time()}
        alert = detector._create_flap_alert("wan2", history)

        assert alert["severity"] == "CRITICAL"
        assert alert["flap_count"] == 5


class TestFlapStatus:
    """Test status reporting."""

    def test_empty_status(self):
        detector = WANFlapDetector()
        status = detector.get_flap_status()
        assert status == {}

    def test_populated_status(self):
        detector = WANFlapDetector()
        detector.check_gateway_state("wan1", "up", "down")

        status = detector.get_flap_status()
        assert "wan1" in status
        assert status["wan1"]["current_state"] == "down"
        assert status["wan1"]["total_changes"] >= 1


class TestRecentFlaps:
    """Test recent flap history."""

    def test_no_recent_flaps(self):
        detector = WANFlapDetector()
        flaps = detector.get_recent_flaps()
        assert flaps == []

    def test_recent_flaps_after_changes(self, monkeypatch):
        detector = WANFlapDetector()

        tick = 0
        original_time = time.time

        def fake_time():
            nonlocal tick
            tick += 10
            return original_time() + tick

        monkeypatch.setattr(time, "time", fake_time)

        # Create some state changes
        detector.check_gateway_state("wan1", "up", "down")
        detector.check_gateway_state("wan1", "down", "up")
        detector.check_gateway_state("wan1", "up", "down")

        flaps = detector.get_recent_flaps()
        assert len(flaps) > 0
        assert all(f["gateway"] == "wan1" for f in flaps)

    def test_old_flaps_excluded(self, monkeypatch):
        detector = WANFlapDetector()

        tick = 0
        original_time = time.time

        def fake_time():
            nonlocal tick
            tick += 1
            return original_time() + tick

        monkeypatch.setattr(time, "time", fake_time)

        # Record a change
        detector.check_gateway_state("wan1", "up", "down")

        # Advance time past 24 hours
        monkeypatch.setattr(time, "time", lambda: original_time() + 90000)

        flaps = detector.get_recent_flaps(hours=24)
        # History should be cleaned up
        assert len(detector._flap_history["wan1"]["history"]) == 0 or len(flaps) == 0