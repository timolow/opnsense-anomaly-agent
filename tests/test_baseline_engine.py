"""Tests for baseline_engine.py — traffic baseline learning engine."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from baseline_engine import (
    TrafficBaseline,
    BaselineEngine,
    MIN_EVENTS_FOR_BASELINE,
    HOURS_IN_DAY,
)


class TestTrafficBaseline:
    """Test TrafficBaseline dataclass."""

    def test_creation_defaults(self):
        bl = TrafficBaseline(rule="test_rule")
        assert bl.rule == "test_rule"
        assert bl.ip is None
        assert bl.hour is None
        assert bl.avg_events_per_hour == 0.0
        assert bl.sample_count == 0
        assert bl.protocol_distribution == {}
        assert bl.hourly_distribution == []

    def test_creation_with_values(self):
        bl = TrafficBaseline(
            rule="r1",
            ip="10.0.0.1",
            hour=14,
            avg_events_per_hour=50.0,
            std_events_per_hour=10.0,
            max_events_per_hour=100,
            sample_count=500,
        )
        assert bl.ip == "10.0.0.1"
        assert bl.hour == 14
        assert bl.avg_events_per_hour == 50.0
        assert bl.max_events_per_hour == 100

    def test_confidence_zero_samples(self):
        bl = TrafficBaseline(rule="r", sample_count=0)
        assert bl.confidence_score() == 0.0

    def test_confidence_below_min(self):
        bl = TrafficBaseline(rule="r", sample_count=5)
        assert bl.confidence_score() == 0.0

    def test_confidence_at_min(self):
        bl = TrafficBaseline(rule="r", sample_count=MIN_EVENTS_FOR_BASELINE)
        score = bl.confidence_score()
        assert score > 0.0
        assert score <= 1.0

    def test_confidence_high_samples(self):
        bl = TrafficBaseline(rule="r", sample_count=1000)
        assert bl.confidence_score() == pytest.approx(1.0)

    def test_confidence_increases_with_samples(self):
        bl1 = TrafficBaseline(rule="r", sample_count=50)
        bl2 = TrafficBaseline(rule="r", sample_count=500)
        assert bl2.confidence_score() > bl1.confidence_score()


class TestBaselineEngineInit:
    """Test BaselineEngine initialization."""

    def test_init_creates_empty_baselines(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        assert engine._baselines == {}

    def test_init_loads_existing_baselines(self):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_db.connect.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            (
                "rule1", None, None, 10.0, 2.0, 20, 0,
                '{"tcp": 0.8, "udp": 0.2}', 5, 3, 10,
                0.7, 0.3, '[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]',
                100, datetime.now(timezone.utc).isoformat(),
            )
        ]
        engine = BaselineEngine(mock_db)
        assert "rule1" in engine._baselines
        assert engine._baselines["rule1"].avg_events_per_hour == 10.0

    def test_init_db_error_graceful(self):
        mock_db = MagicMock()
        mock_db.connect.side_effect = Exception("DB error")
        # Should not raise
        engine = BaselineEngine(mock_db)
        assert engine._baselines == {}


class TestBaselineKey:
    """Test _make_baseline_key."""

    def test_rule_only(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        assert engine._make_baseline_key("rule1") == "rule1"

    def test_rule_and_ip(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        assert engine._make_baseline_key("rule1", "10.0.0.1") == "rule1:10.0.0.1"

    def test_rule_and_hour(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        assert engine._make_baseline_key("rule1", hour=14) == "rule1:hour:14"

    def test_rule_ip_and_hour(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        assert engine._make_baseline_key("rule1", "10.0.0.1", 14) == "rule1:10.0.0.1:14"


class TestLearnFromTrainingData:
    """Test learning baselines from training data."""

    def _make_event(self, rule="r1", hour=10, src_ip="1.2.3.4",
                    protocol="tcp", action="pass", dst_port=80, dst_ip="5.6.7.8"):
        dt = datetime(2026, 1, 1, hour, 0, 0, tzinfo=timezone.utc)
        return {
            "rule": rule,
            "timestamp": dt.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "action": action,
            "dst_port": dst_port,
        }

    def test_empty_events(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        count = engine.learn_from_training_data([])
        assert count == 0

    def test_below_min_events_no_baseline(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        events = [self._make_event(hour=i) for i in range(3)]
        count = engine.learn_from_training_data(events)
        assert count == 0

    def test_learns_rule_baseline(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        # Generate 20 events across different hours
        events = [self._make_event(hour=i % 24) for i in range(20)]
        count = engine.learn_from_training_data(events)
        assert count >= 1
        baseline = engine.get_baseline("r1")
        assert baseline is not None
        assert baseline.sample_count == 20

    def test_learns_ip_baseline(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        # Generate 15 events from same IP
        events = [self._make_event(src_ip="10.0.0.1", hour=i % 24) for i in range(15)]
        count = engine.learn_from_training_data(events)
        assert count >= 1
        ip_baseline = engine.get_baseline("r1", ip="10.0.0.1")
        assert ip_baseline is not None
        assert ip_baseline.ip == "10.0.0.1"

    def test_baseline_protocol_distribution(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        events = [
            self._make_event(protocol="tcp") for _ in range(8)
        ] + [
            self._make_event(protocol="udp") for _ in range(2)
        ]
        engine.learn_from_training_data(events)
        baseline = engine.get_baseline("r1")
        assert baseline is not None
        assert "tcp" in baseline.protocol_distribution
        assert baseline.protocol_distribution["tcp"] == pytest.approx(0.8)
        assert baseline.protocol_distribution["udp"] == pytest.approx(0.2)

    def test_baseline_hourly_distribution(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        # 2 events in hour 0, 8 in hour 1, rest spread
        events = [self._make_event(hour=0) for _ in range(2)]
        events += [self._make_event(hour=1) for _ in range(8)]
        events += [self._make_event(hour=2) for _ in range(10)]
        engine.learn_from_training_data(events)
        baseline = engine.get_baseline("r1")
        assert baseline is not None
        assert len(baseline.hourly_distribution) == 24
        assert baseline.hourly_distribution[0] == 2
        assert baseline.hourly_distribution[1] == 8
        assert baseline.hourly_distribution[2] == 10

    def test_std_dev_calculation(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        # All events in same hour -> high variance in hourly distribution
        events = [self._make_event(hour=0) for _ in range(20)]
        engine.learn_from_training_data(events)
        baseline = engine.get_baseline("r1")
        assert baseline is not None
        assert baseline.std_events_per_hour > 0


class TestGetAndUpdateBaseline:
    """Test get_baseline and update_baseline."""

    def _make_event(self):
        return {
            "rule": "r1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "tcp",
            "action": "pass",
        }

    def test_get_nonexistent_baseline(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        result = engine.get_baseline("nonexistent")
        assert result is None

    def test_update_creates_baseline(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        events = [self._make_event() for _ in range(15)]
        engine.update_baseline("new_rule", events)
        baseline = engine.get_baseline("new_rule")
        assert baseline is not None

    def test_update_existing_baseline(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        # First create a baseline
        events1 = [self._make_event() for _ in range(15)]
        engine.learn_from_training_data(events1)
        original_count = engine.get_baseline("r1").sample_count

        # Update with new events
        events2 = [self._make_event() for _ in range(5)]
        engine.update_baseline("r1", events2)

        baseline = engine.get_baseline("r1")
        assert baseline.sample_count == original_count + 5

    def test_std_dev_single_value(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        assert engine._std_dev([5.0]) == 0.0

    def test_std_dev_known_values(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().fetchall.return_value = []
        engine = BaselineEngine(mock_db)
        # Known population stddev for [2, 4, 4, 4, 5, 5, 7, 9]
        result = engine._std_dev([2, 4, 4, 4, 5, 5, 7, 9])
        assert result == pytest.approx(2.0, abs=0.1)


class TestSaveBaselines:
    """Test saving baselines to database."""

    def test_save_calls_db(self):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_db.connect.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []
        engine = BaselineEngine(mock_db)

        # Add a baseline manually
        engine._baselines["test"] = TrafficBaseline(
            rule="test",
            sample_count=50,
            avg_events_per_hour=10.0,
            last_updated=datetime.now(timezone.utc),
        )

        engine.save_baselines()
        mock_cursor.execute.assert_called()