#!/usr/bin/env python3
"""Tests for IP-level baselines migrated from baseline_engine.py into UnifiedBehavioralEngine.

Verifies that:
- IPBaseline dataclass is created with correct fields and defaults
- IPBaseline.confidence_score() behaves like TrafficBaseline.confidence_score()
- UnifiedBehavioralEngine.learn_ip_baselines_from_events() learns per-IP baselines
- UnifiedBehavioralEngine.get_ip_baseline() returns serialized baseline dicts
- UnifiedBehavioralEngine.update_ip_baseline() does incremental EMA updates
- UnifiedBehavioralEngine._save_ip_baselines() / _load_ip_baselines() persist correctly
- rule_baselines table is NOT used by the new IP baseline code (backward compat)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest
from unified_behavioral_engine import (
    UnifiedBehavioralEngine,
    IPBaseline,
    MIN_EVENTS_FOR_BASELINE,
    HOURS_IN_DAY,
    BASELINE_WINDOW_HOURS,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_events(ip, count, hour=12, proto="TCP", action="pass", dst_ports=None, dst_ips=None, bytes_val=1000):
    """Generate count events for the given IP at the given hour."""
    if dst_ports is None:
        dst_ports = list(range(1024, 1024 + count))
    if dst_ips is None:
        dst_ips = [f"10.0.{i // 256}.{i % 256}" for i in range(count)]
    events = []
    for i in range(count):
        ts = datetime(2024, 6, 1, hour, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=i)
        events.append({
            "src_ip": ip,
            "dst_ip": dst_ips[i % len(dst_ips)],
            "dport": dst_ports[i % len(dst_ports)],
            "proto": proto,
            "action": action,
            "ip_total_length": bytes_val,
            "timestamp": ts,
        })
    return events


class TestIPBaselineDataclass:
    """Test IPBaseline dataclass creation and confidence."""

    def test_creation_defaults(self):
        bl = IPBaseline(ip="10.0.0.1")
        assert bl.ip == "10.0.0.1"
        assert bl.hour is None
        assert bl.avg_events_per_hour == 0.0
        assert bl.std_events_per_hour == 0.0
        assert bl.sample_count == 0
        assert bl.protocol_distribution == {}
        assert bl.hourly_distribution == []
        assert bl.pass_ratio == 0.0
        assert bl.block_ratio == 0.0

    def test_creation_with_values(self):
        bl = IPBaseline(
            ip="10.0.0.1",
            avg_events_per_hour=50.0,
            avg_unique_dst_ports=25,
            avg_unique_dst_ips=10,
            avg_bytes_per_conn=2048,
            pass_ratio=0.8,
            block_ratio=0.2,
            sample_count=500,
        )
        assert bl.avg_unique_dst_ports == 25
        assert bl.avg_bytes_per_conn == 2048
        assert bl.pass_ratio == 0.8

    def test_confidence_zero_samples(self):
        bl = IPBaseline(ip="x", sample_count=0)
        assert bl.confidence_score() == 0.0

    def test_confidence_below_min(self):
        bl = IPBaseline(ip="x", sample_count=5)
        assert bl.confidence_score() == 0.0

    def test_confidence_at_min(self):
        bl = IPBaseline(ip="x", sample_count=MIN_EVENTS_FOR_BASELINE)
        assert 0.0 < bl.confidence_score() <= 1.0

    def test_confidence_high_samples(self):
        bl = IPBaseline(ip="x", sample_count=1000)
        assert bl.confidence_score() == pytest.approx(1.0)

    def test_confidence_increases_with_samples(self):
        assert IPBaseline(ip="x", sample_count=500).confidence_score() > IPBaseline(ip="x", sample_count=50).confidence_score()

    def test_to_dict_serializable(self):
        bl = IPBaseline(
            ip="10.0.0.1",
            avg_events_per_hour=25.5,
            sample_count=200,
            last_updated=datetime.now(timezone.utc),
            hourly_distribution=[0.0] * HOURS_IN_DAY,
        )
        d = bl.to_dict()
        assert isinstance(d, dict)
        assert d["ip"] == "10.0.0.1"
        assert d["sample_count"] == 200
        assert d["confidence"] > 0.0
        # Verify JSON round-trips
        json.loads(json.dumps(d))


class TestIPBaselineComputation:
    """Test _compute_ip_baseline() logic."""

    def _engine(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().execute.return_value.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            return UnifiedBehavioralEngine(mock_db)

    def test_returns_none_below_min_events(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", MIN_EVENTS_FOR_BASELINE - 1)
        result = engine._compute_ip_baseline("10.0.0.1", events)
        assert result is None

    def test_creates_baseline_at_min_events(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", MIN_EVENTS_FOR_BASELINE)
        result = engine._compute_ip_baseline("10.0.0.1", events)
        assert result is not None
        assert result.ip == "10.0.0.1"
        assert result.sample_count == MIN_EVENTS_FOR_BASELINE

    def test_hourly_distribution(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", 30, hour=14)
        result = engine._compute_ip_baseline("10.0.0.1", events)
        assert len(result.hourly_distribution) == HOURS_IN_DAY
        assert result.hourly_distribution[14] == 30.0
        assert result.hourly_distribution[0] == 0.0

    def test_protocol_distribution(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", 20, proto="UDP", action="block")
        result = engine._compute_ip_baseline("10.0.0.1", events)
        assert "UDP" in result.protocol_distribution
        assert result.protocol_distribution["UDP"] == pytest.approx(1.0)
        assert result.block_ratio == pytest.approx(1.0)
        assert result.pass_ratio == pytest.approx(0.0)

    def test_diversity_stats(self):
        engine = self._engine()
        # 20 events hitting 5 unique ports and 3 unique IPs
        dst_ports = [80, 443, 8080, 22, 3306]
        dst_ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        events = _make_events("10.0.0.1", 20, dst_ports=dst_ports, dst_ips=dst_ips)
        result = engine._compute_ip_baseline("10.0.0.1", events)
        assert result.avg_unique_dst_ports == 5
        assert result.avg_unique_dst_ips == 3

    def test_bytes_per_conn(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", 20, bytes_val=5000)
        result = engine._compute_ip_baseline("10.0.0.1", events)
        assert result.avg_bytes_per_conn == pytest.approx(5000.0)


class TestLearnIPBaselines:
    """Test learn_ip_baselines_from_events() with multiple IPs."""

    def _engine(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().execute.return_value.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            return UnifiedBehavioralEngine(mock_db)

    def test_learns_multiple_ips(self):
        engine = self._engine()
        events = (
            _make_events("10.0.0.1", 20) +
            _make_events("10.0.0.2", 20) +
            _make_events("10.0.0.3", 20)
        )
        with patch.object(engine, '_save_ip_baselines'):
            count = engine.learn_ip_baselines_from_events(events)
        assert count == 3

    def test_skips_ips_below_threshold(self):
        engine = self._engine()
        events = (
            _make_events("10.0.0.1", 20) +
            _make_events("10.0.0.2", 5)  # below MIN_EVENTS_FOR_BASELINE
        )
        with patch.object(engine, '_save_ip_baselines'):
            count = engine.learn_ip_baselines_from_events(events)
        assert count == 1
        assert "10.0.0.1" in engine._ip_baselines
        assert "10.0.0.2" not in engine._ip_baselines

    def test_empty_events(self):
        engine = self._engine()
        count = engine.learn_ip_baselines_from_events([])
        assert count == 0

    def test_no_src_ip_events(self):
        engine = self._engine()
        events = [{"timestamp": datetime.now(timezone.utc)}]
        count = engine.learn_ip_baselines_from_events(events)
        assert count == 0


class TestGetAndUpdateIPBaseline:
    """Test get_ip_baseline() and update_ip_baseline()."""

    def _engine(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().execute.return_value.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            return UnifiedBehavioralEngine(mock_db)

    def test_get_nonexistent(self):
        engine = self._engine()
        assert engine.get_ip_baseline("10.0.0.1") is None

    def test_get_after_learn(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", 20)
        with patch.object(engine, '_save_ip_baselines'):
            engine.learn_ip_baselines_from_events(events)
        result = engine.get_ip_baseline("10.0.0.1")
        assert result is not None
        assert result["ip"] == "10.0.0.1"
        assert result["sample_count"] == 20

    def test_update_creates_new(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", 20)
        with patch.object(engine, '_save_ip_baselines'):
            engine.update_ip_baseline("10.0.0.1", events)
        result = engine.get_ip_baseline("10.0.0.1")
        assert result is not None
        assert result["sample_count"] == 20

    def test_update_increments_existing(self):
        engine = self._engine()
        initial = _make_events("10.0.0.1", 20)
        with patch.object(engine, '_save_ip_baselines'):
            engine.update_ip_baseline("10.0.0.1", initial)
        assert engine.get_ip_baseline("10.0.0.1")["sample_count"] == 20

        # More events
        more = _make_events("10.0.0.1", 10)
        with patch.object(engine, '_save_ip_baselines'):
            engine.update_ip_baseline("10.0.0.1", more)
        assert engine.get_ip_baseline("10.0.0.1")["sample_count"] == 30

    def test_update_empty_noop(self):
        engine = self._engine()
        with patch.object(engine, '_save_ip_baselines'):
            engine.update_ip_baseline("10.0.0.1", [])
        assert engine.get_ip_baseline("10.0.0.1") is None

    def test_update_below_min_not_created(self):
        engine = self._engine()
        events = _make_events("10.0.0.1", 5)
        with patch.object(engine, '_save_ip_baselines'):
            engine.update_ip_baseline("10.0.0.1", events)
        # Below threshold, no baseline created from scratch
        assert engine.get_ip_baseline("10.0.0.1") is None


class TestIncrementalUpdate:
    """Test _incremental_ip_baseline_update() EMA blending."""

    def _engine(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().execute.return_value.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            return UnifiedBehavioralEngine(mock_db)

    def test_ema_sample_count_increases(self):
        engine = self._engine()
        bl = IPBaseline(ip="10.0.0.1", sample_count=100, hourly_distribution=[1.0] * HOURS_IN_DAY)
        new_events = _make_events("10.0.0.1", 10)
        updated = engine._incremental_ip_baseline_update(bl, new_events)
        assert updated.sample_count == 110

    def test_ema_pass_ratio_shifts(self):
        engine = self._engine()
        bl = IPBaseline(ip="10.0.0.1", sample_count=100, pass_ratio=1.0,
                         hourly_distribution=[1.0] * HOURS_IN_DAY)
        # New events are all blocks
        new_events = _make_events("10.0.0.1", 10, action="block")
        updated = engine._incremental_ip_baseline_update(bl, new_events)
        # Pass ratio should decrease (EMA blend)
        assert updated.pass_ratio < 1.0
        # Block ratio should increase from 0
        assert updated.block_ratio > 0.0

    def test_ema_diversity_updates(self):
        engine = self._engine()
        bl = IPBaseline(ip="10.0.0.1", sample_count=100,
                         avg_unique_dst_ports=5, avg_unique_dst_ips=3,
                         avg_bytes_per_conn=1000,
                         hourly_distribution=[1.0] * HOURS_IN_DAY)
        # New events have different ports and IPs
        new_events = _make_events("10.0.0.1", 10, dst_ports=[80], dst_ips=["1.1.1.1"], bytes_val=5000)
        updated = engine._incremental_ip_baseline_update(bl, new_events)
        # EMA blend: alpha = 10/110 = ~0.09
        # avg_unique_dst_ports: (1-0.09)*5 + 0.09*1 = 4.61
        assert updated.avg_unique_dst_ports < 5
        # bytes per conn: (1-0.09)*1000 + 0.09*5000 = 910 + 450 = 1360
        assert updated.avg_bytes_per_conn > 1000


class TestGetAllIPBaselines:
    """Test get_all_ip_baselines()."""

    def _engine(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().execute.return_value.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            return UnifiedBehavioralEngine(mock_db)

    def test_returns_all(self):
        engine = self._engine()
        all_events = _make_events("10.0.0.1", 20) + _make_events("10.0.0.2", 20)
        with patch.object(engine, '_save_ip_baselines'):
            engine.learn_ip_baselines_from_events(all_events)
        result = engine.get_all_ip_baselines()
        assert len(result) == 2
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        for bl in result.values():
            assert isinstance(bl, dict)
            assert "ip" in bl
            assert "sample_count" in bl


class TestIPBaselinePersistence:
    """Test _save_ip_baselines() and _load_ip_baselines() SQL."""

    def _engine(self):
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_db.connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cur
        mock_cur.fetchall.return_value = []
        return UnifiedBehavioralEngine(mock_db)

    def test_save_executes_upsert(self):
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_db.connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cur
        mock_cur.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            engine = UnifiedBehavioralEngine(mock_db)
        bl = IPBaseline(
            ip="10.0.0.1",
            avg_events_per_hour=25.0,
            sample_count=100,
            protocol_distribution={"TCP": 0.8, "UDP": 0.2},
            hourly_distribution=[1.0] * HOURS_IN_DAY,
            last_updated=datetime.now(timezone.utc),
        )
        engine._ip_baselines["10.0.0.1"] = bl
        engine._save_ip_baselines()

        # Verify execute was called with the right SQL pattern
        assert mock_cur.execute.called
        sql = mock_cur.execute.call_args[0][0]
        assert "ip_baselines" in sql.lower()
        assert "ON CONFLICT" in sql

    def test_load_from_db_rows(self):
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_db.connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cur
        now = datetime.now(timezone.utc)
        mock_cur.fetchall.return_value = [
            (
                "10.0.0.1", None, 25.0, 5.0, 30, 20,
                10.0, 5.0, 2048.0,
                json.dumps({"TCP": 0.9}), 0.8, 0.2,
                json.dumps([1.0] * HOURS_IN_DAY), 200, now,
            ),
        ]
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            engine = UnifiedBehavioralEngine(mock_db)
        # Re-call _load_ip_baselines which uses the mock
        engine._load_ip_baselines()
        assert "10.0.0.1" in engine._ip_baselines
        bl = engine._ip_baselines["10.0.0.1"]
        assert bl.avg_events_per_hour == 25.0
        assert bl.sample_count == 200
        assert "TCP" in bl.protocol_distribution

    def test_load_empty_does_not_crash(self):
        engine = self._engine()
        engine._load_ip_baselines()
        assert len(engine._ip_baselines) == 0


class TestIPBaselineNotRuleLevel:
    """Verify the new code is truly IP-level, not rule-level."""

    def _engine(self):
        mock_db = MagicMock()
        mock_db.connect().cursor().execute.return_value.fetchall.return_value = []
        with patch.object(UnifiedBehavioralEngine, '_load_ip_baselines', return_value=None):
            return UnifiedBehavioralEngine(mock_db)

    def test_baseline_keyed_by_ip_not_rule(self):
        """Same IP, different rules → single baseline."""
        engine = self._engine()
        events = []
        for rule in ["rule_A", "rule_B", "rule_C"]:
            for i in range(5):
                events.append({
                    "src_ip": "10.0.0.1",
                    "rule_name": rule,
                    "dport": 80,
                    "proto": "TCP",
                    "action": "pass",
                    "ip_total_length": 1000,
                    "timestamp": datetime(2024, 6, 1, 12, i, 0, tzinfo=timezone.utc),
                })
        with patch.object(engine, '_save_ip_baselines'):
            count = engine.learn_ip_baselines_from_events(events)
        assert count == 1
        assert "10.0.0.1" in engine._ip_baselines
        bl = engine._ip_baselines["10.0.0.1"]
        assert bl.sample_count == 15  # All 15 events, regardless of rule

    def test_multiple_ips_separate_baselines(self):
        """Different IPs → separate baselines."""
        engine = self._engine()
        events = _make_events("10.0.0.1", 15) + _make_events("10.0.0.2", 15)
        with patch.object(engine, '_save_ip_baselines'):
            count = engine.learn_ip_baselines_from_events(events)
        assert count == 2
        assert engine._ip_baselines["10.0.0.1"].ip == "10.0.0.1"
        assert engine._ip_baselines["10.0.0.2"].ip == "10.0.0.2"
