"""Tests for statistical_model.py and its migration into UnifiedBehavioralEngine.

Tests cover:
- RunningStats (Welford's online algorithm)
- WindowedCounter (rate tracking)
- Baseline (z-score anomaly detection)
- StatisticalModel orchestrator
- UnifiedBehavioralEngine integration (global baselines, unique tracking,
  temporal anomalies, learn(), add_events(), get_stats())
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from statistical_model import RunningStats, WindowedCounter, Baseline, StatisticalModel
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock


class TestRunningStats:
    """Test RunningStats accumulator (Welford's algorithm)."""

    def test_creation_default(self):
        stats = RunningStats()
        assert stats.count == 0
        assert stats.mean == 0.0
        assert stats.stddev == 0.0

    def test_update_single_value(self):
        stats = RunningStats()
        stats.update(10.0)
        assert stats.count == 1
        assert stats.mean == pytest.approx(10.0)
        assert stats.stddev == pytest.approx(0.0)

    def test_update_multiple_values(self):
        stats = RunningStats()
        for v in [10, 20, 30]:
            stats.update(v)
        assert stats.count == 3
        assert stats.mean == pytest.approx(20.0)

    def test_update_same_value(self):
        stats = RunningStats()
        for _ in range(100):
            stats.update(50.0)
        assert stats.mean == pytest.approx(50.0)
        assert stats.stddev == pytest.approx(0.0)

    def test_update_multiple_values_correct_variance(self):
        stats = RunningStats()
        for v in [2, 4, 4, 4, 5, 5, 7, 9]:
            stats.update(float(v))
        assert stats.count == 8
        assert stats.mean == pytest.approx(5.0)

    def test_variance(self):
        stats = RunningStats()
        for v in [2, 4, 4, 4, 5, 5, 7, 9]:
            stats.update(float(v))
        var = stats.variance
        # sum((x-5)^2)/(n-1) = 32/7 = 4.571
        assert var == pytest.approx(4.571, abs=0.01)

    def test_count_increments(self):
        stats = RunningStats()
        for i in range(10):
            stats.update(float(i))
        assert stats.count == 10

    def test_empty_stats_safe(self):
        stats = RunningStats()
        assert stats.mean == 0.0
        assert stats.stddev == 0.0
        z = stats.z_score(0)
        assert z == pytest.approx(0.0)

    def test_latest_values(self):
        stats = RunningStats()
        for v in [1, 2, 3, 4, 5]:
            stats.update(v)
        values = stats.latest_values()
        assert len(values) == 5
        assert values[-1] == 5

    def test_latest_values_limited(self):
        stats = RunningStats()
        for v in [1, 2, 3, 4, 5]:
            stats.update(v)
        values = stats.latest_values(n=3)
        assert len(values) == 3
        assert values == [3, 4, 5]

    def test_z_score(self):
        stats = RunningStats()
        for v in [10, 20, 30, 40, 50]:
            stats.update(v)
        z = stats.z_score(30)
        assert z == pytest.approx(0.0)
        z = stats.z_score(60)
        assert z > 0

    def test_z_score_single_value(self):
        stats = RunningStats()
        stats.update(42.0)
        z = stats.z_score(42.0)
        assert z == pytest.approx(0.0)

    def test_z_score_zero_stdev(self):
        stats = RunningStats()
        for _ in range(3):
            stats.update(100.0)
        z = stats.z_score(100.0)
        assert z == pytest.approx(0.0)


class TestWindowedCounter:
    """Test WindowedCounter for rate tracking."""

    def test_init(self):
        wc = WindowedCounter(window_minutes=60)
        assert wc.get_rate('test') >= 0

    def test_record(self):
        wc = WindowedCounter(window_minutes=60)
        wc.record('test_key')
        assert wc.get_rate('test_key') >= 0

    def test_record_multiple(self):
        wc = WindowedCounter(window_minutes=60)
        for _ in range(10):
            wc.record('test_key')
        rate = wc.get_rate('test_key')
        assert rate > 0

    def test_get_rate(self):
        wc = WindowedCounter(window_minutes=60)
        wc.record('test_key')
        rate = wc.get_rate('test_key')
        assert rate >= 0

    def test_current_rate(self):
        wc = WindowedCounter(window_minutes=60)
        wc.record('test_key')
        rate = wc.get_current_rate('test_key')
        assert rate >= 0

    def test_record_different_keys(self):
        wc = WindowedCounter(window_minutes=60)
        wc.record('key1')
        wc.record('key2')
        rate1 = wc.get_rate('key1')
        rate2 = wc.get_rate('key2')
        assert rate1 >= 0
        assert rate2 >= 0


class TestBaseline:
    """Test Baseline dataclass."""

    def test_init(self):
        rs = RunningStats()
        for _ in range(35):
            rs.update(10.0)
        bl = Baseline(metric_name='test', running_stats=rs)
        assert bl.metric_name == 'test'
        assert bl.window_minutes == 60
        assert bl.anomaly_threshold == 3.0
        assert bl.min_samples == 30

    def test_is_anomalous_below_min_samples(self):
        rs = RunningStats()
        rs.update(10.0)
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=35)
        is_anom, z = bl.is_anomalous(10.0)
        assert is_anom is False

    def test_is_anomalous_normal(self):
        rs = RunningStats()
        for _ in range(35):
            rs.update(10.0)
        bl = Baseline(metric_name='test', running_stats=rs)
        is_anom, z = bl.is_anomalous(10.0)
        assert is_anom is False
        assert z == pytest.approx(0.0)

    def test_is_anomalous_high_value(self):
        rs = RunningStats()
        for _ in range(35):
            rs.update(10.0)
        # Add some variance
        for v in [8, 12, 9, 11, 7, 13]:
            rs.update(v)
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=10)
        is_anom, z = bl.is_anomalous(100.0)
        assert is_anom is True
        assert z > 3.0

    def test_is_anomalous_low_value(self):
        rs = RunningStats()
        for _ in range(35):
            rs.update(50.0)
        for v in [48, 52, 49, 51, 47, 53]:
            rs.update(v)
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=10)
        is_anom, z = bl.is_anomalous(-100.0)
        assert is_anom is True
        assert z < -3.0

    def test_deviation_score_below_min(self):
        rs = RunningStats()
        rs.update(10.0)
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=35)
        dev = bl.deviation_score(10.0)
        assert dev == pytest.approx(0.0)

    def test_deviation_score_mean(self):
        rs = RunningStats()
        for _ in range(35):
            rs.update(10.0)
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=10)
        dev = bl.deviation_score(10.0)
        assert dev == pytest.approx(0.0)

    def test_deviation_score_normal_range(self):
        rs = RunningStats()
        for _ in range(35):
            rs.update(10.0)
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=10)
        dev = bl.deviation_score(12.0)
        assert 0 <= dev <= 1.0

    def test_deviation_score_capped_at_1(self):
        rs = RunningStats()
        # Give some variance so z_score can be non-zero
        for _ in range(35):
            rs.update(10.0)
        for v in [5, 15, 25, -5, 35]:
            rs.update(float(v))
        bl = Baseline(metric_name='test', running_stats=rs, min_samples=10)
        dev = bl.deviation_score(1000.0)
        # With high variance, extreme value should give deviation close to 1
        assert 0 <= dev <= 1.0


class TestStatisticalModel:
    """Test StatisticalModel orchestrator (standalone module)."""

    def test_init(self):
        sm = StatisticalModel()
        assert sm.default_threshold == 3.0
        assert sm.min_samples == 30
        assert sm.window_minutes == 60

    def test_init_custom_params(self):
        sm = StatisticalModel(default_threshold=4.0, min_samples=20, window_minutes=30)
        assert sm.default_threshold == 4.0
        assert sm.min_samples == 20
        assert sm.window_minutes == 30

    def test_get_baseline_creates(self):
        sm = StatisticalModel()
        bl = sm.get_baseline('test_metric')
        assert bl.metric_name == 'test_metric'
        assert bl.anomaly_threshold == 3.0
        assert bl.min_samples == 30

    def test_get_baseline_reuses(self):
        sm = StatisticalModel()
        bl1 = sm.get_baseline('metric1')
        bl2 = sm.get_baseline('metric1')
        assert bl1 is bl2

    def test_get_baseline_missing(self):
        sm = StatisticalModel()
        bl = sm.get_baseline('missing')
        assert bl.metric_name == 'missing'
        assert bl.running_stats.count == 0

    def test_record_event(self):
        sm = StatisticalModel()
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'tcp_flags': 'SYN',
            'action': 'BLOCK', 'dport': 443
        }
        sm.record_event(event)

    def test_record_event_counts(self):
        sm = StatisticalModel()
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'tcp_flags': 'SYN',
            'action': 'BLOCK', 'dport': 443
        }
        for _ in range(10):
            sm.record_event(event)
        # Check that counts increased
        bl = sm.get_baseline('events_per_minute')
        assert bl.running_stats.count >= 10

    def test_record_tcp_event(self):
        sm = StatisticalModel()
        event = {'src_ip': '10.0.0.1', 'proto': 'TCP', 'action': 'PASS'}
        for _ in range(5):
            sm.record_event(event)
        bl = sm.get_baseline('packets_per_minute')
        assert bl.running_stats.count >= 5

    def test_record_udp_event(self):
        sm = StatisticalModel()
        event = {'src_ip': '10.0.0.1', 'proto': 'UDP', 'action': 'PASS'}
        for _ in range(5):
            sm.record_event(event)
        bl = sm.get_baseline('udp_per_minute')
        assert bl.running_stats.count >= 5

    def test_record_syn_event(self):
        sm = StatisticalModel()
        event = {'src_ip': '10.0.0.1', 'proto': 'TCP', 'tcp_flags': 'SYN', 'action': 'BLOCK'}
        for _ in range(5):
            sm.record_event(event)
        bl = sm.get_baseline('syn_per_minute')
        assert bl.running_stats.count >= 5

    def test_record_block_event(self):
        sm = StatisticalModel()
        event = {'src_ip': '10.0.0.1', 'proto': 'TCP', 'action': 'BLOCK'}
        for _ in range(5):
            sm.record_event(event)
        bl = sm.get_baseline('blocked_per_minute')
        assert bl.running_stats.count >= 5

    def test_record_icmp_event(self):
        sm = StatisticalModel()
        event = {'src_ip': '10.0.0.1', 'proto': 'ICMP', 'action': 'PASS'}
        for _ in range(5):
            sm.record_event(event)
        bl = sm.get_baseline('icmp_per_minute')
        assert bl.running_stats.count >= 5

    def test_update_per_minute_rates(self):
        sm = StatisticalModel()
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'tcp_flags': 'SYN',
            'action': 'BLOCK', 'dport': 443
        }
        for _ in range(10):
            sm.record_event(event)
        sm.update_per_minute_rates()

    def test_check_anomaly(self):
        sm = StatisticalModel(min_samples=5)
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'tcp_flags': 'SYN',
            'action': 'BLOCK', 'dport': 443
        }
        for _ in range(10):
            sm.record_event(event)
        # check_anomaly takes (value, metric)
        result = sm.check_anomaly(100.0, 'events_per_minute')
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_get_all_anomaly_checks(self):
        sm = StatisticalModel(min_samples=5)
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'tcp_flags': 'SYN',
            'action': 'BLOCK', 'dport': 443
        }
        for _ in range(10):
            sm.record_event(event)
        sm.update_per_minute_rates()
        # get_all_anomaly_checks takes Dict[str, float]
        checks = sm.get_all_anomaly_checks({})
        assert isinstance(checks, list)

    def test_add_event(self):
        sm = StatisticalModel()
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'action': 'PASS'
        }
        sm.add_event(event)
        bl = sm.get_baseline('events_per_minute')
        assert bl.running_stats.count >= 1

    def test_learn(self):
        sm = StatisticalModel(min_samples=5)
        event = {
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
            'proto': 'TCP', 'tcp_flags': 'SYN',
            'action': 'BLOCK', 'dport': 443
        }
        for _ in range(10):
            sm.record_event(event)
        # learn takes events list
        result = sm.learn([event])
        assert isinstance(result, dict)


# ============================================================
# UnifiedBehavioralEngine integration tests
# ============================================================

class TestUnifiedEngineRunningStats:
    """Test RunningStats migrated into UnifiedBehavioralEngine."""

    def test_unified_runningstats_creation(self):
        from unified_behavioral_engine import RunningStats
        stats = RunningStats()
        assert stats.count == 0
        assert stats.mean == 0.0
        assert stats.stddev == 0.0

    def test_unified_runningstats_welford(self):
        from unified_behavioral_engine import RunningStats
        stats = RunningStats()
        for v in [2, 4, 4, 4, 5, 5, 7, 9]:
            stats.update(float(v))
        assert stats.count == 8
        assert stats.mean == pytest.approx(5.0)
        var = stats.variance
        assert var == pytest.approx(4.571, abs=0.01)

    def test_unified_runningstats_zscore(self):
        from unified_behavioral_engine import RunningStats
        stats = RunningStats()
        for v in [10, 20, 30, 40, 50]:
            stats.update(v)
        z = stats.z_score(30)
        assert z == pytest.approx(0.0)
        z = stats.z_score(60)
        assert z > 0

    def test_unified_runningstats_empty_safe(self):
        from unified_behavioral_engine import RunningStats
        stats = RunningStats()
        assert stats.z_score(0) == pytest.approx(0.0)
        assert stats.stddev == 0.0


class TestUnifiedEngineGlobalBaselines:
    """Test global statistical baselines in UnifiedBehavioralEngine."""

    def _make_db(self):
        """Create a mock DB for engine initialization."""
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_engine_creates_global_baselines(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        assert "events_per_minute" in engine._global_baselines
        assert "syn_per_minute" in engine._global_baselines
        assert "blocked_per_minute" in engine._global_baselines
        assert "icmp_per_minute" in engine._global_baselines
        assert "udp_per_minute" in engine._global_baselines
        assert "packets_per_minute" in engine._global_baselines

    def test_engine_global_stats_update_on_ingest(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        event = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "proto": "TCP", "tcp_flags": "SYN",
            "action": "BLOCK", "dport": 443,
            "timestamp": datetime.now(timezone.utc),
        }
        for _ in range(10):
            engine.ingest_event(event)

        assert engine._global_baselines["events_per_minute"].count == 10
        assert engine._global_baselines["syn_per_minute"].count == 10
        assert engine._global_baselines["blocked_per_minute"].count == 10

    def test_engine_protocol_specific_stats(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())

        # UDP events
        for _ in range(5):
            engine.ingest_event({
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "proto": "UDP", "action": "PASS",
                "timestamp": datetime.now(timezone.utc),
            })
        assert engine._global_baselines["udp_per_minute"].count >= 5

        # ICMP events
        for _ in range(3):
            engine.ingest_event({
                "src_ip": "10.0.0.1", "proto": "ICMP", "action": "PASS",
                "timestamp": datetime.now(timezone.utc),
            })
        assert engine._global_baselines["icmp_per_minute"].count >= 3


class TestUnifiedEngineUniqueTracking:
    """Test unique IP/port tracking per minute in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_unique_tracking_on_ingest(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        now = datetime.now(timezone.utc)

        # Ingest events from different IPs
        for i in range(5):
            engine.ingest_event({
                "src_ip": f"10.0.0.{i}",
                "dst_ip": f"192.168.1.{i}",
                "proto": "TCP", "action": "PASS",
                "dport": 443 + i,
                "timestamp": now,
            })

        bucket = now.strftime("%Y-%m-%d %H:%M")
        assert len(engine._src_ips_per_min[bucket]) == 5
        assert len(engine._dst_ips_per_min[bucket]) == 5
        assert len(engine._ports_per_min[bucket]) == 5

    def test_unique_tracking_deduplicates(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        now = datetime.now(timezone.utc)

        # Same IP, same bucket
        for _ in range(10):
            engine.ingest_event({
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.1",
                "proto": "TCP", "action": "PASS",
                "dport": 443,
                "timestamp": now,
            })

        bucket = now.strftime("%Y-%m-%d %H:%M")
        assert len(engine._src_ips_per_min[bucket]) == 1
        assert len(engine._ports_per_min[bucket]) == 1


class TestUnifiedEngineBaselineSummary:
    """Test get_baseline_summary in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_baseline_summary_empty(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        summary = engine.get_baseline_summary()
        assert isinstance(summary, dict)
        # No data yet, so summary should be empty
        assert len(summary) == 0

    def test_baseline_summary_with_data(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        now = datetime.now(timezone.utc)

        for _ in range(10):
            engine.ingest_event({
                "src_ip": "10.0.0.1",
                "proto": "TCP", "action": "PASS",
                "timestamp": now,
            })

        summary = engine.get_baseline_summary()
        assert "events_per_minute" in summary
        assert summary["events_per_minute"]["count"] == 10
        assert "mean" in summary["events_per_minute"]
        assert "stddev" in summary["events_per_minute"]


class TestUnifiedEngineAnomalyChecks:
    """Test get_all_anomaly_checks in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_anomaly_checks_return_list(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        checks = engine.get_all_anomaly_checks({})
        assert isinstance(checks, list)

    def test_anomaly_detects_extreme_value(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())

        # Seed the baseline with values that have some variance
        stats = engine._global_baselines["events_per_minute"]
        for v in [1.0, 2.0, 1.0, 3.0, 1.0, 2.0, 1.0, 2.0, 1.0, 3.0] * 5:
            stats.update(v)

        # Check an extreme value (100.0 vs mean ~1.8)
        checks = engine.get_all_anomaly_checks({"events_per_minute": 100.0})
        assert len(checks) > 0
        assert checks[0]["metric"] == "events_per_minute"
        assert checks[0]["type"] == "STATISTICAL_ANOMALY"


class TestUnifiedEngineTemporalAnomalies:
    """Test _check_temporal_anomalies in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_temporal_anomaly_insufficient_data(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        anomalies = engine._check_temporal_anomalies()
        assert anomalies == []

    def test_temporal_anomaly_detects_spike(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())

        # Seed normal hours (hours 0-22 with ~100 events each)
        for hour in range(23):
            for _ in range(100):
                engine._hourly_counts[hour] += 1

        # Hour 23 gets a massive spike
        engine._hourly_counts[23] = 5000

        anomalies = engine._check_temporal_anomalies()
        # Should detect hour 23 as anomalous
        temporal_anomalies = [a for a in anomalies if a.get("hour") == 23]
        assert len(temporal_anomalies) > 0


class TestUnifiedEngineLearn:
    """Test learn() method in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_learn_returns_dict(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        events = [
            {
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "proto": "TCP", "action": "PASS",
                "timestamp": datetime.now(timezone.utc),
            }
            for _ in range(5)
        ]
        result = engine.learn(events)
        assert isinstance(result, dict)
        assert result["events_processed"] == 5
        assert result["events_learned"] == 5
        assert "baselines_count" in result
        assert "summary" in result

    def test_learn_increments_stats(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        events = [
            {
                "src_ip": "10.0.0.1", "proto": "TCP",
                "tcp_flags": "SYN", "action": "BLOCK",
                "timestamp": datetime.now(timezone.utc),
            }
            for _ in range(10)
        ]
        engine.learn(events)
        assert engine._total_ingested == 10


class TestUnifiedEngineAddEvents:
    """Test add_events() compatibility method."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_add_events_alias(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        events = [
            {
                "src_ip": "10.0.0.1", "proto": "TCP",
                "action": "PASS",
                "timestamp": datetime.now(timezone.utc),
            }
        ]
        engine.add_events(events)
        assert engine._total_ingested >= 1


class TestUnifiedEngineGetStats:
    """Test get_stats() in UnifiedBehavioralEngine with statistical fields."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_get_stats_includes_unique_ips(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        stats = engine.get_stats()
        assert "unique_ips" in stats
        assert "unique_ports" in stats
        assert "hourly_counts" in stats
        assert "global_baselines" in stats
        assert "total_ingested" in stats
        assert "total_signals" in stats

    def test_get_stats_includes_baselines(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        now = datetime.now(timezone.utc)
        for _ in range(5):
            engine.ingest_event({
                "src_ip": "10.0.0.1", "proto": "TCP",
                "action": "PASS", "timestamp": now,
            })
        stats = engine.get_stats()
        assert "events_per_minute" in stats["global_baselines"]

    def test_get_stats_total_profiles(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        assert engine.get_stats()["total_profiles"] == 0


class TestUnifiedEngineBucketKey:
    """Test _bucket_key helper in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_bucket_key_format(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        ts = datetime(2026, 6, 30, 14, 35, 42, tzinfo=timezone.utc)
        bucket = engine._bucket_key(ts)
        assert bucket == "2026-06-30 14:35"


class TestUnifiedEngineCurrentRatesSnapshot:
    """Test _current_rates_snapshot in UnifiedBehavioralEngine."""

    def _make_db(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        return db

    def test_rates_snapshot_returns_dict(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        rates = engine._current_rates_snapshot()
        assert isinstance(rates, dict)

    def test_rates_snapshot_includes_metrics(self):
        from unified_behavioral_engine import UnifiedBehavioralEngine
        engine = UnifiedBehavioralEngine(self._make_db())
        now = datetime.now(timezone.utc)
        for _ in range(5):
            engine.ingest_event({
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "proto": "TCP", "action": "PASS",
                "dport": 443, "timestamp": now,
            })
        rates = engine._current_rates_snapshot()
        # Should have unique_src, unique_dst, unique_ports from current bucket
        assert "unique_src_per_minute" in rates
        assert "unique_dst_per_minute" in rates
        assert "unique_dst_ports_per_minute" in rates
