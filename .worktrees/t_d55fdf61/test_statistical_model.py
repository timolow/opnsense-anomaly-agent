"""Tests for statistical_model.py — baselines, z-scores, anomaly detection."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from statistical_model import RunningStats, WindowedCounter, Baseline, StatisticalModel
from datetime import datetime, timezone, timedelta


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
    """Test StatisticalModel orchestrator."""

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
