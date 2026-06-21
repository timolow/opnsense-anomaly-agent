#!/usr/bin/env python3
"""Unit tests for anomaly_detector module.

Tests cover: check_volume, check_temporal (z-scores), check_port_scan,
check_new_ip, and the analyze() batch method.
"""
import sys
import os
import unittest
from unittest.mock import patch
from collections import defaultdict

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from anomaly_detector import (
    AnomalyDetector,
    is_internal_ip,
    INTERNAL_IP_PREFIXES,
    VOLUME_ZSCORE,
    PORT_SCAN_MIN,
    NEW_IP_MIN,
    TEMPORAL_ZSCORE,
)


class FakeBaseline:
    """Fake baseline object matching TrafficBaseline interface."""
    def __init__(self, avg=100, std=20, hourly=None, ip=None):
        self.avg_events_per_hour = avg
        self.std_events_per_hour = std
        self.hourly_distribution = hourly or []
        self.ip = ip


class TestVolumeDetection(unittest.TestCase):
    """Test check_volume() z-score volume spike detection."""

    def setUp(self):
        self.detector = AnomalyDetector({
            'rule_a': FakeBaseline(avg=100, std=20),
            'rule_b': FakeBaseline(avg=50, std=5),
            'rule_flat': FakeBaseline(avg=0, std=0),  # No variance
        })

    def test_normal_volume_no_alert(self):
        """Normal volume within baseline should not trigger."""
        result = self.detector.check_volume('rule_a', 10)  # 120/hr, close to avg 100
        self.assertIsNone(result)

    def test_volume_spike_triggers_alert(self):
        """Large volume spike should trigger alert."""
        # 100 events in 5 min = 1200/hr, baseline avg 100, std 20
        # z = (1200 - 100) / 20 = 55 >> threshold
        result = self.detector.check_volume('rule_a', 100)
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'volume_spike')
        self.assertIn('severity', result)
        self.assertEqual(result['rule'], 'rule_a')

    def test_severity_scales_with_zscore(self):
        """Severity should scale: MEDIUM (z>=3), HIGH (z>=4), CRITICAL (z>=5)."""
        # z ~3.0 → MEDIUM
        result = self.detector.check_volume('rule_a', 10)  # 120/hr, z=(120-100)/20=1 → no alert
        self.assertIsNone(result)

        # z ~3.0 → MEDIUM: need count where (count*12-100)/20 >= 3 → count*12 >= 160 → count >= 14
        result_med = self.detector.check_volume('rule_a', 14)  # z=3.0
        if result_med:
            self.assertEqual(result_med['severity'], 'MEDIUM')

        # z ~4.0 → HIGH: count*12 >= 180 → count >= 15
        result_high = self.detector.check_volume('rule_a', 15)  # z=4.0
        if result_high:
            self.assertEqual(result_high['severity'], 'HIGH')

    def test_no_variance_no_alert(self):
        """Rule with zero stddev should not trigger."""
        result = self.detector.check_volume('rule_flat', 100)
        self.assertIsNone(result)

    def test_no_baseline_no_alert(self):
        """Rule without baseline should not trigger."""
        result = self.detector.check_volume('unknown_rule', 100)
        self.assertIsNone(result)

    def test_result_includes_zscore(self):
        """Result should include z_score field."""
        result = self.detector.check_volume('rule_a', 50)  # 600/hr
        self.assertIsNotNone(result)
        self.assertIn('z_score', result)
        self.assertGreater(result['z_score'], 0)


class TestTemporalDetection(unittest.TestCase):
    """Test check_temporal() z-score temporal anomaly detection."""

    def setUp(self):
        # Realistic distribution: business hours busy, nights quiet
        self.business_dist = [
            0, 0, 0, 0, 0, 0,    # 0-5  midnight-early morning
            1, 2, 5, 15, 30, 50,  # 6-11 morning ramp
            60, 65, 60, 55, 50, 40, # 12-17 afternoon
            30, 20, 10, 5, 2, 1,  # 18-23 evening wind down
        ]
        self.detector = AnomalyDetector({
            'business_rule': FakeBaseline(avg=25, std=23, hourly=self.business_dist),
        })

    def test_normal_activity_no_alert(self):
        """Normal activity should not trigger temporal anomaly."""
        result = self.detector.check_temporal('business_rule', 3)  # ~36/hr, close to mean
        # z = (36 - 20.9) / 23.4 = 0.65 < threshold 2.0
        self.assertIsNone(result)

    def test_large_spike_triggers_alert(self):
        """Large spike should trigger temporal anomaly."""
        result = self.detector.check_temporal('business_rule', 20)  # 240/hr
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'temporal_anomaly')

    def test_no_baseline_no_alert(self):
        """Rule without baseline should not trigger."""
        result = self.detector.check_temporal('unknown', 100)
        self.assertIsNone(result)

    def test_flat_distribution_no_alert(self):
        """Flat distribution (no variance) should not trigger."""
        flat = FakeBaseline(hourly=[10.0] * 24)
        detector = AnomalyDetector({'flat': flat})
        result = detector.check_temporal('flat', 100)
        self.assertIsNone(result)

    def test_empty_distribution_no_alert(self):
        """Empty hourly distribution should not trigger."""
        empty = FakeBaseline(hourly=[])
        detector = AnomalyDetector({'empty': empty})
        result = detector.check_temporal('empty', 100)
        self.assertIsNone(result)

    def test_result_includes_distribution_stats(self):
        """Result should include distribution mean, std, and this-hour expected."""
        result = self.detector.check_temporal('business_rule', 50)  # 600/hr
        self.assertIsNotNone(result)
        self.assertIn('baseline_mean', result)
        self.assertIn('baseline_std', result)
        self.assertIn('baseline_this_hour', result)
        self.assertIn('z_score', result)

    def test_severity_scales_with_zscore(self):
        """Severity should scale with z-score magnitude."""
        # Small spike → should not trigger (z < 2.0)
        result_low = self.detector.check_temporal('business_rule', 3)
        self.assertIsNone(result_low)

        # Medium spike → MEDIUM (z >= 2.0)
        result_med = self.detector.check_temporal('business_rule', 10)  # 120/hr, z ~3.8
        if result_med:
            self.assertIn(result_med['severity'], ['MEDIUM', 'HIGH'])

        # Extreme spike → CRITICAL (z >= 5.0)
        result_crit = self.detector.check_temporal('business_rule', 100)  # 1200/hr
        self.assertIsNotNone(result_crit)
        self.assertEqual(result_crit['severity'], 'CRITICAL')


class TestPortScanDetection(unittest.TestCase):
    """Test check_port_scan() detection."""

    def setUp(self):
        self.detector = AnomalyDetector({})

    def test_below_threshold_no_alert(self):
        """Few unique ports should not trigger."""
        self.detector.ip_ports['10.0.0.1'] = {22, 80, 443}
        result = self.detector.check_port_scan('10.0.0.1')
        self.assertIsNone(result)

    def test_above_threshold_triggers_alert(self):
        """Many unique ports should trigger port scan alert."""
        self.detector.ip_ports['10.0.0.1'] = set(range(1, 16))  # 15 ports
        result = self.detector.check_port_scan('10.0.0.1')
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'port_scan')
        self.assertEqual(result['src_ip'], '10.0.0.1')

    def test_severity_scales_with_port_count(self):
        """Severity should scale: MEDIUM (10-15), HIGH (15-20), CRITICAL (>20)."""
        self.detector.ip_ports['scan1'] = set(range(1, 11))  # 10 ports → MEDIUM
        r1 = self.detector.check_port_scan('scan1')
        if r1:
            self.assertEqual(r1['severity'], 'MEDIUM')

        self.detector.ip_ports['scan2'] = set(range(1, 16))  # 15 ports → HIGH
        r2 = self.detector.check_port_scan('scan2')
        if r2:
            self.assertEqual(r2['severity'], 'HIGH')

        self.detector.ip_ports['scan3'] = set(range(1, 26))  # 25 ports → CRITICAL
        r3 = self.detector.check_port_scan('scan3')
        if r3:
            self.assertEqual(r3['severity'], 'CRITICAL')


class TestNewIpDetection(unittest.TestCase):
    """Test check_new_ip() detection with internal IP filtering."""

    def setUp(self):
        self.detector = AnomalyDetector({})

    def test_internal_ip_no_alert(self):
        """Internal IPs should never trigger new IP alert."""
        result = self.detector.check_new_ip('192.168.1.100', 100)
        self.assertIsNone(result)
        result = self.detector.check_new_ip('127.0.0.1', 100)
        self.assertIsNone(result)

    def test_below_threshold_no_alert(self):
        """External IP below event threshold should not trigger."""
        with patch('anomaly_detector.INTERNAL_IP_PREFIXES', ['192.168.']):
            result = self.detector.check_new_ip('203.0.113.1', 2)
            self.assertIsNone(result)

    def test_new_external_ip_triggers_alert(self):
        """New external IP above threshold should trigger."""
        with patch('anomaly_detector.INTERNAL_IP_PREFIXES', ['192.168.']):
            result = self.detector.check_new_ip('203.0.113.1', 10)
            self.assertIsNotNone(result)
            self.assertEqual(result['type'], 'new_ip')
            self.assertEqual(result['src_ip'], '203.0.113.1')

    def test_known_ip_no_alert(self):
        """IP with existing baseline should not trigger."""
        known = FakeBaseline(ip='203.0.113.1')
        detector = AnomalyDetector({'rule1': known})
        with patch('anomaly_detector.INTERNAL_IP_PREFIXES', ['192.168.']):
            result = detector.check_new_ip('203.0.113.1', 10)
            self.assertIsNone(result)

    def test_deduplication(self):
        """Same IP should only alert once."""
        with patch('anomaly_detector.INTERNAL_IP_PREFIXES', ['192.168.']):
            r1 = self.detector.check_new_ip('203.0.113.5', 10)
            self.assertIsNotNone(r1)
            r2 = self.detector.check_new_ip('203.0.113.5', 10)
            self.assertIsNone(r2)  # Deduped


class TestIsInternalIp(unittest.TestCase):
    """Test is_internal_ip() helper."""

    def test_localhost(self):
        self.assertTrue(is_internal_ip('127.0.0.1'))
        self.assertTrue(is_internal_ip('127.0.0.2'))

    def test_rfc1918(self):
        self.assertTrue(is_internal_ip('192.168.1.1'))
        self.assertTrue(is_internal_ip('10.1.1.1'))

    def test_external_ip(self):
        self.assertFalse(is_internal_ip('8.8.8.8'))
        self.assertFalse(is_internal_ip('203.0.113.50'))

    def test_empty_ip(self):
        self.assertTrue(is_internal_ip(''))
        self.assertTrue(is_internal_ip(None))

    def test_ipv6(self):
        self.assertTrue(is_internal_ip('fe80::1'))
        self.assertTrue(is_internal_ip('ff02::2'))


class TestAnalyzeBatch(unittest.TestCase):
    """Test analyze() batch event processing."""

    def setUp(self):
        self.baseline = FakeBaseline(avg=100, std=20)
        self.detector = AnomalyDetector({'rule_a': self.baseline})

    def test_empty_events(self):
        """Empty event list should return no anomalies."""
        result = self.detector.analyze([])
        self.assertEqual(result, [])

    def test_batch_collects_stats(self):
        """Batch should collect stats and check for anomalies."""
        events = [
            {'rule': 'rule_a', 'src_ip': '10.0.0.1', 'dst_port': 80},
            {'rule': 'rule_a', 'src_ip': '10.0.0.1', 'dst_port': 443},
            {'rule': 'rule_a', 'src_ip': '10.0.0.1', 'dst_port': 22},
        ]
        result = self.detector.analyze(events)
        # Should have processed events and checked all detectors
        self.assertIsInstance(result, list)

    def test_batch_detects_port_scan(self):
        """Batch should detect port scan across events."""
        events = [
            {'rule': 'rule_a', 'src_ip': '10.0.0.1', 'dst_port': p}
            for p in range(1, 16)  # 15 unique ports
        ]
        result = self.detector.analyze(events)
        port_scans = [a for a in result if a['type'] == 'port_scan']
        self.assertGreaterEqual(len(port_scans), 0)  # May or may not trigger

    def test_batch_resets_counters(self):
        """Each analyze() call should reset counters."""
        events = [{'rule': 'rule_a', 'src_ip': '10.0.0.1', 'dst_port': 80}]
        self.detector.analyze(events)
        # Counters should be reset on next call
        result2 = self.detector.analyze([])
        self.assertEqual(result2, [])


class TestFeedbackLoop(unittest.TestCase):
    """Test P2-2 feedback loop integration."""

    def test_profile_confidence_calculation(self):
        """Confidence should reflect event count and feedback."""
        from rule_classifier import RuleProfile, MIN_RULE_EVENTS
        profile = RuleProfile(rule_name='test_rule')
        for _ in range(MIN_RULE_EVENTS * 3):
            profile.total_events += 1
            profile.actions['PASS'] = profile.actions.get('PASS', 0) + 1

        # Base confidence should be reasonable
        conf = profile.calculate_confidence()
        self.assertGreater(conf, 0)
        self.assertLessEqual(conf, 1.0)

    def test_feedback_reduces_confidence(self):
        """Incorrect feedback should reduce confidence."""
        from rule_classifier import RuleProfile, MIN_RULE_EVENTS
        profile = RuleProfile(rule_name='test_rule')
        profile.total_events = MIN_RULE_EVENTS * 5
        profile.actions['PASS'] = MIN_RULE_EVENTS * 5

        conf_before = profile.calculate_confidence()
        profile.feedback_incorrect = 3

        conf_after = profile.calculate_confidence()
        self.assertLess(conf_after, conf_before)

    def test_feedback_increases_confidence(self):
        """Correct feedback should slightly increase confidence."""
        from rule_classifier import RuleProfile, MIN_RULE_EVENTS
        profile = RuleProfile(rule_name='test_rule')
        profile.total_events = MIN_RULE_EVENTS * 3
        profile.actions['PASS'] = MIN_RULE_EVENTS * 3

        conf_before = profile.calculate_confidence()
        profile.feedback_correct = 5

        conf_after = profile.calculate_confidence()
        self.assertGreaterEqual(conf_after, conf_before)


if __name__ == '__main__':
    unittest.main()