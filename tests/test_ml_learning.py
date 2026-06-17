"""Tests for ml_learning.py — self-learning ML engine (Weeks 1-5)."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from ml_learning import (
    FeedbackRecord,
    RuleBaseline,
    RuleTemporalPattern,
    MLFeatures,
    RuleStatsSummary,
    SelfLearningClassifier,
    compute_ml_features,
    classify_rule,
    get_temporal_anomaly_score,
    detect_drift,
    compute_dynamic_thresholds,
    get_active_learning_queue,
    save_feedback,
    load_state,
    update_baseline,
    update_temporal,
)


class TestMLFeatures:
    """Test ML feature extraction."""

    def test_compute_ml_features_basic(self):
        features = compute_ml_features({"unique_ports": 5, "unique_dst_ips": 3,
                                         "total_events": 100, "block_count": 10, "pass_count": 90,
                                         "protocols": {"TCP": 80, "UDP": 20}})
        assert features is not None
        assert isinstance(features.port_scan_score, float)
        assert isinstance(features.dest_scan_score, float)
        assert isinstance(features.action_ratio, float)
        assert isinstance(features.volume_score, float)
        assert isinstance(features.protocol_score, float)
        assert isinstance(features.goodness_score, float)

    def test_ml_features_scanning_high_port_diversity(self):
        features = compute_ml_features({
            "unique_ports": 50, "unique_dst_ips": 5,
            "total_events": 1000, "block_count": 100, "pass_count": 900,
            "protocols": {"TCP": 500, "UDP": 300, "ICMP": 200}
        })
        # High port diversity -> high port scan score
        assert features.port_scan_score > 0.5

    def test_ml_features_normal_traffic(self):
        features = compute_ml_features({
            "unique_ports": 2, "unique_dst_ips": 1,
            "total_events": 5000, "block_count": 0, "pass_count": 5000,
            "protocols": {"TCP": 4500, "UDP": 500}
        })
        assert features.port_scan_score < 0.3
        assert features.dest_scan_score < 0.3
        assert features.action_ratio > 0.7

    def test_ml_features_high_block_ratio(self):
        features = compute_ml_features({
            "unique_ports": 2, "unique_dst_ips": 1,
            "total_events": 100, "block_count": 90, "pass_count": 10,
            "protocols": {"TCP": 100}
        })
        # High block ratio -> low action_ratio (goodness impact)
        assert features.action_ratio < 0.3

    def test_ml_features_low_volume(self):
        features = compute_ml_features({
            "unique_ports": 1, "unique_dst_ips": 1,
            "total_events": 5, "block_count": 0, "pass_count": 5,
            "protocols": {"TCP": 5}
        })
        assert features.volume_score < 0.3


class TestClassifyRule:
    """Test rule classification."""

    def test_classify_good_rule(self):
        features = compute_ml_features({
            "unique_ports": 3, "unique_dst_ips": 2,
            "total_events": 5000, "block_count": 0, "pass_count": 5000,
            "protocols": {"TCP": 4000, "UDP": 1000}
        })
        result = classify_rule(features)
        assert result['classification'] == 'GOOD'
        assert result['confidence'] > 0.7

    def test_classify_suspicious_rule(self):
        features = compute_ml_features({
            "unique_ports": 20, "unique_dst_ips": 100,
            "total_events": 1000, "block_count": 500, "pass_count": 500,
            "protocols": {"TCP": 600, "UDP": 300, "ICMP": 100}
        })
        result = classify_rule(features)
        # High scan scores + mixed pass/block -> suspicious
        assert result['classification'] in ('SUSPICIOUS', 'UNCERTAIN')

    def test_classify_with_user_feedback(self):
        features = compute_ml_features({
            "unique_ports": 5, "unique_dst_ips": 3,
            "total_events": 1000, "block_count": 100, "pass_count": 900,
            "protocols": {"TCP": 800, "UDP": 200}
        })
        result = classify_rule(features, user_feedback_rate=0.9)
        # High user agreement -> higher confidence
        assert result['confidence'] > 0.7

    def test_classify_uncertain_low_events(self):
        features = compute_ml_features({
            "unique_ports": 3, "unique_dst_ips": 2,
            "total_events": 5, "block_count": 0, "pass_count": 5,
            "protocols": {"TCP": 5}
        })
        result = classify_rule(features)
        # Very few events -> uncertain
        assert result['classification'] == 'UNCERTAIN'

    def test_classify_abusive_high_block(self):
        features = compute_ml_features({
            "unique_ports": 30, "unique_dst_ips": 200,
            "total_events": 1000, "block_count": 950, "pass_count": 50,
            "protocols": {"TCP": 600, "UDP": 300, "ICMP": 100}
        })
        result = classify_rule(features)
        assert result['classification'] == 'ABUSIVE'


class TestTemporalPattern:
    """Test temporal pattern detection."""

    def test_normal_time_distribution(self):
        pattern = RuleTemporalPattern(rule_name="test", hours={})
        # Empty -> no anomaly
        score = get_temporal_anomaly_score(pattern, {12: 100})
        assert score < 0.3

    def test_anomalous_time_distribution(self):
        pattern = RuleTemporalPattern(rule_name="test", hours={12: 500})
        # Traffic at unexpected hour -> high anomaly
        score = get_temporal_anomaly_score(pattern, {3: 400})
        assert score > 0.3

    def test_chi_squared_calculation(self):
        pattern = RuleTemporalPattern(rule_name="test", hours={0: 100, 12: 100})
        observed = {0: 200, 12: 0}
        score = get_temporal_anomaly_score(pattern, observed)
        assert score >= 0  # Never negative


class TestDriftDetection:
    """Test per-rule baseline drift detection."""

    def test_no_drift_similar_stats(self):
        baseline = RuleBaseline(
            rule_name="test", avg_port_diversity=5, avg_dest_diversity=3,
            avg_volume=1000, avg_block_ratio=0.1
        )
        current = {"unique_ports": 5, "unique_dst_ips": 3,
                   "total_events": 1050, "block_count": 100, "pass_count": 950}
        drift = detect_drift(baseline, current)
        assert drift['drifting'] is False

    def test_detect_port_drift(self):
        baseline = RuleBaseline(
            rule_name="test", avg_port_diversity=2, avg_dest_diversity=1,
            avg_volume=1000, avg_block_ratio=0.1
        )
        current = {"unique_ports": 50, "unique_dst_ips": 1,
                   "total_events": 1000, "block_count": 100, "pass_count": 900}
        drift = detect_drift(baseline, current)
        assert drift['drifting'] is True

    def test_detect_volume_drift(self):
        baseline = RuleBaseline(
            rule_name="test", avg_port_diversity=2, avg_dest_diversity=1,
            avg_volume=100, avg_block_ratio=0.1
        )
        current = {"unique_ports": 2, "unique_dst_ips": 1,
                   "total_events": 10000, "block_count": 1000, "pass_count": 9000}
        drift = detect_drift(baseline, current)
        assert drift['drifting'] is True


class TestThresholdTuning:
    """Test dynamic threshold computation."""

    def test_basic_thresholds(self):
        thresholds = compute_dynamic_thresholds(
            agreement_rate=0.85, sensitivity="medium"
        )
        assert 'port_diversity_threshold' in thresholds
        assert 'dest_diversity_threshold' in thresholds
        assert 'block_ratio_threshold' in thresholds
        assert 'low_volume_threshold' in thresholds

    def test_sensitive_thresholds(self):
        thresholds = compute_dynamic_thresholds(
            agreement_rate=0.5, sensitivity="high"
        )
        # High sensitivity -> lower thresholds (flag more)
        assert thresholds['port_diversity_threshold'] < 0.5

    def test_conservative_thresholds(self):
        thresholds = compute_dynamic_thresholds(
            agreement_rate=0.95, sensitivity="low"
        )
        # Low sensitivity -> higher thresholds (flag less)
        assert thresholds['port_diversity_threshold'] > 0.3


class TestActiveLearningQueue:
    """Test active learning queue computation."""

    def test_queue_filters_uncertain(self):
        rules = [
            {"rule_name": "a", "confidence": 0.9, "classification": "GOOD"},
            {"rule_name": "b", "confidence": 0.5, "classification": "SUSPICIOUS"},
            {"rule_name": "c", "confidence": 0.3, "classification": "UNCERTAIN"},
            {"rule_name": "d", "confidence": 0.95, "classification": "GOOD"},
        ]
        queue = get_active_learning_queue(rules)
        rule_names = [r['rule_name'] for r in queue]
        assert 'b' in rule_names  # 0.5 is in uncertain range
        assert 'c' in rule_names  # 0.3 is low confidence
        assert 'a' not in rule_names  # 0.9 is confident
        assert 'd' not in rule_names  # 0.95 is confident


class TestSelfLearningClassifierInit:
    """Test classifier initialization."""

    def test_init_default_config(self):
        clf = SelfLearningClassifier()
        assert clf.classification_config is not None
        assert clf.thresholds is not None
        assert hasattr(clf, 'state_file')


class TestFeedbackRecord:
    """Test feedback dataclass."""

    def test_feedback_record_creation(self):
        record = FeedbackRecord(rule_name="test", label="correct", reason="legit")
        assert record.rule_name == "test"
        assert record.label == "correct"
        assert record.reason == "legit"

    def test_feedback_record_timestamp(self):
        record = FeedbackRecord(rule_name="test", label="correct")
        assert record.timestamp is not None


class TestRuleBaseline:
    """Test baseline dataclass."""

    def test_baseline_defaults(self):
        baseline = RuleBaseline(rule_name="test")
        assert baseline.avg_port_diversity == 0.0
        assert baseline.avg_dest_diversity == 0.0
        assert baseline.drift_detected is False


class TestRuleTemporalPattern:
    """Test temporal pattern dataclass."""

    def test_temporal_pattern_creation(self):
        pattern = RuleTemporalPattern(rule_name="test", hours={0: 10, 12: 50})
        assert pattern.rule_name == "test"
        assert pattern.hours[0] == 10


class TestRuleStatsSummary:
    """Test summary dataclass."""

    def test_summary_creation(self):
        summary = RuleStatsSummary(
            total_rules=29, good_rules=15, abusive_rules=0,
            suspicious_rules=1, uncertain_rules=13
        )
        assert summary.total_rules == 29
        assert summary.good_rules == 15
