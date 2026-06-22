"""Tests for rule_classifier.py ML features (FeatureExtractor, MLRuleClassifier)."""

import sys
import os
import tempfile
import math
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import numpy as np
from datetime import datetime, timezone, timedelta
from collections import Counter

from rule_classifier import (
    RuleProfile, FeatureExtractor, MLRuleClassifier, RuleClassifier,
    ML_FEATURE_NAMES, ML_PREDICT_CONFIDENCE_THRESHOLD,
)


# ── Helpers ─────────────────────────────────────────────────────────────

def make_profile(name, actions=None, src_ips=None, dst_ips=None,
                 dst_ports=None, first_seen=None, last_seen=None,
                 feedback_correct=0, feedback_incorrect=0):
    """Create a RuleProfile for testing."""
    if first_seen is None:
        first_seen = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    if last_seen is None:
        last_seen = first_seen + timedelta(hours=24)
    actions_counter = Counter(actions or {"PASS": 10})
    p = RuleProfile(
        rule_name=name,
        actions=actions_counter,
        total_events=sum(actions_counter.values()),
        first_seen=first_seen,
        last_seen=last_seen,
        feedback_correct=feedback_correct,
        feedback_incorrect=feedback_incorrect,
    )
    if src_ips:
        p.src_ips = set(src_ips)
    if dst_ips:
        p.dst_ips = set(dst_ips)
    if dst_ports:
        p.dst_ports = set(dst_ports)
    return p


# ── FeatureExtractor tests ─────────────────────────────────────────────


class TestFeatureExtractor:

    def test_extract_returns_correct_shape(self):
        profile = make_profile("r1", actions={"PASS": 50})
        vec = FeatureExtractor.extract(profile)
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (len(ML_FEATURE_NAMES),)

    def test_volume_features(self):
        profile = make_profile("r1", actions={"PASS": 42})
        profile.src_ips = {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
        profile.dst_ips = {"10.0.0.1"}
        profile.dst_ports = {80, 443}
        vec = FeatureExtractor.extract(profile)
        feats = dict(zip(ML_FEATURE_NAMES, vec))
        assert feats["total_events"] == 42.0
        assert feats["unique_src_ips"] == 3.0
        assert feats["unique_dst_ips"] == 1.0
        assert feats["unique_dst_ports"] == 2.0

    def test_action_ratios(self):
        profile = make_profile("r1", actions={"PASS": 80, "BLOCK": 20})
        vec = FeatureExtractor.extract(profile)
        feats = dict(zip(ML_FEATURE_NAMES, vec))
        assert abs(feats["pass_ratio"] - 0.8) < 1e-6
        assert abs(feats["block_ratio"] - 0.2) < 1e-6

    def test_entropy_features(self):
        profile = make_profile("r1", actions={"PASS": 10})
        profile.src_ips = {"1.1.1.1"}
        vec = FeatureExtractor.extract(profile)
        feats = dict(zip(ML_FEATURE_NAMES, vec))
        assert feats["src_ip_entropy"] == 0.0  # single IP = zero entropy

    def test_extract_batch_filters_uncertain(self):
        profiles = {
            "r1": make_profile("r1", actions={"PASS": 5}),
            "r2": make_profile("r2", actions={"PASS": 50, "BLOCK": 10}),
        }
        X, names = FeatureExtractor.extract_batch(profiles)
        # r1 has 5 events < MIN_RULE_EVENTS (10) so only r2 is included
        assert X.shape[0] == 1
        assert len(names) == 1
        assert names[0] == "r2"

    def test_extract_batch_empty(self):
        profiles = {
            "r1": make_profile("r1", actions={"PASS": 3}),
        }
        X, names = FeatureExtractor.extract_batch(profiles)
        assert X.shape == (0, len(ML_FEATURE_NAMES))
        assert names == []


# ── MLRuleClassifier tests ─────────────────────────────────────────────


class TestMLRuleClassifier:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ["AGENT_DATA_DIR"] = self.tmpdir

    def teardown_method(self):
        del os.environ["AGENT_DATA_DIR"]
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_profiles(self, count=25):
        """Generate synthetic rule profiles for ML training tests."""
        profiles = {}
        for i in range(count):
            # PERMIT rules: mostly PASS, few unique ports
            if i < count // 2:
                actions = {"PASS": 50 + i * 2, "BLOCK": max(0, i - 10)}
                src_ips = [f"192.168.1.{j}" for j in range(min(5, i + 1))]
                dst_ips = ["10.0.0.1"]
                dst_ports = [80, 443]
            # DENY rules: mostly BLOCK, many unique ports
            elif i < 3 * count // 4:
                actions = {"PASS": max(0, i - 20), "BLOCK": 60 + i}
                src_ips = [f"10.1.{j}.{k}" for j in range(10) for k in range(5)]
                dst_ips = [f"10.0.0.{j}" for j in range(3)]
                dst_ports = list(range(1, 30))
            # MIXED rules
            else:
                actions = {"PASS": 30 + i, "BLOCK": 30 + i}
                src_ips = [f"172.16.{j}.{k}" for j in range(5) for k in range(3)]
                dst_ips = [f"10.0.0.{j}" for j in range(5)]
                dst_ports = list(range(1, 15))

            profiles[f"rule_{i:03d}"] = make_profile(
                f"rule_{i:03d}",
                actions=actions,
                src_ips=src_ips,
                dst_ips=dst_ips,
                dst_ports=dst_ports,
                first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=i),
                last_seen=datetime(2026, 1, 2, tzinfo=timezone.utc) + timedelta(hours=i),
            )
        return profiles

    def test_no_model_loads_cleanly(self):
        clf = MLRuleClassifier()
        assert clf.model is None
        assert clf.label_encoder is None

    def test_train_insufficient_data(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=5)  # below ML_MIN_SAMPLES (20)
        metrics = clf.train(profiles)
        assert "error" in metrics

    def test_train_succeeds(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=30)
        metrics = clf.train(profiles)
        assert "error" not in metrics
        assert metrics["accuracy"] > 0.0
        assert metrics["train_samples"] >= 20
        assert clf.model is not None
        assert clf.label_encoder is not None

    def test_model_persisted_and_loaded(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=30)
        clf.train(profiles)
        model_path = clf.model_path
        assert os.path.exists(model_path)

        # Load fresh instance
        clf2 = MLRuleClassifier()
        assert clf2.model is not None
        assert clf2.metrics == clf.metrics

    def test_predict_trained_model(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=30)
        clf.train(profiles)

        profile = make_profile("test", actions={"PASS": 100})
        profile.src_ips = {"192.168.1.1"}
        label, confidence = clf.predict(profile)
        assert label in ("PERMIT", "DENY", "MIXED", "UNCERTAIN")
        assert 0.0 <= confidence <= 1.0

    def test_predict_untrained_fallback(self):
        clf = MLRuleClassifier()
        profile = make_profile("test", actions={"PASS": 50})
        label, confidence = clf.predict(profile)
        assert label == "PERMIT"  # heuristic fallback

    def test_feature_importances(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=30)
        clf.train(profiles)
        assert len(clf.feature_importances) > 0
        assert all(isinstance(v, float) for v in clf.feature_importances.values())

    def test_get_model_info(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=30)
        clf.train(profiles)
        info = clf.get_model_info()
        assert info["model_trained"] is True
        assert info["model_type"] == "GradientBoosting"
        assert "metrics" in info
        assert "feature_names" in info

    def test_should_retrain(self):
        clf = MLRuleClassifier()
        assert not clf.should_retrain()
        from rule_classifier import ML_RETRAIN_THRESHOLD
        clf.increment_samples(ML_RETRAIN_THRESHOLD)
        assert clf.should_retrain()

    def test_train_updates_metrics(self):
        clf = MLRuleClassifier()
        profiles = self._make_profiles(count=30)
        metrics = clf.train(profiles)
        assert "cv_accuracy_mean" in metrics
        assert "cv_accuracy_std" in metrics
        assert "precision_macro" in metrics
        assert "recall_macro" in metrics
        assert "f1_macro" in metrics
        assert "class_distribution" in metrics
        assert "trained_at" in metrics


# ── RuleClassifier integration tests ───────────────────────────────────


class TestRuleClassifierIntegration:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ["AGENT_DATA_DIR"] = self.tmpdir

    def teardown_method(self):
        del os.environ["AGENT_DATA_DIR"]
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_classifier_has_ml(self):
        rc = RuleClassifier()
        assert hasattr(rc, "ml_classifier")
        from rule_classifier import MLRuleClassifier
        assert isinstance(rc.ml_classifier, MLRuleClassifier)

    def test_train_ml_model(self):
        rc = RuleClassifier()
        for i in range(30):
            # Mix of PERMIT, DENY, and MIXED for multi-class training
            if i < 10:
                actions = {"PASS": 50 + i, "BLOCK": 2}  # PERMIT
            elif i < 20:
                actions = {"PASS": 2, "BLOCK": 50 + i}  # DENY
            else:
                actions = {"PASS": 30 + i, "BLOCK": 30 + i}  # MIXED
            profile = make_profile(
                f"rule_{i:03d}",
                actions=actions,
                src_ips=[f"192.168.1.{j}" for j in range(min(5, i + 1))],
            )
            rc.rule_profiles[f"rule_{i:03d}"] = profile

        metrics = rc.train_ml_model()
        assert "error" not in metrics
        assert rc.ml_classifier.model is not None

    def test_get_ml_classification(self):
        rc = RuleClassifier()
        profile = make_profile("test_rule", actions={"PASS": 100})
        profile.src_ips = {"192.168.1.1", "192.168.1.2"}
        rc.rule_profiles["test_rule"] = profile

        result = rc.get_ml_classification("test_rule")
        assert result["label"] in ("PERMIT", "DENY", "MIXED", "UNCERTAIN")
        assert result["confidence"] >= 0.0
        assert result["source"] in ("heuristic", "ML", "ML_fallback", "ML_error_fallback")
        assert result["rule_name"] == "test_rule"

    def test_get_all_classifications(self):
        rc = RuleClassifier()
        for i in range(5):
            profile = make_profile(f"r{i}", actions={"PASS": 20 + i})
            rc.rule_profiles[f"r{i}"] = profile

        classifications = rc.get_all_classifications()
        assert len(classifications) == 5
        # Sorted by confidence descending
        confidences = [c["confidence"] for c in classifications]
        assert confidences == sorted(confidences, reverse=True)

    def test_model_info_endpoint(self):
        rc = RuleClassifier()
        info = rc.get_model_info()
        assert "model_trained" in info
        assert "heuristic_rules_count" in info
        assert "total_events_processed" in info
        assert "should_retrain" in info

    def test_model_metrics_endpoint(self):
        rc = RuleClassifier()
        metrics = rc.get_model_metrics()
        assert "model_trained" in metrics
        assert "samples_since_retrain" in metrics

    def test_process_event_tracks_samples(self):
        rc = RuleClassifier()
        for i in range(5):
            rc.process_event({
                "rule_name": "test_rule",
                "action": "PASS",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dport": 80,
            })
        assert rc.ml_classifier.samples_since_retrain == 5

    def test_auto_retrain_triggers(self):
        rc = RuleClassifier()
        from rule_classifier import ML_RETRAIN_THRESHOLD
        # Add enough profiles with mixed classes for training
        for i in range(30):
            if i < 10:
                actions = {"PASS": 50 + i, "BLOCK": 2}  # PERMIT
            elif i < 20:
                actions = {"PASS": 2, "BLOCK": 50 + i}  # DENY
            else:
                actions = {"PASS": 30 + i, "BLOCK": 30 + i}  # MIXED
            profile = make_profile(
                f"rule_{i:03d}",
                actions=actions,
                src_ips=[f"192.168.1.{j}" for j in range(min(3, i + 1))],
            )
            rc.rule_profiles[f"rule_{i:03d}"] = profile

        # Force enough sample increments to trigger retrain
        rc.ml_classifier.samples_since_retrain = ML_RETRAIN_THRESHOLD

        assert rc.should_retrain_ml()
        metrics = rc.train_ml_model()
        assert "error" not in metrics
        assert not rc.should_retrain_ml()  # reset after train


if __name__ == "__main__":
    pytest.main([__file__, "-v"])