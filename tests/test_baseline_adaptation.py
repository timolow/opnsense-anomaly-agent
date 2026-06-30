#!/usr/bin/env python3
"""Tests for baseline adaptation rates.

Verifies that:
- AdaptiveWeights tracks per-feature alpha multipliers
- False positive feedback increases alpha multipliers (faster baseline adaptation)
- True positive feedback decreases alpha multipliers (keep baseline strict)
- Feature alpha multipliers are clamped to configured bounds
- New profiles created by the engine inherit the global multipliers
- Feature alpha multipliers persist to and load from the DB
- reset() clears feature alpha multipliers
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock
from datetime import datetime, timezone

from unified_behavioral_engine import (
    UnifiedBehavioralEngine,
    UnifiedIPProfile,
    UnifiedSignal,
    AdaptiveWeights,
    EMABaseline,
    EMA_WINDOWS,
    FEATURE_DIMENSIONS,
    SIGNAL_TYPE_TO_FEATURES,
    ADAPTIVE_MIN_FEEDBACK,
    BASELINE_ALPHA_MULTIPLIER_MIN,
    BASELINE_ALPHA_MULTIPLIER_MAX,
    BASELINE_ALPHA_FP_BOOST,
    BASELINE_ALPHA_TP_REDUCE,
    FP_ALPHA_BOOST_FACTOR,
    FP_ALPHA_MAX,
)


class TestFeatureAlphaMultiplierDefaults:
    """Test default behavior of feature alpha multipliers."""

    def test_default_multiplier_is_one(self):
        """No feedback -> multiplier is 1.0 for all features."""
        aw = AdaptiveWeights()
        for feature in FEATURE_DIMENSIONS:
            assert aw.get_feature_alpha_multiplier(feature) == 1.0

    def test_adjust_increase(self):
        """adjust_feature_alpha('increase') raises multiplier."""
        aw = AdaptiveWeights()
        aw.adjust_feature_alpha("conn_rate", "increase")
        assert aw.get_feature_alpha_multiplier("conn_rate") == 1.0 + BASELINE_ALPHA_FP_BOOST

    def test_adjust_decrease(self):
        """adjust_feature_alpha('decrease') lowers multiplier."""
        aw = AdaptiveWeights()
        aw.adjust_feature_alpha("conn_rate", "decrease")
        assert aw.get_feature_alpha_multiplier("conn_rate") == 1.0 - BASELINE_ALPHA_TP_REDUCE

    def test_increase_clamped_to_max(self):
        """Repeated increases are clamped to BASELINE_ALPHA_MULTIPLIER_MAX."""
        aw = AdaptiveWeights()
        for _ in range(20):
            aw.adjust_feature_alpha("conn_rate", "increase")
        assert aw.get_feature_alpha_multiplier("conn_rate") <= BASELINE_ALPHA_MULTIPLIER_MAX

    def test_decrease_clamped_to_min(self):
        """Repeated decreases are clamped to BASELINE_ALPHA_MULTIPLIER_MIN."""
        aw = AdaptiveWeights()
        for _ in range(20):
            aw.adjust_feature_alpha("conn_rate", "decrease")
        assert aw.get_feature_alpha_multiplier("conn_rate") >= BASELINE_ALPHA_MULTIPLIER_MIN

    def test_unknown_direction_noop(self):
        """Unknown direction does not change the multiplier."""
        aw = AdaptiveWeights()
        aw.adjust_feature_alpha("conn_rate", "unknown")
        assert aw.get_feature_alpha_multiplier("conn_rate") == 1.0

    def test_get_feature_alpha_summary(self):
        """get_feature_alpha_summary returns the multiplier dict."""
        aw = AdaptiveWeights()
        aw.adjust_feature_alpha("conn_rate", "increase")
        summary = aw.get_feature_alpha_summary()
        assert "conn_rate" in summary
        assert summary["conn_rate"] > 1.0


class TestRecordAttackDecreasesAlpha:
    """Test that true positive (attack) feedback decreases feature alpha multipliers."""

    def test_record_attack_decreases_alpha_multiplier(self):
        """record_attack on a deviation signal decreases the corresponding feature multiplier."""
        aw = AdaptiveWeights()
        # Build up feedback past threshold
        for _ in range(ADAPTIVE_MIN_FEEDBACK):
            aw.record_attack(["deviation_conn_rate"])
        aw.record_attack(["deviation_conn_rate"])

        # conn_rate multiplier should be < 1.0 (stricter baseline)
        assert aw.get_feature_alpha_multiplier("conn_rate") < 1.0

    def test_record_attack_multiple_features(self):
        """record_attack adjusts all features mapped from the signal type."""
        aw = AdaptiveWeights()
        # firewall_port_scan maps to unique_dst_ports and conn_rate
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 1):
            aw.record_attack(["firewall_port_scan"])

        assert aw.get_feature_alpha_multiplier("unique_dst_ports") < 1.0
        assert aw.get_feature_alpha_multiplier("conn_rate") < 1.0

    def test_record_attack_no_effect_on_content_signals(self):
        """record_attack on ids_signature (no feature mapping) does not change any multiplier."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 1):
            aw.record_attack(["ids_signature"])

        # All feature multipliers should still be 1.0 (no mapping for ids_signature)
        for feature in FEATURE_DIMENSIONS:
            assert aw.get_feature_alpha_multiplier(feature) == 1.0, (
                f"ids_signature should not affect {feature} multiplier"
            )


class TestRecordBenignIncreasesAlpha:
    """Test that false positive (benign) feedback increases feature alpha multipliers."""

    def test_record_benign_increases_alpha_multiplier(self):
        """record_benign on a deviation signal increases the corresponding feature multiplier."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK):
            aw.record_benign(["deviation_conn_rate"])
        aw.record_benign(["deviation_conn_rate"])

        assert aw.get_feature_alpha_multiplier("conn_rate") > 1.0

    def test_record_benign_multiple_features(self):
        """record_benign adjusts all features mapped from the signal type."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 1):
            aw.record_benign(["volume_anomaly"])

        # volume_anomaly maps to bytes_per_conn and packet_count
        assert aw.get_feature_alpha_multiplier("bytes_per_conn") > 1.0
        assert aw.get_feature_alpha_multiplier("packet_count") > 1.0


class TestFalsePositiveIncreasesAlpha:
    """Test that record_false_positive increases alpha multipliers via engine API."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def _make_profile_with_signals(self, engine, ip, signal_types):
        profile = UnifiedIPProfile(ip)
        for i in range(15):
            profile.record_event({
                "src_ip": ip,
                "dst_port": 80,
                "proto": "TCP",
                "action": "pass",
            })
        now = datetime.now(timezone.utc)
        for st in signal_types:
            profile.signals.append(UnifiedSignal(
                source="behavior", signal_type=st, score=0.8, timestamp=now,
            ))
        engine._profiles[ip] = profile
        return profile

    def test_false_positive_on_volume_anomaly_increases_multiplier(self):
        """False positive on volume_anomaly -> bytes_per_conn and packet_count multipliers increase."""
        engine = self._make_engine()
        self._make_profile_with_signals(engine, "10.0.0.1", ["volume_anomaly"])

        # Build up feedback past threshold
        for _ in range(ADAPTIVE_MIN_FEEDBACK):
            engine.adaptive_weights.record_benign(["volume_anomaly"])

        engine.record_false_positive("10.0.0.1")

        # After FP, multipliers should be > 1.0
        assert engine.adaptive_weights.get_feature_alpha_multiplier("bytes_per_conn") > 1.0
        assert engine.adaptive_weights.get_feature_alpha_multiplier("packet_count") > 1.0

    def test_false_positive_on_volume_spike_scenario(self):
        """False positive on volume_spike -> volume baseline adapts faster next time.

        This is the canonical scenario from the task spec:
        'false positive on volume_spike -> volume baseline adapts faster next time.'
        """
        engine = self._make_engine()
        # volume_anomaly is the signal for volume spike detection
        self._make_profile_with_signals(engine, "10.0.0.1", ["volume_anomaly"])

        # Record enough benign feedback to trigger multiplier change
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 1):
            engine.adaptive_weights.record_benign(["volume_anomaly"])

        # Record the false positive
        engine.record_false_positive("10.0.0.1")

        # Verify multipliers increased
        assert engine.adaptive_weights.get_feature_alpha_multiplier("bytes_per_conn") > 1.0
        assert engine.adaptive_weights.get_feature_alpha_multiplier("packet_count") > 1.0


class TestTruePositiveDecreasesAlpha:
    """Test that record_true_positive decreases alpha multipliers via engine API."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def _make_profile_with_signals(self, engine, ip, signal_types):
        profile = UnifiedIPProfile(ip)
        for i in range(15):
            profile.record_event({
                "src_ip": ip,
                "dst_port": 80,
                "proto": "TCP",
                "action": "pass",
            })
        now = datetime.now(timezone.utc)
        for st in signal_types:
            profile.signals.append(UnifiedSignal(
                source="behavior", signal_type=st, score=0.8, timestamp=now,
            ))
        engine._profiles[ip] = profile
        return profile

    def test_true_positive_keeps_baseline_strict(self):
        """True positive -> alpha multiplier decreases (baseline stays strict/slow to adapt)."""
        engine = self._make_engine()
        self._make_profile_with_signals(engine, "10.0.0.1", ["deviation_conn_rate"])

        for _ in range(ADAPTIVE_MIN_FEEDBACK + 1):
            engine.adaptive_weights.record_attack(["deviation_conn_rate"])

        engine.record_true_positive("10.0.0.1")

        # After TP, multiplier should be < 1.0 (stricter baseline)
        assert engine.adaptive_weights.get_feature_alpha_multiplier("conn_rate") < 1.0


class TestEngineAppliesMultipliersToNewProfiles:
    """Test that new profiles inherit the global feature alpha multipliers."""

    def test_new_profile_inherits_multiplier(self):
        """When engine creates a new profile, it applies global multipliers to baselines."""
        engine = self._make_engine()
        # Set a multiplier > 1.0 for conn_rate
        engine.adaptive_weights._feature_alpha_multipliers["conn_rate"] = 2.0

        # Get a new profile (trigger creation)
        profile = engine._get_or_create_profile("10.0.0.1")

        # Baseline alpha should be default * multiplier
        expected_1h = EMA_WINDOWS["1h"]["alpha"] * 2.0
        assert profile.baselines["1h"]["conn_rate"].alpha == expected_1h

    def test_new_profile_no_multiplier_uses_default(self):
        """When no multiplier is set, new profile uses default alpha."""
        engine = self._make_engine()

        profile = engine._get_or_create_profile("10.0.0.1")

        for window, cfg in EMA_WINDOWS.items():
            assert profile.baselines[window]["conn_rate"].alpha == cfg["alpha"]

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)


class TestPersistence:
    """Test that feature alpha multipliers persist to and load from the DB."""

    def test_save_to_db_includes_multipliers(self):
        """save_to_db writes feature_alpha_multipliers column."""
        db = MagicMock()
        aw = AdaptiveWeights(db)
        aw.adjust_feature_alpha("conn_rate", "increase")
        aw._feedback["test"] = MagicMock(
            attack_count=1, benign_count=0,
            last_attack=None, last_benign=None,
            current_weight=None, decay_multiplier=1.0,
        )
        aw.save_to_db()

        # Check that db.execute was called with feature_alpha_multipliers in the query
        assert db.execute.called
        call_args = str(db.execute.call_args)
        assert "feature_alpha_multipliers" in call_args

    def test_load_from_db_restores_multipliers(self):
        """Loading from DB restores feature alpha multipliers."""
        import json
        db = MagicMock()
        multipliers = {"conn_rate": 1.5, "bytes_per_conn": 0.7}
        db.execute.return_value.fetchall.return_value = [
            ("deviation_conn_rate", 5, 1,
             "2025-06-01T12:00:00+00:00", "2025-06-01T13:00:00+00:00",
             0.75, 1.0, json.dumps(multipliers)),
        ]
        aw = AdaptiveWeights(db)
        assert aw.get_feature_alpha_multiplier("conn_rate") == 1.5
        assert aw.get_feature_alpha_multiplier("bytes_per_conn") == 0.7


class TestReset:
    """Test reset behavior for feature alpha multipliers."""

    def test_reset_single_signal(self):
        """Reset removes feature alpha multipliers for that signal's features."""
        aw = AdaptiveWeights()
        aw.adjust_feature_alpha("conn_rate", "increase")
        aw.reset("deviation_conn_rate")  # maps to conn_rate
        assert aw.get_feature_alpha_multiplier("conn_rate") == 1.0

    def test_reset_all(self):
        """Reset with no arg clears all feature alpha multipliers."""
        aw = AdaptiveWeights()
        aw.adjust_feature_alpha("conn_rate", "increase")
        aw.adjust_feature_alpha("bytes_per_conn", "decrease")
        aw.reset()
        assert aw.get_feature_alpha_summary() == {}


class TestConstants:
    """Verify baseline adaptation constants are reasonable."""

    def test_multiplier_bounds(self):
        assert 0 < BASELINE_ALPHA_MULTIPLIER_MIN < 1.0
        assert 1.0 < BASELINE_ALPHA_MULTIPLIER_MAX

    def test_boost_positive(self):
        assert BASELINE_ALPHA_FP_BOOST > 0

    def test_reduce_positive(self):
        assert BASELINE_ALPHA_TP_REDUCE > 0

    def test_learning_rate_reasonable(self):
        """BASELINE_ALPHA_LEARNING_RATE is defined and reasonable."""
        from unified_behavioral_engine import BASELINE_ALPHA_LEARNING_RATE
        assert 0 < BASELINE_ALPHA_LEARNING_RATE < 1.0


class TestBaselineAlphaAppliedToExistingProfile:
    """Test that existing profiles can have alpha multipliers applied."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def test_false_positive_adjusts_existing_profile_baseline(self):
        """record_false_positive adjusts the existing profile's baseline alpha directly."""
        engine = self._make_engine()
        profile = UnifiedIPProfile("10.0.0.1")
        for i in range(15):
            profile.record_event({
                "src_ip": "10.0.0.1",
                "dst_port": 80,
                "proto": "TCP",
                "action": "pass",
            })
        now = datetime.now(timezone.utc)
        profile.signals.append(UnifiedSignal(
            source="behavior", signal_type="deviation_conn_rate",
            score=0.8, timestamp=now,
        ))
        engine._profiles["10.0.0.1"] = profile

        orig_alpha = profile.baselines["1h"]["conn_rate"].alpha

        engine.record_false_positive("10.0.0.1")

        # The existing profile's alpha should be boosted (local adjustment)
        new_alpha = profile.baselines["1h"]["conn_rate"].alpha
        assert new_alpha > orig_alpha
        assert new_alpha <= FP_ALPHA_MAX
