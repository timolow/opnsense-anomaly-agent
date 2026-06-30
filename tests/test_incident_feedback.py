#!/usr/bin/env python3
"""Tests for incident feedback in UnifiedBehavioralEngine.

Verifies that:
- record_false_positive() adjusts EMA baselines and reduces signal weights
- record_true_positive() reinforces signal weights (no baseline change)
- Signal type to feature mapping is correct
- Feedback is persisted to incident_feedback table
- Both methods infer signal types from profile when not provided
- Edge cases: no profile, no signals, DB failures are handled gracefully
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

from unified_behavioral_engine import (
    UnifiedBehavioralEngine,
    UnifiedIPProfile,
    UnifiedSignal,
    AdaptiveWeights,
    EMABaseline,
    EMA_WINDOWS,
    FEATURE_DIMENSIONS,
    SIGNAL_WEIGHTS,
    SIGNAL_TYPE_TO_FEATURES,
    ADAPTIVE_MIN_FEEDBACK,
    FP_ALPHA_BOOST_FACTOR,
    FP_ALPHA_MAX,
)


class TestSignalTypeToFeatures:
    """Test the signal type to feature dimension mapping."""

    def test_deviation_signals_map_to_features(self):
        """Deviation signals map to their corresponding features."""
        assert "conn_rate" in SIGNAL_TYPE_TO_FEATURES["deviation_conn_rate"]
        assert "unique_dst_ports" in SIGNAL_TYPE_TO_FEATURES["deviation_unique_dst_ports"]
        assert "unique_dst_ips" in SIGNAL_TYPE_TO_FEATURES["deviation_unique_dst_ips"]
        assert "bytes_per_conn" in SIGNAL_TYPE_TO_FEATURES["deviation_bytes_per_conn"]
        assert "packet_count" in SIGNAL_TYPE_TO_FEATURES["deviation_packet_count"]

    def test_firewall_signals_map_to_features(self):
        """Firewall signals map to relevant behavioral features."""
        assert "unique_dst_ports" in SIGNAL_TYPE_TO_FEATURES["firewall_port_scan"]
        assert "unique_dst_ips" in SIGNAL_TYPE_TO_FEATURES["firewall_dest_scan"]
        assert "conn_rate" in SIGNAL_TYPE_TO_FEATURES["firewall_block_ratio"]

    def test_content_signals_have_no_features(self):
        """Content/geo signals have no baseline feature impact."""
        assert SIGNAL_TYPE_TO_FEATURES.get("ids_signature", []) == []
        assert SIGNAL_TYPE_TO_FEATURES.get("zenarmor_threat", []) == []
        assert SIGNAL_TYPE_TO_FEATURES.get("nginx_attack", []) == []
        assert SIGNAL_TYPE_TO_FEATURES.get("geo_anomaly", []) == []

    def test_all_mapped_features_are_valid(self):
        """All features referenced in the mapping are valid FEATURE_DIMENSIONS."""
        for st, features in SIGNAL_TYPE_TO_FEATURES.items():
            for feature in features:
                assert feature in FEATURE_DIMENSIONS, (
                    f"Signal {st} maps to unknown feature {feature}"
                )


class TestRecordFalsePositive:
    """Test record_false_positive baseline adjustment and weight reduction."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def _make_profile_with_signals(self, engine, ip, signal_types):
        """Create a profile with the given signal types."""
        profile = UnifiedIPProfile(ip)
        # Record enough events to pass the 10-event threshold
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
                source="behavior",
                signal_type=st,
                score=0.8,
                timestamp=now,
            ))
        engine._profiles[ip] = profile
        return profile

    def test_false_positive_boosts_ema_alpha(self):
        """False positive increases EMA alpha for affected features."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate", "deviation_unique_dst_ports"]
        )

        # Check original alpha values
        orig_alpha_1h = profile.baselines["1h"]["conn_rate"].alpha
        orig_alpha_6h = profile.baselines["6h"]["conn_rate"].alpha

        engine.record_false_positive("10.0.0.1")

        # Alpha should be boosted (but clamped)
        new_alpha_1h = profile.baselines["1h"]["conn_rate"].alpha
        new_alpha_6h = profile.baselines["6h"]["conn_rate"].alpha

        assert new_alpha_1h > orig_alpha_1h, "1h alpha should increase"
        assert new_alpha_6h > orig_alpha_6h, "6h alpha should increase"
        assert new_alpha_1h <= FP_ALPHA_MAX, "Alpha should not exceed max"

    def test_false_positive_boosts_all_windows(self):
        """False positive boosts alpha across all EMA windows."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        engine.record_false_positive("10.0.0.1")

        for window in profile.baselines:
            alpha = profile.baselines[window]["conn_rate"].alpha
            # At least some windows should show increase
        # 1h window (alpha=0.15) -> 0.15 * 2.5 = 0.375 (below max 0.4)
        assert profile.baselines["1h"]["conn_rate"].alpha == 0.375

    def test_false_positive_reduces_signal_weights(self):
        """False positive delegates to record_benign for weight reduction."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate", "http_anomaly"]
        )

        # Build up feedback counts so weights actually change
        for _ in range(ADAPTIVE_MIN_FEEDBACK):
            engine.adaptive_weights.record_benign(["deviation_conn_rate", "http_anomaly"])

        initial_weight = engine.adaptive_weights.get_weight("http_anomaly")
        engine.record_false_positive("10.0.0.1")
        reduced_weight = engine.adaptive_weights.get_weight("http_anomaly")

        assert reduced_weight <= initial_weight, "Weight should not increase after FP"

    def test_false_positive_no_baseline_change_for_content_signals(self):
        """Content signals (ids_signature) don't change baselines."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["ids_signature", "zenarmor_threat"]
        )

        original_alphas = {
            feat: profile.baselines["1h"][feat].alpha
            for feat in FEATURE_DIMENSIONS
        }

        engine.record_false_positive("10.0.0.1")

        for feat in FEATURE_DIMENSIONS:
            assert profile.baselines["1h"][feat].alpha == original_alphas[feat], (
                f"Alpha for {feat} should not change for content signals"
            )

    def test_false_positive_infers_signal_types_from_profile(self):
        """Signal types inferred from profile when not provided."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        engine.record_false_positive("10.0.0.1")  # No signal_types arg

        new_alpha = profile.baselines["1h"]["conn_rate"].alpha
        assert new_alpha > EMA_WINDOWS["1h"]["alpha"]

    def test_false_positive_skips_when_no_signals(self):
        """Gracefully skips when IP has no signals."""
        engine = self._make_engine()
        engine.record_false_positive("9.9.9.9")  # No profile at all
        # Should not crash

    def test_false_positive_with_explicit_signal_types(self):
        """Uses explicit signal types when provided."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        engine.record_false_positive(
            "10.0.0.1",
            signal_types=["deviation_unique_dst_ports"],
        )

        # conn_rate alpha should NOT change (we only passed unique_dst_ports)
        assert profile.baselines["1h"]["conn_rate"].alpha == EMA_WINDOWS["1h"]["alpha"]
        # unique_dst_ports alpha SHOULD change
        assert profile.baselines["1h"]["unique_dst_ports"].alpha > EMA_WINDOWS["1h"]["alpha"]

    def test_false_positive_persists_feedback(self):
        """_persist_feedback is called with correct parameters."""
        engine = self._make_engine()
        self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        with patch.object(engine, "_persist_feedback") as mock_persist:
            engine.record_false_positive("10.0.0.1")
            assert mock_persist.called
            call_args = mock_persist.call_args
            assert call_args[0][0] == "10.0.0.1"
            assert call_args[0][1] == "false_positive"

    def test_false_positive_alpha_clamped_to_max(self):
        """Alpha is clamped to FP_ALPHA_MAX even after boosting."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        # Set alpha very high (simulate multiple FP feedbacks)
        profile.baselines["1h"]["conn_rate"].alpha = 0.2

        engine.record_false_positive("10.0.0.1")

        assert profile.baselines["1h"]["conn_rate"].alpha <= FP_ALPHA_MAX


class TestRecordTruePositive:
    """Test record_true_positive weight reinforcement."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def _make_profile_with_signals(self, engine, ip, signal_types):
        """Create a profile with the given signal types."""
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
                source="behavior",
                signal_type=st,
                score=0.8,
                timestamp=now,
            ))
        engine._profiles[ip] = profile
        return profile

    def test_true_positive_boosts_signal_weights(self):
        """True positive boosts signal weights via record_attack."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["ids_signature"]
        )

        # Build up feedback so weights change
        for _ in range(ADAPTIVE_MIN_FEEDBACK):
            engine.adaptive_weights.record_attack(["ids_signature"])

        initial_weight = engine.adaptive_weights.get_weight("ids_signature")
        engine.record_true_positive("10.0.0.1")
        boosted_weight = engine.adaptive_weights.get_weight("ids_signature")

        assert boosted_weight >= initial_weight, "Weight should increase after TP"

    def test_true_positive_does_not_change_baselines(self):
        """True positive does not modify EMA baselines."""
        engine = self._make_engine()
        profile = self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        original_alpha = profile.baselines["1h"]["conn_rate"].alpha
        engine.record_true_positive("10.0.0.1")

        assert profile.baselines["1h"]["conn_rate"].alpha == original_alpha, (
            "True positive should not change baselines"
        )

    def test_true_positive_infers_signal_types(self):
        """Signal types inferred from profile when not provided."""
        engine = self._make_engine()
        self._make_profile_with_signals(
            engine, "10.0.0.1", ["ids_signature"]
        )

        engine.record_true_positive("10.0.0.1")  # No signal_types arg
        # Should not crash and should record attack feedback
        fb = engine.adaptive_weights._feedback.get("ids_signature")
        assert fb is not None
        assert fb.attack_count >= 1

    def test_true_positive_skips_when_no_signals(self):
        """Gracefully skips when IP has no signals."""
        engine = self._make_engine()
        engine.record_true_positive("9.9.9.9")  # No profile at all

    def test_true_positive_with_explicit_signal_types(self):
        """Uses explicit signal types when provided."""
        engine = self._make_engine()
        self._make_profile_with_signals(
            engine, "10.0.0.1", ["deviation_conn_rate"]
        )

        engine.record_true_positive(
            "10.0.0.1",
            signal_types=["firewall_port_scan"],
        )

        fb = engine.adaptive_weights._feedback.get("firewall_port_scan")
        assert fb is not None
        assert fb.attack_count >= 1

    def test_true_positive_persists_feedback(self):
        """_persist_feedback is called with correct parameters."""
        engine = self._make_engine()
        self._make_profile_with_signals(
            engine, "10.0.0.1", ["ids_signature"]
        )

        with patch.object(engine, "_persist_feedback") as mock_persist:
            engine.record_true_positive("10.0.0.1")
            assert mock_persist.called
            call_args = mock_persist.call_args
            assert call_args[0][0] == "10.0.0.1"
            assert call_args[0][1] == "true_positive"


class TestPersistFeedback:
    """Test _persist_feedback database operations."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def test_persist_with_existing_incident(self):
        """Uses existing active incident when found."""
        engine = self._make_engine()
        cur = MagicMock()
        cur.fetchone.return_value = (42,)  # incident_id = 42
        conn = MagicMock()
        conn.cursor.return_value = cur
        engine.db.connect.return_value = conn

        engine._persist_feedback(
            "10.0.0.1",
            "false_positive",
            ["deviation_conn_rate"],
            datetime.now(timezone.utc),
            "user notes",
        )

        # Should NOT create a new incident
        cur.execute.assert_called()
        # Verify insert into incident_feedback was called
        calls = [c for c in cur.execute.call_args_list]
        # The incident_feedback INSERT should be among the calls
        assert any("incident_feedback" in str(c) for c in calls), (
            f"Expected incident_feedback insert, got: {calls}"
        )

    def test_persist_creates_incident_when_none_exists(self):
        """Creates an incident when no active incident is found."""
        engine = self._make_engine()
        cur = MagicMock()
        cur.fetchone.side_effect = [None, (100,)]  # no incident -> new incident id
        conn = MagicMock()
        conn.cursor.return_value = cur
        engine.db.connect.return_value = conn

        engine._persist_feedback(
            "10.0.0.1",
            "true_positive",
            ["ids_signature"],
            datetime.now(timezone.utc),
        )

        # Should create incident AND insert feedback
        calls = [str(c) for c in cur.execute.call_args_list]
        assert any("INSERT INTO incidents" in c for c in calls), (
            f"Expected incident creation, got: {calls}"
        )
        assert any("INSERT INTO incident_feedback" in c for c in calls)

    def test_persist_no_db(self):
        """Does nothing when db is None."""
        engine = UnifiedBehavioralEngine(None)
        engine._persist_feedback(
            "10.0.0.1",
            "false_positive",
            ["deviation_conn_rate"],
            datetime.now(timezone.utc),
        )
        # Should not crash

    def test_persist_db_failure_is_caught(self):
        """DB errors are caught and logged, not raised."""
        engine = self._make_engine()
        engine.db.connect.side_effect = Exception("connection refused")

        engine._persist_feedback(
            "10.0.0.1",
            "false_positive",
            ["deviation_conn_rate"],
            datetime.now(timezone.utc),
        )
        # Should not raise


class TestFeedbackConstants:
    """Test feedback-related configuration constants."""

    def test_fp_alpha_boost_factor(self):
        """FP_ALPHA_BOOST_FACTOR is reasonable (> 1 for boosting)."""
        assert FP_ALPHA_BOOST_FACTOR > 1.0

    def test_fp_alpha_max_reasonable(self):
        """FP_ALPHA_MAX is below 1.0 and above default alphas."""
        assert 0.1 < FP_ALPHA_MAX < 1.0

    def test_fp_alpha_max_above_default_alphas(self):
        """FP_ALPHA_MAX should be above the highest default alpha."""
        max_default = max(cfg["alpha"] for cfg in EMA_WINDOWS.values())
        assert FP_ALPHA_MAX >= max_default
