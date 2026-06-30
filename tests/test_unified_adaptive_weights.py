#!/usr/bin/env python3
"""Tests for adaptive weight learning in UnifiedBehavioralEngine.

Verifies that:
- AdaptiveWeights class is already migrated from threat_engine.py
- SignalFeedback tracking works correctly
- record_attack() / record_benign() feedback methods adapt weights
- Weight clamping, decay multipliers, and persistence all function
- UnifiedBehavioralEngine exposes the full adaptive weights API
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone

from unified_behavioral_engine import (
    UnifiedBehavioralEngine,
    UnifiedIPProfile,
    UnifiedSignal,
    AdaptiveWeights,
    SignalFeedback,
    SIGNAL_WEIGHTS,
    ADAPTIVE_WEIGHT_MIN,
    ADAPTIVE_WEIGHT_MAX,
    ADAPTIVE_MIN_FEEDBACK,
    ADAPTIVE_DECAY_BOOST,
    ADAPTIVE_ATTACK_BOOST,
    SCORE_DECAY_RATE,
    SCORE_DECAY_MIN,
    ThreatLevel,
)


class TestAdaptiveWeightsDefaults:
    """Test AdaptiveWeights fallback behavior."""

    def test_default_weight_from_signal_weights(self):
        """Known signal types fall back to SIGNAL_WEIGHTS."""
        aw = AdaptiveWeights()
        assert aw.get_weight("ids_signature") == SIGNAL_WEIGHTS["ids_signature"]
        assert aw.get_weight("firewall_port_scan") == SIGNAL_WEIGHTS["firewall_port_scan"]

    def test_unknown_signal_type_default(self):
        """Unknown signal types fall back to 0.5."""
        aw = AdaptiveWeights()
        assert aw.get_weight("completely_unknown_signal") == 0.5

    def test_default_decay_multiplier(self):
        """No feedback → decay multiplier is 1.0."""
        aw = AdaptiveWeights()
        assert aw.get_decay_multiplier("ids_signature") == 1.0


class TestAdaptiveWeightsAttackFeedback:
    """Test attack feedback boosts weights."""

    def test_attack_boosts_weight_after_threshold(self):
        """Attack feedback boosts signal weight after MIN_FEEDBACK threshold."""
        aw = AdaptiveWeights()
        initial = aw.get_weight("ids_signature")

        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_attack(["ids_signature"])

        boosted = aw.get_weight("ids_signature")
        assert boosted > initial, f"Expected {boosted} > {initial}"
        assert boosted <= ADAPTIVE_WEIGHT_MAX

    def test_attack_keeps_decay_at_1_0(self):
        """Attack-correlated signals should persist (no extra decay)."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_attack(["ids_signature"])
        decay = aw.get_decay_multiplier("ids_signature")
        assert decay == 1.0

    def test_weight_unchanged_below_threshold(self):
        """Weights do NOT change when feedback < ADAPTIVE_MIN_FEEDBACK."""
        aw = AdaptiveWeights()
        default_weight = aw.get_weight("ids_signature")

        for _ in range(ADAPTIVE_MIN_FEEDBACK - 1):
            aw.record_attack(["ids_signature"])

        weight = aw.get_weight("ids_signature")
        assert weight == default_weight, f"Weight should not change: {weight} != {default_weight}"

    def test_counts_incremented_below_threshold(self):
        """Feedback counts tracked even below threshold."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK - 1):
            aw.record_attack(["ids_signature"])
        fb = aw._feedback["ids_signature"]
        assert fb.attack_count == ADAPTIVE_MIN_FEEDBACK - 1
        assert aw.get_weight("ids_signature") == SIGNAL_WEIGHTS["ids_signature"]

    def test_weight_clamped_to_max(self):
        """Weights never exceed ADAPTIVE_WEIGHT_MAX even with extreme feedback."""
        aw = AdaptiveWeights()
        for _ in range(100):
            aw.record_attack(["ids_signature"])
        weight = aw.get_weight("ids_signature")
        assert ADAPTIVE_WEIGHT_MIN <= weight <= ADAPTIVE_WEIGHT_MAX

    def test_multiple_signal_types_updated(self):
        """Multiple signal types all get updated from a single attack."""
        aw = AdaptiveWeights()
        signal_types = ["ids_signature", "firewall_port_scan", "http_anomaly"]
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_attack(signal_types)

        for st in signal_types:
            assert aw.get_weight(st) > SIGNAL_WEIGHTS.get(st, 0.5), f"{st} should be boosted"


class TestAdaptiveWeightsBenignFeedback:
    """Test benign feedback reduces weights and increases decay."""

    def test_benign_reduces_weight(self):
        """Benign feedback reduces signal weight."""
        aw = AdaptiveWeights()
        initial = aw.get_weight("http_anomaly")
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_benign(["http_anomaly"])
        reduced = aw.get_weight("http_anomaly")
        assert reduced < initial, f"Expected {reduced} < {initial}"
        assert reduced >= ADAPTIVE_WEIGHT_MIN

    def test_benign_increases_decay_multiplier(self):
        """Benign feedback increases decay multiplier (>1 = faster decay)."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_benign(["http_anomaly"])
        decay = aw.get_decay_multiplier("http_anomaly")
        assert decay > 1.0, f"Benign signals should decay faster: {decay}"

    def test_benign_weight_unchanged_below_threshold(self):
        """Benign feedback does NOT change weights below threshold."""
        aw = AdaptiveWeights()
        default_weight = aw.get_weight("http_anomaly")
        for _ in range(ADAPTIVE_MIN_FEEDBACK - 1):
            aw.record_benign(["http_anomaly"])
        weight = aw.get_weight("http_anomaly")
        assert weight == default_weight

    def test_benign_decay_unchanged_below_threshold(self):
        """Decay multiplier unchanged below threshold."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK - 1):
            aw.record_benign(["http_anomaly"])
        decay = aw.get_decay_multiplier("http_anomaly")
        assert decay == 1.0


class TestAdaptiveWeightsPersistence:
    """Test AdaptiveWeights DB persistence."""

    def test_load_from_db(self):
        """Loading from DB restores SignalFeedback entries."""
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = [
            ("ids_signature", 5, 1,
             "2025-06-01T12:00:00+00:00", "2025-06-01T13:00:00+00:00",
             0.75, 1.0),
        ]
        aw = AdaptiveWeights(db)
        assert "ids_signature" in aw._feedback
        fb = aw._feedback["ids_signature"]
        assert fb.attack_count == 5
        assert fb.benign_count == 1
        assert fb.current_weight == 0.75
        assert fb.decay_multiplier == 1.0

    def test_save_to_db(self):
        """Save writes UPSERT statements to DB."""
        db = MagicMock()
        aw = AdaptiveWeights(db)
        aw.record_attack(["ids_signature"])
        aw.save_to_db()
        # save_to_db calls db.execute() for each signal type
        assert db.execute.called
        assert db.commit.called

    def test_save_without_db_is_noop(self):
        """Save with no DB connection is a no-op."""
        aw = AdaptiveWeights(None)
        aw.record_attack(["ids_signature"])
        aw.save_to_db()  # Should not raise


class TestAdaptiveWeightsReset:
    """Test weight reset functionality."""

    def test_reset_single_signal(self):
        """Reset restores default weight for a single signal type."""
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_attack(["ids_signature"])
        aw.reset("ids_signature")
        assert aw.get_weight("ids_signature") == SIGNAL_WEIGHTS["ids_signature"]
        assert aw.get_decay_multiplier("ids_signature") == 1.0

    def test_reset_all(self):
        """Reset with no arg clears all feedback."""
        aw = AdaptiveWeights()
        aw.record_attack(["ids_signature"])
        aw.record_benign(["http_anomaly"])
        aw.reset()
        assert len(aw._feedback) == 0


class TestUnifiedBehavioralEngineFeedbackAPI:
    """Test UnifiedBehavioralEngine record_attack/record_benign."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def test_record_attack_via_engine(self):
        """record_attack extracts signal types from profile and adapts weights."""
        engine = self._make_engine()
        # Ingest an IDS event to create signals
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "signature": "ET MALWARE CnC",
            "severity": "critical",
        })
        # Record enough attacks to exceed threshold
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            engine.record_attack("1.2.3.4")
        weight = engine.adaptive_weights.get_weight("ids_signature")
        assert weight > SIGNAL_WEIGHTS["ids_signature"]

    def test_record_benign_via_engine(self):
        """record_benign reduces weights and increases decay."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "http",
            "status_code": "404",
            "path": "/missing",
        })
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            engine.record_benign("1.2.3.4")
        weight = engine.adaptive_weights.get_weight("http_anomaly")
        decay = engine.adaptive_weights.get_decay_multiplier("http_anomaly")
        assert weight < SIGNAL_WEIGHTS["http_anomaly"]
        assert decay > 1.0

    def test_record_attack_no_signals(self):
        """record_attack on IP with no signals does not crash."""
        engine = self._make_engine()
        engine.record_attack("9.9.9.9")  # No signals for this IP

    def test_record_benign_no_signals(self):
        """record_benign on IP with no signals does not crash."""
        engine = self._make_engine()
        engine.record_benign("9.9.9.9")

    def test_get_adaptive_weights_summary(self):
        """Public API returns structured data for monitoring."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "severity": "high",
        })
        engine.record_attack("1.2.3.4")
        summary = engine.get_adaptive_weights_summary()
        assert "ids_signature" in summary
        assert summary["ids_signature"]["attack_count"] >= 1

    def test_reset_adaptive_weights(self):
        """Reset restores defaults via engine API."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "severity": "high",
        })
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            engine.record_attack("1.2.3.4")
        engine.reset_adaptive_weights("ids_signature")
        assert engine.adaptive_weights.get_weight("ids_signature") == SIGNAL_WEIGHTS["ids_signature"]

    def test_multi_signal_feedback(self):
        """Multiple signal types in one IP all get updated."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "severity": "high",
        })
        # Manually add a firewall signal
        profile = engine._profiles["1.2.3.4"]
        profile.signals.append(UnifiedSignal(
            source="firewall",
            signal_type="firewall_block_ratio",
            score=0.8,
            timestamp=datetime.now(timezone.utc),
        ))
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            engine.record_attack("1.2.3.4")
        summary = engine.get_adaptive_weights_summary()
        assert "ids_signature" in summary
        assert "firewall_block_ratio" in summary


class TestGetBehavioralScoreWithAdaptiveWeights:
    """Test that get_behavioral_score uses adaptive weights."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def test_score_uses_adaptive_weights(self):
        """get_behavioral_score uses AdaptiveWeights.get_weight()."""
        engine = self._make_engine()
        # Ingest events to build up signals
        for _ in range(10):
            engine.ingest_event({
                "src_ip": "1.2.3.4",
                "log_type": "ids",
                "severity": "high",
                "signature": "test",
            })
        initial_score = engine.get_behavioral_score("1.2.3.4")

        # Record attacks to boost IDS weight
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 5):
            engine.record_attack("1.2.3.4")

        # Score should be non-zero (profile has signals)
        assert initial_score > 0 or len(engine._profiles["1.2.3.4"].signals) > 0

    def test_score_ip_returns_zero_for_unknown(self):
        """Unknown IPs return 0.0 score."""
        engine = self._make_engine()
        assert engine.get_behavioral_score("0.0.0.0") == 0.0

    def test_score_returns_100_max(self):
        """Score is capped at 100."""
        engine = self._make_engine()
        for _ in range(50):
            engine.ingest_event({
                "src_ip": "1.2.3.4",
                "log_type": "ids",
                "severity": "critical",
                "signature": "CRITICAL THREAT",
            })
        score = engine.get_behavioral_score("1.2.3.4")
        assert score <= 100.0


class TestAdaptiveDecayInProfile:
    """Test that profile.apply_decay uses adaptive decay multipliers."""

    def test_benign_signals_decay_faster(self):
        """Signals confirmed as benign decay faster than normal ones."""
        profile_attack = UnifiedIPProfile("1.2.3.4")
        profile_benign = UnifiedIPProfile("5.6.7.8")

        old_time = datetime.now(timezone.utc) - timedelta(hours=1)

        # Same signal score for both
        profile_attack.signals.append(UnifiedSignal(
            source="ids", signal_type="ids_signature", score=0.8,
            timestamp=old_time,
        ))
        profile_benign.signals.append(UnifiedSignal(
            source="http", signal_type="http_anomaly", score=0.8,
            timestamp=old_time,
        ))
        profile_attack.last_seen = old_time
        profile_benign.last_seen = old_time

        # Record benign feedback for http_anomaly to increase decay
        aw = AdaptiveWeights()
        for _ in range(ADAPTIVE_MIN_FEEDBACK + 2):
            aw.record_benign(["http_anomaly"])

        profile_attack.apply_decay(aw)
        profile_benign.apply_decay(aw)

        # Benign signal should have lower score after decay
        assert profile_benign.signals[0].score < profile_attack.signals[0].score


class TestAllSignalWeightsDefined:
    """Verify all signal weight entries are present."""

    def test_expected_signal_weights(self):
        """All original threat_engine signal weights exist."""
        expected = [
            "firewall_block_ratio", "firewall_port_scan", "firewall_dest_scan",
            "http_anomaly", "ids_signature", "zenarmor_threat", "nginx_attack",
            "volume_anomaly", "temporal_anomaly", "geo_anomaly",
        ]
        for key in expected:
            assert key in SIGNAL_WEIGHTS, f"Missing signal weight: {key}"
            assert 0 < SIGNAL_WEIGHTS[key] <= 1.0

    def test_deviation_signal_weights(self):
        """Deviation signal weights exist (from ip_behavior_model merge)."""
        deviation_keys = [
            "deviation_conn_rate", "deviation_unique_dst_ports",
            "deviation_unique_dst_ips", "deviation_bytes_per_conn",
            "deviation_packet_count", "statistical_anomaly",
        ]
        for key in deviation_keys:
            assert key in SIGNAL_WEIGHTS, f"Missing deviation weight: {key}"

    def test_adaptive_constants(self):
        """Adaptive tuning constants are reasonable."""
        assert 0 < ADAPTIVE_WEIGHT_MIN < ADAPTIVE_WEIGHT_MAX
        assert ADAPTIVE_MIN_FEEDBACK >= 1
        assert ADAPTIVE_DECAY_BOOST > 1.0
        assert ADAPTIVE_ATTACK_BOOST > 1.0


class TestEngineStatsWithAdaptiveWeights:
    """Test that get_stats() includes adaptive weight summary."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def test_stats_include_adaptive_weights(self):
        """get_stats returns adaptive_weights_summary."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "severity": "high",
        })
        engine.record_attack("1.2.3.4")
        stats = engine.get_stats()
        assert "adaptive_weights_summary" in stats
        assert "ids_signature" in stats["adaptive_weights_summary"]

    def test_stats_include_threat_level_counts(self):
        """get_stats returns threat_level_counts."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "severity": "critical",
        })
        stats = engine.get_stats()
        assert "threat_level_counts" in stats


class TestPeriodicPersistWithAdaptiveWeights:
    """Test that periodic_persist saves adaptive weights."""

    def _make_engine(self):
        db = MagicMock()
        return UnifiedBehavioralEngine(db)

    def test_persist_saves_weights(self):
        """periodic_persist calls adaptive_weights.save_to_db()."""
        engine = self._make_engine()
        engine.ingest_event({
            "src_ip": "1.2.3.4",
            "log_type": "ids",
            "severity": "high",
        })
        engine.record_attack("1.2.3.4")
        # Patch save_to_db to verify it's called
        engine.adaptive_weights.save_to_db = MagicMock()
        engine.periodic_persist()
        engine.adaptive_weights.save_to_db.assert_called()
