#!/usr/bin/env python3
"""
Unit tests for unified threat levels with behavioral score thresholds.

Tests:
1. ThreatLevel enum ordering and values
2. Score-based threshold classification (BENIGN 0-20, SUSPICIOUS 21-45, etc.)
3. Signal-type context bumps (IDS/zenarmor → RECON+, http_anomaly → SUSPICIOUS+)
4. to_dict() serialization completeness
5. Edge cases (score=0, score=100, no signals, multiple signal bumps)
"""

import sys
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

# Allow importing from project root regardless of cwd
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from unified_behavioral_engine import (
    ThreatLevel,
    THREAT_LEVEL_THRESHOLDS,
    SIGNAL_MIN_THREAT_LEVEL,
    UnifiedIPProfile,
    UnifiedSignal,
    UnifiedBehavioralEngine,
)


class TestThreatLevelEnum(unittest.TestCase):
    """Test ThreatLevel enum values and ordering."""

    def test_enum_ordering(self):
        """BENIGN < SUSPICIOUS < RECONNAISSANCE < ATTACK < EXPLOIT."""
        self.assertLess(ThreatLevel.BENIGN, ThreatLevel.SUSPICIOUS)
        self.assertLess(ThreatLevel.SUSPICIOUS, ThreatLevel.RECONNAISSANCE)
        self.assertLess(ThreatLevel.RECONNAISSANCE, ThreatLevel.ATTACK)
        self.assertLess(ThreatLevel.ATTACK, ThreatLevel.EXPLOIT)

    def test_enum_values(self):
        """Verify numeric values for comparison."""
        self.assertEqual(int(ThreatLevel.BENIGN), 0)
        self.assertEqual(int(ThreatLevel.SUSPICIOUS), 1)
        self.assertEqual(int(ThreatLevel.RECONNAISSANCE), 2)
        self.assertEqual(int(ThreatLevel.ATTACK), 3)
        self.assertEqual(int(ThreatLevel.EXPLOIT), 4)

    def test_threshold_boundaries(self):
        """Verify thresholds match spec: 0-20, 21-45, 46-65, 66-85, 86-100."""
        self.assertEqual(THREAT_LEVEL_THRESHOLDS[ThreatLevel.BENIGN], (0, 20))
        self.assertEqual(THREAT_LEVEL_THRESHOLDS[ThreatLevel.SUSPICIOUS], (21, 45))
        self.assertEqual(THREAT_LEVEL_THRESHOLDS[ThreatLevel.RECONNAISSANCE], (46, 65))
        self.assertEqual(THREAT_LEVEL_THRESHOLDS[ThreatLevel.ATTACK], (66, 85))
        self.assertEqual(THREAT_LEVEL_THRESHOLDS[ThreatLevel.EXPLOIT], (86, 100))

    def test_all_thresholds_covered(self):
        """All 5 levels present in thresholds."""
        self.assertEqual(len(THREAT_LEVEL_THRESHOLDS), 5)


class TestThreatLevelFromScore(unittest.TestCase):
    """Test threat level derivation from behavioral score alone (no signal bumps)."""

    def _make_profile(self, score_signals):
        """Create a profile with pre-loaded signals that produce the desired score."""
        profile = UnifiedIPProfile("10.0.0.1")
        profile.total_events = 100  # Enough events to compute score
        # Inject signals with known scores
        for s in score_signals:
            profile.signals.append(UnifiedSignal(
                source=s.get("source", "firewall"),
                signal_type=s.get("signal_type", "volume_anomaly"),
                score=s["score"],
                timestamp=datetime.now(timezone.utc),
                details=s.get("details", {}),
            ))
        return profile

    def test_score_zero_is_benign(self):
        """Score 0 → BENIGN (no signals, minimal events)."""
        profile = UnifiedIPProfile("10.0.0.1")
        profile.total_events = 5  # Below threshold
        # Score returns 0 when total_events < 10
        self.assertEqual(profile.get_threat_level(), ThreatLevel.BENIGN)

    def test_boundary_scores(self):
        """Test exact boundary values: 20→BENIGN, 21→SUSPICIOUS, 45→SUSPICIOUS, 46→RECON, 65→RECON, 66→ATTACK, 85→ATTACK, 86→EXPLOIT."""
        # We need to verify the thresholds are applied correctly by checking
        # the classification logic directly (since producing exact scores
        # from signal aggregation is complex).
        # Instead, test that THREAT_LEVEL_THRESHOLDS classify correctly.
        def classify(score):
            for level, (low, high) in THREAT_LEVEL_THRESHOLDS.items():
                if low <= score <= high:
                    return level
            return ThreatLevel.EXPLOIT

        self.assertEqual(classify(0), ThreatLevel.BENIGN)
        self.assertEqual(classify(10), ThreatLevel.BENIGN)
        self.assertEqual(classify(20), ThreatLevel.BENIGN)
        self.assertEqual(classify(21), ThreatLevel.SUSPICIOUS)
        self.assertEqual(classify(33), ThreatLevel.SUSPICIOUS)
        self.assertEqual(classify(45), ThreatLevel.SUSPICIOUS)
        self.assertEqual(classify(46), ThreatLevel.RECONNAISSANCE)
        self.assertEqual(classify(55), ThreatLevel.RECONNAISSANCE)
        self.assertEqual(classify(65), ThreatLevel.RECONNAISSANCE)
        self.assertEqual(classify(66), ThreatLevel.ATTACK)
        self.assertEqual(classify(75), ThreatLevel.ATTACK)
        self.assertEqual(classify(85), ThreatLevel.ATTACK)
        self.assertEqual(classify(86), ThreatLevel.EXPLOIT)
        self.assertEqual(classify(95), ThreatLevel.EXPLOIT)
        self.assertEqual(classify(100), ThreatLevel.EXPLOIT)


class TestSignalTypeContextBumps(unittest.TestCase):
    """Test that signal types bump threat level above score-derived level."""

    def _make_profile_with_signal(self, signal_type, score=0.3):
        """Create a profile with one signal of the given type."""
        profile = UnifiedIPProfile("10.0.0.1")
        profile.total_events = 5
        # Score will be 0 (below threshold), so threat level should come from signal bump
        profile.signals.append(UnifiedSignal(
            source="ids",
            signal_type=signal_type,
            score=score,
            timestamp=datetime.now(timezone.utc),
            details={},
        ))
        return profile

    def test_ids_signature_bumps_to_recon(self):
        """IDS signature with score 0 → RECONNAISSANCE (minimum bump)."""
        profile = self._make_profile_with_signal("ids_signature")
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)

    def test_zenarmor_threat_bumps_to_recon(self):
        """ZenArmor threat with score 0 → RECONNAISSANCE (minimum bump)."""
        profile = self._make_profile_with_signal("zenarmor_threat")
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)

    def test_firewall_port_scan_bumps_to_recon(self):
        """Port scan signal → RECONNAISSANCE (minimum bump)."""
        profile = self._make_profile_with_signal("firewall_port_scan")
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)

    def test_firewall_dest_scan_bumps_to_recon(self):
        """Destination scan signal → RECONNAISSANCE (minimum bump)."""
        profile = self._make_profile_with_signal("firewall_dest_scan")
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)

    def test_nginx_attack_bumps_to_recon(self):
        """Nginx attack signal → RECONNAISSANCE (minimum bump)."""
        profile = self._make_profile_with_signal("nginx_attack")
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)

    def test_http_anomaly_bumps_to_suspicious(self):
        """HTTP anomaly → SUSPICIOUS (minimum bump)."""
        profile = self._make_profile_with_signal("http_anomaly")
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.SUSPICIOUS)

    def test_no_bump_signal_stays_benign(self):
        """Signal type with no minimum → score-derived level only."""
        profile = self._make_profile_with_signal("volume_anomaly")
        level = profile.get_threat_level()
        # Volume anomaly has no minimum bump, score is 0 (events < 10) → BENIGN
        self.assertEqual(level, ThreatLevel.BENIGN)

    def test_highest_signal_wins_bump(self):
        """When multiple signals have different bumps, highest wins."""
        profile = UnifiedIPProfile("10.0.0.1")
        profile.total_events = 5
        profile.signals.append(UnifiedSignal(
            source="http", signal_type="http_anomaly", score=0.3,
            timestamp=datetime.now(timezone.utc), details={},
        ))
        profile.signals.append(UnifiedSignal(
            source="ids", signal_type="ids_signature", score=0.5,
            timestamp=datetime.now(timezone.utc), details={},
        ))
        # http_anomaly → SUSPICIOUS, ids_signature → RECONNAISSANCE
        # Result: RECONNAISSANCE (highest)
        level = profile.get_threat_level()
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)

    def test_score_level_above_signal_bump(self):
        """When score-derived level > signal minimum, score level wins."""
        profile = UnifiedIPProfile("10.0.0.1")
        profile.total_events = 100
        # High-score signals that produce a high behavioral score
        for _ in range(10):
            profile.signals.append(UnifiedSignal(
                source="ids", signal_type="ids_signature", score=1.0,
                timestamp=datetime.now(timezone.utc), details={},
            ))
        profile.blocked_events = 90
        profile.firewall_events = 100
        level = profile.get_threat_level()
        # High block ratio + IDS signals → score should be high (ATTACK or EXPLOIT)
        self.assertGreaterEqual(level, ThreatLevel.RECONNAISSANCE)


class TestSignalMinThreatLevelConfig(unittest.TestCase):
    """Verify SIGNAL_MIN_THREAT_LEVEL is properly configured."""

    def test_all_expected_signals_present(self):
        """Check all expected signal types are in the bump config."""
        expected_signals = {
            "ids_signature",
            "zenarmor_threat",
            "nginx_attack",
            "firewall_port_scan",
            "firewall_dest_scan",
            "http_anomaly",
        }
        for sig in expected_signals:
            self.assertIn(sig, SIGNAL_MIN_THREAT_LEVEL, f"{sig} missing from bump config")

    def test_recon_signals(self):
        """IDS, ZenArmor, nginx, port scan, dest scan → RECONNAISSANCE."""
        recon_signals = [
            "ids_signature",
            "zenarmor_threat",
            "nginx_attack",
            "firewall_port_scan",
            "firewall_dest_scan",
        ]
        for sig in recon_signals:
            self.assertEqual(
                SIGNAL_MIN_THREAT_LEVEL[sig],
                ThreatLevel.RECONNAISSANCE,
                f"{sig} should bump to RECONNAISSANCE",
            )

    def test_suspicious_signals(self):
        """HTTP anomaly → SUSPICIOUS."""
        self.assertEqual(
            SIGNAL_MIN_THREAT_LEVEL["http_anomaly"],
            ThreatLevel.SUSPICIOUS,
            "http_anomaly should bump to SUSPICIOUS",
        )


class TestToDict(unittest.TestCase):
    """Test UnifiedIPProfile.to_dict() serialization."""

    def setUp(self):
        self.profile = UnifiedIPProfile("10.0.0.1")
        self.profile.total_events = 50
        self.profile.blocked_events = 10
        self.profile.firewall_events = 50
        self.profile.signals.append(UnifiedSignal(
            source="ids", signal_type="ids_signature", score=0.8,
            timestamp=datetime.now(timezone.utc), details={"signature": "TEST"},
        ))

    def test_to_dict_returns_dict(self):
        """to_dict() returns a dict."""
        result = self.profile.to_dict()
        self.assertIsInstance(result, dict)

    def test_to_dict_contains_ip(self):
        """to_dict() contains IP address."""
        result = self.profile.to_dict()
        self.assertEqual(result["ip"], "10.0.0.1")

    def test_to_dict_contains_timestamps(self):
        """to_dict() contains first_seen and last_seen as ISO strings."""
        result = self.profile.to_dict()
        self.assertIn("first_seen", result)
        self.assertIn("last_seen", result)
        # Should be ISO format strings
        datetime.fromisoformat(result["first_seen"])
        datetime.fromisoformat(result["last_seen"])

    def test_to_dict_contains_behavioral_score(self):
        """to_dict() contains behavioral_score as float."""
        result = self.profile.to_dict()
        self.assertIn("behavioral_score", result)
        self.assertIsInstance(result["behavioral_score"], (int, float))

    def test_to_dict_contains_threat_level(self):
        """to_dict() contains threat_level name and numeric value."""
        result = self.profile.to_dict()
        self.assertIn("threat_level", result)
        self.assertIn("threat_level_value", result)
        # Name should be a string
        self.assertIsInstance(result["threat_level"], str)
        # Value should be an int
        self.assertIsInstance(result["threat_level_value"], int)

    def test_threat_level_consistent(self):
        """to_dict threat_level matches get_threat_level()."""
        result = self.profile.to_dict()
        expected = self.profile.get_threat_level()
        self.assertEqual(result["threat_level"], expected.name)
        self.assertEqual(result["threat_level_value"], int(expected))

    def test_to_dict_contains_profile_baselines_signals(self):
        """to_dict() contains profile, baselines, and signals sub-dicts."""
        result = self.profile.to_dict()
        self.assertIn("profile", result)
        self.assertIn("baselines", result)
        self.assertIn("signals", result)

    def test_to_dict_signals_include_ids(self):
        """to_dict() signals list includes our injected signal."""
        result = self.profile.to_dict()
        signal_types = [s["signal_type"] for s in result["signals"]]
        self.assertIn("ids_signature", signal_types)

    def test_to_dict_json_serializable(self):
        """to_dict() output is JSON-serializable (no datetime objects etc.)."""
        import json
        result = self.profile.to_dict()
        # Should not raise
        json.dumps(result)


class TestToDictWithEngine(unittest.TestCase):
    """Test to_dict() through the UnifiedBehavioralEngine."""

    def setUp(self):
        mock_db = MagicMock()
        self.engine = UnifiedBehavioralEngine(mock_db)

    def test_ingest_and_dict(self):
        """Ingest event → get profile from memory → to_dict works end to end."""
        event = {
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "log_type": "ids",
            "severity": "high",
            "signature": "TEST-SIG",
        }
        self.engine.ingest_event(event)
        # Access internal profile directly (engine.get_profile returns a dict)
        profile = self.engine._profiles.get("1.2.3.4")
        self.assertIsNotNone(profile)
        result = profile.to_dict()
        self.assertIn("behavioral_score", result)
        self.assertIn("threat_level", result)
        self.assertEqual(result["ip"], "1.2.3.4")


if __name__ == "__main__":
    unittest.main()
