#!/usr/bin/env python3
"""
Test attack chain detection with unified behavioral engine signals.

Covers:
1. ATTACK_PHASES mapping completeness (all signal types mapped)
2. Full chain detection: recon -> probe -> attack -> exploit
3. Escalated incident creation on 3+ consecutive phases
4. Chain timeline generation for dashboard visualization
5. Cross-source chain detection (signals from different sources)
6. Non-consecutive phases do NOT trigger escalation
"""

import sys
import os
import time
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from correlation_engine import (
    ATTACK_PHASES, PHASE_ORDER, Incident, CorrelationEngine,
    SEVERITY_RANK, SEVERITY_NAMES,
)
from signal_bus import SIGNAL_TYPES, SignalBus


class TestAttackPhasesMapping:
    """Verify all signal types from all sources are mapped to attack phases."""

    def test_all_signal_types_mapped(self):
        """Every SIGNAL_TYPES entry should appear in ATTACK_PHASES or be a non-threat type."""
        # Non-threat signal types that intentionally are NOT in ATTACK_PHASES
        exempt = {
            "firewall_pass",      # info only, never correlated
            "service_recovery",   # positive event
            "threat_score_update", # info-level
            "attack_chain",       # correlation meta-signal
            "attack_chain_escalated", # correlation meta-signal
            "incident_created",   # correlation meta-signal
            "incident_escalated", # correlation meta-signal
        }
        unmapped = []
        for st in SIGNAL_TYPES:
            if st not in ATTACK_PHASES and st not in exempt:
                unmapped.append(st)
        assert unmapped == [], f"Unmapped signal types (not in ATTACK_PHASES): {unmapped}"

    def test_all_phases_valid(self):
        """Every phase value in ATTACK_PHASES must be in PHASE_ORDER."""
        for st, phase in ATTACK_PHASES.items():
            assert phase in PHASE_ORDER, f"Invalid phase '{phase}' for signal '{st}'"

    def test_phase_order(self):
        """PHASE_ORDER must be the canonical sequence."""
        assert PHASE_ORDER == ["recon", "probe", "attack", "exploit"]

    def test_recon_signals(self):
        """Check key recon signal types are mapped."""
        for st in ["port_scan", "horizontal_scan", "flow_recon", "new_ip",
                     "firewall_port_scan", "ids_new_signature", "new_country",
                     "http_scan", "anomaly_new_ip"]:
            assert ATTACK_PHASES.get(st) == "recon", f"{st} should map to recon"

    def test_probe_signals(self):
        """Check key probe signal types are mapped."""
        for st in ["behavior_deviation", "temporal_anomaly", "ids_signature",
                     "zenarmor_threat", "nginx_attack", "http_anomaly",
                     "deviation_conn_rate", "firewall_block_ratio", "statistical_anomaly"]:
            assert ATTACK_PHASES.get(st) == "probe", f"{st} should map to probe"

    def test_attack_signals(self):
        """Check key attack signal types are mapped."""
        for st in ["syn_flood", "brute_force", "http_brute_force", "flow_attack",
                     "path_traversal", "ids_signature_spike", "http_ddos",
                     "block_spike", "baseline_volume_spike"]:
            assert ATTACK_PHASES.get(st) == "attack", f"{st} should map to attack"

    def test_exploit_signals(self):
        """Check key exploit signal types are mapped."""
        for st in ["flow_exploit", "policy_violation"]:
            assert ATTACK_PHASES.get(st) == "exploit", f"{st} should map to exploit"


class TestIncidentChainTracking:
    """Test per-phase timestamp tracking and chain timeline on Incident objects."""

    def test_phase_first_seen_tracking(self):
        """Phase first-seen timestamps are recorded correctly."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {"dst_port": 22})

        assert "recon" in inc.phase_first_seen
        assert len(inc.phase_first_seen) == 1

    def test_phase_first_seen_not_overwritten(self):
        """Subsequent signals in the same phase do NOT overwrite phase_first_seen."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        first_ts = inc.phase_first_seen["recon"]

        time.sleep(0.01)
        inc.add_signal("horizontal_scan", "attack_detector", "medium", {})

        # phase_first_seen["recon"] should still be the first one
        assert inc.phase_first_seen["recon"] == first_ts

    def test_chain_timeline_ordering(self):
        """Chain timeline entries are added in phase discovery order."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        inc.add_signal("behavior_deviation", "behavior_profiler", "low", {})
        inc.add_signal("syn_flood", "attack_detector", "critical", {})

        assert len(inc.chain_timeline) == 3
        assert inc.chain_timeline[0]["phase"] == "recon"
        assert inc.chain_timeline[1]["phase"] == "probe"
        assert inc.chain_timeline[2]["phase"] == "attack"

    def test_chain_timeline_signal_types(self):
        """Chain timeline records the exact signal type that triggered each phase."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("horizontal_scan", "attack_detector", "medium", {})
        inc.add_signal("zenarmor_threat", "zenarmor", "low", {})
        inc.add_signal("http_ddos", "nginx", "high", {})

        assert inc.chain_timeline[0]["signal_type"] == "horizontal_scan"
        assert inc.chain_timeline[1]["signal_type"] == "zenarmor_threat"
        assert inc.chain_timeline[2]["signal_type"] == "http_ddos"


class TestAttackChainDetection:
    """Test full chain progression detection: recon -> probe -> attack -> exploit."""

    def test_full_chain_recon_probe_attack(self):
        """3 consecutive phases (recon->probe->attack) triggers escalation."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        inc.add_signal("behavior_deviation", "behavior_profiler", "low", {})
        inc.add_signal("syn_flood", "attack_detector", "critical", {})

        assert inc.is_full_chain(3), "Should detect full chain: recon->probe->attack"
        assert inc.is_escalated, "Incident should be escalated"
        assert inc.severity == "critical", "Severity should be critical"

    def test_full_chain_all_four_phases(self):
        """4 consecutive phases (recon->probe->attack->exploit) is the ultimate escalation."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        inc.add_signal("ids_signature", "ids", "medium", {})
        inc.add_signal("brute_force", "attack_detector", "high", {})
        inc.add_signal("flow_exploit", "flow_classifier", "critical", {})

        chain = inc.get_attack_chain()
        assert chain == ["recon", "probe", "attack", "exploit"]
        assert inc.is_full_chain(3)
        assert inc.is_escalated
        assert inc.severity == "critical"

    def test_non_consecutive_phases_no_escalation(self):
        """Phases recon + attack (skipping probe) should NOT be a full chain."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        inc.add_signal("syn_flood", "attack_detector", "high", {})

        assert not inc.is_full_chain(3), "recon->attack is NOT a full chain (skips probe)"
        assert not inc.is_escalated, "Should not escalate without probe phase"

    def test_probe_attack_only_no_escalation(self):
        """probe -> attack (2 phases) is not a full chain (needs 3+)."""
        inc = Incident("10.0.0.1", "behavior_deviation")
        inc.add_signal("behavior_deviation", "behavior_profiler", "low", {})
        inc.add_signal("syn_flood", "attack_detector", "high", {})

        assert not inc.is_full_chain(3)
        assert not inc.is_escalated

    def test_single_phase_no_escalation(self):
        """A single phase never triggers escalation."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})

        assert not inc.is_full_chain(3)
        assert not inc.is_escalated


class TestCrossSourceChainDetection:
    """Test that chains detected across different sources trigger escalation."""

    def test_firewall_nginx_ids_chain(self):
        """Chain across firewall (recon) -> ids (probe) -> nginx (attack)."""
        inc = Incident("203.0.113.50", "firewall_port_scan")
        inc.add_signal("firewall_port_scan", "firewall", "medium", {"dst_port": 443})
        inc.add_signal("ids_signature", "ids", "medium", {"dst_ip": "192.168.1.10"})
        inc.add_signal("http_ddos", "nginx", "high", {"dst_port": 80})

        assert inc.is_full_chain(3)
        assert inc.is_escalated
        assert len(inc.sources) == 3

    def test_behavioral_flow_attack_chain(self):
        """Chain across behavior (recon) -> behavioral (probe) -> flow (attack)."""
        inc = Incident("198.51.100.23", "deviation_unique_dst_ports")
        inc.add_signal("deviation_unique_dst_ports", "behavior", "medium", {})
        inc.add_signal("deviation_conn_rate", "behavior", "medium", {})
        inc.add_signal("flow_attack", "flow_classifier", "high", {})

        assert inc.is_full_chain(3)
        assert inc.is_escalated

    def test_zenarmor_system_attack_chain(self):
        """Chain across geo (recon) -> zenarmor (probe) -> system (attack)."""
        inc = Incident("185.220.101.1", "new_country")
        inc.add_signal("new_country", "geo", "low", {"country": "RU"})
        inc.add_signal("zenarmor_threat", "zenarmor", "medium", {})
        inc.add_signal("service_down", "service_monitor", "high", {})

        assert inc.is_full_chain(3)
        assert inc.is_escalated


class TestChainVisualization:
    """Test chain timing and visualization data generation."""

    def test_get_chain_timing(self):
        """get_chain_timing returns ordered phase data for dashboard."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        time.sleep(0.01)
        inc.add_signal("behavior_deviation", "behavior_profiler", "low", {})
        time.sleep(0.01)
        inc.add_signal("syn_flood", "attack_detector", "critical", {})

        timing = inc.get_chain_timing()
        assert len(timing) == 3
        assert timing[0]["phase"] == "recon"
        assert timing[1]["phase"] == "probe"
        assert timing[2]["phase"] == "attack"
        assert timing[0]["signal_types"] == ["port_scan"]
        assert timing[1]["signal_types"] == ["behavior_deviation"]
        assert timing[2]["signal_types"] == ["syn_flood"]
        # Total chain duration should be positive
        assert timing[-1].get("total_chain_duration", 0) > 0

    def test_to_dict_includes_chain_timeline(self):
        """to_dict() includes chain_timeline, is_escalated, and phases."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        inc.add_signal("behavior_deviation", "behavior_profiler", "low", {})
        inc.add_signal("syn_flood", "attack_detector", "critical", {})

        d = inc.to_dict()
        assert "chain_timeline" in d
        assert "is_escalated" in d
        assert "phases" in d
        assert d["is_escalated"] is True
        assert d["phases"] == ["recon", "probe", "attack"]
        assert len(d["chain_timeline"]) == 3

    def test_description_includes_escalated(self):
        """Escalated incidents show ESCALATED prefix in description."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium", {})
        inc.add_signal("behavior_deviation", "behavior_profiler", "low", {})
        inc.add_signal("syn_flood", "attack_detector", "critical", {})

        desc = inc.get_description()
        assert "ESCALATED" in desc
        assert "recon" in desc
        assert "probe" in desc
        assert "attack" in desc


class TestCorrelationEngineChainIntegration:
    """Test the CorrelationEngine with synthetic chain data."""

    def test_chain_via_process_signal(self):
        """Full chain processed through CorrelationEngine triggers escalation."""
        engine = CorrelationEngine()
        signals = [
            MagicMock(signal_type="port_scan", severity="medium", ip="10.0.0.1",
                      source="attack_detector", metadata={}, timestamp=time.time()),
            MagicMock(signal_type="ids_signature", severity="medium", ip="10.0.0.1",
                      source="ids", metadata={}, timestamp=time.time()),
            MagicMock(signal_type="syn_flood", severity="critical", ip="10.0.0.1",
                      source="attack_detector", metadata={}, timestamp=time.time()),
        ]
        for sig in signals:
            engine.process_signal(sig)

        incidents = engine.get_active_incidents()
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.is_escalated
        assert inc.severity == "critical"
        assert inc.get_attack_chain() == ["recon", "probe", "attack"]

    def test_chain_via_group_signals(self):
        """Batch group_signals detects chain escalation."""
        engine = CorrelationEngine()
        signals = [
            MagicMock(signal_type="firewall_port_scan", severity="medium", ip="10.0.0.1",
                      source="firewall", metadata={}, timestamp=time.time()),
            MagicMock(signal_type="zenarmor_threat", severity="low", ip="10.0.0.1",
                      source="zenarmor", metadata={}, timestamp=time.time()),
            MagicMock(signal_type="brute_force", severity="high", ip="10.0.0.1",
                      source="attack_detector", metadata={}, timestamp=time.time()),
        ]
        incidents = engine.group_signals(signals)
        assert len(incidents) == 1
        assert incidents[0].is_escalated

    def test_escalated_signal_emitted(self):
        """CorrelationEngine emits attack_chain_escalated signal on full chain."""
        bus = SignalBus()
        engine = CorrelationEngine(signal_bus=bus)

        # Feed recon signal
        sig1 = MagicMock(signal_type="port_scan", severity="medium", ip="10.0.0.1",
                         source="attack_detector", metadata={}, timestamp=time.time())
        engine.process_signal(sig1)

        # Feed probe signal
        sig2 = MagicMock(signal_type="behavior_deviation", severity="low", ip="10.0.0.1",
                         source="behavior_profiler", metadata={}, timestamp=time.time())
        engine.process_signal(sig2)

        # Feed attack signal -> triggers escalation
        sig3 = MagicMock(signal_type="syn_flood", severity="critical", ip="10.0.0.1",
                         source="attack_detector", metadata={}, timestamp=time.time())
        engine.process_signal(sig3)

        # Check emitted signals
        recent = bus.get_recent()
        chain_signals = [s for s in recent if s.signal_type == "attack_chain_escalated"]
        assert len(chain_signals) >= 1, f"Expected attack_chain_escalated signal, got: {[s.signal_type for s in recent]}"

        # Verify metadata in escalated signal
        escalated = chain_signals[0]
        assert "phases" in escalated.metadata
        assert "chain_timeline" in escalated.metadata
        assert "recon" in escalated.metadata["phases"]

    def test_stats_include_escalated_count(self):
        """Incident stats include escalation info."""
        engine = CorrelationEngine()
        signals = [
            MagicMock(signal_type="port_scan", severity="medium", ip="10.0.0.1",
                      source="attack_detector", metadata={}, timestamp=time.time()),
            MagicMock(signal_type="behavior_deviation", severity="low", ip="10.0.0.1",
                      source="behavior_profiler", metadata={}, timestamp=time.time()),
            MagicMock(signal_type="syn_flood", severity="critical", ip="10.0.0.1",
                      source="attack_detector", metadata={}, timestamp=time.time()),
        ]
        for sig in signals:
            engine.process_signal(sig)

        stats = engine.get_incident_stats()
        assert "by_phase" in stats
        assert "recon" in stats["by_phase"]
        assert "probe" in stats["by_phase"]
        assert "attack" in stats["by_phase"]


def run_tests():
    """Run all tests and report results."""
    test_classes = [
        TestAttackPhasesMapping,
        TestIncidentChainTracking,
        TestAttackChainDetection,
        TestCrossSourceChainDetection,
        TestChainVisualization,
        TestCorrelationEngineChainIntegration,
    ]

    total = 0
    passed = 0
    failed = 0

    for cls in test_classes:
        instance = cls()
        for attr in sorted(dir(instance)):
            if attr.startswith("test_"):
                total += 1
                try:
                    method = getattr(instance, attr)
                    method()
                    passed += 1
                    print(f"  PASS: {cls.__name__}.{attr}")
                except AssertionError as e:
                    failed += 1
                    print(f"  FAIL: {cls.__name__}.{attr}: {e}")
                except Exception as e:
                    failed += 1
                    print(f"  ERROR: {cls.__name__}.{attr}: {e}")

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
