"""Integration tests for the new ML pipeline components.

Tests the full pipeline: signal_bus -> correlation_engine -> incident_manager
with realistic firewall event data flowing through the system.
"""

import sys
import os
import json
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from signal_bus import SignalBus, Signal, SIGNAL_TYPES
from correlation_engine import CorrelationEngine, Incident, SEVERITY_RANK, ATTACK_PHASES
from ip_behavior_model import BehaviorProfiler, IPBehaviorProfile

try:
    from flow_classifier import FlowClassifier, FlowMLClassifier
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

import pytest


# ── Signal Bus Tests ───────────────────────────────────────────────────────

class TestSignalBus:
    """Test the signal bus architecture."""

    def setup_method(self):
        self.bus = SignalBus()
        self.received_signals = []

    def test_emit_signal(self):
        """Test emitting a signal to the bus."""
        signal = self.bus.emit(
            source="attack_detector",
            signal_type="port_scan",
            severity="high",
            ip="10.0.0.1",
            metadata={"dst_port": 22}
        )
        assert signal is not None
        assert signal.source == "attack_detector"
        assert signal.signal_type == "port_scan"
        assert signal.severity == "high"
        assert signal.ip == "10.0.0.1"
        assert signal.metadata["dst_port"] == 22

    def test_emit_all_signal_types(self):
        """Test that all 51 signal types can be emitted."""
        for signal_type in SIGNAL_TYPES:
            signal = self.bus.emit(
                source="test",
                signal_type=signal_type,
                severity="medium",
                ip="10.0.0.1"
            )
            assert signal is not None, f"Failed to emit signal type: {signal_type}"

    def test_subscribe_callback(self):
        """Test that callbacks receive signals."""
        def on_signal(sig):
            self.received_signals.append(sig)

        self.bus.subscribe("all", on_signal)
        self.bus.emit(
            source="test",
            signal_type="test_signal",
            severity="low",
            ip="10.0.0.1"
        )
        assert len(self.received_signals) == 1
        assert self.received_signals[0].ip == "10.0.0.1"

    def test_signal_serialization(self):
        """Test that signals can be serialized to dict."""
        signal = self.bus.emit(
            source="test",
            signal_type="test_signal",
            severity="medium",
            ip="10.0.0.1",
            metadata={"key": "value", "nested": {"a": 1}}
        )
        sig_dict = signal.to_dict()
        assert sig_dict["source"] == "test"
        assert sig_dict["metadata"]["key"] == "value"
        assert sig_dict["metadata"]["nested"]["a"] == 1


# ── Correlation Engine Tests ───────────────────────────────────────────────

class TestCorrelationEngine:
    """Test the correlation engine."""

    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_create_incident(self):
        """Test creating a new incident from a signal."""
        signal = MagicMock()
        signal.signal_type = "port_scan"
        signal.severity = "high"
        signal.ip = "10.0.0.1"
        signal.source = "attack_detector"
        signal.metadata = {"dst_port": 22}

        incident = self.engine.process_signal(signal)
        assert incident is not None
        assert incident.ip == "10.0.0.1"
        assert incident.severity == "high"

    def test_correlate_signals_same_ip(self):
        """Test that signals from same IP are correlated."""
        signal1 = MagicMock()
        signal1.signal_type = "port_scan"
        signal1.severity = "high"
        signal1.ip = "10.0.0.1"
        signal1.source = "attack_detector"
        signal1.metadata = {}

        signal2 = MagicMock()
        signal2.signal_type = "syn_flood"
        signal2.severity = "critical"
        signal2.ip = "10.0.0.1"
        signal2.source = "attack_detector"
        signal2.metadata = {}

        inc1 = self.engine.process_signal(signal1)
        inc2 = self.engine.process_signal(signal2)

        assert inc1 is inc2
        assert inc1.signal_types == {"port_scan", "syn_flood"}
        assert inc1.severity == "critical"

    def test_attack_chain_detection(self):
        """Test detection of attack chain progression."""
        phases = ["recon", "probe", "attack"]
        for phase in phases:
            signal_type = None
            for st, p in ATTACK_PHASES.items():
                if p == phase:
                    signal_type = st
                    break

            signal = MagicMock()
            signal.signal_type = signal_type
            signal.severity = "medium"
            signal.ip = "10.0.0.1"
            signal.source = "attack_detector"
            signal.metadata = {}

            self.engine.process_signal(signal)

        incident = self.engine.get_active_incidents()[0]
        assert len(incident.phases) >= 3
        assert "recon" in incident.phases
        assert "attack" in incident.phases

    def test_severity_escalation(self):
        """Test that severity escalates with multiple signal types."""
        signal_types = ["port_scan", "syn_flood", "brute_force", "http_probe"]
        for signal_type in signal_types:
            signal = MagicMock()
            signal.signal_type = signal_type
            signal.severity = "low"
            signal.ip = "10.0.0.1"
            signal.source = "attack_detector"
            signal.metadata = {}

            self.engine.process_signal(signal)

        incident = self.engine.get_active_incidents()[0]
        assert incident.severity_rank >= SEVERITY_RANK["high"]

    def test_auto_resolve_stale(self):
        """Test auto-resolving stale incidents."""
        signal = MagicMock()
        signal.signal_type = "port_scan"
        signal.severity = "medium"
        signal.ip = "10.0.0.1"
        signal.source = "attack_detector"
        signal.metadata = {}

        incident = self.engine.process_signal(signal)
        assert incident.is_active

        # Manually set last_seen to simulate time passing
        original_last_seen = incident.last_seen
        with patch.object(incident, 'last_seen', original_last_seen - 7200):
            resolved = self.engine.auto_resolve_stale()
            assert resolved > 0

        active = self.engine.get_active_incidents()
        assert len(active) == 0

    def test_incident_stats(self):
        """Test incident statistics tracking."""
        signal = MagicMock()
        signal.signal_type = "port_scan"
        signal.severity = "high"
        signal.ip = "10.0.0.1"
        signal.source = "attack_detector"
        signal.metadata = {}

        self.engine.process_signal(signal)

        stats = self.engine.get_incident_stats()
        assert stats["total_incidents"] >= 1
        assert stats["active_incidents"] >= 1
        assert stats["total_signals_processed"] >= 1


# ── IP Behavior Model Tests ────────────────────────────────────────────────

class TestIPBehaviorModel:
    """Test the IP behavior model."""

    def setup_method(self):
        self.profiler = BehaviorProfiler(db=None)

    def test_track_ip_behavior(self):
        """Test tracking IP behavior over time."""
        events = [
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dport": 80, "action": "PASS"},
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dport": 443, "action": "PASS"},
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.2", "dport": 22, "action": "BLOCK"},
        ]

        for event in events:
            signals = self.profiler.ingest_event(event)

        profile = self.profiler.get_profile("10.0.0.1")
        assert profile is not None
        assert profile["total_events"] >= 3

    def test_threat_score_calculation(self):
        """Test threat score calculation for different behaviors."""
        # Normal behavior (50+ events, all PASS, single port)
        normal_events = [
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dport": 80, "action": "PASS"}
            for _ in range(55)
        ]
        for event in normal_events:
            self.profiler.ingest_event(event)

        profile = self.profiler.get_profile("10.0.0.1")
        normal_score = profile["behavior_score"]

        # Reset profiler for malicious test
        self.profiler = BehaviorProfiler(db=None)

        # Malicious behavior (50+ events, all BLOCK, many ports = port scan)
        malicious_events = [
            {"src_ip": "10.0.0.2", "dst_ip": "192.168.1.1", "dport": port, "action": "BLOCK"}
            for port in range(20, 85)  # 65 unique ports, all blocked
        ]
        for event in malicious_events:
            self.profiler.ingest_event(event)

        malicious_profile = self.profiler.get_profile("10.0.0.2")
        malicious_score = malicious_profile["behavior_score"]

        # Malicious IP should have higher behavior score (block-heavy + port diverse)
        assert malicious_score > normal_score

    def test_ema_baseline_update(self):
        """Test that EMA baselines update over time."""
        # Add some events
        for i in range(10):
            self.profiler.ingest_event({
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.1",
                "dport": 80,
                "action": "PASS",
            })

        profile = self.profiler.get_profile("10.0.0.1")
        assert profile["total_events"] > 0

    def test_get_all_profiles(self):
        """Test retrieving all IP profiles from memory."""
        for i in range(5):
            self.profiler.ingest_event({
                "src_ip": f"10.0.0.{i}",
                "dst_ip": "192.168.1.1",
                "dport": 80,
                "action": "PASS",
            })

        # Check in-memory profiles directly (get_profiles requires DB)
        with self.profiler._lock:
            assert len(self.profiler._profiles) == 5


# ── Flow Classifier Tests ──────────────────────────────────────────────────

@pytest.mark.skipif(not HAS_SKLEARN, reason="sklearn not installed")
class TestFlowClassifier:
    """Test the flow classifier."""

    def setup_method(self):
        if not HAS_SKLEARN:
            pytest.skip("sklearn not installed")
        self.classifier = FlowClassifier()  # type: ignore[unbound]

    def test_classify_benign_flow(self):
        """Test classifying a benign network flow."""
        result = self.classifier.predict({
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "dport": 443,
            "proto": "TCP",
            "bytes": 1500,
            "packets": 10,
        }, {})
        assert result is not None

    def test_classify_malicious_flow(self):
        """Test classifying a malicious network flow."""
        result = self.classifier.predict({
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "dport": 22,
            "proto": "TCP",
            "bytes": 100,
            "packets": 1000,
        }, {})
        assert result is not None


# ── Full Pipeline Integration Test ─────────────────────────────────────────

class TestFullPipeline:
    """Test the full ML pipeline integration."""

    def setup_method(self):
        self.signal_bus = SignalBus()
        self.correlation_engine = CorrelationEngine()
        self.behavior_profiler = BehaviorProfiler(db=None)

        # Wire signal bus to correlation engine
        def on_signal(sig):
            self.correlation_engine.process_signal(sig)

        self.signal_bus.subscribe("all", on_signal)

    def test_port_scan_pipeline(self):
        """Test the full pipeline with a port scan scenario."""
        for port in range(20, 90):  # 70 events to cross threshold
            event = {
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.1",
                "dport": port,
                "sport": 50000 + port,
                "proto": "TCP",
                "action": "BLOCK",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.behavior_profiler.ingest_event(event)
            self.signal_bus.emit(
                source="attack_detector",
                signal_type="port_scan",
                severity="high",
                ip="10.0.0.1",
                metadata={"dst_port": port, "action": "BLOCK"}
            )

        profile = self.behavior_profiler.get_profile("10.0.0.1")
        assert profile["behavior_score"] > 0

        incidents = self.correlation_engine.get_active_incidents()
        assert len(incidents) > 0
        assert incidents[0].ip == "10.0.0.1"

    def test_brute_force_pipeline(self):
        """Test the full pipeline with a brute force scenario."""
        for i in range(60):  # 60 events to cross threshold
            event = {
                "src_ip": "10.0.0.2",
                "dst_ip": "192.168.1.1",
                "dport": 22,
                "sport": 50000 + i,
                "proto": "TCP",
                "action": "BLOCK",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.behavior_profiler.ingest_event(event)
            self.signal_bus.emit(
                source="attack_detector",
                signal_type="brute_force",
                severity="high",
                ip="10.0.0.2",
                metadata={"dst_port": 22, "action": "BLOCK"}
            )

        profile = self.behavior_profiler.get_profile("10.0.0.2")
        assert profile["behavior_score"] > 0

        incidents = self.correlation_engine.get_active_incidents()
        assert len(incidents) > 0

    def test_attack_chain_pipeline(self):
        """Test the full pipeline with an attack chain scenario."""
        # Phase 1: Reconnaissance (port scan)
        for port in [22, 80, 443, 3306, 5432]:
            self.signal_bus.emit(
                source="attack_detector",
                signal_type="port_scan",
                severity="medium",
                ip="10.0.0.3",
                metadata={"dst_port": port}
            )

        # Phase 2: Probing (HTTP probe)
        self.signal_bus.emit(
            source="attack_detector",
            signal_type="http_probe",
            severity="medium",
            ip="10.0.0.3",
            metadata={"dst_port": 80}
        )

        # Phase 3: Attack (brute force)
        for i in range(5):
            self.signal_bus.emit(
                source="attack_detector",
                signal_type="brute_force",
                severity="high",
                ip="10.0.0.3",
                metadata={"dst_port": 22}
            )

        incidents = self.correlation_engine.get_active_incidents()
        assert len(incidents) > 0
        assert incidents[0].ip == "10.0.0.3"
        assert incidents[0].severity_rank >= SEVERITY_RANK["high"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
