#!/usr/bin/env python3
"""Tests for structured detection decision logging (detection_logging.py).

Verifies:
  1. DetectionLogger produces valid JSON on every decision
  2. All required fields are present and correctly typed
  3. log_alert / log_suppressed / log_decision all emit the full schema
  4. build_explanation generates human-readable strings
  5. Integration: detection logs from agent.py detection paths are parseable
"""

import json
import logging
import sys
import os
import re
from io import StringIO
from typing import Any, Dict, List

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection_logging import (
    DetectionLogger,
    get_detection_logger,
    REQUIRED_FIELDS,
    VALID_DECISIONS,
    VALID_SEVERITIES,
)


class TestDetectionLoggerInit:
    """Test DetectionLogger factory and constructor."""

    def test_factory(self):
        dl = get_detection_logger("test_module")
        assert isinstance(dl, DetectionLogger)

    def test_constructor(self):
        dl = DetectionLogger("explicit_name")
        assert dl._slog is not None


class TestLogDecisionSchema:
    """Test that log_decision emits all required fields with correct types."""

    def setup_method(self):
        # Capture structured log output via a custom handler
        self.captured: List[str] = []
        self.handler = _JsonCaptureHandler(self.captured)
        root = logging.getLogger()
        root.addHandler(self.handler)
        root.setLevel(logging.DEBUG)
        self.dl = get_detection_logger("test_schema")

    def teardown_method(self):
        logging.getLogger().removeHandler(self.handler)

    def _get_last_record(self) -> Dict[str, Any]:
        assert self.captured, "No log records captured"
        return json.loads(self.captured[-1])

    def test_log_decision_all_fields_present(self):
        self.dl.log_decision(
            event_id="evt-1",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            detection_module="test",
            decision="ALERT",
            score=0.95,
            severity="HIGH",
            signal_types=["PORT_SCAN"],
            threshold=15,
            action_taken="discord",
            explanation="Flagged because: port_scan (15 ports in 120s)",
            detail={"ports": 15},
        )
        record = self._get_last_record()
        for field in REQUIRED_FIELDS:
            assert field in record, f"Missing required field: {field}"
        # Additional schema fields
        assert "event_id" in record
        assert "dst_ip" in record
        assert "threshold" in record
        assert "action_taken" in record
        assert "detail" in record

    def test_log_decision_types(self):
        self.dl.log_decision(
            detection_module="test",
            decision="ALERT",
            score=1.0,
            severity="CRITICAL",
            signal_types=["A", "B"],
            explanation="test",
        )
        record = self._get_last_record()
        assert isinstance(record["detection_id"], str)
        assert len(record["detection_id"]) == 36  # UUID4 format
        assert isinstance(record["timestamp"], str)
        assert "T" in record["timestamp"]  # ISO 8601
        assert isinstance(record["signal_types"], list)
        assert isinstance(record["detail"], dict)
        assert isinstance(record["score"], float)
        assert record["decision"] in VALID_DECISIONS
        assert record["severity"] in VALID_SEVERITIES

    def test_log_decision_returns_id(self):
        det_id = self.dl.log_decision(
            detection_module="test",
            decision="ALERT",
            score=0.5,
            severity="LOW",
            signal_types=["TEST"],
            explanation="test",
        )
        assert isinstance(det_id, str)
        assert len(det_id) == 36  # UUID4

    def test_log_decision_normalizes_decision(self):
        self.dl.log_decision(
            detection_module="test",
            decision="alert",  # lowercase
            score=0.5,
            severity="low",   # lowercase
            signal_types=["X"],
            explanation="test",
        )
        record = self._get_last_record()
        assert record["decision"] == "ALERT"
        assert record["severity"] == "LOW"

    def test_log_decision_invalid_decision_defaults_to_alert(self):
        self.dl.log_decision(
            detection_module="test",
            decision="UNKNOWN",
            score=0.5,
            severity="MEDIUM",
            signal_types=["X"],
            explanation="test",
        )
        record = self._get_last_record()
        assert record["decision"] == "ALERT"

    def test_log_alert_shortcut(self):
        det_id = self.dl.log_alert(
            src_ip="10.0.0.1",
            detection_module="geo",
            score=0.8,
            severity="MEDIUM",
            signal_types=["GEO_ANOMALY"],
            explanation="New country CN",
        )
        assert det_id
        record = self._get_last_record()
        assert record["decision"] == "ALERT"
        assert record["src_ip"] == "10.0.0.1"
        assert record["action_taken"] == "discord+apprise"

    def test_log_suppressed_shortcut(self):
        det_id = self.dl.log_suppressed(
            src_ip="10.0.0.1",
            detection_module="attack_detector",
            signal_types=["PORT_SCAN"],
            explanation="Muted IP",
        )
        assert det_id
        record = self._get_last_record()
        assert record["decision"] == "SUPPRESSED"
        assert record["action_taken"] == "muted"


class TestBuildExplanation:
    """Test human-readable explanation generation."""

    def setup_method(self):
        self.dl = DetectionLogger("test_explain")

    def test_port_scan_explanation(self):
        result = self.dl.build_explanation(
            ["PORT_SCAN"],
            {"distinct_ports": 15},
        )
        assert "port_scan" in result
        assert "15" in result
        assert "Flagged because" in result

    def test_syn_flood_explanation(self):
        result = self.dl.build_explanation(
            ["SYN_FLOOD"],
            {"syn_count": 200},
        )
        assert "syn_flood" in result
        assert "200" in result

    def test_brute_force_explanation(self):
        result = self.dl.build_explanation(
            ["BRUTE_FORCE"],
            {"attempt_count": 25},
        )
        assert "brute_force" in result
        assert "25" in result

    def test_multi_signal_explanation(self):
        result = self.dl.build_explanation(
            ["PORT_SCAN", "SYN_FLOOD"],
            {"distinct_ports": 15, "syn_count": 200},
        )
        assert "port_scan" in result
        assert "syn_flood" in result

    def test_empty_signals(self):
        result = self.dl.build_explanation([], {})
        assert "anomalous behavior" in result

    def test_geo_explanation(self):
        result = self.dl.build_explanation(
            ["new_country"],
            {"country_code": "CN"},
        )
        assert "cn" in result.lower()

    def test_baseline_deviation_explanation(self):
        result = self.dl.build_explanation(
            ["baseline_deviation"],
            {"z_score": 4.5},
        )
        assert "4.5" in result


class TestJsonValidity:
    """End-to-end: verify every log line is valid JSON and parseable."""

    def setup_method(self):
        self.captured: List[str] = []
        self.handler = _JsonCaptureHandler(self.captured)
        root = logging.getLogger()
        root.addHandler(self.handler)
        root.setLevel(logging.DEBUG)
        self.dl = get_detection_logger("test_json")

    def teardown_method(self):
        logging.getLogger().removeHandler(self.handler)

    def test_all_decision_types_produce_valid_json(self):
        # ALERT
        self.dl.log_alert(
            src_ip="1.2.3.4",
            detection_module="attack_detector",
            score=0.9,
            severity="HIGH",
            signal_types=["PORT_SCAN"],
            explanation="Test alert",
            detail={"ports": 15},
        )
        # SUPPRESSED
        self.dl.log_suppressed(
            src_ip="1.2.3.4",
            detection_module="attack_detector",
            signal_types=["PORT_SCAN"],
            explanation="Muted",
        )
        # OK
        self.dl.log_decision(
            detection_module="test",
            decision="OK",
            score=0.0,
            severity="LOW",
            signal_types=[],
            explanation="All clear",
        )

        assert len(self.captured) == 3
        for i, line in enumerate(self.captured):
            record = json.loads(line)  # must not raise
            for field in REQUIRED_FIELDS:
                assert field in record, f"Line {i}: missing {field}"

    def test_detail_with_nested_objects(self):
        self.dl.log_decision(
            detection_module="test",
            decision="ALERT",
            score=1.0,
            severity="CRITICAL",
            signal_types=["COMPLEX"],
            explanation="Complex detail",
            detail={
                "nested": {"key": "value"},
                "list_val": [1, 2, 3],
                "description": "Test with 'quotes' and special chars: \n\t",
            },
        )
        line = self.captured[-1]
        record = json.loads(line)
        assert record["detail"]["nested"]["key"] == "value"
        assert record["detail"]["list_val"] == [1, 2, 3]

    def test_uuid_uniqueness(self):
        ids = set()
        for _ in range(10):
            det_id = self.dl.log_decision(
                detection_module="test",
                decision="ALERT",
                score=0.5,
                severity="MEDIUM",
                signal_types=["UNIQUE"],
                explanation="test",
            )
            ids.add(det_id)
        assert len(ids) == 10, "UUIDs should all be unique"


class TestIntegrationAgentPaths:
    """Simulate detection paths from agent.py to verify structured logging."""

    def setup_method(self):
        self.captured: List[str] = []
        self.handler = _JsonCaptureHandler(self.captured)
        root = logging.getLogger()
        root.addHandler(self.handler)
        root.setLevel(logging.DEBUG)
        self.dl = get_detection_logger("agent_test")

    def teardown_method(self):
        logging.getLogger().removeHandler(self.handler)

    def test_attack_detector_path(self):
        """Simulate _process_batch attack detection path."""
        attack = {
            "attack_type": "PORT_SCAN",
            "src_ip": "203.0.113.5",
            "dst_ip": "10.0.0.1",
            "severity": "HIGH",
            "description": "Port scan: 203.0.113.5 hit 25 distinct ports in 120s",
            "detail": {"distinct_ports": 25, "threshold": 15, "scan_subtype": "VERTICAL"},
        }
        explanation = self.dl.build_explanation([attack["attack_type"]], attack["detail"])
        self.dl.log_alert(
            src_ip=attack["src_ip"],
            dst_ip=attack["dst_ip"],
            detection_module="attack_detector",
            score=0.9,
            severity=attack["severity"],
            signal_types=[attack["attack_type"]],
            threshold=attack["detail"].get("threshold"),
            explanation=explanation,
            detail=attack["detail"],
        )
        record = json.loads(self.captured[-1])
        assert record["detection_module"] == "attack_detector"
        assert record["src_ip"] == "203.0.113.5"
        assert record["decision"] == "ALERT"
        assert "25" in record["explanation"]

    def test_geo_anomaly_path(self):
        """Simulate geo anomaly detection path."""
        self.dl.log_alert(
            src_ip="198.51.100.7",
            detection_module="geo_anomaly",
            score=0.8,
            severity="MEDIUM",
            signal_types=["GEO_ANOMALY"],
            explanation="Flagged because: new_country (RU)",
            detail={"country_code": "RU", "country_name": "Russia"},
        )
        record = json.loads(self.captured[-1])
        assert record["detection_module"] == "geo_anomaly"
        assert record["detail"]["country_code"] == "RU"

    def test_muted_attack_path(self):
        """Simulate muted/suppressed attack path."""
        self.dl.log_suppressed(
            src_ip="10.0.0.99",
            detection_module="attack_detector",
            signal_types=["PORT_SCAN"],
            explanation="Muted: PORT_SCAN from 10.0.0.99 (alert suppression active)",
        )
        record = json.loads(self.captured[-1])
        assert record["decision"] == "SUPPRESSED"
        assert record["action_taken"] == "muted"

    def test_ids_anomaly_path(self):
        """Simulate IDS signature anomaly path."""
        self.dl.log_alert(
            detection_module="ids_signature_analyzer",
            src_ip="",
            score=0.8,
            severity="HIGH",
            signal_types=["SIGNATURE_SPIKE"],
            explanation="Flagged because: signature_spike (42 triggers)",
            detail={
                "signature": "ET SCAN Nmap",
                "trigger_count": 42,
                "z_score": 3.5,
            },
        )
        record = json.loads(self.captured[-1])
        assert record["detection_module"] == "ids_signature_analyzer"
        assert record["detail"]["trigger_count"] == 42

    def test_wan_flap_path(self):
        """Simulate WAN flap detection path."""
        self.dl.log_alert(
            detection_module="wan_flap_detector",
            src_ip="",
            score=0.8,
            severity="HIGH",
            signal_types=["WAN_FLAP"],
            explanation="Flagged because: wan_flap (gateway wan1 flapped up->down)",
            detail={
                "gateway": "wan1",
                "old_state": "up",
                "new_state": "down",
            },
        )
        record = json.loads(self.captured[-1])
        assert record["detection_module"] == "wan_flap_detector"
        assert record["detail"]["old_state"] == "up"

    def test_baseline_anomaly_path(self):
        """Simulate baseline deviation path."""
        self.dl.log_alert(
            src_ip="192.168.1.50",
            detection_module="anomaly_detector",
            score=4.5,
            severity="HIGH",
            signal_types=["BASELINE_DEVIATION"],
            threshold=3.0,
            explanation="Flagged because: baseline_deviation (z_score=4.5)",
            detail={"z_score": 4.5, "rule": "FW-001"},
        )
        record = json.loads(self.captured[-1])
        assert record["detection_module"] == "anomaly_detector"
        assert record["threshold"] == 3.0
        assert record["score"] == 4.5


# ── Helpers ────────────────────────────────────────────────────────────

class _JsonCaptureHandler(logging.Handler):
    """Capture log records as JSON strings for testing."""

    def __init__(self, capture_list: list) -> None:
        super().__init__()
        self.capture_list = capture_list
        # Use the same formatter as the real agent
        from json_logging import JsonFormatter
        self.setFormatter(JsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
            # Only capture DETECTION_DECISION lines
            if "DETECTION_DECISION" in line:
                self.capture_list.append(line)
        except Exception:
            pass
