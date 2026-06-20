#!/usr/bin/env python3
"""
Anomaly Detection Engine for OPNsense Anomaly Agent.

Detects deviations from learned baselines including:
- Volume spikes (z-score based)
- Protocol distribution shifts
- Port scan patterns
- New IP detection
- Temporal anomalies
"""
import json
import math
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Thresholds
VOLUME_ZSCORE_THRESHOLD = 3.0
PROTOCOL_SHIFT_THRESHOLD = 0.15  # 15% shift
PORT_SCAN_THRESHOLD = 10  # Unique ports
TEMPORAL_ANOMALY_THRESHOLD = 2.0  # z-score for hourly patterns


class AnomalyEvent:
    """Represents a detected anomaly."""
    def __init__(self, anomaly_type: str, severity: str, rule: str, details: Dict[str, Any]):
        self.type = anomaly_type
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.rule = rule
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "rule": self.rule,
            "description": self.generate_description(),
            **self.details
        }

    def generate_description(self) -> str:
        if self.type == "volume_spike":
            return (f"Volume spike: {self.details.get('current_count', 0)} events "
                    f"(baseline avg: {self.details.get('baseline_avg', 0):.0f}, "
                    f"std: {self.details.get('baseline_std', 0):.0f}, "
                    f"z-score: {self.details.get('z_score', 0):.1f})")
        elif self.type == "protocol_shift":
            return (f"Protocol shift: {self.details.get('protocol', '')} "
                    f"actual={self.details.get('actual_ratio', 0):.1%} "
                    f"vs baseline={self.details.get('baseline_ratio', 0):.1%} "
                    f"(shift={self.details.get('shift', 0):.1%})")
        elif self.type == "port_scan":
            return (f"Port scan: {self.details.get('src_ip', '')} "
                    f"hit {self.details.get('ports_count', 0)} unique ports")
        elif self.type == "new_ip":
            return (f"New IP: {self.details.get('src_ip', '')} "
                    f"({self.details.get('event_count', 0)} events, no baseline)")
        elif self.type == "temporal_anomaly":
            return (f"Temporal anomaly: hour {self.details.get('hour', 0)}:00 "
                    f"actual={self.details.get('current_count', 0)} events "
                    f"vs baseline={self.details.get('baseline_hourly', 0):.0f}")
        return f"{self.type}: {self.details}"


class AnomalyDetector:
    """Detects anomalies by comparing events against learned baselines."""

    def __init__(self, baselines: Dict[str, Any]):
        """
        Initialize anomaly detector.

        Args:
            baselines: Dict mapping rule/IP to baseline objects
        """
        self.baselines = baselines
        self.ip_port_tracker: Dict[str, set] = defaultdict(set)
        self.ip_event_counts: Dict[str, int] = defaultdict(int)
        self.rule_event_counts: Dict[str, int] = defaultdict(int)
        self.detected_anomalies: List[AnomalyEvent] = []

    def detect_volume_anomaly(self, rule: str, current_count: int, baseline_avg: float,
                               baseline_std: float) -> Optional[AnomalyEvent]:
        """Detect volume spikes using z-score."""
        if baseline_std == 0:
            return None

        z_score = (current_count - baseline_avg) / baseline_std

        if abs(z_score) >= VOLUME_ZSCORE_THRESHOLD:
            severity = "CRITICAL" if abs(z_score) >= 5.0 else "HIGH" if abs(z_score) >= 4.0 else "MEDIUM"
            return AnomalyEvent(
                anomaly_type="volume_spike",
                severity=severity,
                rule=rule,
                details={
                    "current_count": current_count,
                    "baseline_avg": baseline_avg,
                    "baseline_std": baseline_std,
                    "z_score": z_score
                }
            )
        return None

    def detect_protocol_anomaly(self, rule: str, protocol: str, actual_ratio: float,
                                 baseline_ratio: float) -> Optional[AnomalyEvent]:
        """Detect protocol distribution shifts."""
        shift = abs(actual_ratio - baseline_ratio)

        if shift >= PROTOCOL_SHIFT_THRESHOLD:
            severity = "HIGH" if shift >= 0.3 else "MEDIUM"
            return AnomalyEvent(
                anomaly_type="protocol_shift",
                severity=severity,
                rule=rule,
                details={
                    "protocol": protocol,
                    "actual_ratio": actual_ratio,
                    "baseline_ratio": baseline_ratio,
                    "shift": shift
                }
            )
        return None

    def detect_port_scan(self, src_ip: str, ports: set) -> Optional[AnomalyEvent]:
        """Detect port scanning patterns."""
        if len(ports) >= PORT_SCAN_THRESHOLD:
            severity = "CRITICAL" if len(ports) > 20 else "HIGH" if len(ports) > 10 else "MEDIUM"
            return AnomalyEvent(
                anomaly_type="port_scan",
                severity=severity,
                rule="any",
                details={
                    "src_ip": src_ip,
                    "ports_count": len(ports),
                    "ports": list(ports)[:20]  # First 20 ports
                }
            )
        return None

    def detect_new_ip(self, src_ip: str, event_count: int) -> Optional[AnomalyEvent]:
        """Detect IPs that don't have baselines."""
        # Check if IP has any baseline
        has_baseline = False
        for key, baseline in self.baselines.items():
            if hasattr(baseline, 'ip') and baseline.ip == src_ip:
                has_baseline = True
                break

        if not has_baseline and event_count >= 5:
            severity = "MEDIUM" if event_count > 10 else "LOW"
            return AnomalyEvent(
                anomaly_type="new_ip",
                severity=severity,
                rule="any",
                details={
                    "src_ip": src_ip,
                    "event_count": event_count
                }
            )
        return None

    def detect_temporal_anomaly(self, rule: str, current_hour: int, current_count: int,
                                  hourly_baseline: List[float]) -> Optional[AnomalyEvent]:
        """Detect temporal anomalies (unusual activity for time of day)."""
        if not hourly_baseline or len(hourly_baseline) != 24:
            return None

        baseline_hourly = hourly_baseline[current_hour]
        if baseline_hourly == 0 and current_count > 0:
            # Activity when there should be none
            return AnomalyEvent(
                anomaly_type="temporal_anomaly",
                severity="HIGH",
                rule=rule,
                details={
                    "hour": current_hour,
                    "current_count": current_count,
                    "baseline_hourly": baseline_hourly
                }
            )

        # Check if current count is significantly higher than typical for this hour
        if baseline_hourly > 0:
            z_score = (current_count - baseline_hourly) / max(baseline_hourly * 0.5, 1)
            if z_score >= TEMPORAL_ANOMALY_THRESHOLD:
                return AnomalyEvent(
                    anomaly_type="temporal_anomaly",
                    severity="MEDIUM",
                    rule=rule,
                    details={
                        "hour": current_hour,
                        "current_count": current_count,
                        "baseline_hourly": baseline_hourly,
                        "z_score": z_score
                    }
                )
        return None

    def analyze_events(self, events: List[Dict[str, Any]]) -> List[AnomalyEvent]:
        """Analyze a batch of events against baselines."""
        anomalies = []

        # Reset counters
        self.rule_event_counts.clear()
        self.ip_port_tracker.clear()
        self.ip_event_counts.clear()

        # Collect event statistics
        for event in events:
            rule = event.get("rule", "")
            src_ip = event.get("src_ip", "")
            dst_port = event.get("dst_port")
            protocol = event.get("protocol", "")

            if rule:
                self.rule_event_counts[rule] += 1
            if src_ip:
                self.ip_event_counts[src_ip] += 1
            if src_ip and dst_port:
                self.ip_port_tracker[src_ip].add(dst_port)

        # Check volume anomalies
        for rule, count in self.rule_event_counts.items():
            baseline = self.baselines.get(rule)
            if baseline and hasattr(baseline, 'avg_events_per_hour'):
                # Extrapolate count to hourly rate (assuming 5 min window)
                hourly_count = count * 12
                anomaly = self.detect_volume_anomaly(
                    rule=rule,
                    current_count=hourly_count,
                    baseline_avg=baseline.avg_events_per_hour,
                    baseline_std=baseline.std_events_per_hour
                )
                if anomaly:
                    anomalies.append(anomaly)

        # Check port scans
        for src_ip, ports in self.ip_port_tracker.items():
            anomaly = self.detect_port_scan(src_ip, ports)
            if anomaly:
                anomalies.append(anomaly)

        # Check for new IPs
        for src_ip, count in self.ip_event_counts.items():
            anomaly = self.detect_new_ip(src_ip, count)
            if anomaly:
                anomalies.append(anomaly)

        # Check temporal anomalies
        from datetime import datetime, timezone
        current_hour = datetime.now(timezone.utc).hour
        for rule, count in self.rule_event_counts.items():
            baseline = self.baselines.get(rule)
            if baseline and hasattr(baseline, 'hourly_distribution'):
                anomaly = self.detect_temporal_anomaly(
                    rule=rule,
                    current_hour=current_hour,
                    current_count=count * 12,  # Extrapolate to hourly
                    hourly_baseline=baseline.hourly_distribution
                )
                if anomaly:
                    anomalies.append(anomaly)

        self.detected_anomalies = anomalies
        return anomalies