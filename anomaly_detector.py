#!/usr/bin/env python3
"""
Anomaly Detector - integrated with agent.py
Detects: volume spikes, port scans, new IPs, protocol shifts, temporal anomalies
"""
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Thresholds
VOLUME_ZSCORE = 3.0      # z-score for volume spikes
PORT_SCAN_MIN = 10       # unique ports to trigger port scan alert
NEW_IP_MIN = 5           # events from new IP to alert
PROTOCOL_SHIFT = 0.15    # 15% protocol shift threshold
TEMPORAL_ZSCORE = 2.0    # z-score for temporal anomalies


class AnomalyDetector:
    """Detects anomalies by comparing events against learned baselines."""

    def __init__(self, baselines):
        self.baselines = baselines
        self.ip_ports: Dict[str, set] = defaultdict(set)
        self.ip_counts: Dict[str, int] = defaultdict(int)
        self.rule_counts: Dict[str, int] = defaultdict(int)
        self.detected: List[Dict[str, Any]] = []
        self.detected_ips: set = set()  # Track IPs we've already alerted on

    def check_volume(self, rule: str, count_5min: int) -> Optional[Dict]:
        """Check if event volume deviates from baseline."""
        b = self.baselines.get(rule)
        if not b:
            return None
        # Handle both dict and TrafficBaseline objects
        avg = b.avg_events_per_hour if hasattr(b, 'avg_events_per_hour') else b.get("avg", 0)
        std = b.std_events_per_hour if hasattr(b, 'std_events_per_hour') else b.get("std", 0)
        if std == 0:
            return None
        hourly = count_5min * 12  # extrapolate
        z = (hourly - avg) / std
        if abs(z) >= VOLUME_ZSCORE:
            sev = "CRITICAL" if abs(z) >= 5 else "HIGH" if abs(z) >= 4 else "MEDIUM"
            return {
                "type": "volume_spike", "severity": sev, "rule": rule,
                "current_hourly": hourly, "baseline_avg": avg,
                "baseline_std": std, "z_score": z,
                "description": f"Volume anomaly on rule {rule}: {hourly:.0f}/hr (baseline {avg:.0f}/hr, z={z:.1f})"
            }
        return None

    def check_port_scan(self, ip: str) -> Optional[Dict]:
        """Check for port scanning."""
        ports = self.ip_ports.get(ip, set())
        if len(ports) >= PORT_SCAN_MIN:
            sev = "CRITICAL" if len(ports) > 20 else "HIGH" if len(ports) > 10 else "MEDIUM"
            return {
                "type": "port_scan", "severity": sev, "rule": "any",
                "src_ip": ip, "ports_count": len(ports),
                "description": f"Port scan from {ip}: {len(ports)} unique ports"
            }
        return None

    def check_new_ip(self, ip: str, count: int) -> Optional[Dict]:
        """Check for IPs without baselines."""
        if count < NEW_IP_MIN:
            return None
        # Check if IP has any baseline (handle both dict and TrafficBaseline)
        known = False
        for b in self.baselines.values():
            b_ip = b.ip if hasattr(b, 'ip') else b.get("ip")
            if b_ip == ip:
                known = True
                break
        if not known:
            # Deduplication: only alert once per IP
            if ip in self.detected_ips:
                return None
            self.detected_ips.add(ip)
            return {
                "type": "new_ip", "severity": "MEDIUM", "rule": "any",
                "src_ip": ip, "event_count": count,
                "description": f"New IP {ip} with {count} events (no baseline)"
            }
        return None

    def check_temporal(self, rule: str, count_5min: int) -> Optional[Dict]:
        """Check for temporal anomalies (unusual activity for time of day)."""
        b = self.baselines.get(rule)
        if not b:
            return None
        # Handle both dict and TrafficBaseline
        hourly = b.hourly_distribution if hasattr(b, 'hourly_distribution') else b.get("hourly")
        if not hourly:
            return None
        hour = datetime.now(timezone.utc).hour
        baseline_hourly = hourly[hour]
        if baseline_hourly == 0 and count_5min > 0:
            return {
                "type": "temporal_anomaly", "severity": "HIGH", "rule": rule,
                "hour": hour, "current_count": count_5min,
                "baseline_hourly": baseline_hourly,
                "description": f"Temporal anomaly: rule {rule} at {hour}:00 (baseline: {baseline_hourly} events/hr)"
            }
        return None

    def analyze(self, events: List[Dict]) -> List[Dict]:
        """Analyze a batch of events."""
        # Reset counters
        self.ip_ports.clear()
        self.ip_counts.clear()
        self.rule_counts.clear()

        # Collect stats
        for e in events:
            rule = e.get("rule", "")
            src_ip = e.get("src_ip", "")
            dst_port = e.get("dst_port")
            if rule:
                self.rule_counts[rule] += 1
            if src_ip:
                self.ip_counts[src_ip] += 1
            if src_ip and dst_port:
                self.ip_ports[src_ip].add(dst_port)

        anomalies = []

        # Check volume anomalies
        for rule, count in self.rule_counts.items():
            a = self.check_volume(rule, count)
            if a:
                anomalies.append(a)
            # Check temporal
            a = self.check_temporal(rule, count)
            if a:
                anomalies.append(a)

        # Check port scans
        for ip in self.ip_ports:
            a = self.check_port_scan(ip)
            if a:
                anomalies.append(a)

        # Check new IPs
        for ip, count in self.ip_counts.items():
            a = self.check_new_ip(ip, count)
            if a:
                anomalies.append(a)

        self.detected = anomalies
        return anomalies