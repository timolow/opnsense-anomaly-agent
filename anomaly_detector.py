#!/usr/bin/env python3
"""
Anomaly Detector - integrated with agent.py
Detects: volume spikes, port scans, new IPs, protocol shifts, temporal anomalies
Supports dynamic threshold tuning via ThresholdTuner integration.
"""
import os
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Default thresholds (overridden by ThresholdTuner when integrated)
VOLUME_ZSCORE = 3.0      # z-score for volume spikes
PORT_SCAN_MIN = 10       # unique ports to trigger port scan alert
NEW_IP_MIN = 5           # events from new IP to alert
PROTOCOL_SHIFT = 0.15    # 15% protocol shift threshold
TEMPORAL_ZSCORE = 2.0    # z-score for temporal anomalies

# Default whitelisted internal IPs and ranges (never alert on these)
# Override via INTERNAL_IP_PREFIXES env var (comma-separated)
_DEFAULT_INTERNAL_PREFIXES = [
    "127.",              # localhost
    "192.168.1.",        # OPNsense LAN
    "192.168.222.",      # OPNsense OPT1
    "192.168.255.",      # OPNsense OPT2
    "10.1.1.",           # VPN LAN
    "10.1.2.",           # VPN OPT
    "fe80::",            # IPv6 link-local
    "ff02::",            # IPv6 multicast
]

def _parse_internal_prefixes() -> List[str]:
    """Parse INTERNAL_IP_PREFIXES from env var or return defaults."""
    env_val = os.environ.get("INTERNAL_IP_PREFIXES", "")
    if env_val:
        prefixes = [p.strip() for p in env_val.split(",") if p.strip()]
        logger.info("Using %d internal IP prefixes from env: %s", len(prefixes), prefixes)
        return prefixes
    return _DEFAULT_INTERNAL_PREFIXES.copy()


INTERNAL_IP_PREFIXES = _parse_internal_prefixes()

def is_internal_ip(ip: str) -> bool:
    """Check if an IP is whitelisted as internal."""
    if not ip:
        return True  # Empty IPs are internal/noise
    for prefix in INTERNAL_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


class AnomalyDetector:
    """Detects anomalies by comparing events against learned baselines."""

    def __init__(self, baselines, threshold_tuner=None):
        self.baselines = baselines
        self.threshold_tuner = threshold_tuner  # Optional ThresholdTuner
        self.ip_ports: Dict[str, set] = defaultdict(set)
        self.ip_counts: Dict[str, int] = defaultdict(int)
        self.rule_counts: Dict[str, int] = defaultdict(int)
        self.detected: List[Dict[str, Any]] = []
        self.detected_ips: set = set()  # Track IPs we've already alerted on
    
    def _get_threshold(self, name: str, default: float) -> float:
        """Get threshold value from tuner or fallback to module default."""
        if self.threshold_tuner:
            return self.threshold_tuner.get_threshold(name)
        return default

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
        zscore_threshold = self._get_threshold('volume_zscore', VOLUME_ZSCORE)
        if abs(z) >= zscore_threshold:
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
        port_scan_min = self._get_threshold('port_scan_min', PORT_SCAN_MIN)
        if len(ports) >= port_scan_min:
            sev = "CRITICAL" if len(ports) > 20 else "HIGH" if len(ports) > 10 else "MEDIUM"
            return {
                "type": "port_scan", "severity": sev, "rule": "any",
                "src_ip": ip, "ports_count": len(ports),
                "description": f"Port scan from {ip}: {len(ports)} unique ports"
            }
        return None

    def check_new_ip(self, ip: str, count: int) -> Optional[Dict]:
        """Check for IPs without baselines."""
        # Skip internal/whitelisted IPs
        if is_internal_ip(ip):
            return None
        new_ip_min = self._get_threshold('new_ip_min', NEW_IP_MIN)
        if count < new_ip_min:
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
                "description": f"New external IP {ip} with {count} events (no baseline)"
            }
        return None

    def check_temporal(self, rule: str, count_5min: int) -> Optional[Dict]:
        """Check for temporal anomalies using z-scores against hourly distribution.

        Compares current activity against the distribution of all 24 hours.
        A spike relative to the learned pattern triggers an alert.
        Catches: unusual activity at quiet hours, spikes during busy periods.
        """
        b = self.baselines.get(rule)
        if not b:
            return None
        # Handle both dict and TrafficBaseline objects
        hourly = (b.hourly_distribution
                   if hasattr(b, 'hourly_distribution')
                   else b.get("hourly", []))
        if not hourly:
            return None

        # Pad to 24 hours if distribution is incomplete
        dist = list(hourly) + [0.0] * (24 - len(hourly))

        # Compute population mean and stddev of the full distribution
        mean = sum(dist) / len(dist)
        variance = sum((x - mean) ** 2 for x in dist) / len(dist)
        stddev = variance ** 0.5

        # Skip if no variance (all hours identical — no temporal pattern to compare)
        if stddev < 0.1:
            return None

        hour = datetime.now(timezone.utc).hour
        current_rate = count_5min * 12  # extrapolate 5-min count to hourly rate
        expected_this_hour = dist[hour] if hour < len(dist) else 0.0

        # Z-score: how many stddevs away from the distribution mean is the current rate
        z = (current_rate - mean) / stddev

        # Also check ratio against this specific hour's baseline (catches quiet-hour spikes)
        # If the hour normally sees near-zero traffic, even a small absolute count is suspicious
        ratio_anomaly = False
        temporal_zscore = self._get_threshold('temporal_zscore', TEMPORAL_ZSCORE)
        if expected_this_hour < 1 and current_rate > 0:
            # Activity when there should be none — flag if rate is meaningfully above mean
            if current_rate > mean + temporal_zscore * stddev:
                ratio_anomaly = True

        if abs(z) >= temporal_zscore or ratio_anomaly:
            sev = ("CRITICAL" if abs(z) >= 5
                   else "HIGH" if abs(z) >= 4
                   else "MEDIUM")
            return {
                "type": "temporal_anomaly",
                "severity": sev,
                "rule": rule,
                "hour": hour,
                "current_5min": count_5min,
                "current_hourly_rate": current_rate,
                "baseline_mean": round(mean, 1),
                "baseline_std": round(stddev, 1),
                "baseline_this_hour": expected_this_hour,
                "z_score": round(z, 2),
                "description": (
                    f"Temporal anomaly on rule {rule}: {current_rate:.0f}/hr "
                    f"at {hour}:00 UTC (dist mean {mean:.0f}/hr, "
                    f"this hour expected {expected_this_hour:.0f}/hr, z={z:.1f})"
                ),
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