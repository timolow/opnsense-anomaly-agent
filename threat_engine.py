#!/usr/bin/env python3
"""
Unified Threat Engine for OPNsense Anomaly Detection

Correlates events from all sources (firewall, HTTP, IDS, ZenArmor, nginx)
into a unified threat score per IP. Replaces 10 siloed modules with one brain.

Architecture:
- Ingests events from all sources
- Scores threats per IP using multiple signals
- Correlates cross-source patterns
- Outputs actionable alerts to Discord/Apprise
- Feeds the dashboard API

Usage:
    from threat_engine import ThreatEngine
    engine = ThreatEngine(db_connection, baseline_engine)
    threat_score = engine.score_ip(ip_address)
    engine.ingest_firewall_event(event)
    engine.ingest_http_event(event)
"""

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Configuration ──
THREAT_SCORE_MAX = 100
THREAT_SCORE_CRITICAL = 90
THREAT_SCORE_HIGH = 70
THREAT_SCORE_MEDIUM = 40
THREAT_SCORE_LOW = 20

# Signal weights
SIGNAL_WEIGHTS = {
    "firewall_block_ratio": 0.25,
    "firewall_port_scan": 0.30,
    "firewall_dest_scan": 0.25,
    "http_anomaly": 0.20,
    "ids_signature": 0.35,
    "zenarmor_threat": 0.40,
    "nginx_attack": 0.25,
    "volume_anomaly": 0.15,
    "temporal_anomaly": 0.10,
    "geo_anomaly": 0.15
}

# Decay settings
SCORE_DECAY_RATE = 0.95  # Per hour
SCORE_DECAY_MIN = 0.1    # Minimum decay

@dataclass
class ThreatSignal:
    """A single threat signal from one source."""
    source: str
    signal_type: str
    score: float
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0

@dataclass
class IPThreatProfile:
    """Unified threat profile for a single IP."""
    ip: str
    unified_score: float = 0.0
    signals: List[ThreatSignal] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    firewall_events: int = 0
    http_events: int = 0
    ids_events: int = 0
    zenarmor_events: int = 0
    nginx_events: int = 0
    baseline_deviations: List[float] = field(default_factory=list)
    geo_info: Optional[Dict[str, Any]] = None

class ThreatEngine:
    """Unified threat scoring and correlation engine."""
    
    def __init__(self, db_connection, baseline_engine=None):
        self.db = db_connection
        self.baseline_engine = baseline_engine
        self._ip_profiles: Dict[str, IPThreatProfile] = {}
        self._signal_cache: Dict[str, List[ThreatSignal]] = defaultdict(list)
    
    def ingest_firewall_event(self, event: Dict[str, Any]):
        """Ingest firewall event and update threat scores."""
        ip = event.get("src_ip")
        if not ip:
            return
        
        profile = self._get_or_create_profile(ip)
        profile.total_events += 1
        profile.firewall_events += 1
        profile.last_seen = datetime.now(timezone.utc)
        
        # Check against baseline
        rule = event.get("rule")
        if rule and self.baseline_engine:
            baseline = self.baseline_engine.get_baseline(rule)
            if baseline:
                deviation = self._calculate_deviation(event, baseline)
                if deviation > 0:
                    profile.baseline_deviations.append(deviation)
                    self._add_signal(ip, "firewall", "baseline_deviation", 
                                   deviation * SIGNAL_WEIGHTS["volume_anomaly"], 
                                   {"rule": rule, "deviation": deviation})
        
        # Check for port scan pattern
        if self._is_port_scan(ip, event):
            self._add_signal(ip, "firewall", "port_scan",
                           SIGNAL_WEIGHTS["firewall_port_scan"],
                           {"dst_port": event.get("dst_port")})
        
        # Check for destination scan
        if self._is_destination_scan(ip, event):
            self._add_signal(ip, "firewall", "dest_scan",
                           SIGNAL_WEIGHTS["firewall_dest_scan"],
                           {"dst_ip": event.get("dst_ip")})
        
        # Check block ratio
        action = event.get("action")
        if action == "block":
            self._update_block_ratio(ip)
    
    def ingest_http_event(self, event: Dict[str, Any]):
        """Ingest HTTP event and update threat scores."""
        ip = event.get("src_ip")
        if not ip:
            return
        
        profile = self._get_or_create_profile(ip)
        profile.total_events += 1
        profile.http_events += 1
        profile.last_seen = datetime.now(timezone.utc)
        
        # Check for HTTP anomalies
        status_code = event.get("status_code")
        if status_code and status_code.startswith("4"):
            self._add_signal(ip, "http", "client_error",
                           SIGNAL_WEIGHTS["http_anomaly"] * 0.5,
                           {"status_code": status_code})
        
        path = event.get("path", "")
        if any(pattern in path.lower() for pattern in ["../", ".php?", "cmd=", "exec=", "eval="]):
            self._add_signal(ip, "http", "path_traversal",
                           SIGNAL_WEIGHTS["http_anomaly"],
                           {"path": path})
    
    def ingest_ids_event(self, event: Dict[str, Any]):
        """Ingest IDS event and update threat scores."""
        ip = event.get("src_ip")
        if not ip:
            return
        
        profile = self._get_or_create_profile(ip)
        profile.total_events += 1
        profile.ids_events += 1
        profile.last_seen = datetime.now(timezone.utc)
        
        signature = event.get("signature", "")
        severity = event.get("severity", "low")
        
        self._add_signal(ip, "ids", "signature_match",
                       SIGNAL_WEIGHTS["ids_signature"] * {"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.5}.get(severity, 1.0),
                       {"signature": signature, "severity": severity})
    
    def ingest_zenarmor_event(self, event: Dict[str, Any]):
        """Ingest ZenArmor event and update threat scores."""
        ip = event.get("src_ip")
        if not ip:
            return
        
        profile = self._get_or_create_profile(ip)
        profile.total_events += 1
        profile.zenarmor_events += 1
        profile.last_seen = datetime.now(timezone.utc)
        
        threat_type = event.get("threat_type", "")
        threat_level = event.get("threat_level", "low")
        
        self._add_signal(ip, "zenarmor", "threat_detected",
                       SIGNAL_WEIGHTS["zenarmor_threat"] * {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}.get(threat_level, 1.0),
                       {"threat_type": threat_type, "threat_level": threat_level})
    
    def ingest_nginx_event(self, event: Dict[str, Any]):
        """Ingest nginx event and update threat scores."""
        ip = event.get("src_ip")
        if not ip:
            return
        
        profile = self._get_or_create_profile(ip)
        profile.total_events += 1
        profile.nginx_events += 1
        profile.last_seen = datetime.now(timezone.utc)
        
        attack_type = event.get("attack_type")
        if attack_type:
            self._add_signal(ip, "nginx", "attack",
                           SIGNAL_WEIGHTS["nginx_attack"],
                           {"attack_type": attack_type})
    
    def _get_or_create_profile(self, ip: str) -> IPThreatProfile:
        """Get or create threat profile for IP."""
        if ip not in self._ip_profiles:
            self._ip_profiles[ip] = IPThreatProfile(
                ip=ip,
                first_seen=datetime.now(timezone.utc)
            )
        return self._ip_profiles[ip]
    
    def _add_signal(self, ip: str, source: str, signal_type: str, score: float, details: Dict[str, Any] = None):
        """Add threat signal for IP."""
        signal = ThreatSignal(
            source=source,
            signal_type=signal_type,
            score=score,
            timestamp=datetime.now(timezone.utc),
            details=details or {}
        )
        
        profile = self._get_or_create_profile(ip)
        profile.signals.append(signal)
        self._signal_cache[ip].append(signal)
        
        # Update unified score
        self._update_unified_score(ip)
    
    def _update_unified_score(self, ip: str):
        """Update unified threat score for IP."""
        profile = self._ip_profiles.get(ip)
        if not profile:
            return
        
        # Group signals by source and type
        signal_scores: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        for signal in profile.signals:
            key = (signal.source, signal.signal_type)
            signal_scores[key].append(signal.score)
        
        # Calculate weighted score
        weighted_score = 0.0
        for (source, signal_type), scores in signal_scores.items():
            avg_score = sum(scores) / len(scores)
            weight = SIGNAL_WEIGHTS.get(signal_type, 0.5)
            weighted_score += avg_score * weight
        
        # Apply baseline deviation penalty
        if profile.baseline_deviations:
            avg_deviation = sum(profile.baseline_deviations[-10:]) / min(len(profile.baseline_deviations), 10)
            weighted_score *= (1 + avg_deviation * 0.1)
        
        profile.unified_score = min(weighted_score, THREAT_SCORE_MAX)
    
    def _apply_decay(self, profile: IPThreatProfile):
        """Apply time-based decay to threat score."""
        if not profile.last_seen:
            return
        
        now = datetime.now(timezone.utc)
        hours_since_last_seen = (now - profile.last_seen).total_seconds() / 3600
        
        if hours_since_last_seen > 0:
            decay_factor = SCORE_DECAY_RATE ** hours_since_last_seen
            decay_factor = max(decay_factor, SCORE_DECAY_MIN)
            profile.unified_score *= decay_factor
    
    def _calculate_deviation(self, event: Dict[str, Any], baseline: Any) -> float:
        """Calculate deviation from baseline."""
        try:
            # Simple volume deviation
            if hasattr(baseline, 'avg_events_per_hour') and baseline.avg_events_per_hour > 0:
                current_volume = event.get("volume", 1)  # Simplified
                deviation = abs(current_volume - baseline.avg_events_per_hour) / baseline.std_events_per_hour
                return deviation
        except Exception as e:
            logger.debug(f"Error calculating deviation: {e}")
        
        return 0.0
    
    def _is_port_scan(self, ip: str, event: Dict[str, Any]) -> bool:
        """Check if event indicates port scan."""
        profile = self._ip_profiles.get(ip)
        if not profile or profile.firewall_events < 5:
            return False
        
        # Check unique destination ports
        unique_ports = set()
        for signal in profile.signals:
            if signal.source == "firewall" and signal.details.get("dst_port"):
                unique_ports.add(signal.details["dst_port"])
        
        return len(unique_ports) > 10  # Threshold
    
    def _is_destination_scan(self, ip: str, event: Dict[str, Any]) -> bool:
        """Check if event indicates destination scan."""
        profile = self._ip_profiles.get(ip)
        if not profile or profile.firewall_events < 10:
            return False
        
        unique_dsts = set()
        for signal in profile.signals:
            if signal.source == "firewall" and signal.details.get("dst_ip"):
                unique_dsts.add(signal.details["dst_ip"])
        
        return len(unique_dsts) > 20  # Threshold
    
    def _update_block_ratio(self, ip: str):
        """Update block ratio for IP."""
        profile = self._ip_profiles.get(ip)
        if not profile:
            return
        
        # Count blocks vs passes
        block_count = sum(1 for s in profile.signals 
                         if s.source == "firewall" and s.signal_type == "block")
        total = block_count + sum(1 for s in profile.signals 
                                 if s.source == "firewall" and s.signal_type == "pass")
        
        if total > 0:
            block_ratio = block_count / total
            if block_ratio > 0.7:  # High block ratio
                self._add_signal(ip, "firewall", "high_block_ratio",
                               SIGNAL_WEIGHTS["firewall_block_ratio"] * block_ratio,
                               {"block_ratio": block_ratio, "total_events": total})
    
    def save_profiles(self):
        """Save threat profiles to database."""
        for ip, profile in self._ip_profiles.items():
            try:
                self.db.execute("""
                    INSERT OR REPLACE INTO ip_threat_profiles 
                    (ip, unified_score, total_events, firewall_events, http_events,
                     ids_events, zenarmor_events, nginx_events, baseline_deviations,
                     geo_info, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    profile.unified_score,
                    profile.total_events,
                    profile.firewall_events,
                    profile.http_events,
                    profile.ids_events,
                    profile.zenarmor_events,
                    profile.nginx_events,
                    json.dumps(profile.baseline_deviations),
                    json.dumps(profile.geo_info) if profile.geo_info else None,
                    profile.first_seen.isoformat() if profile.first_seen else None,
                    profile.last_seen.isoformat() if profile.last_seen else None
                ))
            except Exception as e:
                logger.error(f"Failed to save profile for {ip}: {e}")
        
        self.db.commit()