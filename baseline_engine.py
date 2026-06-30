#!/usr/bin/env python3
"""
Baseline Engine for OPNsense Anomaly Detection

Learns traffic baselines from historical data (Graylog training data + live events).
Tracks per-rule, per-IP, per-time-of-day patterns to establish what is "normal".
"""

import warnings

# ── DEPRECATED ─────────────────────────────────────────────────────────
# This module has been superseded by unified_behavioral_engine.py.
# All functionality (BaselineEngine, TrafficBaseline, IP-level baselines,
# temporal drift detection) has been migrated into UnifiedBehavioralEngine.
#
# Migration guide:
#   OLD:  from baseline_engine import BaselineEngine
#   NEW:  from unified_behavioral_engine import UnifiedBehavioralEngine
#
# These files are retained until 2026-07-14 as a safety net, then will be
# removed. Please update any remaining imports.
# ──────────────────────────────────────────────────────────────────────────
warnings.warn(
    "baseline_engine is DEPRECATED — functionality migrated to "
    "unified_behavioral_engine.UnifiedBehavioralEngine. "
    "This module will be removed after 2026-07-14.",
    DeprecationWarning,
    stacklevel=2,
)

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Configuration
HOURS_IN_DAY = 24
BASELINE_WINDOW_HOURS = 24
MIN_EVENTS_FOR_BASELINE = 10
TEMPORAL_DRIFT_THRESHOLD = 0.5  # 50% deviation from baseline

@dataclass
class TrafficBaseline:
    """Statistical baseline for a specific traffic pattern."""
    rule: str
    ip: Optional[str] = None
    hour: Optional[int] = None
    
    # Volume stats
    avg_events_per_hour: float = 0.0
    std_events_per_hour: float = 0.0
    max_events_per_hour: int = 0
    min_events_per_hour: int = 0
    
    # Protocol distribution
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    
    # Port diversity
    avg_dst_ports: float = 0.0
    avg_src_ports: float = 0.0
    avg_unique_dst_ips: float = 0.0
    
    # Action distribution (pass/block ratio)
    pass_ratio: float = 0.0
    block_ratio: float = 0.0
    
    # Temporal pattern (hourly distribution)
    hourly_distribution: List[float] = field(default_factory=list)
    
    # Confidence
    sample_count: int = 0
    last_updated: Optional[datetime] = None
    
    def confidence_score(self) -> float:
        """Higher confidence = more data points."""
        if self.sample_count < MIN_EVENTS_FOR_BASELINE:
            return 0.0
        return min(1.0, math.log(self.sample_count) / math.log(1000))

class BaselineEngine:
    """Learns and maintains traffic baselines."""
    
    def __init__(self, db_connection):
        self.db = db_connection
        self._baselines: Dict[str, TrafficBaseline] = {}
        self._load_baselines()
    
    def _load_baselines(self):
        """Load existing baselines from database."""
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            cur.execute("""
                SELECT rule, ip, hour, avg_events_per_hour, std_events_per_hour,
                       max_events_per_hour, min_events_per_hour, protocol_distribution,
                       avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio, 
                       block_ratio, hourly_distribution, sample_count, last_updated
                FROM rule_baselines
            """)
            
            for row in cur.fetchall():
                key = self._make_baseline_key(row[0], row[1], row[2])
                self._baselines[key] = TrafficBaseline(
                    rule=row[0],
                    ip=row[1],
                    hour=row[2],
                    avg_events_per_hour=row[3] or 0,
                    std_events_per_hour=row[4] or 0,
                    max_events_per_hour=row[5] or 0,
                    min_events_per_hour=row[6] or 0,
                    protocol_distribution=(row[7] if isinstance(row[7], dict) else (json.loads(row[7]) if isinstance(row[7], str) else {})),
                    avg_dst_ports=row[8] or 0,
                    avg_src_ports=row[9] or 0,
                    avg_unique_dst_ips=row[10] or 0,
                    pass_ratio=row[11] or 0,
                    block_ratio=row[12] or 0,
                    hourly_distribution=(row[13] if isinstance(row[13], list) else (json.loads(row[13]) if isinstance(row[13], str) else [])),
                    sample_count=row[14] or 0,
                    last_updated=row[15] if row[15] else None
                )
            cur.close()
            self.db.putconn(conn)
        except Exception as e:
            logger.error(f"Failed to load baselines: {e}")
    
    def _make_baseline_key(self, rule: str, ip: Optional[str] = None, hour: Optional[int] = None) -> str:
        """Create unique key for baseline."""
        if ip and hour is not None:
            return f"{rule}:{ip}:{hour}"
        elif ip:
            return f"{rule}:{ip}"
        elif hour is not None:
            return f"{rule}:hour:{hour}"
        else:
            return rule
    
    def learn_from_training_data(self, events: List[Dict[str, Any]]) -> int:
        """Learn baselines from historical training data."""
        if not events:
            return 0
        
        logger.info(f"Learning from {len(events)} training events...")
        
        # Group events by rule and time window
        rule_hourly_data: Dict[str, Dict[int, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        rule_ip_data: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        
        for event in events:
            rule = event.get("rule", "unknown")
            timestamp = event.get("timestamp")
            
            if not timestamp:
                continue
            
            # Parse timestamp
            try:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            except Exception:
                continue
            
            hour = dt.hour
            
            # Group by rule and hour
            rule_hourly_data[rule][hour].append(event)
            
            # Group by rule and source IP
            src_ip = event.get("src_ip")
            if src_ip:
                rule_ip_data[rule][src_ip].append(event)
        
        # Learn baselines
        learned_count = 0
        
        # Rule-level baselines
        for rule, hourly_data in rule_hourly_data.items():
            baseline = self._learn_rule_baseline(rule, hourly_data)
            if baseline:
                self._baselines[self._make_baseline_key(rule)] = baseline
                learned_count += 1
        
        # IP-level baselines (for high-value rules)
        for rule, ip_data in rule_ip_data.items():
            for ip, ip_events in ip_data.items():
                if len(ip_events) >= MIN_EVENTS_FOR_BASELINE:
                    baseline = self._learn_ip_baseline(rule, ip, ip_events)
                    if baseline:
                        self._baselines[self._make_baseline_key(rule, ip)] = baseline
                        learned_count += 1
        
        logger.info(f"Learned {learned_count} baselines from training data")
        return learned_count
    
    def _learn_rule_baseline(self, rule: str, hourly_data: Dict[int, List[Dict[str, Any]]]) -> Optional[TrafficBaseline]:
        """Learn baseline for a single rule."""
        total_events = sum(len(v) for v in hourly_data.values())
        
        if total_events < MIN_EVENTS_FOR_BASELINE:
            return None
        
        # Calculate hourly volumes
        hourly_volumes = [len(hourly_data.get(h, [])) for h in range(HOURS_IN_DAY)]
        avg_volume = sum(hourly_volumes) / len(hourly_volumes)
        std_volume = self._std_dev(hourly_volumes)
        
        # Protocol distribution
        protocols = Counter()
        for events in hourly_data.values():
            for event in events:
                proto = event.get("protocol", "unknown")
                protocols[proto] += 1
        
        protocol_dist = {k: v / total_events for k, v in protocols.items()}
        
        # Port diversity
        dst_ports = Counter()
        src_ports = Counter()
        dst_ips = set()
        
        for events in hourly_data.values():
            for event in events:
                dst_port = event.get("dst_port")
                src_port = event.get("src_port")
                dst_ip = event.get("dst_ip")
                
                if dst_port:
                    dst_ports[dst_port] += 1
                if src_port:
                    src_ports[src_port] += 1
                if dst_ip:
                    dst_ips.add(dst_ip)
        
        # Action distribution
        pass_count = sum(1 for events in hourly_data.values() for e in events if e.get("action") == "pass")
        block_count = sum(1 for events in hourly_data.values() for e in events if e.get("action") == "block")
        
        baseline = TrafficBaseline(
            rule=rule,
            avg_events_per_hour=avg_volume,
            std_events_per_hour=std_volume,
            max_events_per_hour=max(hourly_volumes) if hourly_volumes else 0,
            min_events_per_hour=min(hourly_volumes) if hourly_volumes else 0,
            protocol_distribution=protocol_dist,
            avg_dst_ports=len(dst_ports),
            avg_src_ports=len(src_ports),
            avg_unique_dst_ips=len(dst_ips),
            pass_ratio=pass_count / total_events if total_events > 0 else 0,
            block_ratio=block_count / total_events if total_events > 0 else 0,
            hourly_distribution=hourly_volumes,
            sample_count=total_events,
            last_updated=datetime.now(timezone.utc)
        )
        
        return baseline
    
    def _learn_ip_baseline(self, rule: str, ip: str, events: List[Dict[str, Any]]) -> Optional[TrafficBaseline]:
        """Learn baseline for a specific IP."""
        if len(events) < MIN_EVENTS_FOR_BASELINE:
            return None
        
        # Calculate stats for this IP
        dst_ports = Counter()
        protocols = Counter()
        pass_count = 0
        block_count = 0
        
        for event in events:
            dst_port = event.get("dst_port")
            proto = event.get("protocol", "unknown")
            action = event.get("action")
            
            if dst_port:
                dst_ports[dst_port] += 1
            protocols[proto] += 1
            if action == "pass":
                pass_count += 1
            elif action == "block":
                block_count += 1
        
        total = len(events)
        
        baseline = TrafficBaseline(
            rule=rule,
            ip=ip,
            avg_events_per_hour=total / BASELINE_WINDOW_HOURS,
            std_events_per_hour=0,  # Would need time series data
            max_events_per_hour=total,
            min_events_per_hour=0,
            protocol_distribution={k: v / total for k, v in protocols.items()},
            avg_dst_ports=len(dst_ports),
            avg_src_ports=0,  # Would need more data
            avg_unique_dst_ips=0,  # Would need more data
            pass_ratio=pass_count / total if total > 0 else 0,
            block_ratio=block_count / total if total > 0 else 0,
            sample_count=total,
            last_updated=datetime.now(timezone.utc)
        )
        
        return baseline
    
    def get_baseline(self, rule: str, ip: Optional[str] = None, hour: Optional[int] = None) -> Optional[TrafficBaseline]:
        """Get baseline for given parameters."""
        key = self._make_baseline_key(rule, ip, hour)
        return self._baselines.get(key)
    
    def update_baseline(self, rule: str, new_events: List[Dict[str, Any]]):
        """Incrementally update baseline with new events."""
        existing = self.get_baseline(rule)
        
        if not existing:
            # Create new baseline from scratch
            hourly_data = {0: new_events}  # Simplified for now
            new_baseline = self._learn_rule_baseline(rule, hourly_data)
            if new_baseline:
                self._baselines[self._make_baseline_key(rule)] = new_baseline
        else:
            # Update existing baseline
            existing.sample_count += len(new_events)
            existing.last_updated = datetime.now(timezone.utc)
            
            # Update protocol distribution
            new_protocols = Counter()
            for event in new_events:
                proto = event.get("protocol", "unknown")
                new_protocols[proto] += 1
            
            if new_protocols:
                for proto, count in new_protocols.items():
                    if proto in existing.protocol_distribution:
                        existing.protocol_distribution[proto] = (
                            existing.protocol_distribution[proto] * (existing.sample_count - len(new_events)) +
                            count
                        ) / existing.sample_count
                    else:
                        existing.protocol_distribution[proto] = count / existing.sample_count
    
    def _std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
    
    def save_baselines(self):
        """Save baselines to database."""
        try:
            conn = self.db.connect()
            cur = conn.cursor()

            for key, baseline in self._baselines.items():
                try:
                    cur.execute("""
                        INSERT INTO rule_baselines
                        (rule, ip, hour, avg_events_per_hour, std_events_per_hour,
                         max_events_per_hour, min_events_per_hour, protocol_distribution,
                         avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio,
                         block_ratio, hourly_distribution, sample_count, last_updated)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (rule, ip, hour) DO UPDATE SET
                            avg_events_per_hour = EXCLUDED.avg_events_per_hour,
                            std_events_per_hour = EXCLUDED.std_events_per_hour,
                            max_events_per_hour = EXCLUDED.max_events_per_hour,
                            min_events_per_hour = EXCLUDED.min_events_per_hour,
                            protocol_distribution = EXCLUDED.protocol_distribution,
                            avg_dst_ports = EXCLUDED.avg_dst_ports,
                            avg_src_ports = EXCLUDED.avg_src_ports,
                            avg_unique_dst_ips = EXCLUDED.avg_unique_dst_ips,
                            pass_ratio = EXCLUDED.pass_ratio,
                            block_ratio = EXCLUDED.block_ratio,
                            hourly_distribution = EXCLUDED.hourly_distribution,
                            sample_count = EXCLUDED.sample_count,
                            last_updated = EXCLUDED.last_updated
                    """, (
                        baseline.rule,
                        baseline.ip,
                        baseline.hour,
                        baseline.avg_events_per_hour,
                        baseline.std_events_per_hour,
                        baseline.max_events_per_hour,
                        baseline.min_events_per_hour,
                        json.dumps(baseline.protocol_distribution),
                        baseline.avg_dst_ports,
                        baseline.avg_src_ports,
                        baseline.avg_unique_dst_ips,
                        baseline.pass_ratio,
                        baseline.block_ratio,
                        json.dumps(baseline.hourly_distribution),
                        baseline.sample_count,
                        baseline.last_updated
                    ))
                except Exception as e:
                    logger.error(f"Failed to save baseline for {baseline.rule}: {e}")

            cur.close()
            self.db.putconn(conn)
            logger.info(f"Saved {len(self._baselines)} baselines to database")
        except Exception as e:
            logger.error(f"Failed to save baselines: {e}")