#!/usr/bin/env python3
"""
Multi-source signal correlation engine for OPNsense Anomaly Detection Agent.

Groups signals across all data sources into unified incidents. Detects
attack chains (recon -> probe -> exploit), escalates signal severity
based on patterns, and provides a single source of truth for what's
happening at any given time.

Architecture:
- Subscribes to SignalBus for real-time signal ingestion
- Groups signals per-IP within configurable time windows
- Detects attack chains: reconnaissance -> probe -> exploit progression
- Escalates severity when multiple signal types appear
- Outputs INCIDENT objects with unified severity, timeline, targets

Usage:
    from correlation_engine import CorrelationEngine
    engine = CorrelationEngine(db, signal_bus)
    engine.process_signal(signal)  # Called by SignalBus subscriber
"""

import json
import logging
import time
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Severity mapping ─────────────────────────────────────────────────

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"]


# ── Signal type categories for attack chain detection ────────────────

# Map signal types to their phase in the attack lifecycle.
# Includes signal types from ALL 15 sources so the correlation engine
# can detect chains that span any combination of detectors.
ATTACK_PHASES = {
    # ── Phase 1: Reconnaissance ─────────────────────────────────────
    # Scanning, enumeration, new actors appearing
    "port_scan":            "recon",
    "horizontal_scan":      "recon",
    "vertical_scan":        "recon",
    "xmas_scan":            "recon",
    "null_scan":            "recon",
    "fin_scan":             "recon",
    "icmp_scan":            "recon",
    "new_ip":               "recon",
    "path_probe":           "recon",
    "flow_recon":           "recon",
    "http_scan":            "recon",
    "anomaly_new_ip":       "recon",
    "anomaly_port_scan":    "recon",
    "ids_new_signature":    "recon",
    "new_country":          "recon",
    "high_risk_country":    "recon",
    "new_service":          "recon",
    "baseline_pattern_change": "recon",
    "volume_spike":         "recon",
    "deviation_unique_dst_ports": "recon",
    "deviation_unique_dst_ips":   "recon",
    "firewall_port_scan":   "recon",
    "firewall_dest_scan":   "recon",

    # ── Phase 2: Targeting / Probing ─────────────────────────────────
    # Suspicious behavior, deviations, initial probing
    "flow_suspicious":               "probe",
    "behavior_deviation":            "probe",
    "temporal_anomaly":              "probe",
    "anomaly_temporal":              "probe",
    "port_diversity_anomaly":        "probe",
    "http_404_spike":                "probe",
    "http_anomaly":                  "probe",
    "ids_signature":                 "probe",
    "zenarmor_threat":               "probe",
    "nginx_attack":                  "probe",
    "volume_anomaly":                "probe",
    "statistical_anomaly":           "probe",
    "deviation_conn_rate":           "probe",
    "deviation_bytes_per_conn":      "probe",
    "deviation_packet_count":        "probe",
    "repeated_blocks":               "probe",
    "multi_port_blocks":             "probe",
    "policy_change":                 "probe",
    "mixed_policy":                  "probe",
    "error_burst":                   "probe",
    "high_ip_diversity":             "probe",
    "system_volume_spike":           "probe",
    "geo_volume_anomaly":            "probe",
    "firewall_block_ratio":          "probe",
    "invalid_ua":                    "probe",
    "new_policy":                    "probe",

    # ── Phase 3: Attack ──────────────────────────────────────────────
    # Active hostile actions: floods, brute force, exploit attempts
    "syn_flood":                "attack",
    "brute_force":              "attack",
    "http_attack":              "attack",
    "http_brute_force":         "attack",
    "http_ddos":                "attack",
    "path_traversal":           "attack",
    "flow_attack":              "attack",
    "anomaly_volume":           "attack",
    "baseline_volume_spike":    "attack",
    "ids_signature_spike":      "attack",
    "ids_target_change":        "attack",
    "ids_cross_network":        "attack",
    "block_spike":              "attack",
    "system_block_spike":       "attack",
    "threat_escalation":        "attack",
    "firewall_block":           "attack",
    "service_down":             "attack",
    "wan_flap":                 "attack",

    # ── Phase 4: Exploitation ────────────────────────────────────────
    # Confirmed exploits, policy violations, post-exploitation
    "flow_exploit":         "exploit",
    "policy_violation":     "exploit",
    "incident_escalated":   "exploit",
}

# Ordered phase progression for chain detection
PHASE_ORDER = ["recon", "probe", "attack", "exploit"]


# ── Incident data structure ──────────────────────────────────────────

class Incident:
    """Represents a correlated security incident.

    An incident groups related signals from the same IP within a
    time window, providing unified severity, attack chain analysis,
    and lifecycle management.
    """

    def __init__(self, ip: str, initial_signal_type: str):
        self.ip = ip
        self.signal_types: Set[str] = set()
        self.sources: Set[str] = set()
        self.phases: Set[str] = set()
        self.signal_count = 0
        self.severity = "low"
        self.severity_rank = 0
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.is_active = True
        self.auto_resolved = False
        self.is_escalated = False  # True when full chain detected (3+ consecutive phases)

        # Per-phase first-seen timestamps for chain visualization
        self.phase_first_seen: Dict[str, float] = {}

        # Chain timeline: ordered list of {phase, signal_type, timestamp}
        self.chain_timeline: List[Dict[str, Any]] = []

        # Metadata
        self.metadata: Dict[str, Any] = {
            "dst_ips": set(),
            "dst_ports": set(),
            "protocols": set(),
            "countries": set(),
        }

    def add_signal(self, signal_type: str, source: str,
                   severity: str, metadata: Optional[Dict[str, Any]] = None):
        """Add a signal to this incident, updating severity and phases."""
        self.signal_types.add(signal_type)
        self.sources.add(source)
        self.last_seen = time.time()
        self.signal_count += 1

        # Track attack phase with first-seen timestamp
        phase = ATTACK_PHASES.get(signal_type)
        if phase:
            # Record when each phase was first observed
            if phase not in self.phase_first_seen:
                self.phase_first_seen[phase] = self.last_seen
                # Append to chain timeline in phase order
                self.chain_timeline.append({
                    "phase": phase,
                    "signal_type": signal_type,
                    "source": source,
                    "timestamp": self.last_seen,
                })

            self.phases.add(phase)

        # Enrich metadata
        if metadata:
            dst_ip = metadata.get("dst_ip")
            if dst_ip:
                self.metadata["dst_ips"].add(dst_ip)
            dst_port = metadata.get("dst_port")
            if dst_port:
                self.metadata["dst_ports"].add(dst_port)
            protocol = metadata.get("protocol")
            if protocol:
                self.metadata["protocols"].add(protocol)
            country = metadata.get("country")
            if country:
                self.metadata["countries"].add(country)

        # Update severity
        sig_rank = SEVERITY_RANK.get(severity, 0)
        if sig_rank > self.severity_rank:
            self.severity_rank = sig_rank
            self.severity = severity

        # Escalate based on signal diversity and chain progression
        self._escalate_by_pattern()

    def get_attack_chain(self) -> List[str]:
        """Get the ordered attack chain (phases detected in progression order)."""
        return [p for p in PHASE_ORDER if p in self.phases]

    def is_full_chain(self, min_phases: int = 3) -> bool:
        """Check if this incident has a progression of min_phases+ consecutive phases.

        A full chain means the attacker moved from recon -> probe -> attack (3 phases)
        or recon -> probe -> attack -> exploit (4 phases).
        """
        chain = self.get_attack_chain()
        if len(chain) < min_phases:
            return False

        # Verify phases are consecutive in the PHASE_ORDER sequence
        chain_indices = [PHASE_ORDER.index(p) for p in chain]
        for i in range(len(chain_indices) - 1):
            if chain_indices[i + 1] - chain_indices[i] != 1:
                return False

        return True

    def get_chain_timing(self) -> List[Dict[str, Any]]:
        """Get ordered phase timing for dashboard visualization."""
        result = []
        chain = self.get_attack_chain()
        for phase in chain:
            first_seen = self.phase_first_seen.get(phase, self.first_seen)
            result.append({
                "phase": phase,
                "first_seen": first_seen,
                "duration": (self.phase_first_seen[phase] - first_seen) if phase in self.phase_first_seen else 0,
                "signal_types": sorted([
                    st for st in self.signal_types
                    if ATTACK_PHASES.get(st) == phase
                ]),
            })
        # Add total duration
        if len(result) >= 2:
            result[-1]["total_chain_duration"] = result[-1]["first_seen"] - result[0]["first_seen"]
        return result

    def get_description(self) -> str:
        """Generate a human-readable description of this incident."""
        chain = self.get_attack_chain()

        # Full chain escalation description
        if self.is_escalated and self.is_full_chain():
            chain_str = " -> ".join(chain)
            return f"ESCALATED: Attack chain detected ({chain_str}) — {self.signal_count} signals from {len(self.sources)} sources"

        if chain:
            return f"Attack chain detected: {' -> '.join(chain)} ({self.signal_count} signals from {len(self.sources)} sources)"

        # Cross-source correlation description
        security_sources = self.sources & {"firewall", "nginx", "ids", "attack_detector", "anomaly_detector"}
        if len(security_sources) >= 2:
            return f"Cross-source correlation: {', '.join(sorted(security_sources))} ({self.signal_count} signals, {len(self.signal_types)} types)"

        # Single-phase descriptions
        if "recon" in self.phases:
            return f"Reconnaissance activity: {', '.join(sorted(self.signal_types))} ({self.signal_count} signals)"
        if "attack" in self.phases:
            return f"Active attack: {', '.join(sorted(self.signal_types))} ({self.signal_count} signals)"

        return f"Multi-source signals from {len(self.sources)} sources: {', '.join(sorted(self.signal_types))}"

    def get_affected_targets(self) -> List[str]:
        """Get list of affected target IPs/ports."""
        targets = []
        for ip in sorted(self.metadata.get("dst_ips", set())):
            for port in sorted(self.metadata.get("dst_ports", set())):
                targets.append(f"{ip}:{port}")
        return targets[:20]  # Limit to 20 targets

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for API response."""
        return {
            "ip": self.ip,
            "severity": self.severity,
            "signal_types": sorted(self.signal_types),
            "sources": sorted(self.sources),
            "phases": self.get_attack_chain(),
            "signal_count": self.signal_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_active": self.is_active,
            "is_escalated": self.is_escalated,
            "auto_resolved": self.auto_resolved,
            "description": self.get_description(),
            "affected_targets": self.get_affected_targets(),
            "chain_timeline": self.chain_timeline,
            "metadata": {
                k: sorted(v) if isinstance(v, set) else v
                for k, v in self.metadata.items()
            },
        }

    def _escalate_by_pattern(self):
        """Escalate severity based on detected patterns."""
        # Multiple signal types = higher severity
        if len(self.signal_types) >= 3 and self.severity_rank < SEVERITY_RANK["high"]:
            self.severity_rank = SEVERITY_RANK["high"]
            self.severity = "high"

        # Full attack chain progression (consecutive phases) = critical + escalated
        if self.is_full_chain(3):
            self.severity_rank = SEVERITY_RANK["critical"]
            self.severity = "critical"
            self.is_escalated = True

        # Cross-source correlation: signals from 3+ security sources = strong evidence
        security_sources = self.sources & {"firewall", "nginx", "ids", "attack_detector", "anomaly_detector"}
        if len(security_sources) >= 3:
            if self.severity_rank < SEVERITY_RANK["critical"]:
                self.severity_rank = SEVERITY_RANK["critical"]
                self.severity = "critical"
        elif len(security_sources) >= 2 and self.severity_rank < SEVERITY_RANK["high"]:
            self.severity_rank = SEVERITY_RANK["high"]
            self.severity = "high"

        # Multiple sources = escalation
        if len(self.sources) >= 3 and self.severity_rank < SEVERITY_RANK["medium"]:
            self.severity_rank = SEVERITY_RANK["medium"]
            self.severity = "medium"


# ── Correlation Engine ────────────────────────────────────────────────

class CorrelationEngine:
    """Multi-source signal correlation engine.

    Groups signals from the same IP within configurable time windows,
    detects attack chains, escalates severity, and manages incident
    lifecycle.

    Thread-safe: uses locks for incident dictionary access.
    """

    def __init__(self, db: Any = None, signal_bus: Any = None, correlation_window: int = 300,
                 auto_resolve_after: int = 86400, min_signals_escalate: int = 3):
        """Initialize correlation engine.

        Args:
            db: EventDatabase instance for persistence.
            signal_bus: SignalBus instance for emitting correlation signals.
            correlation_window: Seconds to group signals from same IP (default 300s/5min).
            auto_resolve_after: Seconds without new signals before auto-resolving (default 86400s/24h).
            min_signals_escalate: Minimum signals needed before escalation kicks in.
        """
        self.db = db
        self.signal_bus = signal_bus
        self.correlation_window = correlation_window
        self.auto_resolve_after = auto_resolve_after
        self.min_signals_escalate = min_signals_escalate
        self._incidents: Dict[str, List[Incident]] = defaultdict(list)
        self._lock = threading.Lock()
        self._total_incidents = 0
        self._total_signals_processed = 0
        self._callbacks: List[Callable[[Incident], None]] = []
        logger.info("CorrelationEngine initialized (window=%ds, auto_resolve=%ds)",
                    correlation_window, auto_resolve_after)

    def process_signal(self, signal: Any) -> Optional[Incident]:
        """Process a signal and correlate it with existing incidents.

        Args:
            signal: Signal object from SignalBus.

        Returns:
            Incident that the signal was added to, or None if ignored.
        """
        if not signal:
            return None

        self._total_signals_processed += 1

        # Skip info-level signals for correlation (noise reduction)
        if signal.severity == "info":
            return None

        ip = signal.ip
        if not ip:
            return None

        with self._lock:
            # Find or create active incident for this IP
            incident = self._group_signals(ip, signal)

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(incident)
            except Exception as e:
                logger.error("Correlation callback error: %s", e)

        return incident

    def get_active_incidents(self, min_severity: str = "low") -> List[Incident]:
        """Get all active incidents, filtered by minimum severity."""
        with self._lock:
            min_rank = SEVERITY_RANK.get(min_severity, 0)
            all_active = []
            for ip, incidents in self._incidents.items():
                for inc in incidents:
                    if inc.is_active and inc.severity_rank >= min_rank:
                        all_active.append(inc)

        # Sort by severity (highest first), then by recency
        all_active.sort(
            key=lambda i: (i.severity_rank, i.last_seen),
            reverse=True
        )
        return all_active

    def get_incident_by_ip(self, ip: str) -> Optional[Incident]:
        """Get the most recent active incident for an IP."""
        with self._lock:
            incidents = self._incidents.get(ip, [])
            active = [i for i in incidents if i.is_active]
            if active:
                return max(active, key=lambda i: i.last_seen)
        return None

    def get_incident_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        with self._lock:
            active_count = 0
            resolved_count = 0
            by_severity: Dict[str, int] = defaultdict(int)
            by_phase: Dict[str, int] = defaultdict(int)

            for ip, incidents in self._incidents.items():
                for inc in incidents:
                    if inc.is_active:
                        active_count += 1
                    else:
                        resolved_count += 1
                    by_severity[inc.severity] += 1
                    for phase in inc.phases:
                        by_phase[phase] += 1

            return {
                "total_incidents": self._total_incidents,
                "active_incidents": active_count,
                "resolved_incidents": resolved_count,
                "total_signals_processed": self._total_signals_processed,
                "by_severity": dict(by_severity),
                "by_phase": dict(by_phase),
                "unique_ips": len(self._incidents),
            }

    def on_incident_created(self, callback: Callable[[Incident], None]):
        """Register callback for new/updated incidents."""
        self._callbacks.append(callback)

    def auto_resolve_stale(self) -> int:
        """Auto-resolve incidents that haven't received signals in the timeout window.

        Returns:
            Number of incidents auto-resolved.
        """
        now = time.time()
        resolved = 0

        with self._lock:
            for ip, incidents in list(self._incidents.items()):
                for inc in incidents:
                    if (inc.is_active and
                        (now - inc.last_seen) > self.auto_resolve_after):
                        inc.is_active = False
                        inc.auto_resolved = True
                        resolved += 1

        if resolved:
            logger.info("Auto-resolved %d stale incidents", resolved)
        return resolved

    def group_signals(self, signals: List[Any]) -> List[Incident]:
        """Batch-process a list of signals and group them by IP + time window.

        Optimized for bulk ingestion: acquires the lock once, groups signals
        by IP, processes them sequentially within the batch, and emits a single
        correlation signal per IP at the end.

        Args:
            signals: List of Signal objects from SignalBus.

        Returns:
            List of Incidents created or updated during this batch.
        """
        if not signals:
            return []

        # Pre-group by IP outside the lock for analysis
        by_ip: Dict[str, List[Any]] = defaultdict(list)
        for sig in signals:
            if sig and sig.ip and sig.severity != "info":
                by_ip[sig.ip].append(sig)

        with self._lock:
            created_or_updated: List[Incident] = []
            for ip, ip_signals in by_ip.items():
                # Sort by timestamp within the batch
                ip_signals.sort(key=lambda s: s.timestamp)
                for sig in ip_signals:
                    self._total_signals_processed += 1
                    inc = self._group_signals(ip, sig)
                    if inc not in created_or_updated:
                        created_or_updated.append(inc)

        # Notify callbacks once per incident after batch
        for inc in created_or_updated:
            for cb in self._callbacks:
                try:
                    cb(inc)
                except Exception as e:
                    logger.error("Correlation callback error: %s", e)

        logger.info("group_signals: processed %d signals into %d incidents (%d unique IPs)",
                    len(signals), len(created_or_updated), len(by_ip))
        return created_or_updated

    def _group_signals(self, ip: str, signal: Any) -> Incident:
        """Find an active incident for this IP or create a new one.

        Must be called with self._lock held.
        """
        incidents = self._incidents.get(ip, [])

        # Find active incident within correlation window
        now = time.time()
        for inc in incidents:
            if inc.is_active and (now - inc.last_seen) < self.correlation_window:
                # Add signal to existing incident
                old_severity = inc.severity
                old_escalated = inc.is_escalated
                inc.add_signal(
                    signal.signal_type, signal.source,
                    signal.severity, signal.metadata
                )
                self._persist_incident(inc)
                # Emit correlation signal if severity escalated or attack chain detected
                if self.signal_bus and inc.is_active:
                    # Full chain escalation — highest priority signal
                    if inc.is_escalated and not old_escalated:
                        self.signal_bus.emit(
                            source="correlation",
                            signal_type="attack_chain_escalated",
                            severity=inc.severity,
                            ip=inc.ip,
                            metadata={
                                "signal_types": sorted(inc.signal_types),
                                "sources": sorted(inc.sources),
                                "phases": inc.get_attack_chain(),
                                "chain_timeline": inc.chain_timeline,
                                "signal_count": inc.signal_count,
                                "description": inc.get_description(),
                            },
                        )
                    elif inc.severity != old_severity:
                        self.signal_bus.emit(
                            source="correlation",
                            signal_type="incident_escalated",
                            severity=inc.severity,
                            ip=inc.ip,
                            metadata={
                                "signal_types": sorted(inc.signal_types),
                                "sources": sorted(inc.sources),
                                "signal_count": inc.signal_count,
                                "phases": inc.get_attack_chain(),
                                "description": inc.get_description(),
                            },
                        )
                    elif len(inc.signal_types) >= 3:
                        self.signal_bus.emit(
                            source="correlation",
                            signal_type="attack_chain",
                            severity=inc.severity,
                            ip=inc.ip,
                            metadata={
                                "signal_types": sorted(inc.signal_types),
                                "sources": sorted(inc.sources),
                                "phases": inc.get_attack_chain(),
                                "chain_timeline": inc.chain_timeline,
                                "description": inc.get_description(),
                            },
                        )
                return inc

        # Create new incident
        new_incident = Incident(ip, signal.signal_type)
        new_incident.add_signal(
            signal.signal_type, signal.source,
            signal.severity, signal.metadata
        )

        if ip not in self._incidents:
            self._incidents[ip] = []
        self._incidents[ip].append(new_incident)
        self._total_incidents += 1

        # Cleanup old resolved incidents for this IP (keep last 50)
        self._incidents[ip] = self._incidents[ip][-50:]

        self._persist_incident(new_incident)
        # Emit incident_created signal
        if self.signal_bus:
            self.signal_bus.emit(
                source="correlation",
                signal_type="incident_created",
                severity=new_incident.severity,
                ip=new_incident.ip,
                metadata={
                    "signal_types": sorted(new_incident.signal_types),
                    "sources": sorted(new_incident.sources),
                    "signal_count": new_incident.signal_count,
                    "phases": new_incident.get_attack_chain(),
                    "description": new_incident.get_description(),
                },
            )
        return new_incident

    def _persist_incident(self, incident: Incident):
        """Persist incident to PostgreSQL."""
        if not self.db:
            return

        try:
            inc_dict = incident.to_dict()
            # Convert sets to JSON-serializable lists
            metadata = json.dumps({
                k: sorted(v) if isinstance(v, set) else v
                for k, v in inc_dict["metadata"].items()
            })

            # PostgreSQL ARRAY columns need native Python lists, NOT json.dumps()
            signal_types = sorted(incident.signal_types)
            sources = sorted(incident.sources)
            phases = incident.get_attack_chain()

            # Check if incident already exists in DB
            cur = self.db._new_cursor()
            cur.execute(
                "SELECT id FROM incidents WHERE ip = %s AND is_active = TRUE",
                (incident.ip,),
            )
            row = cur.fetchone()

            if row:
                # Update existing
                cur.execute(
                    """UPDATE incidents SET
                       severity = %s, signal_count = %s, signal_types = %s::text[],
                       sources = %s::text[], phases = %s::text[],
                       last_seen = to_timestamp(%s),
                       description = %s, metadata = %s::jsonb
                       WHERE id = %s""",
                    (incident.severity, incident.signal_count,
                     signal_types, sources, phases,
                     incident.last_seen, incident.get_description(),
                     metadata, row[0]),
                )
            else:
                # Insert new
                cur.execute(
                    """INSERT INTO incidents
                       (ip, severity, signal_count, signal_types, sources,
                        phases, first_seen, last_seen, description, metadata)
                       VALUES (%s, %s, %s, %s::text[], %s::text[], %s::text[],
                               to_timestamp(%s), to_timestamp(%s), %s, %s::jsonb)""",
                    (incident.ip, incident.severity, incident.signal_count,
                     signal_types, sources, phases,
                     incident.first_seen, incident.last_seen,
                     incident.get_description(), metadata),
                )
            cur.close()

        except Exception as e:
            logger.warning("Failed to persist incident for %s: %s", incident.ip, e)
