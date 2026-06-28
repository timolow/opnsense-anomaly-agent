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

# Map signal types to their phase in the attack lifecycle
ATTACK_PHASES = {
    # Phase 1: Reconnaissance
    "port_scan": "recon",
    "horizontal_scan": "recon",
    "vertical_scan": "recon",
    "xmas_scan": "recon",
    "null_scan": "recon",
    "fin_scan": "recon",
    "icmp_scan": "recon",
    "new_ip": "recon",
    "path_probe": "recon",
    "flow_recon": "recon",

    # Phase 2: Targeting / Probing
    "flow_suspicious": "probe",
    "behavior_deviation": "probe",
    "temporal_anomaly": "probe",
    "port_diversity_anomaly": "probe",
    "http_404_spike": "probe",
    "ids_signature_hit": "probe",

    # Phase 3: Attack
    "syn_flood": "attack",
    "brute_force": "attack",
    "http_attack": "attack",
    "http_brute_force": "attack",
    "flow_attack": "attack",
    "anomaly_volume": "attack",
    "baseline_volume_spike": "attack",

    # Phase 4: Exploitation
    "flow_exploit": "exploit",
    "policy_violation": "exploit",
    "ids_signature_spike": "exploit",
}


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

        # Track attack phase
        phase = ATTACK_PHASES.get(signal_type)
        if phase:
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

        # Escalate based on signal diversity
        self._escalate_by_pattern()

    def get_attack_chain(self) -> List[str]:
        """Get the ordered attack chain (phases detected)."""
        phase_order = ["recon", "probe", "attack", "exploit"]
        return [p for p in phase_order if p in self.phases]

    def get_description(self) -> str:
        """Generate a human-readable description of this incident."""
        chain = self.get_attack_chain()
        if chain:
            return f"Attack chain detected: {' -> '.join(chain)} ({self.signal_count} signals from {len(self.sources)} sources)"

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
            "auto_resolved": self.auto_resolved,
            "description": self.get_description(),
            "affected_targets": self.get_affected_targets(),
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

        # Attack chain progression = critical
        chain = self.get_attack_chain()
        if len(chain) >= 3:
            self.severity_rank = SEVERITY_RANK["critical"]
            self.severity = "critical"

        # Multiple sources = escalation
        if len(self.sources) >= 3 and self.severity_rank < SEVERITY_RANK["high"]:
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

    def __init__(self, db: Any = None, correlation_window: int = 300,
                 auto_resolve_after: int = 3600, min_signals_escalate: int = 3):
        """Initialize correlation engine.

        Args:
            db: EventDatabase instance for persistence.
            correlation_window: Seconds to group signals from same IP (default 300s).
            auto_resolve_after: Seconds without new signals before auto-resolving (default 3600s).
            min_signals_escalate: Minimum signals needed before escalation kicks in.
        """
        self.db = db
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
            incident = self._find_or_create_incident(ip, signal)

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

    def _find_or_create_incident(self, ip: str, signal: Any) -> Incident:
        """Find an active incident for this IP or create a new one.

        Must be called with self._lock held.
        """
        incidents = self._incidents.get(ip, [])

        # Find active incident within correlation window
        now = time.time()
        for inc in incidents:
            if inc.is_active and (now - inc.last_seen) < self.correlation_window:
                # Add signal to existing incident
                inc.add_signal(
                    signal.signal_type, signal.source,
                    signal.severity, signal.metadata
                )
                self._persist_incident(inc)
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

            # Check if incident already exists in DB
            cur = self.db.execute(
                "SELECT id FROM incidents WHERE ip = %s AND is_active = TRUE",
                (incident.ip,),
            )
            row = cur.fetchone()

            if row:
                # Update existing
                self.db.execute(
                    """UPDATE incidents SET
                       severity = %s, signal_count = %s, signal_types = %s,
                       sources = %s, phases = %s, last_seen = to_timestamp(%s),
                       description = %s, metadata = %s
                       WHERE id = %s""",
                    (incident.severity, incident.signal_count,
                     json.dumps(sorted(incident.signal_types)),
                     json.dumps(sorted(incident.sources)),
                     json.dumps(incident.get_attack_chain()),
                     incident.last_seen, incident.get_description(),
                     metadata, row[0]),
                )
            else:
                # Insert new
                self.db.execute(
                    """INSERT INTO incidents
                       (ip, severity, signal_count, signal_types, sources,
                        phases, first_seen, last_seen, description, metadata)
                       VALUES (%s, %s, %s, %s, %s, %s,
                               to_timestamp(%s), to_timestamp(%s), %s, %s)""",
                    (incident.ip, incident.severity, incident.signal_count,
                     json.dumps(sorted(incident.signal_types)),
                     json.dumps(sorted(incident.sources)),
                     json.dumps(incident.get_attack_chain()),
                     incident.first_seen, incident.last_seen,
                     incident.get_description(), metadata),
                )

        except Exception as e:
            logger.warning("Failed to persist incident for %s: %s", incident.ip, e)
