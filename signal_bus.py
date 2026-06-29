#!/usr/bin/env python3
import sys

"""
Signal bus architecture for OPNsense Anomaly Detection Agent.

Unifies all detector outputs into a common signal format that the
behavioral engine and correlation engine consume. Acts as the central
nervous system — every detection event flows through here.

Architecture:
- Single SignalBus instance in agent.py
- All detectors emit signals via signal_bus.emit()
- Signals are written to ip_behavior_signals table (V15 migration)
- SignalBus routes signals to BehaviorProfiler for real-time profile updates
- SignalBus routes signals to CorrelationEngine for incident creation
- Backpressure: bounded signal queue, oldest signals dropped when full

Usage:
    from signal_bus import SignalBus
    bus = SignalBus(db)
    bus.emit("firewall", "port_scan", "high", "10.0.0.1", metadata={"ports": 50})
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Signal severity levels ───────────────────────────────────────────

SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

# ── Signal source types ──────────────────────────────────────────────

SOURCE_FIREWALL = "firewall"
SOURCE_ATTACK_DETECTOR = "attack_detector"
SOURCE_BEHAVIOR_PROFILER = "behavior_profiler"
SOURCE_FLOW_CLASSIFIER = "flow_classifier"
SOURCE_BASLINE_ENGINE = "baseline_engine"
SOURCE_ANOMALY_DETECTOR = "anomaly_detector"
SOURCE_NGINX = "nginx"
SOURCE_IDS = "ids"
SOURCE_ZENARMOR = "zenarmor"
SOURCE_GEO = "geo"
SOURCE_THREAT_ENGINE = "threat_engine"
SOURCE_SYSTEM_LOG = "system_log"
SOURCE_SERVICE_MONITOR = "service_monitor"
SOURCE_WAN_FLAP = "wan_flap"
SOURCE_CORRELATION = "correlation"

# ── Signal type registry (exhaustive list of signal types) ───────────

SIGNAL_TYPES = {
    # Attack detector signals
    "port_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_MEDIUM},
    "syn_flood": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_CRITICAL},
    "brute_force": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_HIGH},
    "xmas_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_MEDIUM},
    "null_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_MEDIUM},
    "fin_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_MEDIUM},
    "icmp_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_LOW},
    "horizontal_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_HIGH},
    "vertical_scan": {"source": SOURCE_ATTACK_DETECTOR, "default_severity": SEVERITY_MEDIUM},

    # Behavior profiler signals
    "new_ip": {"source": SOURCE_BEHAVIOR_PROFILER, "default_severity": SEVERITY_INFO},
    "volume_spike": {"source": SOURCE_BEHAVIOR_PROFILER, "default_severity": SEVERITY_MEDIUM},
    "temporal_anomaly": {"source": SOURCE_BEHAVIOR_PROFILER, "default_severity": SEVERITY_MEDIUM},
    "port_diversity_anomaly": {"source": SOURCE_BEHAVIOR_PROFILER, "default_severity": SEVERITY_MEDIUM},
    "behavior_deviation": {"source": SOURCE_BEHAVIOR_PROFILER, "default_severity": SEVERITY_LOW},

    # Flow classifier signals
    "flow_recon": {"source": SOURCE_FLOW_CLASSIFIER, "default_severity": SEVERITY_MEDIUM},
    "flow_suspicious": {"source": SOURCE_FLOW_CLASSIFIER, "default_severity": SEVERITY_LOW},
    "flow_attack": {"source": SOURCE_FLOW_CLASSIFIER, "default_severity": SEVERITY_HIGH},
    "flow_exploit": {"source": SOURCE_FLOW_CLASSIFIER, "default_severity": SEVERITY_CRITICAL},

    # Baseline engine signals
    "baseline_volume_spike": {"source": SOURCE_BASLINE_ENGINE, "default_severity": SEVERITY_MEDIUM},
    "baseline_pattern_change": {"source": SOURCE_BASLINE_ENGINE, "default_severity": SEVERITY_LOW},

    # Anomaly detector signals
    "anomaly_volume": {"source": SOURCE_ANOMALY_DETECTOR, "default_severity": SEVERITY_MEDIUM},
    "anomaly_temporal": {"source": SOURCE_ANOMALY_DETECTOR, "default_severity": SEVERITY_MEDIUM},
    "anomaly_new_ip": {"source": SOURCE_ANOMALY_DETECTOR, "default_severity": SEVERITY_INFO},
    "anomaly_port_scan": {"source": SOURCE_ANOMALY_DETECTOR, "default_severity": SEVERITY_MEDIUM},

    # Nginx signals
    "http_attack": {"source": SOURCE_NGINX, "default_severity": SEVERITY_HIGH},
    "http_brute_force": {"source": SOURCE_NGINX, "default_severity": SEVERITY_HIGH},
    "path_probe": {"source": SOURCE_NGINX, "default_severity": SEVERITY_MEDIUM},
    "http_404_spike": {"source": SOURCE_NGINX, "default_severity": SEVERITY_MEDIUM},

    # IDS signals
    "ids_signature_hit": {"source": SOURCE_IDS, "default_severity": SEVERITY_HIGH},
    "ids_signature_spike": {"source": SOURCE_IDS, "default_severity": SEVERITY_HIGH},
    "new_ids_signature": {"source": SOURCE_IDS, "default_severity": SEVERITY_MEDIUM},

    # ZenArmor signals
    "policy_violation": {"source": SOURCE_ZENARMOR, "default_severity": SEVERITY_HIGH},
    "content_block": {"source": SOURCE_ZENARMOR, "default_severity": SEVERITY_MEDIUM},
    "new_policy": {"source": SOURCE_ZENARMOR, "default_severity": SEVERITY_INFO},
    "policy_change": {"source": SOURCE_ZENARMOR, "default_severity": SEVERITY_MEDIUM},

    # Geo signals
    "new_country": {"source": SOURCE_GEO, "default_severity": SEVERITY_LOW},
    "high_risk_country": {"source": SOURCE_GEO, "default_severity": SEVERITY_MEDIUM},
    "geo_volume_anomaly": {"source": SOURCE_GEO, "default_severity": SEVERITY_MEDIUM},

    # Threat engine signals
    "threat_score_update": {"source": SOURCE_THREAT_ENGINE, "default_severity": SEVERITY_INFO},
    "threat_escalation": {"source": SOURCE_THREAT_ENGINE, "default_severity": SEVERITY_HIGH},

    # Firewall signals
    "firewall_block": {"source": SOURCE_FIREWALL, "default_severity": SEVERITY_INFO},
    "firewall_pass": {"source": SOURCE_FIREWALL, "default_severity": SEVERITY_INFO},
    "repeated_blocks": {"source": SOURCE_FIREWALL, "default_severity": SEVERITY_MEDIUM},
    "multi_port_blocks": {"source": SOURCE_FIREWALL, "default_severity": SEVERITY_MEDIUM},

    # System signals
    "service_down": {"source": SOURCE_SERVICE_MONITOR, "default_severity": SEVERITY_HIGH},
    "service_recovery": {"source": SOURCE_SERVICE_MONITOR, "default_severity": SEVERITY_INFO},
    "wan_flap": {"source": SOURCE_WAN_FLAP, "default_severity": SEVERITY_HIGH},
    "system_anomaly": {"source": SOURCE_SYSTEM_LOG, "default_severity": SEVERITY_MEDIUM},

    # Correlation signals (internal)
    "attack_chain": {"source": SOURCE_CORRELATION, "default_severity": SEVERITY_CRITICAL},
    "incident_created": {"source": SOURCE_CORRELATION, "default_severity": SEVERITY_INFO},
    "incident_escalated": {"source": SOURCE_CORRELATION, "default_severity": SEVERITY_HIGH},
}


# ── Signal data class ────────────────────────────────────────────────

class Signal:
    """Immutable signal object."""

    __slots__ = ("source", "signal_type", "severity", "ip", "metadata",
                 "timestamp", "signal_id")

    def __init__(self, source: str, signal_type: str, severity: str,
                 ip: str, metadata: Dict[str, Any], timestamp: Optional[float] = None,
 signal_id: Optional[str] = None):
        self.source = source
        self.signal_type = signal_type
        self.severity = severity
        self.ip = ip
        self.metadata = metadata
        self.timestamp = timestamp or time.time()
        self.signal_id = signal_id

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for DB insertion or API response."""
        return {
            "source": self.source,
            "signal_type": self.signal_type,
            "severity": self.severity,
            "ip": self.ip,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "signal_id": self.signal_id,
        }

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def __repr__(self):
        return (f"Signal({self.source}/{self.signal_type} severity={self.severity} "
                f"ip={self.ip} ts={self.timestamp:.0f})")


# ── Signal Bus ────────────────────────────────────────────────────────

class SignalBus:
    """Central signal bus for all detection modules.

    Collects signals from all detectors, persists them to PostgreSQL,
    and routes them to downstream consumers (BehaviorProfiler,
    CorrelationEngine).

    Thread-safe: uses a bounded deque with lock.
    Backpressure: drops oldest signals when queue is full.
    """

    def __init__(self, db: Any = None, max_queue: int = 10000):
        """Initialize signal bus.

        Args:
            db: EventDatabase instance for persistence.
            max_queue: Maximum signal queue size (backpressure limit).
        """
        self.db = db
        self._queue: deque = deque(maxlen=max_queue)
        self._lock = threading.Lock()
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._total_emitted = 0
        self._total_dropped = 0
        self._total_persisted = 0
        self._running = True
        logger.info("SignalBus initialized (max_queue=%d)", max_queue)

    def emit(self, source: str, signal_type: str, severity: str,
             ip: str, metadata: Optional[Dict[str, Any]] = None,
 timestamp: Optional[float] = None) -> Optional[Signal]:
        """Emit a signal into the bus.

        This is the primary interface for all detectors. Signals are
        queued, persisted, and routed to subscribers.

        Args:
            source: Signal source (e.g., 'attack_detector', 'nginx').
            signal_type: Signal type (e.g., 'port_scan', 'http_attack').
            severity: Severity level (info/low/medium/high/critical).
            ip: Source IP address.
            metadata: Arbitrary metadata dict.
            timestamp: Unix timestamp (defaults to now).

        Returns:
            Signal object (may be used by caller for reference).
        """
        # CRITICAL DEBUG - count emits
        if self._total_emitted < 10 or self._total_emitted == 1000 or self._total_emitted == 5000:
            print(f"SIGNAL_BUS: emit #{self._total_emitted}: source={source} type={signal_type} subs={len(self._subscribers)}")
            sys.stdout.flush()
        if not self._running:
            logger.warning("SignalBus is shut down, dropping signal: %s/%s",
                          source, signal_type)
            return None

        # Validate severity
        if severity not in SEVERITY_ORDER:
            severity = SEVERITY_INFO

        # Override source with signal_type's default source if source doesn't match
        if signal_type in SIGNAL_TYPES:
            expected_source = SIGNAL_TYPES[signal_type]["source"]
            if source != expected_source:
                logger.debug("Signal source mismatch: %s/%s (expected source=%s)",
                           source, signal_type, expected_source)

        signal = Signal(
            source=source,
            signal_type=signal_type,
            severity=severity,
            ip=ip,
            metadata=metadata or {},
            timestamp=timestamp,
        )

        with self._lock:
            if len(self._queue) == self._queue.maxlen:
                self._total_dropped += 1
                # Queue is full, oldest signal dropped by deque maxlen
            self._queue.append(signal)
            self._total_emitted += 1

        # Persist to DB (async-friendly, non-blocking)
        self._persist(signal)

        # Route to subscribers
        if self._total_emitted <= 3 or self._total_emitted % 100 == 0:
            logger.info("SignalBus.emit #%d: routing %s/%s (subscribers=%d)",
                       self._total_emitted, signal.source, signal.signal_type,
                       sum(len(v) for v in self._subscribers.values()))
        self._route(signal)

        return signal

    def subscribe(self, event: str, callback: Callable[[Signal], None]):
        """Subscribe to signals matching a pattern.

        Args:
            event: Event pattern. Use 'all' for all signals, 'source:<name>' for
                   signals from a specific source, 'type:<name>' for a specific
                   signal type, or 'severity:<level>' for minimum severity.
            callback: Function called with the Signal object.
        """
        with self._lock:
            self._subscribers[event].append(callback)

    def unsubscribe(self, event: str, callback: Callable):
        """Unsubscribe from signals."""
        with self._lock:
            if event in self._subscribers:
                self._subscribers[event].remove(callback)

    def get_recent(self, count: int = 100, source: Optional[str] = None,
                   severity: Optional[str] = None) -> List[Signal]:
        """Get recent signals from the queue.

        Args:
            count: Maximum number of signals to return.
            source: Filter by source.
            severity: Filter by minimum severity level.

        Returns:
            List of Signal objects (most recent first).
        """
        with self._lock:
            signals = list(self._queue)

        # Filter
        if source:
            signals = [s for s in signals if s.source == source]
        if severity:
            min_rank = SEVERITY_ORDER.get(severity, 0)
            signals = [s for s in signals if s.severity_rank >= min_rank]

        # Sort by timestamp (most recent first)
        signals.sort(key=lambda s: s.timestamp, reverse=True)

        return signals[:count]

    def get_stats(self) -> Dict[str, Any]:
        """Get signal bus statistics."""
        with self._lock:
            # Count by source
            by_source: Dict[str, int] = defaultdict(int)
            by_type: Dict[str, int] = defaultdict(int)
            by_severity: Dict[str, int] = defaultdict(int)
            for s in self._queue:
                by_source[s.source] += 1
                by_type[s.signal_type] += 1
                by_severity[s.severity] += 1

            return {
                "total_emitted": self._total_emitted,
                "total_dropped": self._total_dropped,
                "total_persisted": self._total_persisted,
                "queue_size": len(self._queue),
                "queue_max": self._queue.maxlen,
                "by_source": dict(by_source),
                "by_type": dict(by_type),
                "by_severity": dict(by_severity),
            }

    def shutdown(self):
        """Shut down the signal bus."""
        self._running = False
        logger.info("SignalBus shut down: emitted=%d, dropped=%d, persisted=%d",
                    self._total_emitted, self._total_dropped, self._total_persisted)

    def _persist(self, signal: Signal):
        """Persist a signal to the ip_behavior_signals table."""
        if not self.db:
            return

        try:
            self.db.execute(
                """INSERT INTO ip_behavior_signals
                   (ip, timestamp, source, signal_type, severity, metadata)
                   VALUES (%s, to_timestamp(%s), %s, %s, %s, %s)""",
                (signal.ip, signal.timestamp, signal.source, signal.signal_type,
                 signal.severity, json.dumps(signal.metadata)),
            )
            self._total_persisted += 1
        except Exception as e:
            logger.warning("Failed to persist signal %s/%s: %s",
                          signal.source, signal.signal_type, e)

    def _route(self, signal: Signal):
        """Route a signal to all matching subscribers."""
        with self._lock:
            subscribers_copy = dict(self._subscribers)

        if not subscribers_copy:
            logger.info("SignalBus._route: NO subscribers for %s/%s — callback may not be registered", 
                       signal.source, signal.signal_type)
            return

        total_subs = sum(len(v) for v in subscribers_copy.values())
        matched = 0
        for event, callbacks in subscribers_copy.items():
            is_match = self._matches(event, signal)
            if is_match:
                for callback in callbacks:
                    try:
                        callback(signal)
                        matched += 1
                    except Exception as e:
                        logger.error("Signal subscriber error for %s: %s", event, e)
        
        # Log first few routing events for debugging
        if self._total_emitted <= 5:
            print(f"SIGNAL_ROUTE: event={event} matched={is_match} total_matched={matched} total_subs={total_subs}")
            sys.stdout.flush()
        # Log routing stats periodically
        if self._total_emitted % 1000 == 0:
            logger.info("SignalBus routing stats: total_emitted=%d, subscribers=%d, last_match=%s (matched=%d)",
                       self._total_emitted, total_subs, signal.signal_type, matched)

    def _matches(self, event: str, signal: Signal) -> bool:
        """Check if a signal matches a subscription event pattern."""
        if event == "all":
            return True
        if event.startswith("source:"):
            return signal.source == event[7:]
        if event.startswith("type:"):
            return signal.signal_type == event[5:]
        if event.startswith("severity:"):
            min_severity = event[9:]
            min_rank = SEVERITY_ORDER.get(min_severity, 0)
            return signal.severity_rank >= min_rank
        return False
