#!/usr/bin/env python3
"""
Unified Behavioral Engine for OPNsense Anomaly Detection Agent.

Merges four siloed detection modules into a single behavioral analysis engine:
- ip_behavior_model.py (BehaviorProfiler): per-IP EMA baselines, deviation signals
- threat_engine.py (ThreatEngine): multi-source threat scoring, adaptive weights
- baseline_engine.py (BaselineEngine): rule-level traffic baselines from training data
- statistical_model.py (StatisticalModel): global rolling statistics, z-score anomaly detection

Architecture:
  - Single ingest_event() / ingest_batch() entry point for all event types
  - Unified IP profile (UnifiedIPProfile): one profile per IP, all features
  - Unified behavioral score (0-100) combining deviation, threat, baseline, and statistical signals
  - Unified threat level enum: BENIGN, SUSPICIOUS, RECONNAISSANCE, ATTACK, EXPLOIT
  - Single DB persistence layer (unified_ip_profiles, unified_signals, unified_baselines)
  - Adaptive signal weights from user feedback (attack/benign labels)

Usage:
    from unified_behavioral_engine import UnifiedBehavioralEngine
    engine = UnifiedBehavioralEngine(event_database)
    signals = engine.ingest_event(event)
    profile = engine.get_profile("192.168.1.50")
    engine.record_attack("1.2.3.4")       # feedback: confirmed attack
    engine.record_benign("10.0.0.1")      # feedback: confirmed benign
"""

import json
import logging
import math
import time
import threading
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter, deque
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)


# ============================================================
# Configuration — consolidated from all 4 modules
# ============================================================

# ── EMA windows (from ip_behavior_model.py) ──
# alpha = decay rate. Higher = faster adaptation.
EMA_WINDOWS = {
    "1h":  {"alpha": 0.15,  "seconds": 3600},
    "6h":  {"alpha": 0.05,  "seconds": 21600},
    "24h": {"alpha": 0.02,  "seconds": 86400},
    "7d":  {"alpha": 0.005, "seconds": 604800},
}

# ── Feature dimensions tracked per IP (from ip_behavior_model.py) ──
FEATURE_DIMENSIONS = [
    "conn_rate",          # connections per minute
    "unique_dst_ports",   # unique destination ports per window
    "unique_dst_ips",     # unique destination IPs per window
    "bytes_per_conn",     # average bytes per connection
    "packet_count",       # packets per window
]

# ── Z-score thresholds (from ip_behavior_model.py) ──
ZSCORE_WARNING = 2.0
ZSCORE_CRITICAL = 3.5

# ── Unified threat levels (new — replaces separate threshold systems) ──
class ThreatLevel(IntEnum):
    """Unified threat level with numeric ordering for comparison."""
    BENIGN = 0           # score 0-20: normal traffic, no concern
    SUSPICIOUS = 1       # score 21-40: mild deviation or single weak signal
    RECONNAISSANCE = 2   # score 41-60: active scanning, port sweeps, enumeration
    ATTACK = 3           # score 61-80: confirmed attack patterns, IDS hits
    EXPLOIT = 4          # score 81-100: exploit attempts, critical threats, multi-source correlation


# ── Threat score boundaries for level assignment ──
THREAT_LEVEL_THRESHOLDS = {
    ThreatLevel.BENIGN:         (0, 20),
    ThreatLevel.SUSPICIOUS:     (21, 40),
    ThreatLevel.RECONNAISSANCE: (41, 60),
    ThreatLevel.ATTACK:         (61, 80),
    ThreatLevel.EXPLOIT:        (81, 100),
}

# ── Default signal weights (from threat_engine.py) ──
# Overridden by AdaptiveWeights at runtime based on user feedback.
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
    "geo_anomaly": 0.15,
    "deviation_conn_rate": 0.20,
    "deviation_unique_dst_ports": 0.25,
    "deviation_unique_dst_ips": 0.20,
    "deviation_bytes_per_conn": 0.15,
    "deviation_packet_count": 0.10,
    "statistical_anomaly": 0.15,
}

# ── Score decay settings (from threat_engine.py) ──
SCORE_DECAY_RATE = 0.95      # per-hour base decay
SCORE_DECAY_MIN = 0.1        # minimum decay floor

# ── Adaptive weight tuning (from threat_engine.py) ──
ADAPTIVE_LEARNING_RATE = 0.1
ADAPTIVE_WEIGHT_MIN = 0.02
ADAPTIVE_WEIGHT_MAX = 1.0
ADAPTIVE_DECAY_BOOST = 1.5
ADAPTIVE_ATTACK_BOOST = 1.3
ADAPTIVE_MIN_FEEDBACK = 3

# ── Baseline settings (from baseline_engine.py) ──
MIN_EVENTS_FOR_BASELINE = 10
TEMPORAL_DRIFT_THRESHOLD = 0.5

# ── Statistical model settings (from statistical_model.py) ──
DEFAULT_ANOMALY_THRESHOLD = 3.0
DEFAULT_MIN_SAMPLES = 30
DEFAULT_WINDOW_MINUTES = 60

# ── Persistence settings (from ip_behavior_model.py) ──
PERSIST_INTERVAL = 100
MAX_RECENT_SIGNALS = 200


# ============================================================
# Utility classes — extracted from original modules
# ============================================================

class EMABaseline:
    """Exponential Moving Average baseline for a single feature.

    Tracks mean, variance, and count using EMA that adapts faster
    than Welford's online algorithm (configurable alpha per window).

    Source: ip_behavior_model.py
    """

    __slots__ = ("alpha", "mean", "var", "count", "last_update")

    def __init__(self, alpha: float):
        self.alpha = alpha
        self.mean = 0.0
        self.var = 0.0
        self.count = 0
        self.last_update = 0.0

    def update(self, value: float) -> None:
        """Update EMA with a new observation."""
        self.count += 1
        diff = value - self.mean
        self.mean += self.alpha * diff
        self.var += self.alpha * (diff * diff - self.var)
        # Clamp variance to avoid numerical drift
        self.var = max(0.0, self.var)
        self.last_update = time.time()

    def z_score(self, value: float) -> float:
        """Compute z-score of a value against this baseline.

        Returns 0 if insufficient data (count < 10).
        """
        if self.count < 10:
            return 0.0
        std = math.sqrt(self.var) if self.var > 0 else 1.0
        # Minimum std floor to avoid infinite z-scores
        std = max(std, 0.1)
        return (value - self.mean) / std

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-serializable dict."""
        return {
            "alpha": self.alpha,
            "mean": round(self.mean, 4),
            "var": round(self.var, 4),
            "stddev": round(math.sqrt(max(0, self.var)), 4),
            "count": self.count,
        }


class RunningStats:
    """Maintains running mean and standard deviation using Welford's online algorithm.

    Source: statistical_model.py
    """

    def __init__(self):
        self.count: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0
        self._values: deque = deque(maxlen=1000)

    def update(self, value: float) -> None:
        """Update running statistics with a new value."""
        self.count += 1
        self._values.append(value)
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def stddev(self) -> float:
        """Calculate standard deviation."""
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))

    @property
    def variance(self) -> float:
        """Calculate variance."""
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    def z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        sd = self.stddev
        if sd == 0:
            return 0.0
        return (value - self.mean) / sd

    def latest_values(self, n: int = 10) -> List[float]:
        """Get the N most recent values."""
        return list(self._values)[-n:]


@dataclass
class SignalFeedback:
    """Per-signal-type feedback history for adaptive weighting.

    Source: threat_engine.py
    """
    signal_type: str
    attack_count: int = 0
    benign_count: int = 0
    last_attack: Optional[datetime] = None
    last_benign: Optional[datetime] = None
    current_weight: Optional[float] = None   # None = use default from SIGNAL_WEIGHTS
    decay_multiplier: float = 1.0            # >1 means faster decay (stale/benign signals)


class AdaptiveWeights:
    """Learns optimal signal weights from user feedback (attack/benign labels).

    Core logic:
    - Confirmed attack: boost weights of correlated signals.
    - Confirmed benign: reduce weights and increase decay for false-positive signals.
    - Weights clamped to [ADAPTIVE_WEIGHT_MIN, ADAPTIVE_WEIGHT_MAX].
    - Persists to / loads from the adaptive_weights database table.

    Source: threat_engine.py
    """

    def __init__(self, db: Any = None):
        self._feedback: Dict[str, SignalFeedback] = {}
        self.db = db
        if db:
            self._ensure_table()
            self._load_from_db()

    def _ensure_table(self) -> None:
        """Ensure the adaptive_weights table exists (managed by schema_migrations)."""
        pass  # Managed by schema_migrations.py

    def _load_from_db(self) -> None:
        """Load existing adaptive weight entries from database."""
        try:
            cur = self.db.execute("SELECT * FROM adaptive_weights")
            rows = cur.fetchall()
            for row in rows:
                signal_type = row[0]
                self._feedback[signal_type] = SignalFeedback(
                    signal_type=signal_type,
                    attack_count=row[1] or 0,
                    benign_count=row[2] or 0,
                    last_attack=datetime.fromisoformat(row[3]) if row[3] else None,
                    last_benign=datetime.fromisoformat(row[4]) if row[4] else None,
                    current_weight=row[5],
                    decay_multiplier=row[6] or 1.0,
                )
            logger.info("Loaded %d adaptive weight entries from DB", len(self._feedback))
        except Exception as e:
            logger.debug("No adaptive weights in DB yet: %s", e)

    def save_to_db(self) -> None:
        """Persist current adaptive weights to database."""
        if not self.db:
            return
        try:
            for st, fb in self._feedback.items():
                self.db.execute("""
                    INSERT INTO adaptive_weights
                        (signal_type, attack_count, benign_count, last_attack,
                         last_benign, weight, decay_multiplier)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (signal_type) DO UPDATE SET
                        attack_count = EXCLUDED.attack_count,
                        benign_count = EXCLUDED.benign_count,
                        last_attack = EXCLUDED.last_attack,
                        last_benign = EXCLUDED.last_benign,
                        weight = EXCLUDED.weight,
                        decay_multiplier = EXCLUDED.decay_multiplier
                """, (
                    st,
                    fb.attack_count,
                    fb.benign_count,
                    fb.last_attack.isoformat() if fb.last_attack else None,
                    fb.last_benign.isoformat() if fb.last_benign else None,
                    fb.current_weight,
                    fb.decay_multiplier,
                ))
            self.db.commit()
        except Exception as e:
            logger.error("Failed to save adaptive weights: %s", e)

    def get_weight(self, signal_type: str) -> float:
        """Get the current adaptive weight for a signal type."""
        fb = self._feedback.get(signal_type)
        if fb and fb.current_weight is not None:
            return fb.current_weight
        return SIGNAL_WEIGHTS.get(signal_type, 0.5)

    def get_decay_multiplier(self, signal_type: str) -> float:
        """Get decay multiplier: >1 means faster decay for stale/benign signals."""
        fb = self._feedback.get(signal_type)
        return fb.decay_multiplier if fb else 1.0

    def record_attack(self, signal_types: List[str], timestamp: Optional[datetime] = None) -> None:
        """Record that a confirmed attack contained these signal types.

        Boosts weights for correlated signals.
        """
        ts = timestamp or datetime.now(timezone.utc)
        for st in signal_types:
            fb = self._feedback.setdefault(st, SignalFeedback(signal_type=st))
            fb.attack_count += 1
            fb.last_attack = ts
            total = fb.attack_count + fb.benign_count
            if total < ADAPTIVE_MIN_FEEDBACK:
                logger.debug(
                    "Skipping weight update for %s: only %d/%d feedback samples",
                    st, total, ADAPTIVE_MIN_FEEDBACK,
                )
                continue
            if fb.current_weight is None:
                fb.current_weight = SIGNAL_WEIGHTS.get(st, 0.5)
            ratio = fb.attack_count / total
            target = ADAPTIVE_WEIGHT_MIN + ratio * (ADAPTIVE_WEIGHT_MAX - ADAPTIVE_WEIGHT_MIN)
            target = min(target * ADAPTIVE_ATTACK_BOOST, ADAPTIVE_WEIGHT_MAX)
            fb.current_weight += ADAPTIVE_LEARNING_RATE * (target - fb.current_weight)
            fb.current_weight = max(fb.current_weight, ADAPTIVE_WEIGHT_MIN)
            fb.decay_multiplier = max(1.0, fb.decay_multiplier * 0.95)
            logger.debug(
                "Attack feedback: %s weight=%.3f decay_mult=%.2f "
                "(attacks=%d, benign=%d)",
                st, fb.current_weight, fb.decay_multiplier,
                fb.attack_count, fb.benign_count,
            )

    def record_benign(self, signal_types: List[str], timestamp: Optional[datetime] = None) -> None:
        """Record that a confirmed-benign IP contained these signal types.

        Reduces weights and increases decay for false-positive signals.
        """
        ts = timestamp or datetime.now(timezone.utc)
        for st in signal_types:
            fb = self._feedback.setdefault(st, SignalFeedback(signal_type=st))
            fb.benign_count += 1
            fb.last_benign = ts
            total = fb.attack_count + fb.benign_count
            if total < ADAPTIVE_MIN_FEEDBACK:
                logger.debug(
                    "Skipping weight update for %s: only %d/%d feedback samples",
                    st, total, ADAPTIVE_MIN_FEEDBACK,
                )
                continue
            if fb.current_weight is None:
                fb.current_weight = SIGNAL_WEIGHTS.get(st, 0.5)
            ratio = fb.attack_count / total
            target = ADAPTIVE_WEIGHT_MIN + ratio * (ADAPTIVE_WEIGHT_MAX - ADAPTIVE_WEIGHT_MIN)
            fb.current_weight += ADAPTIVE_LEARNING_RATE * (target - fb.current_weight)
            fb.current_weight = max(fb.current_weight, ADAPTIVE_WEIGHT_MIN)
            fb.decay_multiplier = min(fb.decay_multiplier * ADAPTIVE_DECAY_BOOST, 5.0)
            logger.debug(
                "Benign feedback: %s weight=%.3f decay_mult=%.2f "
                "(attacks=%d, benign=%d)",
                st, fb.current_weight, fb.decay_multiplier,
                fb.attack_count, fb.benign_count,
            )

    def get_feedback_summary(self) -> Dict[str, Dict[str, Any]]:
        """Return current state of all adaptive weights for monitoring."""
        result = {}
        for st, fb in self._feedback.items():
            result[st] = {
                "attack_count": fb.attack_count,
                "benign_count": fb.benign_count,
                "current_weight": fb.current_weight,
                "default_weight": SIGNAL_WEIGHTS.get(st, None),
                "decay_multiplier": fb.decay_multiplier,
                "total_feedback": fb.attack_count + fb.benign_count,
            }
        return result

    def reset(self, signal_type: Optional[str] = None) -> None:
        """Reset weights back to defaults. Reset all if no signal_type given."""
        if signal_type:
            if signal_type in self._feedback:
                self._feedback[signal_type].current_weight = None
                self._feedback[signal_type].decay_multiplier = 1.0
        else:
            self._feedback.clear()


# ============================================================
# Unified IP Profile — one profile per IP, all features
# ============================================================

@dataclass
class UnifiedSignal:
    """A single behavioral signal from any source.

    Replaces ThreatSignal (threat_engine.py) and ad-hoc signal dicts
    from ip_behavior_model.py with a unified structure.

    Score is normalized 0-1 representing the severity/intensity of
    this specific signal instance. Adaptive weights are applied during
    unified score calculation, not at ingestion time.
    """
    source: str                # "firewall", "http", "ids", "zenarmor", "nginx", "behavior", "statistical", "baseline"
    signal_type: str           # e.g. "firewall_port_scan", "deviation_conn_rate", "ids_signature"
    score: float               # normalized 0-1 severity
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


class UnifiedIPProfile:
    """Unified behavioral profile for a single IP address.

    Merges features from:
    - IPBehaviorProfile (ip_behavior_model.py): connection patterns, EMA baselines, deviation signals
    - IPThreatProfile (threat_engine.py): threat signals, multi-source event counts
    - TrafficBaseline (baseline_engine.py): per-rule traffic baselines
    - StatisticalModel (statistical_model.py): global metric baselines

    Each IP has ONE profile. No separate rule-level or source-level profiles.

    Features:
    - Connection patterns: dst_ports, dst_ips, protocols, actions, interfaces
    - Temporal: hour_distribution, daily_distribution
    - Volume: total_bytes, total_packets, bytes_per_conn (EMA)
    - Geographic: countries (Counter), country_risk
    - Source-specific: nginx_paths, ids_signatures, zenarmor_policies
    - Baselines: {window: {feature: EMABaseline}} for 1h, 6h, 24h, 7d windows
    - Behavioral score (0-100) computed from ALL deviation signals
    - Threat level from ThreatLevel enum
    """

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = datetime.now(timezone.utc)
        self.last_seen = self.first_seen
        self.total_events = 0

        # ── Connection patterns ──
        self.dst_ports: Counter = Counter()
        self.dst_ips: Counter = Counter()
        self.protocols: Counter = Counter()
        self.actions: Counter = Counter()          # pass/block
        self.interfaces: Counter = Counter()

        # ── Temporal patterns ──
        self.hour_distribution: Counter = Counter()
        self.daily_distribution: Counter = Counter()

        # ── Volume patterns ──
        self.total_bytes = 0
        self.total_packets = 0

        # ── Geographic patterns ──
        self.countries: Counter = Counter()
        self.country_risk: Dict[str, float] = {}   # country_code -> risk score

        # ── Source-specific patterns ──
        self.nginx_paths: Counter = Counter()
        self.ids_signatures: Counter = Counter()
        self.zenarmor_policies: Counter = Counter()

        # ── Multi-source event counters ──
        self.firewall_events = 0
        self.http_events = 0
        self.ids_events = 0
        self.zenarmor_events = 0
        self.nginx_events = 0
        self.blocked_events = 0

        # ── EMA baselines: {window: {feature: EMABaseline}} ──
        self.baselines: Dict[str, Dict[str, EMABaseline]] = {}
        for window, cfg in EMA_WINDOWS.items():
            self.baselines[window] = {
                feat: EMABaseline(cfg["alpha"]) for feat in FEATURE_DIMENSIONS
            }

        # ── Threat signals ──
        self.signals: List[UnifiedSignal] = []

        # ── Baseline deviations (from baseline_engine) ──
        self.baseline_deviations: List[float] = []

        # ── Signal dedup ──
        self._recent_signals: List[Tuple[str, str, float]] = []

        # ── Persistence tracking ──
        self._events_since_persist = 0

        # ── Window counters (reset on baseline update) ──
        self._window_events = 0
        self._window_start = time.time()
        self._window_unique_ports: set = set()
        self._window_unique_ips: set = set()

    def record_event(self, event: Dict[str, Any]) -> List[UnifiedSignal]:
        """Record a parsed event into this profile.

        Updates all pattern counters, computes deviations against EMA baselines,
        checks for threat patterns (port scan, dest scan, etc.), and returns
        any new signals generated.

        Merges logic from:
        - IPBehaviorProfile.record_event(): pattern tracking + deviation signals
        - ThreatEngine.ingest_*_event(): source-specific threat detection
        - StatisticalModel.record_event(): global metric updates (handled by engine)

        Args:
            event: Parsed event dict with normalized_events schema fields.

        Returns:
            List of new UnifiedSignal instances (may be empty).
        """
        self.total_events += 1
        self.last_seen = datetime.now(timezone.utc)
        now = time.time()

        # ── Extract fields ────────────────────────────────────────────
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dport") or event.get("dst_port")
        proto = event.get("proto", "") or event.get("protocol", "")
        action = event.get("action", "")
        interface = event.get("interface", "")
        total_length = event.get("ip_total_length", 0) or 0
        tcp_flags = event.get("tcp_flags", "")
        log_type = event.get("log_type", "")
        rule = event.get("rule", "")

        # Timestamp extraction (from IPBehaviorProfile)
        ts = event.get("timestamp")
        hour = 0
        dow = 0
        if isinstance(ts, datetime):
            hour = ts.hour
            dow = ts.weekday()
        elif isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour
                dow = dt.weekday()
            except (ValueError, AttributeError):
                pass

        # Country from event (populated by geo_lookup)
        country = event.get("country_code", "") or event.get("geo_country", "")

        # ── Update pattern counters ───────────────────────────────────
        if dst_port is not None:
            self.dst_ports[int(dst_port)] += 1
        if dst_ip:
            self.dst_ips[dst_ip] += 1
        if proto:
            self.protocols[proto] += 1
        if action:
            self.actions[action] += 1
        if interface:
            self.interfaces[interface] += 1
        self.hour_distribution[hour] += 1
        self.daily_distribution[dow] += 1
        self.total_bytes += total_length
        self.total_packets += 1
        if country:
            self.countries[country] += 1

        # ── Source-specific counters (from ThreatEngine) ──────────────
        if log_type == "filterlog":
            self.firewall_events += 1
        elif log_type == "http":
            self.http_events += 1
        elif log_type in ("ids", "suricata"):
            self.ids_events += 1
            sig = event.get("signature", "")
            if sig:
                self.ids_signatures[sig] += 1
        elif log_type == "zenarmor":
            self.zenarmor_events += 1
            policy = event.get("policy", "") or event.get("threat_type", "")
            if policy:
                self.zenarmor_policies[policy] += 1
        elif log_type == "nginx":
            self.nginx_events += 1
            path = event.get("path", "")
            if path:
                self.nginx_paths[path] += 1

        if action in ("block", "BLOCK"):
            self.blocked_events += 1

        # ── Update window counters (from IPBehaviorProfile) ──────────
        self._window_events += 1
        if dst_port is not None:
            self._window_unique_ports.add(int(dst_port))
        if dst_ip:
            self._window_unique_ips.add(dst_ip)

        # ── Compute current-window feature values ─────────────────────
        elapsed = max(now - self._window_start, 1)
        window_minutes = elapsed / 60.0
        conn_rate = self._window_events / max(window_minutes, 0.01)
        unique_ports = len(self._window_unique_ports)
        unique_ips = len(self._window_unique_ips)
        bytes_per_conn = self.total_bytes / max(self.total_events, 1)
        packet_count = self._window_events

        feature_values = {
            "conn_rate": conn_rate,
            "unique_dst_ports": float(unique_ports),
            "unique_dst_ips": float(unique_ips),
            "bytes_per_conn": float(bytes_per_conn),
            "packet_count": float(packet_count),
        }

        # ── Source-specific threat detection (from ThreatEngine) ──────
        new_signals: List[UnifiedSignal] = []

        # Firewall: block ratio
        if self.firewall_events > 3:
            block_ratio = self.blocked_events / max(self.firewall_events, 1)
            if block_ratio > 0.5:
                new_signals.append(UnifiedSignal(
                    source="firewall",
                    signal_type="firewall_block_ratio",
                    score=min(block_ratio, 1.0),
                    timestamp=self.last_seen,
                    details={"blocked": self.blocked_events, "total": self.firewall_events},
                ))

        # Firewall: port scan detection
        if self.firewall_events >= 5 and len(self.dst_ports) > 10:
            new_signals.append(UnifiedSignal(
                source="firewall",
                signal_type="firewall_port_scan",
                score=0.8,
                timestamp=self.last_seen,
                details={"unique_ports": len(self.dst_ports), "dst_port": dst_port},
            ))

        # Firewall: destination scan detection
        if self.firewall_events >= 10 and len(self.dst_ips) > 20:
            new_signals.append(UnifiedSignal(
                source="firewall",
                signal_type="firewall_dest_scan",
                score=0.7,
                timestamp=self.last_seen,
                details={"unique_dsts": len(self.dst_ips), "dst_ip": dst_ip},
            ))

        # HTTP anomaly detection
        if log_type == "http":
            status_code = event.get("status_code")
            path = event.get("path", "")
            if status_code and str(status_code).startswith("4"):
                new_signals.append(UnifiedSignal(
                    source="http",
                    signal_type="http_anomaly",
                    score=0.3,
                    timestamp=self.last_seen,
                    details={"status_code": status_code},
                ))
            if path and any(p in path.lower() for p in ["../", ".php?", "cmd=", "exec=", "eval="]):
                new_signals.append(UnifiedSignal(
                    source="http",
                    signal_type="http_anomaly",
                    score=0.8,
                    timestamp=self.last_seen,
                    details={"path": path, "type": "path_traversal"},
                ))

        # IDS signature detection
        if log_type in ("ids", "suricata"):
            severity = event.get("severity", "low")
            severity_score = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}.get(severity, 0.3)
            new_signals.append(UnifiedSignal(
                source="ids",
                signal_type="ids_signature",
                score=severity_score,
                timestamp=self.last_seen,
                details={"signature": event.get("signature", ""), "severity": severity},
            ))

        # ZenArmor threat detection
        if log_type == "zenarmor":
            threat_level = event.get("threat_level", "low")
            level_score = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}.get(threat_level, 0.3)
            new_signals.append(UnifiedSignal(
                source="zenarmor",
                signal_type="zenarmor_threat",
                score=level_score,
                timestamp=self.last_seen,
                details={"threat_type": event.get("threat_type", ""), "threat_level": threat_level},
            ))

        # Nginx attack detection
        if log_type == "nginx":
            attack_type = event.get("attack_type")
            if attack_type:
                new_signals.append(UnifiedSignal(
                    source="nginx",
                    signal_type="nginx_attack",
                    score=0.7,
                    timestamp=self.last_seen,
                    details={"attack_type": attack_type},
                ))

        # ── Baseline deviation signals (from baseline_engine) ─────────
        # Volume anomaly: check if bytes per connection deviates significantly
        if self.total_events > MIN_EVENTS_FOR_BASELINE and total_length > 0:
            avg_bytes = self.total_bytes / self.total_events
            if avg_bytes > 10000:
                new_signals.append(UnifiedSignal(
                    source="firewall",
                    signal_type="volume_anomaly",
                    score=min((avg_bytes - 5000) / 10000, 1.0),
                    timestamp=self.last_seen,
                    details={"avg_bytes": avg_bytes, "total_length": total_length},
                ))

        # Temporal anomaly: activity at unusual hours (0-5 AM)
        if hour and 0 <= hour <= 5 and self.total_events > MIN_EVENTS_FOR_BASELINE:
            day_ratio = self.hour_distribution.get(hour, 0) / sum(self.hour_distribution.values()) if self.hour_distribution else 0
            if day_ratio > 0.3:  # More than 30% of traffic in off-hours
                new_signals.append(UnifiedSignal(
                    source="behavior",
                    signal_type="temporal_anomaly",
                    score=0.5,
                    timestamp=self.last_seen,
                    details={"hour": hour, "day_ratio": round(day_ratio, 3)},
                ))

        # ── Deviation z-score signals (from IPBehaviorProfile) ────────
        for window, baselines in self.baselines.items():
            for feat, value in feature_values.items():
                baseline = baselines.get(feat)
                if baseline is None:
                    continue

                z = baseline.z_score(value)

                # Check for significant deviation
                if abs(z) >= ZSCORE_WARNING and self.total_events >= 50:
                    severity = "high" if abs(z) >= ZSCORE_CRITICAL else "medium"
                    signal_type = f"deviation_{feat}"

                    # Dedup: skip if same signal emitted recently
                    sig_key = (signal_type, severity)
                    if self._recent_signals and self._recent_signals[-1][0] == signal_type:
                        last_ts = self._recent_signals[-1][2]
                        if now - last_ts < 300:  # 5 min cooldown
                            continue

                    new_signals.append(UnifiedSignal(
                        source="behavior",
                        signal_type=signal_type,
                        score=min(abs(z) / ZSCORE_CRITICAL, 1.0),
                        timestamp=self.last_seen,
                        details={
                            "window": window,
                            "z_score": round(z, 2),
                            "value": round(value, 2),
                            "baseline_mean": round(baseline.mean, 2),
                            "baseline_std": round(math.sqrt(max(0, baseline.var)), 2),
                        },
                    ))
                    self._recent_signals.append((signal_type, severity, now))
                    if len(self._recent_signals) > MAX_RECENT_SIGNALS:
                        self._recent_signals = self._recent_signals[-MAX_RECENT_SIGNALS:]

                # Update EMA with current value (after z-score check)
                baseline.update(value)

        # ── Add signals to profile (with dedup) ───────────────────────
        for signal in new_signals:
            # Dedup against existing signals: skip if very recent duplicate
            is_dup = False
            for existing in self.signals[-50:]:
                if (existing.signal_type == signal.signal_type
                        and existing.source == signal.source
                        and (self.last_seen - existing.timestamp).total_seconds() < 60):
                    is_dup = True
                    break
            if not is_dup:
                self.signals.append(signal)
                if len(self.signals) > MAX_RECENT_SIGNALS:
                    self.signals = self.signals[-MAX_RECENT_SIGNALS:]

        self._events_since_persist += 1
        return new_signals

    def compute_behavioral_score(self, adaptive_weights: Optional[AdaptiveWeights] = None) -> float:
        """Compute unified behavioral score (0-100).

        Aggregates signals from all sources:
        - Deviation z-scores against EMA baselines (from ip_behavior_model)
        - Weighted threat signal scores with adaptive weights (from threat_engine)
        - Baseline deviation penalties (from baseline_engine)
        - Statistical anomaly scores (from statistical_model)

        Higher score = more anomalous behavior.

        Args:
            adaptive_weights: Optional AdaptiveWeights for per-signal-type weights.
                Falls back to SIGNAL_WEIGHTS defaults if None.

        Returns:
            Float in range [0.0, 100.0].
        """
        if self.total_events < 10:
            return 0.0

        get_weight = (
            adaptive_weights.get_weight if adaptive_weights is not None
            else lambda st: SIGNAL_WEIGHTS.get(st, 0.5)
        )

        # ── Component 1: Weighted signal scores (from ThreatEngine) ───
        if self.signals:
            signal_scores: Dict[str, List[float]] = defaultdict(list)
            for signal in self.signals:
                signal_scores[signal.signal_type].append(signal.score)

            weighted_score = 0.0
            total_weight = 0.0
            for signal_type, scores in signal_scores.items():
                avg_score = sum(scores) / len(scores)
                weight = get_weight(signal_type)
                weighted_score += avg_score * weight
                total_weight += weight

            if total_weight > 0:
                signal_component = (weighted_score / total_weight) * 100.0
            else:
                signal_component = 0.0
        else:
            signal_component = 0.0

        # ── Component 2: Behavioral pattern score (from IPBehaviorProfile) ─
        # Block ratio, port diversity, destination diversity, volume anomaly
        block_count = self.actions.get("block", 0) + self.actions.get("BLOCK", 0)
        block_ratio = block_count / max(self.total_events, 1)
        port_diversity = len(self.dst_ports) / max(self.total_events, 1)
        dst_diversity = len(self.dst_ips) / max(self.total_events, 1)
        avg_bytes = self.total_bytes / max(self.total_events, 1) if self.total_bytes > 0 else 0

        behavior_component = 0.0
        # Block ratio component (0-30)
        if block_ratio > 0.8:
            behavior_component += 30
        elif block_ratio > 0.5:
            behavior_component += 15
        elif block_ratio > 0.2:
            behavior_component += 5

        # Port diversity component (0-30)
        if port_diversity > 0.5:
            behavior_component += 30
        elif port_diversity > 0.2:
            behavior_component += 15
        elif port_diversity > 0.05:
            behavior_component += 5

        # Destination diversity (0-20)
        if dst_diversity > 0.5:
            behavior_component += 20
        elif dst_diversity > 0.2:
            behavior_component += 10

        # Volume anomaly (0-20)
        if self.total_events > 100:
            if avg_bytes > 10000:
                behavior_component += 20
            elif avg_bytes > 5000:
                behavior_component += 10

        behavior_component = min(behavior_component, 100.0)

        # ── Component 3: Baseline deviation penalty (from baseline_engine) ─
        baseline_penalty = 0.0
        if self.baseline_deviations:
            avg_deviation = sum(self.baseline_deviations[-10:]) / min(len(self.baseline_deviations), 10)
            baseline_penalty = avg_deviation * 10  # Scale to ~0-20 range

        # ── Component 4: Recent deviation signal intensity ──
        recent_deviations = sum(
            1 for s in self._recent_signals[-50:]
            if s[1] in ("medium", "high")
        )
        deviation_component = min(recent_deviations * 2.0, 20.0)

        # ── Final aggregation: blend all components ────────────────────
        # Weight signal-based scoring most heavily (it has the most signal types)
        if self.signals:
            score = (
                signal_component * 0.5 +
                behavior_component * 0.25 +
                baseline_penalty * 0.15 +
                deviation_component * 0.10
            )
        else:
            # No signals yet, rely on behavioral patterns
            score = (
                behavior_component * 0.5 +
                baseline_penalty * 0.3 +
                deviation_component * 0.2
            )

        # Apply baseline deviation multiplier
        score *= (1 + baseline_penalty * 0.01)

        return round(min(max(score, 0.0), 100.0), 1)

    def get_threat_level(self) -> ThreatLevel:
        """Map behavioral score to unified threat level.

        Uses the pre-computed behavioral score and THREAT_LEVEL_THRESHOLDS
        to assign BENIGN, SUSPICIOUS, RECONNAISSANCE, ATTACK, or EXPLOIT.

        Returns:
            ThreatLevel enum value.
        """
        score = self.compute_behavioral_score()
        for level, (low, high) in THREAT_LEVEL_THRESHOLDS.items():
            if low <= score <= high:
                return level
        return ThreatLevel.EXPLOIT  # score > 100 (shouldn't happen, but safe fallback)

    def apply_decay(self, adaptive_weights: AdaptiveWeights) -> None:
        """Apply time-based decay to all signal scores.

        Each signal is decayed individually based on its age and its
        signal_type's adaptive decay_multiplier.

        Args:
            adaptive_weights: The shared AdaptiveWeights instance for per-signal-type config.
        """
        if not self.signals:
            return

        now = datetime.now(timezone.utc)
        for signal in self.signals:
            hours_old = (now - signal.timestamp).total_seconds() / 3600
            if hours_old > 0:
                decay_mult = adaptive_weights.get_decay_multiplier(signal.signal_type)
                effective_rate = SCORE_DECAY_RATE ** (hours_old * decay_mult)
                effective_rate = max(effective_rate, SCORE_DECAY_MIN)
                signal.score *= effective_rate

        # Remove decayed signals that are effectively zero
        self.signals = [s for s in self.signals if s.score > 0.01]

    def to_profile_data(self) -> Dict[str, Any]:
        """Serialize profile patterns to JSON-serializable dict.

        Returns:
            Dict with all connection, temporal, volume, geographic, and
            source-specific pattern data suitable for DB persistence or API response.
        """
        return {
            "dst_ports": dict(self.dst_ports.most_common(50)),
            "dst_ips": dict(self.dst_ips.most_common(50)),
            "protocols": dict(self.protocols.most_common(20)),
            "actions": dict(self.actions.most_common(10)),
            "interfaces": dict(self.interfaces.most_common(10)),
            "hour_distribution": {str(k): v for k, v in self.hour_distribution.items()},
            "daily_distribution": {str(k): v for k, v in self.daily_distribution.items()},
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "countries": dict(self.countries.most_common(20)),
            "unique_dst_ports": len(self.dst_ports),
            "unique_dst_ips": len(self.dst_ips),
            "nginx_paths": dict(self.nginx_paths.most_common(20)),
            "ids_signatures": dict(self.ids_signatures.most_common(20)),
            "zenarmor_policies": dict(self.zenarmor_policies.most_common(20)),
            "firewall_events": self.firewall_events,
            "http_events": self.http_events,
            "ids_events": self.ids_events,
            "zenarmor_events": self.zenarmor_events,
            "nginx_events": self.nginx_events,
            "blocked_events": self.blocked_events,
        }

    def to_baseline_data(self) -> Dict[str, Any]:
        """Serialize baseline data to JSON-serializable dict.

        Returns:
            Dict mapping window -> feature -> baseline stats.
        """
        result = {}
        for window, baselines in self.baselines.items():
            result[window] = {
                feat: bl.to_dict() for feat, bl in baselines.items()
            }
        return result

    def to_signals_data(self) -> List[Dict[str, Any]]:
        """Serialize all signals to JSON-serializable list.

        Returns:
            List of signal dicts suitable for DB persistence.
        """
        return [
            {
                "source": s.source,
                "signal_type": s.signal_type,
                "score": round(s.score, 4),
                "timestamp": s.timestamp.isoformat(),
                "details": s.details,
            }
            for s in self.signals
        ]

    def needs_persist(self) -> bool:
        """Check if this profile needs to be flushed to the database."""
        return self._events_since_persist >= PERSIST_INTERVAL

    def mark_persisted(self) -> None:
        """Mark this profile as persisted (reset event counter)."""
        self._events_since_persist = 0


# ============================================================
# Unified Behavioral Engine
# ============================================================

class UnifiedBehavioralEngine:
    """Single entry point for all behavioral analysis and threat detection.

    Replaces four separate engines:
    - BehaviorProfiler (ip_behavior_model.py): per-IP behavioral profiling with EMA baselines
    - ThreatEngine (threat_engine.py): multi-source threat scoring with adaptive weights
    - BaselineEngine (baseline_engine.py): rule-level traffic baselines from training data
    - StatisticalModel (statistical_model.py): global rolling statistics and anomaly detection

    Architecture:
    - ingest_event() / ingest_batch(): single entry point for all event types
    - UnifiedIPProfile: one profile per IP, all features merged
    - Behavioral score (0-100): combines deviation, threat, baseline, statistical signals
    - ThreatLevel enum: BENIGN, SUSPICIOUS, RECONNAISSANCE, ATTACK, EXPLOIT
    - AdaptiveWeights: learns signal weights from user feedback (record_attack/record_benign)
    - Single DB persistence: unified_ip_profiles + unified_signals tables

    Thread-safe: uses a lock for profile access.

    Usage:
        engine = UnifiedBehavioralEngine(event_database)
        signals = engine.ingest_event(event)
        signals = engine.ingest_batch(events)
        profile = engine.get_profile("192.168.1.50")
        profiles = engine.get_profiles(limit=50, min_score=40)
        engine.record_attack("1.2.3.4")
        engine.record_benign("10.0.0.1")
        stats = engine.get_stats()
    """

    def __init__(self, db: Any):
        """Initialize the unified behavioral engine.

        Args:
            db: EventDatabase instance for persistence (connect/putconn interface).
        """
        self.db = db
        self._profiles: Dict[str, UnifiedIPProfile] = {}
        self._lock = threading.Lock()
        self.adaptive_weights = AdaptiveWeights(db)

        # ── Global statistical baselines (from statistical_model.py) ──
        self._global_baselines: Dict[str, RunningStats] = {}

        # ── Counters for stats ──
        self._total_ingested = 0
        self._total_signals = 0

        # ── Pre-create global baselines for standard metrics ──
        self._global_baselines["events_per_minute"] = RunningStats()
        self._global_baselines["syn_per_minute"] = RunningStats()
        self._global_baselines["blocked_per_minute"] = RunningStats()
        self._global_baselines["icmp_per_minute"] = RunningStats()
        self._global_baselines["udp_per_minute"] = RunningStats()
        self._global_baselines["unique_src_per_minute"] = RunningStats()
        self._global_baselines["unique_dst_per_minute"] = RunningStats()
        self._global_baselines["unique_dst_ports_per_minute"] = RunningStats()
        self._global_baselines["packets_per_minute"] = RunningStats()

        logger.info("UnifiedBehavioralEngine initialized")

    # ── Event ingestion ──

    def ingest_event(self, event: Dict[str, Any]) -> List[UnifiedSignal]:
        """Process a single parsed event through the unified engine.

        This is the primary entry point. Replaces:
        - BehaviorProfiler.ingest_event()
        - ThreatEngine.ingest_firewall_event() / ingest_http_event() / etc.
        - StatisticalModel.record_event()
        - BaselineEngine.update_baseline()

        Updates the source IP's unified profile, computes deviations,
        checks for threat patterns, updates global statistics, and
        returns any signals generated.

        Args:
            event: Parsed event dict from the parser (normalized_events schema).

        Returns:
            List of UnifiedSignal instances (may be empty).
        """
        src_ip = event.get("src_ip")
        if not src_ip:
            return []

        with self._lock:
            profile = self._get_or_create_profile(src_ip)
            signals = profile.record_event(event)
            self._total_ingested += 1

            if profile.needs_persist():
                self._persist_profile(profile)
                profile.mark_persisted()

        # Update global statistics (outside lock)
        self._update_global_stats(event)

        # Persist signals to DB (outside lock to avoid holding it during I/O)
        if signals:
            try:
                self._persist_signals(src_ip, signals)
                self._total_signals += len(signals)
            except Exception as e:
                logger.warning("Failed to persist signals for %s: %s", src_ip, e)

        return signals

    def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, List[UnifiedSignal]]:
        """Process a batch of events efficiently.

        Pre-warms profiles and defers per-profile signal computation
        for high-volume throughput.

        Args:
            events: List of parsed event dicts.

        Returns:
            Dict mapping source IP -> list of signals.
        """
        all_signals: Dict[str, List[UnifiedSignal]] = defaultdict(list)
        for event in events:
            signals = self.ingest_event(event)
            src_ip = event.get("src_ip", "")
            if signals and src_ip:
                all_signals[src_ip].extend(signals)
        return dict(all_signals)

    # ── Profile queries ──

    def get_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a full unified profile for an IP address.

        Checks in-memory first, falls back to database.

        Args:
            ip: The IP address to look up.

        Returns:
            Profile dict with all fields, or None if not found.
        """
        with self._lock:
            profile = self._profiles.get(ip)

        if profile is not None:
            score = profile.compute_behavioral_score(self.adaptive_weights)
            threat = profile.get_threat_level()
            return {
                "ip": ip,
                "first_seen": profile.first_seen.isoformat(),
                "last_seen": profile.last_seen.isoformat(),
                "total_events": profile.total_events,
                "behavior_score": score,
                "threat_level": threat.name,
                "profile_data": profile.to_profile_data(),
                "baseline_data": profile.to_baseline_data(),
                "signals": profile.to_signals_data(),
                "source": "memory",
            }

        # Fallback: query DB
        return self._load_profile_from_db(ip)

    def get_profiles(self, limit: int = 50, offset: int = 0,
                     min_score: float = 0) -> List[Dict[str, Any]]:
        """Get top profiles sorted by behavioral score.

        Queries the database for persisted profiles.

        Args:
            limit: Maximum number of profiles to return.
            offset: Pagination offset.
            min_score: Minimum behavioral score filter (0-100).

        Returns:
            List of profile dicts.
        """
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                if min_score > 0:
                    cur.execute(
                        """SELECT ip, first_seen, last_seen, profile_data, baseline_data,
                                  threat_level, total_events, behavior_score, updated_at
                           FROM unified_ip_profiles
                           WHERE behavior_score >= %s
                           ORDER BY behavior_score DESC
                           LIMIT %s OFFSET %s""",
                        (min_score, limit, offset),
                    )
                else:
                    cur.execute(
                        """SELECT ip, first_seen, last_seen, profile_data, baseline_data,
                                  threat_level, total_events, behavior_score, updated_at
                           FROM unified_ip_profiles
                           ORDER BY behavior_score DESC
                           LIMIT %s OFFSET %s""",
                        (limit, offset),
                    )

                profiles = []
                for row in cur.fetchall():
                    profiles.append({
                        "ip": row[0],
                        "first_seen": str(row[1]),
                        "last_seen": str(row[2]),
                        "profile_data": row[3] if isinstance(row[3], dict) else (json.loads(row[3]) if row[3] else {}),
                        "baseline_data": row[4] if isinstance(row[4], dict) else (json.loads(row[4]) if row[4] else {}),
                        "threat_level": row[5],
                        "total_events": row[6],
                        "behavior_score": row[7],
                        "updated_at": str(row[8]),
                    })
                return profiles
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to query unified profiles: %s", e)
            return []

    def get_signals(self, ip: Optional[str] = None, limit: int = 100,
                    min_severity: str = "info") -> List[Dict[str, Any]]:
        """Get unified signals, optionally filtered by IP.

        Args:
            ip: Filter by source IP (None for all).
            limit: Maximum number of signals.
            min_severity: Minimum severity level (info < medium < high < critical).

        Returns:
            List of signal dicts.
        """
        severity_order = {"info": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev_val = severity_order.get(min_severity, 0)

        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                if ip:
                    cur.execute(
                        """SELECT id, ip, timestamp, source, signal_type, severity, metadata, created_at
                           FROM unified_signals
                           WHERE ip = %s
                           ORDER BY timestamp DESC
                           LIMIT %s""",
                        (ip, limit),
                    )
                else:
                    cur.execute(
                        """SELECT id, ip, timestamp, source, signal_type, severity, metadata, created_at
                           FROM unified_signals
                           ORDER BY timestamp DESC
                           LIMIT %s""",
                        (limit,),
                    )

                signals = []
                for row in cur.fetchall():
                    sev = row[5]
                    if severity_order.get(sev, 0) < min_sev_val:
                        continue
                    signals.append({
                        "id": row[0],
                        "ip": row[1],
                        "timestamp": str(row[2]),
                        "source": row[3],
                        "signal_type": row[4],
                        "severity": sev,
                        "metadata": row[6] if isinstance(row[6], dict) else (json.loads(row[6]) if row[6] else {}),
                        "created_at": str(row[7]),
                    })
                return signals
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to query unified signals: %s", e)
            return []

    # ── Scoring API ──

    def get_behavioral_score(self, ip: str) -> float:
        """Get the current behavioral score (0-100) for an IP.

        Applies decay before computing the score.

        Args:
            ip: The IP address.

        Returns:
            Float in [0.0, 100.0].
        """
        with self._lock:
            profile = self._profiles.get(ip)
            if not profile:
                return 0.0
            profile.apply_decay(self.adaptive_weights)
            return profile.compute_behavioral_score(self.adaptive_weights)

    def get_threat_level(self, ip: str) -> ThreatLevel:
        """Get the current threat level for an IP.

        Args:
            ip: The IP address.

        Returns:
            ThreatLevel enum value.
        """
        with self._lock:
            profile = self._profiles.get(ip)
            if not profile:
                return ThreatLevel.BENIGN
            return profile.get_threat_level()

    # ── Feedback API (adaptive weight learning) ──

    def record_attack(self, ip: str, timestamp: Optional[datetime] = None) -> None:
        """Record that an IP was confirmed as a genuine attack.

        Extracts signal types from the IP's profile and feeds them to
        AdaptiveWeights so correlated signals get boosted weights.

        Replaces: ThreatEngine.record_attack()

        Args:
            ip: The confirmed attacker IP.
            timestamp: Optional timestamp; defaults to now.
        """
        with self._lock:
            profile = self._profiles.get(ip)
        if not profile or not profile.signals:
            logger.warning("record_attack: no signals for %s", ip)
            return
        signal_types = list({s.signal_type for s in profile.signals})
        self.adaptive_weights.record_attack(signal_types, timestamp)
        logger.info("Attack recorded for %s: %d signal types (%s)", ip, len(signal_types), ", ".join(signal_types))

    def record_benign(self, ip: str, timestamp: Optional[datetime] = None) -> None:
        """Record that an IP was confirmed as benign (false positive).

        Extracts signal types from the IP's profile and feeds them to
        AdaptiveWeights so those signals get reduced weights and faster decay.

        Replaces: ThreatEngine.record_benign()

        Args:
            ip: The confirmed-benign IP.
            timestamp: Optional timestamp; defaults to now.
        """
        with self._lock:
            profile = self._profiles.get(ip)
        if not profile or not profile.signals:
            logger.warning("record_benign: no signals for %s", ip)
            return
        signal_types = list({s.signal_type for s in profile.signals})
        self.adaptive_weights.record_benign(signal_types, timestamp)
        logger.info("Benign recorded for %s: %d signal types (%s)", ip, len(signal_types), ", ".join(signal_types))

    def get_adaptive_weights_summary(self) -> Dict[str, Dict[str, Any]]:
        """Return current state of adaptive weights for monitoring."""
        return self.adaptive_weights.get_feedback_summary()

    def reset_adaptive_weights(self, signal_type: Optional[str] = None) -> None:
        """Reset adaptive weights back to defaults."""
        self.adaptive_weights.reset(signal_type)

    # ── Global statistics ──

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics for dashboard.

        Returns:
            Dict with total_profiles, total_ingested, total_signals,
            threat_level_counts, adaptive_weights_summary, and
            global baseline summaries.
        """
        with self._lock:
            total_profiles = len(self._profiles)
            total_ingested = self._total_ingested
            total_signals = self._total_signals

            # Count profiles by threat level (in-memory)
            threat_counts: Dict[str, int] = defaultdict(int)
            for p in self._profiles.values():
                score = p.compute_behavioral_score(self.adaptive_weights)
                level = p.get_threat_level()
                threat_counts[level.name] += 1

        return {
            "total_profiles": total_profiles,
            "total_ingested": total_ingested,
            "total_signals": total_signals,
            "threat_level_counts": dict(threat_counts),
            "adaptive_weights_summary": self.adaptive_weights.get_feedback_summary(),
            "global_baselines": self.get_baseline_summary(),
        }

    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get a summary of all global statistical baselines.

        Replaces: StatisticalModel.get_baseline_summary()
        """
        summary = {}
        for name, stats in self._global_baselines.items():
            if stats.count > 0:
                summary[name] = {
                    "mean": round(stats.mean, 2),
                    "stddev": round(stats.stddev, 2),
                    "count": stats.count,
                }
        return summary

    def get_all_anomaly_checks(self, current_rates: Dict[str, float]) -> List[Dict[str, Any]]:
        """Check all global baselines against current rates.

        Replaces: StatisticalModel.get_all_anomaly_checks()

        Args:
            current_rates: Dict mapping metric name -> current value.

        Returns:
            List of anomaly finding dicts.
        """
        anomalies = []
        for metric, current_value in current_rates.items():
            stats = self._global_baselines.get(metric)
            if not stats or stats.count < DEFAULT_MIN_SAMPLES:
                continue

            z_score = stats.z_score(current_value)
            if abs(z_score) > DEFAULT_ANOMALY_THRESHOLD:
                severity = "CRITICAL" if abs(z_score) >= 5.0 else "HIGH" if abs(z_score) >= 4.0 else "MEDIUM" if abs(z_score) >= 3.0 else "LOW"
                anomalies.append({
                    "type": "STATISTICAL_ANOMALY",
                    "metric": metric,
                    "severity": severity,
                    "z_score": round(z_score, 2),
                    "baseline_mean": round(stats.mean, 2),
                    "baseline_stddev": round(stats.stddev, 2),
                    "current_value": round(current_value, 2),
                    "sample_count": stats.count,
                })
        return anomalies

    # ── Persistence ──

    def periodic_persist(self) -> int:
        """Persist all dirty profiles and adaptive weights to DB.

        Call periodically (e.g., every save interval in agent loop).

        Returns:
            Number of profiles persisted.
        """
        persisted = 0
        with self._lock:
            for profile in self._profiles.values():
                try:
                    self._persist_profile(profile)
                    profile.mark_persisted()
                    persisted += 1
                except Exception as e:
                    logger.warning("Failed to persist profile for %s: %s", profile.ip, e)
        # Persist adaptive weights outside lock
        try:
            self.adaptive_weights.save_to_db()
        except Exception as e:
            logger.warning("Failed to persist adaptive weights: %s", e)
        return persisted

    # ── Internal methods ──

    def _get_or_create_profile(self, ip: str) -> UnifiedIPProfile:
        """Get or create a unified profile for an IP.

        Must be called with self._lock held.

        Args:
            ip: The IP address.

        Returns:
            The UnifiedIPProfile instance.
        """
        if ip not in self._profiles:
            self._profiles[ip] = UnifiedIPProfile(ip)
        return self._profiles[ip]

    def _add_signal(self, ip: str, signal: UnifiedSignal) -> None:
        """Add a threat signal to an IP's profile.

        Args:
            ip: The source IP.
            signal: The UnifiedSignal to add.
        """
        profile = self._profiles.get(ip)
        if not profile:
            return
        profile.signals.append(signal)
        if len(profile.signals) > MAX_RECENT_SIGNALS:
            profile.signals = profile.signals[-MAX_RECENT_SIGNALS:]

    def _update_behavioral_score(self, ip: str) -> float:
        """Update and return the unified behavioral score for an IP.

        Combines all signal sources with adaptive weights.

        Args:
            ip: The IP address.

        Returns:
            Updated score in [0.0, 100.0].
        """
        profile = self._profiles.get(ip)
        if not profile:
            return 0.0
        return profile.compute_behavioral_score(self.adaptive_weights)

    def _persist_profile(self, profile: UnifiedIPProfile) -> None:
        """Upsert a profile to the unified_ip_profiles table.

        Args:
            profile: The profile to persist.
        """
        behavior_score = profile.compute_behavioral_score(self.adaptive_weights)
        threat_level = profile.get_threat_level()

        conn = self.db.connect()
        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO unified_ip_profiles
                   (ip, first_seen, last_seen, profile_data, baseline_data,
                    threat_level, total_events, behavior_score, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                   ON CONFLICT (ip) DO UPDATE SET
                       last_seen = EXCLUDED.last_seen,
                       profile_data = EXCLUDED.profile_data,
                       baseline_data = EXCLUDED.baseline_data,
                       threat_level = EXCLUDED.threat_level,
                       total_events = EXCLUDED.total_events,
                       behavior_score = EXCLUDED.behavior_score,
                       updated_at = NOW()""",
                (
                    profile.ip,
                    profile.first_seen,
                    profile.last_seen,
                    json.dumps(profile.to_profile_data()),
                    json.dumps(profile.to_baseline_data()),
                    threat_level.name,
                    profile.total_events,
                    behavior_score,
                ),
            )
        finally:
            cur.close()
            self.db.putconn(conn)

    def _persist_signals(self, ip: str, signals: List[UnifiedSignal]) -> None:
        """Insert signals into the unified_signals table.

        Args:
            ip: The source IP.
            signals: List of signals to persist.
        """
        if not signals:
            return

        conn = self.db.connect()
        cur = conn.cursor()
        try:
            for sig in signals:
                severity = "high" if sig.score >= 0.7 else "medium" if sig.score >= 0.4 else "info"
                cur.execute(
                    """INSERT INTO unified_signals
                       (ip, timestamp, source, signal_type, severity, metadata)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (
                        ip,
                        sig.timestamp,
                        sig.source,
                        sig.signal_type,
                        severity,
                        json.dumps(sig.details),
                    ),
                )
        finally:
            cur.close()
            self.db.putconn(conn)

    def _load_profile_from_db(self, ip: str) -> Optional[Dict[str, Any]]:
        """Load a profile from the database.

        Args:
            ip: The IP address.

        Returns:
            Profile dict or None.
        """
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """SELECT ip, first_seen, last_seen, profile_data, baseline_data,
                              threat_level, total_events, behavior_score, updated_at
                       FROM unified_ip_profiles WHERE ip = %s""",
                    (ip,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "ip": row[0],
                    "first_seen": str(row[1]),
                    "last_seen": str(row[2]),
                    "profile_data": row[3] if isinstance(row[3], dict) else (json.loads(row[3]) if row[3] else {}),
                    "baseline_data": row[4] if isinstance(row[4], dict) else (json.loads(row[4]) if row[4] else {}),
                    "threat_level": row[5],
                    "total_events": row[6],
                    "behavior_score": row[7],
                    "updated_at": str(row[8]),
                    "source": "database",
                }
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to load profile for %s from DB: %s", ip, e)
            return None

    def _extract_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from an event for baseline comparison.

        Args:
            event: Parsed event dict.

        Returns:
            Dict mapping feature_name -> value.
        """
        total_length = event.get("ip_total_length", 0) or 0
        dst_port = event.get("dport") or event.get("dst_port")
        return {
            "ip_total_length": float(total_length),
            "has_dst_port": 1.0 if dst_port is not None else 0.0,
        }

    def _check_threat_patterns(self, profile: UnifiedIPProfile, event: Dict[str, Any]) -> List[UnifiedSignal]:
        """Check an event against known threat patterns.

        Detects: port scans, destination scans, block ratio spikes,
        HTTP anomalies (path traversal, etc.), IDS signature matches,
        ZenArmor threats, nginx attacks.

        Note: Most threat detection is now in UnifiedIPProfile.record_event().
        This method is kept for engine-level pattern checks that need cross-profile context.

        Args:
            profile: The IP's unified profile.
            event: The parsed event.

        Returns:
            List of new signals if threat patterns detected.
        """
        return []  # Handled in profile.record_event()

    def _update_global_stats(self, event: Dict[str, Any]) -> None:
        """Update global statistical baselines with event data.

        Updates running stats for: events_per_minute, syn_per_minute,
        blocked_per_minute, icmp_per_minute, udp_per_minute, etc.

        Replaces: StatisticalModel.record_event()

        Args:
            event: Parsed event dict.
        """
        proto = event.get("proto", "") or event.get("protocol", "")
        tcp_flags = event.get("tcp_flags", "")
        action = event.get("action", "")

        # General event rate
        self._global_baselines["events_per_minute"].update(1)

        # Protocol-specific
        if proto in ("TCP", "tcp"):
            self._global_baselines["packets_per_minute"].update(1)
        if proto in ("UDP", "udp"):
            self._global_baselines["udp_per_minute"].update(1)
        if proto in ("ICMP", "icmp", "ICMPV6"):
            self._global_baselines["icmp_per_minute"].update(1)

        # TCP flags
        if tcp_flags == "SYN":
            self._global_baselines["syn_per_minute"].update(1)

        # Action tracking
        if action in ("BLOCK", "block"):
            self._global_baselines["blocked_per_minute"].update(1)
