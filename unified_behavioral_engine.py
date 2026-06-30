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
        ...

    def z_score(self, value: float) -> float:
        """Compute z-score of a value against this baseline.

        Returns 0 if insufficient data (count < 10).
        """
        ...

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-serializable dict."""
        ...


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
        ...

    @property
    def stddev(self) -> float:
        """Calculate standard deviation."""
        ...

    @property
    def variance(self) -> float:
        """Calculate variance."""
        ...

    def z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        ...

    def latest_values(self, n: int = 10) -> List[float]:
        """Get the N most recent values."""
        ...


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
        ...

    def _ensure_table(self) -> None:
        """Ensure the adaptive_weights table exists (managed by schema_migrations)."""
        ...

    def _load_from_db(self) -> None:
        """Load existing adaptive weight entries from database."""
        ...

    def save_to_db(self) -> None:
        """Persist current adaptive weights to database."""
        ...

    def get_weight(self, signal_type: str) -> float:
        """Get the current adaptive weight for a signal type."""
        ...

    def get_decay_multiplier(self, signal_type: str) -> float:
        """Get decay multiplier: >1 means faster decay for stale/benign signals."""
        ...

    def record_attack(self, signal_types: List[str], timestamp: Optional[datetime] = None) -> None:
        """Record that a confirmed attack contained these signal types.

        Boosts weights for correlated signals.
        """
        ...

    def record_benign(self, signal_types: List[str], timestamp: Optional[datetime] = None) -> None:
        """Record that a confirmed-benign IP contained these signal types.

        Reduces weights and increases decay for false-positive signals.
        """
        ...

    def get_feedback_summary(self) -> Dict[str, Dict[str, Any]]:
        """Return current state of all adaptive weights for monitoring."""
        ...

    def reset(self, signal_type: Optional[str] = None) -> None:
        """Reset weights back to defaults. Reset all if no signal_type given."""
        ...


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
        ...

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

        Args:
            event: Parsed event dict with normalized_events schema fields.

        Returns:
            List of new UnifiedSignal instances (may be empty).
        """
        ...

    def compute_behavioral_score(self) -> float:
        """Compute unified behavioral score (0-100).

        Aggregates signals from all sources:
        - Deviation z-scores against EMA baselines (from ip_behavior_model)
        - Weighted threat signal scores with adaptive weights (from threat_engine)
        - Baseline deviation penalties (from baseline_engine)
        - Statistical anomaly scores (from statistical_model)

        Higher score = more anomalous behavior.

        Returns:
            Float in range [0.0, 100.0].
        """
        ...

    def get_threat_level(self) -> ThreatLevel:
        """Map behavioral score to unified threat level.

        Uses the pre-computed behavioral score and THREAT_LEVEL_THRESHOLDS
        to assign BENIGN, SUSPICIOUS, RECONNAISSANCE, ATTACK, or EXPLOIT.

        Returns:
            ThreatLevel enum value.
        """
        ...

    def apply_decay(self, adaptive_weights: AdaptiveWeights) -> None:
        """Apply time-based decay to all signal scores.

        Each signal is decayed individually based on its age and its
        signal_type's adaptive decay_multiplier.

        Args:
            adaptive_weights: The shared AdaptiveWeights instance for per-signal-type config.
        """
        ...

    def to_profile_data(self) -> Dict[str, Any]:
        """Serialize profile patterns to JSON-serializable dict.

        Returns:
            Dict with all connection, temporal, volume, geographic, and
            source-specific pattern data suitable for DB persistence or API response.
        """
        ...

    def to_baseline_data(self) -> Dict[str, Any]:
        """Serialize baseline data to JSON-serializable dict.

        Returns:
            Dict mapping window -> feature -> baseline stats.
        """
        ...

    def to_signals_data(self) -> List[Dict[str, Any]]:
        """Serialize all signals to JSON-serializable list.

        Returns:
            List of signal dicts suitable for DB persistence.
        """
        ...

    def needs_persist(self) -> bool:
        """Check if this profile needs to be flushed to the database."""
        ...

    def mark_persisted(self) -> None:
        """Mark this profile as persisted (reset event counter)."""
        ...


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
        ...

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
        ...

    def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, List[UnifiedSignal]]:
        """Process a batch of events efficiently.

        Pre-warms profiles and defers per-profile signal computation
        for high-volume throughput.

        Args:
            events: List of parsed event dicts.

        Returns:
            Dict mapping source IP -> list of signals.
        """
        ...

    # ── Profile queries ──

    def get_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a full unified profile for an IP address.

        Checks in-memory first, falls back to database.

        Args:
            ip: The IP address to look up.

        Returns:
            Profile dict with all fields, or None if not found.
        """
        ...

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
        ...

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
        ...

    # ── Scoring API ──

    def get_behavioral_score(self, ip: str) -> float:
        """Get the current behavioral score (0-100) for an IP.

        Applies decay before computing the score.

        Args:
            ip: The IP address.

        Returns:
            Float in [0.0, 100.0].
        """
        ...

    def get_threat_level(self, ip: str) -> ThreatLevel:
        """Get the current threat level for an IP.

        Args:
            ip: The IP address.

        Returns:
            ThreatLevel enum value.
        """
        ...

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
        ...

    def record_benign(self, ip: str, timestamp: Optional[datetime] = None) -> None:
        """Record that an IP was confirmed as benign (false positive).

        Extracts signal types from the IP's profile and feeds them to
        AdaptiveWeights so those signals get reduced weights and faster decay.

        Replaces: ThreatEngine.record_benign()

        Args:
            ip: The confirmed-benign IP.
            timestamp: Optional timestamp; defaults to now.
        """
        ...

    def get_adaptive_weights_summary(self) -> Dict[str, Dict[str, Any]]:
        """Return current state of adaptive weights for monitoring."""
        ...

    def reset_adaptive_weights(self, signal_type: Optional[str] = None) -> None:
        """Reset adaptive weights back to defaults."""
        ...

    # ── Global statistics ──

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics for dashboard.

        Returns:
            Dict with total_profiles, total_ingested, total_signals,
            threat_level_counts, adaptive_weights_summary, and
            global baseline summaries.
        """
        ...

    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get a summary of all global statistical baselines.

        Replaces: StatisticalModel.get_baseline_summary()
        """
        ...

    def get_all_anomaly_checks(self, current_rates: Dict[str, float]) -> List[Dict[str, Any]]:
        """Check all global baselines against current rates.

        Replaces: StatisticalModel.get_all_anomaly_checks()

        Args:
            current_rates: Dict mapping metric name -> current value.

        Returns:
            List of anomaly finding dicts.
        """
        ...

    # ── Persistence ──

    def periodic_persist(self) -> int:
        """Persist all dirty profiles and adaptive weights to DB.

        Call periodically (e.g., every save interval in agent loop).

        Returns:
            Number of profiles persisted.
        """
        ...

    # ── Internal methods ──

    def _get_or_create_profile(self, ip: str) -> UnifiedIPProfile:
        """Get or create a unified profile for an IP.

        Must be called with self._lock held.

        Args:
            ip: The IP address.

        Returns:
            The UnifiedIPProfile instance.
        """
        ...

    def _add_signal(self, ip: str, signal: UnifiedSignal) -> None:
        """Add a threat signal to an IP's profile.

        Args:
            ip: The source IP.
            signal: The UnifiedSignal to add.
        """
        ...

    def _update_behavioral_score(self, ip: str) -> float:
        """Update and return the unified behavioral score for an IP.

        Combines all signal sources with adaptive weights.

        Args:
            ip: The IP address.

        Returns:
            Updated score in [0.0, 100.0].
        """
        ...

    def _persist_profile(self, profile: UnifiedIPProfile) -> None:
        """Upsert a profile to the unified_ip_profiles table.

        Args:
            profile: The profile to persist.
        """
        ...

    def _persist_signals(self, ip: str, signals: List[UnifiedSignal]) -> None:
        """Insert signals into the unified_signals table.

        Args:
            ip: The source IP.
            signals: List of signals to persist.
        """
        ...

    def _load_profile_from_db(self, ip: str) -> Optional[Dict[str, Any]]:
        """Load a profile from the database.

        Args:
            ip: The IP address.

        Returns:
            Profile dict or None.
        """
        ...

    def _extract_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from an event for baseline comparison.

        Args:
            event: Parsed event dict.

        Returns:
            Dict mapping feature_name -> value.
        """
        ...

    def _check_threat_patterns(self, profile: UnifiedIPProfile, event: Dict[str, Any]) -> List[UnifiedSignal]:
        """Check an event against known threat patterns.

        Detects: port scans, destination scans, block ratio spikes,
        HTTP anomalies (path traversal, etc.), IDS signature matches,
        ZenArmor threats, nginx attacks.

        Args:
            profile: The IP's unified profile.
            event: The parsed event.

        Returns:
            List of new signals if threat patterns detected.
        """
        ...

    def _update_global_stats(self, event: Dict[str, Any]) -> None:
        """Update global statistical baselines with event data.

        Updates running stats for: events_per_minute, syn_per_minute,
        blocked_per_minute, icmp_per_minute, udp_per_minute, etc.

        Replaces: StatisticalModel.record_event()

        Args:
            event: Parsed event dict.
        """
        ...
