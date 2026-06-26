#!/usr/bin/env python3
"""
Unified Threat Engine for OPNsense Anomaly Detection

Correlates events from all sources (firewall, HTTP, IDS, ZenArmor, nginx)
into a unified threat score per IP. Replaces 10 siloed modules with one brain.

Architecture:
- Ingests events from all sources
- Scores threats per IP using multiple signals (0-1 normalized)
- Correlates cross-source patterns
- Outputs actionable alerts to Discord/Apprise
- Feeds the dashboard API
- Adapts signal weights from user feedback (attack/benign labels)

Usage:
    from threat_engine import ThreatEngine
    engine = ThreatEngine(db_connection, baseline_engine)
    threat_score = engine.score_ip(ip_address)
    engine.ingest_firewall_event(event)
    engine.ingest_http_event(event)
    engine.record_attack("1.2.3.4")       # feedback: confirmed attack
    engine.record_benign("10.0.0.1")      # feedback: confirmed benign
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

# Default signal weights — overridden by AdaptiveWeights at runtime
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
SCORE_DECAY_RATE = 0.95  # Per hour base decay
SCORE_DECAY_MIN = 0.1    # Minimum decay floor

# Adaptive weight tuning
ADAPTIVE_LEARNING_RATE = 0.1    # Step size for weight updates
ADAPTIVE_WEIGHT_MIN = 0.02      # Floor — signals never fully silenced
ADAPTIVE_WEIGHT_MAX = 1.0       # Ceiling — signals never dominate alone
ADAPTIVE_DECAY_BOOST = 1.5      # Extra decay multiplier for benign-decayed signals
ADAPTIVE_ATTACK_BOOST = 1.3     # Extra boost multiplier for attack-correlated signals
ADAPTIVE_MIN_FEEDBACK = 3       # Min feedback samples before auto-tuning kicks in


@dataclass
class SignalFeedback:
    """Per-signal-type feedback history for adaptive weighting."""
    signal_type: str
    attack_count: int = 0        # Times this signal was present in confirmed attacks
    benign_count: int = 0        # Times this signal was present, IP marked benign
    last_attack: Optional[datetime] = None
    last_benign: Optional[datetime] = None
    current_weight: Optional[float] = None  # None = use default from SIGNAL_WEIGHTS
    decay_multiplier: float = 1.0  # >1 means faster decay (stale/benign signals)


class AdaptiveWeights:
    """Learns optimal signal weights from user feedback (attack/benign labels).

    Core logic:
    - When an IP is confirmed as an ATTACK: boost weights of signals that were
      present for that IP. Signals consistently correlating with attacks get
      permanently higher influence on future scoring.
    - When an IP is confirmed as BENIGN: reduce weights of signals that were
      present and increase decay_multiplier so those signal scores evaporate
      faster in the future. Stale false-positive signals self-destruct.
    - Weights are clamped to [ADAPTIVE_WEIGHT_MIN, ADAPTIVE_WEIGHT_MAX].
    - Persists to / loads from the adaptive_weights database table.
    """

    def __init__(self, db_connection: Any = None):
        self._feedback: Dict[str, SignalFeedback] = {}
        self.db = db_connection
        if db_connection:
            self._ensure_table()
            self._load_from_db()

    # ── Persistence ──

    def _ensure_table(self):
        # adaptive_weights table is now managed by schema_migrations.py (v8).
        # This method is a no-op — called before _load_from_db for ordering.
        pass

    def _load_from_db(self):
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
                    current_weight=row[5],  # None means use default
                    decay_multiplier=row[6] or 1.0,
                )
            logger.info(f"Loaded {len(self._feedback)} adaptive weight entries from DB")
        except Exception as e:
            logger.debug(f"No adaptive weights in DB yet: {e}")

    def save_to_db(self):
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
            logger.error(f"Failed to save adaptive weights: {e}")

    # ── Weight lookup ──

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

    # ── Feedback recording + weight adaptation ──

    def record_attack(self, signal_types: List[str], timestamp: Optional[datetime] = None):
        """Record that a confirmed attack contained these signal types.

        Boosts weights for correlated signals.
        """
        ts = timestamp or datetime.now(timezone.utc)
        for st in signal_types:
            fb = self._feedback.setdefault(st, SignalFeedback(signal_type=st))
            fb.attack_count += 1
            fb.last_attack = ts
            # Boost weight proportional to attack correlation
            if fb.current_weight is None:
                fb.current_weight = SIGNAL_WEIGHTS.get(st, 0.5)
            # Ratio of attacks to total feedback — drives weight toward ADAPTIVE_WEIGHT_MAX
            ratio = fb.attack_count / (fb.attack_count + fb.benign_count)
            # Target: scale between min and max based on ratio
            target = ADAPTIVE_WEIGHT_MIN + ratio * (ADAPTIVE_WEIGHT_MAX - ADAPTIVE_WEIGHT_MIN)
            target = min(target * ADAPTIVE_ATTACK_BOOST, ADAPTIVE_WEIGHT_MAX)
            fb.current_weight += ADAPTIVE_LEARNING_RATE * (target - fb.current_weight)
            fb.current_weight = max(fb.current_weight, ADAPTIVE_WEIGHT_MIN)
            # Reduce decay multiplier — attack-correlated signals should persist longer
            fb.decay_multiplier = max(1.0, fb.decay_multiplier * 0.95)
            logger.debug(
                f"Attack feedback: {st} weight={fb.current_weight:.3f} "
                f"decay_mult={fb.decay_multiplier:.2f} "
                f"(attacks={fb.attack_count}, benign={fb.benign_count})"
            )

    def record_benign(self, signal_types: List[str], timestamp: Optional[datetime] = None):
        """Record that a confirmed-benign IP contained these signal types.

        Reduces weights and increases decay for false-positive signals.
        """
        ts = timestamp or datetime.now(timezone.utc)
        for st in signal_types:
            fb = self._feedback.setdefault(st, SignalFeedback(signal_type=st))
            fb.benign_count += 1
            fb.last_benign = ts
            if fb.current_weight is None:
                fb.current_weight = SIGNAL_WEIGHTS.get(st, 0.5)
            # Lower weight — signal was a false positive
            # Target: scale from max (all attacks) to min (all benign)
            ratio = fb.attack_count / (fb.attack_count + fb.benign_count)
            target = ADAPTIVE_WEIGHT_MIN + ratio * (ADAPTIVE_WEIGHT_MAX - ADAPTIVE_WEIGHT_MIN)
            fb.current_weight += ADAPTIVE_LEARNING_RATE * (target - fb.current_weight)
            fb.current_weight = max(fb.current_weight, ADAPTIVE_WEIGHT_MIN)
            # Increase decay multiplier — stale false-positive signals should evaporate faster
            fb.decay_multiplier = min(fb.decay_multiplier * ADAPTIVE_DECAY_BOOST, 5.0)
            logger.debug(
                f"Benign feedback: {st} weight={fb.current_weight:.3f} "
                f"decay_mult={fb.decay_multiplier:.2f} "
                f"(attacks={fb.attack_count}, benign={fb.benign_count})"
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

    def reset(self, signal_type: Optional[str] = None):
        """Reset weights back to defaults. Reset all if no signal_type given."""
        if signal_type:
            if signal_type in self._feedback:
                self._feedback[signal_type].current_weight = None
                self._feedback[signal_type].decay_multiplier = 1.0
        else:
            self._feedback.clear()


@dataclass
class ThreatSignal:
    """A single threat signal from one source.

    score is a normalized 0-1 value representing the severity/intensity
    of this specific signal instance. Adaptive weights are applied during
    unified score calculation, not at ingestion time.
    """
    source: str
    signal_type: str
    score: float          # Normalized 0-1 severity
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


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
    """Unified threat scoring and correlation engine.

    Uses AdaptiveWeights to learn optimal signal weights from user feedback.
    Signal scores are normalized 0-1 at ingestion; adaptive weights modulate
    their contribution during unified score calculation. Per-signal decay
    multipliers control how fast scores evaporate.
    """

    def __init__(self, db_connection, baseline_engine=None):
        self.db = db_connection
        self.baseline_engine = baseline_engine
        self._ip_profiles: Dict[str, IPThreatProfile] = {}
        self._signal_cache: Dict[str, List[ThreatSignal]] = defaultdict(list)
        # Adaptive weights — learns from feedback
        self.adaptive_weights = AdaptiveWeights(db_connection)

    # ── Public feedback API ──

    def record_attack(self, ip: str, timestamp: Optional[datetime] = None):
        """Record that an IP was confirmed as a genuine attack.

        Extracts signal types from the IP's profile and feeds them to
        AdaptiveWeights so correlated signals get boosted weights.
        """
        profile = self._ip_profiles.get(ip)
        if not profile or not profile.signals:
            logger.warning(f"record_attack: no signals for {ip}")
            return
        signal_types = list({s.signal_type for s in profile.signals})
        self.adaptive_weights.record_attack(signal_types, timestamp)
        logger.info(
            f"Attack recorded for {ip}: {len(signal_types)} signal types "
            f"({', '.join(signal_types)})"
        )

    def record_benign(self, ip: str, timestamp: Optional[datetime] = None):
        """Record that an IP was confirmed as benign (false positive).

        Extracts signal types from the IP's profile and feeds them to
        AdaptiveWeights so those signals get reduced weights and faster decay.
        """
        profile = self._ip_profiles.get(ip)
        if not profile or not profile.signals:
            logger.warning(f"record_benign: no signals for {ip}")
            return
        signal_types = list({s.signal_type for s in profile.signals})
        self.adaptive_weights.record_benign(signal_types, timestamp)
        logger.info(
            f"Benign recorded for {ip}: {len(signal_types)} signal types "
            f"({', '.join(signal_types)})"
        )

    def get_adaptive_weights_summary(self) -> Dict[str, Dict[str, Any]]:
        """Return current state of adaptive weights for monitoring."""
        return self.adaptive_weights.get_feedback_summary()

    def reset_adaptive_weights(self, signal_type: Optional[str] = None):
        """Reset adaptive weights back to defaults."""
        self.adaptive_weights.reset(signal_type)

    # ── Scoring ──

    def score_ip(self, ip: str) -> float:
        """Get the current unified threat score for an IP."""
        profile = self._ip_profiles.get(ip)
        if not profile:
            return 0.0
        # Apply decay first
        self._apply_decay(profile)
        return profile.unified_score

    # ── Event ingestion ──

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
                    # Normalized score: deviation / (deviation + 1) caps at ~1.0
                    norm_score = min(deviation / (deviation + 1), 1.0)
                    self._add_signal(ip, "firewall", "volume_anomaly",
                                   norm_score,
                                   {"rule": rule, "deviation": deviation})

        # Check for port scan pattern
        if self._is_port_scan(ip, event):
            self._add_signal(ip, "firewall", "firewall_port_scan",
                           0.8,
                           {"dst_port": event.get("dst_port")})

        # Check for destination scan
        if self._is_destination_scan(ip, event):
            self._add_signal(ip, "firewall", "firewall_dest_scan",
                           0.7,
                           {"dst_ip": event.get("dst_ip")})

        # Check block ratio
        action = event.get("action")
        if action == "block":
            self._update_block_ratio(ip)

    def ingest_firewall_events(self, events: List[Dict[str, Any]]):
        """Ingest a batch of firewall events and update threat scores.

        Optimized for high volume: pre-warms profiles and defers
        per-profile signal computation.
        """
        now = datetime.now(timezone.utc)
        # Pre-warm: count events per IP, track blocks
        ip_event_counts: Dict[str, int] = defaultdict(int)
        ip_blocks: Dict[str, int] = defaultdict(int)
        for event in events:
            ip = event.get("src_ip")
            if not ip:
                continue
            ip_event_counts[ip] += 1
            if event.get("action") == "block":
                ip_blocks[ip] += 1

        # Bulk-update profiles
        for ip, count in ip_event_counts.items():
            profile = self._get_or_create_profile(ip)
            profile.total_events += count
            profile.firewall_events += count
            profile.last_seen = now

        # Per-event signal processing (baseline, port scan, dest scan)
        for event in events:
            ip = event.get("src_ip")
            if not ip:
                continue

            # Check against baseline
            rule = event.get("rule")
            if rule and self.baseline_engine:
                baseline = self.baseline_engine.get_baseline(rule)
                if baseline:
                    deviation = self._calculate_deviation(event, baseline)
                    if deviation > 0:
                        profile = self._profiles[ip]
                        profile.baseline_deviations.append(deviation)
                        norm_score = min(deviation / (deviation + 1), 1.0)
                        self._add_signal(ip, "firewall", "volume_anomaly",
                                       norm_score,
                                       {"rule": rule, "deviation": deviation})

            # Check for port scan pattern
            if self._is_port_scan(ip, event):
                self._add_signal(ip, "firewall", "firewall_port_scan",
                               0.8,
                               {"dst_port": event.get("dst_port")})

            # Check for destination scan
            if self._is_destination_scan(ip, event):
                self._add_signal(ip, "firewall", "firewall_dest_scan",
                               0.7,
                               {"dst_ip": event.get("dst_ip")})

        # Bulk-update block ratios
        for ip, blocks in ip_blocks.items():
            self._update_block_ratio_count(ip, blocks)

    def _update_block_ratio_count(self, ip: str, block_count: int):
        """Update block ratio by a count (batch-friendly variant)."""
        profile = self._profiles.get(ip)
        if not profile:
            return
        profile.blocked_events += block_count
        ratio = profile.blocked_events / profile.firewall_events if profile.firewall_events else 0
        if ratio > 0.5:
            self._add_signal(ip, "firewall", "firewall_block_ratio",
                           min(ratio, 1.0),
                           {"blocked": profile.blocked_events, "total": profile.firewall_events})

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
            self._add_signal(ip, "http", "http_anomaly",
                           0.3,
                           {"status_code": status_code})

        path = event.get("path", "")
        if any(pattern in path.lower() for pattern in ["../", ".php?", "cmd=", "exec=", "eval="]):
            self._add_signal(ip, "http", "http_anomaly",
                           0.8,
                           {"path": path, "type": "path_traversal"})

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

        # Normalized score based on severity
        severity_score = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}.get(severity, 0.3)
        self._add_signal(ip, "ids", "ids_signature",
                       severity_score,
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

        # Normalized score based on threat level
        level_score = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}.get(threat_level, 0.3)
        self._add_signal(ip, "zenarmor", "zenarmor_threat",
                       level_score,
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
            self._add_signal(ip, "nginx", "nginx_attack",
                           0.7,
                           {"attack_type": attack_type})

    # ── Profile management ──

    def _get_or_create_profile(self, ip: str) -> IPThreatProfile:
        """Get or create threat profile for IP."""
        if ip not in self._ip_profiles:
            self._ip_profiles[ip] = IPThreatProfile(
                ip=ip,
                first_seen=datetime.now(timezone.utc)
            )
        return self._ip_profiles[ip]

    def _add_signal(self, ip: str, source: str, signal_type: str, score: float, details: Dict[str, Any] = None):
        """Add threat signal for IP. Score should be normalized 0-1."""
        signal = ThreatSignal(
            source=source,
            signal_type=signal_type,
            score=max(0.0, min(1.0, score)),  # Clamp to [0, 1]
            timestamp=datetime.now(timezone.utc),
            details=details or {}
        )

        profile = self._get_or_create_profile(ip)
        profile.signals.append(signal)
        self._signal_cache[ip].append(signal)

        # Update unified score
        self._update_unified_score(ip)

    def _update_unified_score(self, ip: str):
        """Update unified threat score for IP using adaptive weights.

        Signal scores are normalized 0-1. Adaptive weights modulate each
        signal type's contribution. The final score is scaled to [0, 100].
        """
        profile = self._ip_profiles.get(ip)
        if not profile:
            return

        # Group signals by type and compute average score per type
        signal_scores: Dict[str, List[float]] = defaultdict(list)
        for signal in profile.signals:
            signal_scores[signal.signal_type].append(signal.score)

        # Calculate weighted score using adaptive weights
        weighted_score = 0.0
        total_weight = 0.0
        for signal_type, scores in signal_scores.items():
            avg_score = sum(scores) / len(scores)
            weight = self.adaptive_weights.get_weight(signal_type)
            weighted_score += avg_score * weight
            total_weight += weight

        # Normalize by total weight so score stays in reasonable range,
        # then scale to [0, 100]
        if total_weight > 0:
            normalized = weighted_score / total_weight
            profile.unified_score = min(normalized * THREAT_SCORE_MAX, THREAT_SCORE_MAX)
        else:
            profile.unified_score = 0.0

        # Apply baseline deviation penalty
        if profile.baseline_deviations:
            avg_deviation = sum(profile.baseline_deviations[-10:]) / min(len(profile.baseline_deviations), 10)
            profile.unified_score *= (1 + avg_deviation * 0.1)
            profile.unified_score = min(profile.unified_score, THREAT_SCORE_MAX)

    def _apply_decay(self, profile: IPThreatProfile):
        """Apply per-signal time-based decay using adaptive decay multipliers.

        Each signal is decayed individually based on its age and its
        signal_type's adaptive decay_multiplier. Signals confirmed as
        benign get faster decay; attack-correlated signals persist longer.
        """
        if not profile.last_seen or not profile.signals:
            return

        now = datetime.now(timezone.utc)

        # Decay individual signals
        for signal in profile.signals:
            hours_old = (now - signal.timestamp).total_seconds() / 3600
            if hours_old > 0:
                # Per-signal-type decay multiplier from adaptive weights
                decay_mult = self.adaptive_weights.get_decay_multiplier(signal.signal_type)
                # Effective decay rate: base_rate ^ (hours * multiplier)
                effective_rate = SCORE_DECAY_RATE ** (hours_old * decay_mult)
                effective_rate = max(effective_rate, SCORE_DECAY_MIN)
                signal.score *= effective_rate

        # Recalculate unified score after per-signal decay
        self._update_unified_score(profile.ip)

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

        # Count blocks vs passes from events (use firewall_events as proxy)
        block_count = sum(1 for s in profile.signals
                         if s.source == "firewall" and s.signal_type == "firewall_block_ratio")
        total_fw = profile.firewall_events

        if total_fw > 3:
            block_ratio = block_count / max(total_fw, 1)
            if block_ratio > 0.7:  # High block ratio
                self._add_signal(ip, "firewall", "firewall_block_ratio",
                               min(block_ratio, 1.0),
                               {"block_ratio": block_ratio, "total_events": total_fw})

    # ── Persistence ──

    def save_profiles(self):
        """Save threat profiles AND adaptive weights to database."""
        # Save IP profiles
        for ip, profile in self._ip_profiles.items():
            try:
                self.db.execute("""
                    INSERT INTO ip_threat_profiles
                    (ip, unified_score, total_events, firewall_events, http_events,
                     ids_events, zenarmor_events, nginx_events, baseline_deviations,
                     geo_info, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (ip) DO UPDATE SET
                        unified_score = EXCLUDED.unified_score,
                        total_events = EXCLUDED.total_events,
                        firewall_events = EXCLUDED.firewall_events,
                        http_events = EXCLUDED.http_events,
                        ids_events = EXCLUDED.ids_events,
                        zenarmor_events = EXCLUDED.zenarmor_events,
                        nginx_events = EXCLUDED.nginx_events,
                        baseline_deviations = EXCLUDED.baseline_deviations,
                        geo_info = EXCLUDED.geo_info,
                        first_seen = EXCLUDED.first_seen,
                        last_seen = EXCLUDED.last_seen
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

        # Save adaptive weights
        self.adaptive_weights.save_to_db()