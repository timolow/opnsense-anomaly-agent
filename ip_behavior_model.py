#!/usr/bin/env python3
"""
IP Behavior Profiling Engine for OPNsense Anomaly Detection Agent.

Replaces static rule-classification with dynamic behavioral profiling.
Each IP address gets a persistent behavioral profile that learns normal
patterns over multiple time windows and flags deviations via z-score
aggregation.

Architecture:
- Per-IP profiles: connection, temporal, volume, geographic patterns
- EMA baselines: 1h, 6h, 24h, 7d windows with adaptive decay rates
- Deviation scoring: z-score against each window, aggregated into behavior_score (0-100)
- Signal stream: every deviation generates a typed signal with severity

Usage:
    from ip_behavior_model import BehaviorProfiler
    profiler = BehaviorProfiler(event_database)
    signals = profiler.ingest_event(event)
    profile = profiler.get_profile("192.168.1.50")
"""

import json
import logging
import math
import time
import threading
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────

# EMA decay rates per window (alpha). Higher = faster adaptation.
# alpha = 2 / (window_size + 1) is standard, we use tuned values:
EMA_WINDOWS = {
    "1h":  {"alpha": 0.15,  "seconds": 3600},
    "6h":  {"alpha": 0.05,  "seconds": 21600},
    "24h": {"alpha": 0.02,  "seconds": 86400},
    "7d":  {"alpha": 0.005, "seconds": 604800},
}

# Feature dimensions tracked per IP
FEATURE_DIMENSIONS = [
    "conn_rate",       # connections per minute
    "unique_dst_ports", # unique destination ports per window
    "unique_dst_ips",   # unique destination IPs per window
    "bytes_per_conn",   # average bytes per connection (ip_total_length)
    "packet_count",     # packets per window (approximate via event count)
]

# Z-score thresholds for behavior scoring
ZSCORE_WARNING = 2.0
ZSCORE_CRITICAL = 3.5

# Behavior score thresholds for threat levels
THREAT_LOW_MAX = 25
THREAT_MEDIUM_MAX = 50
THREAT_HIGH_MAX = 75

# Profile persistence: flush to DB every N events per IP
PERSIST_INTERVAL = 100

# Max recent events kept in memory per IP (for signal dedup)
MAX_RECENT_SIGNALS = 200


# ── EMA baseline tracker ─────────────────────────────────────────────

class EMABaseline:
    """Exponential Moving Average baseline for a single feature.

    Tracks mean, variance, and count using EMA that adapts faster
    than Welford's online algorithm (configurable alpha per window).
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
        return {
            "alpha": self.alpha,
            "mean": round(self.mean, 4),
            "var": round(self.var, 4),
            "stddev": round(math.sqrt(max(0, self.var)), 4),
            "count": self.count,
        }


# ── IP Behavior Profile (in-memory) ──────────────────────────────────

class IPBehaviorProfile:
    """In-memory behavioral profile for a single IP address.

    Maintains:
    - Connection patterns: ports, protocols, destinations
    - Temporal patterns: time-of-day distribution, frequency
    - Volume patterns: bytes, packets
    - Geographic patterns: countries seen
    - Baselines: one EMA set per window per feature
    """

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = datetime.now(timezone.utc)
        self.last_seen = self.first_seen
        self.total_events = 0

        # Connection patterns
        self.dst_ports: Counter = Counter()
        self.dst_ips: Counter = Counter()
        self.protocols: Counter = Counter()
        self.actions: Counter = Counter()  # pass/block
        self.interfaces: Counter = Counter()

        # Temporal patterns
        self.hour_distribution: Counter = Counter()  # hour -> count
        self.daily_distribution: Counter = Counter() # day_of_week -> count

        # Volume patterns
        self.total_bytes = 0
        self.total_packets = 0

        # Geographic patterns
        self.countries: Counter = Counter()

        # Baselines: {window: {feature: EMABaseline}}
        self.baselines: Dict[str, Dict[str, EMABaseline]] = {}
        for window, cfg in EMA_WINDOWS.items():
            self.baselines[window] = {
                feat: EMABaseline(cfg["alpha"]) for feat in FEATURE_DIMENSIONS
            }

        # Recent signal dedup: (signal_type, severity) -> last_timestamp
        self._recent_signals: List[Tuple[str, str, float]] = []

        # Event counter since last DB flush
        self._events_since_persist = 0

        # Current window counters (reset on baseline update)
        self._window_events = 0
        self._window_start = time.time()
        self._window_unique_ports: set = set()
        self._window_unique_ips: set = set()

    def record_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Record a parsed event into this profile.

        Returns list of behavior signals (if any deviations detected).
        """
        self.total_events += 1
        self.last_seen = datetime.now(timezone.utc)
        now = time.time()

        # ── Extract features ────────────────────────────────────────
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dport") or event.get("dst_port")
        proto = event.get("proto", "")
        action = event.get("action", "")
        interface = event.get("interface", "")
        total_length = event.get("ip_total_length", 0) or 0

        # Timestamp extraction
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

        # ── Update patterns ─────────────────────────────────────────
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

        # ── Update window counters ──────────────────────────────────
        self._window_events += 1
        if dst_port is not None:
            self._window_unique_ports.add(int(dst_port))
        if dst_ip:
            self._window_unique_ips.add(dst_ip)

        # ── Compute current-window features ─────────────────────────
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

        # ── Update baselines + compute deviations ───────────────────
        signals = []
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
                        if now - last_ts < 300:  # 5 min cooldown per signal type
                            continue

                    signals.append({
                        "ip": self.ip,
                        "timestamp": datetime.now(timezone.utc),
                        "source": "behavior_profiler",
                        "signal_type": signal_type,
                        "severity": severity,
                        "metadata": {
                            "window": window,
                            "z_score": round(z, 2),
                            "value": round(value, 2),
                            "baseline_mean": round(baseline.mean, 2),
                            "baseline_std": round(math.sqrt(max(0, baseline.var)), 2),
                            "threshold": ZSCORE_CRITICAL if severity == "high" else ZSCORE_WARNING,
                        },
                    })
                    self._recent_signals.append((signal_type, severity, now))
                    # Keep signal history bounded
                    if len(self._recent_signals) > MAX_RECENT_SIGNALS:
                        self._recent_signals = self._recent_signals[-MAX_RECENT_SIGNALS:]

                # Update EMA with current value
                baseline.update(value)

        self._events_since_persist += 1
        return signals

    def compute_behavior_score(self) -> float:
        """Compute aggregated behavior score (0-100).

        Score is derived from max z-scores across all windows and features.
        Higher = more anomalous behavior.
        """
        if self.total_events < 50:
            return 0.0

        max_z_scores = []
        for window, baselines in self.baselines.items():
            window_max_z = 0.0
            for feat, baseline in baselines.items():
                if baseline.count >= 10:
                    # Compute z-score for current observed rate
                    # We use the mean itself as a proxy when no live event
                    # Actual z-scores are computed during event recording
                    pass
            # Use stored baseline state - we need current features
            # For a snapshot score, use the ratio of recent deviation signals
            recent_deviations = sum(
                1 for s in self._recent_signals[-50:]
                if s[1] in ("medium", "high")
            )
            if recent_deviations > 0:
                # Weight by window recency: more recent signals matter more
                window_max_z = min(recent_deviations * 0.5, 5.0)

        # Simple aggregation: sum of weighted z-scores, mapped to 0-100
        if not max_z_scores:
            # Fallback: derive from action ratio (block-heavy = suspicious)
            block_ratio = self.actions.get("block", 0) / max(self.total_events, 1)
            port_diversity = len(self.dst_ports) / max(self.total_events, 1)

            score = 0.0
            # Block ratio component (0-30)
            if block_ratio > 0.8:
                score += 30
            elif block_ratio > 0.5:
                score += 15
            elif block_ratio > 0.2:
                score += 5

            # Port diversity component (0-30)
            if port_diversity > 0.5:
                score += 30
            elif port_diversity > 0.2:
                score += 15
            elif port_diversity > 0.05:
                score += 5

            # Destination diversity (0-20)
            dst_diversity = len(self.dst_ips) / max(self.total_events, 1)
            if dst_diversity > 0.5:
                score += 20
            elif dst_diversity > 0.2:
                score += 10

            # Volume anomaly (0-20)
            if self.total_bytes > 0 and self.total_events > 100:
                avg_bytes = self.total_bytes / self.total_events
                if avg_bytes > 10000:
                    score += 20
                elif avg_bytes > 5000:
                    score += 10

            return min(score, 100.0)

        # Aggregate z-scores into score
        total_z = sum(max_z_scores)
        score = min(total_z * 10, 100.0)
        return round(score, 1)

    def get_threat_level(self, behavior_score: float) -> str:
        """Map behavior score to threat level string."""
        if behavior_score >= THREAT_HIGH_MAX:
            return "high"
        elif behavior_score >= THREAT_MEDIUM_MAX:
            return "medium"
        elif behavior_score >= THREAT_LOW_MAX:
            return "low"
        return "info"

    def to_profile_data(self) -> Dict[str, Any]:
        """Serialize profile patterns to JSON-serializable dict."""
        return {
            "dst_ports": dict(self.dst_ports.most_common(50)),
            "dst_ips": dict(self.dst_ips.most_common(50)),
            "protocols": dict(self.protocols.most_common(20)),
            "actions": dict(self.actions.most_common(10)),
            "interfaces": dict(self.interfaces.most_common(10)),
            "hour_distribution": dict(self.hour_distribution),
            "daily_distribution": dict(self.daily_distribution),
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "countries": dict(self.countries.most_common(20)),
            "unique_dst_ports": len(self.dst_ports),
            "unique_dst_ips": len(self.dst_ips),
        }

    def to_baseline_data(self) -> Dict[str, Any]:
        """Serialize baseline data to JSON-serializable dict."""
        result = {}
        for window, baselines in self.baselines.items():
            result[window] = {
                feat: bl.to_dict() for feat, bl in baselines.items()
            }
        return result

    def needs_persist(self) -> bool:
        return self._events_since_persist >= PERSIST_INTERVAL

    def mark_persisted(self) -> None:
        self._events_since_persist = 0


# ── Behavior Profiler (main class) ────────────────────────────────────

class BehaviorProfiler:
    """Core behavioral profiling engine.

    Maintains per-IP behavioral profiles in memory with periodic
    persistence to PostgreSQL. Computes deviation scores via z-score
    against multi-window EMA baselines.

    Thread-safe: uses a lock for profile access.
    """

    def __init__(self, db: Any):
        """Initialize profiler.

        Args:
            db: EventDatabase instance for persistence.
        """
        self.db = db
        self._profiles: Dict[str, IPBehaviorProfile] = {}
        self._lock = threading.Lock()
        self._total_ingested = 0
        self._total_signals = 0
        logger.info("BehaviorProfiler initialized")

    def ingest_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a single parsed event through the behavior profiler.

        Updates the source IP's profile, computes deviations, and
        returns any behavior signals generated.

        Args:
            event: Parsed event dict from the parser.

        Returns:
            List of behavior signal dicts (may be empty).
        """
        src_ip = event.get("src_ip")
        if not src_ip:
            return []

        with self._lock:
            profile = self._profiles.get(src_ip)
            if profile is None:
                profile = IPBehaviorProfile(src_ip)
                self._profiles[src_ip] = profile

            signals = profile.record_event(event)
            self._total_ingested += 1

            # Persist profile if needed
            if profile.needs_persist():
                self._persist_profile(profile)
                profile.mark_persisted()

        # Persist signals to DB (outside lock to avoid holding it during I/O)
        if signals:
            try:
                self._persist_signals(src_ip, signals)
                self._total_signals += len(signals)
            except Exception as e:
                logger.warning("Failed to persist behavior signals for %s: %s", src_ip, e)

        return signals

    def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Process a batch of events.

        Returns dict mapping IP -> list of signals.
        """
        all_signals: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            signals = self.ingest_event(event)
            src_ip = event.get("src_ip", "")
            if signals and src_ip:
                all_signals[src_ip].extend(signals)
        return dict(all_signals)

    def get_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a full profile for an IP address.

        Checks in-memory first, falls back to DB.
        """
        with self._lock:
            profile = self._profiles.get(ip)

        if profile is not None:
            score = profile.compute_behavior_score()
            threat = profile.get_threat_level(score)
            return {
                "ip": ip,
                "first_seen": profile.first_seen.isoformat(),
                "last_seen": profile.last_seen.isoformat(),
                "total_events": profile.total_events,
                "behavior_score": score,
                "threat_level": threat,
                "profile_data": profile.to_profile_data(),
                "baseline_data": profile.to_baseline_data(),
                "source": "memory",
            }

        # Fallback: query DB
        return self._load_profile_from_db(ip)

    def get_profiles(self, limit: int = 50, offset: int = 0,
                     min_score: float = 0) -> List[Dict[str, Any]]:
        """Get top behavior profiles sorted by behavior_score.

        Queries the database for persisted profiles.
        """
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                if min_score > 0:
                    cur.execute(
                        """SELECT ip, first_seen, last_seen, profile_data, baseline_data,
                                  threat_level, total_events, behavior_score, updated_at
                           FROM ip_behavior_profiles
                           WHERE behavior_score >= %s
                           ORDER BY behavior_score DESC
                           LIMIT %s OFFSET %s""",
                        (min_score, limit, offset),
                    )
                else:
                    cur.execute(
                        """SELECT ip, first_seen, last_seen, profile_data, baseline_data,
                                  threat_level, total_events, behavior_score, updated_at
                           FROM ip_behavior_profiles
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
                        "profile_data": row[3] if isinstance(row[3], dict) else json.loads(row[3]) if row[3] else {},
                        "baseline_data": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {},
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
            logger.warning("Failed to query behavior profiles: %s", e)
            return []

    def get_signals(self, ip: Optional[str] = None, limit: int = 100,
                    min_severity: str = "info") -> List[Dict[str, Any]]:
        """Get behavior signals, optionally filtered by IP.

        Severity ordering: info < medium < high < critical
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
                           FROM ip_behavior_signals
                           WHERE ip = %s
                           ORDER BY timestamp DESC
                           LIMIT %s""",
                        (ip, limit),
                    )
                else:
                    cur.execute(
                        """SELECT id, ip, timestamp, source, signal_type, severity, metadata, created_at
                           FROM ip_behavior_signals
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
                        "metadata": row[6] if isinstance(row[6], dict) else json.loads(row[6]) if row[6] else {},
                        "created_at": str(row[7]),
                    })
                return signals
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to query behavior signals: %s", e)
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get profiler statistics for dashboard."""
        with self._lock:
            total_profiles = len(self._profiles)
            total_ingested = self._total_ingested
            total_signals = self._total_signals

            # Count profiles by threat level (in-memory)
            threat_counts = defaultdict(int)
            for p in self._profiles.values():
                score = p.compute_behavior_score()
                threat_counts[p.get_threat_level(score)] += 1

        return {
            "total_profiles": total_profiles,
            "total_ingested": total_ingested,
            "total_signals": total_signals,
            "threat_level_counts": dict(threat_counts),
        }

    def periodic_persist(self) -> int:
        """Persist all dirty profiles to DB.

        Call periodically (e.g., every save interval in agent loop).
        Returns number of profiles persisted.
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
        return persisted

    # ── Internal persistence ─────────────────────────────────────────

    def _persist_profile(self, profile: IPBehaviorProfile) -> None:
        """Upsert a profile to the ip_behavior_profiles table."""
        behavior_score = profile.compute_behavior_score()
        threat_level = profile.get_threat_level(behavior_score)

        conn = self.db.connect()
        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO ip_behavior_profiles
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
                    threat_level,
                    profile.total_events,
                    behavior_score,
                ),
            )
        finally:
            cur.close()
            self.db.putconn(conn)

    def _persist_signals(self, ip: str, signals: List[Dict[str, Any]]) -> None:
        """Insert behavior signals into ip_behavior_signals table."""
        if not signals:
            return

        conn = self.db.connect()
        cur = conn.cursor()
        try:
            for sig in signals:
                cur.execute(
                    """INSERT INTO ip_behavior_signals
                       (ip, timestamp, source, signal_type, severity, metadata)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (
                        ip,
                        sig.get("timestamp", datetime.now(timezone.utc)),
                        sig.get("source", "behavior_profiler"),
                        sig.get("signal_type", "unknown"),
                        sig.get("severity", "info"),
                        json.dumps(sig.get("metadata", {})),
                    ),
                )
        finally:
            cur.close()
            self.db.putconn(conn)

    def _load_profile_from_db(self, ip: str) -> Optional[Dict[str, Any]]:
        """Load a profile from the database."""
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """SELECT ip, first_seen, last_seen, profile_data, baseline_data,
                              threat_level, total_events, behavior_score, updated_at
                       FROM ip_behavior_profiles WHERE ip = %s""",
                    (ip,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "ip": row[0],
                    "first_seen": str(row[1]),
                    "last_seen": str(row[2]),
                    "profile_data": row[3] if isinstance(row[3], dict) else json.loads(row[3]) if row[3] else {},
                    "baseline_data": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {},
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
