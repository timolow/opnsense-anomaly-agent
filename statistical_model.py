"""
Statistical model for OPNsense anomaly detection agent.

Maintains rolling baselines of traffic patterns and computes
z-scores and deviation metrics to identify statistically
anomalous behavior.
"""

import math
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================
# Rolling statistics (Welford's algorithm for running mean/std)
# ============================================================


@dataclass
class RunningStats:
    """Maintains running mean and standard deviation using Welford's online algorithm."""
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    _values: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    def update(self, value: float):
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


# ============================================================
# Windowed counters for time-series tracking
# ============================================================


class WindowedCounter:
    """Count events in sliding time windows.
    
    Used to track per-minute/per-hour event rates for baseline
    calculation and anomaly detection.
    """
    
    def __init__(self, window_minutes: int = 60):
        self.window_minutes = window_minutes
        self._buckets: Dict[Tuple[str, datetime], int] = defaultdict(int)
        self._timestamps: Dict[Tuple[str, datetime], deque] = defaultdict(deque)
    
    def record(self, key: str, ts: Optional[datetime] = None):
        """Record an event for a given key."""
        ts = ts or datetime.now(timezone.utc)
        bucket_key = self._bucket_key(ts)
        compound_key = (key, bucket_key)
        self._buckets[compound_key] += 1
        self._timestamps[compound_key].append(ts)
        
        # Cleanup old buckets
        cutoff = ts - timedelta(minutes=self.window_minutes)
        for k in list(self._buckets.keys()):
            bk = k[1]
            if bk and bk < cutoff:
                del self._buckets[k]
                self._timestamps.pop(k, None)
    
    def get_rate(self, key: str, now: Optional[datetime] = None) -> float:
        """Get the event rate (events per minute) for a key."""
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=self.window_minutes)
        
        total = 0
        bucket_count = 0
        for (k, bk), count in self._buckets.items():
            if k == key and bk >= cutoff:
                total += count
                bucket_count += 1
        
        if bucket_count == 0:
            return 0.0
        
        return total / self.window_minutes
    
    def get_current_rate(self, key: str, now: Optional[datetime] = None) -> float:
        """Get the current window's rate for a key."""
        now = now or datetime.now(timezone.utc)
        bucket_key = self._bucket_key(now)
        return self._buckets.get((key, bucket_key), 0)
    
    def _bucket_key(self, ts: datetime) -> datetime:
        """Round timestamp to a bucket boundary."""
        return ts.replace(minute=0, second=0, microsecond=0)


# ============================================================
# Baseline manager
# ============================================================


@dataclass
class Baseline:
    """A statistical baseline for a specific metric."""
    metric_name: str
    running_stats: RunningStats
    window_minutes: int = 60
    anomaly_threshold: float = 3.0  # z-score threshold
    min_samples: int = 30  # minimum samples before flagging anomalies
    
    def is_anomalous(self, value: float) -> Tuple[bool, float]:
        """Check if a value is anomalous based on the baseline.
        
        Returns (is_anomalous, z_score).
        """
        if self.running_stats.count < self.min_samples:
            return False, 0.0
        
        z = self.running_stats.z_score(value)
        return abs(z) > self.anomaly_threshold, z
    
    def deviation_score(self, value: float) -> float:
        """Calculate a deviation score (0-1 normalized from z-score)."""
        if self.running_stats.count < self.min_samples:
            return 0.0
        
        z = abs(self.running_stats.z_score(value))
        # Clamp to 0-1 range (z=3 -> 1.0, z=0 -> 0.0)
        return min(z / self.anomaly_threshold, 1.0)


class StatisticalModel:
    """Manages multiple statistical baselines for traffic analysis."""
    
    # Pre-defined metrics
    METRIC_EVENTS_PER_MIN = "events_per_minute"
    METRIC_SYN_PER_MIN = "syn_per_minute"
    METRIC_BLOCKED_PER_MIN = "blocked_per_minute"
    METRIC_ICMP_PER_MIN = "icmp_per_minute"
    METRIC_UDP_PER_MIN = "udp_per_minute"
    METRIC_UNIQUE_SRC_PER_MIN = "unique_src_per_minute"
    METRIC_UNIQUE_DST_PER_MIN = "unique_dst_per_minute"
    METRIC_UNIQUE_PORTS_PER_MIN = "unique_dst_ports_per_minute"
    METRIC_PACKETS_PER_MIN = "packets_per_minute"
    
    def __init__(self, default_threshold: float = 3.0, min_samples: int = 30):
        self.default_threshold = default_threshold
        self.min_samples = min_samples
        
        # Baselines by metric name
        self._baselines: Dict[str, Baseline] = {}
        
        # Track unique IPs per minute for counting
        self._src_ips_per_min: Dict[str, set] = defaultdict(set)
        self._dst_ips_per_min: Dict[str, set] = defaultdict(set)
        self._ports_per_min: Dict[str, set] = defaultdict(set)
    
    def get_baseline(self, metric: str) -> Baseline:
        """Get or create a baseline for a metric."""
        if metric not in self._baselines:
            self._baselines[metric] = Baseline(
                metric_name=metric,
                running_stats=RunningStats(),
                anomaly_threshold=self.default_threshold,
                min_samples=self.min_samples,
            )
        return self._baselines[metric]
    
    def record_event(self, event: Dict[str, Any], ts: Optional[datetime] = None):
        """Record an event to update all baselines."""
        ts = ts or datetime.now(timezone.utc)
        bucket = self._bucket_key(ts)
        
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        proto = event.get('proto', '')
        tcp_flags = event.get('tcp_flags', '')
        action = event.get('action', '')
        dst_port = event.get('dport')
        
        # General event rate
        self.get_baseline(self.METRIC_EVENTS_PER_MIN).running_stats.update(1)
        
        # Protocol-specific rates
        if proto == 'TCP':
            self.get_baseline(self.METRIC_PACKETS_PER_MIN).running_stats.update(1)
        if proto == 'UDP':
            self.get_baseline(self.METRIC_UDP_PER_MIN).running_stats.update(1)
        if proto in ('ICMP', 'ICMPV6'):
            self.get_baseline(self.METRIC_ICMP_PER_MIN).running_stats.update(1)
        
        # TCP flag tracking
        if tcp_flags == 'SYN':
            self.get_baseline(self.METRIC_SYN_PER_MIN).running_stats.update(1)
        
        # Action tracking
        if action == 'BLOCK':
            self.get_baseline(self.METRIC_BLOCKED_PER_MIN).running_stats.update(1)
        
        # Unique tracking
        if src_ip:
            self._src_ips_per_min[bucket].add(src_ip)
        if dst_ip:
            self._dst_ips_per_min[bucket].add(dst_ip)
        if dst_port is not None:
            self._ports_per_min[bucket].add(dst_port)
    
    def update_per_minute_rates(self, ts: Optional[datetime] = None):
        """Update per-minute unique counts baselines."""
        ts = ts or datetime.now(timezone.utc)
        bucket = self._bucket_key(ts)
        
        src_count = len(self._src_ips_per_min.get(bucket, set()))
        dst_count = len(self._dst_ips_per_min.get(bucket, set()))
        port_count = len(self._ports_per_min.get(bucket, set()))
        
        if src_count > 0:
            self.get_baseline(self.METRIC_UNIQUE_SRC_PER_MIN).running_stats.update(src_count)
        if dst_count > 0:
            self.get_baseline(self.METRIC_UNIQUE_DST_PER_MIN).running_stats.update(dst_count)
        if port_count > 0:
            self.get_baseline(self.METRIC_UNIQUE_PORTS_PER_MIN).running_stats.update(port_count)
    
    def check_anomaly(self, value: float, metric: str) -> Tuple[bool, float]:
        """Check if a value is anomalous for a given metric."""
        baseline = self.get_baseline(metric)
        return baseline.is_anomalous(value)
    
    def get_all_anomaly_checks(self, current_rates: Dict[str, float]) -> List[Dict[str, Any]]:
        """Check all baselines against current rates.
        
        Returns list of anomaly findings.
        """
        anomalies = []
        for metric, current_value in current_rates.items():
            baseline = self.get_baseline(metric)
            is_anom, z_score = baseline.is_anomalous(current_value)
            
            if is_anom:
                severity = self._severity_from_z(z_score)
                anomalies.append({
                    'type': 'STATISTICAL_ANOMALY',
                    'metric': metric,
                    'severity': severity,
                    'z_score': round(z_score, 2),
                    'baseline_mean': round(baseline.running_stats.mean, 2),
                    'baseline_stddev': round(baseline.running_stats.stddev, 2),
                    'current_value': round(current_value, 2),
                    'sample_count': baseline.running_stats.count,
                    'description': f"Statistical anomaly: {metric} current={current_value:.1f} baseline_mean={baseline.running_stats.mean:.1f}+/-{baseline.running_stats.stddev:.1f} (z={z_score:.2f})",
                    'detail': {
                        'metric': metric,
                        'z_score': z_score,
                        'baseline_mean': baseline.running_stats.mean,
                        'baseline_stddev': baseline.running_stats.stddev,
                    },
                })
        
        return anomalies
    
    def _severity_from_z(self, z: float) -> str:
        """Convert z-score to severity level."""
        az = abs(z)
        if az >= 5.0:
            return 'CRITICAL'
        elif az >= 4.0:
            return 'HIGH'
        elif az >= 3.0:
            return 'MEDIUM'
        return 'LOW'
    
    def _bucket_key(self, ts: datetime) -> str:
        """Create a minute-level bucket key."""
        return ts.strftime('%Y-%m-%d %H:%M')
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get a summary of all baselines."""
        summary = {}
        for name, baseline in self._baselines.items():
            if baseline.running_stats.count > 0:
                summary[name] = {
                    'mean': round(baseline.running_stats.mean, 2),
                    'stddev': round(baseline.running_stats.stddev, 2),
                    'count': baseline.running_stats.count,
                    'threshold': baseline.anomaly_threshold,
                }
        return summary
