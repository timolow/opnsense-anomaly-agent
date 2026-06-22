#!/usr/bin/env python3
"""
Concept Drift Detection for firewall traffic patterns.

Monitors statistical properties of incoming traffic over time and detects
when traffic distribution shifts significantly (new attack types, network
changes, etc.) using the ADWIN (Adaptive Windowing) algorithm.

ADWIN is an online algorithm that maintains an adaptive window of recent
data points and detects distribution changes without needing labeled data.
Memory efficient: O(log(n)) sub-windows. Detects both abrupt and gradual drift.

Key metrics tracked:
- Event volume per rule (per-hour rate)
- Protocol distribution (TCP/UDP/ICMP ratios)
- Port diversity (unique dst ports per window)
- Source IP diversity (unique src IPs per window)

Drift events are stored in the database for historical analysis and
trigger retraining signals so baselines stay accurate.
"""

import os
import math
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── ADWIN Configuration ─────────────────────────────────────────────────
# delta controls sensitivity: lower = more sensitive (default 0.002 is standard)
ADWIN_DELTA = float(os.getenv("DRIFT_DELTA", "0.002"))
# Minimum samples before drift detection activates
ADWIN_MIN_SAMPLES = int(os.getenv("DRIFT_MIN_SAMPLES", "50"))
# Maximum window size (memory cap)
ADWIN_MAX_WINDOW = int(os.getenv("DRIFT_MAX_WINDOW", "2000"))
# Check interval in seconds (how often to evaluate drift)
DRIFT_CHECK_INTERVAL = int(os.getenv("DRIFT_CHECK_INTERVAL", "300"))
# Retraining cooldown — don't retrain more often than this (seconds)
RETRAIN_COOLDOWN = int(os.getenv("DRIFT_RETRAIN_COOLDOWN", "3600"))
# Metrics to track for drift
DRIFT_METRICS = os.getenv("DRIFT_METRICS", "volume,protocol,port_diversity,ip_diversity").split(",")


# ── ADWIN Sub-window ────────────────────────────────────────────────────

class _AdwinSubWindow:
    """A sub-window in the ADWIN data structure."""
    __slots__ = ('width', 'sum', 'sum_sq')

    def __init__(self, width: int, sum_val: float, sum_sq: float):
        self.width = width
        self.sum = sum_val
        self.sum_sq = sum_sq

    @property
    def mean(self) -> float:
        return self.sum / self.width if self.width > 0 else 0.0

    @property
    def variance(self) -> float:
        if self.width < 2:
            return 0.0
        m = self.mean
        return (self.sum_sq / self.width) - (m * m)


# ── ADWIN Algorithm ─────────────────────────────────────────────────────

class ADWIN:
    """Adaptive Windowing for change detection in data streams.

    Maintains an adaptive window of recent values. The window is split
    into exponentially-sized sub-windows. On each update, checks whether
    the distribution between any prefix and suffix of the window has
    changed significantly (using Hoeffding bound).

    When drift is detected, the larger part of the window is cut off,
    keeping only the most recent data that reflects the new concept.
    """

    def __init__(self, delta: float = ADWIN_DELTA, max_window: int = ADWIN_MAX_WINDOW, min_samples: int = ADWIN_MIN_SAMPLES):
        self.delta = delta
        self.max_window = max_window
        self.min_samples = min_samples
        self._windows: List[_AdwinSubWindow] = []
        self._total_sum = 0.0
        self._total_sum_sq = 0.0
        self._total_width = 0

    def add_value(self, value: float):
        """Add a new value to the stream."""
        # Add new element as a width-1 sub-window
        new_win = _AdwinSubWindow(1, value, value * value)
        self._windows.append(new_win)
        self._total_sum += value
        self._total_sum_sq += value * value
        self._total_width += 1

        # Merge adjacent equal-sized sub-windows
        self._merge()

        # Enforce max window size by dropping oldest
        if self._total_width > self.max_window:
            excess = self._total_width - self.max_window
            while excess > 0 and self._windows:
                drop = self._windows.pop(0)
                self._total_sum -= drop.sum
                self._total_sum_sq -= drop.sum_sq
                self._total_width -= drop.width
                excess -= drop.width

        # Check for drift after enough samples
        if self._total_width >= self.min_samples:
            self._cut()

    def _merge(self):
        """Merge adjacent sub-windows of equal size."""
        changed = True
        while changed and len(self._windows) >= 2:
            changed = False
            i = 0
            while i < len(self._windows) - 1:
                curr = self._windows[i]
                nxt = self._windows[i + 1]
                if curr.width == nxt.width:
                    merged = _AdwinSubWindow(
                        curr.width + nxt.width,
                        curr.sum + nxt.sum,
                        curr.sum_sq + nxt.sum_sq
                    )
                    self._windows[i] = merged
                    self._windows.pop(i + 1)
                    changed = True
                else:
                    i += 1

    def _cut(self):
        """Check all cut points and remove oldest data if drift detected."""
        delta = self.delta / (2.0 * self._total_width)
        max_diff = 0.0
        cut_point = -1

        # Compute cumulative sums from left
        width_left = 0
        sum_left = 0.0
        sum_sq_left = 0.0

        for i, win in enumerate(self._windows):
            width_left += win.width
            sum_left += win.sum
            sum_sq_left += win.sum_sq

            width_right = self._total_width - width_left
            sum_right = self._total_sum - sum_left
            sum_sq_right = self._total_sum_sq - sum_sq_left

            if width_right == 0:
                continue

            # Hoeffding bound for the cut point
            h = math.sqrt(
                (1.0 / (2.0 * min(width_left, width_right))) *
                math.log(4.0 / delta)
            )

            mean_left = sum_left / width_left
            mean_right = sum_right / width_right
            diff = abs(mean_left - mean_right)

            if diff > max_diff:
                max_diff = diff
                cut_point = i

        # If drift detected at the best cut point, remove oldest part
        if cut_point >= 0 and max_diff > math.sqrt(
            (1.0 / (2.0 * min(
                sum(w.width for w in self._windows[:cut_point + 1]),
                sum(w.width for w in self._windows[cut_point + 1:])
            ))) * math.log(4.0 / self.delta)
        ):
            removed = 0
            while self._windows and removed <= cut_point:
                drop = self._windows.pop(0)
                self._total_sum -= drop.sum
                self._total_sum_sq -= drop.sum_sq
                self._total_width -= drop.width
                removed += 1
            logger.info(
                "ADWIN drift: cut %d/%d elements (diff=%.4f)",
                cut_point + 1, self._total_width + cut_point + 1, max_diff
            )
            return True
        return False

    @property
    def width(self) -> int:
        return self._total_width

    @property
    def mean(self) -> float:
        return self._total_sum / self._total_width if self._total_width > 0 else 0.0

    @property
    def variance(self) -> float:
        if self._total_width < 2:
            return 0.0
        m = self.mean
        return (self._total_sum_sq / self._total_width) - (m * m)

    @property
    def stddev(self) -> float:
        return math.sqrt(max(0, self.variance))

    def is_stable(self) -> bool:
        """Check if the current window is stable (no recent drift)."""
        return self._total_width >= self.min_samples


# ── Drift Detector ──────────────────────────────────────────────────────

class DriftEvent:
    """A detected concept drift event."""

    def __init__(self, metric: str, scope: str, old_mean: float, new_mean: float,
                 drift_magnitude: float, window_size: int, timestamp: Optional[datetime] = None):
        self.metric = metric
        self.scope = scope          # e.g. "rule:<name>", "global:protocol", "global:volume"
        self.old_mean = old_mean
        self.new_mean = new_mean
        self.drift_magnitude = drift_magnitude
        self.window_size = window_size
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric": self.metric,
            "scope": self.scope,
            "old_mean": round(self.old_mean, 4),
            "new_mean": round(self.new_mean, 4),
            "drift_magnitude": round(self.drift_magnitude, 4),
            "window_size": self.window_size,
            "timestamp": self.timestamp.isoformat(),
        }

    def severity(self) -> str:
        mag = self.drift_magnitude
        if mag > 0.5:
            return "CRITICAL"
        elif mag > 0.3:
            return "HIGH"
        elif mag > 0.15:
            return "MEDIUM"
        return "LOW"

    def description(self) -> str:
        sev = self.severity()
        return (
            f"Concept drift [{sev}] on {self.metric} ({self.scope}): "
            f"mean shifted {self.old_mean:.2f} → {self.new_mean:.2f} "
            f"(magnitude={self.drift_magnitude:.3f}, window={self.window_size})"
        )


class ConceptDriftDetector:
    """Detects concept drift in firewall traffic patterns.

    Tracks multiple metrics per rule and globally using ADWIN windows.
    When drift is detected, emits DriftEvent objects that can trigger
    alerts and retraining signals.

    Usage:
        detector = ConceptDriftDetector()
        for event in stream:
            detector.process_event(event)
        drift_events = detector.check_drift()
    """

    def __init__(self):
        # ADWIN windows per (metric, scope)
        self._windows: Dict[str, ADWIN] = {}
        # For magnitude tracking: keep a longer-term baseline
        self._baselines: Dict[str, float] = {}
        self._baseline_samples: Dict[str, int] = {}
        self._last_drift: Dict[str, float] = {}  # scope -> last drift timestamp
        self._cooldown = RETRAIN_COOLDOWN
        # Track detected drift events (for history)
        self._drift_history: deque = deque(maxlen=500)

    def _key(self, metric: str, scope: str) -> str:
        return f"{metric}:{scope}"

    def process_event(self, event: Dict[str, Any]):
        """Feed a single firewall event into the drift detector.

        Extracts relevant metrics and updates ADWIN windows.
        """
        rule = event.get("rule_name", "unknown")
        proto = event.get("proto", "unknown").upper()
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port")

        # 1. Volume metric: 1 per event (ADWIN tracks event rate via window density)
        vol_key = self._key("volume", f"rule:{rule}")
        if vol_key not in self._windows:
            self._windows[vol_key] = ADWIN()
        self._windows[vol_key].add_value(1.0)

        # Global volume
        gvol_key = self._key("volume", "global")
        if gvol_key not in self._windows:
            self._windows[gvol_key] = ADWIN()
        self._windows[gvol_key].add_value(1.0)

        # 2. Protocol distribution (one-hot encoded per rule)
        if "protocol" in DRIFT_METRICS:
            proto_key = self._key("protocol", f"rule:{rule}")
            if proto_key not in self._windows:
                self._windows[proto_key] = ADWIN()
            # Encode protocol as numeric: TCP=1, UDP=2, ICMP=3, other=4
            proto_val = {"TCP": 1.0, "UDP": 2.0, "ICMP": 3.0}.get(proto, 4.0)
            self._windows[proto_key].add_value(proto_val)

            # Global protocol drift
            gproto_key = self._key("protocol", "global")
            if gproto_key not in self._windows:
                self._windows[gproto_key] = ADWIN()
            self._windows[gproto_key].add_value(proto_val)

        # 3. Port diversity: use dst_port as indicator
        if "port_diversity" in DRIFT_METRICS and dst_port is not None:
            port_key = self._key("port_diversity", f"rule:{rule}")
            if port_key not in self._windows:
                self._windows[port_key] = ADWIN()
            # Log-scale port value to normalize
            port_val = math.log1p(float(dst_port))
            self._windows[port_key].add_value(port_val)

        # 4. IP diversity: hash src_ip to a numeric value for distribution tracking
        if "ip_diversity" in DRIFT_METRICS and src_ip:
            ip_key = self._key("ip_diversity", f"rule:{rule}")
            if ip_key not in self._windows:
                self._windows[ip_key] = ADWIN()
            # Use a simple hash to map IP to a numeric value in [0, 1)
            ip_val = (hash(src_ip) % 1000) / 1000.0
            self._windows[ip_key].add_value(ip_val)

    def process_batch(self, events: List[Dict[str, Any]]):
        """Process a batch of events."""
        for event in events:
            self.process_event(event)

    def check_drift(self) -> List[DriftEvent]:
        """Check all tracked metrics for concept drift.

        Returns a list of DriftEvent objects for any detected drift.
        Uses cooldown to avoid alerting on the same metric too frequently.
        """
        drift_events = []
        now = time.time()

        for key, adwin in list(self._windows.items()):
            if adwin.width < ADWIN_MIN_SAMPLES:
                continue

            metric, scope = key.split(":", 1)

            # Cooldown check
            last = self._last_drift.get(scope, 0)
            if now - last < self._cooldown:
                continue

            # Detect drift: temporarily split window and check if means differ
            drift_event = self._check_single_drift(adwin, metric, scope, now)
            if drift_event:
                drift_events.append(drift_event)
                self._last_drift[scope] = now
                self._drift_history.append(drift_event)

        return drift_events

    def _check_single_drift(self, adwin: ADWIN, metric: str, scope: str,
                           now: float) -> Optional[DriftEvent]:
        """Check a single ADWIN window for drift.

        Strategy: compare the mean of the first half vs second half of the window.
        If they differ significantly relative to the variance, drift is detected.
        """
        if adwin.width < ADWIN_MIN_SAMPLES:
            return None

        windows = adwin._windows
        if len(windows) < 2:
            return None

        # Split into two halves
        mid = len(windows) // 2
        left = windows[:mid]
        right = windows[mid:]

        left_width = sum(w.width for w in left)
        right_width = sum(w.width for w in right)

        if left_width < 10 or right_width < 10:
            return None

        left_sum = sum(w.sum for w in left)
        right_sum = sum(w.sum for w in right)

        left_mean = left_sum / left_width
        right_mean = right_sum / right_width

        # Compute combined variance for significance test
        left_sq = sum(w.sum_sq for w in left)
        right_sq = sum(w.sum_sq for w in right)

        left_var = (left_sq / left_width) - (left_mean ** 2)
        right_var = (right_sq / right_width) - (right_mean ** 2)
        combined_std = math.sqrt(max(0, (left_var + right_var) / 2))

        if combined_std == 0:
            return None

        # Drift magnitude: standardized difference between halves
        drift_mag = abs(right_mean - left_mean) / combined_std

        # Threshold: use ADWIN delta to set sensitivity
        # Higher drift_mag = stronger drift signal
        threshold = 2.0  # roughly 2-sigma difference

        if drift_mag >= threshold:
            # Update baseline
            bkey = f"{metric}:{scope}"
            old_mean = self._baselines.get(bkey, left_mean)
            self._baselines[bkey] = right_mean

            return DriftEvent(
                metric=metric,
                scope=scope,
                old_mean=left_mean,
                new_mean=right_mean,
                drift_magnitude=drift_mag,
                window_size=adwin.width,
            )

        return None

    def get_status(self) -> Dict[str, Any]:
        """Get current status of the drift detector.

        Returns summary of tracked metrics, window sizes, and recent drift.
        """
        status = {
            "tracked_metrics": {},
            "recent_drift": [],
            "total_windows": len(self._windows),
            "history_size": len(self._drift_history),
        }

        for key, adwin in self._windows.items():
            metric, scope = key.split(":", 1)
            status["tracked_metrics"][key] = {
                "width": adwin.width,
                "mean": round(adwin.mean, 4),
                "stddev": round(adwin.stddev, 4),
                "stable": adwin.is_stable(),
            }

        # Recent drift events (last 10)
        for de in list(self._drift_history)[-10:]:
            status["recent_drift"].append(de.to_dict())

        return status

    def needs_retraining(self) -> bool:
        """Check if any recent drift signals that retraining is needed.

        Returns True if drift was detected within the retraining cooldown
        window and the drift magnitude is significant enough.
        """
        now = time.time()
        for de in self._drift_history:
            drift_age = now - time.mktime(de.timestamp.timetuple()) if isinstance(de.timestamp, datetime) else 0
            # Significant drift in last cooldown period
            if de.drift_magnitude > 0.3 and drift_age < self._cooldown:
                return True
        return False

    def get_drift_summary(self) -> List[Dict[str, Any]]:
        """Get a summary of recent drift events for alerts/dashboard."""
        return [de.to_dict() for de in list(self._drift_history)[-20:]]

    def clear(self):
        """Reset all drift state (used during retraining)."""
        self._windows.clear()
        self._baselines.clear()
        self._baseline_samples.clear()
        self._last_drift.clear()
        self._drift_history.clear()
        logger.info("Concept drift detector state cleared (post-retraining)")