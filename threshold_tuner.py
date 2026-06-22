#!/usr/bin/env python3
"""
Threshold Auto-Tuning Engine for OPNsense Anomaly Detection.

Implements automatic threshold optimization using:
- ROC curve analysis to find optimal threshold points
- False positive rate vs detection rate trade-off analysis
- Periodic threshold adjustment based on feedback
- Database persistence for thresholds and tuning history

Usage:
    from threshold_tuner import ThresholdTuner
    tuner = ThresholdTuner(db)  # db = EventDatabase instance
    tuner.record_detection(anomaly_type='volume_spike', score=4.5, is_true_positive=True)
    tuner.record_feedback(anomaly_id=123, label='false_positive', reason='legitimate traffic')
    results = tuner.tune()  # returns list of adjusted thresholds
"""

import json
import logging
import math
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================
# Default threshold configuration
# ============================================================

DEFAULT_THRESHOLDS = {
    'volume_zscore': {
        'value': 3.0,
        'min': 1.5,
        'max': 6.0,
        'step': 0.1,
        'description': 'Z-score threshold for volume spike detection',
    },
    'port_scan_min': {
        'value': 10,
        'min': 5,
        'max': 50,
        'step': 1,
        'description': 'Minimum unique ports to trigger port scan alert',
    },
    'new_ip_min': {
        'value': 5,
        'min': 2,
        'max': 30,
        'step': 1,
        'description': 'Minimum events from new IP to trigger alert',
    },
    'temporal_zscore': {
        'value': 2.0,
        'min': 1.0,
        'max': 5.0,
        'step': 0.1,
        'description': 'Z-score threshold for temporal anomaly detection',
    },
    'protocol_shift': {
        'value': 0.15,
        'min': 0.05,
        'max': 0.50,
        'step': 0.01,
        'description': 'Protocol distribution deviation threshold',
    },
}

# Performance targets
TARGET_FPR = float(os.getenv('TUNER_TARGET_FPR', '0.05'))      # Max 5% false positive rate
TARGET_TPR = float(os.getenv('TUNER_TARGET_TPR', '0.90'))      # Min 90% detection rate
MIN_FEEDBACK_FOR_TUNING = int(os.getenv('TUNER_MIN_FEEDBACK', '10'))  # Min feedback before tuning
TUNING_WINDOW_HOURS = int(os.getenv('TUNER_WINDOW_HOURS', '72'))  # Lookback window for tuning
ADJUSTMENT_STEP_PCT = float(os.getenv('TUNER_ADJUSTMENT_PCT', '0.05'))  # 5% adjustment per step


# ============================================================
# ROC Curve Analysis
# ============================================================

class ROCCurve:
    """Compute ROC curve and optimal operating point from scored detections."""
    
    def __init__(self):
        self.positive_scores: List[float] = []  # scores for true positives
        self.negative_scores: List[float] = []  # scores for false positives
    
    def add(self, score: float, is_positive: bool):
        """Add a detection result with its score and ground truth label."""
        if is_positive:
            self.positive_scores.append(score)
        else:
            self.negative_scores.append(score)
    
    @property
    def sample_count(self) -> int:
        return len(self.positive_scores) + len(self.negative_scores)
    
    def compute_curve(self, n_points: int = 100) -> List[Tuple[float, float, float]]:
        """Compute ROC curve as list of (threshold, fpr, tpr) points.
        
        Returns points sorted by threshold descending (most sensitive first).
        """
        if not self.positive_scores or not self.negative_scores:
            return []
        
        # Get all unique thresholds to evaluate
        all_scores = self.positive_scores + self.negative_scores
        min_score = min(all_scores)
        max_score = max(all_scores)
        
        if min_score == max_score:
            return [(min_score, 0.5, 0.5)]
        
        thresholds = []
        for i in range(n_points):
            t = min_score + (max_score - min_score) * i / (n_points - 1)
            thresholds.append(t)
        
        points = []
        for threshold in thresholds:
            # True positives: positive scores >= threshold
            tp = sum(1 for s in self.positive_scores if s >= threshold)
            # False positives: negative scores >= threshold
            fp = sum(1 for s in self.negative_scores if s >= threshold)
            
            tpr = tp / len(self.positive_scores) if self.positive_scores else 0.0
            fpr = fp / len(self.negative_scores) if self.negative_scores else 0.0
            
            points.append((threshold, fpr, tpr))
        
        # Sort by threshold descending
        points.sort(key=lambda x: -x[0])
        return points
    
    def find_optimal_threshold(self, target_fpr: float = TARGET_FPR, 
                                target_tpr: float = TARGET_TPR) -> Tuple[float, float, float]:
        """Find the threshold that best meets FPR/TPR targets.
        
        Strategy:
        1. First, find thresholds that meet the FPR target
        2. Among those, pick the one with highest TPR
        3. If no threshold meets FPR target, pick the one with best F1 score
        
        Returns (threshold, fpr, tpr).
        """
        curve = self.compute_curve()
        if not curve:
            return (0.0, 0.0, 0.0)
        
        # Find thresholds meeting FPR target
        meeting_fpr = [(t, fpr, tpr) for t, fpr, tpr in curve if fpr <= target_fpr]
        
        if meeting_fpr:
            # Among thresholds meeting FPR target, pick one with highest TPR
            best = max(meeting_fpr, key=lambda x: x[2])
            return best
        
        # No threshold meets FPR target — pick best F1
        def f1_score(t, fpr, tpr):
            precision = tpr / (tpr + fpr) if (tpr + fpr) > 0 else 0.0
            recall = tpr
            if precision + recall == 0:
                return 0.0
            return 2 * precision * recall / (precision + recall)
        
        best = max(curve, key=lambda x: f1_score(*x))
        return best
    
    def youden_index(self) -> Tuple[float, float, float]:
        """Find threshold maximizing Youden's J statistic (sensitivity + specificity - 1).
        
        Returns (threshold, fpr, tpr).
        """
        curve = self.compute_curve()
        if not curve:
            return (0.0, 0.5, 0.5)
        
        best = max(curve, key=lambda x: x[2] - x[1])  # tpr - fpr = J
        return best
    
    def auc(self) -> float:
        """Compute Area Under the ROC Curve (AUC)."""
        curve = self.compute_curve()
        if len(curve) < 2:
            return 0.5
        
        # Sort by FPR ascending for trapezoidal integration
        sorted_curve = sorted(curve, key=lambda x: x[1])
        
        auc_value = 0.0
        for i in range(1, len(sorted_curve)):
            dx = sorted_curve[i][1] - sorted_curve[i-1][1]  # delta FPR
            avg_y = (sorted_curve[i][2] + sorted_curve[i-1][2]) / 2  # avg TPR
            auc_value += dx * avg_y
        
        return auc_value


# ============================================================
# Per-type ROC trackers
# ============================================================

class ThresholdTypeTracker:
    """Track detection scores and labels for a single threshold type."""
    
    def __init__(self, threshold_type: str, roc_window: int = 500):
        self.threshold_type = threshold_type
        self.roc = ROCCurve()
        # Rolling window of recent detections: (timestamp, score, label)
        self.detection_history: deque = deque(maxlen=roc_window)
        # Feedback map: anomaly_id -> label
        self.feedback: Dict[int, str] = {}
    
    def record_detection(self, score: float, timestamp: Optional[str] = None):
        """Record a detection event (label unknown until feedback arrives)."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        self.detection_history.append({
            'timestamp': ts,
            'score': score,
            'label': None,  # unknown until feedback
        })
    
    def record_feedback(self, score: float, label: str, timestamp: Optional[str] = None):
        """Record feedback for a detection: true_positive, false_positive, dismissed."""
        if label in ('true_positive', 'tp'):
            self.roc.add(score, is_positive=True)
        elif label in ('false_positive', 'fp'):
            self.roc.add(score, is_positive=False)
        # 'dismissed' — don't add to ROC (insufficient data to label)


# ============================================================
# Main Threshold Tuner
# ============================================================

class ThresholdTuner:
    """Automatic threshold optimization for anomaly detection.
    
    Tracks detection outcomes, computes ROC curves per threshold type,
    and adjusts thresholds to minimize FPR while maintaining TPR.
    """
    
    def __init__(self, db=None):
        self.db = db
        self.current_thresholds: Dict[str, float] = {}
        self.trackers: Dict[str, ThresholdTypeTracker] = {}
        
        # Initialize from defaults
        for name, cfg in DEFAULT_THRESHOLDS.items():
            self.current_thresholds[name] = cfg['value']
            self.trackers[name] = ThresholdTypeTracker(name)
        
        # Load persisted state
        self._load_state()
        
        logger.info("ThresholdTuner initialized with %d threshold types", len(self.trackers))
    
    def get_threshold(self, threshold_type: str) -> float:
        """Get the current threshold value for a type."""
        return self.current_thresholds.get(threshold_type, 
                                           DEFAULT_THRESHOLDS.get(threshold_type, {}).get('value', 3.0)) or 3.0
    
    def get_all_thresholds(self) -> Dict[str, float]:
        """Get all current threshold values."""
        return dict(self.current_thresholds)
    
    def set_threshold(self, threshold_type: str, value: float):
        """Manually set a threshold value (with bounds checking)."""
        cfg = DEFAULT_THRESHOLDS.get(threshold_type)
        if not cfg:
            raise ValueError(f"Unknown threshold type: {threshold_type}")
        
        value = max(cfg['min'], min(cfg['max'], value))
        old = self.current_thresholds.get(threshold_type) or cfg['value']
        if old != value:
            self.current_thresholds[threshold_type] = value
            self._record_tuning(threshold_type, float(old), float(value), 'manual')
            self._save_state()
            logger.info("Threshold %s manually set: %.2f -> %.2f", threshold_type, old, value)
    
    def record_detection(self, anomaly_type: str, score: float, 
                         anomaly_id: Optional[int] = None,
                         timestamp: Optional[str] = None):
        """Record a detection event. Call this for every anomaly detected.
        
        Args:
            anomaly_type: e.g., 'volume_spike', 'port_scan', 'new_ip', etc.
            score: The detection score (z-score, port count, event count, etc.)
            anomaly_id: Optional DB anomaly ID for later feedback linking
            timestamp: Optional ISO timestamp
        """
        # Map anomaly type to threshold type
        threshold_type = self._anomaly_to_threshold_type(anomaly_type)
        tracker = self.trackers.get(threshold_type)
        if not tracker:
            logger.debug("No tracker for anomaly type %s (threshold: %s)", anomaly_type, threshold_type)
            return
        
        tracker.record_detection(score, timestamp)
        
        # Store in DB if available
        if self.db and anomaly_id:
            self._store_detection_record(anomaly_id, anomaly_type, score, threshold_type, timestamp)
    
    def record_feedback(self, anomaly_id: int, label: str, 
                        reason: str = "", user_id: str = ""):
        """Record user feedback on a detected anomaly.
        
        Args:
            anomaly_id: DB anomaly ID
            label: 'true_positive', 'false_positive', or 'dismissed'
            reason: Optional explanation
            user_id: Optional user identifier
        """
        if label not in ('true_positive', 'false_positive', 'dismissed'):
            raise ValueError(f"Invalid label: {label}. Must be true_positive, false_positive, or dismissed")
        
        # Store feedback in DB
        if self.db:
            self._store_feedback(anomaly_id, label, reason, user_id)
        
        # Also add to ROC tracker if we have the score
        score = self._get_detection_score(anomaly_id)
        if score is not None:
            anomaly_type = self._get_detection_type(anomaly_id)
            threshold_type = self._anomaly_to_threshold_type(anomaly_type)
            tracker = self.trackers.get(threshold_type)
            if tracker:
                tracker.record_feedback(score, label)
                logger.info("Feedback recorded: anomaly_id=%d, label=%s, score=%.2f, type=%s",
                          anomaly_id, label, score, threshold_type)
        
        # Check if tuning is needed
        self._maybe_auto_tune()
    
    def tune(self, threshold_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run threshold tuning for one or all types.
        
        Returns list of adjustments made: [{type, old_value, new_value, reason, fpr, tpr}]
        """
        types_to_tune = [threshold_type] if threshold_type else list(self.trackers.keys())
        adjustments = []
        
        for ttype in types_to_tune:
            tracker = self.trackers.get(ttype)
            if not tracker:
                continue
            
            # Check if enough data to tune
            if tracker.roc.sample_count < MIN_FEEDBACK_FOR_TUNING:
                logger.debug("Skipping tune for %s: only %d labeled samples (need %d)",
                           ttype, tracker.roc.sample_count, MIN_FEEDBACK_FOR_TUNING)
                continue
            
            # Find optimal threshold
            roc = tracker.roc
            optimal_threshold, optimal_fpr, optimal_tpr = roc.find_optimal_threshold()
            current = float(self.current_thresholds.get(ttype) or DEFAULT_THRESHOLDS.get(ttype, {}).get('value', 3.0))
            
            # Check current metrics
            current_fpr, current_tpr = self._compute_current_metrics(ttype)
            
            # Decide if adjustment is needed
            reason = ""
            new_value = current
            
            if current_fpr > TARGET_FPR:
                # Too many false positives — raise threshold
                reason = f"FPR {current_fpr:.1%} > target {TARGET_FPR:.1%}, raising threshold"
                adjustment = current * (1 + ADJUSTMENT_STEP_PCT)
                cfg = DEFAULT_THRESHOLDS.get(ttype, {})
                max_val = cfg.get('max', float('inf'))
                new_value = min(float(max_val), adjustment)
            elif current_tpr < TARGET_TPR and current_fpr <= TARGET_FPR * 0.5:
                # Missing true positives and FPR is comfortably low — lower threshold
                reason = f"TPR {current_tpr:.1%} < target {TARGET_TPR:.1%} (FPR room), lowering threshold"
                adjustment = current * (1 - ADJUSTMENT_STEP_PCT)
                cfg = DEFAULT_THRESHOLDS.get(ttype, {})
                min_val = cfg.get('min', 0)
                new_value = max(float(min_val), adjustment)
            
            if new_value != current:
                self.current_thresholds[ttype] = new_value
                self._record_tuning(ttype, current, new_value, reason)
                self._save_state()
                adjustments.append({
                    'type': ttype,
                    'old_value': current,
                    'new_value': new_value,
                    'reason': reason,
                    'fpr': current_fpr,
                    'tpr': current_tpr,
                    'optimal_threshold': optimal_threshold,
                    'optimal_fpr': optimal_fpr,
                    'optimal_tpr': optimal_tpr,
                    'auc': roc.auc(),
                })
                logger.info("Tuned threshold %s: %.2f -> %.2f | %s (FPR=%.1%, TPR=%.1%, AUC=%.3f)",
                          ttype, current, new_value, reason, current_fpr, current_tpr, roc.auc())
            else:
                adjustments.append({
                    'type': ttype,
                    'old_value': current,
                    'new_value': current,
                    'reason': 'Within targets, no adjustment needed',
                    'fpr': current_fpr,
                    'tpr': current_tpr,
                    'optimal_threshold': optimal_threshold,
                    'optimal_fpr': optimal_fpr,
                    'optimal_tpr': optimal_tpr,
                    'auc': roc.auc(),
                })
        
        return adjustments
    
    def get_metrics(self, threshold_type: Optional[str] = None) -> Dict[str, Any]:
        """Get performance metrics for one or all threshold types."""
        types = [threshold_type] if threshold_type else list(self.trackers.keys())
        result = {}
        
        for ttype in types:
            tracker = self.trackers.get(ttype)
            if not tracker:
                continue
            
            roc = tracker.roc
            fpr, tpr = self._compute_current_metrics(ttype)
            precision = tpr / (tpr + fpr) if (tpr + fpr) > 0 else 0.0
            recall = tpr
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            
            result[ttype] = {
                'current_threshold': self.current_thresholds.get(ttype),
                'false_positive_rate': round(fpr, 4),
                'true_positive_rate': round(tpr, 4),
                'precision': round(precision, 4),
                'recall': round(recall, 4),
                'f1_score': round(f1, 4),
                'sample_count': roc.sample_count,
                'labeled_positive': len(roc.positive_scores),
                'labeled_negative': len(roc.negative_scores),
                'auc': round(roc.auc(), 4),
                'optimal_threshold': round(roc.find_optimal_threshold()[0], 4),
                'detection_history_size': len(tracker.detection_history),
            }
        
        return result
    
    def get_tuning_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get tuning history from DB or memory."""
        if self.db:
            return self._get_tuning_history_from_db(limit)
        # Fallback: return empty (no persistence without DB)
        return []
    
    def get_roc_curve(self, threshold_type: str) -> List[Dict[str, float]]:
        """Get ROC curve points for a threshold type."""
        tracker = self.trackers.get(threshold_type)
        if not tracker:
            return []
        
        curve = tracker.roc.compute_curve()
        return [{'threshold': t, 'fpr': round(f, 4), 'tpr': round(tp, 4)} for t, f, tp in curve]
    
    # ── Internal methods ──────────────────────────────────────────
    
    def _anomaly_to_threshold_type(self, anomaly_type: str) -> str:
        """Map anomaly type to threshold type."""
        mapping = {
            'volume_spike': 'volume_zscore',
            'port_scan': 'port_scan_min',
            'new_ip': 'new_ip_min',
            'temporal_anomaly': 'temporal_zscore',
            'protocol_shift': 'protocol_shift',
        }
        return mapping.get(anomaly_type, anomaly_type)
    
    def _compute_current_metrics(self, threshold_type: str) -> Tuple[float, float]:
        """Compute current FPR/TPR at the active threshold."""
        tracker = self.trackers.get(threshold_type)
        if not tracker or tracker.roc.sample_count == 0:
            return (0.0, 0.0)
        
        threshold = self.current_thresholds.get(threshold_type, 3.0)
        pos = tracker.roc.positive_scores
        neg = tracker.roc.negative_scores
        
        tp = sum(1 for s in pos if s >= threshold)
        fp = sum(1 for s in neg if s >= threshold)
        fn = len(pos) - tp
        tn = len(neg) - fp
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        return (fpr, tpr)
    
    def _maybe_auto_tune(self):
        """Check if conditions are met for auto-tuning and trigger it."""
        # Auto-tune if any tracker has enough labeled samples
        for ttype, tracker in self.trackers.items():
            if tracker.roc.sample_count >= MIN_FEEDBACK_FOR_TUNING:
                self.tune(ttype)
                break
    
    # ── Database persistence ──────────────────────────────────────
    
    def _store_detection_record(self, anomaly_id: int, anomaly_type: str,
                                  score: float, threshold_type: str,
                                  timestamp: Optional[str] = None):
        """Store a detection record in the DB."""
        if not self.db:
            return
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT INTO threshold_detection_records
                       (anomaly_id, anomaly_type, score, threshold_type, timestamp)
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (anomaly_id) DO NOTHING""",
                    (anomaly_id, anomaly_type, score, threshold_type,
                     timestamp or datetime.now(timezone.utc).isoformat())
                )
            finally:
                cur.close()
        except Exception as e:
            logger.debug("Failed to store detection record: %s", e)
    
    def _store_feedback(self, anomaly_id: int, label: str, reason: str, user_id: str):
        """Store feedback in the DB."""
        if not self.db:
            return
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT INTO threshold_feedback
                       (anomaly_id, label, reason, user_id, created_at)
                       VALUES (%s, %s, %s, %s, NOW())""",
                    (anomaly_id, label, reason, user_id)
                )
            finally:
                cur.close()
        except Exception as e:
            logger.warning("Failed to store feedback: %s", e)
    
    def _get_detection_score(self, anomaly_id: int) -> Optional[float]:
        """Get the detection score for an anomaly from DB."""
        if not self.db:
            return None
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT score, anomaly_type FROM threshold_detection_records WHERE anomaly_id = %s",
                    (anomaly_id,)
                )
                row = cur.fetchone()
                if row:
                    return row[0]
            finally:
                cur.close()
        except Exception:
            pass
        return None
    
    def _get_detection_type(self, anomaly_id: int) -> str:
        """Get the anomaly type for an anomaly from DB."""
        if not self.db:
            return ''
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT anomaly_type FROM threshold_detection_records WHERE anomaly_id = %s",
                    (anomaly_id,)
                )
                row = cur.fetchone()
                if row:
                    return row[0]
            finally:
                cur.close()
        except Exception:
            pass
        return ''
    
    def _record_tuning(self, threshold_type: str, old_value: float, new_value: float, reason: str):
        """Record a tuning adjustment in history."""
        if not self.db:
            return
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT INTO threshold_tuning_history
                       (threshold_type, old_value, new_value, reason, created_at)
                       VALUES (%s, %s, %s, %s, NOW())""",
                    (threshold_type, old_value, new_value, reason)
                )
            finally:
                cur.close()
        except Exception as e:
            logger.debug("Failed to record tuning: %s", e)
    
    def _get_tuning_history_from_db(self, limit: int) -> List[Dict[str, Any]]:
        """Get tuning history from DB."""
        if not self.db:
            return []
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """SELECT threshold_type, old_value, new_value, reason, created_at
                       FROM threshold_tuning_history
                       ORDER BY created_at DESC
                       LIMIT %s""",
                    (limit,)
                )
                results = []
                for row in cur.fetchall():
                    results.append({
                        'threshold_type': row[0],
                        'old_value': row[1],
                        'new_value': row[2],
                        'reason': row[3],
                        'created_at': row[4].isoformat() if row[4] else None,
                    })
                return results
            finally:
                cur.close()
        except Exception as e:
            logger.warning("Failed to get tuning history: %s", e)
            return []
    
    # ── State persistence (JSON file) ─────────────────────────────
    
    def _load_state(self):
        """Load tuner state from JSON file."""
        state_path = '/app/agent_data/threshold_tuner_state.json'
        if not os.path.exists(state_path):
            return
        
        try:
            with open(state_path) as f:
                state = json.load(f)
            
            if 'thresholds' in state:
                for k, v in state['thresholds'].items():
                    if k in self.current_thresholds:
                        self.current_thresholds[k] = v
            
            logger.info("Loaded threshold tuner state: %d thresholds", len(self.current_thresholds))
        except Exception as e:
            logger.warning("Failed to load threshold tuner state: %s", e)
    
    def _save_state(self):
        """Save tuner state to JSON file."""
        import json
        os.makedirs('/app/agent_data', exist_ok=True)
        state_path = '/app/agent_data/threshold_tuner_state.json'
        
        try:
            state = {
                'thresholds': self.current_thresholds,
                'saved_at': datetime.now(timezone.utc).isoformat(),
            }
            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save threshold tuner state: %s", e)