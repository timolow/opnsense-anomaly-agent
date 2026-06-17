#!/usr/bin/env python3
"""
Self-Learning ML Engine for OPNsense Firewall Rule Classification

This module implements a continuously improving classifier that learns from:
1. User feedback (correct/incorrect labels)
2. Per-rule baseline statistics
3. Temporal patterns (time-of-day behavior)
4. Active learning (requesting labels for uncertain rules)
5. Threshold auto-tuning (optimizing classification boundaries)

Architecture:
- Week 1: User Feedback Loop - Store user labels, adjust confidence scores
- Week 2: Per-Rule Baselines - Track rolling stats per rule, detect drift
- Week 3: Temporal Patterns - Learn time-based behavior, flag timing anomalies
- Week 4: Active Learning Queue - Identify uncertain rules, batch for review
- Week 5: Threshold Auto-Tuning - Optimize thresholds using user agreement rates

Usage:
    from ml_learning import SelfLearningClassifier
    clf = SelfLearningClassifier(db_connection)
    clf.classify_rules(events)
    clf.save_feedback(rule_name, "correct")
    review_queue = clf.get_active_learning_queue()
"""

import os
import json
import logging
import math
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict, deque
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────
# These can be overridden via environment variables
MIN_RULE_EVENTS = int(os.getenv("ML_MIN_RULE_EVENTS", "20"))
HIGH_PORT_DIVERSITY = int(os.getenv("ML_HIGH_PORT_DIVERSITY", "100"))
HIGH_DEST_DIVERSITY = int(os.getenv("ML_HIGH_DEST_DIVERSITY", "100"))
LOW_VOLUME_THRESHOLD = int(os.getenv("ML_LOW_VOLUME_THRESHOLD", "50"))
HIGH_BLOCK_RATIO = float(os.getenv("ML_HIGH_BLOCK_RATIO", "0.3"))
NORMAL_PROTOCOLS = set(os.getenv("ML_NORMAL_PROTOCOLS", "TCP,UDP,ICMP,ip").split(","))

# Temporal learning settings
TEMPORAL_WINDOW_HOURS = int(os.getenv("ML_TEMPORAL_WINDOW_HOURS", "24"))
TEMPORAL_DRIFT_THRESHOLD = float(os.getenv("ML_TEMPORAL_DRIFT_THRESHOLD", "0.5"))

# Active learning settings
ACTIVE_LEARNING_CONFIDENCE_LOW = float(os.getenv("ML_ACTIVE_LEARNING_LOW", "0.4"))
ACTIVE_LEARNING_CONFIDENCE_HIGH = float(os.getenv("ML_ACTIVE_LEARNING_HIGH", "0.6"))

# Threshold tuning settings
TUNING_LEARNING_RATE = float(os.getenv("ML_TUNING_LEARNING_RATE", "0.05"))
TUNING_MIN_AGREEMENT_RATE = float(os.getenv("ML_TUNING_MIN_AGREEMENT", "0.6"))

# ── Data Classes ──────────────────────────────────────────────────────────

@dataclass
class RuleFeatures:
    """Computed features for a single rule with self-learning metadata."""
    rule_name: str
    total_events: int = 0
    pass_count: int = 0
    block_count: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_ports: int = 0
    protocols: Counter = field(default_factory=Counter)
    src_port_distribution: Counter = field(default_factory=Counter)
    dst_port_distribution: Counter = field(default_factory=Counter)
    src_ip_counts: Counter = field(default_factory=Counter)
    dst_ip_counts: Counter = field(default_factory=Counter)
    hour_distribution: Counter = field(default_factory=Counter)  # temporal
    
    # ML scores
    port_scan_score: float = 0.0
    dest_scan_score: float = 0.0
    action_ratio_score: float = 0.0
    volume_score: float = 0.0
    protocol_score: float = 0.0
    temporal_anomaly_score: float = 0.0  # Week 3
    goodness_score: float = 0.0
    classification: str = "UNKNOWN"
    confidence: float = 0.0
    
    # Week 1: User feedback
    user_feedback_count: int = 0
    user_correct_count: int = 0
    user_agreement_rate: float = 1.0
    
    # Week 2: Per-rule baselines
    baseline_port_diversity: float = 0.0
    baseline_dest_diversity: float = 0.0
    baseline_volume: float = 0.0
    baseline_block_ratio: float = 0.0
    baseline_goodness: float = 0.0
    baseline_updated: bool = False
    
    # Week 5: Tuning history
    tuning_history: List[Dict] = field(default_factory=list)
    
    # Details
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedbackRecord:
    """User feedback record for a rule classification."""
    rule_name: str
    timestamp: str
    label: str  # "correct" or "incorrect"
    reason: Optional[str] = None
    user_id: Optional[str] = None


@dataclass
class RuleBaseline:
    """Per-rule baseline statistics for drift detection."""
    rule_name: str
    avg_port_diversity: float = 0.0
    avg_dest_diversity: float = 0.0
    avg_volume: float = 0.0
    avg_block_ratio: float = 0.0
    baseline_goodness: float = 0.0
    sample_count: int = 0
    baseline_updated: bool = False
    window_start: Optional[str] = None
    window_end: Optional[str] = None


@dataclass
class TemporalPattern:
    """Learned temporal pattern for a rule."""
    rule_name: str
    hour_distribution: Dict[int, float] = field(default_factory=dict)
    total_samples: int = 0
    updated_at: Optional[str] = None


@dataclass
class ActiveLearningItem:
    """Rule queued for active learning review."""
    rule_name: str
    classification: str
    confidence: float
    reasons: List[str] = field(default_factory=list)


class SelfLearningClassifier:
    """
    Self-learning firewall rule classifier.
    
    Combines:
    - Static ML features (port diversity, dest diversity, etc.)
    - User feedback loop (Week 1)
    - Per-rule baselines (Week 2)
    - Temporal patterns (Week 3)
    - Active learning queue (Week 4)
    - Threshold auto-tuning (Week 5)
    """
    
    def __init__(self, db=None):
        self.db = db
        self.features_map: Dict[str, RuleFeatures] = {}
        self.total_events = 0
        self.events_with_rule = 0
        self.events_without_rule = 0
        
        # Week 1: Feedback storage
        self.feedback_records: List[FeedbackRecord] = []
        self._feedback_cache: Dict[str, List[FeedbackRecord]] = defaultdict(list)
        
        # Week 2: Baselines
        self.baselines: Dict[str, RuleBaseline] = {}
        self._baseline_windows: Dict[str, deque] = defaultdict(deque)  # rule -> recent features
        
        # Week 3: Temporal patterns
        self.temporal_patterns: Dict[str, TemporalPattern] = {}
        
        # Week 4: Active learning queue
        self.active_queue: List[ActiveLearningItem] = []
        
        # Week 5: Tuning state
        self.current_thresholds = {
            'port_diversity': HIGH_PORT_DIVERSITY,
            'dest_diversity': HIGH_DEST_DIVERSITY,
            'block_ratio': HIGH_BLOCK_RATIO,
            'low_volume': LOW_VOLUME_THRESHOLD,
        }
        self.tuning_history: List[Dict] = []
        
        logger.info("SelfLearningClassifier initialized with self-learning modules")
    
    def load_state(self):
        """Load classifier state from JSON file."""
        import json
        state_path = '/app/agent_data/ml_state.json'
        if not os.path.exists(state_path):
            logger.info("No ML state file found at %s", state_path)
            return False
        
        try:
            with open(state_path) as f:
                state = json.load(f)
            
            # Load feedback records
            if 'feedback_records' in state:
                self.feedback_records = [
                    FeedbackRecord(**fr) for fr in state['feedback_records']
                ]
                # Rebuild cache
                self._feedback_cache = defaultdict(list)
                for fr in self.feedback_records:
                    self._feedback_cache[fr.rule_name].append(fr)
            
            # Load baselines
            if 'baselines' in state:
                self.baselines = {}
                for name, data in state['baselines'].items():
                    self.baselines[name] = RuleBaseline(**data)
            
            # Load temporal patterns
            if 'temporal_patterns' in state:
                self.temporal_patterns = {}
                for name, data in state['temporal_patterns'].items():
                    self.temporal_patterns[name] = TemporalPattern(**data)
            
            # Load thresholds
            if 'current_thresholds' in state:
                self.current_thresholds = state['current_thresholds']
            
            # Load tuning history
            if 'tuning_history' in state:
                self.tuning_history = state['tuning_history']
            
            logger.info(f"Loaded ML state: {len(self.feedback_records)} feedback records, "
                       f"{len(self.baselines)} baselines, {len(self.temporal_patterns)} temporal patterns")
            return True
        except Exception as e:
            logger.warning(f"Failed to load ML state: {e}")
            return False
    
    def save_state(self):
        """Save classifier state to JSON file."""
        import json
        os.makedirs('/app/agent_data', exist_ok=True)
        state_path = '/app/agent_data/ml_state.json'
        
        state = {
            'feedback_records': [
                {
                    'rule_name': fr.rule_name,
                    'timestamp': fr.timestamp,
                    'label': fr.label,
                    'reason': fr.reason,
                    'user_id': fr.user_id,
                }
                for fr in self.feedback_records
            ],
            'baselines': {
                name: {
                    'rule_name': b.rule_name,
                    'avg_port_diversity': b.avg_port_diversity,
                    'avg_dest_diversity': b.avg_dest_diversity,
                    'avg_volume': b.avg_volume,
                    'avg_block_ratio': b.avg_block_ratio,
                    'baseline_goodness': b.baseline_goodness,
                    'sample_count': b.sample_count,
                    'baseline_updated': b.baseline_updated,
                    'window_start': str(b.window_start) if b.window_start else None,
                    'window_end': str(b.window_end) if b.window_end else None,
                }
                for name, b in self.baselines.items()
            },
            'temporal_patterns': {
                name: {
                    'rule_name': p.rule_name,
                    'hour_distribution': p.hour_distribution,
                    'total_samples': p.total_samples,
                    'updated_at': str(p.updated_at) if p.updated_at else None,
                }
                for name, p in self.temporal_patterns.items()
            },
            'current_thresholds': self.current_thresholds,
            'tuning_history': self.tuning_history,
        }
        
        try:
            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            logger.info(f"Saved ML state to {state_path}")
        except Exception as e:
            logger.warning(f"Failed to save ML state: {e}")
    
    def ingest_events(self, events: List[Dict]):
        """Ingest events and compute features for all rules."""
        src_dst_ports = defaultdict(Counter)
        src_dst_ips = defaultdict(set)
        
        for event in events:
            self.total_events += 1
            
            rule_name = event.get('rule_name')
            action = event.get('action', '').upper()
            src_ip = event.get('src_ip', '')
            dst_ip = event.get('dst_ip', '')
            dport = event.get('dport')
            sport = event.get('sport')
            proto = (event.get('proto', '') or '').upper()
            timestamp = event.get('timestamp')
            
            if rule_name:
                self.events_with_rule += 1
                
                if rule_name not in self.features_map:
                    self.features_map[rule_name] = RuleFeatures(rule_name=rule_name)
                
                features = self.features_map[rule_name]
                features.total_events += 1
                
                if action == 'PASS':
                    features.pass_count += 1
                elif action == 'BLOCK':
                    features.block_count += 1
                
                features.protocols[proto] += 1
                features.src_ip_counts[src_ip] += 1
                features.dst_ip_counts[dst_ip] += 1
                
                if dport:
                    features.dst_port_distribution[dport] += 1
                    src_dst_ports[src_ip][dport] += 1
                if sport:
                    features.src_port_distribution[sport] += 1
                
                # Week 3: Temporal data
                if timestamp:
                    try:
                        ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        hour = ts.hour
                        features.hour_distribution[hour] += 1
                    except Exception:
                        pass
                
                src_dst_ips[src_ip].add(dst_ip)
            else:
                self.events_without_rule += 1
        
        # Compute derived features
        for rule_name, features in self.features_map.items():
            self._compute_features(features)
            self._update_baselines(rule_name, features)
            self._update_temporal_pattern(rule_name, features)
        
        logger.info(f"Ingested {len(events)} events, {len(self.features_map)} rules")
    
    def _compute_features(self, features: RuleFeatures):
        """Compute derived ML features for a rule."""
        if features.total_events < MIN_RULE_EVENTS:
            return
        
        # Port diversity
        features.unique_ports = len(features.dst_port_distribution)
        features.port_scan_score = min(1.0, features.unique_ports / HIGH_PORT_DIVERSITY)
        
        # Destination diversity
        features.unique_dst_ips = len(features.dst_ip_counts)
        features.dest_scan_score = min(1.0, features.unique_dst_ips / HIGH_DEST_DIVERSITY)
        
        # Action ratio
        if features.total_events > 0:
            block_ratio = features.block_count / features.total_events
            features.action_ratio_score = max(0, 1.0 - block_ratio * 3)  # 0-1, higher = good
        
        # Volume score
        features.volume_score = min(1.0, features.total_events / (LOW_VOLUME_THRESHOLD * 2))
        
        # Protocol score
        total_proto = sum(features.protocols.values())
        normal_count = sum(features.protocols.get(p, 0) for p in NORMAL_PROTOCOLS)
        features.protocol_score = normal_count / total_proto if total_proto > 0 else 0.0
        
        # Temporal anomaly (Week 3)
        features.temporal_anomaly_score = self._compute_temporal_anomaly(features)
        
        # Goodness score (weighted combination)
        weights = {
            'port_diversity': 0.20,
            'dest_diversity': 0.20,
            'action_ratio': 0.25,
            'volume_score': 0.15,
            'protocol_normalcy': 0.15,
            'temporal_anomaly': 0.05,  # Week 3 addition
        }
        
        goodness = (
            (1 - features.port_scan_score) * weights['port_diversity'] +
            (1 - features.dest_scan_score) * weights['dest_diversity'] +
            features.action_ratio_score * weights['action_ratio'] +
            features.volume_score * weights['volume_score'] +
            features.protocol_score * weights['protocol_normalcy'] +
            (1 - features.temporal_anomaly_score) * weights['temporal_anomaly']
        )
        features.goodness_score = goodness
        
        # Classification with user feedback adjustment (Week 1)
        classification = self._classify_with_feedback(features)
        features.classification = classification
        
        # Confidence calculation
        features.confidence = self._calculate_confidence(features)
    
    def _classify_with_feedback(self, features: RuleFeatures) -> str:
        """Classify rule incorporating user feedback (Week 1)."""
        base_goodness = features.goodness_score
        
        # Adjust goodness based on user agreement
        if features.user_feedback_count > 0:
            agreement = features.user_agreement_rate
            # If users consistently say it's wrong, reduce goodness
            features.goodness_score = base_goodness * (1.0 - agreement) + base_goodness * agreement
            goodness = features.goodness_score
        else:
            goodness = base_goodness
        
        # Classification thresholds (tunable in Week 5)
        if goodness < 0.3:
            return "ABUSIVE"
        elif goodness < 0.6:
            return "SUSPICIOUS"
        else:
            return "GOOD"
    
    def _calculate_confidence(self, features: RuleFeatures) -> float:
        """Calculate classification confidence with feedback and baselines."""
        # Base confidence from goodness
        base_conf = abs(features.goodness_score - 0.5) * 2  # 0-1
        
        # Week 1: Increase confidence with user feedback
        if features.user_feedback_count > 0:
            agreement_boost = features.user_agreement_rate * 0.3
            base_conf = min(1.0, base_conf + agreement_boost)
        
        # Week 2: Increase confidence if well-baselineed
        if features.baseline_updated:
            baseline_conf = 1.0 - abs(features.goodness_score - features.baseline_goodness)
            base_conf = min(1.0, base_conf * 0.7 + baseline_conf * 0.3)
        
        return base_conf
    
    def save_feedback(self, rule_name: str, label: str, reason: str = None, user_id: str = None):
        """
        Store user feedback for a rule classification (Week 1).
        
        Args:
            rule_name: Name of the firewall rule
            label: "correct" or "incorrect"
            reason: Optional explanation
            user_id: Optional user identifier
        """
        record = FeedbackRecord(
            rule_name=rule_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            label=label,
            reason=reason,
            user_id=user_id
        )
        self.feedback_records.append(record)
        self._feedback_cache[rule_name].append(record)
        
        # Update rule features with feedback
        if rule_name in self.features_map:
            features = self.features_map[rule_name]
            features.user_feedback_count += 1
            
            if label == "correct":
                features.user_correct_count += 1
            
            # Recalculate agreement rate
            features.user_agreement_rate = (
                features.user_correct_count / features.user_feedback_count
                if features.user_feedback_count > 0
                else 1.0
            )
            
            logger.info(f"Feedback saved for {rule_name}: {label} "
                       f"(agreement: {features.user_agreement_rate:.2f})")
    
    def _update_baselines(self, rule_name: str, features: RuleFeatures):
        """Update per-rule baseline statistics (Week 2)."""
        if rule_name not in self.baselines:
            self.baselines[rule_name] = RuleBaseline(rule_name=rule_name)
        
        baseline = self.baselines[rule_name]
        
        # Store recent feature snapshots for rolling average
        self._baseline_windows[rule_name].append({
            'port_diversity': features.unique_ports,
            'dest_diversity': features.unique_dst_ips,
            'volume': features.total_events,
            'block_ratio': (features.block_count / features.total_events
                          if features.total_events > 0 else 0),
            'goodness': features.goodness_score,
        })
        
        # Maintain rolling window of last 10 samples
        max_window = 10
        if len(self._baseline_windows[rule_name]) > max_window:
            self._baseline_windows[rule_name].popleft()
        
        # Update averages
        if self._baseline_windows[rule_name]:
            window = list(self._baseline_windows[rule_name])
            n = len(window)
            
            baseline.avg_port_diversity = sum(w['port_diversity'] for w in window) / n
            baseline.avg_dest_diversity = sum(w['dest_diversity'] for w in window) / n
            baseline.avg_volume = sum(w['volume'] for w in window) / n
            baseline.avg_block_ratio = sum(w['block_ratio'] for w in window) / n
            baseline.baseline_goodness = sum(w['goodness'] for w in window) / n
            baseline.sample_count = n
            baseline.baseline_updated = True
    
    def _update_temporal_pattern(self, rule_name: str, features: RuleFeatures):
        """Update temporal pattern for a rule (Week 3)."""
        if rule_name not in self.temporal_patterns:
            self.temporal_patterns[rule_name] = TemporalPattern(rule_name=rule_name)
        
        pattern = self.temporal_patterns[rule_name]
        
        # Merge hour distribution
        for hour, count in features.hour_distribution.items():
            if hour in pattern.hour_distribution:
                pattern.hour_distribution[hour] += count
            else:
                pattern.hour_distribution[hour] = 0
        
        pattern.total_samples += features.total_events
        pattern.updated_at = datetime.now(timezone.utc).isoformat()
    
    def _compute_temporal_anomaly(self, features: RuleFeatures) -> float:
        """
        Compute temporal anomaly score for a rule (Week 3).
        
        Returns 0-1 where higher = more anomalous timing pattern.
        """
        if not features.hour_distribution:
            return 0.0
        
        pattern = self.temporal_patterns.get(features.rule_name)
        if not pattern or pattern.total_samples < 100:
            return 0.0
        
        # Compare current distribution to learned pattern
        current_total = sum(features.hour_distribution.values())
        pattern_total = pattern.total_samples
        
        if current_total == 0 or pattern_total == 0:
            return 0.0
        
        # Calculate chi-squared statistic
        chi_sq = 0.0
        for hour in range(24):
            current_count = features.hour_distribution.get(hour, 0)
            expected_count = pattern.hour_distribution.get(hour, 0) * (current_total / pattern_total)
            
            if expected_count > 0:
                chi_sq += ((current_count - expected_count) ** 2) / expected_count
        
        # Convert chi-squared to anomaly score (higher = more anomalous)
        # Max chi-squared for 24 bins with equal distribution is ~24
        anomaly_score = min(1.0, chi_sq / 24)
        
        return anomaly_score
    
    def get_active_learning_queue(self) -> List[ActiveLearningItem]:
        """
        Get rules queued for active learning review (Week 4).
        
        Returns rules with confidence between ACTIVE_LEARNING_CONFIDENCE_LOW
        and ACTIVE_LEARNING_CONFIDENCE_HIGH.
        """
        self.active_queue = []
        
        for rule_name, features in self.features_map.items():
            # Only consider rules with sufficient events
            if features.total_events < MIN_RULE_EVENTS:
                continue
            
            # Only consider uncertain rules
            if not (ACTIVE_LEARNING_CONFIDENCE_LOW <= features.confidence <= ACTIVE_LEARNING_CONFIDENCE_HIGH):
                continue
            
            # Build reasons for uncertainty
            reasons = []
            if features.port_scan_score > 0.3 and features.action_ratio_score > 0.7:
                reasons.append("High port diversity but low block ratio (conflicting signals)")
            if features.dest_scan_score > 0.5 and features.total_events < LOW_VOLUME_THRESHOLD:
                reasons.append("High dest diversity with low volume")
            if features.temporal_anomaly_score > 0.5:
                reasons.append("Anomalous timing pattern")
            
            item = ActiveLearningItem(
                rule_name=rule_name,
                classification=features.classification,
                confidence=features.confidence,
                reasons=reasons
            )
            self.active_queue.append(item)
        
        # Sort by confidence (most uncertain first)
        self.active_queue.sort(key=lambda x: abs(x.confidence - 0.5))
        
        return self.active_queue
    
    def optimize_thresholds(self):
        """
        Optimize classification thresholds based on user feedback (Week 5).
        
        Adjusts thresholds to maximize user agreement rate.
        """
        if not self.feedback_records:
            logger.info("No feedback data available for threshold tuning")
            return
        
        # Calculate agreement rates by classification
        agreement_by_class = defaultdict(lambda: {'correct': 0, 'incorrect': 0})
        
        for record in self.feedback_records:
            if record.rule_name in self.features_map:
                classification = self.features_map[record.rule_name].classification
                if record.label == "correct":
                    agreement_by_class[classification]['correct'] += 1
                else:
                    agreement_by_class[classification]['incorrect'] += 1
        
        # Identify problematic classifications
        low_agreement = []
        for classification, counts in agreement_by_class.items():
            total = counts['correct'] + counts['incorrect']
            if total > 0:
                rate = counts['correct'] / total
                if rate < TUNING_MIN_AGREEMENT_RATE:
                    low_agreement.append((classification, rate, counts))
        
        if not low_agreement:
            logger.info("All classifications above minimum agreement rate")
            return
        
        # Adjust thresholds to address low agreement
        for classification, rate, counts in low_agreement:
            logger.info(f"Adjusting thresholds for {classification} "
                       f"(agreement: {rate:.2f})")
            
            if classification == "ABUSIVE":
                # Too many false positives - raise threshold
                self.current_thresholds['block_ratio'] *= (1 + TUNING_LEARNING_RATE)
            elif classification == "GOOD":
                # Too many false positives - raise threshold
                self.current_thresholds['low_volume'] *= (1 - TUNING_LEARNING_RATE)
            elif classification == "SUSPICIOUS":
                # Adjust to reduce uncertainty
                pass  # Special handling in next iteration
        
        # Record tuning action
        self.tuning_history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'low_agreement': [(c, r, counts) for c, r, counts in low_agreement],
            'new_thresholds': dict(self.current_thresholds),
        })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of classification state."""
        rules = list(self.features_map.values())
        
        by_class = defaultdict(list)
        for rule in rules:
            by_class[rule.classification].append(rule)
        
        # Calculate statistics
        total_feedback = sum(r.user_feedback_count for r in rules)
        correct_feedback = sum(r.user_correct_count for r in rules)
        overall_agreement = correct_feedback / total_feedback if total_feedback > 0 else 1.0
        
        return {
            'total_rules': len(rules),
            'total_events': self.total_events,
            'events_with_rule': self.events_with_rule,
            'events_without_rule': self.events_without_rule,
            'by_classification': {
                'GOOD': len(by_class.get('GOOD', [])),
                'ABUSIVE': len(by_class.get('ABUSIVE', [])),
                'SUSPICIOUS': len(by_class.get('SUSPICIOUS', [])),
            },
            'default_deny': {
                'events': self.events_without_rule,
                'percentage': (self.events_without_rule / self.total_events * 100
                             if self.total_events > 0 else 0),
            },
            'feedback_stats': {
                'total_records': total_feedback,
                'correct_count': correct_feedback,
                'agreement_rate': overall_agreement,
            },
            'active_learning_queue': len(self.active_queue),
            'temporal_patterns': len(self.temporal_patterns),
            'baselines_updated': sum(1 for b in self.baselines.values() if b.baseline_updated),
            'thresholds': dict(self.current_thresholds),
        }
    
    def get_rule_details(self, rule_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific rule."""
        if rule_name not in self.features_map:
            return {}
        
        features = self.features_map[rule_name]
        
        # Get temporal pattern
        temporal = self.temporal_patterns.get(rule_name)
        temporal_data = {}
        if temporal:
            total = sum(temporal.hour_distribution.values())
            if total > 0:
                temporal_data = {
                    hour: count / total * 100
                    for hour, count in temporal.hour_distribution.items()
                }
        
        # Get baseline info
        baseline = self.baselines.get(rule_name)
        baseline_data = {}
        if baseline and baseline.baseline_updated:
            baseline_data = {
                'avg_port_diversity': baseline.avg_port_diversity,
                'avg_dest_diversity': baseline.avg_dest_diversity,
                'avg_volume': baseline.avg_volume,
                'avg_block_ratio': baseline.avg_block_ratio,
                'sample_count': baseline.sample_count,
            }
        
        # Get feedback records
        feedback = self._feedback_cache.get(rule_name, [])
        feedback_data = [
            {'timestamp': f.timestamp, 'label': f.label, 'reason': f.reason}
            for f in feedback[-10:]  # Last 10 records
        ]
        
        # Get active learning item if in queue
        active_item = None
        for item in self.active_queue:
            if item.rule_name == rule_name:
                active_item = {
                    'in_queue': True,
                    'confidence': item.confidence,
                    'reasons': item.reasons,
                }
                break
        
        return {
            'rule_name': rule_name,
            'classification': features.classification,
            'confidence': features.confidence,
            'goodness_score': features.goodness_score,
            'total_events': features.total_events,
            'pass_count': features.pass_count,
            'block_count': features.block_count,
            'unique_ports': features.unique_ports,
            'unique_dst_ips': features.unique_dst_ips,
            'port_scan_score': features.port_scan_score,
            'dest_scan_score': features.dest_scan_score,
            'action_ratio_score': features.action_ratio_score,
            'temporal_anomaly_score': features.temporal_anomaly_score,
            'user_feedback': {
                'count': features.user_feedback_count,
                'correct_count': features.user_correct_count,
                'agreement_rate': features.user_agreement_rate,
                'records': feedback_data,
            },
            'baseline': baseline_data,
            'temporal': temporal_data,
            'active_learning': active_item,
        }
