#!/usr/bin/env python3
"""
Rule-based anomaly learning for OPNsense firewall.

Classifies traffic as:
- KNOWN_PERMITTED: Traffic matching a firewall rule that allows it (action=PASS with a named rule)
- KNOWN_DENIED: Traffic matching a firewall rule that blocks it (action=BLOCK)
- UNKNOWN_PERMITTED: Traffic with no rule but action=PASS
- UNKNOWN_DENIED: Traffic with no rule but action=BLOCK
- UNCLASSIFIED: No rule_name available

ML Learning Approach:
1. Collect (rule_name, action, src_ip, dst_ip, dst_port) pairs from filterlog
2. Build a "known_rules" database: for each rule_name, track the actions it allows
3. If a rule_name has mostly PASS -> it's a permitted rule
4. If a rule_name has mostly BLOCK -> it's a deny rule
5. Traffic with no rule_name but normal patterns -> likely from default rules
6. Anomaly detection focuses on:
   - NEW rule_names appearing (potential unauthorized rules)
   - Rule_name -> action mismatches (rule allows but traffic is suspicious)
   - Traffic with no rule_name (should be caught by default deny)

P2-2: Feedback loop — reads rule_feedback from DB, adjusts confidence.
P2-4: Active learning queue — queues UNCERTAIN rules for human review.
"""

import os
import json
import math
import logging
import pickle
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix,
)
from sklearn.model_selection import cross_val_score
import joblib

logger = logging.getLogger(__name__)

# Default classification thresholds
MIN_RULE_EVENTS = 10
DEFAULT_DENY_THRESHOLD = 0.7

# ML-specific constants
ML_MIN_SAMPLES = 20                    # min samples to train
ML_RETRAIN_THRESHOLD = 50              # new samples since last train
ML_PREDICT_CONFIDENCE_THRESHOLD = 0.55 # min confidence to trust ML
ML_FEATURE_NAMES = [
    "total_events", "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
    "src_ip_entropy", "dst_ip_entropy", "dst_port_entropy",
    "pass_ratio", "block_ratio", "action_diversity",
    "hour_of_day_mean", "hour_of_day_std", "hour_span",
    "port_diversity_log", "ip_ratio", "avg_events_per_hour",
    "rule_age_hours", "feedback_ratio",
]
ML_LABEL_NAMES = ["PERMIT", "DENY", "MIXED"]


@dataclass
class RuleProfile:
    """Profile of a firewall rule's behavior."""
    rule_name: str
    actions: Counter = field(default_factory=Counter)
    src_ips: Set = field(default_factory=set)
    dst_ips: Set = field(default_factory=set)
    dst_ports: Set = field(default_factory=set)
    total_events: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    # P2-2: Confidence scoring (0.0-1.0, starts at None = not scored)
    confidence: Optional[float] = None
    feedback_correct: int = 0
    feedback_incorrect: int = 0
    
    @property
    def is_permit_rule(self) -> Optional[bool]:
        """If mostly PASS actions -> permitted rule."""
        if self.total_events < MIN_RULE_EVENTS:
            return None
        pass_ratio = self.actions.get('PASS', 0) / self.total_events
        return pass_ratio > (1.0 - DEFAULT_DENY_THRESHOLD)
    
    @property
    def is_deny_rule(self) -> Optional[bool]:
        """If mostly BLOCK actions -> deny rule."""
        if self.total_events < MIN_RULE_EVENTS:
            return None
        block_ratio = self.actions.get('BLOCK', 0) / self.total_events
        return block_ratio > DEFAULT_DENY_THRESHOLD
    
    @property
    def classification(self) -> str:
        """Classify the rule as PERMIT, DENY, MIXED, or UNCERTAIN."""
        if self.total_events < MIN_RULE_EVENTS:
            return "UNCERTAIN"
        if self.is_permit_rule:
            return "PERMIT"
        if self.is_deny_rule:
            return "DENY"
        return "MIXED"
    
    def calculate_confidence(self) -> float:
        """Calculate confidence score (0.0-1.0) based on event count and feedback."""
        if self.total_events < MIN_RULE_EVENTS:
            return 0.0
        
        # Base confidence from event count (more events = higher base confidence)
        base_confidence = min(1.0, self.total_events / (MIN_RULE_EVENTS * 5))
        
        # Adjust based on action clarity
        pass_ratio = self.actions.get('PASS', 0) / self.total_events if self.total_events > 0 else 0.5
        block_ratio = self.actions.get('BLOCK', 0) / self.total_events if self.total_events > 0 else 0.5
        action_clarity = max(pass_ratio, block_ratio)  # 1.0 = all same action
        
        confidence = base_confidence * action_clarity
        
        # P2-2: Apply feedback adjustments
        total_feedback = self.feedback_correct + self.feedback_incorrect
        if total_feedback > 0:
            # Each incorrect label reduces confidence
            incorrect_penalty = self.feedback_incorrect * 0.15  # 15% per incorrect
            correct_bonus = min(0.1, self.feedback_correct * 0.05)  # up to 10% bonus
            confidence = max(0.0, min(1.0, confidence - incorrect_penalty + correct_bonus))
        
        return round(confidence, 3)


class FeatureExtractor:
    """Extract ML feature vectors from RuleProfile objects.

    Features (18 total):
    - Volume: total_events, unique IPs/ports counts
    - Entropy: src_ip_entropy, dst_ip_entropy, dst_port_entropy
    - Action profile: pass_ratio, block_ratio, action_diversity
    - Temporal: hour_of_day_mean/std/span
    - Diversity: port_diversity_log, ip_ratio, avg_events_per_hour
    - Meta: rule_age_hours, feedback_ratio
    """

    @staticmethod
    def extract(profile: RuleProfile) -> np.ndarray:
        """Extract a single feature vector from a RuleProfile."""
        feats = {}

        # Volume features
        feats["total_events"] = float(profile.total_events)
        feats["unique_src_ips"] = float(len(profile.src_ips))
        feats["unique_dst_ips"] = float(len(profile.dst_ips))
        feats["unique_dst_ports"] = float(len(profile.dst_ports))

        # Entropy features (Shannon entropy of distribution)
        feats["src_ip_entropy"] = _shannon_entropy(len(profile.src_ips))
        feats["dst_ip_entropy"] = _shannon_entropy(len(profile.dst_ips))
        feats["dst_port_entropy"] = _shannon_entropy(len(profile.dst_ports))

        # Action profile
        total = max(profile.total_events, 1)
        pass_count = profile.actions.get("PASS", 0)
        block_count = profile.actions.get("BLOCK", 0)
        feats["pass_ratio"] = pass_count / total
        feats["block_ratio"] = block_count / total
        # Action diversity: entropy over action categories
        action_counts = list(profile.actions.values())
        feats["action_diversity"] = _distribution_entropy(action_counts)

        # Temporal features
        if profile.first_seen and profile.last_seen:
            span = (profile.last_seen - profile.first_seen).total_seconds() / 3600.0
            feats["hour_span"] = float(min(span, 9999))  # cap runaway values
            feats["rule_age_hours"] = feats["hour_span"]
            # Approximate mean hour from first/last seen
            mean_hour = (profile.first_seen.hour + profile.last_seen.hour) / 2.0
            feats["hour_of_day_mean"] = float(mean_hour)
            feats["hour_of_day_std"] = float(abs(profile.last_seen.hour - profile.first_seen.hour) / 2.0)
        else:
            feats["hour_span"] = 0.0
            feats["rule_age_hours"] = 0.0
            feats["hour_of_day_mean"] = 12.0
            feats["hour_of_day_std"] = 0.0

        # Diversity ratios
        port_div = max(len(profile.dst_ports), 1)
        feats["port_diversity_log"] = float(math.log1p(port_div))
        src_ratio = len(profile.src_ips) / max(len(profile.dst_ips), 1)
        feats["ip_ratio"] = float(min(src_ratio, 100))  # cap extreme ratios
        age = max(feats["rule_age_hours"], 1.0)
        feats["avg_events_per_hour"] = float(profile.total_events / age)

        # Feedback signal
        total_fb = profile.feedback_correct + profile.feedback_incorrect
        feats["feedback_ratio"] = float(profile.feedback_correct / max(total_fb, 1))

        return np.array([feats[f] for f in ML_FEATURE_NAMES], dtype=np.float64)

    @staticmethod
    def extract_batch(profiles: Dict[str, RuleProfile]) -> Tuple[np.ndarray, List[str]]:
        """Extract feature matrix from multiple profiles.

        Returns (X, rule_names) where X is (n_rules, n_features).
        Only includes profiles with total_events >= MIN_RULE_EVENTS.
        """
        X = []
        names = []
        for name, profile in profiles.items():
            if profile.total_events >= MIN_RULE_EVENTS:
                X.append(FeatureExtractor.extract(profile))
                names.append(name)

        if not X:
            return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64), []

        return np.array(X), names


def _shannon_entropy(count: int) -> float:
    """Approximate Shannon entropy for a uniform distribution of `count` categories."""
    if count <= 1:
        return 0.0
    return float(math.log2(count))


def _distribution_entropy(counts: List[int]) -> float:
    """Shannon entropy of a categorical distribution given raw counts."""
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


class MLRuleClassifier:
    """scikit-learn based ML classifier for firewall rules.

    Uses GradientBoosting to classify rules as PERMIT, DENY, or MIXED
    based on features extracted from RuleProfile objects.

    Persists trained model to disk via joblib. Provides graceful fallback
    to heuristic classification when the model is not yet trained or
    confidence is too low.
    """

    def __init__(self):
        self.model: Optional[GradientBoostingClassifier] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.model_path = os.path.join(
            os.environ.get("AGENT_DATA_DIR", "/app/agent_data"),
            "rule_classifier_model.pkl",
        )
        self.samples_since_retrain = 0
        self.metrics: Dict[str, Any] = {}
        self.feature_importances: Dict[str, float] = {}
        self._load_model()

    def _load_model(self):
        """Load a persisted model from disk if available."""
        if not os.path.exists(self.model_path):
            logger.info("No persisted ML model found at %s", self.model_path)
            return

        try:
            data = joblib.load(self.model_path)
            self.model = data["model"]
            self.label_encoder = data["label_encoder"]
            self.metrics = data.get("metrics", {})
            self.feature_importances = data.get("feature_importances", {})
            logger.info(
                "ML model loaded from %s (accuracy=%.3f, trained on %d samples)",
                self.model_path,
                self.metrics.get("accuracy", 0),
                self.metrics.get("train_samples", 0),
            )
        except Exception as e:
            logger.error("Failed to load ML model: %s", e)
            self.model = None
            self.label_encoder = None

    def _save_model(self):
        """Persist the current model to disk."""
        if self.model is None:
            return

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        data = {
            "model": self.model,
            "label_encoder": self.label_encoder,
            "metrics": self.metrics,
            "feature_importances": self.feature_importances,
            "feature_names": ML_FEATURE_NAMES,
            "label_names": ML_LABEL_NAMES,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        joblib.dump(data, self.model_path)
        logger.info(
            "ML model saved to %s (train_samples=%d, accuracy=%.3f)",
            self.model_path,
            self.metrics.get("train_samples", 0),
            self.metrics.get("accuracy", 0),
        )

    def _heuristic_label(self, profile: RuleProfile) -> str:
        """Fallback heuristic label for training data generation."""
        return profile.classification  # PERMIT / DENY / MIXED / UNCERTAIN

    def train(self, profiles: Dict[str, RuleProfile]) -> Dict[str, Any]:
        """Train (or retrain) the ML model from rule profiles.

        Args:
            profiles: All rule profiles with sufficient data.

        Returns:
            Dict with training metrics (accuracy, precision, recall, etc.).
        """
        X, rule_names = FeatureExtractor.extract_batch(profiles)

        if len(X) < ML_MIN_SAMPLES:
            logger.warning(
                "Not enough data to train ML model (%d samples, need %d)",
                len(X), ML_MIN_SAMPLES,
            )
            self.metrics = {"error": "insufficient_data", "samples": len(X)}
            return self.metrics

        # Generate labels from heuristic classification (bootstrap training)
        raw_labels = []
        valid_X = []
        valid_names = []
        for i, (features, name) in enumerate(zip(X, rule_names)):
            profile = profiles[name]
            label = self._heuristic_label(profile)
            if label in ("PERMIT", "DENY", "MIXED"):  # skip UNCERTAIN
                valid_X.append(features)
                raw_labels.append(label)
                valid_names.append(name)

        if len(valid_X) < ML_MIN_SAMPLES:
            logger.warning(
                "Not enough labelled data after filtering (%d samples, need %d)",
                len(valid_X), ML_MIN_SAMPLES,
            )
            self.metrics = {"error": "insufficient_labeled_data", "samples": len(valid_X)}
            return self.metrics

        X_train = np.array(valid_X)
        y_labels = raw_labels

        # Encode labels
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(ML_LABEL_NAMES)  # fixed order: DENY, MIXED, PERMIT
        y_train = self.label_encoder.transform(y_labels)

        # Train GradientBoosting classifier
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            random_state=42,
            min_samples_split=3,
            min_samples_leaf=2,
        )
        self.model.fit(X_train, y_train)

        # Cross-validation for honest metrics
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=min(3, len(valid_X)), scoring="accuracy")
        train_preds = self.model.predict(X_train)

        self.metrics = {
            "accuracy": round(float(accuracy_score(y_train, train_preds)), 4),
            "cv_accuracy_mean": round(float(cv_scores.mean()), 4),
            "cv_accuracy_std": round(float(cv_scores.std()), 4),
            "precision_macro": round(float(precision_score(y_train, train_preds, average="macro", zero_division=0)), 4),
            "recall_macro": round(float(recall_score(y_train, train_preds, average="macro", zero_division=0)), 4),
            "f1_macro": round(float(f1_score(y_train, train_preds, average="macro", zero_division=0)), 4),
            "train_samples": len(X_train),
            "n_rules_classified": len(valid_names),
            "class_distribution": dict(Counter(y_labels)),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }

        # Feature importances
        importances = self.model.feature_importances_
        self.feature_importances = {
            ML_FEATURE_NAMES[i]: round(float(imp), 4)
            for i, imp in enumerate(importances)
            if imp > 0.001
        }

        self.samples_since_retrain = 0

        logger.info(
            "ML model trained: accuracy=%.3f (±%.3f CV), samples=%d, top_features=%s",
            self.metrics["cv_accuracy_mean"],
            self.metrics["cv_accuracy_std"],
            self.metrics["train_samples"],
            list(self.feature_importances.keys())[:3],
        )

        self._save_model()
        return self.metrics

    def predict(self, profile: RuleProfile) -> Tuple[str, float]:
        """Predict classification for a single rule profile.

        Returns (label, confidence) where label is PERMIT/DENY/MIXED
        and confidence is the predicted probability for that class.

        If no model is trained or confidence is below threshold,
        falls back to heuristic classification.
        """
        if self.model is None or self.label_encoder is None:
            return self._fallback_predict(profile)

        try:
            features = FeatureExtractor.extract(profile)
            proba = self.model.predict_proba(features.reshape(1, -1))[0]
            pred_idx = np.argmax(proba)
            label = self.label_encoder.classes_[pred_idx]
            confidence = float(proba[pred_idx])

            if confidence < ML_PREDICT_CONFIDENCE_THRESHOLD:
                logger.debug(
                    "ML confidence %.3f below threshold for rule %s, using fallback",
                    confidence, profile.rule_name,
                )
                return self._fallback_predict(profile)

            return label, confidence

        except Exception as e:
            logger.warning("ML prediction failed for %s: %s", profile.rule_name, e)
            return self._fallback_predict(profile)

    def _fallback_predict(self, profile: RuleProfile) -> Tuple[str, float]:
        """Fall back to heuristic classification."""
        label = profile.classification
        if label == "UNCERTAIN":
            return "UNCERTAIN", 0.0

        confidence = profile.calculate_confidence()
        return label, confidence

    def should_retrain(self) -> bool:
        """Check if the model should be retrained based on new data."""
        return self.samples_since_retrain >= ML_RETRAIN_THRESHOLD

    def increment_samples(self, count: int = 1):
        """Track new samples since last retrain."""
        self.samples_since_retrain += count

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata and metrics for API exposure."""
        return {
            "model_trained": self.model is not None,
            "model_type": "GradientBoosting",
            "metrics": self.metrics,
            "feature_importances": self.feature_importances,
            "samples_since_retrain": self.samples_since_retrain,
            "feature_names": ML_FEATURE_NAMES,
            "label_names": ML_LABEL_NAMES,
        }


class RuleClassifier:
    
    def __init__(self, min_events=MIN_RULE_EVENTS, deny_threshold=DEFAULT_DENY_THRESHOLD):
        self.min_events = min_events
        self.deny_threshold = deny_threshold
        self.rule_profiles: Dict[str, RuleProfile] = {}
        self.total_events = 0
        self.events_with_rule = 0
        self.events_without_rule = 0
        self.traffic_baselines: Counter = Counter()

        # ML classifier
        self.ml_classifier = MLRuleClassifier()

        logger.info("RuleClassifier initialized (min_events=%d, deny_threshold=%.2f, ml=%s)",
                    min_events, deny_threshold, "trained" if self.ml_classifier.model is not None else "untrained")
    
    def process_event(self, event: Dict[str, Any], timestamp: Optional[datetime] = None):
        """Process a single event and update rule profiles."""
        self.total_events += 1
        
        rule_name = event.get('rule_name')
        action = event.get('action', '').upper()
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dport')
        
        if rule_name:
            self.events_with_rule += 1
            self._update_rule_profile(rule_name, action, src_ip, dst_ip, dst_port, timestamp)
            # Track samples for ML retraining
            self.ml_classifier.increment_samples()
        else:
            self.events_without_rule += 1
            self._update_traffic_baseline(action, src_ip, dst_ip, dst_port)

    def process_events(self, events: List[Dict[str, Any]]):
        """Process a batch of events and update rule profiles."""
        for event in events:
            self.process_event(event)

    def _update_rule_profile(self, rule_name: str, action: str,
                             src_ip: Optional[str], dst_ip: Optional[str],
                             dst_port: Optional[int], timestamp: Optional[datetime]):
        """Update the profile for a specific rule."""
        if rule_name not in self.rule_profiles:
            self.rule_profiles[rule_name] = RuleProfile(rule_name=rule_name)
        
        profile = self.rule_profiles[rule_name]
        profile.total_events += 1
        profile.actions[action] += 1
        
        if src_ip:
            profile.src_ips.add(src_ip)
        if dst_ip:
            profile.dst_ips.add(dst_ip)
        if dst_port:
            profile.dst_ports.add(dst_port)
        
        if timestamp:
            if profile.first_seen is None or timestamp < profile.first_seen:
                profile.first_seen = timestamp
            if profile.last_seen is None or timestamp > profile.last_seen:
                profile.last_seen = timestamp
    
    def _update_traffic_baseline(self, action: str, src_ip: Optional[str],
                                  dst_ip: Optional[str], dst_port: Optional[int]):
        """Update traffic baseline for events without rule_name."""
        key = (action, str(src_ip), str(dst_ip), str(dst_port))
        self.traffic_baselines[key] += 1
    
    def get_rule_classification(self, rule_name: str) -> str:
        """Get the classification of a specific rule."""
        if rule_name not in self.rule_profiles:
            return "UNKNOWN"
        return self.rule_profiles[rule_name].classification
    
    def get_all_known_rules(self) -> List[Dict[str, Any]]:
        """Return all known rules with their classifications."""
        rules = []
        for name, profile in self.rule_profiles.items():
            rules.append({
                'rule_name': name,
                'classification': profile.classification,
                'total_events': profile.total_events,
                'actions': dict(profile.actions),
                'unique_src_ips': len(profile.src_ips),
                'unique_dst_ips': len(profile.dst_ips),
                'unique_dst_ports': len(profile.dst_ports),
                'first_seen': profile.first_seen.isoformat() if profile.first_seen else None,
                'last_seen': profile.last_seen.isoformat() if profile.last_seen else None,
            })
        rules.sort(key=lambda x: -x['total_events'])
        return rules
    
    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get a summary of traffic patterns."""
        return {
            'total_events': self.total_events,
            'events_with_rule': self.events_with_rule,
            'events_without_rule': self.events_without_rule,
            'known_rules_count': len(self.rule_profiles),
            'rules_by_classification': dict(Counter(
                p.classification for p in self.rule_profiles.values()
            )),
            'top_rules': [
                {'name': name, 'events': profile.total_events, 'classification': profile.classification}
                for name, profile in sorted(self.rule_profiles.items(),
                                           key=lambda x: -x[1].total_events)[:10]
            ],
        }
    
    def detect_anomalies(self, current_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Detect anomalies in rule usage patterns."""
        anomalies = []
        
        for name, profile in self.rule_profiles.items():
            # New rules appearing
            if profile.total_events < 5 and profile.total_events > 0:
                anomalies.append({
                    'type': 'NEW_RULE',
                    'severity': 'MEDIUM',
                    'rule_name': name,
                    'description': f"New rule '{name}' detected with only {profile.total_events} events",
                    'events': profile.total_events,
                    'actions': dict(profile.actions),
                })
            
            # Mixed action rules
            if profile.total_events >= self.min_events:
                if 'PASS' in profile.actions and 'BLOCK' in profile.actions:
                    pass_ratio = profile.actions['PASS'] / profile.total_events
                    if 0.2 < pass_ratio < 0.8:
                        anomalies.append({
                            'type': 'MIXED_RULE',
                            'severity': 'LOW',
                            'rule_name': name,
                            'description': f"Rule '{name}' has mixed actions: PASS={profile.actions['PASS']}, BLOCK={profile.actions['BLOCK']}",
                            'pass_ratio': round(pass_ratio, 2),
                        })
        
        # Traffic without rule_name
        if self.events_without_rule > 0 and self.total_events > 100:
            without_rule_ratio = self.events_without_rule / self.total_events
            if without_rule_ratio > 0.1:
                anomalies.append({
                    'type': 'NO_RULE_TRAFFIC',
                    'severity': 'HIGH',
                    'description': f"{self.events_without_rule} events ({without_rule_ratio:.1%}) have no rule_name",
                    'events_without_rule': self.events_without_rule,
                    'total_events': self.total_events,
                    'ratio': round(without_rule_ratio, 3),
                })
        
        return anomalies

    # ─── ML Integration ────────────────────────────────────────────────

    def get_ml_classification(self, rule_name: str) -> Dict[str, Any]:
        """Get ML-based classification with confidence for a rule.

        Uses the ML model if trained, falls back to heuristic.

        Returns:
            Dict with 'label', 'confidence', 'source' (ML or heuristic).
        """
        if rule_name not in self.rule_profiles:
            return {"label": "UNKNOWN", "confidence": 0.0, "source": "not_found"}

        profile = self.rule_profiles[rule_name]
        label, confidence = self.ml_classifier.predict(profile)

        source = "ML" if self.ml_classifier.model is not None else "heuristic"
        # Check if ML actually made the prediction or fell back
        if self.ml_classifier.model is not None:
            try:
                features = FeatureExtractor.extract(profile)
                proba = self.ml_classifier.model.predict_proba(features.reshape(1, -1))[0]
                max_proba = float(np.max(proba))
                if max_proba >= ML_PREDICT_CONFIDENCE_THRESHOLD:
                    source = "ML"
                else:
                    source = "ML_fallback"
            except Exception:
                source = "ML_error_fallback"

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "source": source,
            "rule_name": rule_name,
        }

    def get_all_classifications(self) -> List[Dict[str, Any]]:
        """Get ML/heuristic classifications for all known rules."""
        results = []
        for name in self.rule_profiles:
            cls = self.get_ml_classification(name)
            results.append(cls)
        results.sort(key=lambda x: -x["confidence"])
        return results

    def train_ml_model(self) -> Dict[str, Any]:
        """Train or retrain the ML model from current rule profiles.

        Can be called manually or triggered automatically when
        enough new samples have accumulated (see should_retrain).

        Returns:
            Dict with training metrics.
        """
        logger.info("Training ML model with %d rule profiles...", len(self.rule_profiles))
        metrics = self.ml_classifier.train(self.rule_profiles)

        if "error" in metrics:
            logger.warning("ML training did not complete: %s", metrics["error"])
        else:
            logger.info(
                "ML training complete: accuracy=%.3f, cv=%.3f (±%.3f), samples=%d",
                metrics["accuracy"],
                metrics["cv_accuracy_mean"],
                metrics["cv_accuracy_std"],
                metrics["train_samples"],
            )

        return metrics

    def should_retrain_ml(self) -> bool:
        """Check if the ML model should be retrained."""
        return self.ml_classifier.should_retrain()

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata and metrics for API/dashboard exposure."""
        info = self.ml_classifier.get_model_info()
        info["heuristic_rules_count"] = len(self.rule_profiles)
        info["total_events_processed"] = self.total_events
        info["should_retrain"] = self.should_retrain_ml()
        return info

    def get_model_metrics(self) -> Dict[str, Any]:
        """Return just the evaluation metrics (for Prometheus endpoint)."""
        metrics = self.ml_classifier.metrics.copy()
        metrics["model_trained"] = self.ml_classifier.model is not None
        metrics["samples_since_retrain"] = self.ml_classifier.samples_since_retrain
        return metrics

    # ─── State Persistence ──────────────────────────────────────────────

    def save_state(self, filepath: str = None):
        """Save rule profiles to disk."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "rule_classifier_state.json")
        
        state = {
            'rules': {name: {
                'rule_name': p.rule_name,
                'actions': dict(p.actions),
                'total_events': p.total_events,
                'first_seen': p.first_seen.isoformat() if p.first_seen else None,
                'last_seen': p.last_seen.isoformat() if p.last_seen else None,
            } for name, p in self.rule_profiles.items()},
            'summary': self.get_traffic_summary(),
            'traffic_baselines': {str(k): v for k, v in list(self.traffic_baselines.items())[:1000]},
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        logger.info("Rule classifier state saved to %s", filepath)
    
    def load_state(self, filepath: str = None):
        """Load rule profiles from disk."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "rule_classifier_state.json")
        
        if not os.path.exists(filepath):
            logger.info("No rule classifier state file found at %s", filepath)
            return
        
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            for name, data in state.get('rules', {}).items():
                profile = RuleProfile(
                    rule_name=name,
                    total_events=data.get('total_events', 0),
                )
                profile.actions = Counter(data.get('actions', {}))
                profile.first_seen = datetime.fromisoformat(data['first_seen']) if data.get('first_seen') else None
                profile.last_seen = datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None
                self.rule_profiles[name] = profile
            
            for key_str, count in state.get('traffic_baselines', {}).items():
                try:
                    key = json.loads(key_str)
                    self.traffic_baselines[tuple(key)] = count
                except:
                    pass
            
            logger.info("Rule classifier state loaded from %s (%d rules)", filepath, len(self.rule_profiles))
        except Exception as e:
            logger.error("Failed to load rule classifier state: %s", e)
    
    # ─── P2-2: Feedback Loop ───────────────────────────────────────────
    
    def apply_feedback(self, db=None):
        """Read rule_feedback from the DB and adjust rule profiles.
        
        For each rule with feedback:
        - 'correct' feedback increases confidence
        - 'incorrect' feedback decreases confidence
        - Multiple 'incorrect' labels can flip the classification to UNCERTAIN
        
        Args:
            db: Optional EventDatabase instance. If not provided, feedback
                adjustments are skipped (no DB connection).
        """
        if not db:
            logger.debug("No DB connection for feedback loop, skipping")
            return
        
        from eventdb import EventDatabase
        if not isinstance(db, EventDatabase):
            logger.warning("Invalid DB type for feedback loop")
            return
        
        adjusted = 0
        for rule_name, profile in self.rule_profiles.items():
            try:
                stats = db.get_feedback_stats(rule_name)
                correct = stats.get('correct_count', 0)
                incorrect = stats.get('incorrect_count', 0)
                total = stats.get('total_records', 0)
                
                if total == 0:
                    continue
                
                # Apply feedback to confidence
                profile.feedback_correct = correct
                profile.feedback_incorrect = incorrect
                
                # Calculate confidence based on feedback
                agreement_rate = correct / total if total > 0 else 1.0
                
                # Start with base confidence from classification
                if profile.total_events >= MIN_RULE_EVENTS:
                    base_confidence = 0.7 if profile.classification in ("PERMIT", "DENY") else 0.4
                else:
                    base_confidence = 0.3
                
                # Adjust confidence based on feedback
                feedback_factor = agreement_rate * min(total, 10) / 10.0
                profile.confidence = min(1.0, max(0.0, base_confidence * feedback_factor))
                
                # If many incorrect labels, downgrade to UNCERTAIN
                if incorrect >= 3 and total >= 5:
                    profile.confidence = max(0.1, profile.confidence - 0.3)
                    logger.info("Rule '%s' downgraded due to %d incorrect feedbacks", rule_name, incorrect)
                
                adjusted += 1
            except Exception as e:
                logger.warning("Feedback processing failed for rule %s: %s", rule_name, e)
        
        if adjusted > 0:
            logger.info("Feedback loop applied to %d rules", adjusted)
    
    # ─── P2-4: Active Learning Queue ───────────────────────────────────
    
    def queue_uncertain_rules(self, db=None):
        """Queue rules with UNCERTAIN classification for human review.
        
        Args:
            db: EventDatabase instance for queue storage.
        """
        if not db:
            logger.debug("No DB connection for active learning queue, skipping")
            return
        
        from eventdb import EventDatabase
        if not isinstance(db, EventDatabase):
            logger.warning("Invalid DB type for active learning queue")
            return
        
        queued = 0
        for rule_name, profile in self.rule_profiles.items():
            classification = profile.classification
            confidence = profile.confidence if profile.confidence is not None else 0.0
            
            # Queue rules that are UNCERTAIN or have low confidence
            should_queue = False
            reasons = []
            
            if classification == "UNCERTAIN":
                should_queue = True
                reasons.append(f"Insufficient data: {profile.total_events} events (need {MIN_RULE_EVENTS})")
            
            elif classification == "MIXED":
                should_queue = True
                reasons.append(f"Mixed actions: PASS={profile.actions.get('PASS', 0)}, BLOCK={profile.actions.get('BLOCK', 0)}")
            
            if confidence is not None and confidence < 0.3:
                should_queue = True
                reasons.append(f"Low confidence: {confidence:.2f}")
            
            if profile.feedback_incorrect >= 2:
                should_queue = True
                reasons.append(f"User flagged as incorrect {profile.feedback_incorrect} times")
            
            if should_queue:
                try:
                    db.queue_for_review(
                        rule_name=rule_name,
                        classification=classification,
                        confidence=confidence,
                        reasons="; ".join(reasons),
                    )
                    queued += 1
                except Exception as e:
                    logger.warning("Failed to queue rule %s for review: %s", rule_name, e)
        
        if queued > 0:
            logger.info("Queued %d rules for active learning review", queued)
