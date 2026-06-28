#!/usr/bin/env python3
"""
Flow-based behavioral classifier for OPNsense firewall.

Classifies traffic flows based on behavioral features rather than static
rule properties. Uses GradientBoosting with 30+ features extracted from
event data to classify flows as:

- BENIGN (0): Normal, expected traffic
- SUSPICIOUS (1): Unusual but not necessarily malicious
- RECONNAISSANCE (2): Scanning, probing, information gathering
- ATTACK (3): Active attack attempts (DoS, brute force, etc.)
- EXPLOIT (4): Exploitation attempts targeting specific vulnerabilities

Feature categories:
- Source IP features: threat_level, behavior_score, country, frequency
- Destination features: is_open_port, is_nat, service_type
- Flow features: packet_count, byte_count, duration, flag_pattern
- Temporal features: hour_of_day, is_business_hours
- Contextual features: simultaneous_blocked_connections, scan_activity

Active learning: low-confidence flows are queued for human review.
"""

import os
import json
import math
import logging
import pickle
import hashlib
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix,
)
from sklearn.model_selection import cross_val_score
import joblib

logger = logging.getLogger(__name__)

# ── Label definitions ────────────────────────────────────────────────
FLOW_LABELS = {
    "BENIGN": 0,
    "SUSPICIOUS": 1,
    "RECONNAISSANCE": 2,
    "ATTACK": 3,
    "EXPLOIT": 4,
}
FLOW_LABEL_NAMES = ["BENIGN", "SUSPICIOUS", "RECONNAISSANCE", "ATTACK", "EXPLOIT"]
FLOW_LABEL_BY_CODE = {v: k for k, v in FLOW_LABELS.items()}

# ── ML constants ─────────────────────────────────────────────────────
ML_MIN_SAMPLES = 30                   # min samples to train
ML_RETRAIN_THRESHOLD = 100            # new samples since last train
ML_PREDICT_CONFIDENCE_THRESHOLD = 0.45  # min confidence to trust ML (lower than rule classifier due to more classes)
ML_FEATURE_COUNT = 36  # number of features


# ── Well-known service ports for classification ──────────────────────
WELL_KNOWN_SERVICES = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    443: "https", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 8080: "http-alt",
    8443: "https-alt", 1433: "mssql", 6379: "redis", 27017: "mongodb",
}

# Ports commonly targeted in exploits
EXPLOIT_TARGET_PORTS = {23, 445, 1433, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 27017}

# TCP flag patterns
TCP_FLAG_SYN_ONLY = "SA"  # SYN without ACK — typical scan indicator
TCP_FLAG_RST = "RA"       # RST — connection rejection


@dataclass
class FlowProfile:
    """Profile of a single traffic flow (src_ip → dst_ip:dst_port)."""
    flow_key: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    action: str
    total_events: int = 0
    packet_count: int = 0
    byte_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tcp_flags: List[str] = field(default_factory=list)
    interfaces: Set[str] = field(default_factory=set)
    src_ports: Set[int] = field(default_factory=set)
    blocked_count: int = 0
    passed_count: int = 0


# ── Feature names (ordered) ─────────────────────────────────────────
FLOW_FEATURE_NAMES = [
    # Source IP features (1-6)
    "src_event_frequency",          # 1: events from this src_ip in window
    "src_unique_dst_count",         # 2: unique dest IPs targeted by src
    "src_unique_port_count",        # 3: unique dest ports targeted by src
    "src_block_ratio",              # 4: ratio of blocked events for src
    "src_threat_score",             # 5: threat_engine unified_score (0-100 → 0-1)
    "src_country_risk",             # 6: risk score based on country (0-1)

    # Destination features (7-12)
    "dst_is_well_known_port",       # 7: 1.0 if dst_port in well-known services
    "dst_is_exploit_target",        # 8: 1.0 if dst_port in exploit targets
    "dst_port_category",            # 9: 0=high, 1=registered, 2=well-known, 3=privileged
    "dst_service_risk",             # 10: risk of the service (telnet=1.0, https=0.0)
    "dst_is_internal",              # 11: 1.0 if dst_ip is RFC1918
    "dst_event_frequency",          # 12: total events hitting this dst_ip

    # Flow-level features (13-22)
    "flow_event_count",             # 13: total events in this flow
    "flow_packet_count",            # 14: estimated packet count
    "flow_byte_count",              # 15: estimated byte count
    "flow_duration_seconds",        # 16: seconds between first/last seen
    "flow_bytes_per_second",        # 17: avg bytes/sec
    "flow_is_blocked",              # 18: 1.0 if action == BLOCK
    "flow_block_ratio",             # 19: blocked / total for this flow
    "flow_syn_only_ratio",          # 20: ratio of SYN-only packets
    "flow_rst_ratio",               # 21: ratio of RST packets
    "flow_flag_diversity",          # 22: entropy of TCP flag distribution

    # Temporal features (23-26)
    "hour_of_day",                  # 23: hour when flow was first seen
    "is_business_hours",            # 24: 1.0 if 9-17 local time
    "is_weekend",                   # 25: 1.0 if Sat/Sun
    "hour_deviation",               # 26: |hour - 12| / 12 (0=noon, 1=midnight)

    # Contextual features (27-32)
    "simultaneous_blocked",         # 27: blocked connections from src in ±60s window
    "scan_port_ratio",              # 28: unique ports / unique IPs for src (high = scan)
    "scan_ip_ratio",                # 29: unique IPs / unique ports for src (high = sweep)
    "src_recent_anomaly_count",     # 30: anomalies attributed to src in last hour
    "flow_new_ratio",               # 31: 1.0 if flow is < 5 min old
    "src_flow_diversity",           # 32: number of distinct flows from this src

    # Protocol features (33-36)
    "is_tcp",                       # 33: 1.0 if TCP
    "is_udp",                       # 34: 1.0 if UDP
    "is_icmp",                      # 35: 1.0 if ICMP
    "proto_entropy",                # 36: protocol diversity from src (0-1)
]


class FlowFeatureExtractor:
    """Extract feature vectors from flow events and context."""

    @staticmethod
    def extract(event: Dict[str, Any], context: Dict[str, Any]) -> np.ndarray:
        """Extract a single feature vector from an event + context.

        Args:
            event: Parsed firewall event with src_ip, dst_ip, etc.
            context: Pre-computed context with src_stats, dst_stats, etc.

        Returns:
            numpy array of shape (36,)
        """
        feats = {}

        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dst_port") or 0
        proto = (event.get("proto") or "").upper()
        action = (event.get("action") or "").upper()
        tcp_flags = event.get("tcp_flags") or ""
        timestamp = event.get("timestamp")

        src_stats = context.get("src_stats", {}).get(src_ip, {})
        dst_stats = context.get("dst_stats", {}).get(dst_ip, {})
        flow_profiles = context.get("flow_profiles", {})

        # ── Source IP features ─────────────────────────────────────
        src_events = src_stats.get("total_events", 0)
        feats["src_event_frequency"] = min(float(math.log1p(src_events)), 10.0) / 10.0
        feats["src_unique_dst_count"] = min(float(math.log1p(src_stats.get("unique_dsts", 0))), 15.0) / 15.0
        feats["src_unique_port_count"] = min(float(math.log1p(src_stats.get("unique_ports", 0))), 15.0) / 15.0
        src_blocked = src_stats.get("blocked", 0)
        feats["src_block_ratio"] = src_blocked / max(src_events, 1)

        # Threat score from threat_engine (0-100 → 0-1)
        threat_score = src_stats.get("threat_score", 0.0)
        feats["src_threat_score"] = min(threat_score / 100.0, 1.0)

        # Country risk (from geo_info in src_stats)
        country = src_stats.get("country", "")
        feats["src_country_risk"] = _country_risk_score(country)

        # ── Destination features ───────────────────────────────────
        feats["dst_is_well_known_port"] = 1.0 if dst_port in WELL_KNOWN_SERVICES else 0.0
        feats["dst_is_exploit_target"] = 1.0 if dst_port in EXPLOIT_TARGET_PORTS else 0.0

        # Port category
        if dst_port <= 1023:
            feats["dst_port_category"] = 3.0  # privileged
        elif dst_port <= 49151:
            feats["dst_port_category"] = 2.0  # well-known/registered
        elif dst_port <= 1024:
            feats["dst_port_category"] = 1.0  # registered
        else:
            feats["dst_port_category"] = 0.0  # high/ephemeral
        feats["dst_port_category"] /= 3.0  # normalize

        # Service risk
        service = WELL_KNOWN_SERVICES.get(dst_port, "")
        feats["dst_service_risk"] = _service_risk_score(service)

        # Is internal destination
        feats["dst_is_internal"] = 1.0 if _is_rfc1918(dst_ip) else 0.0

        dst_events = dst_stats.get("total_events", 0)
        feats["dst_event_frequency"] = min(float(math.log1p(dst_events)), 15.0) / 15.0

        # ── Flow-level features ────────────────────────────────────
        flow_key = f"{src_ip}->{dst_ip}:{dst_port}"
        flow = flow_profiles.get(flow_key)

        if flow:
            feats["flow_event_count"] = min(float(math.log1p(flow.total_events)), 10.0) / 10.0
            feats["flow_packet_count"] = min(float(math.log1p(flow.packet_count)), 15.0) / 15.0
            feats["flow_byte_count"] = min(float(math.log1p(flow.byte_count)), 25.0) / 25.0

            duration = 0.0
            if flow.first_seen and flow.last_seen:
                duration = (flow.last_seen - flow.first_seen).total_seconds()
            feats["flow_duration_seconds"] = min(float(math.log1p(duration)), 15.0) / 15.0
            feats["flow_bytes_per_second"] = min(float(math.log1p(flow.byte_count / max(duration, 1))), 15.0) / 15.0

            feats["flow_is_blocked"] = 1.0 if action == "BLOCK" else 0.0
            feats["flow_block_ratio"] = flow.blocked_count / max(flow.total_events, 1)

            # TCP flag analysis
            flag_counts = Counter(flow.tcp_flags) if flow.tcp_flags else Counter()
            total_flags = sum(flag_counts.values()) or 1
            feats["flow_syn_only_ratio"] = flag_counts.get("SA", 0) / total_flags
            feats["flow_rst_ratio"] = flag_counts.get("RA", 0) / total_flags
            feats["flow_flag_diversity"] = _distribution_entropy(list(flag_counts.values())) / 3.0  # max entropy ~3 bits
        else:
            feats["flow_event_count"] = 0.0
            feats["flow_packet_count"] = 0.0
            feats["flow_byte_count"] = 0.0
            feats["flow_duration_seconds"] = 0.0
            feats["flow_bytes_per_second"] = 0.0
            feats["flow_is_blocked"] = 1.0 if action == "BLOCK" else 0.0
            feats["flow_block_ratio"] = 1.0 if action == "BLOCK" else 0.0
            feats["flow_syn_only_ratio"] = 0.0
            feats["flow_rst_ratio"] = 0.0
            feats["flow_flag_diversity"] = 0.0

        # ── Temporal features ──────────────────────────────────────
        if isinstance(timestamp, datetime):
            hour = timestamp.hour
            weekday = timestamp.weekday()
        else:
            hour = 12
            weekday = 0

        feats["hour_of_day"] = hour / 24.0
        feats["is_business_hours"] = 1.0 if 9 <= hour <= 17 and weekday < 5 else 0.0
        feats["is_weekend"] = 1.0 if weekday >= 5 else 0.0
        feats["hour_deviation"] = abs(hour - 12) / 12.0

        # ── Contextual features ────────────────────────────────────
        feats["simultaneous_blocked"] = min(float(src_stats.get("simultaneous_blocked", 0)), 20.0) / 20.0

        unique_dsts = src_stats.get("unique_dsts", 0)
        unique_ports = src_stats.get("unique_ports", 0)
        feats["scan_port_ratio"] = min(unique_ports / max(unique_dsts, 1), 10.0) / 10.0
        feats["scan_ip_ratio"] = min(unique_dsts / max(unique_ports, 1), 10.0) / 10.0

        feats["src_recent_anomaly_count"] = min(float(src_stats.get("recent_anomalies", 0)), 10.0) / 10.0

        # Is this a new flow? (< 5 min old)
        if flow and flow.first_seen:
            age = (datetime.now(timezone.utc) - flow.first_seen).total_seconds()
            feats["flow_new_ratio"] = 1.0 if age < 300 else max(0.0, 1.0 - age / 3600.0)
        else:
            feats["flow_new_ratio"] = 1.0

        src_flows = src_stats.get("flow_count", 0)
        feats["src_flow_diversity"] = min(float(math.log1p(src_flows)), 10.0) / 10.0

        # ── Protocol features ──────────────────────────────────────
        feats["is_tcp"] = 1.0 if proto == "TCP" else 0.0
        feats["is_udp"] = 1.0 if proto == "UDP" else 0.0
        feats["is_icmp"] = 1.0 if proto == "ICMP" else 0.0

        proto_diversity = src_stats.get("proto_count", 1)
        feats["proto_entropy"] = min(float(math.log(proto_diversity + 1) / math.log(4)), 1.0)  # max 4 protos

        return np.array([feats[f] for f in FLOW_FEATURE_NAMES], dtype=np.float64)

    @staticmethod
    def extract_batch(events: List[Dict], context: Dict) -> Tuple[np.ndarray, List[str]]:
        """Extract feature matrix from multiple events.

        Returns (X, flow_keys).
        """
        X = []
        keys = []
        for event in events:
            flow_key = f"{event.get('src_ip', '')}->{event.get('dst_ip', '')}:{event.get('dst_port', 0)}"
            X.append(FlowFeatureExtractor.extract(event, context))
            keys.append(flow_key)

        if not X:
            return np.empty((0, ML_FEATURE_COUNT), dtype=np.float64), []

        return np.array(X), keys


def _country_risk_score(country: str) -> float:
    """Return risk score (0-1) for a country code.

    High-risk countries known for state-sponsored attacks or high botnet prevalence
    get higher scores. Unknown/missing countries get 0.5.
    """
    if not country:
        return 0.5  # unknown

    # High-risk (based on Verizon DBIR and similar reports)
    high_risk = {"CN", "RU", "KP", "IR"}
    medium_risk = {"BR", "VN", "IN", "UA", "RO"}

    if country.upper() in high_risk:
        return 0.85
    elif country.upper() in medium_risk:
        return 0.55
    else:
        return 0.15


def _service_risk_score(service: str) -> float:
    """Return risk score for a service type."""
    high_risk = {"telnet", "vnc", "rdp", "redis", "mongodb", "mysql", "mssql", "postgresql"}
    medium_risk = {"ssh", "ftp", "smtp"}
    if service in high_risk:
        return 0.9
    elif service in medium_risk:
        return 0.5
    else:
        return 0.1


def _is_rfc1918(ip: str) -> bool:
    """Check if IP is in RFC1918 private range."""
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False
    except (ValueError, IndexError):
        return False


def _distribution_entropy(counts: List[int]) -> float:
    """Shannon entropy of a categorical distribution."""
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


class FlowMLClassifier:
    """GradientBoosting classifier for flow-based behavioral classification.

    Predicts: BENIGN, SUSPICIOUS, RECONNAISSANCE, ATTACK, EXPLOIT
    """

    def __init__(self):
        self.model: Optional[GradientBoostingClassifier] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.model_path = os.path.join(
            os.environ.get("AGENT_DATA_DIR", "/app/agent_data"),
            "flow_classifier_model.pkl",
        )
        self.samples_since_retrain = 0
        self.metrics: Dict[str, Any] = {}
        self.feature_importances: Dict[str, float] = {}
        self.total_classified = 0
        self._load_model()

    def _load_model(self):
        """Load a persisted model from disk if available."""
        if not os.path.exists(self.model_path):
            logger.info("No persisted flow classifier model found at %s", self.model_path)
            return

        try:
            data = joblib.load(self.model_path)
            self.model = data["model"]
            self.label_encoder = data["label_encoder"]
            self.metrics = data.get("metrics", {})
            self.feature_importances = data.get("feature_importances", {})
            self.total_classified = data.get("total_classified", 0)
            logger.info(
                "Flow classifier model loaded (accuracy=%.3f, trained on %d samples)",
                self.metrics.get("accuracy", 0),
                self.metrics.get("train_samples", 0),
            )
        except Exception as e:
            logger.error("Failed to load flow classifier model: %s", e)
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
            "feature_names": FLOW_FEATURE_NAMES,
            "label_names": FLOW_LABEL_NAMES,
            "total_classified": self.total_classified,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        joblib.dump(data, self.model_path)
        logger.info(
            "Flow classifier model saved (train_samples=%d, accuracy=%.3f)",
            self.metrics.get("train_samples", 0),
            self.metrics.get("accuracy", 0),
        )

    def _heuristic_label(self, event: Dict, context: Dict) -> str:
        """Fallback heuristic label for training data generation."""
        action = (event.get("action") or "").upper()
        dst_port = event.get("dst_port") or 0
        src_stats = context.get("src_stats", {}).get(event.get("src_ip", ""), {})

        # Blocked traffic to exploit-target ports with high threat score
        if action == "BLOCK" and dst_port in EXPLOIT_TARGET_PORTS:
            threat = src_stats.get("threat_score", 0)
            if threat > 50:
                return "EXPLOIT"
            return "ATTACK"

        # Blocked traffic with scan-like behavior (many ports, few IPs)
        if action == "BLOCK":
            unique_ports = src_stats.get("unique_ports", 0)
            unique_dsts = src_stats.get("unique_dsts", 0)
            if unique_ports > 10 and unique_dsts < 5:
                return "RECONNAISSANCE"
            return "ATTACK"

        # High-frequency scanner (many ports from single source)
        if src_stats.get("unique_ports", 0) > 20:
            return "RECONNAISSANCE"

        # Known threat with high score
        if src_stats.get("threat_score", 0) > 70:
            return "ATTACK"

        # Anomaly-flagged source
        if src_stats.get("recent_anomalies", 0) > 3:
            return "SUSPICIOUS"

        # Default: if blocked, at least suspicious
        if action == "BLOCK":
            return "SUSPICIOUS"

        return "BENIGN"

    def train(self, events: List[Dict], contexts: List[Dict]) -> Dict[str, Any]:
        """Train the ML model from events + contexts.

        Args:
            events: List of parsed firewall events.
            contexts: List of context dicts (one per event).

        Returns:
            Dict with training metrics.
        """
        if len(events) < ML_MIN_SAMPLES:
            logger.warning(
                "Not enough data to train flow classifier (%d events, need %d)",
                len(events), ML_MIN_SAMPLES,
            )
            self.metrics = {"error": "insufficient_data", "samples": len(events)}
            return self.metrics

        X = []
        y_labels = []
        for event, ctx in zip(events, contexts):
            features = FlowFeatureExtractor.extract(event, ctx)
            label = self._heuristic_label(event, ctx)
            X.append(features)
            y_labels.append(label)

        X_train = np.array(X)

        # Encode labels
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(FLOW_LABEL_NAMES)  # fixed order
        y_train = self.label_encoder.transform(y_labels)

        # Train GradientBoosting
        self.model = GradientBoostingClassifier(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
            min_samples_split=5,
            min_samples_leaf=3,
            subsample=0.9,
        )
        self.model.fit(X_train, y_train)

        # Cross-validation
        cv_folds = min(3, len(X_train) // ML_MIN_SAMPLES, 3)
        if cv_folds >= 2:
            cv_scores = cross_val_score(
                self.model, X_train, y_train, cv=cv_folds, scoring="accuracy"
            )
        else:
            cv_scores = np.array([0.0])

        train_preds = self.model.predict(X_train)

        self.metrics = {
            "accuracy": round(float(accuracy_score(y_train, train_preds)), 4),
            "cv_accuracy_mean": round(float(cv_scores.mean()), 4),
            "cv_accuracy_std": round(float(cv_scores.std()), 4),
            "precision_macro": round(float(
                precision_score(y_train, train_preds, average="macro", zero_division=0)
            ), 4),
            "recall_macro": round(float(
                recall_score(y_train, train_preds, average="macro", zero_division=0)
            ), 4),
            "f1_macro": round(float(
                f1_score(y_train, train_preds, average="macro", zero_division=0)
            ), 4),
            "train_samples": len(X_train),
            "n_classes": len(FLOW_LABEL_NAMES),
            "class_distribution": dict(Counter(y_labels)),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }

        # Feature importances
        importances = self.model.feature_importances_
        self.feature_importances = {
            FLOW_FEATURE_NAMES[i]: round(float(imp), 4)
            for i, imp in enumerate(importances)
            if imp > 0.001
        }

        self.samples_since_retrain = 0

        logger.info(
            "Flow classifier trained: accuracy=%.3f (CV±%.3f), samples=%d, top_features=%s",
            self.metrics["accuracy"],
            self.metrics["cv_accuracy_std"],
            self.metrics["train_samples"],
            list(self.feature_importances.keys())[:5],
        )

        self._save_model()
        return self.metrics

    def predict(self, event: Dict, context: Dict) -> Tuple[str, float, bool]:
        """Predict classification for a single event.

        Returns (label, confidence, is_uncertain).
        """
        if self.model is None or self.label_encoder is None:
            return self._fallback_predict(event, context)

        try:
            features = FlowFeatureExtractor.extract(event, context)
            proba = self.model.predict_proba(features.reshape(1, -1))[0]
            pred_idx = int(np.argmax(proba))
            label = self.label_encoder.classes_[pred_idx]
            confidence = float(proba[pred_idx])

            is_uncertain = confidence < ML_PREDICT_CONFIDENCE_THRESHOLD

            if is_uncertain:
                logger.debug(
                    "Flow classifier confidence %.3f below threshold, marking UNCERTAIN",
                    confidence,
                )

            self.total_classified += 1
            return label, confidence, is_uncertain

        except Exception as e:
            logger.warning("Flow classifier prediction failed: %s", e)
            return self._fallback_predict(event, context)

    def _fallback_predict(self, event: Dict, context: Dict) -> Tuple[str, float, bool]:
        """Fall back to heuristic classification."""
        label = self._heuristic_label(event, context)
        # Heuristic confidence: BLOCK → medium, PASS → higher if benign
        action = (event.get("action") or "").upper()
        if action == "BLOCK":
            confidence = 0.4
        else:
            confidence = 0.6
        is_uncertain = True
        return label, confidence, is_uncertain

    def should_retrain(self) -> bool:
        """Check if the model should be retrained."""
        return self.samples_since_retrain >= ML_RETRAIN_THRESHOLD

    def increment_samples(self, count: int = 1):
        """Track new samples since last retrain."""
        self.samples_since_retrain += count

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata for API exposure."""
        return {
            "model_trained": self.model is not None,
            "model_type": "GradientBoosting",
            "metrics": self.metrics,
            "feature_importances": self.feature_importances,
            "samples_since_retrain": self.samples_since_retrain,
            "total_classified": self.total_classified,
            "feature_names": FLOW_FEATURE_NAMES,
            "label_names": FLOW_LABEL_NAMES,
            "feature_count": ML_FEATURE_COUNT,
        }


class FlowClassifier:
    """Top-level flow classifier with context management, persistence, and active learning.

    Manages:
    - Per-flow state tracking
    - Context building (src stats, dst stats, etc.)
    - ML model training and prediction
    - Active learning queue for uncertain flows
    - DB persistence via EventDatabase
    """

    def __init__(self):
        self.ml_classifier = FlowMLClassifier()
        self.flow_profiles: Dict[str, FlowProfile] = {}
        self.src_stats: Dict[str, Dict] = defaultdict(self._empty_src_stats)
        self.dst_stats: Dict[str, Dict] = defaultdict(self._empty_dst_stats)
        self.total_processed = 0
        self.total_classified = 0
        self.total_uncertain = 0
        self.label_counts: Counter = Counter()
        self._recent_anomalies: Dict[str, List[datetime]] = defaultdict(list)
        logger.info(
            "FlowClassifier initialized (ml=%s)",
            "trained" if self.ml_classifier.model is not None else "untrained",
        )

    @staticmethod
    def _empty_src_stats() -> Dict:
        return {
            "total_events": 0,
            "unique_dsts": set(),
            "unique_ports": set(),
            "blocked": 0,
            "threat_score": 0.0,
            "country": "",
            "simultaneous_blocked": 0,
            "recent_anomalies": 0,
            "flow_count": 0,
            "proto_count": 1,
        }

    @staticmethod
    def _empty_dst_stats() -> Dict:
        return {
            "total_events": 0,
            "unique_srcs": set(),
            "ports": set(),
        }

    def process_event(self, event: Dict[str, Any], threat_score: float = 0.0, country: str = ""):
        """Process a single event: update flow profile + stats, classify if model ready.

        Args:
            event: Parsed firewall event.
            threat_score: Optional threat score from threat_engine (0-100).
            country: Optional country code from geo lookup.
        """
        self.total_processed += 1

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        dst_port = event.get("dst_port") or 0
        proto = (event.get("proto") or "TCP").upper()
        action = (event.get("action") or "").upper()
        tcp_flags = event.get("tcp_flags") or ""
        timestamp = event.get("timestamp")
        ip_total_length = event.get("ip_total_length") or 0

        if not src_ip:
            return

        # ── Update source stats ────────────────────────────────────
        src = self.src_stats[src_ip]
        src["total_events"] += 1
        if dst_ip:
            src["unique_dsts"].add(dst_ip)
        src["unique_ports"].add(dst_port)
        if action == "BLOCK":
            src["blocked"] += 1
        src["threat_score"] = max(src["threat_score"], threat_score)
        if country:
            src["country"] = country

        # ── Update destination stats ───────────────────────────────
        if dst_ip:
            dst = self.dst_stats[dst_ip]
            dst["total_events"] += 1
            dst["unique_srcs"].add(src_ip)
            dst["ports"].add(dst_port)

        # ── Update flow profile ────────────────────────────────────
        flow_key = f"{src_ip}->{dst_ip}:{dst_port}"
        if flow_key not in self.flow_profiles:
            now = datetime.now(timezone.utc)
            self.flow_profiles[flow_key] = FlowProfile(
                flow_key=flow_key,
                src_ip=src_ip,
                dst_ip=dst_ip or "",
                dst_port=dst_port,
                proto=proto,
                action=action,
                first_seen=timestamp or now,
                last_seen=timestamp or now,
            )

        flow = self.flow_profiles[flow_key]
        flow.total_events += 1
        flow.packet_count += 1
        flow.byte_count += ip_total_length
        if tcp_flags:
            flow.tcp_flags.append(tcp_flags)
        if event.get("interface"):
            flow.interfaces.add(event["interface"])
        if event.get("src_port"):
            flow.src_ports.add(event["src_port"])
        if action == "BLOCK":
            flow.blocked_count += 1
        elif action == "PASS":
            flow.passed_count += 1
        if timestamp:
            flow.last_seen = timestamp

        # ── Build context and classify ─────────────────────────────
        context = self._build_context(src_ip, dst_ip or "")
        label, confidence, is_uncertain = self.ml_classifier.predict(event, context)
        self.total_classified += 1
        self.label_counts[label] += 1

        if is_uncertain:
            self.total_uncertain += 1

    def process_events(self, events: List[Dict]):
        """Process a batch of events."""
        for event in events:
            self.process_event(event)

    def _build_context(self, src_ip: str, dst_ip: str) -> Dict:
        """Build context dict for feature extraction."""
        src = self.src_stats.get(src_ip, {})
        dst = self.dst_stats.get(dst_ip, {})

        # Convert sets to counts for serialization
        src_context = {
            "total_events": src.get("total_events", 0),
            "unique_dsts": len(src.get("unique_dsts", set())),
            "unique_ports": len(src.get("unique_ports", set())),
            "blocked": src.get("blocked", 0),
            "threat_score": src.get("threat_score", 0.0),
            "country": src.get("country", ""),
            "simultaneous_blocked": src.get("simultaneous_blocked", 0),
            "recent_anomalies": src.get("recent_anomalies", 0),
            "flow_count": len([k for k in self.flow_profiles if k.startswith(src_ip)]),
            "proto_count": 1,  # simplified
        }

        dst_context = {
            "total_events": dst.get("total_events", 0),
            "unique_srcs": len(dst.get("unique_srcs", set())),
            "ports": len(dst.get("ports", set())),
        }

        return {
            "src_stats": {src_ip: src_context},
            "dst_stats": {dst_ip: dst_context},
            "flow_profiles": self.flow_profiles,
        }

    def update_threat_info(self, ip: str, threat_score: float, country: str = ""):
        """Update threat score for a source IP (called from threat_engine integration)."""
        src = self.src_stats[ip]
        src["threat_score"] = max(src.get("threat_score", 0.0), threat_score)
        if country:
            src["country"] = country

    def record_anomaly(self, ip: str):
        """Record that an anomaly was detected for this IP (updates recent_anomalies)."""
        src = self.src_stats[ip]
        now = datetime.now(timezone.utc)
        src["recent_anomalies"] = src.get("recent_anomalies", 0) + 1
        self._recent_anomalies[ip].append(now)

    def train_ml_model(self) -> Dict[str, Any]:
        """Train the ML model on accumulated flow data.

        Uses historical flow profiles to generate training samples.
        """
        # Generate training samples from flow profiles
        events = []
        contexts = []

        for flow in self.flow_profiles.values():
            if flow.total_events < 2:
                continue

            event = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "proto": flow.proto,
                "action": flow.action,
                "timestamp": flow.first_seen,
                "ip_total_length": flow.byte_count // max(flow.packet_count, 1),
                "tcp_flags": flow.tcp_flags[0] if flow.tcp_flags else "",
            }

            context = self._build_context(flow.src_ip, flow.dst_ip)
            events.append(event)
            contexts.append(context)

        if len(events) < ML_MIN_SAMPLES:
            logger.warning(
                "Not enough flow data to train (%d flows with 2+ events, need %d)",
                len(events), ML_MIN_SAMPLES,
            )
            return {"error": "insufficient_data", "flows": len(events)}

        return self.ml_classifier.train(events, contexts)

    def should_retrain_ml(self) -> bool:
        """Check if ML model should be retrained."""
        return self.ml_classifier.should_retrain()

    def get_classifications_summary(self) -> Dict[str, Any]:
        """Get summary of all classifications."""
        total = sum(self.label_counts.values()) or 1
        return {
            "total_processed": self.total_processed,
            "total_classified": self.total_classified,
            "total_uncertain": self.total_uncertain,
            "uncertain_ratio": round(self.total_uncertain / max(self.total_classified, 1), 4),
            "label_distribution": dict(self.label_counts),
            "label_percentages": {
                label: round(count / total, 4)
                for label, count in self.label_counts.items()
            },
            "active_flows": len(self.flow_profiles),
            "tracked_sources": len(self.src_stats),
            "tracked_destinations": len(self.dst_stats),
            "model_info": self.ml_classifier.get_model_info(),
        }

    def get_uncertain_flows(self, limit: int = 50) -> List[Dict]:
        """Get flows flagged as uncertain for human review (active learning)."""
        uncertain = []
        # Flows with high block ratio or high threat score but uncertain classification
        for flow in sorted(
            self.flow_profiles.values(),
            key=lambda f: f.blocked_count / max(f.total_events, 1),
            reverse=True,
        ):
            if len(uncertain) >= limit:
                break

            src = self.src_stats.get(flow.src_ip, {})
            threat = src.get("threat_score", 0)
            block_ratio = flow.blocked_count / max(flow.total_events, 1)

            # Include if uncertain indicators are present
            if block_ratio > 0.5 or threat > 30:
                context = self._build_context(flow.src_ip, flow.dst_ip)
                event = {
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "dst_port": flow.dst_port,
                    "proto": flow.proto,
                    "action": flow.action,
                    "timestamp": flow.first_seen,
                }
                label, confidence, is_uncertain = self.ml_classifier.predict(event, context)

                uncertain.append({
                    "flow_key": flow.flow_key,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "dst_port": flow.dst_port,
                    "proto": flow.proto,
                    "label": label,
                    "confidence": confidence,
                    "is_uncertain": is_uncertain,
                    "event_count": flow.total_events,
                    "blocked_count": flow.blocked_count,
                    "block_ratio": round(block_ratio, 3),
                    "threat_score": threat,
                    "reason": self._uncertain_reason(flow, src),
                })

        return uncertain

    def _uncertain_reason(self, flow: FlowProfile, src: Dict) -> str:
        """Generate human-readable reason for uncertainty."""
        reasons = []
        block_ratio = flow.blocked_count / max(flow.total_events, 1)

        if block_ratio > 0.8:
            reasons.append(f"high block rate ({block_ratio:.0%})")
        elif block_ratio > 0.3:
            reasons.append(f"moderate block rate ({block_ratio:.0%})")

        threat = src.get("threat_score", 0)
        if threat > 50:
            reasons.append(f"high threat score ({threat:.0f})")
        elif threat > 20:
            reasons.append(f"elevated threat score ({threat:.0f})")

        unique_ports = len(src.get("unique_ports", set()))
        if unique_ports > 10:
            reasons.append(f"port scanning ({unique_ports} unique ports)")

        if not reasons:
            reasons.append("low model confidence")

        return "; ".join(reasons)

    def persist_classification(self, db: Any, flow_key: str, label: str,
                                confidence: float, event: Dict, is_uncertain: bool):
        """Persist a classification to the database.

        Args:
            db: EventDatabase instance.
            flow_key: Unique flow identifier.
            label: Classification label.
            confidence: Model confidence (0-1).
            event: Source event with timestamp, IPs, etc.
            is_uncertain: Whether the classification was uncertain.
        """
        try:
            cur = db._new_cursor()
            try:
                cur.execute(
                    """INSERT INTO flow_classifications
                       (timestamp, src_ip, dst_ip, flow_key, label, label_code,
                        confidence, feature_vector, reason, is_uncertain)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (flow_key) DO UPDATE SET
                           label = EXCLUDED.label,
                           label_code = EXCLUDED.label_code,
                           confidence = EXCLUDED.confidence,
                           is_uncertain = EXCLUDED.is_uncertain,
                           classified_at = NOW()
                       RETURNING id""",
                    (
                        event.get("timestamp") or datetime.now(timezone.utc),
                        event.get("src_ip", ""),
                        event.get("dst_ip", ""),
                        flow_key,
                        label,
                        FLOW_LABELS.get(label, 1),
                        confidence,
                        None,  # feature_vector (skip storing full vector for space)
                        self._classification_reason(label, event),
                        is_uncertain,
                    ),
                )
            finally:
                cur.close()
        except Exception as e:
            logger.debug("Failed to persist flow classification: %s", e)

    def _classification_reason(self, label: str, event: Dict) -> str:
        """Generate a reason string for the classification."""
        reasons = []
        action = (event.get("action") or "").upper()
        dst_port = event.get("dst_port") or 0

        if action == "BLOCK":
            reasons.append("blocked traffic")
        if dst_port in EXPLOIT_TARGET_PORTS:
            reasons.append(f"exploit-target port {dst_port}")
        if dst_port in WELL_KNOWN_SERVICES:
            reasons.append(f"service: {WELL_KNOWN_SERVICES[dst_port]}")

        src_stats = self.src_stats.get(event.get("src_ip", ""), {})
        if src_stats.get("threat_score", 0) > 30:
            reasons.append("elevated threat score")
        if len(src_stats.get("unique_ports", set())) > 10:
            reasons.append("port scanning behavior")

        return f"[{label}] " + "; ".join(reasons) if reasons else f"[{label}] classified by ML"

    def get_model_info(self) -> Dict[str, Any]:
        """Get ML model info."""
        return self.ml_classifier.get_model_info()

    def get_model_metrics(self) -> Dict[str, Any]:
        """Get model metrics for Prometheus-style exposure."""
        info = self.ml_classifier.get_model_info()
        return info.get("metrics", {})

    def get_state(self) -> Dict:
        """Get serializable state for persistence."""
        return {
            "total_processed": self.total_processed,
            "total_classified": self.total_classified,
            "total_uncertain": self.total_uncertain,
            "label_counts": dict(self.label_counts),
            "flow_count": len(self.flow_profiles),
            "src_count": len(self.src_stats),
            "dst_count": len(self.dst_stats),
        }
