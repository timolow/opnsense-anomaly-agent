#!/usr/bin/env python3
"""
ML Firewall Rule Classification

Classifies firewall rules into 3 categories based on traffic behavior:
  1. DEFAULT_DENY — Traffic with no rule (caught by default deny policy)
  2. ABUSIVE — Traffic patterns indicating scanning, brute force, or malicious activity
  3. GOOD — Normal, legitimate traffic patterns

Uses multiple features per rule to determine classification:
- Event volume and distribution
- Unique source/destination diversity
- Port scan indicators (high unique port count)
- Destination scan indicators (high unique dst count)
- Protocol anomalies
- Time distribution (burst vs steady)
- Pass/Block ratio

"""

import os
import json
import logging
import math
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ── Feature Weights ─────────────────────────────────────────────────────
# Each feature contributes to a "goodness" score (0-1)
FEATURE_WEIGHTS = {
    'port_diversity': 0.25,      # High unique ports per src -> scanning
    'dest_diversity': 0.25,      # High unique dst per src -> scanning
    'action_ratio': 0.20,        # Pass/Block ratio
    'volume_score': 0.15,        # Event volume context
    'protocol_normalcy': 0.15,   # Protocol distribution
}


# ── Thresholds ──────────────────────────────────────────────────────────
MIN_RULE_EVENTS = 20            # Minimum events for analysis
HIGH_PORT_DIVERSITY = 100       # Unique ports -> potential scan
HIGH_DEST_DIVERSITY = 100       # Unique destinations -> potential scan
LOW_VOLUME_THRESHOLD = 50       # Events below this = suspicious
HIGH_BLOCK_RATIO = 0.3          # >30% blocked = potentially abusive
NORMAL_PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ip'}


@dataclass
class RuleFeatures:
    """Computed features for a single rule."""
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
    port_scan_score: float = 0.0       # 0-1: higher = more scanning
    dest_scan_score: float = 0.0       # 0-1: higher = more scanning
    action_ratio_score: float = 0.0    # 0-1: higher = more legitimate
    volume_score: float = 0.0          # 0-1: higher = more normal volume
    protocol_score: float = 0.0        # 0-1: higher = more normal protocols
    goodness_score: float = 0.0        # 0-1: overall goodness
    classification: str = "UNKNOWN"    # GOOD, ABUSIVE, DEFAULT_DENY
    confidence: float = 0.0            # 0-1: classifier confidence
    details: Dict[str, Any] = field(default_factory=dict)


class RuleClassifierML:
    """
    ML-based firewall rule classifier.
    
    Analyzes traffic patterns to classify rules into:
    - GOOD: Legitimate traffic (low diversity, normal ports, high pass ratio)
    - ABUSIVE: Scanning, brute force, or suspicious patterns (high diversity, bursty)
    - DEFAULT_DENY: No rule matched (handled separately)
    """
    
    def __init__(self):
        self.features_map: Dict[str, RuleFeatures] = {}
        self.total_events = 0
        self.events_with_rule = 0
        self.events_without_rule = 0
        self.classification_history: List[Dict] = []
        
        # Global statistics for normalization
        self.global_avg_events = 0
        self.global_avg_unique_ports = 0
        self.global_avg_unique_dsts = 0
        
        logger.info("RuleClassifierML initialized")
    
    def ingest_events(self, events: List[Dict]):
        """Ingest a batch of firewall events to build rule profiles."""
        src_dst_ports = defaultdict(Counter)  # src_ip -> Counter(dst_port)
        src_dst_ips = defaultdict(set)         # src_ip -> set(dst_ip)
        rule_src_ports = defaultdict(Counter)  # rule_name -> Counter(src_port)
        
        for event in events:
            self.total_events += 1
            
            rule_name = event.get('rule_name')
            action = event.get('action', '').upper()
            src_ip = event.get('src_ip', '')
            dst_ip = event.get('dst_ip', '')
            dport = event.get('dport')
            sport = event.get('sport')
            proto = (event.get('proto', '') or '').upper()
            
            if rule_name:
                self.events_with_rule += 1
                
                # Track per-rule features
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
                
                src_dst_ips[src_ip].add(dst_ip)
            else:
                self.events_without_rule += 1
        
        # Compute derived features
        for rule_name, features in self.features_map.items():
            self._compute_port_scan_score(features, src_dst_ports)
            self._compute_dest_scan_score(features, src_dst_ips)
            self._compute_action_score(features)
            self._compute_volume_score(features)
            self._compute_protocol_score(features)
            self._compute_goodness_score(features)
            self._classify_rule(features)
        
        # Compute global stats for normalization
        if self.features_map:
            all_events = [f.total_events for f in self.features_map.values()]
            all_ports = [f.unique_ports for f in self.features_map.values()]
            all_dsts = [f.unique_dst_ips for f in self.features_map.values()]
            self.global_avg_events = sum(all_events) / len(all_events)
            self.global_avg_unique_ports = sum(all_ports) / len(all_ports) if all_ports else 0
            self.global_avg_unique_dsts = sum(all_dsts) / len(all_dsts) if all_dsts else 0
    
    def _compute_port_scan_score(self, features: RuleFeatures, src_dst_ports):
        """Score how much this rule involves port scanning (0-1)."""
        # Count how many src IPs have high port diversity
        high_diversity_sources = 0
        total_sources = len(features.src_ip_counts)
        
        for src_ip, port_counts in src_dst_ports.items():
            if features.src_ip_counts.get(src_ip, 0) > 0:
                if len(port_counts) >= HIGH_PORT_DIVERSITY:
                    high_diversity_sources += 1
        
        # Port diversity score: ratio of high-diversity sources
        port_score = min(high_diversity_sources / max(total_sources, 1), 1.0)
        features.port_scan_score = round(port_score, 3)
    
    def _compute_dest_scan_score(self, features: RuleFeatures, src_dst_ips):
        """Score how much this rule involves destination scanning (0-1)."""
        high_diversity_sources = 0
        total_sources = len(features.src_ip_counts)
        
        for src_ip, dst_ips in src_dst_ips.items():
            if len(dst_ips) >= HIGH_DEST_DIVERSITY:
                high_diversity_sources += 1
        
        dest_score = min(high_diversity_sources / max(total_sources, 1), 1.0)
        features.dest_scan_score = round(dest_score, 3)
    
    def _compute_action_score(self, features: RuleFeatures):
        """Score action distribution (1.0 = all PASS, 0.0 = all BLOCK)."""
        if features.total_events == 0:
            features.action_ratio_score = 0.5
            return
        
        pass_ratio = features.pass_count / features.total_events
        # Normal rules should have high pass ratio
        features.action_ratio_score = round(pass_ratio, 3)
    
    def _compute_volume_score(self, features: RuleFeatures):
        """Score if event volume is normal (1.0) or anomalous (0.0)."""
        if self.global_avg_events == 0:
            features.volume_score = 0.5
            return
        
        ratio = features.total_events / self.global_avg_events
        
        # Normal range: 0.1x to 10x average
        if ratio < 0.1:
            features.volume_score = 0.1  # Too few events
        elif ratio > 10:
            features.volume_score = 0.3  # Too many events (potential DDoS)
        else:
            features.volume_score = 1.0  # Normal range
    
    def _compute_protocol_score(self, features: RuleFeatures):
        """Score protocol normalcy (1.0 = normal, 0.0 = anomalous)."""
        total = features.total_events
        if total == 0:
            features.protocol_score = 0.5
            return
        
        # Check for unusual protocols
        unusual = sum(count for proto, count in features.protocols.items()
                     if proto and proto not in NORMAL_PROTOCOLS)
        
        unusual_ratio = unusual / total
        features.protocol_score = round(max(0, 1.0 - unusual_ratio), 3)
    
    def _compute_goodness_score(self, features: RuleFeatures):
        """Compute weighted goodness score (0-1)."""
        score = 0.0
        score += (1.0 - features.port_scan_score) * FEATURE_WEIGHTS['port_diversity']
        score += (1.0 - features.dest_scan_score) * FEATURE_WEIGHTS['dest_diversity']
        score += features.action_ratio_score * FEATURE_WEIGHTS['action_ratio']
        score += features.volume_score * FEATURE_WEIGHTS['volume_score']
        score += features.protocol_score * FEATURE_WEIGHTS['protocol_normalcy']
        
        features.goodness_score = round(score, 3)
    
    def _classify_rule(self, features: RuleFeatures):
        """Classify rule based on goodness score."""
        if features.total_events < MIN_RULE_EVENTS:
            features.classification = "UNCERTAIN"
            features.confidence = 0.3
            return
        
        goodness = features.goodness_score
        
        # Classification thresholds
        if goodness >= 0.65:
            features.classification = "GOOD"
            features.confidence = round(goodness, 2)
        elif goodness <= 0.35:
            features.classification = "ABUSIVE"
            features.confidence = round(1.0 - goodness, 2)
        else:
            features.classification = "SUSPICIOUS"
            features.confidence = 0.5
        
        # Special case: DENY rules are always GOOD (they block bad traffic)
        if features.block_count > features.pass_count * 2:
            features.classification = "GOOD"
            features.confidence = 0.8
            features.details['note'] = 'DENY rule (actively blocking traffic)'
        
        logger.debug("Rule %s: goodness=%.3f -> %s (confidence=%.2f)",
                    features.rule_name, goodness, features.classification, features.confidence)
    
    def get_classified_rules(self) -> List[Dict[str, Any]]:
        """Return all classified rules sorted by importance."""
        rules = []
        for name, features in self.features_map.items():
            rules.append({
                'rule_name': name,
                'classification': features.classification,
                'confidence': features.confidence,
                'goodness_score': features.goodness_score,
                'total_events': features.total_events,
                'pass_count': features.pass_count,
                'block_count': features.block_count,
                'unique_src_ips': len(features.src_ip_counts),
                'unique_dst_ips': len(features.dst_ip_counts),
                'unique_ports': features.unique_ports,
                'protocols': dict(features.protocols),
                'port_scan_score': features.port_scan_score,
                'dest_scan_score': features.dest_scan_score,
                'action_ratio': features.action_ratio_score,
                'volume_score': features.volume_score,
                'protocol_score': features.protocol_score,
                'details': features.details,
            })
        
        # Sort: ABUSIVE first, then SUSPICIOUS, then GOOD
        order = {'ABUSIVE': 0, 'SUSPICIOUS': 1, 'UNCERTAIN': 2, 'GOOD': 3}
        rules.sort(key=lambda r: (order.get(r['classification'], 4), -r['total_events']))
        
        return rules
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of classification results."""
        classified = self.get_classified_rules()
        
        summary = {
            'total_events': self.total_events,
            'events_with_rule': self.events_with_rule,
            'events_without_rule': self.events_without_rule,
            'total_rules': len(classified),
            'by_classification': Counter(r['classification'] for r in classified),
            'rules_by_classification': {
                'GOOD': [r for r in classified if r['classification'] == 'GOOD'],
                'ABUSIVE': [r for r in classified if r['classification'] == 'ABUSIVE'],
                'SUSPICIOUS': [r for r in classified if r['classification'] == 'SUSPICIOUS'],
                'UNCERTAIN': [r for r in classified if r['classification'] == 'UNCERTAIN'],
            },
            'default_deny': {
                'events': self.events_without_rule,
                'percentage': round(self.events_without_rule / max(self.total_events, 1) * 100, 1),
            },
        }
        
        return summary
    
    def get_top_abusive_rules(self, n=10) -> List[Dict]:
        """Return top N most abusive rules."""
        rules = self.get_classified_rules()
        return [r for r in rules if r['classification'] == 'ABUSIVE'][:n]
    
    def get_top_good_rules(self, n=10) -> List[Dict]:
        """Return top N best rules."""
        rules = self.get_classified_rules()
        return [r for r in rules if r['classification'] == 'GOOD'][:n]
    
    def save_state(self, filepath: str = None):
        """Save classification state."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "rule_classify_state.json")
        
        data = {
            'classification_history': self.classification_history,
            'features': {
                name: {
                    'rule_name': f.rule_name,
                    'total_events': f.total_events,
                    'pass_count': f.pass_count,
                    'block_count': f.block_count,
                    'unique_src_ips': f.unique_src_ips,
                    'unique_dst_ips': f.unique_dst_ips,
                    'unique_ports': f.unique_ports,
                    'protocols': dict(f.protocols),
                    'port_scan_score': f.port_scan_score,
                    'dest_scan_score': f.dest_scan_score,
                    'action_ratio_score': f.action_ratio_score,
                    'volume_score': f.volume_score,
                    'protocol_score': f.protocol_score,
                    'goodness_score': f.goodness_score,
                    'classification': f.classification,
                    'confidence': f.confidence,
                    'details': f.details,
                }
                for name, f in self.features_map.items()
            },
            'summary': self.get_summary(),
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info("Rule classifier ML state saved to %s", filepath)
    
    def load_state(self, filepath: str = None):
        """Load classification state."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "rule_classify_state.json")
        
        if not os.path.exists(filepath):
            logger.info("No rule classifier ML state found at %s", filepath)
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            for name, features_data in data.get('features', {}).items():
                features = RuleFeatures(
                    rule_name=name,
                    total_events=features_data.get('total_events', 0),
                    pass_count=features_data.get('pass_count', 0),
                    block_count=features_data.get('block_count', 0),
                    unique_src_ips=features_data.get('unique_src_ips', 0),
                    unique_dst_ips=features_data.get('unique_dst_ips', 0),
                    unique_ports=features_data.get('unique_ports', 0),
                    port_scan_score=features_data.get('port_scan_score', 0),
                    dest_scan_score=features_data.get('dest_scan_score', 0),
                    action_ratio_score=features_data.get('action_ratio_score', 0),
                    volume_score=features_data.get('volume_score', 0),
                    protocol_score=features_data.get('protocol_score', 0),
                    goodness_score=features_data.get('goodness_score', 0),
                )
                features.protocols = Counter(features_data.get('protocols', {}))
                features.classification = features_data.get('classification', 'UNKNOWN')
                features.confidence = features_data.get('confidence', 0)
                features.details = features_data.get('details', {})
                self.features_map[name] = features
            
            self.classification_history = data.get('classification_history', [])
            logger.info("Rule classifier ML state loaded (%d rules)", len(self.features_map))
        except Exception as e:
            logger.error("Failed to load rule classifier ML state: %s", e)
