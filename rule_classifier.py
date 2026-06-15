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
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Default classification thresholds
MIN_RULE_EVENTS = 10
DEFAULT_DENY_THRESHOLD = 0.7


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
        """Classify the rule as PERMIT, DENY, or UNCLASSIFIED."""
        if self.total_events < MIN_RULE_EVENTS:
            return "UNCERTAIN"
        if self.is_permit_rule:
            return "PERMIT"
        if self.is_deny_rule:
            return "DENY"
        return "MIXED"


class RuleClassifier:
    """
    Classifies firewall rules and learns which are permitted vs denied.
    """
    
    def __init__(self, min_events=MIN_RULE_EVENTS, deny_threshold=DEFAULT_DENY_THRESHOLD):
        self.min_events = min_events
        self.deny_threshold = deny_threshold
        self.rule_profiles: Dict[str, RuleProfile] = {}
        self.total_events = 0
        self.events_with_rule = 0
        self.events_without_rule = 0
        self.traffic_baselines: Counter = Counter()
        
        logger.info("RuleClassifier initialized (min_events=%d, deny_threshold=%.2f)",
                    min_events, deny_threshold)
    
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
        else:
            self.events_without_rule += 1
            self._update_traffic_baseline(action, src_ip, dst_ip, dst_port)
    
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
