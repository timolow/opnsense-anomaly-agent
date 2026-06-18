#!/usr/bin/env python3
"""
ZenArmor Rule Classifier — tracks ZenArmor policies and detects anomalies.

Unlike rule_classifier.py which focuses on firewall rules, this tracks
ZenArmor security gateway policies:

Classification:
- ALLOW_POLICY: Policy that mostly allows traffic
- BLOCK_POLICY: Policy that mostly blocks traffic
- MIXED_POLICY: Policy with mixed allow/block behavior
- UNKNOWN_POLICY: Policy with too few events to classify

Anomaly Detection:
- NEW_POLICY: New ZenArmor policy appearing
- POLICY_CHANGE: Policy that has changed its action pattern significantly
- BLOCK_SPIKE: Policy with abnormally high block rate (potential new threat)
- BLOCK_RATE_CHANGE: Policy whose block rate changed significantly

This complements rule_classifier.py (firewall rules) by adding ZenArmor
policy-level tracking on top of the existing event pipeline.
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Classification thresholds
MIN_POLICY_EVENTS = 5
BLOCK_SPIKE_ZSCORE = 3.0
CHANGE_THRESHOLD = 0.4  # Change ratio to flag as POLICY_CHANGE


@dataclass
class ZenArmorPolicy:
    """Profile of a ZenArmor policy's behavior."""
    name: str
    actions: Counter = field(default_factory=Counter)
    src_ips: Set = field(default_factory=set)
    dst_ips: Set = field(default_factory=set)
    dst_ports: Set = field(default_factory=set)
    total_events: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    _action_history: List[float] = field(default_factory=list)

    @property
    def is_allow_policy(self) -> Optional[bool]:
        """If mostly PASS/ALLOW actions -> allow policy."""
        if self.total_events < 5:  # MIN_POLICY_EVENTS
            return None
        pass_ratio = self.actions.get('PASS', 0) / self.total_events
        return pass_ratio > 0.5

    @property
    def is_block_policy(self) -> Optional[bool]:
        """If mostly BLOCK actions -> block policy."""
        if self.total_events < 5:  # MIN_POLICY_EVENTS
            return None
        block_ratio = self.actions.get('BLOCK', 0) / self.total_events
        return block_ratio > 0.5

    @property
    def classification(self) -> str:
        """Classify the policy as ALLOW, BLOCK, MIXED, or UNKNOWN."""
        if self.total_events < 5:  # MIN_POLICY_EVENTS
            return "UNKNOWN"
        if self.is_allow_policy:
            return "ALLOW"
        if self.is_block_policy:
            return "BLOCK"
        return "MIXED"

    @property
    def block_ratio(self) -> float:
        """Current block ratio for this policy."""
        if self.total_events == 0:
            return 0.0
        return self.actions.get('BLOCK', 0) / self.total_events


class ZenArmorClassifier:
    """
    Classifies ZenArmor policies and detects anomalies in their behavior.
    
    Unlike filterlog rules which have fixed RUIDs, ZenArmor policies are
    named strings (e.g., "Block External", "Allow HTTPS"). This class
    tracks their usage patterns and detects changes.
    """

    def __init__(self, min_events=MIN_POLICY_EVENTS, 
                 block_spike_zscore=BLOCK_SPIKE_ZSCORE,
                 change_threshold=CHANGE_THRESHOLD):
        self.min_events = min_events
        self.block_spike_zscore = block_spike_zscore
        self.change_threshold = change_threshold
        self.policies: Dict[str, ZenArmorPolicy] = {}
        self.total_events = 0
        self.events_with_policy = 0
        self.events_without_policy = 0
        self.anomalies: List[Dict[str, Any]] = []

        logger.info("ZenArmorClassifier initialized "
                    "(min_events=%d, block_spike_zscore=%.1f, "
                    "change_threshold=%.2f)",
                    min_events, block_spike_zscore, change_threshold)

    def process_event(self, event: Dict[str, Any], 
                      timestamp: Optional[datetime] = None):
        """Process a single ZenArmor event and update policy profiles."""
        self.total_events += 1

        # ZenArmor events use 'rule' field for policy name
        policy_name = event.get('rule') or event.get('policy')
        action = event.get('action', '').upper()
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dport')

        if policy_name:
            self.events_with_policy += 1
            self._update_policy(policy_name, action, src_ip, dst_ip, dst_port, timestamp)
        else:
            self.events_without_policy += 1
            logger.warning("ZenArmor event without policy name: %s", 
                          event.get('raw', '')[:100])

    def _update_policy(self, policy_name: str, action: str,
                       src_ip: Optional[str], dst_ip: Optional[str],
                       dst_port: Optional[int], 
                       timestamp: Optional[datetime]):
        """Update the profile for a specific ZenArmor policy."""
        if policy_name not in self.policies:
            self.policies[policy_name] = ZenArmorPolicy(name=policy_name)
        
        profile = self.policies[policy_name]
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
        
        # Track action history for change detection (last 20 events)
        action_value = 1.0 if action in ('PASS', 'ALLOW', 'PERMIT') else 0.0
        profile._action_history.append(action_value)
        if len(profile._action_history) > 20:
            profile._action_history.pop(0)

    def detect_anomalies(self, current_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Detect anomalies in ZenArmor policy usage patterns."""
        self.anomalies = []
        now = current_time or datetime.now(timezone.utc)

        for name, profile in self.policies.items():
            # NEW_POLICY: Recently appeared with very few events
            if profile.total_events <= 3 and profile.total_events > 0:
                age = (now - profile.first_seen).total_seconds() if profile.first_seen else 0
                self.anomalies.append({
                    'type': 'NEW_POLICY',
                    'severity': 'MEDIUM',
                    'policy_name': name,
                    'description': f"New ZenArmor policy '{name}' detected ({profile.total_events} events, age: {age:.0f}s)",
                    'events': profile.total_events,
                    'actions': dict(profile.actions),
                    'age_seconds': age,
                })
            
            # POLICY_CHANGE: Policy action ratio changed significantly
            if profile.total_events >= self.min_events and len(profile._action_history) >= 5:
                recent = profile._action_history[-5:]
                earlier = profile._action_history[:-5]
                if len(earlier) >= 5:
                    recent_mean = sum(recent) / len(recent)
                    earlier_mean = sum(earlier) / len(earlier)
                    change = abs(recent_mean - earlier_mean)
                    if change >= self.change_threshold:
                        self.anomalies.append({
                            'type': 'POLICY_CHANGE',
                            'severity': 'HIGH',
                            'policy_name': name,
                            'description': f"Policy '{name}' changed behavior: "
                                          f"allow ratio {earlier_mean:.0%} -> {recent_mean:.0%}",
                            'actions': dict(profile.actions),
                            'change_ratio': change,
                            'earlier_mean': round(earlier_mean, 3),
                            'recent_mean': round(recent_mean, 3),
                        })
            
            # BLOCK_SPIKE: Policy with very high block rate
            if profile.total_events >= self.min_events:
                block_ratio = profile.block_ratio
                if block_ratio > 0.8 and profile.actions.get('BLOCK', 0) > 5:
                    self.anomalies.append({
                        'type': 'BLOCK_SPIKE',
                        'severity': 'HIGH',
                        'policy_name': name,
                        'description': f"Policy '{name}' blocking {block_ratio:.0%} "
                                      f"of traffic ({profile.actions.get('BLOCK', 0)} blocks "
                                      f"out of {profile.total_events} events)",
                        'block_ratio': block_ratio,
                        'actions': dict(profile.actions),
                    })
            
            # MIXED_POLICY: Policy with roughly equal allow/block (suspicious)
            if profile.total_events >= self.min_events:
                pass_ratio = profile.actions.get('PASS', 0) / profile.total_events
                if 0.3 < pass_ratio < 0.7:
                    self.anomalies.append({
                        'type': 'MIXED_POLICY',
                        'severity': 'LOW',
                        'policy_name': name,
                        'description': f"Policy '{name}' has mixed behavior: "
                                      f"PASS={profile.actions.get('PASS', 0)}, "
                                      f"BLOCK={profile.actions.get('BLOCK', 0)}",
                        'pass_ratio': round(pass_ratio, 2),
                    })

        # Track overall system-level anomalies
        if self.total_events > 50:
            total_blocks = sum(p.actions.get('BLOCK', 0) for p in self.policies.values())
            total_blocks_ratio = total_blocks / self.total_events
            
            # System-wide block rate spike
            if total_blocks_ratio > 0.5:
                self.anomalies.append({
                    'type': 'SYSTEM_BLOCK_SPIKE',
                    'severity': 'HIGH',
                    'description': f"System-wide ZenArmor block rate elevated: "
                                  f"{total_blocks_ratio:.0%} ({total_blocks}/{self.total_events})",
                    'block_ratio': total_blocks_ratio,
                    'total_events': self.total_events,
                    'total_blocks': total_blocks,
                })

        return self.anomalies

    def get_policy_classification(self, policy_name: str) -> str:
        """Get the classification of a specific policy."""
        if policy_name not in self.policies:
            return "UNKNOWN"
        return self.policies[policy_name].classification

    def get_all_known_policies(self) -> List[Dict[str, Any]]:
        """Return all known policies with their classifications."""
        policies = []
        for name, profile in self.policies.items():
            policies.append({
                'policy_name': name,
                'classification': profile.classification,
                'total_events': profile.total_events,
                'actions': dict(profile.actions),
                'unique_src_ips': len(profile.src_ips),
                'unique_dst_ips': len(profile.dst_ips),
                'unique_dst_ports': len(profile.dst_ports),
                'block_ratio': profile.block_ratio,
                'first_seen': profile.first_seen.isoformat() if profile.first_seen else None,
                'last_seen': profile.last_seen.isoformat() if profile.last_seen else None,
            })
        policies.sort(key=lambda x: -x['total_events'])
        return policies

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of ZenArmor policy statistics."""
        classifications = Counter(p.classification for p in self.policies.values())
        return {
            'total_events': self.total_events,
            'events_with_policy': self.events_with_policy,
            'events_without_policy': self.events_without_policy,
            'known_policies_count': len(self.policies),
            'policies_by_classification': dict(classifications),
            'top_policies': [
                {'name': name, 'events': profile.total_events, 
                 'classification': profile.classification}
                for name, profile in sorted(self.policies.items(),
                                           key=lambda x: -x[1].total_events)[:10]
            ],
        }

    def save_state(self, filepath: str = None):
        """Save policy profiles to disk."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "zenarmor_state.json")
        
        state = {
            'policies': {name: {
                'name': p.name,
                'actions': dict(p.actions),
                'total_events': p.total_events,
                'first_seen': p.first_seen.isoformat() if p.first_seen else None,
                'last_seen': p.last_seen.isoformat() if p.last_seen else None,
                'action_history': p._action_history,
            } for name, p in self.policies.items()},
            'summary': self.get_summary(),
            'total_events': self.total_events,
            'events_with_policy': self.events_with_policy,
            'events_without_policy': self.events_without_policy,
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        logger.info("ZenArmor classifier state saved to %s", filepath)

    def load_state(self, filepath: str = None):
        """Load policy profiles from disk."""
        if filepath is None:
            base_dir = os.environ.get("AGENT_DATA_DIR", "/app/agent_data")
            filepath = os.path.join(base_dir, "zenarmor_state.json")
        
        if not os.path.exists(filepath):
            logger.info("No ZenArmor state file found at %s", filepath)
            return
        
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            for name, data in state.get('policies', {}).items():
                profile = ZenArmorPolicy(
                    name=data['name'],
                    total_events=data.get('total_events', 0),
                )
                profile.actions = Counter(data.get('actions', {}))
                profile.first_seen = datetime.fromisoformat(data['first_seen']) if data.get('first_seen') else None
                profile.last_seen = datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None
                profile._action_history = data.get('action_history', [])
                self.policies[name] = profile
            
            self.total_events = state.get('total_events', 0)
            self.events_with_policy = state.get('events_with_policy', 0)
            self.events_without_policy = state.get('events_without_policy', 0)
            
            logger.info("ZenArmor classifier state loaded from %s (%d policies)", 
                       filepath, len(self.policies))
        except Exception as e:
            logger.error("Failed to load ZenArmor state: %s", e)
