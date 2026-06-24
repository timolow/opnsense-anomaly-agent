#!/usr/bin/env python3
"""
IDS Signature Analyzer — tracks IDS/Snort/Suricata signatures and detects anomalies.

Unlike filterlog/zenarmor which track rules/policies, this tracks
individual IDS signatures (rules) that trigger on network traffic:

Classification:
- HIGH_PRIORITY: Signature with priority 1 (most critical)
- MEDIUM_PRIORITY: Signature with priority 2-3
- LOW_PRIORITY: Signature with priority 4+
- UNKNOWN_PRIORITY: Signature without priority information

Anomaly Detection:
- NEW_SIGNATURE: New IDS signature appearing
- SIGNATURE_SPIKE: Signature with abnormally high trigger count
- TARGET_CHANGE: Signature suddenly targeting different IPs/ports
- CROSS_NETWORK: Signature triggered across many distinct networks

This complements the attack detectors by adding IDS-specific analysis
on top of the existing event pipeline.
"""

import logging
from datetime import datetime, timezone, timedelta
from collections import Counter
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Classification thresholds
MIN_SIGNATURE_EVENTS = 3
SPIKE_ZSCORE = 3.0
SIGNATURE_CHANGE_THRESHOLD = 0.5


@dataclass
class IDSSignature:
    """Profile of an IDS signature's behavior."""
    name: str
    priority: int = 0
    trigger_count: int = 0
    src_ips: Set = field(default_factory=set)
    dst_ips: Set = field(default_factory=set)
    dst_ports: Set = field(default_factory=set)
    protocols: Set = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    _trigger_history: List[int] = field(default_factory=list)
    _action_history: List[float] = field(default_factory=list)

    @property
    def classification(self) -> str:
        """Classify signature by priority level."""
        if self.trigger_count < 3:  # MIN_SIGNATURE_EVENTS
            return "UNKNOWN"
        if self.priority <= 1:
            return "HIGH_PRIORITY"
        if self.priority <= 3:
            return "MEDIUM_PRIORITY"
        return "LOW_PRIORITY"

    @property
    def unique_targets(self) -> int:
        """Number of unique destination IPs this signature targets."""
        return len(self.dst_ips)

    @property
    def unique_targets_recent(self) -> Set:
        """Unique destination IPs in the last 5 triggers."""
        return set(list(self._action_history)[:5]) if self._action_history else set()


class IDSSignatureAnalyzer:
    """
    Analyzes IDS signatures and detects anomalies in their behavior.
    
    Tracks individual signatures (rules) from IDS/Snort/Suricata logs,
    counts triggers, and detects anomalies like:
    - New signatures appearing
    - Signature spikes (unusually high trigger count)
    - Target changes (suddenly targeting different IPs/ports)
    - Cross-network behavior (targets many distinct networks)
    """

    def __init__(self, min_events=MIN_SIGNATURE_EVENTS,
                 spike_zscore=SPIKE_ZSCORE,
                 change_threshold=SIGNATURE_CHANGE_THRESHOLD):
        self.min_events = min_events
        self.spike_zscore = spike_zscore
        self.change_threshold = change_threshold
        self.signatures: Dict[str, IDSSignature] = {}
        self.total_events = 0
        self.events_with_signature = 0
        self.events_without_signature = 0
        self.anomalies: List[Dict[str, Any]] = []

        logger.info("IDSSignatureAnalyzer initialized "
                    "(min_events=%d, spike_zscore=%.1f, "
                    "change_threshold=%.2f)",
                    min_events, spike_zscore, change_threshold)

    def process_event(self, event: Dict[str, Any],
                      timestamp: Optional[datetime] = None):
        """Process a single IDS event and update signature profiles."""
        self.total_events += 1

        # IDS events use 'rule' field for signature name
        sig_name = event.get('rule')
        priority = event.get('priority_score', 0)
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dport')
        proto = event.get('proto', 'UNKNOWN')

        if sig_name:
            self.events_with_signature += 1
            self._update_signature(sig_name, priority, src_ip, dst_ip, dst_port, proto, timestamp)
        else:
            self.events_without_signature += 1
            logger.warning("IDS event without signature name: %s",
                          event.get('raw', '')[:100])

    def _update_signature(self, sig_name: str, priority: int,
                          src_ip: Optional[str], dst_ip: Optional[str],
                          dst_port: Optional[int], proto: str,
                          timestamp: Optional[datetime]):
        """Update the profile for a specific IDS signature."""
        if sig_name not in self.signatures:
            self.signatures[sig_name] = IDSSignature(name=sig_name, priority=priority)
        
        profile = self.signatures[sig_name]
        profile.trigger_count += 1
        
        # Update priority (keep highest priority seen)
        if priority > 0 and priority < profile.priority:
            profile.priority = priority
        
        if src_ip:
            profile.src_ips.add(src_ip)
        if dst_ip:
            profile.dst_ips.add(dst_ip)
        if dst_port:
            profile.dst_ports.add(dst_port)
        if proto:
            profile.protocols.add(proto)
        
        if timestamp:
            if profile.first_seen is None or timestamp < profile.first_seen:
                profile.first_seen = timestamp
            if profile.last_seen is None or timestamp > profile.last_seen:
                profile.last_seen = timestamp
        
        # Track trigger history (1 per event, last 100 events)
        profile._trigger_history.append(1)
        if len(profile._trigger_history) > 100:
            profile._trigger_history.pop(0)
        
        # Track recent targets for change detection
        profile._action_history.append(dst_ip or 'unknown')
        if len(profile._action_history) > 20:
            profile._action_history.pop(0)

    def detect_anomalies(self, current_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Detect anomalies in IDS signature behavior."""
        self.anomalies = []
        now = current_time or datetime.now(timezone.utc)

        # Build trigger counts for spike detection
        trigger_counts = [p.trigger_count for p in self.signatures.values()]
        mean_count = sum(trigger_counts) / len(trigger_counts) if trigger_counts else 0
        variance = sum((c - mean_count) ** 2 for c in trigger_counts) / max(len(trigger_counts) - 1, 1) if len(trigger_counts) > 1 else 0
        std_dev = variance ** 0.5

        for name, profile in self.signatures.items():
            # NEW_SIGNATURE: Recently appeared with very few triggers
            if profile.trigger_count <= 3 and profile.trigger_count > 0:
                age = (now - profile.first_seen).total_seconds() if profile.first_seen else 0
                self.anomalies.append({
                    'type': 'NEW_SIGNATURE',
                    'severity': 'MEDIUM',
                    'signature': name,
                    'priority': profile.priority,
                    'description': f"New IDS signature '{name}' triggered ({profile.trigger_count} times, age: {age:.0f}s)",
                    'trigger_count': profile.trigger_count,
                    'age_seconds': age,
                })
            
            # SIGNATURE_SPIKE: Unusually high trigger count
            if std_dev > 0 and profile.trigger_count > mean_count + self.spike_zscore * std_dev:
                self.anomalies.append({
                    'type': 'SIGNATURE_SPIKE',
                    'severity': 'HIGH',
                    'signature': name,
                    'priority': profile.priority,
                    'description': f"Signature '{name}' spike: {profile.trigger_count} triggers "
                                  f"(mean: {mean_count:.0f}, z-score: {(profile.trigger_count - mean_count) / std_dev:.1f})",
                    'trigger_count': profile.trigger_count,
                    'mean_count': round(mean_count, 1),
                    'z_score': round((profile.trigger_count - mean_count) / std_dev, 1) if std_dev > 0 else 0,
                })
            
            # TARGET_CHANGE: Signature suddenly targeting different IPs
            if len(profile._action_history) >= 10:
                recent = set(profile._action_history[-5:])
                earlier = set(profile._action_history[:-5])
                if len(earlier) > 0:
                    overlap = len(recent.intersection(earlier))
                    change_ratio = 1.0 - (overlap / len(earlier)) if earlier else 0
                    if change_ratio >= self.change_threshold:
                        self.anomalies.append({
                            'type': 'TARGET_CHANGE',
                            'severity': 'HIGH',
                            'signature': name,
                            'priority': profile.priority,
                            'description': f"Signature '{name}' targets changed: "
                                          f"{change_ratio:.0%} overlap with earlier targets",
                            'change_ratio': round(change_ratio, 2),
                            'recent_targets': list(recent)[:10],
                            'earlier_targets': list(earlier)[:10],
                        })
            
            # CROSS_NETWORK: Signature targeting many distinct networks
            if profile.trigger_count >= self.min_events:
                unique_dsts = len(profile.dst_ips)
                if unique_dsts >= 10:
                    self.anomalies.append({
                        'type': 'CROSS_NETWORK',
                        'severity': 'HIGH',
                        'signature': name,
                        'priority': profile.priority,
                        'description': f"Signature '{name}' targets {unique_dsts} distinct hosts",
                        'unique_dst_count': unique_dsts,
                    })

        # Track overall system-level anomalies
        if self.total_events > 10:
            unique_sigs = len(self.signatures)
            # Many new signatures appearing (potential IDS rule update)
            new_sigs = sum(1 for p in self.signatures.values() 
                          if p.trigger_count <= 3 and p.trigger_count > 0)
            if new_sigs >= 5:
                self.anomalies.append({
                    'type': 'MULTIPLE_NEW_SIGNATURES',
                    'severity': 'MEDIUM',
                    'description': f"Multiple new IDS signatures detected: {new_sigs} "
                                  f"out of {unique_sigs} unique signatures",
                    'new_signature_count': new_sigs,
                    'total_unique_signatures': unique_sigs,
                })

        return self.anomalies

    def get_signature_classification(self, sig_name: str) -> str:
        """Get the classification of a specific signature."""
        if sig_name not in self.signatures:
            return "UNKNOWN"
        return self.signatures[sig_name].classification

    def get_all_known_signatures(self) -> List[Dict[str, Any]]:
        """Return all known signatures with their classifications."""
        sigs = []
        for name, profile in self.signatures.items():
            sigs.append({
                'signature': name,
                'classification': profile.classification,
                'priority': profile.priority,
                'trigger_count': profile.trigger_count,
                'unique_src_ips': len(profile.src_ips),
                'unique_dst_ips': len(profile.dst_ips),
                'unique_dst_ports': len(profile.dst_ports),
                'protocols': list(profile.protocols),
                'first_seen': profile.first_seen.isoformat() if profile.first_seen else None,
                'last_seen': profile.last_seen.isoformat() if profile.last_seen else None,
            })
        sigs.sort(key=lambda x: -x['trigger_count'])
        return sigs

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of IDS signature statistics."""
        classifications = Counter(p.classification for p in self.signatures.values())
        return {
            'total_events': self.total_events,
            'events_with_signature': self.events_with_signature,
            'events_without_signature': self.events_without_signature,
            'known_signatures_count': len(self.signatures),
            'signatures_by_classification': dict(classifications),
            'top_signatures': [
                {'name': name, 'triggers': profile.trigger_count,
                 'classification': profile.classification,
                 'priority': profile.priority}
                for name, profile in sorted(self.signatures.items(),
                                           key=lambda x: -x[1].trigger_count)[:10]
            ],
        }

    # State persistence is handled centrally by StatePersistence in state_persistence.py
    # (saves to state.json alongside all other agent modules)
