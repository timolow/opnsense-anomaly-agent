#!/usr/bin/env python3
"""Tests for the ZenArmor rule classifier."""

import pytest
import os
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from unittest.mock import patch, mock_open

# Add project root to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from zenarmor_classifier import ZenArmorClassifier, ZenArmorPolicy


class TestZenArmorPolicy:
    """Test the ZenArmorPolicy dataclass."""
    
    def test_unknown_with_few_events(self):
        """Policy with < MIN_POLICY_EVENTS events is UNKNOWN."""
        p = ZenArmorPolicy(name="Test Policy")
        assert p.classification == "UNKNOWN"
        assert p.is_allow_policy is None
        assert p.is_block_policy is None
    
    def test_allow_policy(self):
        """Policy with mostly PASS is classified as ALLOW."""
        p = ZenArmorPolicy(name="Allow Policy")
        for _ in range(10):
            p.total_events += 1
            p.actions['PASS'] += 1
        assert p.is_allow_policy is True
        assert p.is_block_policy is False
        assert p.classification == "ALLOW"
        assert p.block_ratio == 0.0
    
    def test_block_policy(self):
        """Policy with mostly BLOCK is classified as BLOCK."""
        p = ZenArmorPolicy(name="Block Policy")
        for _ in range(10):
            p.total_events += 1
            p.actions['BLOCK'] += 1
        assert p.is_allow_policy is False
        assert p.is_block_policy is True
        assert p.classification == "BLOCK"
        assert p.block_ratio == 1.0
    
    def test_mixed_policy(self):
        """Policy with roughly equal PASS/BLOCK is MIXED."""
        p = ZenArmorPolicy(name="Mixed Policy")
        for _ in range(10):
            p.total_events += 1
            p.actions['PASS'] += 1 if _ % 2 == 0 else 0
            p.actions['BLOCK'] += 1 if _ % 2 == 1 else 0
        assert p.classification == "MIXED"


class TestZenArmorClassifier:
    """Test the ZenArmorClassifier class."""
    
    def test_process_event(self):
        """Process a ZenArmor event and update policy."""
        c = ZenArmorClassifier(min_events=1)
        event = {
            'rule': 'Block External',
            'action': 'BLOCK',
            'src_ip': '1.2.3.4',
            'dst_ip': '5.6.7.8',
            'dport': 80,
            'log_type': 'zenarmor',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        c.process_event(event)
        assert c.events_with_policy == 1
        assert c.events_without_policy == 0
        assert 'Block External' in c.policies
    
    def test_process_event_without_policy(self):
        """ZenArmor event without policy name increments without_policy counter."""
        c = ZenArmorClassifier(min_events=1)
        event = {
            'action': 'BLOCK',
            'src_ip': '1.2.3.4',
            'log_type': 'zenarmor',
        }
        c.process_event(event)
        assert c.events_with_policy == 0
        assert c.events_without_policy == 1
    
    def test_detect_new_policy(self):
        """New policy (≤3 events) triggers NEW_POLICY anomaly."""
        c = ZenArmorClassifier(min_events=3)
        for i in range(2):
            event = {
                'rule': 'New Policy',
                'action': 'BLOCK',
                'src_ip': '1.2.3.4',
                'dst_ip': '5.6.7.8',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'NEW_POLICY' for a in anomalies)
    
    def test_detect_block_spike(self):
        """Policy with >80% block rate triggers BLOCK_SPIKE."""
        c = ZenArmorClassifier(min_events=3)
        for i in range(10):
            event = {
                'rule': 'Heavy Block',
                'action': 'BLOCK',
                'src_ip': '1.2.3.4',
                'dst_ip': '5.6.7.8',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'BLOCK_SPIKE' for a in anomalies)
    
    def test_detect_policy_change(self):
        """Policy with changed behavior ratio triggers POLICY_CHANGE."""
        c = ZenArmorClassifier(min_events=3, change_threshold=0.2)
        
        # First 5 events: all PASS
        for i in range(5):
            event = {
                'rule': 'Changing Policy',
                'action': 'PASS',
                'src_ip': '1.2.3.4',
                'timestamp': (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            }
            c.process_event(event)
        
        # Last 5 events: all BLOCK
        for i in range(5):
            event = {
                'rule': 'Changing Policy',
                'action': 'BLOCK',
                'src_ip': '1.2.3.4',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'POLICY_CHANGE' for a in anomalies)
    
    def test_detect_system_block_spike(self):
        """System-wide block rate >50% triggers SYSTEM_BLOCK_SPIKE."""
        c = ZenArmorClassifier(min_events=3)
        
        # Add enough events to trigger system check (>50)
        for i in range(60):
            event = {
                'rule': 'Block Policy',
                'action': 'BLOCK',
                'src_ip': f'1.2.3.{i}',
                'dst_ip': '5.6.7.8',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'SYSTEM_BLOCK_SPIKE' for a in anomalies)
    
    def test_get_policy_classification(self):
        """Get classification of a specific policy."""
        c = ZenArmorClassifier(min_events=1)
        for _ in range(6):  # >= MIN_POLICY_EVENTS (5)
            event = {
                'rule': 'Test Policy',
                'action': 'BLOCK',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        assert c.get_policy_classification('Test Policy') == "BLOCK"
        assert c.get_policy_classification('Nonexistent') == "UNKNOWN"
    
    def test_get_all_policies(self):
        """Get all policies sorted by event count."""
        c = ZenArmorClassifier(min_events=1)
        for name in ['A', 'B', 'A', 'B', 'A']:
            event = {
                'rule': name,
                'action': 'BLOCK',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        policies = c.get_all_known_policies()
        assert len(policies) == 2
        assert policies[0]['policy_name'] == 'A'  # 3 events
        assert policies[1]['policy_name'] == 'B'  # 2 events
    
    def test_get_summary(self):
        """Get policy statistics summary."""
        c = ZenArmorClassifier(min_events=1)
        event = {
            'rule': 'Block Policy',
            'action': 'BLOCK',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        c.process_event(event)
        
        summary = c.get_summary()
        assert summary['total_events'] == 1
        assert summary['events_with_policy'] == 1
        assert summary['known_policies_count'] == 1
    
    def test_save_and_load_state(self, tmp_path):
        """Test save and load state persistence."""
        filepath = str(tmp_path / "zenarmor_state.json")
        c = ZenArmorClassifier(min_events=1)
        
        # Process some events
        event = {
            'rule': 'Test Policy',
            'action': 'BLOCK',
            'src_ip': '1.2.3.4',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        c.process_event(event)
        
        # Save
        c.save_state(filepath)
        assert os.path.exists(filepath)
        
        # Load into new instance
        c2 = ZenArmorClassifier(min_events=1)
        c2.load_state(filepath)
        
        assert 'Test Policy' in c2.policies
        assert c2.policies['Test Policy'].total_events == 1
    
    def test_multiple_policies(self):
        """Process events for multiple policies."""
        c = ZenArmorClassifier(min_events=1)
        
        policies = [
            ('Allow DNS', 'PASS', 53),
            ('Block Malware', 'BLOCK', 443),
            ('Allow HTTP', 'PASS', 80),
        ]
        
        for policy_name, action, port in policies:
            for i in range(5):  # >= min_events (1) but enough to get classification
                event = {
                    'rule': policy_name,
                    'action': action,
                    'src_ip': f'1.2.3.{i}',
                    'dst_ip': '5.6.7.8',
                    'dport': port,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }
                c.process_event(event)
        
        # Verify all policies tracked and classified
        assert len(c.policies) == 3
        assert c.get_policy_classification('Allow DNS') == "ALLOW"
        assert c.get_policy_classification('Block Malware') == "BLOCK"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
