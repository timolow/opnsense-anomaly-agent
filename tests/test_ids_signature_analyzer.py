#!/usr/bin/env python3
"""Tests for the IDS signature analyzer."""

import pytest
import os
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

# Add project root to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ids_signature_analyzer import IDSSignatureAnalyzer, IDSSignature


class TestIDSSignature:
    """Test the IDSSignature dataclass."""
    
    def test_unknown_with_few_triggers(self):
        """Signature with < MIN_SIGNATURE_EVENTS is UNKNOWN."""
        s = IDSSignature(name="Test Sig")
        assert s.classification == "UNKNOWN"
    
    def test_high_priority(self):
        """Signature with priority 1 is HIGH_PRIORITY."""
        s = IDSSignature(name="Test Sig", priority=1, trigger_count=5)
        assert s.classification == "HIGH_PRIORITY"
    
    def test_medium_priority(self):
        """Signature with priority 2-3 is MEDIUM_PRIORITY."""
        s = IDSSignature(name="Test Sig", priority=2, trigger_count=5)
        assert s.classification == "MEDIUM_PRIORITY"
    
    def test_low_priority(self):
        """Signature with priority 4+ is LOW_PRIORITY."""
        s = IDSSignature(name="Test Sig", priority=5, trigger_count=5)
        assert s.classification == "LOW_PRIORITY"


class TestIDSSignatureAnalyzer:
    """Test the IDSSignatureAnalyzer class."""
    
    def test_process_event(self):
        """Process an IDS event and update signature."""
        c = IDSSignatureAnalyzer(min_events=1)
        event = {
            'rule': 'ET SCAN SSH Scan',
            'priority_score': 2,
            'src_ip': '1.2.3.4',
            'dst_ip': '5.6.7.8',
            'dport': 22,
            'proto': 'TCP',
            'log_type': 'ids',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        c.process_event(event)
        assert c.events_with_signature == 1
        assert c.events_without_signature == 0
        assert 'ET SCAN SSH Scan' in c.signatures
    
    def test_process_event_without_signature(self):
        """IDS event without signature name increments without_signature counter."""
        c = IDSSignatureAnalyzer(min_events=1)
        event = {
            'src_ip': '1.2.3.4',
            'log_type': 'ids',
        }
        c.process_event(event)
        assert c.events_with_signature == 0
        assert c.events_without_signature == 1
    
    def test_detect_new_signature(self):
        """New signature (≤3 triggers) triggers NEW_SIGNATURE anomaly."""
        c = IDSSignatureAnalyzer(min_events=3)
        for i in range(2):
            event = {
                'rule': 'New Signature',
                'priority_score': 3,
                'src_ip': '1.2.3.4',
                'dst_ip': '5.6.7.8',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'NEW_SIGNATURE' for a in anomalies)
    
    def test_detect_signature_spike(self):
        """Signature with unusually high trigger count triggers SIGNATURE_SPIKE."""
        c = IDSSignatureAnalyzer(min_events=1, spike_zscore=2.0)
        
        # Create some low-frequency signatures
        for i in range(5):
            event = {
                'rule': f'Low Freq {i}',
                'priority_score': 3,
                'src_ip': '1.2.3.4',
                'dst_ip': '5.6.7.8',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        # Create one high-frequency signature
        for i in range(30):
            event = {
                'rule': 'Spiky Signature',
                'priority_score': 2,
                'src_ip': '1.2.3.5',
                'dst_ip': '5.6.7.9',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'SIGNATURE_SPIKE' for a in anomalies)
    
    def test_detect_cross_network(self):
        """Signature targeting many hosts triggers CROSS_NETWORK."""
        c = IDSSignatureAnalyzer(min_events=3)
        for i in range(15):
            event = {
                'rule': 'Wide Scan',
                'priority_score': 1,
                'src_ip': '1.2.3.4',
                'dst_ip': f'5.6.7.{i}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'CROSS_NETWORK' for a in anomalies)
    
    def test_detect_multiple_new_signatures(self):
        """5+ new signatures trigger MULTIPLE_NEW_SIGNATURES."""
        c = IDSSignatureAnalyzer(min_events=3)
        
        for sig in range(7):
            for i in range(2):
                event = {
                    'rule': f'New Sig {sig}',
                    'priority_score': 3,
                    'src_ip': '1.2.3.4',
                    'dst_ip': '5.6.7.8',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }
                c.process_event(event)
        
        anomalies = c.detect_anomalies()
        assert any(a['type'] == 'MULTIPLE_NEW_SIGNATURES' for a in anomalies)
    
    def test_get_signature_classification(self):
        """Get classification of a specific signature."""
        c = IDSSignatureAnalyzer(min_events=1)
        for _ in range(3):
            event = {
                'rule': 'Test Sig',
                'priority_score': 1,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        assert c.get_signature_classification('Test Sig') == "HIGH_PRIORITY"
        assert c.get_signature_classification('Nonexistent') == "UNKNOWN"
    
    def test_get_all_signatures(self):
        """Get all signatures sorted by trigger count."""
        c = IDSSignatureAnalyzer(min_events=1)
        for name in ['A', 'B', 'A', 'B', 'A']:
            event = {
                'rule': name,
                'priority_score': 2,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            c.process_event(event)
        
        sigs = c.get_all_known_signatures()
        assert len(sigs) == 2
        assert sigs[0]['signature'] == 'A'  # 3 triggers
        assert sigs[1]['signature'] == 'B'  # 2 triggers
    
    def test_get_summary(self):
        """Get signature statistics summary."""
        c = IDSSignatureAnalyzer(min_events=1)
        event = {
            'rule': 'Test Sig',
            'priority_score': 2,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        c.process_event(event)
        
        summary = c.get_summary()
        assert summary['total_events'] == 1
        assert summary['events_with_signature'] == 1
        assert summary['known_signatures_count'] == 1
    
    def test_save_and_load_state(self, tmp_path):
        """Test save and load state persistence."""
        filepath = str(tmp_path / "ids_state.json")
        c = IDSSignatureAnalyzer(min_events=1)
        
        event = {
            'rule': 'Test Sig',
            'priority_score': 2,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        c.process_event(event)
        
        # Save
        c.save_state(filepath)
        assert os.path.exists(filepath)
        
        # Load into new instance
        c2 = IDSSignatureAnalyzer(min_events=1)
        c2.load_state(filepath)
        
        assert 'Test Sig' in c2.signatures
        assert c2.signatures['Test Sig'].trigger_count == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
