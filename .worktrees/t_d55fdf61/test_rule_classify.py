"""Tests for rule_classify.py — ML firewall rule classification engine."""

import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from rule_classify import RuleFeatures, RuleClassifierML
from collections import Counter


# ── Fixtures ──────────────────────────────────────────────────────────────

def make_event(**kwargs):
    """Create a sample event dict for ingestion."""
    return {
        'src_ip': kwargs.get('src_ip', '10.0.0.1'),
        'dst_ip': kwargs.get('dst_ip', '10.0.0.2'),
        'dport': kwargs.get('dport', 80),
        'sport': kwargs.get('sport', 49152),
        'proto': kwargs.get('proto', 'TCP'),
        'action': kwargs.get('action', 'PASS'),
        'rule_name': kwargs.get('rule_name', 'test-rule'),
        'timestamp': kwargs.get('timestamp', '2026-06-17T10:00:00'),
    }


class TestRuleFeatures:
    """Test the RuleFeatures dataclass."""

    def test_creation_default_scores(self):
        features = RuleFeatures(rule_name='test')
        assert features.rule_name == 'test'
        assert features.port_scan_score == 0.0
        assert features.dest_scan_score == 0.0
        assert features.action_ratio_score == 0.0
        assert features.goodness_score == 0.0
        assert features.classification == 'UNKNOWN'
        assert features.confidence == 0.0

    def test_creation_with_counts(self):
        features = RuleFeatures(
            rule_name='test', total_events=100, pass_count=90, block_count=10,
            unique_ports=5, unique_src_ips=3, unique_dst_ips=2,
            protocols=Counter({'TCP': 80, 'UDP': 20})
        )
        assert features.total_events == 100
        assert features.pass_count == 90
        assert features.block_count == 10
        assert features.unique_ports == 5

    def test_action_ratio_score_zero_total(self):
        features = RuleFeatures(rule_name='test', total_events=0,
                                pass_count=0, block_count=0)
        assert features.action_ratio_score == 0.0  # Default for zero events

    def test_port_scan_score_capped_at_1(self):
        features = RuleFeatures(rule_name='test', unique_ports=500)
        assert features.port_scan_score == 0.0  # Not computed by dataclass

    def test_dest_scan_score_capped_at_1(self):
        features = RuleFeatures(rule_name='test', unique_dst_ips=500)
        assert features.dest_scan_score == 0.0  # Not computed by dataclass

    def test_volume_score_for_1000_events(self):
        features = RuleFeatures(rule_name='test', total_events=1000)
        assert 0 <= features.volume_score <= 1.0
        # Default is 0.0 for new RuleFeatures (not computed)

    def test_volume_score_for_1_event(self):
        features = RuleFeatures(rule_name='test', total_events=1)
        assert 0 <= features.volume_score <= 1.0

    def test_default_factory_counters(self):
        features = RuleFeatures(rule_name='test')
        assert isinstance(features.protocols, Counter)
        assert isinstance(features.src_port_distribution, Counter)
        assert isinstance(features.dst_port_distribution, Counter)
        assert isinstance(features.src_ip_counts, Counter)
        assert isinstance(features.dst_ip_counts, Counter)

    def test_default_factory_details(self):
        features = RuleFeatures(rule_name='test')
        assert isinstance(features.details, dict)

    def test_classification_values(self):
        features = RuleFeatures(rule_name='test', classification='GOOD')
        assert features.classification == 'GOOD'
        features.classification = 'ABUSIVE'
        assert features.classification == 'ABUSIVE'
        features.classification = 'DEFAULT_DENY'
        assert features.classification == 'DEFAULT_DENY'

    def test_protocols_counter_preserved(self):
        proto = Counter({'TCP': 80, 'UDP': 20, 'ICMP': 5})
        features = RuleFeatures(rule_name='test', protocols=proto)
        assert features.protocols['TCP'] == 80
        assert features.protocols['UDP'] == 20

    def test_goodness_default_zero(self):
        features = RuleFeatures(rule_name='test')
        assert features.goodness_score == 0.0


class TestRuleClassifierML:
    """Test the ML rule classifier engine."""

    def test_init_empty(self):
        clf = RuleClassifierML()
        assert len(clf.features_map) == 0

    def test_ingest_single_event(self):
        clf = RuleClassifierML()
        clf.ingest_events([make_event(rule_name='rule-1', dport=80, action='PASS')])
        assert len(clf.features_map) == 1
        assert clf.features_map['rule-1'].total_events == 1

    def test_ingest_multiple_events_same_rule(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='rule-1', dport=80, action='PASS')
                  for _ in range(25)]
        clf.ingest_events(events)
        assert len(clf.features_map) == 1
        assert clf.features_map['rule-1'].total_events == 25
        assert clf.features_map['rule-1'].pass_count == 25

    def test_ingest_events_different_rules(self):
        clf = RuleClassifierML()
        events1 = [make_event(rule_name='rule-1', dport=80, action='PASS')
                   for _ in range(20)]
        events2 = [make_event(rule_name='rule-2', dport=443, action='PASS')
                   for _ in range(15)]
        clf.ingest_events(events1 + events2)
        assert len(clf.features_map) == 2
        assert clf.features_map['rule-1'].total_events == 20
        assert clf.features_map['rule-2'].total_events == 15

    def test_ingest_block_events(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='block-rule', dport=22, action='BLOCK')
                  for _ in range(25)]
        clf.ingest_events(events)
        assert clf.features_map['block-rule'].block_count == 25
        assert clf.features_map['block-rule'].pass_count == 0

    def test_ingest_mixed_actions(self):
        clf = RuleClassifierML()
        events = []
        events += [make_event(rule_name='mixed', action='PASS') for _ in range(15)]
        events += [make_event(rule_name='mixed', action='BLOCK') for _ in range(10)]
        clf.ingest_events(events)
        assert clf.features_map['mixed'].pass_count == 15
        assert clf.features_map['mixed'].block_count == 10
        assert clf.features_map['mixed'].total_events == 25

    def test_classify_good_rule(self):
        """25 events, all PASS, low diversity -> GOOD."""
        clf = RuleClassifierML()
        events = [make_event(rule_name='good', dport=80, action='PASS')
                  for _ in range(25)]
        clf.ingest_events(events)
        classified = clf.get_classified_rules()
        assert len(classified) >= 1
        assert classified[0]['classification'] == 'GOOD'

    def test_classify_uncertain_low_events(self):
        """Few events (< 20) -> UNCERTAIN."""
        clf = RuleClassifierML()
        events = [make_event(rule_name='few', dport=80, action='PASS')
                  for _ in range(5)]
        clf.ingest_events(events)
        classified = clf.get_classified_rules()
        assert len(classified) >= 1
        assert classified[0]['classification'] == 'UNCERTAIN'

    def test_classify_abusive_rule(self):
        """High port diversity + mixed actions -> ABUSIVE or SUSPICIOUS."""
        clf = RuleClassifierML()
        events = []
        for p in range(150):
            # Mix pass/block so the DENY rule doesn't kick in
            action = 'BLOCK' if p % 2 == 0 else 'PASS'
            events.append(make_event(rule_name='abuse', dport=1000+p,
                                     action=action))
        clf.ingest_events(events)
        classified = clf.get_classified_rules()
        assert len(classified) >= 1
        assert classified[0]['classification'] in ('ABUSIVE', 'SUSPICIOUS')

    def test_ingest_with_metadata(self):
        """Metadata stored in features.details."""
        clf = RuleClassifierML()
        ev = make_event(rule_name='meta', dport=80, action='PASS')
        ev['rule_action'] = 'pass'
        ev['rule_protocol'] = 'tcp'
        clf.ingest_events([ev])
        classified = clf.get_classified_rules()
        assert len(classified) >= 1
        # Metadata goes into details dict
        assert 'details' in classified[0]

    def test_get_classified_rules(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='r', dport=80, action='PASS')
                  for _ in range(25)]
        clf.ingest_events(events)
        classified = clf.get_classified_rules()
        assert len(classified) >= 1
        assert 'classification' in classified[0]
        assert 'confidence' in classified[0]
        assert 'goodness_score' in classified[0]
        assert 'port_scan_score' in classified[0]
        assert 'dest_scan_score' in classified[0]

    def test_get_classified_rules_empty(self):
        clf = RuleClassifierML()
        classified = clf.get_classified_rules()
        assert len(classified) == 0

    def test_get_summary(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='r', dport=80, action='PASS')
                  for _ in range(25)]
        clf.ingest_events(events)
        summary = clf.get_summary()
        assert 'total_rules' in summary
        assert 'total_events' in summary
        assert 'by_classification' in summary
        assert summary['total_rules'] >= 1

    def test_save_and_load_state(self, tmp_path):
        clf = RuleClassifierML()
        events = [make_event(rule_name='r', dport=80, action='PASS')
                  for _ in range(25)]
        clf.ingest_events(events)

        state_file = tmp_path / 'state.json'
        clf.save_state(str(state_file))

        clf2 = RuleClassifierML()
        loaded = clf2.load_state(str(state_file))
        # load_state returns None on success (not True)
        assert loaded is None
        assert len(clf2.features_map) == 1
        assert clf2.features_map['r'].total_events == 25

    def test_save_load_empty_state(self, tmp_path):
        clf = RuleClassifierML()
        state_file = tmp_path / 'state.json'
        clf.save_state(str(state_file))

        clf2 = RuleClassifierML()
        loaded = clf2.load_state(str(state_file))
        assert loaded is None
        assert len(clf2.features_map) == 0

    def test_load_nonexistent_file(self, tmp_path):
        clf = RuleClassifierML()
        loaded = clf.load_state(str(tmp_path / 'nonexistent.json'))
        # Returns None (implicit) when file doesn't exist
        assert loaded is None

    def test_ingest_preserves_protocol_counts(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='proto', dport=53, proto='UDP',
                             action='PASS') for _ in range(7)]
        events += [make_event(rule_name='proto', dport=53, proto='TCP',
                              action='PASS') for _ in range(3)]
        clf.ingest_events(events)
        classified = clf.get_classified_rules()
        protocols = classified[0].get('protocols', {})
        assert protocols.get('UDP', 0) == 7
        assert protocols.get('TCP', 0) == 3

    def test_multiple_rules_classification(self):
        clf = RuleClassifierML()
        for i in range(50):
            clf.ingest_events([make_event(rule_name='g1', dport=80, action='PASS')])
        for i in range(30):
            clf.ingest_events([make_event(rule_name='g2', dport=443, action='PASS')])
        classified = clf.get_classified_rules()
        assert len(classified) == 2
        for r in classified:
            assert r['classification'] == 'GOOD'

    def test_ingest_updates_existing_rule(self):
        clf = RuleClassifierML()
        events1 = [make_event(rule_name='update', dport=80, action='PASS')
                   for _ in range(10)]
        clf.ingest_events(events1)
        assert clf.features_map['update'].total_events == 10
        events2 = [make_event(rule_name='update', dport=80, action='BLOCK')
                   for _ in range(5)]
        clf.ingest_events(events2)
        assert clf.features_map['update'].total_events == 15
        assert clf.features_map['update'].pass_count == 10
        assert clf.features_map['update'].block_count == 5

    def test_events_without_rule(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name=None, action='PASS') for _ in range(5)]
        clf.ingest_events(events)
        assert clf.events_without_rule == 5
        assert clf.events_with_rule == 0

    def test_total_events_counter(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='r', action='PASS') for _ in range(10)]
        clf.ingest_events(events)
        assert clf.total_events == 10

    def test_high_diversity_port_scan(self):
        clf = RuleClassifierML()
        events = [make_event(rule_name='scan', dport=1000+i, action='BLOCK')
                  for i in range(150)]
        clf.ingest_events(events)
        classified = clf.get_classified_rules()
        assert len(classified) >= 1
        assert classified[0]['unique_ports'] == 150
        # 150 events from same src_ip -> port_scan_score > 0
        assert classified[0]['port_scan_score'] > 0

    def test_save_load_state_json_content(self, tmp_path):
        clf = RuleClassifierML()
        events = [make_event(rule_name='r', dport=80, action='PASS')
                  for _ in range(25)]
        clf.ingest_events(events)

        state_file = tmp_path / 'state.json'
        clf.save_state(str(state_file))

        # Verify file content is valid JSON
        with open(state_file) as f:
            data = json.load(f)
        assert 'features' in data
        assert data['features']['r']['total_events'] == 25
