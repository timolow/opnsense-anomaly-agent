"""Tests for ml_learning.py — self-learning ML engine (Weeks 1-5)."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from ml_learning import (
    FeedbackRecord,
    RuleBaseline,
    TemporalPattern,
    ActiveLearningItem,
)


class TestFeedbackRecord:
    """Test FeedbackRecord dataclass."""

    def test_creation(self):
        rec = FeedbackRecord(rule_name='test', timestamp='2026-01-01',
                             label='correct', reason='ok')
        assert rec.rule_name == 'test'
        assert rec.timestamp == '2026-01-01'
        assert rec.label == 'correct'
        assert rec.reason == 'ok'
        assert rec.user_id is None

    def test_defaults(self):
        rec = FeedbackRecord(rule_name='r', timestamp='t', label='inc')
        assert rec.reason is None
        assert rec.user_id is None

    def test_optional_fields(self):
        rec = FeedbackRecord(rule_name='r', timestamp='t', label='ok',
                             reason='fix', user_id='user1')
        assert rec.reason == 'fix'
        assert rec.user_id == 'user1'


class TestRuleBaseline:
    """Test RuleBaseline dataclass."""

    def test_creation_defaults(self):
        bl = RuleBaseline(rule_name='test')
        assert bl.avg_port_diversity == 0.0
        assert bl.avg_dest_diversity == 0.0
        assert bl.avg_volume == 0.0
        assert bl.avg_block_ratio == 0.0
        assert bl.baseline_goodness == 0.0
        assert bl.sample_count == 0
        assert bl.baseline_updated is False
        assert bl.window_start is None
        assert bl.window_end is None

    def test_creation_with_values(self):
        bl = RuleBaseline(rule_name='r', avg_port_diversity=10.0,
                          avg_volume=1000, avg_block_ratio=0.5,
                          baseline_goodness=0.8)
        assert bl.avg_port_diversity == 10.0
        assert bl.avg_volume == 1000
        assert bl.baseline_goodness == 0.8

    def test_baseline_updated_flag(self):
        bl = RuleBaseline(rule_name='r')
        bl.baseline_updated = True
        assert bl.baseline_updated is True


class TestTemporalPattern:
    """Test TemporalPattern dataclass."""

    def test_creation(self):
        tp = TemporalPattern(rule_name='test',
                             hour_distribution={0: 10, 12: 50})
        assert tp.rule_name == 'test'
        assert tp.hour_distribution == {0: 10, 12: 50}
        assert tp.total_samples == 0
        assert tp.updated_at is None

    def test_empty_hour_distribution(self):
        tp = TemporalPattern(rule_name='test')
        assert tp.hour_distribution == {}

    def test_multiple_hours(self):
        tp = TemporalPattern(rule_name='test',
                             hour_distribution={i: i * 10 for i in range(24)})
        assert len(tp.hour_distribution) == 24
        assert tp.hour_distribution[12] == 120

    def test_total_samples(self):
        tp = TemporalPattern(rule_name='test', total_samples=100)
        assert tp.total_samples == 100


class TestActiveLearningItem:
    """Test ActiveLearningItem dataclass."""

    def test_creation(self):
        item = ActiveLearningItem(rule_name='r', classification='SUSPICIOUS',
                                  confidence=0.45, reasons=['port_scan'])
        assert item.rule_name == 'r'
        assert item.classification == 'SUSPICIOUS'
        assert item.confidence == 0.45
        assert item.reasons == ['port_scan']

    def test_empty_reasons(self):
        item = ActiveLearningItem(rule_name='r', classification='GOOD',
                                  confidence=0.9)
        assert item.classification == 'GOOD'
        assert item.reasons == []
        assert item.confidence == 0.9
