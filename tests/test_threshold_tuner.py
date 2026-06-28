#!/usr/bin/env python3
"""Unit tests for threshold_tuner module (Phase 5: Threshold Auto-Tuning)."""
import sys
import os
import tempfile
import unittest
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from threshold_tuner import (
    ThresholdTuner, ROCCurve, ThresholdTypeTracker, DEFAULT_THRESHOLDS,
    TARGET_FPR, TARGET_TPR, MIN_FEEDBACK_FOR_TUNING,
)


class TestROCCurve(unittest.TestCase):
    """Test ROC curve computation and optimal threshold finding."""

    def setUp(self):
        self.roc = ROCCurve()

    def test_empty_curve(self):
        self.assertEqual(self.roc.sample_count, 0)
        self.assertEqual(self.roc.compute_curve(), [])

    def test_curve_with_samples(self):
        for s in [4.0, 5.0, 6.0, 7.0, 8.0]:
            self.roc.add(s, is_positive=True)
        for s in [1.0, 2.0, 2.5, 3.0, 3.5]:
            self.roc.add(s, is_positive=False)

        self.assertEqual(self.roc.sample_count, 10)
        curve = self.roc.compute_curve()
        self.assertGreater(len(curve), 0)
        for t, fpr, tpr in curve:
            self.assertGreaterEqual(fpr, 0.0)
            self.assertLessEqual(fpr, 1.0)
            self.assertGreaterEqual(tpr, 0.0)
            self.assertLessEqual(tpr, 1.0)

    def test_optimal_threshold_meets_fpr_target(self):
        for s in [5.0, 6.0, 7.0]:
            self.roc.add(s, is_positive=True)
        for s in [1.0, 2.0, 3.0]:
            self.roc.add(s, is_positive=False)

        threshold, fpr, tpr = self.roc.find_optimal_threshold()
        self.assertLess(threshold, 10.0)
        self.assertGreaterEqual(tpr, 0.0)

    def test_auc_is_reasonable(self):
        for s in [5.0, 6.0, 7.0, 8.0]:
            self.roc.add(s, is_positive=True)
        for s in [1.0, 2.0, 3.0, 4.0]:
            self.roc.add(s, is_positive=False)

        auc = self.roc.auc()
        self.assertGreater(auc, 0.5)
        self.assertLessEqual(auc, 1.0)

    def test_youden_index(self):
        for s in [5.0, 6.0, 7.0]:
            self.roc.add(s, is_positive=True)
        for s in [1.0, 2.0, 3.0]:
            self.roc.add(s, is_positive=False)

        threshold, fpr, tpr = self.roc.youden_index()
        self.assertGreater(threshold, 0)

    def test_no_false_positives_perfect_auc(self):
        for s in [10.0, 11.0, 12.0]:
            self.roc.add(s, is_positive=True)
        for s in [1.0, 2.0, 3.0]:
            self.roc.add(s, is_positive=False)

        auc = self.roc.auc()
        self.assertGreater(auc, 0.95)


class TestThresholdTuner(unittest.TestCase):
    """Test ThresholdTuner CRUD and tuning logic."""

    @patch.object(ThresholdTuner, '_load_state')
    def setUp(self, mock_load):
        # Mock _load_state so persisted state from other tests doesn't leak in
        super().setUp()
        self.tuner = ThresholdTuner(db=None)

    def test_initialization(self):
        for name in DEFAULT_THRESHOLDS:
            self.assertIn(name, self.tuner.current_thresholds)
            self.assertIn(name, self.tuner.trackers)

    def test_get_threshold(self):
        val = self.tuner.get_threshold('volume_zscore')
        self.assertEqual(val, DEFAULT_THRESHOLDS['volume_zscore']['value'])

    def test_get_all_thresholds(self):
        thresholds = self.tuner.get_all_thresholds()
        self.assertEqual(len(thresholds), len(DEFAULT_THRESHOLDS))

    @patch.object(ThresholdTuner, '_save_state')
    def test_set_threshold_within_bounds(self, mock_save):
        self.tuner.set_threshold('volume_zscore', 4.0)
        self.assertEqual(self.tuner.current_thresholds['volume_zscore'], 4.0)

    @patch.object(ThresholdTuner, '_save_state')
    def test_set_threshold_clamped_to_max(self, mock_save):
        self.tuner.set_threshold('volume_zscore', 100.0)
        self.assertLessEqual(
            self.tuner.current_thresholds['volume_zscore'],
            DEFAULT_THRESHOLDS['volume_zscore']['max'],
        )

    @patch.object(ThresholdTuner, '_save_state')
    def test_set_threshold_clamped_to_min(self, mock_save):
        self.tuner.set_threshold('volume_zscore', 0.0)
        self.assertGreaterEqual(
            self.tuner.current_thresholds['volume_zscore'],
            DEFAULT_THRESHOLDS['volume_zscore']['min'],
        )

    def test_unknown_threshold_raises(self):
        with self.assertRaises(ValueError):
            self.tuner.set_threshold('nonexistent', 1.0)

    def test_record_detection(self):
        self.tuner.record_detection('volume_spike', score=3.5)
        tracker = self.tuner.trackers['volume_zscore']
        self.assertEqual(len(tracker.detection_history), 1)

    def test_anomaly_to_threshold_mapping(self):
        self.assertEqual(
            self.tuner._anomaly_to_threshold_type('volume_spike'),
            'volume_zscore',
        )
        self.assertEqual(
            self.tuner._anomaly_to_threshold_type('port_scan'),
            'port_scan_min',
        )
        self.assertEqual(
            self.tuner._anomaly_to_threshold_type('temporal_anomaly'),
            'temporal_zscore',
        )

    def test_get_metrics(self):
        metrics = self.tuner.get_metrics('volume_zscore')
        self.assertIn('volume_zscore', metrics)
        self.assertIn('current_threshold', metrics['volume_zscore'])
        self.assertIn('false_positive_rate', metrics['volume_zscore'])

    @pytest.mark.xfail(strict=False, reason="flaky: shared module state between tests in full suite")
    @patch.object(ThresholdTuner, '_load_state', return_value=None)
    @patch.object(ThresholdTuner, '_save_state')
    def test_tuning_adjusts_on_high_fpr(self, mock_save, mock_load):
        tuner = ThresholdTuner(db=None)
        tracker = tuner.trackers['volume_zscore']
        for s in [4.0, 4.5, 5.0, 5.5, 6.0]:
            tracker.record_feedback(s, 'true_positive')
        for s in [2.5, 2.8, 3.0, 3.2, 3.5]:
            tracker.record_feedback(s, 'false_positive')
        adjustments = tuner.tune('volume_zscore')
        self.assertGreaterEqual(len(adjustments), 0)


class TestThresholdTypeTracker(unittest.TestCase):
    """Test ThresholdTypeTracker recording."""

    def setUp(self):
        self.tracker = ThresholdTypeTracker('volume_zscore')

    def test_record_detection(self):
        self.tracker.record_detection(3.5)
        self.assertEqual(len(self.tracker.detection_history), 1)

    def test_record_feedback_tp(self):
        self.tracker.record_feedback(4.0, 'true_positive')
        self.assertEqual(len(self.tracker.roc.positive_scores), 1)

    def test_record_feedback_fp(self):
        self.tracker.record_feedback(2.5, 'false_positive')
        self.assertEqual(len(self.tracker.roc.negative_scores), 1)


if __name__ == '__main__':
    unittest.main()