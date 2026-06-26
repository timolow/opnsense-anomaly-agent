#!/usr/bin/env python3
"""Tests for system_log_classifier.py — SystemLogClassifier and ServiceProfile."""

import sys
import os
import json
import tempfile
from datetime import datetime, timezone, timedelta
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from system_log_classifier import (
    SystemLogClassifier,
    ServiceProfile,
    _detect_service,
    _detect_log_level,
    _is_ip_address,
    KNOWN_SERVICES,
    TRUSTED_SERVICES,
    MIN_SAMPLES,
    SPIKE_ZSCORE,
)


class TestHelpers:
    """Test standalone helper functions."""

    def test_is_ip_address_ipv4(self):
        assert _is_ip_address("192.168.1.1") is True
        assert _is_ip_address("10.0.0.1") is True

    def test_is_ip_address_ipv6(self):
        assert _is_ip_address("fe80::1") is True
        assert _is_ip_address("2001:db8::1") is True

    def test_is_ip_address_not_ip(self):
        assert _is_ip_address("") is False
        assert _is_ip_address(None) is False
        assert _is_ip_address("ntpd") is False
        assert _is_ip_address("hello") is False

    def test_detect_service_from_process(self):
        assert _detect_service("", "ntpd") == "ntpd"
        assert _detect_service("", "unbound") == "unbound"
        # openvpn matches "vpn" substring in KNOWN_SERVICES (set iteration order)
        assert _detect_service("", "openvpn") in ("vpn", "openvpn")

    def test_detect_service_ip_as_process(self):
        """IP addresses misparsed as process names should return 'unknown'."""
        assert _detect_service("", "192.168.1.1") == "unknown"

    def test_detect_service_unknown_process(self):
        """Process not in KNOWN_SERVICES falls through to raw name."""
        assert _detect_service("", "my_custom_daemon") == "my_custom_daemon"

    def test_detect_service_from_raw_patterns(self):
        assert _detect_service("kernel: ntp sync", None) == "ntpd"
        assert _detect_service("dhcp lease granted", None) == "dhcp"
        assert _detect_service("arp announcement", None) == "arp"
        assert _detect_service("sshd login", None) == "sshd"

    def test_detect_service_fallback(self):
        assert _detect_service("some random message", None) == "unknown"

    def test_detect_log_level_error(self):
        assert _detect_log_level("connection error occurred") == "error"
        assert _detect_log_level("fatal failure") == "error"
        assert _detect_log_level("critical issue") == "error"

    def test_detect_log_level_warning(self):
        assert _detect_log_level("warning: high latency") == "warning"
        assert _detect_log_level("disk space low warning") == "warning"

    def test_detect_log_level_info(self):
        assert _detect_log_level("service started info") == "info"
        assert _detect_log_level("notice: updated") == "info"

    def test_detect_log_level_debug_default(self):
        assert _detect_log_level("routine message") == "debug"


class TestServiceProfile:
    """Test the ServiceProfile dataclass."""

    def test_init(self):
        p = ServiceProfile(service="ntpd")
        assert p.service == "ntpd"
        assert p.total_events == 0
        assert p.is_new is True

    def test_is_new_after_events(self):
        p = ServiceProfile(service="test")
        assert p.is_new is True
        p.total_events = MIN_SAMPLES
        assert p.is_new is False

    def test_dominant_log_level(self):
        p = ServiceProfile(service="test")
        assert p.dominant_log_level is None
        p.action_counts = Counter({"info": 10, "error": 3})
        assert p.dominant_log_level == "info"

    def test_unique_counts(self):
        p = ServiceProfile(service="test")
        p.src_ips = {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
        p.dst_ips = {"192.168.1.1", "192.168.1.2"}
        assert p.unique_src_count == 3
        assert p.unique_dst_count == 2

    def test_spike_zscore_not_enough_samples(self):
        p = ServiceProfile(service="test")
        p.hourly_counts = Counter({"2024-01-01 10": 5})
        assert p.get_spike_zscore(100) == 0.0

    def test_spike_zscore_zero_variance(self):
        p = ServiceProfile(service="test")
        counts = {f"2024-01-01 {h:02d}": 10 for h in range(MIN_SAMPLES)}
        p.hourly_counts = Counter(counts)
        assert p.get_spike_zscore(10) == 0.0

    def test_spike_zscore_high_spike(self):
        p = ServiceProfile(service="test")
        # Build baseline: 30 hours with some variance so stddev > 0
        counts = {f"2024-01-01 {h:02d}": (10 if h % 2 == 0 else 12) for h in range(30)}
        p.hourly_counts = Counter(counts)
        z = p.get_spike_zscore(50)
        assert z > 3.0

    def test_spike_zscore_normal(self):
        p = ServiceProfile(service="test")
        counts = {f"2024-01-01 {h:02d}": 10 for h in range(30)}
        p.hourly_counts = Counter(counts)
        z = p.get_spike_zscore(10)
        assert z == 0.0


class TestSystemLogClassifierInit:
    """Test SystemLogClassifier initialization."""

    def test_default_init(self):
        clf = SystemLogClassifier()
        assert clf.min_samples == MIN_SAMPLES
        assert clf.spike_zscore == SPIKE_ZSCORE
        assert clf.total_events == 0
        assert clf.service_profiles == {}

    def test_custom_params(self):
        clf = SystemLogClassifier(min_samples=5, spike_zscore=2.5)
        assert clf.min_samples == 5
        assert clf.spike_zscore == 2.5


class TestProcessEvent:
    """Test event processing and profile building."""

    def _make_event(self, raw="test", process=None, src_ip=None, dst_ip=None,
                    log_level=None, timestamp=None):
        event = {"raw": raw}
        if process:
            event["process"] = process
        if src_ip:
            event["src_ip"] = src_ip
        if dst_ip:
            event["dst_ip"] = dst_ip
        if log_level:
            event["log_level"] = log_level
        if timestamp:
            event["timestamp"] = timestamp
        return event

    def test_process_single_event(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="ntpd"))
        assert clf.total_events == 1
        assert "ntpd" in clf.service_profiles

    def test_process_event_counts_service(self):
        clf = SystemLogClassifier()
        for i in range(5):
            clf.process_event(self._make_event(process="sshd"))
        profile = clf.service_profiles["sshd"]
        assert profile.total_events == 5
        assert clf.events_by_service["sshd"] == 5

    def test_process_event_counts_log_level(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="test", log_level="error"))
        assert clf.events_by_level["error"] == 1

    def test_process_event_tracks_src_ip(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="test", src_ip="10.0.0.1"))
        profile = clf.service_profiles["test"]
        assert "10.0.0.1" in profile.src_ips

    def test_process_event_tracks_dst_ip(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="test", dst_ip="192.168.1.1"))
        profile = clf.service_profiles["test"]
        assert "192.168.1.1" in profile.dst_ips

    def test_process_event_updates_timestamps(self):
        clf = SystemLogClassifier()
        ts = "2024-06-15T10:30:00+00:00"
        clf.process_event(self._make_event(process="test", timestamp=ts))
        profile = clf.service_profiles["test"]
        assert profile.first_seen is not None
        assert profile.last_seen is not None
        assert profile.first_seen == profile.last_seen

    def test_process_event_hourly_counts(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="test", timestamp="2024-06-15T10:30:00+00:00"))
        profile = clf.service_profiles["test"]
        assert "2024-06-15 10" in profile.hourly_counts

    def test_new_service_tracking(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="new_daemon"))
        assert "new_daemon" in clf._new_services_seen

    def test_existing_service_removed_from_new(self):
        clf = SystemLogClassifier()
        clf.process_event(self._make_event(process="sshd"))
        clf.process_event(self._make_event(process="sshd"))
        assert "sshd" not in clf._new_services_seen

    def test_process_batch(self):
        clf = SystemLogClassifier()
        events = [
            self._make_event(process="ntpd"),
            self._make_event(process="sshd"),
            self._make_event(process="ntpd"),
        ]
        clf.process_events(events)
        assert clf.total_events == 3
        assert clf.service_profiles["ntpd"].total_events == 2
        assert clf.service_profiles["sshd"].total_events == 1


class TestDetectAnomalies:
    """Test anomaly detection logic."""

    def _make_event(self, **kwargs):
        event = {"raw": kwargs.get("raw", "test")}
        for k, v in kwargs.items():
            if k != "raw":
                event[k] = v
        return event

    def test_no_anomalies_empty(self):
        clf = SystemLogClassifier()
        assert clf.detect_anomalies() == []

    def test_new_service_anomaly(self):
        clf = SystemLogClassifier(min_samples=2)
        # Simulate a new service that's not trusted
        clf.process_event(self._make_event(process="evil_daemon", raw="hello"))
        # Process it twice so it's removed from _new_services_seen,
        # then manually put it back to test detection
        clf._new_services_seen.add("evil_daemon")
        clf.service_profiles["evil_daemon"].total_events = 1
        anomalies = clf.detect_anomalies()
        new_service = [a for a in anomalies if a["type"] == "NEW_SERVICE"]
        assert len(new_service) >= 1
        assert new_service[0]["service"] == "evil_daemon"

    def test_trusted_service_no_new_service_alert(self):
        clf = SystemLogClassifier(min_samples=2)
        clf.process_event(self._make_event(process="ntpd"))
        # Force back to new state for testing
        clf._new_services_seen.add("ntpd")
        clf.service_profiles["ntpd"].total_events = 1
        anomalies = clf.detect_anomalies()
        new_service = [a for a in anomalies if a["type"] == "NEW_SERVICE"]
        # ntpd is in TRUSTED_SERVICES, should NOT appear
        assert all(a["service"] != "ntpd" for a in new_service)

    def test_error_burst_detection(self):
        clf = SystemLogClassifier(min_samples=2)
        now = datetime.now(timezone.utc)
        # Feed many events with timestamps so hourly_counts exist
        for i in range(20):
            clf.process_event(self._make_event(
                process="test_svc", log_level="error", raw="error occurred",
                timestamp=now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            ))
        for i in range(5):
            clf.process_event(self._make_event(
                process="test_svc", log_level="info", raw="info message",
                timestamp=now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            ))
        anomalies = clf.detect_anomalies()
        error_bursts = [a for a in anomalies if a["type"] == "ERROR_BURST"]
        assert len(error_bursts) >= 1
        assert error_bursts[0]["service"] == "test_svc"
        assert error_bursts[0]["error_ratio"] > 0.3

    def test_error_burst_no_low_ratio(self):
        clf = SystemLogClassifier(min_samples=2)
        # Mostly info, few errors -> no burst
        for i in range(20):
            clf.process_event(self._make_event(
                process="healthy_svc", log_level="info", raw="info message"
            ))
        for i in range(2):
            clf.process_event(self._make_event(
                process="healthy_svc", log_level="error", raw="error"
            ))
        anomalies = clf.detect_anomalies()
        error_bursts = [a for a in anomalies if a["type"] == "ERROR_BURST"]
        assert len(error_bursts) == 0

    def test_high_ip_diversity(self):
        clf = SystemLogClassifier(min_samples=2)
        now = datetime.now(timezone.utc)
        # Feed events with timestamps so hourly_counts exist
        for i in range(MIN_SAMPLES):
            clf.process_event(self._make_event(
                process="test_svc", src_ip=f"10.0.{i // 256}.{i % 256}",
                timestamp=now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            ))
        # Add lots of unique source IPs
        for i in range(55):
            clf.process_event(self._make_event(
                process="test_svc", src_ip=f"172.16.{i // 256}.{i % 256}",
                timestamp=now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            ))
        anomalies = clf.detect_anomalies()
        diversity = [a for a in anomalies if a["type"] == "HIGH_IP_DIVERSITY"]
        assert len(diversity) >= 1
        assert diversity[0]["service"] == "test_svc"
        assert diversity[0]["unique_src_ips"] > 50

    def test_volume_spike_detection(self):
        clf = SystemLogClassifier(min_samples=2, spike_zscore=2.0)
        now = datetime.now(timezone.utc)
        # Build 30 hours of baseline with ~10 events each
        for h in range(30):
            hour = now - timedelta(hours=30 - h)
            for _ in range(10):
                clf.process_event(self._make_event(
                    process="spike_svc",
                    timestamp=hour.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                ))
        # Current hour: spike to 100 events
        current_hour = now.strftime("%Y-%m-%d %H")
        for _ in range(100):
            clf.process_event(self._make_event(
                process="spike_svc",
                timestamp=now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            ))
        anomalies = clf.detect_anomalies()
        spikes = [a for a in anomalies if a["type"] == "VOLUME_SPIKE"]
        assert len(spikes) >= 1
        assert spikes[0]["service"] == "spike_svc"
        assert spikes[0]["z_score"] > 2.0


class TestServiceSummary:
    """Test get_service_summary output."""

    def test_empty_summary(self):
        clf = SystemLogClassifier()
        summary = clf.get_service_summary()
        assert summary["total_system_events"] == 0
        assert summary["services_tracked"] == 0
        assert summary["service_details"] == []

    def test_populated_summary(self):
        clf = SystemLogClassifier()
        for i in range(5):
            clf.process_event({"raw": "test", "process": "ntpd", "log_level": "info"})
        summary = clf.get_service_summary()
        assert summary["total_system_events"] == 5
        assert summary["services_tracked"] == 1
        assert len(summary["service_details"]) == 1
        assert summary["service_details"][0]["service"] == "ntpd"
        assert summary["service_details"][0]["total_events"] == 5
        assert summary["service_details"][0]["dominant_level"] == "info"

    def test_summary_services_by_volume(self):
        clf = SystemLogClassifier()
        for _ in range(10):
            clf.process_event({"raw": "a", "process": "ntpd"})
        for _ in range(3):
            clf.process_event({"raw": "b", "process": "sshd"})
        summary = clf.get_service_summary()
        vol = summary["services_by_volume"]
        assert vol["ntpd"] >= vol["sshd"]


class TestStatePersistence:
    """Test save_state and load_state."""

    def test_save_and_load_state(self, tmp_path):
        clf = SystemLogClassifier()
        for i in range(5):
            clf.process_event({"raw": "test", "process": "ntpd", "log_level": "info",
                               "timestamp": "2024-06-15T10:30:00+00:00"})

        filepath = str(tmp_path / "classifier_state.json")
        clf.save_state(filepath)
        assert os.path.exists(filepath)

        # Load into a fresh classifier
        clf2 = SystemLogClassifier()
        clf2.load_state(filepath)
        assert "ntpd" in clf2.service_profiles
        assert clf2.service_profiles["ntpd"].total_events == 5
        assert clf2.events_by_service["ntpd"] == 5

    def test_load_missing_file(self, tmp_path):
        clf = SystemLogClassifier()
        # Should not raise
        clf.load_state(str(tmp_path / "nonexistent.json"))
        assert clf.service_profiles == {}

    def test_save_state_default_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
        clf = SystemLogClassifier()
        clf.process_event({"raw": "x", "process": "test"})
        clf.save_state()
        expected = tmp_path / "system_log_classifier_state.json"
        assert expected.exists()

    def test_load_preserves_counters(self, tmp_path):
        clf = SystemLogClassifier()
        for _ in range(3):
            clf.process_event({"raw": "err", "process": "svc", "log_level": "error"})
        for _ in range(7):
            clf.process_event({"raw": "info", "process": "svc", "log_level": "info"})

        filepath = str(tmp_path / "state.json")
        clf.save_state(filepath)

        clf2 = SystemLogClassifier()
        clf2.load_state(filepath)
        profile = clf2.service_profiles["svc"]
        assert profile.action_counts["error"] == 3
        assert profile.action_counts["info"] == 7
        assert profile.total_events == 10


class TestKnownServices:
    """Test KNOWN_SERVICES and TRUSTED_SERVICES sets."""

    def test_known_services_not_empty(self):
        assert len(KNOWN_SERVICES) > 10

    def test_trusted_services_not_empty(self):
        assert len(TRUSTED_SERVICES) > 10

    def test_common_opnsense_in_known(self):
        for svc in ("ntpd", "unbound", "filterlog", "openvpn", "kernel"):
            assert svc in KNOWN_SERVICES

    def test_common_opnsense_in_trusted(self):
        for svc in ("ntpd", "cron", "sshd", "firewall", "kernel"):
            assert svc in TRUSTED_SERVICES


class TestEdgeCases:
    """Test edge cases and robustness."""

    def test_empty_event(self):
        clf = SystemLogClassifier()
        clf.process_event({})
        assert clf.total_events == 1

    def test_event_with_raw_message_key(self):
        clf = SystemLogClassifier()
        clf.process_event({"raw_message": "backup raw key", "process": "test"})
        assert clf.total_events == 1

    def test_invalid_timestamp_no_crash(self):
        clf = SystemLogClassifier()
        clf.process_event({"raw": "test", "process": "svc", "timestamp": "not-a-date"})
        assert clf.total_events == 1

    def test_detect_service_with_mixed_case_process(self):
        assert _detect_service("", "NTPD") == "ntpd"

    def test_service_with_no_process_or_matching_pattern(self):
        assert _detect_service("unrecognized log line", None) == "unknown"