"""
Unit tests for attack detectors.

Covers:
- Port scan detection (vertical & horizontal)
- SYN flood detection
- Brute force detection
- Probe detection (XMAS, NULL, FIN, ICMP)
- AttackDetector orchestrator & dedup
- Field name consistency: detector output must match embed expectations
"""

import sys
import os
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detectors import (
    PortScanDetector,
    SYNFloodDetector,
    BruteForceDetector,
    ProbeDetector,
    AttackDetector,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def make_event(
    src_ip="10.0.0.1",
    dst_ip="192.168.1.1",
    dst_port=22,
    sport=54321,
    proto="TCP",
    action="BLOCK",
    tcp_flags=None,
    timestamp=None,
):
    """Create a minimal normalized event dict."""
    ev = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dport": dst_port,
        "sport": sport,
        "proto": proto,
        "action": action,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
    }
    if tcp_flags:
        ev["tcp_flags"] = tcp_flags
    return ev


# ── Port Scan Tests ──────────────────────────────────────────────────────

class TestPortScanDetector:
    def test_vertical_scan_detected(self):
        detector = PortScanDetector(vertical_threshold=5, window_seconds=120)
        # Need 5 distinct ports from same source
        for port in [22, 80, 443, 8080, 3306]:
            ev = make_event(dst_port=port)
            result = detector.check(ev)
        assert result is not None, "Vertical port scan should be detected"
        assert result["attack_type"] == "PORT_SCAN"
        assert result["dst_port"] == 3306  # last event's port
        assert result["detail"]["distinct_ports"] >= 5
        assert len(result["detail"]["port_list"]) >= 5

    def test_horizontal_scan_detected(self):
        detector = PortScanDetector(horizontal_threshold=3, window_seconds=120)
        for i in range(4):
            ev = make_event(dst_ip=f"192.168.1.{i}")
            detector.check(ev)
        # The 4th event should trigger horizontal scan
        # Need to send another to the 4th host to count >= 3 hosts
        ev = make_event(dst_ip="192.168.1.3")
        result = detector.check(ev)
        # Actually horizontal scans need distinct hosts, so let's count properly
        # We sent to 192.168.1.1, .2, .3, .3 — that's 3 distinct hosts
        # Need another to a new host
        ev2 = make_event(dst_ip="192.168.1.5")
        result2 = detector.check(ev2)
        assert result2 is not None, "Horizontal scan should be detected"
        assert result2["attack_type"] == "PORT_SCAN"
        assert result2["scan_subtype"] == "HORIZONTAL"

    def test_port_not_none_in_output(self):
        """Regression: verify dst_port is present in detection output."""
        detector = PortScanDetector(vertical_threshold=2, window_seconds=120)
        detector.check(make_event(dst_port=22))
        result = detector.check(make_event(dst_port=80))
        assert result is not None
        assert "dst_port" in result, "Port scan detection must include 'dst_port'"
        assert result["dst_port"] == 80

    def test_non_block_events_ignored(self):
        detector = PortScanDetector(vertical_threshold=2, window_seconds=120)
        for port in [22, 80]:
            ev = make_event(dst_port=port, action="PASS")
            result = detector.check(ev)
        assert result is None

    def test_threshold_respected(self):
        detector = PortScanDetector(vertical_threshold=100, window_seconds=120)
        for port in range(20):
            detector.check(make_event(dst_port=port))
        assert detector.check(make_event()) is None  # below threshold


# ── SYN Flood Tests ──────────────────────────────────────────────────────

class TestSYNFloodDetector:
    def test_syn_flood_detected(self):
        detector = SYNFloodDetector(syn_threshold=5, window_seconds=30)
        for i in range(6):
            ev = make_event(tcp_flags="SYN")
            detector.check(ev)
        # Need another SYN to hit threshold
        result = detector.check(make_event(tcp_flags="SYN"))
        assert result is not None
        assert result["attack_type"] == "SYN_FLOOD"
        assert "dst_port" in result, "SYN flood must include 'dst_port'"
        assert result["detail"]["syn_count"] >= 6

    def test_non_syn_ignored(self):
        detector = SYNFloodDetector(syn_threshold=2, window_seconds=30)
        for _ in range(5):
            ev = make_event(tcp_flags="ACK")
            detector.check(ev)
        assert detector.check(make_event(tcp_flags="ACK")) is None

    def test_port_in_output(self):
        detector = SYNFloodDetector(syn_threshold=2, window_seconds=30)
        detector.check(make_event(tcp_flags="SYN", dst_port=443))
        result = detector.check(make_event(tcp_flags="SYN", dst_port=443))
        assert result is not None
        assert result["dst_port"] == 443

    def test_window_expiration(self):
        detector = SYNFloodDetector(syn_threshold=3, window_seconds=1)
        now = datetime.now(timezone.utc)
        for i in range(3):
            ev = make_event(tcp_flags="SYN", timestamp=now - timedelta(seconds=2))
            detector.check(ev)
        # Old events should be expired
        result = detector.check(make_event(tcp_flags="SYN", timestamp=now))
        assert result is None


# ── Brute Force Tests ────────────────────────────────────────────────────

class TestBruteForceDetector:
    def test_brute_force_detected(self):
        detector = BruteForceDetector(auth_threshold=5, window_seconds=60)
        for _ in range(6):
            ev = make_event(dst_port=22)  # SSH port
            detector.check(ev)
        # 7th should trigger
        result = detector.check(make_event(dst_port=22))
        assert result is not None
        assert result["attack_type"] == "BRUTE_FORCE"
        assert "dst_port" in result, "Brute force must include 'dst_port'"
        assert result["dst_port"] == 22
        assert result["detail"]["attempt_count"] >= 6

    def test_non_auth_port_ignored(self):
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        for _ in range(10):
            ev = make_event(dst_port=5000)  # Not an auth port
            detector.check(ev)
        assert detector.check(make_event(dst_port=5000)) is None

    def test_port_in_output(self):
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        detector.check(make_event(dst_port=3389))
        result = detector.check(make_event(dst_port=3389))
        assert result is not None
        assert result["dst_port"] == 3389

    def test_different_target_not_deduped(self):
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        detector.check(make_event(dst_ip="192.168.1.1", dst_port=22))
        detector.check(make_event(dst_ip="192.168.1.1", dst_port=22))
        # Different target should be independent
        detector.check(make_event(dst_ip="10.0.0.1", dst_port=22))
        detector.check(make_event(dst_ip="10.0.0.1", dst_port=22))
        # First target already triggered, second should too
        r2 = detector.check(make_event(dst_ip="10.0.0.1", dst_port=22))
        assert r2 is not None

    def test_service_name_in_detail(self):
        """Regression: service name should be computed for common ports."""
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        detector.check(make_event(dst_port=22))
        result = detector.check(make_event(dst_port=22))
        assert result is not None
        assert result["detail"]["service"] == "SSH"

    def test_port_3306_service(self):
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        detector.check(make_event(dst_port=3306))
        result = detector.check(make_event(dst_port=3306))
        assert result is not None
        assert result["detail"]["service"] == "MySQL"


# ── Probe Detection Tests ────────────────────────────────────────────────

class TestProbeDetector:
    def test_xmas_scan(self):
        detector = ProbeDetector(probe_threshold=2, window_seconds=30)
        result = detector.check(make_event(tcp_flags="XMAS"))
        assert result is not None
        assert result["attack_type"] == "PROBE"
        assert result["scan_subtype"] == "XMAS_SCAN"
        assert "dst_port" in result, "Probe must include 'dst_port'"
        assert result["detail"]["flags"] == "XMAS (FIN+PSH+URG)"

    def test_null_scan(self):
        detector = ProbeDetector(probe_threshold=2, window_seconds=30)
        result = detector.check(make_event(tcp_flags="NULL"))
        assert result is not None
        assert result["scan_subtype"] == "NULL_SCAN"
        assert result["detail"]["flags"] == "NULL (no flags)"

    def test_fin_scan(self):
        detector = ProbeDetector(probe_threshold=2, window_seconds=30)
        result = detector.check(make_event(tcp_flags="FIN"))
        assert result is not None
        assert result["scan_subtype"] == "FIN_SCAN"
        assert result["detail"]["flags"] == "FIN only"

    def test_icmp_flood(self):
        detector = ProbeDetector(probe_threshold=5, window_seconds=30)
        for _ in range(5):
            detector.check(make_event(proto="ICMP"))
        result = detector.check(make_event(proto="ICMP"))
        assert result is not None
        assert result["scan_subtype"] == "ICMP_FLOOD"
        assert "icmp_count" in result["detail"]

    def test_non_block_ignored(self):
        detector = ProbeDetector(probe_threshold=1, window_seconds=30)
        result = detector.check(make_event(tcp_flags="XMAS", action="PASS"))
        assert result is None

    def test_port_in_output(self):
        detector = ProbeDetector(probe_threshold=1, window_seconds=30)
        result = detector.check(make_event(tcp_flags="XMAS", dst_port=445))
        assert result is not None
        assert result["dst_port"] == 445


# ── AttackDetector Orchestrator ──────────────────────────────────────────

class TestAttackDetector:
    def test_multiple_detections(self):
        config = {
            "port_scan_vertical": 2,
            "port_scan_window": 120,
            "brute_force_threshold": 2,
            "brute_force_window": 60,
            "syn_flood_threshold": 2,
            "syn_flood_window": 30,
            "probe_threshold": 1,
            "probe_window": 30,
        }
        ad = AttackDetector(dedup_seconds=300, config=config)

        # Port scan: 2 distinct ports
        ad.check_event(make_event(dst_port=22))
        results = ad.check_event(make_event(dst_port=80))
        assert any(r["attack_type"] == "PORT_SCAN" for r in results)

    def test_dedup_within_window(self):
        config = {"port_scan_vertical": 1}
        ad = AttackDetector(dedup_seconds=300, config=config)
        ev = make_event(dst_port=22)
        r1 = ad.check_event(ev)
        r2 = ad.check_event(ev)
        # Same detection key, within dedup window -> second should be suppressed
        assert len(r1) > 0
        assert len(r2) == 0

    def test_dedup_expires(self):
        config = {"port_scan_vertical": 1}
        ad = AttackDetector(dedup_seconds=1, config=config)
        r1 = ad.check_event(make_event(dst_port=22))
        time.sleep(1.1)
        r2 = ad.check_event(make_event(dst_port=22))
        # After dedup window, same event should fire again
        assert len(r1) > 0
        assert len(r2) > 0


# ── Field Consistency Tests (Regression) ─────────────────────────────────

class TestFieldConsistency:
    """
    These tests verify that attack detector output field names
    match what discord_bot.py expects when generating embeds.
    """

    def test_brute_force_has_dst_port_not_dport(self):
        """Bug: discord embed reads 'dport' but detector outputs 'dst_port'."""
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        detector.check(make_event(dst_port=22))
        result = detector.check(make_event(dst_port=22))
        assert result is not None
        assert "dst_port" in result
        assert result["dst_port"] == 22
        # Ensure 'dport' key is NOT used (it's the old/wrong key)
        assert "dport" not in result

    def test_brute_force_has_attempt_count(self):
        """Bug: discord embed reads 'attempts' but detector outputs 'attempt_count'."""
        detector = BruteForceDetector(auth_threshold=2, window_seconds=60)
        detector.check(make_event(dst_port=22))
        result = detector.check(make_event(dst_port=22))
        assert result is not None
        assert "attempt_count" in result["detail"]
        assert "attempts" not in result["detail"]

    def test_port_scan_has_scan_subtype(self):
        """Bug: discord embed reads 'scan_type' but detector outputs 'scan_subtype'."""
        detector = PortScanDetector(vertical_threshold=2, window_seconds=120)
        detector.check(make_event(dst_port=22))
        result = detector.check(make_event(dst_port=80))
        assert result is not None
        assert "scan_subtype" in result
        assert result["scan_subtype"] in ("VERTICAL", "HORIZONTAL")
        # The embed should also fall back gracefully
        assert result.get("scan_type") is None  # not 'scan_type'

    def test_port_scan_has_port_list_not_ports(self):
        """Bug: discord embed reads 'detail.ports' but detector outputs 'detail.port_list'."""
        detector = PortScanDetector(vertical_threshold=2, window_seconds=120)
        detector.check(make_event(dst_port=22))
        result = detector.check(make_event(dst_port=80))
        assert result is not None
        assert "port_list" in result["detail"]
        assert "ports" not in result["detail"]

    def test_probes_have_scan_subtype_not_probe_type(self):
        """Bug: discord embed reads 'probe_type' but detector outputs 'scan_subtype'."""
        detector = ProbeDetector(probe_threshold=1, window_seconds=30)
        result = detector.check(make_event(tcp_flags="XMAS"))
        assert result is not None
        assert "scan_subtype" in result
        assert "probe_type" not in result

    def test_probes_have_flags_not_signature(self):
        """Bug: discord embed reads 'detail.signature' but detector outputs 'detail.flags'."""
        detector = ProbeDetector(probe_threshold=1, window_seconds=30)
        result = detector.check(make_event(tcp_flags="XMAS"))
        assert result is not None
        assert "flags" in result["detail"]
        assert "signature" not in result["detail"]

    def test_syn_flood_has_dst_port(self):
        """SYN_FLOOD should include dst_port."""
        detector = SYNFloodDetector(syn_threshold=2, window_seconds=30)
        detector.check(make_event(tcp_flags="SYN", dst_port=80))
        result = detector.check(make_event(tcp_flags="SYN", dst_port=80))
        assert result is not None
        assert "dst_port" in result
        assert result["dst_port"] == 80

    def test_all_detection_keys_present(self):
        """Every detection should have these required keys."""
        required_top_keys = {"attack_type", "severity", "src_ip", "dst_ip", "dst_port"}
        required_detail_keys_brute = {"attempt_count", "threshold", "service", "window_seconds"}

        # Brute force
        bf = BruteForceDetector(auth_threshold=2, window_seconds=60)
        bf.check(make_event(dst_port=22))
        r = bf.check(make_event(dst_port=22))
        assert r is not None
        for key in required_top_keys:
            assert key in r, f"Missing required key in brute force: {key}"
        for key in required_detail_keys_brute:
            assert key in r["detail"], f"Missing required detail key in brute force: {key}"
