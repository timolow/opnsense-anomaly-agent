#!/usr/bin/env python3
"""
Test human-readable incident narratives.

Covers:
1. Basic narrative with IP only (no DNS resolver)
2. Narrative with DNS-resolved hostname
3. Narrative with full attack chain (escalated)
4. Narrative with cross-source signals (firewall + nginx + ids)
5. Narrative with geo context (countries)
6. Narrative with time window formatting (seconds, minutes, hours)
7. Narrative with empty signals (edge case)
8. Narrative in to_dict() output
"""

import sys
import os
import time
from unittest.mock import MagicMock

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from correlation_engine import Incident, ATTACK_PHASES


class TestNarrativeBasic:
    """Test basic narrative generation."""

    def test_narrative_without_dns(self):
        """Narrative uses IP address only when no DNS resolver provided."""
        inc = Incident("203.0.113.42", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.add_signal("firewall_block", "firewall", "medium")

        narrative = inc.get_narrative()

        assert "IP 203.0.113.42" in narrative
        # Should not have hostname-style parenthetical right after IP
        # (may have parens elsewhere e.g. activity chain labels)
        assert "(hostname" not in narrative.lower()
        assert narrative.endswith(".")

    def test_narrative_with_dns(self):
        """Narrative includes resolved hostname when DNS resolver provided."""
        inc = Incident("203.0.113.42", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")

        mock_resolver = MagicMock()
        mock_resolver.lookup.return_value = "scanner.malicious.com"

        narrative = inc.get_narrative(dns_resolver=mock_resolver)

        assert "IP 203.0.113.42 (scanner.malicious.com)" in narrative

    def test_narrative_dns_lookup_failure(self):
        """Narrative gracefully handles DNS lookup failures."""
        inc = Incident("203.0.113.42", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")

        mock_resolver = MagicMock()
        mock_resolver.lookup.side_effect = Exception("DNS timeout")

        narrative = inc.get_narrative(dns_resolver=mock_resolver)

        # Should fall back to IP only
        assert "IP 203.0.113.42" in narrative
        assert "scanner" not in narrative

    def test_narrative_dns_lookup_none(self):
        """Narrative gracefully handles DNS returning None."""
        inc = Incident("203.0.113.42", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")

        mock_resolver = MagicMock()
        mock_resolver.lookup.return_value = None

        narrative = inc.get_narrative(dns_resolver=mock_resolver)

        assert "IP 203.0.113.42" in narrative
        assert "None" not in narrative


class TestNarrativePhases:
    """Test narrative generation for different attack phases."""

    def test_reconnaissance_narrative(self):
        """Recon-phase incident generates scanning/probing narrative."""
        inc = Incident("198.51.100.10", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.add_signal("vertical_scan", "attack_detector", "medium")

        narrative = inc.get_narrative()

        assert "scanning" in narrative.lower() or "probe" in narrative.lower()

    def test_attack_chain_narrative(self):
        """Multi-phase chain generates progression narrative."""
        inc = Incident("203.0.113.50", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.add_signal("http_scan", "nginx", "low")
        inc.add_signal("http_brute_force", "nginx", "high")
        inc.add_signal("firewall_block", "firewall", "medium")

        narrative = inc.get_narrative()

        # Should mention attack chain progression
        assert "attack chain" in narrative.lower() or "advancing" in narrative.lower()

    def test_escalated_chain_narrative(self):
        """Escalated incident (3+ consecutive phases) mentions full chain."""
        inc = Incident("203.0.113.99", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")       # recon
        inc.add_signal("http_scan", "nginx", "low")                     # probe
        inc.add_signal("http_brute_force", "nginx", "high")             # attack
        inc.add_signal("path_traversal", "nginx", "critical")           # attack

        narrative = inc.get_narrative()

        # Should be high severity due to 3+ signal types
        assert "[HIGH]" in narrative or "[CRITICAL]" in narrative


class TestNarrativeTimeWindow:
    """Test time window formatting in narratives."""

    def test_seconds_time_window(self):
        """Duration < 60s shows in seconds."""
        now = time.time()
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        # Set timestamps AFTER add_signal (which resets last_seen)
        inc.first_seen = now - 30
        inc.last_seen = now

        narrative = inc.get_narrative()

        assert "30s" in narrative

    def test_minutes_time_window(self):
        """Duration < 60min shows in minutes."""
        now = time.time()
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.first_seen = now - 300  # 5 min
        inc.last_seen = now

        narrative = inc.get_narrative()

        assert "5 min" in narrative

    def test_hours_time_window(self):
        """Duration > 1h shows in hours."""
        now = time.time()
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.first_seen = now - 7200  # 2h
        inc.last_seen = now

        narrative = inc.get_narrative()

        assert "2h" in narrative


class TestNarrativeGeoContext:
    """Test geographic context in narratives."""

    def test_with_country(self):
        """Narrative includes country when available."""
        inc = Incident("203.0.113.42", "port_scan")
        inc.add_signal("new_country", "geo", "low")
        inc.metadata["countries"].add("CN")

        narrative = inc.get_narrative()

        assert "CN" in narrative

    def test_multiple_countries(self):
        """Narrative lists multiple countries."""
        inc = Incident("203.0.113.42", "port_scan")
        inc.add_signal("new_country", "geo", "low")
        inc.metadata["countries"].add("CN")
        inc.metadata["countries"].add("RU")

        narrative = inc.get_narrative()

        assert "CN" in narrative
        assert "RU" in narrative


class TestNarrativeActivityClauses:
    """Test per-source activity clause generation."""

    def test_firewall_activity(self):
        """Firewall signals generate firewall activity clause."""
        inc = Incident("10.0.0.1", "firewall_block")
        inc.add_signal("firewall_block", "firewall", "medium")
        inc.metadata["dst_ports"].add(22)
        inc.metadata["dst_ports"].add(443)

        narrative = inc.get_narrative()

        assert "firewall" in narrative.lower()

    def test_nginx_activity(self):
        """Nginx signals generate web service clause."""
        inc = Incident("10.0.0.1", "http_scan")
        inc.add_signal("http_scan", "nginx", "low")
        inc.add_signal("http_brute_force", "nginx", "high")

        narrative = inc.get_narrative()

        assert "web" in narrative.lower()

    def test_ids_activity(self):
        """IDS signals generate IDS signature clause."""
        inc = Incident("10.0.0.1", "ids_signature_spike")
        inc.add_signal("ids_signature_spike", "ids", "high")

        narrative = inc.get_narrative()

        assert "ids" in narrative.lower()

    def test_port_scan_activity(self):
        """Port scan signals generate scanning clause."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.metadata["dst_ports"].add(22)
        inc.metadata["dst_ports"].add(80)
        inc.metadata["dst_ports"].add(443)

        narrative = inc.get_narrative()

        assert "port" in narrative.lower() or "scan" in narrative.lower()

    def test_anomaly_activity(self):
        """Anomaly signals generate behavior clause."""
        inc = Incident("10.0.0.1", "anomaly_volume")
        inc.add_signal("anomaly_volume", "anomaly_detector", "medium")
        inc.add_signal("deviation_conn_rate", "anomaly_detector", "low")

        narrative = inc.get_narrative()

        assert "anomalous" in narrative.lower() or "anomaly" in narrative.lower()


class TestNarrativeEdgeCases:
    """Test edge cases in narrative generation."""

    def test_single_signal(self):
        """Single signal still produces valid narrative."""
        inc = Incident("10.0.0.1", "new_ip")
        inc.add_signal("new_ip", "behavior_profiler", "low")

        narrative = inc.get_narrative()

        assert "10.0.0.1" in narrative
        assert narrative.endswith(".")

    def test_to_dict_includes_narrative(self):
        """to_dict() includes the narrative field."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")

        d = inc.to_dict()

        assert "narrative" in d
        assert isinstance(d["narrative"], str)
        assert len(d["narrative"]) > 0
        assert "10.0.0.1" in d["narrative"]

    def test_narrative_severity_tag(self):
        """Narrative includes severity tag in brackets."""
        inc = Incident("10.0.0.1", "port_scan")
        inc.add_signal("port_scan", "attack_detector", "medium")

        narrative = inc.get_narrative()

        assert "[MEDIUM]" in narrative

    def test_full_example(self):
        """Complete realistic scenario: cross-source scanning."""
        now = time.time()
        inc = Incident("203.0.113.42", "port_scan")
        inc.first_seen = now - 120
        inc.last_seen = now

        inc.add_signal("port_scan", "attack_detector", "medium")
        inc.add_signal("firewall_block", "firewall", "medium")
        inc.add_signal("http_scan", "nginx", "low")
        inc.add_signal("ids_signature_spike", "ids", "high")
        inc.metadata["dst_ports"].update([22, 80, 443, 3306, 5432])
        inc.metadata["countries"].add("CN")

        mock_resolver = MagicMock()
        mock_resolver.lookup.return_value = "scanner.malicious.com"

        narrative = inc.get_narrative(dns_resolver=mock_resolver)

        # Verify all key elements are present
        assert "IP 203.0.113.42 (scanner.malicious.com)" in narrative
        assert "CN" in narrative
        assert "2 min" in narrative
        # High severity due to 3+ signal types and cross-source
        assert "[HIGH]" in narrative or "[CRITICAL]" in narrative
        assert "firewall" in narrative.lower()
        assert "web" in narrative.lower()
        assert "ids" in narrative.lower()


def run_tests():
    """Run all narrative tests."""
    test_classes = [
        TestNarrativeBasic,
        TestNarrativePhases,
        TestNarrativeTimeWindow,
        TestNarrativeGeoContext,
        TestNarrativeActivityClauses,
        TestNarrativeEdgeCases,
    ]

    passed = 0
    failed = 0

    for cls in test_classes:
        instance = cls()
        for name in dir(instance):
            if not name.startswith("test_"):
                continue
            try:
                getattr(instance, name)()
                passed += 1
                print(f"  PASS: {cls.__name__}.{name}")
            except Exception as e:
                failed += 1
                print(f"  FAIL: {cls.__name__}.{name}: {e}")

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Narrative tests: {passed}/{total} passed, {failed} failed")
    if failed == 0:
        print("ALL TESTS PASSED")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
