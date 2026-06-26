#!/usr/bin/env python3
"""Unit tests for network_classifier module.

Tests cover: IP classification (OWN/WAN/LAN/VPN/INTERNAL/UNKNOWN),
env var parsing, event recording, classify_event enrichment,
and WAN IP discovery.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock

from network_classifier import NetworkClassifier


class TestNetworkClassifierInit:
    """Test initialization and env var parsing."""

    def test_default_init(self):
        with patch.dict(os.environ, {}, clear=False):
            # Ensure no relevant env vars
            env = dict(os.environ)
            for k in list(env.keys()):
                if k in ("OWN_WAN_IPS", "LAN_IPS", "VPN_IPS", "CUSTOM_INTERFACES",
                         "WAN_IP_MIN_EVENTS", "MAX_WAN_IPS", "OPN_HOST", "OPN_PORT",
                         "OPN_API_KEY", "OPN_API_SECRET"):
                    env.pop(k, None)
            with patch.dict(os.environ, env, clear=True):
                with patch('network_classifier.requests'):
                    nc = NetworkClassifier()
                    assert nc.own_wan_ips == set()
                    assert nc.lan_ips == set()
                    assert nc.min_events_for_tracking == 10
                    assert nc.max_wan_ips == 10000

    def test_own_wan_ips_env(self):
        with patch.dict(os.environ, {"OWN_WAN_IPS": "203.0.113.1, 198.51.100.1"}):
            with patch('network_classifier.requests'):
                nc = NetworkClassifier()
                assert "203.0.113.1" in nc.own_wan_ips
                assert "198.51.100.1" in nc.own_wan_ips

    def test_lan_ips_env(self):
        with patch.dict(os.environ, {"LAN_IPS": "10.0.0.1, 192.168.1.1"}):
            with patch('network_classifier.requests'):
                nc = NetworkClassifier()
                assert "10.0.0.1" in nc.lan_ips
                assert "192.168.1.1" in nc.lan_ips

    def test_vpn_networks_env(self):
        with patch.dict(os.environ, {"VPN_IPS": "10.8.0.0/24, 172.16.0.0/16"}):
            with patch('network_classifier.requests'):
                nc = NetworkClassifier()
                assert len(nc._vpn_networks) == 2

    def test_custom_interfaces_env(self):
        with patch.dict(os.environ, {"CUSTOM_INTERFACES": "em0=wan, ovpnc1=vpn"}):
            with patch('network_classifier.requests'):
                nc = NetworkClassifier()
                assert nc._interface_map.get("em0") == "wan"
                assert nc._interface_map.get("ovpnc1") == "vpn"

    def test_invalid_vpn_network_ignored(self):
        with patch.dict(os.environ, {"VPN_IPS": "not_a_network, 10.0.0.0/8"}):
            with patch('network_classifier.requests'):
                nc = NetworkClassifier()
                assert len(nc._vpn_networks) == 1  # Only valid one


class TestClassifyIP:
    """Test IP classification logic."""

    def _create_classifier(self, own_wan="", lan="", vpn=""):
        env = {
            "OWN_WAN_IPS": own_wan,
            "LAN_IPS": lan,
            "VPN_IPS": vpn,
        }
        with patch.dict(os.environ, env):
            with patch('network_classifier.requests'):
                return NetworkClassifier()

    def test_own_wan_ip(self):
        nc = self._create_classifier(own_wan="203.0.113.1")
        assert nc.classify_ip("203.0.113.1") == "OWN"

    def test_configured_lan_ip(self):
        nc = self._create_classifier(lan="10.0.0.5")
        assert nc.classify_ip("10.0.0.5") == "LAN"

    def test_vpn_network(self):
        nc = self._create_classifier(vpn="10.8.0.0/24")
        assert nc.classify_ip("10.8.0.50") == "VPN"

    def test_rfc1918_private(self):
        nc = self._create_classifier()
        assert nc.classify_ip("192.168.1.100") == "LAN"
        assert nc.classify_ip("10.1.2.3") == "LAN"
        assert nc.classify_ip("172.16.0.1") == "LAN"

    def test_link_local_internal(self):
        nc = self._create_classifier()
        assert nc.classify_ip("169.254.1.1") == "INTERNAL"

    def test_public_wan(self):
        nc = self._create_classifier()
        assert nc.classify_ip("8.8.8.8") == "WAN"
        assert nc.classify_ip("1.1.1.1") == "WAN"

    def test_invalid_ip(self):
        nc = self._create_classifier()
        assert nc.classify_ip("not_an_ip") == "UNKNOWN"
        assert nc.classify_ip("") == "UNKNOWN"

    def test_auto_discovered_wan(self):
        nc = self._create_classifier()
        # Record an external IP
        nc.wan_ips["45.33.32.156"] = {"count": 5}
        assert nc.classify_ip("45.33.32.156") == "WAN"

    def test_auto_discovered_lan(self):
        nc = self._create_classifier()
        nc.lan_ips_auto["192.168.50.1"] = {"count": 3}
        assert nc.classify_ip("192.168.50.1") == "LAN"

    def test_classification_priority(self):
        # OWN > LAN > VPN > auto > heuristic
        nc = self._create_classifier(own_wan="203.0.113.1", lan="203.0.113.1")
        assert nc.classify_ip("203.0.113.1") == "OWN"


class TestRecordInterfaceEvent:
    """Test interface event recording."""

    def test_record_block(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_interface_event({"interface": "em0", "action": "BLOCK"})
        assert nc._interface_events["em0"]["blocked"] == 1
        assert nc._interface_events["em0"]["total"] == 1

    def test_record_pass(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_interface_event({"interface": "em0", "action": "PASS"})
        assert nc._interface_events["em0"]["passed"] == 1

    def test_empty_interface_ignored(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_interface_event({"interface": "", "action": "BLOCK"})
        assert len(nc._interface_events) == 0


class TestRecordIp:
    """Test IP recording."""

    def test_record_creates_entry(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_ip("8.8.8.8", {
            "interface": "wan",
            "dst_port": 443,
            "protocol": "TCP",
            "action": "PASS",
        })
        assert "8.8.8.8" in nc.wan_ips
        assert nc.wan_ips["8.8.8.8"]["count"] == 1

    def test_record_updates_existing(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        for i in range(3):
            nc.record_ip("8.8.8.8", {"interface": "wan"})
        assert nc.wan_ips["8.8.8.8"]["count"] == 3

    def test_record_lan_ip(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_ip("192.168.1.100", {"interface": "lan"})
        assert "192.168.1.100" in nc.lan_ips_auto

    def test_record_empty_ip(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_ip("", {"interface": "wan"})
        assert len(nc.wan_ips) == 0


class TestClassifyEvent:
    """Test event classification enrichment."""

    def test_classify_event(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        event = {
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "interface": "wan",
        }
        result = nc.classify_event(event)
        assert result["src_class"] == "WAN"
        assert result["dst_class"] == "LAN"
        assert result["is_external"] is True
        assert result["is_trusted"] is False

    def test_trusted_event(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        event = {
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
        }
        result = nc.classify_event(event)
        assert result["is_trusted"] is True

    def test_localhost(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        event = {
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
        }
        result = nc.classify_event(event)
        assert result["src_direction"] == "localhost"
        assert result["dst_direction"] == "localhost"

    def test_missing_ips(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        event = {"interface": "wan"}
        result = nc.classify_event(event)
        assert result["src_class"] == "UNKNOWN"
        assert result["dst_class"] == "UNKNOWN"


class TestRecordEvent:
    """Test full event processing."""

    def test_records_both_ips(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        event = {
            "src_ip": "45.33.32.156",
            "dst_ip": "192.168.1.1",
            "interface": "wan",
        }
        result = nc.record_event(event)
        assert "45.33.32.156" in nc.wan_ips
        assert "192.168.1.1" in nc.lan_ips_auto
        assert result["src_class"] == "WAN"
        assert result["dst_class"] == "LAN"

    def test_same_src_dst_skips(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        event = {"src_ip": "192.168.1.1", "dst_ip": "192.168.1.1"}
        nc.record_event(event)
        # Should only record once
        assert nc.lan_ips_auto["192.168.1.1"]["count"] == 1


class TestGetAllWanIps:
    """Test WAN IP queries."""

    def test_filter_min_events(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.wan_ips["1.1.1.1"] = {"count": 5}
        nc.wan_ips["8.8.8.8"] = {"count": 20}
        nc.wan_ips["9.9.9.9"] = {"count": 2}

        results = nc.get_all_wan_ips(min_events=5)
        ips = [r["ip"] for r in results]
        assert "8.8.8.8" in ips
        assert "1.1.1.1" in ips
        assert "9.9.9.9" not in ips

    def test_exclude_own(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.own_wan_ips.add("203.0.113.1")
        nc.wan_ips["203.0.113.1"] = {"count": 100}
        nc.wan_ips["45.33.32.156"] = {"count": 50}

        results = nc.get_all_wan_ips(exclude_own=True, min_events=1)
        ips = [r["ip"] for r in results]
        assert "203.0.113.1" not in ips
        assert "45.33.32.156" in ips

    def test_sorted_by_count(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.wan_ips["1.1.1.1"] = {"count": 10}
        nc.wan_ips["2.2.2.2"] = {"count": 50}
        nc.wan_ips["3.3.3.3"] = {"count": 25}

        results = nc.get_all_wan_ips(min_events=1)
        counts = [r["count"] for r in results]
        assert counts == sorted(counts, reverse=True)


class TestOwnWanIps:
    """Test own WAN IP methods."""

    def test_get_own_wan_ips(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.own_wan_ips.add("203.0.113.1")
        nc.wan_ips["203.0.113.1"] = {"count": 100}

        results = nc.get_own_wan_ips()
        assert len(results) == 1
        assert results[0]["ip"] == "203.0.113.1"

    def test_is_own_wan_ip(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.own_wan_ips.add("203.0.113.1")
        assert nc.is_own_wan_ip("203.0.113.1") is True
        assert nc.is_own_wan_ip("8.8.8.8") is False

    def test_is_external_wan(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.wan_ips["8.8.8.8"] = {"count": 5}
        nc.own_wan_ips.add("203.0.113.1")
        nc.wan_ips["203.0.113.1"] = {"count": 10}

        assert nc.is_external_wan("8.8.8.8") is True
        assert nc.is_external_wan("203.0.113.1") is False


class TestGetStats:
    """Test statistics reporting."""

    def test_stats_structure(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        nc.record_ip("8.8.8.8", {"interface": "wan"})
        nc.record_ip("192.168.1.1", {"interface": "lan"})

        stats = nc.get_stats()
        assert "wan_ips_count" in stats
        assert "lan_ips_count" in stats
        assert "vpn_ips_count" in stats
        assert stats["wan_ips_count"] >= 1
        assert stats["lan_ips_count"] >= 1


class TestNormalizeIpRecord:
    """Test IP record normalization for state migration."""

    def test_normalize_empty_record(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        record = {}
        normalized = nc._normalize_ip_record(record)
        assert "count" in normalized
        assert "interfaces" in normalized
        assert "dst_ports" in normalized
        assert "actions" in normalized

    def test_normalize_partial_record(self):
        with patch('network_classifier.requests'):
            nc = NetworkClassifier()
        record = {"count": 5}
        normalized = nc._normalize_ip_record(record)
        assert normalized["count"] == 5
        assert "interfaces" in normalized