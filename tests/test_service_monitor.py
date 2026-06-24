#!/usr/bin/env python3
"""Unit tests for service_monitor module.

Tests cover: ServiceProfile, OPNsenseAPIClient, ServiceMonitor initialization,
Unbound anomaly checks, WireGuard anomaly checks, polling, status reporting,
and state persistence.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from service_monitor import (
    ServiceMonitor,
    ServiceProfile,
    OPNsenseAPIClient,
    MIN_SAMPLES,
    SPIKE_ZSCORE,
    MAX_WG_PEERS,
    NTP_NORMAL_DRIFT,
    NTP_WARNING_DRIFT,
    NTP_CRITICAL_DRIFT,
    API_CACHE_TTL,
)


class TestServiceProfile:
    """Test ServiceProfile dataclass."""

    def test_creation(self):
        profile = ServiceProfile(service="unbound")
        assert profile.service == "unbound"
        assert profile.total_events == 0
        assert profile.monitored is False
        assert profile.first_seen is None
        assert profile.anomaly_log == []

    def test_monitored_flag(self):
        profile = ServiceProfile(service="wireguard", monitored=True)
        assert profile.monitored is True

    def test_is_new_true(self):
        profile = ServiceProfile(service="test", total_events=5)
        assert profile.is_new is True

    def test_is_new_false(self):
        profile = ServiceProfile(service="test", total_events=MIN_SAMPLES)
        assert profile.is_new is False


class TestOPNsenseAPIClient:
    """Test OPNsenseAPIClient."""

    def test_init(self):
        client = OPNsenseAPIClient("192.168.1.1", 6666, "key", "secret")
        assert client.base_url == "https://192.168.1.1:6666"
        assert "Authorization" in client.headers

    def test_get_success(self):
        client = OPNsenseAPIClient("10.0.0.1", 8080, "k", "s")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "test"}

        with patch('requests.get', return_value=mock_resp):
            result = client.get("/api/test")
            assert result == {"data": "test"}

    def test_get_failure(self):
        client = OPNsenseAPIClient("10.0.0.1", 8080, "k", "s")
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch('requests.get', return_value=mock_resp):
            result = client.get("/api/test")
            assert result is None

    def test_get_exception(self):
        client = OPNsenseAPIClient("10.0.0.1", 8080, "k", "s")
        with patch('requests.get', side_effect=Exception("connection error")):
            result = client.get("/api/test")
            assert result is None


class TestServiceMonitorInit:
    """Test ServiceMonitor initialization."""

    def test_init_default(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
            assert "dhcp" in monitor.profiles
            assert "unbound" in monitor.profiles
            assert "ntp" in monitor.profiles
            assert "openvpn" in monitor.profiles
            assert "wireguard" in monitor.profiles

    def test_monitored_services(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
            assert monitor.profiles["unbound"].monitored is True
            assert monitor.profiles["wireguard"].monitored is True
            assert monitor.profiles["dhcp"].monitored is False
            assert monitor.profiles["ntp"].monitored is False
            assert monitor.profiles["openvpn"].monitored is False

    def test_no_api_client_without_creds(self):
        with patch.dict(os.environ, {
            "OPN_HOST": "192.168.1.1",
            "OPN_PORT": "6666",
            "OPN_API_KEY": "",
            "OPN_API_SECRET": "",
        }):
            monitor = ServiceMonitor({})
            assert monitor.opn_client is None

    def test_api_client_with_creds(self):
        with patch.dict(os.environ, {
            "OPN_HOST": "10.0.0.1",
            "OPN_PORT": "8080",
            "OPN_API_KEY": "mykey",
            "OPN_API_SECRET": "mysecret",
        }):
            with patch('service_monitor.OPNsenseAPIClient') as mock_client:
                monitor = ServiceMonitor({})
                assert monitor.opn_client is not None


class TestUnboundSettings:
    """Test Unbound settings fetching."""

    def test_no_client_returns_empty(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = None
        result = monitor._fetch_unbound_settings()
        assert result == {}

    def test_cache_returns_cached(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = MagicMock()
        monitor.opn_client.get.return_value = {
            "unbound": {
                "general": {"enabled": "1", "port": "53", "num_threads": "4"},
                "advanced": {"dnssec": "1", "verbose": "0"},
                "acls": {"acl1": {}, "acl2": {}},
                "forward_zones": {"zone1": {}},
            }
        }
        result = monitor._fetch_unbound_settings()
        assert result["enabled"] is True
        assert result["dnssec_enabled"] is True
        assert result["num_threads"] == 4
        assert result["acl_count"] == 2
        assert result["forward_zone_count"] == 1

    def test_cache_ttl(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = MagicMock()
        monitor.opn_client.get.return_value = {
            "unbound": {
                "general": {"enabled": "1", "port": "53"},
                "advanced": {"dnssec": "0", "verbose": "0"},
                "acls": {},
                "forward_zones": {},
            }
        }
        # First call caches
        monitor._fetch_unbound_settings()
        # Change what API returns
        monitor.opn_client.get.return_value = None
        # Second call should return cached, not None-derived
        result = monitor._fetch_unbound_settings()
        assert result["enabled"] is True


class TestUnboundAnomalies:
    """Test Unbound anomaly detection."""

    def _create_monitor(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            return ServiceMonitor({})

    def test_dnssec_disabled_anomaly(self):
        monitor = self._create_monitor()
        settings = {"enabled": True, "dnssec_enabled": False, "acl_count": 5}
        anomalies = monitor._check_unbound_anomalies(settings)
        assert len(anomalies) >= 1
        dnssec_anomaly = [a for a in anomalies if a["type"] == "unbound_dnssec_disabled"]
        assert len(dnssec_anomaly) == 1
        assert dnssec_anomaly[0]["severity"] == "warning"

    def test_dnssec_enabled_no_anomaly(self):
        monitor = self._create_monitor()
        settings = {"enabled": True, "dnssec_enabled": True, "acl_count": 5}
        anomalies = monitor._check_unbound_anomalies(settings)
        dnssec_anomaly = [a for a in anomalies if a["type"] == "unbound_dnssec_disabled"]
        assert len(dnssec_anomaly) == 0

    def test_no_acls_debug(self):
        monitor = self._create_monitor()
        settings = {"enabled": True, "dnssec_enabled": True, "acl_count": 0}
        anomalies = monitor._check_unbound_anomalies(settings)
        # No anomaly for ACLs, just debug log
        pass


class TestWireGuardPeers:
    """Test WireGuard peer fetching."""

    def test_no_client_returns_empty(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = None
        result = monitor._fetch_wireguard_peers()
        assert result == {}

    def test_fetch_peers(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = MagicMock()
        monitor.opn_client.get.side_effect = [
            {
                "server": {
                    "servers": {
                        "srv1": {
                            "name": "wg-server",
                            "enabled": "1",
                            "address": "10.0.0.1/24",
                            "listen_port": "51820",
                            "mtu": "1420",
                            "private_key": "abc123def456",
                        }
                    }
                }
            },
            {
                "client": {
                    "clients": {
                        "cli1": {
                            "name": "client1",
                            "enabled": "1",
                            "public_key": "ABCDEF123456",
                            "allowed_ips": "10.0.0.2/32",
                            "persistent_keepalive": "25",
                        }
                    }
                }
            },
        ]
        result = monitor._fetch_wireguard_peers()
        assert len(result["servers"]) == 1
        assert len(result["clients"]) == 1
        assert result["total_peers"] == 2


class TestWireGuardAnomalies:
    """Test WireGuard anomaly detection."""

    def _create_monitor(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            return ServiceMonitor({})

    def test_too_many_peers(self):
        monitor = self._create_monitor()
        data = {"clients": [{"name": f"client{i}"} for i in range(MAX_WG_PEERS + 10)]}
        anomalies = monitor._check_wireguard_anomalies(data)
        assert len(anomalies) >= 1
        assert anomalies[0]["type"] == "wg_too_many_peers"

    def test_normal_peer_count(self):
        monitor = self._create_monitor()
        data = {"clients": [{"name": "client1"}]}
        anomalies = monitor._check_wireguard_anomalies(data)
        assert len(anomalies) == 0


class TestPollApi:
    """Test API polling."""

    def test_no_client_skips(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = None
        monitor.poll_api()
        assert monitor.profiles["unbound"].total_events == 0

    def test_poll_updates_profiles(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = MagicMock()
        monitor.opn_client.get.side_effect = [
            {"unbound": {"general": {"enabled": "1", "port": "53"}, "advanced": {"dnssec": "1"}, "acls": {}, "forward_zones": {}}},
            {"server": {"servers": {}}},  # WireGuard server
            {"client": {"clients": {}}},   # WireGuard client
        ]
        monitor.poll_api()
        assert monitor.profiles["unbound"].total_events == 1
        assert monitor.profiles["wireguard"].total_events == 1


class TestGetStatus:
    """Test status reporting."""

    def test_status_structure(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        status = monitor.get_status()
        assert "dhcp" in status
        assert "unbound" in status
        for svc_name, svc_status in status.items():
            assert "total_events" in svc_status
            assert "monitored" in svc_status
            assert "anomaly_count" in svc_status


class TestGetAllAnomalies:
    """Test anomaly aggregation."""

    def test_no_anomalies(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        anomalies = monitor.get_all_anomalies()
        assert anomalies == []

    def test_aggregated_anomalies(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.profiles["unbound"].anomaly_log = [
            {"type": "test1", "timestamp": "2026-01-01T00:00:00Z"},
            {"type": "test2", "timestamp": "2026-01-02T00:00:00Z"},
        ]
        anomalies = monitor.get_all_anomalies()
        assert len(anomalies) == 2
        # Sorted by timestamp descending
        assert anomalies[0]["type"] == "test2"


class TestCheckAll:
    """Test check_all anomaly detection."""

    def test_check_all_with_data(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        monitor.opn_client = MagicMock()
        monitor.opn_client.get.side_effect = [
            {"unbound": {"general": {"enabled": "1", "port": "53"}, "advanced": {"dnssec": "0"}, "acls": {}, "forward_zones": {}}},
            {"server": {"servers": {}}},  # WireGuard server
            {"client": {"clients": {}}},   # WireGuard client
        ]
        monitor.poll_api()
        anomalies = monitor.check_all()
        # Should have dnssec_disabled anomaly
        dnssec = [a for a in anomalies if a["type"] == "unbound_dnssec_disabled"]
        assert len(dnssec) >= 1


class TestProcessEvent:
    """Test event routing."""

    def test_process_event_noop(self):
        with patch('service_monitor.OPNsenseAPIClient'):
            monitor = ServiceMonitor({})
        # process_event is a no-op (API-driven monitoring)
        monitor.process_event({"service": "unbound", "data": "test"})
        assert monitor.profiles["unbound"].total_events == 0


class TestThresholds:
    """Test threshold constants."""

    def test_constants(self):
        assert MIN_SAMPLES == 15
        assert SPIKE_ZSCORE == 2.5
        assert MAX_WG_PEERS == 50
        assert API_CACHE_TTL == 60
        assert NTP_NORMAL_DRIFT < NTP_WARNING_DRIFT < NTP_CRITICAL_DRIFT
        assert NTP_NORMAL_DRIFT == 0.050
        assert NTP_CRITICAL_DRIFT == 1.000