"""Tests for reverse_dns.py — static map, caching, resolution fallback."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch
import dns.resolver


class TestReverseDNSResolver:
    """Test the ReverseDNSResolver class."""

    def test_init_with_defaults(self):
        """Resolver initializes with sensible defaults."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            dns_server="192.168.1.1",
            enabled=True,
            cache_ttl=3600,
            redis_url="redis://redis:6379/0",
        )
        assert resolver.dns_server == "192.168.1.1"
        assert resolver.enabled is True
        assert resolver.cache_ttl == 3600
        assert resolver._resolver.nameservers == ["192.168.1.1"]
        assert resolver._resolver.timeout == 2

    def test_static_map_defaults(self):
        """Default static map has known IPs."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        assert "192.168.1.1" in resolver.static_map
        assert resolver.static_map["192.168.1.1"] == "opnsense"
        assert "192.168.1.19" in resolver.static_map
        assert resolver.static_map["192.168.1.19"] == "hassio"
        assert "192.168.1.50" in resolver.static_map
        assert resolver.static_map["192.168.1.50"] == "anomaly-agent"

    @patch('builtins.open')
    def test_static_map_from_file(self, mock_open):
        """Static map loads from file when provided."""
        mock_file = MagicMock()
        mock_file.__enter__ = lambda self: self
        mock_file.__exit__ = lambda self, *a: None
        mock_file.read.return_value = (
            "192.168.1.200=cassandra\n"
            "192.168.1.201=postgres\n"
            "# comment line\n"
            "\n"
            "10.8.0.1=vpn-gateway\n"
        )
        mock_open.return_value = mock_file

        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
            static_map_file="/tmp/test_hosts.txt",
        )
        assert resolver.static_map["192.168.1.200"] == "cassandra"
        assert resolver.static_map["192.168.1.201"] == "postgres"
        assert resolver.static_map["10.8.0.1"] == "vpn-gateway"
        # Defaults should still be there
        assert "192.168.1.1" in resolver.static_map

    def test_disabled_resolver_returns_none(self):
        """Disabled resolver returns None for all lookups."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=False,
        )
        assert resolver.lookup("192.168.1.1") is None
        assert resolver.lookup("") is None

    @patch.object(dns.resolver.Resolver, 'query')
    def test_static_map_hits_first(self, mock_query):
        """Static map is checked before DNS query."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        result = resolver.lookup("192.168.1.1")
        assert result == "opnsense"
        # DNS query should NOT be called for static map hits
        mock_query.assert_not_called()

    @patch.object(dns.resolver.Resolver, 'query')
    def test_dns_query_called_for_unknown_ip(self, mock_query):
        """DNS query is called when IP not in static map."""
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "myhost.local"
        mock_query.return_value = [mock_answer]

        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        result = resolver.lookup("192.168.1.200")
        assert result == "myhost.local"
        mock_query.assert_called_once()

    def test_empty_ip_returns_none(self):
        """Empty or None IP returns None."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        assert resolver.lookup("") is None

    @patch.object(dns.resolver.Resolver, 'query')
    def test_dns_failure_returns_none(self, mock_query):
        """DNS failure returns None gracefully."""
        mock_query.side_effect = dns.resolver.NXDOMAIN()

        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        result = resolver.lookup("192.168.1.200")
        assert result is None

    def test_redis_get_fallback(self):
        """Redis unavailable falls back to in-memory cache."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        resolver._redis_available = False
        resolver._cache["192.168.1.200"] = ("mem-host.local", "1000000")
        result = resolver.lookup("192.168.1.200")
        assert result == "mem-host.local"

    def test_get_stats(self):
        """Stats counters work correctly."""
        resolver = __import__('reverse_dns', fromlist=['ReverseDNSResolver']).ReverseDNSResolver(
            enabled=True,
        )
        resolver._resolve_count = 5
        resolver._miss_count = 3
        resolver._error_count = 1
        stats = resolver.get_stats()
        assert stats['resolve_count'] == 5
        assert stats['miss_count'] == 3
        assert stats['error_count'] == 1
        assert stats['success_rate'] == pytest.approx(5 / 8, abs=0.01)
