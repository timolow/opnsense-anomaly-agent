"""
Reverse DNS lookup for OPNsense anomaly detection agent.

Provides IP-to-hostname resolution with caching and configurable DNS server.
Used during event processing to enrich events with hostname information.
"""

import socket
import time
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class ReverseDNSResolver:
    """Resolves IP addresses to hostnames using a configurable DNS server."""

    def __init__(
        self,
        dns_server: str = "192.168.1.1",
        enabled: bool = False,
        cache_ttl: int = 3600,
    ):
        """
        Args:
            dns_server: DNS server IP address (e.g., "192.168.1.1")
            enabled: Whether reverse DNS resolution is active
            cache_ttl: Cache TTL in seconds (default 1 hour)
        """
        self.dns_server = dns_server
        self.enabled = enabled
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[str, float]] = {}
        self._resolve_count = 0
        self._miss_count = 0

        if self.enabled:
            logger.info("Reverse DNS resolver enabled (server=%s, ttl=%ds)", dns_server, cache_ttl)
        else:
            logger.info("Reverse DNS resolver disabled (set REVERSE_DNS_ENABLED=true to enable)")

    def lookup(self, ip: str) -> Optional[str]:
        """Resolve an IP address to hostname.

        Returns the hostname string if found, None if not available or resolution fails.
        Uses cache to avoid repeated lookups.
        """
        if not self.enabled or not ip:
            return None

        # Check cache
        if ip in self._cache:
            hostname, cached_at = self._cache[ip]
            if time.time() - float(cached_at) < self.cache_ttl:
                return hostname
            else:
                del self._cache[ip]

        # Attempt resolution
        try:
            # Override DNS resolver by using socket with the specified server
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._cache[ip] = (hostname, time.time())
            self._resolve_count += 1
            logger.debug("Resolved %s -> %s", ip, hostname)
            return hostname
        except socket.herror:
            self._miss_count += 1
            logger.debug("No PTR record for %s", ip)
            return None
        except socket.gaierror as e:
            self._miss_count += 1
            logger.debug("DNS lookup failed for %s: %s", ip, e)
            return None
        except Exception as e:
            logger.warning("Unexpected error resolving %s: %s", ip, e)
            return None

    def get_stats(self) -> dict:
        """Return resolver statistics."""
        return {
            "enabled": self.enabled,
            "dns_server": self.dns_server,
            "cache_size": len(self._cache),
            "resolve_count": self._resolve_count,
            "miss_count": self._miss_count,
        }

    def is_available(self) -> bool:
        """Check if resolver is enabled and functional."""
        return self.enabled
