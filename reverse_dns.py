"""
Reverse DNS lookup for OPNsense anomaly detection agent.

Provides IP-to-hostname resolution with caching and configurable DNS server.
Uses dnspython for direct queries to the specified DNS server.
"""

import time
import logging
from typing import Optional, Dict

import dns.resolver

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
            dns_server: DNS server IP address (e.g. "192.168.1.1")
            enabled: Whether reverse DNS resolution is active
            cache_ttl: Cache TTL in seconds (default 1 hour)
        """
        self.dns_server = dns_server
        self.enabled = enabled
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[str, float]] = {}
        self._resolve_count = 0
        self._miss_count = 0
        self._error_count = 0

        # Build a nameserver list that dnspython can use
        # We create a Resolver instance with our custom nameserver
        self._resolver = dns.resolver.Resolver()
        self._resolver.nameservers = [dns_server]
        self._resolver.timeout = 2  # 2 second timeout per query
        self._resolver.lifetime = 4  # 4 second total lifetime

        if self.enabled:
            logger.info(
                "Reverse DNS resolver enabled (server=%s, ttl=%ds)",
                dns_server, cache_ttl,
            )
        else:
            logger.info(
                "Reverse DNS resolver disabled "
                "(set REVERSE_DNS_ENABLED=true to enable)"
            )

    def lookup(self, ip: str) -> Optional[str]:
        """Resolve an IP address to hostname.

        Returns the hostname string if found, None if not available or
        resolution fails. Uses cache to avoid repeated lookups.

        Uses dnspython to send PTR queries directly to the configured
        DNS server instead of relying on the system resolver.
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

        # Attempt resolution via dnspython
        try:
            # Build the reverse DNS query name for the IP
            # e.g. 1.168.192.in-addr.arpa for 192.168.1.1
            import ipaddress

            addr = ipaddress.ip_address(ip)
            # in-addr.arpa for IPv4
            reverse_name = addr.reverse_pointer

            # Query for PTR records
            answers = self._resolver.query(reverse_name, "PTR")

            if answers:
                # Return the first answer, strip trailing dot
                hostname = str(answers[0].target).rstrip(".")
                self._cache[ip] = (hostname, time.time())
                self._resolve_count += 1
                logger.debug("Resolved %s -> %s via %s", ip, hostname, self.dns_server)
                return hostname
            else:
                self._miss_count += 1
                logger.debug("No PTR record for %s (%s)", ip, self.dns_server)
                return None

        except dns.resolver.NoAnswer:
            self._miss_count += 1
            logger.debug("No PTR record for %s (%s)", ip, self.dns_server)
            return None

        except dns.resolver.NXDOMAIN:
            self._miss_count += 1
            logger.debug("NXDOMAIN for %s (%s)", ip, self.dns_server)
            return None

        except dns.exception.Timeout:
            self._error_count += 1
            logger.debug("DNS timeout resolving %s via %s", ip, self.dns_server)
            return None

        except dns.resolver.NoNameservers:
            self._error_count += 1
            logger.warning(
                "No nameservers available for %s (%s)", ip, self.dns_server
            )
            return None

        except dns.exception.DNSException as e:
            self._error_count += 1
            logger.debug("DNS error resolving %s via %s: %s", ip, self.dns_server, e)
            return None

        except Exception as e:
            self._error_count += 1
            logger.warning("Unexpected error resolving %s via %s: %s", ip, self.dns_server, e)
            return None

    def get_stats(self) -> dict:
        """Return resolver statistics."""
        return {
            "enabled": self.enabled,
            "dns_server": self.dns_server,
            "cache_size": len(self._cache),
            "resolve_count": self._resolve_count,
            "miss_count": self._miss_count,
            "error_count": self._error_count,
        }

    def is_available(self) -> bool:
        """Check if resolver is enabled and functional."""
        return self.enabled
