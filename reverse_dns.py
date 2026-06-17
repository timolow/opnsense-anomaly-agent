"""
Reverse DNS lookup for OPNsense anomaly detection agent.

Provides IP-to-hostname resolution with persistent Redis caching
and configurable DNS server. Uses dnspython for direct queries
to the specified DNS server.
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
        dns_server: str = "",
        enabled: bool = False,
        cache_ttl: int = 3600,
        redis_url: str = "redis://redis:6379/0",
        static_map_file: Optional[str] = None,
    ):
        """
        Args:
            dns_server: DNS server IP address (e.g. "192.168.1.1")
            enabled: Whether reverse DNS resolution is active
            cache_ttl: Cache TTL in seconds (default 1 hour)
            redis_url: Redis connection URL for persistent caching
        """
        self.dns_server = dns_server
        self.enabled = enabled
        self.cache_ttl = cache_ttl
        self.redis_url = redis_url
        self.static_map: Dict[str, str] = {}  # ip -> hostname
        self.static_map_file = static_map_file

        # Load static hostname map if file provided
        if static_map_file:
            self._load_static_map(static_map_file)
        else:
            # No hardcoded static map — users should configure REVERSE_DNS_STATIC_MAP
            # or use their own DNS server. The default static map ensures zero
            # assumptions about any particular network layout.
            self.static_map = {}
            logger.info("Loaded default static hostname map (empty — configure via REVERSE_DNS_STATIC_MAP or DNS)")

        # Redis cache (persistent across restarts)
        self._redis = None
        self._redis_available = False
        self._cache: Dict[str, tuple] = {}  # In-memory fallback
        self._resolve_count = 0
        self._miss_count = 0
        self._error_count = 0
        self._redis_hits = 0

        # Always initialize resolver (used when lookups happen)
        self._resolver = dns.resolver.Resolver()
        if dns_server:
            self._resolver.nameservers = [dns_server]
        self._resolver.timeout = 2  # 2 second timeout per query
        self._resolver.lifetime = 4  # 4 second total lifetime

        # Try to connect to Redis
        if enabled:
            self._init_redis()
        else:
            logger.info(
                "Reverse DNS resolver disabled "
                "(set REVERSE_DNS_ENABLED=true to enable)"
            )

    def _init_redis(self):
        """Initialize Redis connection for caching."""
        try:
            import redis

            self._redis = redis.from_url(
                self.redis_url,
                socket_timeout=2,
                socket_connect_timeout=2,
                decode_responses=True,
            )
            # Test connection
            self._redis.ping()
            self._redis_available = True
            logger.info(
                "Redis cache connected (%s, ttl=%ds)",
                self.redis_url, self.cache_ttl,
            )
        except Exception as e:
            logger.warning(
                "Redis connection failed (%s), using in-memory cache: %s",
                self.redis_url, e,
            )
            self._redis_available = False

    def _load_static_map(self, file_path: str):
        """Load static hostname mapping from file."""
        try:
            import os
            if os.path.isfile(file_path):
                with open(file_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("=")
                        if len(parts) == 2:
                            ip, hostname = parts[0].strip(), parts[1].strip()
                            self.static_map[ip] = hostname
                logger.info("Loaded static hostname map from %s (%d entries)", file_path, len(self.static_map))
            else:
                logger.warning("Static map file %s not found, using defaults", file_path)
        except Exception as e:
            logger.warning("Failed to load static map from %s: %s", file_path, e)

    def _check_static_map(self, ip: str) -> Optional[str]:
        """Check static hostname map first."""
        if ip in self.static_map:
            return self.static_map[ip]
        return None

    def _get_from_redis(self, ip: str) -> Optional[str]:
        """Get hostname from Redis cache."""
        if not self._redis_available or not self._redis:
            return None
        try:
            hostname = self._redis.get(f"dns:{ip}")
            if hostname:
                self._redis_hits += 1
                return hostname
        except Exception as e:
            logger.debug("Redis GET failed for %s: %s", ip, e)
        return None

    def _set_redis(self, ip: str, hostname: str):
        """Store hostname in Redis cache."""
        if not self._redis_available or not self._redis:
            return
        try:
            self._redis.setex(f"dns:{ip}", self.cache_ttl, hostname)
        except Exception as e:
            logger.debug("Redis SET failed for %s: %s", ip, e)

    def _get_from_memory(self, ip: str) -> Optional[str]:
        """Get hostname from in-memory cache (fallback)."""
        if ip in self._cache:
            hostname, cached_at = self._cache[ip]
            if time.time() - float(cached_at) < self.cache_ttl:
                return hostname
            else:
                del self._cache[ip]
        return None

    def _set_memory(self, ip: str, hostname: str):
        """Store hostname in in-memory cache."""
        self._cache[ip] = (hostname, time.time())

    def lookup(self, ip: str) -> Optional[str]:
        """Resolve an IP address to hostname.

        Returns the hostname string if found, None if not available or
        resolution fails. Uses Redis cache for persistent caching,
        with in-memory fallback.

        Uses dnspython to send PTR queries directly to the configured
        DNS server instead of relying on the system resolver.
        """
        if not self.enabled or not ip:
            return None

        # 1. Check static hostname map (internal IPs)
        hostname = self._check_static_map(ip)
        if hostname:
            logger.debug("Static map: %s -> %s", ip, hostname)
            return hostname

        # 2. Check Redis cache (persistent)
        hostname = self._get_from_redis(ip)
        if hostname:
            return hostname

        # Check in-memory cache (fallback)
        hostname = self._get_from_memory(ip)
        if hostname:
            return hostname

        # Attempt resolution via dnspython
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            # in-addr.arpa for IPv4
            reverse_name = addr.reverse_pointer

            # Query for PTR records
            answers = self._resolver.query(reverse_name, "PTR")

            if answers:
                # Return the first answer, strip trailing dot
                hostname = str(answers[0].target).rstrip(".")
                # Store in both Redis and memory
                self._set_redis(ip, hostname)
                self._set_memory(ip, hostname)
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
            "redis_hits": self._redis_hits,
            "resolve_count": self._resolve_count,
            "miss_count": self._miss_count,
            "error_count": self._error_count,
        }

    def is_available(self) -> bool:
        """Check if resolver is enabled and functional."""
        return self.enabled
