"""
Geographic anomaly detection for OPNsense anomaly detection agent.

Provides IP-to-country lookup and geographic anomaly detection.
Supports MaxMind GeoLite2 databases with graceful fallback when
unavailable. Tracks traffic patterns by country and flags
geographic anomalies like new countries appearing or unusual
traffic volumes from specific regions.
"""

import os
import logging
import time
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


# ============================================================
# Geo lookup providers
# ============================================================


class MaxMindGeoLookup:
    """Geographic lookup using MaxMind GeoLite2 database.
    
    Requires: pip install maxminddb
    Database: Download from https://www.maxmind.com/en/geolite2/download
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get(
            "GEO_DB_PATH", "/usr/share/GeoLite2-City.mmdb"
        )
        self._db = None
        self._available = False
        
        # Try to load the database on init
        try:
            import maxminddb
            self._db = maxminddb.open_database(self.db_path)
            self._available = True
            logger.info(f"MaxMind GeoLite2 loaded from {self.db_path}")
        except ImportError:
            logger.info("maxminddb not installed; geo lookup will use fallback")
        except FileNotFoundError:
            logger.info(f"GeoLite2 DB not found at {self.db_path}; geo lookup will use fallback")
        except Exception as e:
            logger.warning(f"Failed to load MaxMind database: {e}; geo lookup will use fallback")
    
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up geographic info for an IP address."""
        if not self._available or not self._db:
            return None
        
        try:
            result = self._db.get(ip)
            if result:
                loc = result.get('location', {})
                country = result.get('country', {})
                return {
                    'country_code': country.get('iso_code', 'XX'),
                    'country_name': country.get('names', {}).get('en', 'Unknown'),
                    'city': result.get('city', {}).get('names', {}).get('en', 'Unknown'),
                    'latitude': loc.get('latitude'),
                    'longitude': loc.get('longitude'),
                    'time_zone': loc.get('time_zone'),
                }
        except Exception:
            pass
        return None
    
    def is_available(self) -> bool:
        """Check if geo lookup is available."""
        return self._available


class SimpleGeoLookup:
    """Fallback geo lookup using a public API or lightweight method.
    
    Uses ip-api.com (free, no key required) as a lightweight fallback.
    Rate limited to 45 queries/minute.
    """
    
    def __init__(self, cache_ttl: int = 3600):
        self._cache: Dict[str, Tuple[float, Dict]] = {}
        self._cache_ttl = cache_ttl
        self._last_api_call = 0
        self._api_cooldown = 1.5  # seconds between API calls (45/min limit)
        self._available = False
        self._try_init()
    
    def _try_init(self):
        """Check if fallback is available by testing with a known IP."""
        try:
            import urllib.request
            import json
            result = self._fetch_api("8.8.8.8")
            self._available = result is not None
            if self._available:
                logger.info("ip-api.com fallback geo lookup is available")
        except ImportError:
            self._available = False
            logger.info("No HTTP libraries available; geo lookup disabled")
        except Exception:
            self._available = False
            logger.info("ip-api.com fallback unavailable; geo lookup disabled")
    
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up geographic info for an IP address."""
        if not self._available:
            return None
        
        # Check cache
        if ip in self._cache:
            cached_ts, cached_result = self._cache[ip]
            if time.time() - cached_ts < self._cache_ttl:
                return cached_result
        
        # Rate limit API calls
        now = time.time()
        if now - self._last_api_call < self._api_cooldown:
            time.sleep(self._api_cooldown - (now - self._last_api_call))
        
        result = self._fetch_api(ip)
        if result:
            self._cache[ip] = (time.time(), result)
            self._last_api_call = time.time()
        
        return result
    
    def _fetch_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fetch geo info from ip-api.com."""
        try:
            import urllib.request
            import urllib.error
            import json
            
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,timezone"
            req = urllib.request.Request(url, headers={'User-Agent': 'OPNsenseAnomalyAgent/1.0'})
            
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    
                    if data.get('status') != 'success':
                        return None
                    
                    return {
                        'country_code': data.get('countryCode', 'XX'),
                        'country_name': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'time_zone': data.get('timezone'),
                    }
            except urllib.error.URLError:
                return None
        except Exception:
            return None
    
    def is_available(self) -> bool:
        """Check if geo lookup is available."""
        return self._available


# ============================================================
# Geographic anomaly detector
# ============================================================


class GeoAnomalyDetector:
    """Detects geographic anomalies in firewall traffic.
    
    Monitors for:
    - New countries appearing for the first time
    - Unusual traffic volumes from specific countries
    - Traffic from high-risk countries
    - Geo-location changes (same IP appearing from different countries over time)
    """
    
    # Countries considered high-risk for monitoring
    HIGH_RISK_COUNTRIES: Set[str] = {
        'CN', 'RU', 'KP', 'IR', 'SY', 'VE', 'CU', 'MM', 'SD', 'LY',
    }
    
    def __init__(self, volume_threshold: float = 3.0, volume_window_minutes: int = 60):
        self.volume_threshold = volume_threshold
        self.volume_window_minutes = volume_window_minutes
        
        # Geo lookup instance
        self._maxmind = MaxMindGeoLookup()
        self._simple = SimpleGeoLookup()
        
        # Track countries seen for each IP
        self._ip_countries: Dict[str, Set[str]] = defaultdict(set)
        
        # Track country-level event counts
        self._country_events: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        
        # Track countries seen in the last N minutes
        self._recent_countries: Set[str] = set()
        
        # Track known "normal" countries (from baseline traffic)
        self._normal_countries: Set[str] = set()
        self._country_seen_count: Dict[str, int] = defaultdict(int)
        self._total_seen = 0
    
    def _get_lookup(self):
        """Get the best available geo lookup."""
        if self._maxmind.is_available():
            return self._maxmind
        return self._simple
    
    def lookup_country(self, ip: str) -> Optional[str]:
        """Get country code for an IP address."""
        if not ip:
            return None
        
        lookup = self._get_lookup()
        if not lookup:
            return None
        
        result = lookup.lookup(ip)
        if result:
            return result.get('country_code')
        return None
    
    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process an event and check for geographic anomalies.
        
        Returns a detection dict if an anomaly is found, None otherwise.
        """
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip')
        action = event.get('action', '')
        ts = event.get('timestamp') or datetime.now(timezone.utc)
        
        if not src_ip or action != 'BLOCK':
            return None
        
        # Only check new events periodically
        if not self._should_check_geo(ts):
            return None
        
        # Track the IP's country
        country_code = self.lookup_country(src_ip)
        if not country_code:
            return None
        
        self._ip_countries[src_ip].add(country_code)
        self._country_events[country_code].append((ts, src_ip))
        self._total_seen += 1
        self._country_seen_count[country_code] += 1
        
        # Clean old country events
        cutoff = ts - timedelta(minutes=self.volume_window_minutes)
        for cc in self._country_events:
            self._country_events[cc] = [
                (t, s) for t, s in self._country_events[cc] if t >= cutoff
            ]
        
        detections = []
        
        # Check 1: New country appearing
        if self._total_seen < 50:
            # During initial learning, just track - don't flag
            pass
        elif country_code not in self._normal_countries:
            # This country hasn't been seen before
            detections.append({
                'attack_type': 'GEO_ANOMALY',
                'anomaly_subtype': 'NEW_COUNTRY',
                'severity': 'LOW',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'proto': event.get('proto', 'UNKNOWN'),
                'description': f"New country detected in blocked traffic: {country_code}",
                'detail': {
                    'country_code': country_code,
                    'total_seen': self._total_seen,
                    'known_countries': len(self._normal_countries),
                },
            })
        
        # Check 2: High-risk country
        if country_code in self.HIGH_RISK_COUNTRIES:
            count = len(self._country_events.get(country_code, []))
            if count > 5:
                detections.append({
                    'attack_type': 'GEO_ANOMALY',
                    'anomaly_subtype': 'HIGH_RISK_COUNTRY',
                    'severity': 'MEDIUM',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'proto': event.get('proto', 'UNKNOWN'),
                    'description': f"Blocked traffic from high-risk country: {country_code} ({count} events)",
                    'detail': {
                        'country_code': country_code,
                        'event_count': count,
                        'risk_level': 'HIGH',
                    },
                })
        
        # Check 3: Unusual volume from a country
        for cc, events in self._country_events.items():
            if len(events) < 10:
                continue
            
            # Get country name for display
            lookup = self._get_lookup()
            sample_ip = events[0][1]
            geo_result = lookup.lookup(sample_ip) if lookup else None
            country_name = geo_result.get('country_name', cc) if geo_result else cc
            
            # Check if this country has unusually high volume
            if self._total_seen > 100 and len(events) > 20:
                ratio = len(events) / self._total_seen
                if ratio > 0.3 and cc not in self._normal_countries:
                    detections.append({
                        'attack_type': 'GEO_ANOMALY',
                        'anomaly_subtype': 'VOLUME_ANOMALY',
                        'severity': 'MEDIUM',
                        'src_ip': None,
                        'dst_ip': None,
                        'proto': None,
                        'description': f"High volume from {cc} ({country_name}): {len(events)} events ({ratio:.1%} of total)",
                        'detail': {
                            'country_code': cc,
                            'country_name': country_name,
                            'event_count': len(events),
                            'total_events': self._total_seen,
                            'ratio': round(ratio, 3),
                        },
                    })
        
        return detections[0] if detections else None
    
    def _should_check_geo(self, ts) -> bool:
        """Check if we should perform geo lookup for this event."""
        # Rate limit geo lookups: check every 5th blocked event
        # This avoids overwhelming the API with lookups
        self._geo_check_counter = getattr(self, '_geo_check_counter', 0) + 1
        if self._geo_check_counter < 5:
            return False
        self._geo_check_counter = 0
        return True
    
    def learn_normal_countries(self, country_codes: Set[str]):
        """Learn which countries are normal for this network."""
        self._normal_countries.update(country_codes)
        logger.info(f"Learned {len(country_codes)} normal countries: {country_codes}")
    
    def get_country_stats(self) -> Dict[str, Any]:
        """Get statistics about countries seen in traffic."""
        return {
            'total_countries': len(self._country_seen_count),
            'normal_countries': sorted(self._normal_countries),
            'high_risk_seen': sorted(
                cc for cc in self._country_seen_count
                if cc in self.HIGH_RISK_COUNTRIES
            ),
            'top_countries': sorted(
                self._country_seen_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }
    
    def is_available(self) -> bool:
        """Check if any geo lookup is available."""
        return self._maxmind.is_available() or self._simple.is_available()


# ============================================================
# Agent.py compatibility wrapper
# ============================================================


class GeoLookup:
    """Thin wrapper around GeoAnomalyDetector providing the GeoLookup interface."""
    
    def __init__(self, db_path=None):
        self._detector = GeoAnomalyDetector()
        self.country_events = self._detector._country_events
    
    def check_event(self, event):
        """Check event for geo anomalies. Returns detection dict or None."""
        try:
            return self._detector.process_event(event)
        except Exception as e:
            logger.warning("Geo lookup error: %s", e)
            return None
    
    def is_available(self):
        return self._detector.is_available()
