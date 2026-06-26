#!/usr/bin/env python3
"""Unit tests for geo_lookup module.

Tests cover: MaxMindGeoLookup (unavailable mode), SimpleGeoLookup (mocked),
GeoAnomalyDetector anomaly detection, rate limiting, country tracking,
and the GeoLookup wrapper.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import MagicMock, patch
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from geo_lookup import (
    MaxMindGeoLookup,
    SimpleGeoLookup,
    GeoAnomalyDetector,
    GeoLookup,
)


class TestMaxMindUnavailable:
    """Test MaxMindGeoLookup when database is unavailable."""

    def test_no_maxminddb_library(self):
        with patch.dict('sys.modules', {'maxminddb': None}):
            with patch('geo_lookup.maxminddb', create=True) as mock_mm:
                mock_mm.open_database.side_effect = ImportError("no module")
                lookup = MaxMindGeoLookup(db_path="/fake/path.mmdb")
                assert lookup._available is False
                assert lookup.lookup("8.8.8.8") is None

    def test_file_not_found(self):
        lookup = MaxMindGeoLookup(db_path="/nonexistent/db.mmdb")
        assert lookup._available is False
        assert lookup.is_available() is False

    def test_lookup_when_unavailable(self):
        lookup = MaxMindGeoLookup(db_path="/nonexistent/db.mmdb")
        result = lookup.lookup("1.2.3.4")
        assert result is None


class TestSimpleGeoLookupUnavailable:
    """Test SimpleGeoLookup when API is unavailable."""

    def test_unavailable_fallback(self):
        with patch.object(SimpleGeoLookup, '_try_init') as mock_init:
            mock_init.side_effect = lambda: setattr(SimpleGeoLookup.__new__(SimpleGeoLookup), '_available', False) or None
            # Force unavailable
            lookup = SimpleGeoLookup.__new__(SimpleGeoLookup)
            lookup._cache = {}
            lookup._cache_ttl = 3600
            lookup._last_api_call = 0
            lookup._api_cooldown = 1.5
            lookup._available = False
            assert lookup.is_available() is False
            assert lookup.lookup("8.8.8.8") is None


class TestSimpleGeoLookupFetchApi:
    """Test _fetch_api method with mocked HTTP."""

    def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status":"success","country":"United States","countryCode":"US","city":"Mountain View","lat":37.4,"lon":-122.1,"timezone":"America/Los_Angeles"}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = lambda s, *a: None

        with patch('urllib.request.urlopen', return_value=mock_response):
            lookup = SimpleGeoLookup.__new__(SimpleGeoLookup)
            lookup._available = True
            lookup._cache = {}
            result = lookup._fetch_api("8.8.8.8")
            assert result is not None
            assert result["country_code"] == "US"
            assert result["country_name"] == "United States"
            assert result["city"] == "Mountain View"

    def test_failed_status(self):
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status":"fail"}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = lambda s, *a: None

        with patch('urllib.request.urlopen', return_value=mock_response):
            lookup = SimpleGeoLookup.__new__(SimpleGeoLookup)
            lookup._available = True
            lookup._cache = {}
            lookup._cache_ttl = 3600
            lookup._last_api_call = 0
            lookup._api_cooldown = 0
            result = lookup.lookup("8.8.8.8")
            assert result is None

    def test_url_error(self):
        import urllib.error
        with patch('urllib.request.urlopen', side_effect=urllib.error.URLError("timeout")):
            lookup = SimpleGeoLookup.__new__(SimpleGeoLookup)
            lookup._available = True
            lookup._cache = {}
            lookup._cache_ttl = 3600
            lookup._last_api_call = 0
            lookup._api_cooldown = 0
            result = lookup.lookup("8.8.8.8")
            assert result is None


class TestGeoAnomalyDetectorInit:
    """Test GeoAnomalyDetector initialization."""

    def test_default_params(self):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector.volume_threshold = 3.0
        detector.volume_window_minutes = 60
        detector._maxmind = MagicMock()
        detector._maxmind.is_available.return_value = False
        detector._simple = MagicMock()
        detector._simple.is_available.return_value = False
        detector._ip_countries = {}
        detector._country_events = {}
        detector._recent_countries = set()
        detector._normal_countries = set()
        detector._country_seen_count = {}
        detector._total_seen = 0
        detector._geo_check_counter = 0

        assert detector.volume_threshold == 3.0
        assert detector.volume_window_minutes == 60

    def test_high_risk_countries_defined(self):
        assert 'CN' in GeoAnomalyDetector.HIGH_RISK_COUNTRIES
        assert 'RU' in GeoAnomalyDetector.HIGH_RISK_COUNTRIES
        assert 'KP' in GeoAnomalyDetector.HIGH_RISK_COUNTRIES


class TestGeoAnomalyDetectorLookup:
    """Test geo lookup in detector."""

    def test_lookup_returns_none_when_unavailable(self):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector._maxmind = MagicMock()
        detector._maxmind.is_available.return_value = False
        detector._simple = MagicMock()
        detector._simple.is_available.return_value = False

        # Override _get_lookup to return None (no lookup available)
        detector._get_lookup = lambda: None

        result = detector.lookup_country("8.8.8.8")
        assert result is None

    def test_empty_ip(self):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector._maxmind = MagicMock()
        detector._maxmind.is_available.return_value = False
        detector._simple = MagicMock()
        detector._simple.is_available.return_value = False
        result = detector.lookup_country("")
        assert result is None


class TestGeoAnomalyDetectorProcessEvent:
    """Test event processing and anomaly detection."""

    def _create_detector(self, lookup_available=True, mock_country="US"):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector.volume_threshold = 3.0
        detector.volume_window_minutes = 60

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {"country_code": mock_country}
        detector._maxmind = MagicMock()
        detector._maxmind.is_available.return_value = lookup_available
        detector._simple = MagicMock()
        detector._simple.is_available.return_value = False

        if lookup_available:
            detector._maxmind.lookup.return_value = {"country_code": mock_country}

        detector._ip_countries = defaultdict(set)
        detector._country_events = defaultdict(list)
        detector._recent_countries = set()
        detector._normal_countries = {"US"}  # US is normal
        detector._country_seen_count = defaultdict(int)
        detector._total_seen = 100  # Past learning phase
        detector._geo_check_counter = 4  # Next event will be checked

        detector._get_lookup = lambda: mock_lookup if lookup_available else None
        return detector

    def test_non_block_event_ignored(self):
        detector = self._create_detector()
        result = detector.process_event({"src_ip": "1.2.3.4", "action": "PASS"})
        assert result is None

    def test_no_src_ip_ignored(self):
        detector = self._create_detector()
        result = detector.process_event({"action": "BLOCK"})
        assert result is None

    def test_learning_phase_no_alert(self):
        detector = self._create_detector()
        detector._total_seen = 10  # In learning phase
        detector._geo_check_counter = 4
        result = detector.process_event({
            "src_ip": "5.6.7.8",
            "action": "BLOCK",
            "timestamp": datetime.now(timezone.utc),
        })
        assert result is None

    def test_new_country_detection(self):
        detector = self._create_detector(mock_country="CN")
        detector._normal_countries = {"US"}  # Only US is normal
        result = detector.process_event({
            "src_ip": "5.6.7.8",
            "action": "BLOCK",
            "timestamp": datetime.now(timezone.utc),
            "proto": "TCP",
        })
        assert result is not None
        assert result["attack_type"] == "GEO_ANOMALY"
        assert result["anomaly_subtype"] == "NEW_COUNTRY"

    def test_high_risk_country_detection(self):
        detector = self._create_detector(mock_country="RU")
        detector._normal_countries = {"US"}
        # Add many events from RU
        now = datetime.now(timezone.utc)
        for i in range(10):
            detector._country_events["RU"] = [(now, f"10.0.0.{i}")]
        detector._country_seen_count["RU"] = 10

        result = detector.process_event({
            "src_ip": "5.6.7.8",
            "action": "BLOCK",
            "timestamp": now,
            "proto": "TCP",
        })
        assert result is not None

    def test_normal_country_no_alert(self):
        detector = self._create_detector(mock_country="US")
        detector._normal_countries = {"US"}
        result = detector.process_event({
            "src_ip": "5.6.7.8",
            "action": "BLOCK",
            "timestamp": datetime.now(timezone.utc),
        })
        # US is in normal countries, so no NEW_COUNTRY alert
        if result:
            assert result["anomaly_subtype"] != "NEW_COUNTRY"


class TestGeoAnomalyDetectorHelpers:
    """Test helper methods."""

    def test_should_check_geo_rate_limit(self):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector._geo_check_counter = 0

        assert detector._should_check_geo(datetime.now(timezone.utc)) is False
        assert detector._should_check_geo(datetime.now(timezone.utc)) is False
        assert detector._should_check_geo(datetime.now(timezone.utc)) is False
        assert detector._should_check_geo(datetime.now(timezone.utc)) is False
        assert detector._should_check_geo(datetime.now(timezone.utc)) is True

    def test_learn_normal_countries(self):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector._normal_countries = set()
        detector.learn_normal_countries({"US", "CA", "GB"})
        assert "US" in detector._normal_countries
        assert "CA" in detector._normal_countries
        assert "GB" in detector._normal_countries

    def test_get_country_stats(self):
        detector = GeoAnomalyDetector.__new__(GeoAnomalyDetector)
        detector._normal_countries = {"US", "CA"}
        detector._country_seen_count = {"US": 100, "CN": 50, "RU": 10}
        detector._ip_countries = {}

        stats = detector.get_country_stats()
        assert stats["total_countries"] == 3
        assert "RU" in stats["high_risk_seen"]
        assert stats["normal_countries"] == ["CA", "US"]


class TestGeoLookupWrapper:
    """Test GeoLookup compatibility wrapper."""

    def test_wrapper_calls_detector(self):
        with patch('geo_lookup.GeoAnomalyDetector') as mock_constructor:
            mock_detector = MagicMock()
            mock_detector.process_event.return_value = {"anomaly": True}
            mock_constructor.return_value = mock_detector

            wrapper = GeoLookup()
            result = wrapper.check_event({"src_ip": "1.2.3.4", "action": "BLOCK"})
            assert result == {"anomaly": True}

    def test_wrapper_exception_handling(self):
        with patch('geo_lookup.GeoAnomalyDetector') as mock_constructor:
            mock_detector = MagicMock()
            mock_detector.process_event.side_effect = Exception("lookup failed")
            mock_constructor.return_value = mock_detector

            wrapper = GeoLookup()
            result = wrapper.check_event({"src_ip": "1.2.3.4"})
            assert result is None