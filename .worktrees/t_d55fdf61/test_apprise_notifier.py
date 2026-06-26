"""Tests for apprise_notifier.py — Apprise multi-platform notification support."""

import sys
import pytest
from unittest.mock import MagicMock, patch


class TestAppriseNotifier:
    """Test the AppriseNotifier class."""

    def test_init_without_apprise_library(self):
        """Apprise module not installed → notifier disabled gracefully."""
        with patch('apprise_notifier.HAS_APPRISE', False):
            # Patch apprise_lib to be None
            import apprise_notifier
            original_lib = apprise_notifier.apprise_lib
            apprise_notifier.apprise_lib = None
            try:
                notifier = apprise_notifier.AppriseNotifier("tgram://token/123")
                assert notifier.enabled is False
            finally:
                apprise_notifier.apprise_lib = original_lib

    def test_init_with_no_urls(self):
        """Empty APPRISE_URLS → notifier disabled."""
        with patch('apprise_notifier.HAS_APPRISE', True):
            # Mock apprise_lib
            mock_lib = MagicMock()
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("")
                assert notifier.enabled is False

    def test_init_with_urls(self):
        """Non-empty APPRISE_URLS → notifier enabled with targets."""
        mock_ap = MagicMock()
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("tgram://token/123,slack://webhook")
                assert notifier.enabled is True
                assert mock_ap.add.call_count == 2

    def test_send_alert_no_apprise(self):
        """Not enabled → send_alert returns False."""
        with patch('apprise_notifier.HAS_APPRISE', False):
            import apprise_notifier
            notifier = apprise_notifier.AppriseNotifier()
            assert notifier.send_alert({"attack_type": "port_scan", "ip": "1.2.3.4"}) is False

    def test_send_alert_no_urls(self):
        """No URLs configured → send_alert returns False."""
        mock_lib = MagicMock()
        mock_lib.Apprise = MagicMock()
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("")
                assert notifier.send_alert({"attack_type": "port_scan"}) is False

    def test_send_alert_success(self):
        """Alert sent successfully."""
        mock_ap = MagicMock()
        mock_ap.notify.return_value = True
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("tgram://token/123")
                alert = {
                    "attack_type": "port_scan",
                    "severity": "HIGH",
                    "ip": "192.168.1.100",
                    "count": 50,
                    "description": "Vertical scan detected",
                    "timestamp": "2026-06-18T10:00:00Z",
                }
                result = notifier.send_alert(alert)
                assert result is True
                mock_ap.notify.assert_called_once()

    def test_send_alert_notify_failure(self):
        """Apprise notify raises exception → graceful degradation."""
        mock_ap = MagicMock()
        mock_ap.notify.side_effect = Exception("Network error")
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("tgram://token/123")
                result = notifier.send_alert({"attack_type": "brute_force", "ip": "10.0.0.1"})
                assert result is False

    def test_health_check_enabled(self):
        """Health check returns True when enabled."""
        mock_ap = MagicMock()
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("tgram://token/123")
                assert notifier.health_check() is True

    def test_health_check_disabled(self):
        """Health check returns False when not enabled."""
        with patch('apprise_notifier.HAS_APPRISE', False):
            import apprise_notifier
            notifier = apprise_notifier.AppriseNotifier()
            assert notifier.health_check() is False

    def test_send_alert_minimal(self):
        """Alert with minimal data still constructs message."""
        mock_ap = MagicMock()
        mock_ap.notify.return_value = True
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("tgram://token/123")
                alert = {"attack_type": "unknown"}
                notifier.send_alert(alert)
                mock_ap.notify.assert_called_once()

    def test_send_alert_geo_result(self):
        """Geo anomaly alert format."""
        mock_ap = MagicMock()
        mock_ap.notify.return_value = True
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("slack://webhook")
                geo = {
                    "type": "geo_country_anomaly",
                    "country_code": "CN",
                    "ip": "203.0.113.50",
                    "count": 5,
                }
                notifier.send_alert(geo)
                mock_ap.notify.assert_called_once()

    def test_send_alert_wan_flap(self):
        """WAN flap alert format."""
        mock_ap = MagicMock()
        mock_ap.notify.return_value = True
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("pbul://token")
                alert = {
                    "type": "wan_flap",
                    "gateway": "wan1",
                    "old_state": "up",
                    "new_state": "down",
                    "description": "Gateway wan1 went down",
                }
                notifier.send_alert(alert)
                mock_ap.notify.assert_called_once()

    def test_multiple_apprise_targets(self):
        """Multiple comma-separated URLs all added."""
        mock_ap = MagicMock()
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("tgram://t1/1,slack://s1,mailto://m1")
                assert notifier.enabled is True
                assert mock_ap.add.call_count == 3

    def test_invalid_apprise_url_skipped(self):
        """Invalid URL logs warning but doesn't crash."""
        mock_ap = MagicMock()
        mock_ap.add.side_effect = [Exception("bad URL"), None]
        mock_lib = MagicMock(Apprise=MagicMock(return_value=mock_ap))
        
        with patch('apprise_notifier.HAS_APPRISE', True):
            with patch('apprise_notifier.apprise_lib', mock_lib):
                import apprise_notifier
                notifier = apprise_notifier.AppriseNotifier("bad://url,tgram://good/123")
                # Should still be enabled because at least one URL worked
                assert notifier.enabled is True
