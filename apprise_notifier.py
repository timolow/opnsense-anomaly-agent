"""
Apprise notification support for OPNsense anomaly detection agent.

Provides multi-platform alerting via Apprise (Telegram, Slack, Email,
Webhooks, SMS, PushBullet, Gotify, and 70+ other services) using a
unified URI scheme. Optional — agent runs fine without it.
"""

import os
import logging
from typing import Dict, Any


logger = logging.getLogger(__name__)

# Try importing apprise; gracefully degrade if unavailable
try:
    import apprise as apprise_lib
    HAS_APPRISE = True
except ImportError:
    apprise_lib = None  # type: ignore
    HAS_APPRISE = False


class AppriseNotifier:
    """Wraps Apprise for multi-platform alerting."""

    def __init__(self, apprise_urls: str = ""):
        """
        Args:
            apprise_urls: Comma-separated Apprise URLs.
                Examples:
                  - "tgram://BOT_TOKEN/CHAT_ID"
                  - "slack://webhook_url"
                  - "mailto://user:pass@emailhost?to=recipient@example.com"
                  - "pbul://API_TOKEN"
        """
        self.enabled = False

        if not HAS_APPRISE:
            logger.warning("Apprise module not installed — notifications disabled")
            return

        if not apprise_urls.strip():
            logger.info("Apprise not configured (set APPRISE_URLS)")
            return

        self._ap = apprise_lib.Apprise()
        urls = [u.strip() for u in apprise_urls.split(",") if u.strip()]
        for url in urls:
            try:
                self._ap.add(url)
                logger.info("Apprise notification target added: %s", url[:50])
            except Exception as e:
                logger.warning("Apprise URL rejected (%s): %s", url[:40], e)

        self.enabled = bool(self._ap)

        if self.enabled:
            logger.info("Apprise enabled with %d notification target(s)", len(urls))

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Send an alert through Apprise.

        Args:
            alert: Alert dict with keys like attack_type, severity, ip, count, description.

        Returns:
            True if alert was sent, False if skipped by rate-limit or failure.
        """
        if not self.enabled:
            return False

        # Build a human-readable message
        attack = alert.get("attack_type", "unknown")
        severity = alert.get("severity", "MEDIUM").upper()
        ip = alert.get("ip", "N/A")
        count = alert.get("count", 1)
        description = alert.get("description", "")
        timestamp = alert.get("timestamp", "")

        title = f"🚨 [{severity}] {attack}"
        body = (
            f"**Attack:** {attack}\n"
            f"**Severity:** {severity}\n"
            f"**Source IP:** {ip}\n"
            f"**Count:** {count}\n"
        )
        if description:
            body += f"**Details:** {description}\n"
        if timestamp:
            body += f"**Time:** {timestamp}"

        sent = False
        try:
            self._ap.notify(
                title=title,
                body=body,
                body_format=apprise_lib.NotifyFormat.MARKDOWN,
            )
            sent = True
        except Exception as e:
            logger.warning("Apprise notification failed: %s", e)

        return sent

    def health_check(self) -> bool:
        """Verify Apprise connectivity (best-effort, doesn't send real alert)."""
        if not self.enabled:
            return False
        try:
            return bool(self._ap)
        except Exception:
            return False
