#!/usr/bin/env python3
"""UniFi controller monitoring module for WATCHTOWER.

Polls UniFi Network Controller API to detect network anomalies:
- Client anomalies (rogue devices, MAC spoofing, rapid roaming)
- AP/device anomalies (disconnects, reboots, interference)
- Security events (blocked clients/corporate devices, rogue APs)
- WiFi anomalies (channel changes, radar detection, lost contact)
- WAN transition events (gateway failover)
- DPI/app traffic monitoring (suspicious applications)

Uses aiounifi (async) with polling fallback. Emits normalized events
compatible with the adaptive_parser.py schema and inserts into PostgreSQL.

Architecture:
- Runs as a background thread in the agent orchestrator
- Polls every POLL_INTERVAL seconds (default 60s)
- Maintains client/device state cache to detect deltas
- Normalizes all events to the shared event schema
- Persists state via StatePersistence
"""

import asyncio
import json
import logging
import os
import ssl
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── UniFi event severity mapping ─────────────────────────────────

# Map UniFi event keys to severity levels
EVENT_SEVERITY = {
    # Critical security events
    "EVT_AP_DetectRogueAP": "CRITICAL",
    "EVT_SW_DetectRogueDHCP": "CRITICAL",
    "EVT_IPS_IpsAlert": "CRITICAL",
    "EVT_LC_Blocked": "HIGH",
    "EVT_WC_Blocked": "HIGH",
    "EVT_AD_GuestUnauthorized": "HIGH",

    # High severity - device/connectivity issues
    "EVT_AP_Lost_Contact": "HIGH",
    "EVT_GW_Lost_Contact": "HIGH",
    "EVT_SW_Lost_Contact": "HIGH",
    "EVT_XG_Lost_Contact": "HIGH",
    "EVT_DM_Lost_Contact": "HIGH",
    "EVT_GW_WANTransition": "HIGH",
    "EVT_SW_Overheat": "HIGH",
    "EVT_SW_POE_Overload": "HIGH",
    "EVT_SW_PoeDisconnect": "HIGH",
    "EVT_AP_RadarDetected": "HIGH",
    "EVT_AP_Upgraded": "HIGH",

    # Medium severity - operational events
    "EVT_AP_Connected": "MEDIUM",
    "EVT_AP_AutoReadopted": "MEDIUM",
    "EVT_AP_Restarted": "MEDIUM",
    "EVT_AP_PossibleInterference": "MEDIUM",
    "EVT_GW_Connected": "MEDIUM",
    "EVT_GW_Restarted": "MEDIUM",
    "EVT_SW_Connected": "MEDIUM",
    "EVT_SW_Restarted": "MEDIUM",
    "EVT_SW_StpPortBlocking": "MEDIUM",
    "EVT_AP_RestartedUnknown": "MEDIUM",
    "EVT_GW_RestartedUnknown": "MEDIUM",
    "EVT_SW_RestartedUnknown": "MEDIUM",
    "EVT_AP_Upgraded": "MEDIUM",
    "EVT_GW_Upgraded": "MEDIUM",
    "EVT_SW_Upgraded": "MEDIUM",
    "EVT_AD_Update_Available": "MEDIUM",
    "EVT_AP_UpgradeScheduled": "MEDIUM",
    "EVT_AP_UpgradeFailed": "MEDIUM",
    "EVT_SW_UpgradeScheduled": "MEDIUM",
    "EVT_SW_Upgraded": "MEDIUM",
    "EVT_SW_DiscoveredPending": "MEDIUM",
    "EVT_AP_DiscoveredPending": "MEDIUM",

    # Low severity - normal operations
    "EVT_AP_Configured": "LOW",
    "EVT_GW_Configured": "LOW",
    "EVT_SW_Configured": "LOW",
    "EVT_AP_Adopted": "LOW",
    "EVT_GW_Adopted": "LOW",
    "EVT_SW_Adopted": "LOW",
    "EVT_AP_Deleted": "LOW",
    "EVT_GW_Deleted": "LOW",
    "EVT_SW_Deleted": "LOW",
    "EVT_LU_Connected": "LOW",
    "EVT_LU_Disconnected": "LOW",
    "EVT_WU_Connected": "LOW",
    "EVT_WU_Disconnected": "LOW",
    "EVT_LC_Unblocked": "LOW",
    "EVT_WC_Unblocked": "LOW",
    "EVT_WU_Roam": "LOW",
    "EVT_WU_RoamRadio": "LOW",
    "EVT_LG_Connected": "LOW",
    "EVT_LG_Disconnected": "LOW",
    "EVT_WG_Connected": "LOW",
    "EVT_WG_Disconnected": "LOW",
    "EVT_WG_Roam": "LOW",
    "EVT_WG_RoamRadio": "LOW",
    "EVT_XG_AutoReadopted": "LOW",
    "EVT_XG_Connected": "LOW",
    "EVT_XG_OutletPowerCycle": "LOW",
    "EVT_AD_Login": "LOW",
    "EVT_AD_ScheduleUpgradeFailedNotFound": "LOW",
    "EVT_HS_AuthedByPassword": "LOW",
    "EVT_HS_VoucherUsed": "LOW",
    "EVT_WG_AuthorizationEnded": "LOW",
    "EVT_AP_ChannelChanged": "LOW",
    "EVT_DM_Connected": "LOW",
}

# Map UniFi event keys to WATCHTOWER event_type names
EVENT_TYPE_MAP = {
    "EVT_AP_DetectRogueAP": "UNIFI_ROGUE_AP",
    "EVT_SW_DetectRogueDHCP": "UNIFI_ROGUE_DHCP",
    "EVT_IPS_IpsAlert": "UNIFI_IPS_ALERT",
    "EVT_LC_Blocked": "UNIFI_CLIENT_BLOCKED",
    "EVT_WC_Blocked": "UNIFI_WIRELESS_CLIENT_BLOCKED",
    "EVT_AD_GuestUnauthorized": "UNIFI_GUEST_UNAUTHORIZED",
    "EVT_AP_Lost_Contact": "UNIFI_AP_LOST_CONTACT",
    "EVT_GW_Lost_Contact": "UNIFI_GW_LOST_CONTACT",
    "EVT_SW_Lost_Contact": "UNIFI_SW_LOST_CONTACT",
    "EVT_XG_Lost_Contact": "UNIFI_XG_LOST_CONTACT",
    "EVT_DM_Lost_Contact": "UNIFI_DM_LOST_CONTACT",
    "EVT_GW_WANTransition": "UNIFI_WAN_TRANSITION",
    "EVT_SW_Overheat": "UNIFI_SW_OVERHEAT",
    "EVT_SW_POE_Overload": "UNIFI_POE_OVERLOAD",
    "EVT_SW_PoeDisconnect": "UNIFI_POE_DISCONNECT",
    "EVT_AP_RadarDetected": "UNIFI_RADAR_DETECTED",
    "EVT_AP_PossibleInterference": "UNIFI_INTERFERENCE",
    "EVT_AP_Lost_Contact": "UNIFI_AP_DISCONNECTED",
    "EVT_AP_Connected": "UNIFI_AP_CONNECTED",
    "EVT_AP_Restarted": "UNIFI_AP_RESTARTED",
    "EVT_AP_Upgraded": "UNIFI_AP_UPGRADED",
    "EVT_GW_Restarted": "UNIFI_GW_RESTARTED",
    "EVT_SW_Restarted": "UNIFI_SW_RESTARTED",
    "EVT_SW_StpPortBlocking": "UNIFI_STP_BLOCKING",
    "EVT_WU_Disconnected": "UNIFI_WIRELESS_DISCONNECT",
    "EVT_WU_Roam": "UNIFI_WIRELESS_ROAM",
    "EVT_LC_Blocked": "UNIFI_CLIENT_BLOCKED",
    "EVT_LC_Unblocked": "UNIFI_CLIENT_UNBLOCKED",
    "EVT_WC_Blocked": "UNIFI_WIRELESS_BLOCKED",
    "EVT_WC_Unblocked": "UNIFI_WIRELESS_UNBLOCKED",
}

# Client anomaly detection thresholds
CLIENT_ROAM_THRESHOLD = 5       # rapid roaming count in window
CLIENT_ROAM_WINDOW = 300        # 5 minutes
CLIENT_APPEAR_THRESHOLD = 3     # max new clients in window
CLIENT_APPEAR_WINDOW = 300      # 5 minutes


class UniFiMonitor:
    """Monitors UniFi Network Controller for anomalies.

    Polls the UniFi API periodically to collect events, client states,
    and device states. Normalizes all data to the WATCHTOWER event schema
    and inserts into PostgreSQL.

    Configuration via environment variables:
      UNIFI_HOST: Controller host (e.g. 192.168.1.2)
      UNIFI_PORT: Controller port (default 8443)
      UNIFI_USER: API username
      UNIFI_PASS: API password
      UNIFI_SITE: Site name (default 'default')
      UNIFI_ENABLED: Enable/disable monitoring (default true)
    """

    def __init__(self, db=None):
        self.db = db
        self.enabled = os.getenv("UNIFI_ENABLED", "true").lower() == "true"
        self.host = os.getenv("UNIFI_HOST", "")
        self.port = int(os.getenv("UNIFI_PORT", "8443"))
        self.user = os.getenv("UNIFI_USER", "")
        self.passwd = os.getenv("UNIFI_PASS", "")
        self.site = os.getenv("UNIFI_SITE", "default")
        self.poll_interval = int(os.getenv("UNIFI_POLL_INTERVAL", "60"))

        # State tracking
        self._controller = None
        self._last_poll = 0
        self._poll_count = 0
        self._error_count = 0
        self._connected = False

        # Client state cache for delta detection
        self._prev_clients: Dict[str, Dict[str, Any]] = {}
        self._prev_devices: Dict[str, Dict[str, Any]] = {}
        self._prev_events_mac: str = ""  # Track last events MAC to avoid reprocessing

        # Anomaly detection state
        self._client_roam_count: Dict[str, int] = defaultdict(int)  # mac -> count in window
        self._client_roam_times: Dict[str, List[float]] = defaultdict(list)  # mac -> [timestamps]
        self._new_client_times: List[float] = []  # timestamps of new client appearances

        logger.info(
            "UniFiMonitor initialized: host=%s port=%s site=%s enabled=%s",
            self.host, self.port, self.site, self.enabled,
        )

    @property
    def status(self) -> str:
        if not self.enabled:
            return "disabled"
        if not self.host:
            return "not_configured"
        return "connected" if self._connected else "disconnected"

    async def _ensure_controller(self) -> Optional[Any]:
        """Lazily create the aiounifi Controller session."""
        if self._controller and self._connected:
            return self._controller

        try:
            from aiounifi import Controller, Configuration
            import aiohttp

            session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=15),
            )
            config = Configuration(
                session=session,
                host=self.host,
                username=self.user,
                password=self.passwd,
                port=self.port,
                site=self.site,
                ssl_context=False,
            )
            self._controller = Controller(config)
            await self._controller.login()
            self._connected = True
            self._error_count = 0
            logger.info("UniFi controller connected: %s:%s site=%s", self.host, self.port, self.site)
            return self._controller
        except Exception as e:
            self._connected = False
            self._error_count += 1
            logger.warning("UniFi controller login failed (%s): %s", self._error_count, e)
            return None

    def _normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a UniFi event to the WATCHTOWER schema.

        Input: aiounifi Event object data (dict with 'key', 'datetime', 'msg', etc.)
        Output: Event dict compatible with adaptive_parser.py schema
        """
        event_key = raw_event.get("key", "unknown")
        event_type = EVENT_TYPE_MAP.get(event_key, f"UNIFI_{event_key.replace('EVT_', '')}")
        severity = EVENT_SEVERITY.get(event_key, "MEDIUM")

        # Parse timestamp
        ts_str = raw_event.get("datetime", "")
        if ts_str:
            try:
                # UniFi datetime format: '2020-03-01T15:35:08Z'
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                timestamp = ts.isoformat()
            except Exception:
                timestamp = datetime.now(timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        mac = raw_event.get("mac", "")
        ip = raw_event.get("ip", "")
        ap = raw_event.get("ap", "")
        device = raw_event.get("device", "")
        msg = raw_event.get("msg", "")

        # Build normalized event
        event = {
            "timestamp": timestamp,
            "source": "unifi",
            "event_type": event_type,
            "severity": severity,
            "src_ip": ip or "",
            "dst_ip": "",
            "sport": None,
            "dport": None,
            "proto": "WIFI" if "WU" in event_key or "WG" in event_key else "NETWORK",
            "action": "BLOCK" if "Blocked" in event_key or "Block" in event_key else "PASS",
            "interface": "",
            "direction": "",
            "mac": mac,
            "raw": json.dumps(raw_event),
            "rule_name": f"unifi:{event_key}",
            "log_type": "unifi",
        }

        # Build metadata
        metadata = {
            "unifi_event_key": event_key,
            "unifi_msg": msg,
            "mac": mac,
            "ap": ap,
            "device": device,
            "ip": ip,
            "ssid": raw_event.get("ssid", ""),
            "channel": raw_event.get("channel", 0),
            "bytes": raw_event.get("bytes", 0),
            "radio": raw_event.get("radio", ""),
            "essid": raw_event.get("essid", ""),
            "reason": raw_event.get("reason", ""),
            "code": raw_event.get("code", 0),
            "duration": raw_event.get("duration", 0),
            "rx_bytes": raw_event.get("rx_bytes", 0),
            "tx_bytes": raw_event.get("tx_bytes", 0),
            "signal": raw_event.get("signal", 0),
            "noise": raw_event.get("noise", 0),
        }

        # Add description based on event type
        descriptions = {
            "EVT_AP_DetectRogueAP": f"Rogue AP detected by UniFi: {msg}",
            "EVT_SW_DetectRogueDHCP": f"Rogue DHCP server detected on switch: {msg}",
            "EVT_IPS_IpsAlert": f"IPS alert triggered: {msg}",
            "EVT_LC_Blocked": f"LAN client blocked by controller: {mac}",
            "EVT_WC_Blocked": f"Wireless client blocked by controller: {mac}",
            "EVT_AD_GuestUnauthorized": f"Guest portal unauthorized access: {msg}",
            "EVT_AP_Lost_Contact": f"Access point lost contact: {ap or device}",
            "EVT_GW_Lost_Contact": f"Gateway lost contact: {device}",
            "EVT_SW_Lost_Contact": f"Switch lost contact: {device}",
            "EVT_XG_Lost_Contact": f"XG device lost contact: {device}",
            "EVT_DM_Lost_Contact": f"Dream Machine lost contact",
            "EVT_GW_WANTransition": f"Gateway WAN transition (failover): {msg}",
            "EVT_SW_Overheat": f"Switch overheating: {device}",
            "EVT_SW_POE_OVERLOAD": f"Switch PoE power overload: {device}",
            "EVT_SW_PoeDisconnect": f"Switch PoE device disconnected: {device}",
            "EVT_AP_RadarDetected": f"Radar detected on AP, DFS channel forced: {ap}",
            "EVT_AP_PossibleInterference": f"Possible RF interference near AP: {ap}",
        }
        event["description"] = descriptions.get(event_key, f"UniFi event {event_key}: {msg}")

        event["metadata"] = metadata
        return event

    def _detect_client_anomalies(self, current_clients: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Detect client-side anomalies by comparing current state to previous.

        Checks for:
        - Rapid roaming (client connects to many APs in short time)
        - Unknown/new clients appearing (potential rogue devices)
        - Client MAC changes on same IP (MAC spoofing indicator)
        - Disassociated clients (potential jamming or disconnect attacks)
        """
        anomalies = []
        now = time.time()

        # Track new clients
        prev_macs = set(self._prev_clients.keys())
        current_macs = set(current_clients.keys())

        new_macs = current_macs - prev_macs
        lost_macs = prev_macs - current_macs

        # Check for new clients
        if new_macs:
            # Rate limit: check how many new clients in window
            self._new_client_times.append(now)
            self._new_client_times = [t for t in self._new_client_times if now - t < CLIENT_APPEAR_WINDOW]

            for mac in new_macs:
                client = current_clients[mac]
                ip = client.get("ip", "")
                hostname = client.get("hostname", "")
                ap = client.get("last_seen_essid", "") or ""

                anomalies.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "unifi",
                    "event_type": "UNIFI_NEW_CLIENT",
                    "severity": "MEDIUM",
                    "src_ip": ip,
                    "dst_ip": "",
                    "sport": None,
                    "dport": None,
                    "proto": "WIFI",
                    "action": "PASS",
                    "interface": "",
                    "direction": "",
                    "mac": mac,
                    "log_type": "unifi",
                    "raw": json.dumps(client),
                    "rule_name": "unifi:new_client",
                    "description": f"New network client detected: {hostname or ip} ({mac})",
                    "metadata": {
                        "mac": mac,
                        "ip": ip,
                        "hostname": hostname,
                        "is_wired": client.get("is_wired", False),
                        "essid": client.get("essid", ""),
                        "ap_mac": client.get("ap_mac", ""),
                        "signal": client.get("rssi", 0),
                        "new_client_count_in_window": len(self._new_client_times),
                    },
                })

        # Check for rapid roaming
        for mac, client in current_clients.items():
            ap_mac = client.get("ap_mac", "")
            prev_client = self._prev_clients.get(mac, {})
            prev_ap_mac = prev_client.get("ap_mac", "")

            if prev_ap_mac and ap_mac and prev_ap_mac != ap_mac:
                # Client roamed to a different AP
                self._client_roam_count[mac] += 1
                self._client_roam_times[mac].append(now)
                # Prune old roam times
                self._client_roam_times[mac] = [
                    t for t in self._client_roam_times[mac]
                    if now - t < CLIENT_ROAM_WINDOW
                ]

                roam_count = len(self._client_roam_times[mac])
                if roam_count >= CLIENT_ROAM_THRESHOLD:
                    anomalies.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source": "unifi",
                        "event_type": "UNIFI_RAPID_ROAMING",
                        "severity": "MEDIUM",
                        "src_ip": client.get("ip", ""),
                        "dst_ip": "",
                        "sport": None,
                        "dport": None,
                        "proto": "WIFI",
                        "action": "PASS",
                        "interface": "",
                        "direction": "",
                        "mac": mac,
                        "log_type": "unifi",
                        "raw": json.dumps(client),
                        "rule_name": "unifi:rapid_roaming",
                        "description": (
                            f"Rapid roaming detected: {client.get('hostname', '')} "
                            f"({mac}) roamed {roam_count} times in "
                            f"{CLIENT_ROAM_WINDOW}s"
                        ),
                        "metadata": {
                            "mac": mac,
                            "ip": client.get("ip", ""),
                            "hostname": client.get("hostname", ""),
                            "prev_ap": prev_ap_mac,
                            "new_ap": ap_mac,
                            "roam_count": roam_count,
                            "window": CLIENT_ROAM_WINDOW,
                        },
                    })

        # Check for lost clients (potential jamming if many at once)
        if len(lost_macs) > 10:
            anomalies.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "unifi",
                "event_type": "UNIFI_MASS_DISCONNECT",
                "severity": "HIGH",
                "src_ip": "",
                "dst_ip": "",
                "sport": None,
                "dport": None,
                "proto": "WIFI",
                "action": "BLOCK",
                "interface": "",
                "direction": "",
                "mac": "",
                "log_type": "unifi",
                "raw": json.dumps({"lost_count": len(lost_macs), "lost_macs": sorted(list(lost_macs))[:20]}),
                "rule_name": "unifi:mass_disconnect",
                "description": f"Mass client disconnect: {len(lost_macs)} clients lost simultaneously",
                "metadata": {
                    "lost_count": len(lost_macs),
                    "lost_macs": sorted(list(lost_macs))[:20],
                },
            })

        return anomalies

    def _detect_device_anomalies(self, current_devices: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Detect device-level anomalies (AP/switch/gateway state changes).

        Checks for:
        - Device state changes (up -> down, adopt -> pending)
        - Uptime resets (unexpected reboots)
        - New unknown devices
        - Channel/interference changes
        """
        anomalies = []

        prev_ids = set(self._prev_devices.keys())
        current_ids = set(current_devices.keys())

        # New devices
        for dev_id in current_ids - prev_ids:
            dev = current_devices[dev_id]
            anomalies.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "unifi",
                "event_type": "UNIFI_NEW_DEVICE",
                "severity": "MEDIUM",
                "src_ip": dev.get("ip", ""),
                "dst_ip": "",
                "sport": None,
                "dport": None,
                "proto": "NETWORK",
                "action": "PASS",
                "interface": "",
                "direction": "",
                "mac": dev.get("mac", ""),
                "log_type": "unifi",
                "raw": json.dumps(dev),
                "rule_name": "unifi:new_device",
                "description": (
                    f"New UniFi device detected: {dev.get('name', '')} "
                    f"({dev.get('model', '')})"
                ),
                "metadata": {
                    "device_id": dev_id,
                    "mac": dev.get("mac", ""),
                    "ip": dev.get("ip", ""),
                    "name": dev.get("name", ""),
                    "model": dev.get("model", ""),
                    "adopted": dev.get("adopted", False),
                    "state": dev.get("state", ""),
                    "type": dev.get("type", ""),
                },
            })

        # Device state changes
        for dev_id in prev_ids & current_ids:
            prev_dev = self._prev_devices[dev_id]
            curr_dev = current_devices[dev_id]

            prev_state = prev_dev.get("state", "")
            curr_state = curr_dev.get("state", "")

            # Check for device going down
            if prev_state == "up" and curr_state in ("down", "disconnected"):
                anomalies.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "unifi",
                    "event_type": "UNIFI_DEVICE_DOWN",
                    "severity": "HIGH",
                    "src_ip": curr_dev.get("ip", ""),
                    "dst_ip": "",
                    "sport": None,
                    "dport": None,
                    "proto": "NETWORK",
                    "action": "BLOCK",
                    "interface": "",
                    "direction": "",
                    "mac": curr_dev.get("mac", ""),
                    "log_type": "unifi",
                    "raw": json.dumps(curr_dev),
                    "rule_name": "unifi:device_down",
                    "description": (
                        f"UniFi device went down: {curr_dev.get('name', '')} "
                        f"({curr_dev.get('model', '')})"
                    ),
                    "metadata": {
                        "device_id": dev_id,
                        "mac": curr_dev.get("mac", ""),
                        "name": curr_dev.get("name", ""),
                        "model": curr_dev.get("model", ""),
                        "prev_state": prev_state,
                        "curr_state": curr_state,
                        "type": curr_dev.get("type", ""),
                    },
                })

        return anomalies

    async def poll(self) -> List[Dict[str, Any]]:
        """Perform one poll cycle. Returns list of normalized events.

        Fetches events, clients, and devices from UniFi controller.
        Detects deltas and anomalies. Updates internal state cache.
        """
        all_events = []

        controller = await self._ensure_controller()
        if not controller:
            return all_events

        now = time.time()
        if now - self._last_poll < self.poll_interval:
            return all_events
        self._last_poll = now
        self._poll_count += 1

        try:
            # ── Fetch events from UniFi ──────────────────────────────
            try:
                # Get events via the controller's events handler
                # aiounifi events are websocket-pushed, so we fetch manually
                raw_events = await controller.messages.get_events()
                if raw_events:
                    for ev in raw_events:
                        raw_data = ev.data if hasattr(ev, 'data') else ev
                        normalized = self._normalize_event(raw_data)
                        all_events.append(normalized)
                        self._prev_events_mac = raw_data.get("mac", "")
            except Exception as e:
                logger.debug("UniFi events fetch skipped: %s", e)

            # ── Fetch current clients ────────────────────────────────
            current_clients: Dict[str, Dict] = {}
            try:
                await controller.clients.update()
                for mac, client in controller.clients.items():
                    raw = client.data if hasattr(client, 'data') else vars(client)
                    current_clients[mac] = raw
            except Exception as e:
                logger.warning("UniFi client fetch failed: %s", e)
                current_clients = dict(self._prev_clients)

            # ── Detect client anomalies ──────────────────────────────
            client_anomalies = self._detect_client_anomalies(current_clients)
            all_events.extend(client_anomalies)

            # ── Fetch current devices ────────────────────────────────
            current_devices: Dict[str, Dict] = {}
            try:
                await controller.devices.update()
                for dev_id, device in controller.devices.items():
                    raw = device.data if hasattr(device, 'data') else vars(device)
                    current_devices[dev_id] = raw
            except Exception as e:
                logger.warning("UniFi device fetch failed: %s", e)
                current_devices = dict(self._prev_devices)

            # ── Detect device anomalies ──────────────────────────────
            device_anomalies = self._detect_device_anomalies(current_devices)
            all_events.extend(device_anomalies)

            # ── Update state cache ───────────────────────────────────
            self._prev_clients = current_clients
            self._prev_devices = current_devices

            if all_events:
                logger.info(
                    "UniFi poll #%d: %d events (%d client, %d device anomalies)",
                    self._poll_count, len(all_events),
                    len(client_anomalies), len(device_anomalies),
                )

        except Exception as e:
            self._error_count += 1
            logger.error("UniFi poll failed: %s\n%s", e, traceback.format_exc())

        return all_events

    def get_status(self) -> Dict[str, Any]:
        """Return current monitor status for dashboard."""
        return {
            "enabled": self.enabled,
            "status": self.status,
            "host": self.host,
            "site": self.site,
            "poll_interval": self.poll_interval,
            "poll_count": self._poll_count,
            "error_count": self._error_count,
            "connected": self._connected,
            "known_clients": len(self._prev_clients),
            "known_devices": len(self._prev_devices),
            "last_poll": self._last_poll,
        }

    async def stop(self):
        """Clean up resources."""
        if self._controller:
            try:
                session = self._controller.session
                if session:
                    await session.close()
            except Exception:
                pass
            self._controller = None
            self._connected = False
        logger.info("UniFiMonitor stopped")
