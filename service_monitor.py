#!/usr/bin/env python3
"""
Service Monitor — OPNsense Service Lifecycle + Anomaly Detection

Monitors and learns normal behavior for:
  - DHCP: lease lifecycle, decline/renew patterns (API not available, syslog not in pipeline)
  - Unbound: DNS query types, response codes, config analysis (via OPNsense API)
  - NTP: sync accuracy, offset patterns (API not available, syslog not in pipeline)
  - OpenVPN: tunnel up/down, auth success/failure (API not available, syslog not in pipeline)
  - WireGuard: peer handshake frequency, keepalive patterns (via OPNsense API)

Uses OPNsense API where available (Unbound, WireGuard).
DHCP, NTP, OpenVPN are marked as "not monitored" since their syslog is
not in the firewall event pipeline and they have no REST API endpoints.
"""

import os
import json
import time
import logging
import base64
import requests
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import Counter
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# ── Thresholds ──────────────────────────────────────────────────────────
MIN_SAMPLES = 15
SPIKE_ZSCORE = 2.5
MAX_DHCP_LEASES = 254
MAX_WG_PEERS = 50
MAX_OVPN_CLIENTS = 100

# NTP drift thresholds (seconds)
NTP_NORMAL_DRIFT = 0.050  # 50ms
NTP_WARNING_DRIFT = 0.500  # 500ms
NTP_CRITICAL_DRIFT = 1.000  # 1 second

# API cache TTL
API_CACHE_TTL = 60  # seconds


@dataclass
class ServiceProfile:
    """Profile of a service's normal behavior."""
    service: str
    total_events: int = 0
    hourly_counts: Counter = field(default_factory=Counter)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    anomaly_log: List[dict] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)
    monitored: bool = False  # True if actively monitored via API/syslog

    @property
    def is_new(self) -> bool:
        return self.total_events < MIN_SAMPLES


class OPNsenseAPIClient:
    """Client for OPNsense API with authentication."""

    def __init__(self, host: str, port: int, api_key: str, api_secret: str):
        self.base_url = f"https://{host}:{port}"
        self.headers = {
            "Authorization": f"Basic {base64.b64encode(f'{api_key}:{api_secret}'.encode()).decode()}",
            "Accept": "application/json",
        }

    def get(self, endpoint: str) -> Optional[dict]:
        try:
            resp = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug("API GET %s failed: %s", endpoint, e)
        return None


class ServiceMonitor:
    """Main monitor — polls OPNsense API for service data and detects anomalies."""

    def __init__(self, config):
        self.config = config or {}
        self.opn_client = None
        self._init_opn_client()
        self.profiles: Dict[str, ServiceProfile] = {}
        self.api_cache = {}
        self.last_cache_clear = time.time()
        self._poll_count = 0

        # Initialize known service profiles
        # Only Unbound and WireGuard are actually monitored (have API endpoints)
        self.profiles["dhcp"] = ServiceProfile(service="dhcp", monitored=False)
        self.profiles["unbound"] = ServiceProfile(service="unbound", monitored=True)
        self.profiles["ntp"] = ServiceProfile(service="ntp", monitored=False)
        self.profiles["openvpn"] = ServiceProfile(service="openvpn", monitored=False)
        self.profiles["wireguard"] = ServiceProfile(service="wireguard", monitored=True)

        logger.info("ServiceMonitor: initialized with %d services (%d monitored)",
                   len(self.profiles), sum(1 for p in self.profiles.values() if p.monitored))

    def _init_opn_client(self):
        """Initialize OPNsense API client from env vars."""
        host = os.getenv("OPN_HOST", "192.168.1.1")
        port = os.getenv("OPN_PORT", "6666")
        api_key = os.getenv("OPN_API_KEY", "")
        api_secret = os.getenv("OPN_API_SECRET", "")

        if api_key and api_secret:
            self.opn_client = OPNsenseAPIClient(host, int(port), api_key, api_secret)
            logger.info("ServiceMonitor: OPNsense API client initialized for %s:%s", host, port)
        else:
            logger.warning("ServiceMonitor: OPNsense API credentials not set — API polling disabled")

    # ── Unbound ──────────────────────────────────────────────────────
    def _fetch_unbound_settings(self) -> dict:
        """Fetch Unbound settings from API (cached)."""
        if not self.opn_client:
            return {}

        now = time.time()
        if now - self.last_cache_clear > API_CACHE_TTL:
            self.api_cache = {}
            self.last_cache_clear = now

        if "unbound_settings" in self.api_cache:
            return self.api_cache["unbound_settings"]

        data = self.opn_client.get("/api/unbound/settings/get")
        if data and "unbound" in data:
            unbound = data["unbound"]
            general = unbound.get("general", {})
            advanced = unbound.get("advanced", {})

            result = {
                "enabled": general.get("enabled") == "1",
                "port": general.get("port", "53"),
                "dnssec_enabled": advanced.get("dnssec") == "1",
                "verbose": advanced.get("verbose") == "1",
                "num_threads": int(general.get("num_threads", "1")),
            }

            # Count ACLs
            acls = unbound.get("acls", {})
            acl_count = len(acls) if isinstance(acls, dict) else 0
            result["acl_count"] = acl_count

            # Count forward zones
            fz = unbound.get("forward_zones", {})
            fz_count = len(fz) if isinstance(fz, dict) else 0
            result["forward_zone_count"] = fz_count

            self.api_cache["unbound_settings"] = result
            logger.debug("ServiceMonitor: Fetched Unbound settings — port=%s, DNSSEC=%s, ACLs=%s, zones=%s",
                        result["port"], result["dnssec_enabled"], acl_count, fz_count)
            return result

        return {}

    def _check_unbound_anomalies(self, settings: dict) -> list:
        """Check Unbound config for security anomalies."""
        anomalies = []
        profile = self.profiles["unbound"]

        # DNSSEC disabled
        if settings.get("enabled") and not settings.get("dnssec_enabled"):
            if not any(a["type"] == "unbound_dnssec_disabled" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "unbound_dnssec_disabled",
                    "severity": "warning",
                    "description": "Unbound DNSSEC validation is disabled — DNS responses are not verified",
                    "service": "unbound",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        # No ACLs configured (permissive mode)
        if settings.get("acl_count", 0) == 0:
            logger.debug("ServiceMonitor: Unbound has no ACLs configured (permissive)")

        return anomalies

    # ── WireGuard ────────────────────────────────────────────────────
    def _fetch_wireguard_peers(self) -> dict:
        """Fetch WireGuard peer data from API (cached)."""
        if not self.opn_client:
            return {}

        now = time.time()
        if now - self.last_cache_clear > API_CACHE_TTL:
            self.api_cache = {}
            self.last_cache_clear = now

        if "wireguard_peers" in self.api_cache:
            return self.api_cache["wireguard_peers"]

        # Fetch server configs
        server_data = self.opn_client.get("/api/wireguard/server/get")
        client_data = self.opn_client.get("/api/wireguard/client/get")

        result = {
            "servers": [],
            "clients": [],
            "total_peers": 0,
        }

        if server_data and "server" in server_data:
            servers = server_data["server"].get("servers", {})
            for srv_uuid, srv in servers.items():
                result["servers"].append({
                    "uuid": srv_uuid,
                    "name": srv.get("name", ""),
                    "enabled": srv.get("enabled") == "1",
                    "address": srv.get("address", ""),
                    "listen_port": int(srv.get("listen_port", "0")),
                    "mtu": int(srv.get("mtu", "1420")),
                    "private_key_masked": srv.get("private_key", "")[:8] + "..." if srv.get("private_key") else "",
                })

        if client_data and "client" in client_data:
            clients = client_data["client"].get("clients", {})
            for client_uuid, client in clients.items():
                public_key = client.get("public_key", "")
                result["clients"].append({
                    "uuid": client_uuid,
                    "name": client.get("name", ""),
                    "enabled": client.get("enabled") == "1",
                    "public_key_masked": public_key[:16] + "..." if len(public_key) > 16 else public_key,
                    "allowed_ips": client.get("allowed_ips", ""),
                    "persistent_keepalive": int(client.get("persistent_keepalive", "0")),
                })

        result["total_peers"] = len(result["servers"]) + len(result["clients"])
        self.api_cache["wireguard_peers"] = result
        logger.debug("ServiceMonitor: Fetched WireGuard — %s servers, %s clients, %s total peers",
                    len(result["servers"]), len(result["clients"]), result["total_peers"])
        return result

    def _check_wireguard_anomalies(self, data: dict) -> list:
        """Check WireGuard config for security anomalies."""
        anomalies = []
        profile = self.profiles["wireguard"]

        # Too many clients configured
        if len(data.get("clients", [])) > MAX_WG_PEERS:
            if not any(a["type"] == "wg_too_many_peers" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "wg_too_many_peers",
                    "severity": "warning",
                    "description": f"WireGuard has {len(data['clients'])} clients configured (max recommended: {MAX_WG_PEERS})",
                    "service": "wireguard",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return anomalies

    # ── Poll API ─────────────────────────────────────────────────────
    def poll_api(self):
        """Poll OPNsense API for service data. Called periodically from agent."""
        self._poll_count += 1

        if not self.opn_client:
            return

        # Unbound
        unbound_settings = self._fetch_unbound_settings()
        if unbound_settings:
            profile = self.profiles["unbound"]
            profile.last_seen = datetime.now(timezone.utc)
            profile.total_events += 1
            profile.metrics["unbound_settings"] = unbound_settings
            profile.metrics["poll_count"] = self._poll_count

        # WireGuard
        wg_peers = self._fetch_wireguard_peers()
        if wg_peers:
            profile = self.profiles["wireguard"]
            profile.last_seen = datetime.now(timezone.utc)
            profile.total_events += 1
            profile.metrics["wg_peers"] = wg_peers
            profile.metrics["poll_count"] = self._poll_count

    # ── Summary ──────────────────────────────────────────────────────
    def get_status(self) -> dict:
        """Get status of all services."""
        status = {}
        for svc, profile in self.profiles.items():
            status[svc] = {
                "total_events": profile.total_events,
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "anomaly_count": len(profile.anomaly_log),
                "monitored": profile.monitored,
                "metrics": profile.metrics,
            }
        return status

    def get_all_anomalies(self) -> list:
        """Get all detected anomalies from all services."""
        all_anomalies = []
        for svc, profile in self.profiles.items():
            all_anomalies.extend(profile.anomaly_log)
        # Return most recent 50, sorted by timestamp
        all_anomalies.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return all_anomalies[:50]

    def process_event(self, event: dict):
        """Route a single event to the correct service handler.

        Note: Firewall filterlog events don't contain service-level syslog messages
        (DHCP/NTP/OpenVPN), so this is primarily a pass-through. Service monitoring
        is done via API polling in poll_api().
        """
        # No-op — service monitoring is API-driven, not syslog-driven
        pass

    def process_events(self, events: list):
        """Route a batch of events to the correct service handler.

        No-op since individual process_event is already a no-op.
        """
        pass

    def check_all(self) -> list:
        """Run all anomaly checks. Calls poll_api() first to refresh data."""
        # Refresh API data before checking
        self.poll_api()

        anomalies = []

        # Unbound anomalies (from API data)
        unbound_settings = self.profiles["unbound"].metrics.get("unbound_settings", {})
        if unbound_settings:
            anomalies.extend(self._check_unbound_anomalies(unbound_settings))

        # WireGuard anomalies (from API data)
        wg_peers = self.profiles["wireguard"].metrics.get("wg_peers", {})
        if wg_peers:
            anomalies.extend(self._check_wireguard_anomalies(wg_peers))

        return anomalies

    def save(self):
        """Save state to file."""
        state = {
            "services": {},
        }
        for svc, profile in self.profiles.items():
            state["services"][svc] = {
                "total_events": profile.total_events,
                "hourly_counts": dict(profile.hourly_counts),
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "monitored": profile.monitored,
                "metrics": {},
                "anomaly_log": profile.anomaly_log[-50:],
            }
            # Serialize metrics
            if profile.metrics:
                metrics_copy = {}
                for k, v in profile.metrics.items():
                    if isinstance(v, (set, Counter)):
                        metrics_copy[k] = list(v)[:20] if isinstance(v, set) else dict(v.most_common(20))
                    elif isinstance(v, dict) and "private_key" in str(v):
                        # Mask sensitive data
                        metrics_copy[k] = {sk: sv[:8] + "..." if isinstance(sv, str) and len(sv) > 8 else sv
                                          for sk, sv in v.items()}
                    else:
                        metrics_copy[k] = v
                state["services"][svc]["metrics"] = metrics_copy
            # Remove anomaly_log if empty to save space
            if not profile.anomaly_log:
                del state["services"][svc]["anomaly_log"]

        state_path = os.path.join(os.path.dirname(__file__), "agent_data", "service_monitor.json")
        with open(state_path, "w") as f:
            json.dump(state, f, indent=2, default=str)
        logger.info("ServiceMonitor: Saved state with %d services", len(self.profiles))

    def load(self):
        """Load state from file."""
        state_path = os.path.join(os.path.dirname(__file__), "agent_data", "service_monitor.json")
        if not os.path.exists(state_path):
            logger.info("ServiceMonitor: No saved state found")
            return

        try:
            with open(state_path) as f:
                state = json.load(f)

            for svc_name, svc_data in state.get("services", {}).items():
                if svc_name in self.profiles:
                    profile = self.profiles[svc_name]
                    profile.total_events = svc_data.get("total_events", 0)
                    profile.hourly_counts = Counter({int(k): v for k, v in svc_data.get("hourly_counts", {}).items()})
                    if svc_data.get("first_seen"):
                        profile.first_seen = datetime.fromisoformat(svc_data["first_seen"])
                    if svc_data.get("last_seen"):
                        profile.last_seen = datetime.fromisoformat(svc_data["last_seen"])
                    profile.monitored = svc_data.get("monitored", False)
                    if "metrics" in svc_data:
                        profile.metrics = svc_data["metrics"]
                    if "anomaly_log" in svc_data:
                        profile.anomaly_log = svc_data["anomaly_log"]

            logger.info("ServiceMonitor: Loaded state with %d services", len(self.profiles))
        except Exception as e:
            logger.warning("ServiceMonitor: Failed to load state: %s", e)
