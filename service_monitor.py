#!/usr/bin/env python3
"""
Service Monitor — OPNsense Service Lifecycle + Anomaly Detection

Monitors and learns normal behavior for:
  - DHCP: lease lifecycle, decline/renew patterns, IP distribution
  - Unbound: DNS query types, response codes, resolution latency
  - NTP: sync accuracy, offset patterns, server rotation
  - OpenVPN: tunnel up/down, auth success/failure, client count
  - WireGuard: peer handshake frequency, keepalive patterns, data volume

Uses OPNsense API where available (Unbound, WireGuard) and syslog
parsing for services without API (DHCP, NTP, OpenVPN).
"""

import os
import json
import time
import logging
import base64
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter, deque
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

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
    """Main monitor — learns normal behavior and detects anomalies."""

    def __init__(self, config):
        self.config = config or {}
        self.opn_client = None
        self._init_opn_client()
        self.profiles: Dict[str, ServiceProfile] = {}
        self.api_cache = {}
        self.cache_ttl = 60  # cache API responses for 60s
        self.last_cache_clear = time.time()

        # Initialize known service profiles
        for svc in ["dhcp", "unbound", "ntp", "openvpn", "wireguard"]:
            self.profiles[svc] = ServiceProfile(service=svc)

    def _init_opn_client(self):
        """Initialize OPNsense API client from env vars."""
        host = os.getenv("OPN_HOST", "192.168.1.1")
        port = os.getenv("OPN_PORT", "6666")
        api_key = os.getenv("OPN_API_KEY", "")
        api_secret = os.getenv("OPN_API_SECRET", "")

        if api_key and api_secret:
            self.opn_client = OPNsenseAPIClient(host, int(port), api_key, api_secret)
            logger.info("ServiceMonitor: OPNsense API client initialized")

    # ── Unbound ──────────────────────────────────────────────────────
    def _fetch_unbound_settings(self) -> dict:
        """Fetch Unbound settings from API (cached)."""
        if not self.opn_client:
            return {}

        now = time.time()
        if now - self.last_cache_clear > self.cache_ttl:
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
                "enabled": general.get("enable") == "1",
                "listen_addresses": general.get("listen_port", "53"),
                "interface_mode": general.get("interface_modedeny", "all"),
                "dnssec_enabled": advanced.get("dnssec") == "1",
                "verbose": advanced.get("verbose") == "1",
                "quiet_dns": advanced.get("quiet_dns") == "1",
                "rrset_cache": advanced.get("rrset_cache") == "1",
                "msg_cache": advanced.get("msg_cache") == "1",
                "num_threads": int(general.get("num_threads", "1")),
                "so_rcvbuf": int(general.get("so_rcvbuf", "0")),
                "so_sndbuf": int(general.get("so_sndbuf", "0")),
            }

            # ACLs
            acls = unbound.get("acls", {})
            acl_list = []
            if isinstance(acls, dict):
                for acl_uuid, acl in acls.items():
                    acl_list.append({
                        "name": acl.get("name", ""),
                        "action": acl.get("action", ""),
                        "ip": acl.get("ip", ""),
                        "domain": acl.get("domain", ""),
                    })
            result["acls"] = acl_list

            # Forward zones
            forward_zones = unbound.get("forward_zones", {})
            forward_list = []
            if isinstance(forward_zones, dict):
                for fz_uuid, fz in forward_zones.items():
                    forward_list.append({
                        "name": fz.get("name", ""),
                        "forward_addr": fz.get("forward_addr", ""),
                        "forward_ssl": fz.get("forward_ssl") == "1",
                        "forward_do_ds": fz.get("forward_do_ds") == "1",
                    })
            result["forward_zones"] = forward_list

            self.api_cache["unbound_settings"] = result
            logger.debug("ServiceMonitor: Fetched Unbound settings — %s ACLs, %s forward zones",
                        len(acl_list), len(forward_list))
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
        if not settings.get("acls"):
            logger.debug("ServiceMonitor: Unbound has no ACLs configured")

        return anomalies

    # ── WireGuard ────────────────────────────────────────────────────
    def _fetch_wireguard_peers(self) -> dict:
        """Fetch WireGuard peer data from API (cached)."""
        if not self.opn_client:
            return {}

        now = time.time()
        if now - self.last_cache_clear > self.cache_ttl:
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
                    "private_key": srv.get("private_key", "")[:8] + "...",  # Masked
                })

        if client_data and "client" in client_data:
            clients = client_data["client"].get("clients", {})
            for client_uuid, client in clients.items():
                public_key = client.get("public_key", "")
                result["clients"].append({
                    "uuid": client_uuid,
                    "name": client.get("name", ""),
                    "enabled": client.get("enabled") == "1",
                    "public_key": public_key[:16] + "..." if len(public_key) > 16 else public_key,
                    "allowed_ips": client.get("allowed_ips", ""),
                    "persistent_keepalive": int(client.get("persistent_keepalive", "0")),
                    "endpoint_allowed_ips": client.get("endpoint_allowed_ips", ""),
                })

        result["total_peers"] = len(result["servers"]) + len(result["clients"])
        self.api_cache["wireguard_peers"] = result
        logger.debug("ServiceMonitor: Fetched WireGuard — %s servers, %s clients",
                    len(result["servers"]), len(result["clients"]))
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

    # ── DHCP (from syslog) ───────────────────────────────────────────
    def process_dhcp_event(self, event: dict):
        """Process DHCP event from syslog."""
        profile = self.profiles["dhcp"]
        now = datetime.now(timezone.utc)
        profile.last_seen = now
        profile.total_events += 1
        profile.hourly_counts[now.hour] += 1

        # Extract DHCP actions from syslog
        raw = event.get("raw", "")
        action = "unknown"
        if "DISCOVER" in raw or "REQUEST" in raw:
            action = "client_request"
        elif "ACK" in raw:
            action = "lease_granted"
        elif "NAK" in raw:
            action = "lease_denied"
        elif "RELEASE" in raw or "DECLINE" in raw:
            action = "client_release"
        elif "DHCACK" in raw:
            action = "lease_granted"
        elif "DHCNACK" in raw:
            action = "lease_denied"
        elif "DHCPOFFER" in raw:
            action = "offer"

        profile.metrics.setdefault("actions", Counter())[action] += 1
        profile.metrics.setdefault("unique_ips", set()).add(event.get("src_ip", "") or event.get("dst_ip", ""))
        profile.metrics.setdefault("unique_macs", set()).add(event.get("mac_address", ""))

        # Track lease count
        if action in ("lease_granted", "offer"):
            profile.metrics.setdefault("leases_24h", 0)
            profile.metrics["leases_24h"] += 1

    def check_dhcp_anomalies(self) -> list:
        """Check DHCP for anomalies."""
        anomalies = []
        profile = self.profiles["dhcp"]

        # High volume of requests
        action_counts = profile.metrics.get("actions", {})
        total_requests = action_counts.get("client_request", 0)
        total_denied = action_counts.get("lease_denied", 0)

        if total_requests > 100 and total_denied / max(total_requests, 1) > 0.1:
            if not any(a["type"] == "dhcp_high_decline_rate" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "dhcp_high_decline_rate",
                    "severity": "warning",
                    "description": f"DHCP decline rate is {total_denied/total_requests*100:.1f}% — clients rejecting leases",
                    "service": "dhcp",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        # Too many leases in 24h
        if profile.metrics.get("leases_24h", 0) > MAX_DHCP_LEASES:
            if not any(a["type"] == "dhcp_lease_exhaustion" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "dhcp_lease_exhaustion",
                    "severity": "critical",
                    "description": f"DHCP lease count ({profile.metrics['leases_24h']}) exceeds pool size ({MAX_DHCP_LEASES}) — possible exhaustion or misconfiguration",
                    "service": "dhcp",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return anomalies

    # ── NTP (from syslog) ────────────────────────────────────────────
    def process_ntp_event(self, event: dict):
        """Process NTP event from syslog."""
        profile = self.profiles["ntp"]
        now = datetime.now(timezone.utc)
        profile.last_seen = now
        profile.total_events += 1
        profile.hourly_counts[now.hour] += 1

        raw = event.get("raw", "").lower()

        # Extract NTP sync metrics from syslog
        offset = None
        action = "unknown"

        if "offset" in raw:
            action = "sync_attempt"
            # Try to extract offset value
            import re
            offset_match = re.search(r'offset\s+([-+]?[\d.]+)', raw)
            if offset_match:
                try:
                    offset = float(offset_match.group(1))
                except ValueError:
                    pass

        elif "synchronized" in raw:
            action = "synchronized"
        elif "step" in raw:
            action = "time_step"

        profile.metrics.setdefault("sync_attempts", 0)
        profile.metrics.setdefault("sync_successes", 0)
        profile.metrics.setdefault("time_steps", 0)
        profile.metrics.setdefault("drift_samples", [])

        profile.metrics["sync_attempts"] += 1

        if offset is not None:
            profile.metrics["drift_samples"].append(offset)
            # Keep last 100 samples
            profile.metrics["drift_samples"] = profile.metrics["drift_samples"][-100:]

            # Calculate stats
            abs_drifts = [abs(d) for d in profile.metrics["drift_samples"]]
            profile.metrics["current_drift"] = max(abs_drifts) if abs_drifts else 0
            profile.metrics["avg_drift"] = sum(abs_drifts) / len(abs_drifts) if abs_drifts else 0

        if action == "synchronized":
            profile.metrics["sync_successes"] += 1
        elif action == "time_step":
            profile.metrics["time_steps"] += 1

    def check_ntp_anomalies(self) -> list:
        """Check NTP for synchronization anomalies."""
        anomalies = []
        profile = self.profiles["ntp"]

        drift_samples = profile.metrics.get("drift_samples", [])
        if not drift_samples:
            return anomalies

        current_drift = profile.metrics.get("current_drift", 0)
        avg_drift = profile.metrics.get("avg_drift", 0)

        # Current drift too high
        if current_drift > NTP_CRITICAL_DRIFT:
            if not any(a["type"] == "ntp_critical_drift" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "ntp_critical_drift",
                    "severity": "critical",
                    "description": f"NTP drift is {current_drift:.3f}s — time sync is severely degraded",
                    "service": "ntp",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        elif current_drift > NTP_WARNING_DRIFT:
            if not any(a["type"] == "ntp_warning_drift" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "ntp_warning_drift",
                    "severity": "warning",
                    "description": f"NTP drift is {current_drift:.3f}s — time sync is degraded",
                    "service": "ntp",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        # Too many time steps (indicating poor sync)
        if profile.metrics.get("time_steps", 0) > 5:
            if not any(a["type"] == "ntp_too_many_steps" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "ntp_too_many_steps",
                    "severity": "warning",
                    "description": f"NTP performed {profile.metrics['time_steps']} time steps — unstable sync",
                    "service": "ntp",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return anomalies

    # ── OpenVPN (from syslog) ────────────────────────────────────────
    def process_openvpn_event(self, event: dict):
        """Process OpenVPN event from syslog."""
        profile = self.profiles["openvpn"]
        now = datetime.now(timezone.utc)
        profile.last_seen = now
        profile.total_events += 1
        profile.hourly_counts[now.hour] += 1

        raw = event.get("raw", "").lower()
        action = "unknown"

        if "tls: tls handshake" in raw:
            action = "handshake"
        elif "Initialization Sequence Completed" in raw:
            action = "tunnel_up"
        elif "SIGTERM" in raw or "Exiting" in raw:
            action = "tunnel_down"
        elif "auth-user-pass" in raw:
            if "verification passed" in raw or "authenticate" in raw:
                action = "auth_success"
            else:
                action = "auth_failure"
        elif "peer connect" in raw:
            action = "client_connect"
        elif "peer disconnect" in raw:
            action = "client_disconnect"

        profile.metrics.setdefault("actions", Counter())[action] += 1
        profile.metrics.setdefault("active_connections", 0)

        if action == "client_connect":
            profile.metrics["active_connections"] += 1
        elif action == "client_disconnect":
            profile.metrics["active_connections"] = max(0, profile.metrics["active_connections"] - 1)

    def check_openvpn_anomalies(self) -> list:
        """Check OpenVPN for anomalies."""
        anomalies = []
        profile = self.profiles["openvpn"]

        # High connection count
        active = profile.metrics.get("active_connections", 0)
        if active > MAX_OVPN_CLIENTS:
            if not any(a["type"] == "ovpn_too_many_connections" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "ovpn_too_many_connections",
                    "severity": "warning",
                    "description": f"OpenVPN has {active} active connections (max recommended: {MAX_OVPN_CLIENTS})",
                    "service": "openvpn",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        # High auth failure rate
        actions = profile.metrics.get("actions", {})
        auth_success = actions.get("auth_success", 0)
        auth_failure = actions.get("auth_failure", 0)
        if auth_success + auth_failure > 10 and auth_failure > auth_success * 2:
            if not any(a["type"] == "ovpn_high_auth_failure" for a in profile.anomaly_log[-20:]):
                anomalies.append({
                    "type": "ovpn_high_auth_failure",
                    "severity": "critical",
                    "description": f"OpenVPN auth failure rate is {auth_failure/(auth_success+auth_failure)*100:.0f}% — possible credential attack",
                    "service": "openvpn",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return anomalies

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
        """Route a single event to the correct service handler."""
        process = (event.get("process", "") or "").lower()
        message = (event.get("message", "") or "").lower()
        raw = (event.get("raw", "") or "").lower()
        log_type = (event.get("log_type", "") or "").lower()
        
        # Combined text for matching
        combined = f"{process} {message} {raw} {log_type}"

        matched = None
        if ("dhcp" in process or "dhcp" in message or "dhcp" in log_type
            or "dhcpleases" in combined):
            matched = "dhcp"
        
        elif ("unbound" in process or "unbound" in message
              or "dnsmasq" in process or "dnsmasq" in message
              or "dns" in process or "dns" in log_type):
            matched = "unbound"
        
        elif ("ntpd" in process or "ntp" in process
              or "ntp" in log_type):
            matched = "ntp"
        
        elif ("openvpn" in process or "openvpn" in message
              or "ovpn" in process):
            matched = "openvpn"

        if matched:
            logger.info("ServiceMonitor matched service=%s process=%s message=%s", 
                       matched, process, message[:80])
            if matched == "dhcp":
                self.process_dhcp_event(event)
            elif matched == "unbound":
                self._process_dns_event(event)
            elif matched == "ntp":
                self.process_ntp_event(event)
            elif matched == "openvpn":
                self.process_openvpn_event(event)

    def learn(self, events: list):
        """Process events and detect anomalies."""
        for event in events:
            log_type = event.get("log_type", "")
            raw = event.get("raw", "")

            # Classify event
            if "dhcp" in raw or "dhcpleases" in log_type:
                self.process_dhcp_event(event)
            elif "unbound" in log_type or "dns" in log_type or "dnsmasq" in log_type:
                self._process_dns_event(event)
            elif "ntpd" in log_type or "ntp" in log_type:
                self.process_ntp_event(event)
            elif "openvpn" in log_type or "vpn" in log_type:
                self.process_openvpn_event(event)

    def _process_dns_event(self, event: dict):
        """Process DNS event from syslog."""
        profile = self.profiles["unbound"]
        now = datetime.now(timezone.utc)
        profile.last_seen = now
        profile.total_events += 1
        profile.hourly_counts[now.hour] += 1

        raw = event.get("raw", "").lower()

        if "query" in raw:
            profile.metrics.setdefault("queries_24h", 0)
            profile.metrics["queries_24h"] += 1

    def check_all(self) -> list:
        """Run all anomaly checks."""
        anomalies = []

        # API-based checks
        if self.opn_client:
            unbound_settings = self._fetch_unbound_settings()
            anomalies.extend(self._check_unbound_anomalies(unbound_settings))

            wg_peers = self._fetch_wireguard_peers()
            anomalies.extend(self._check_wireguard_anomalies(wg_peers))

        # Syslog-based checks
        anomalies.extend(self.check_dhcp_anomalies())
        anomalies.extend(self.check_ntp_anomalies())
        anomalies.extend(self.check_openvpn_anomalies())

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
                "metrics": {},
                "anomaly_log": profile.anomaly_log[-50:],
            }
            # Serialize metrics (remove sets)
            if profile.metrics:
                metrics_copy = {}
                for k, v in profile.metrics.items():
                    if isinstance(v, set):
                        metrics_copy[k] = list(v)[:20]  # Limit
                    elif isinstance(v, Counter):
                        metrics_copy[k] = dict(v.most_common(20))
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
                    if "metrics" in svc_data:
                        profile.metrics = svc_data["metrics"]
                    if "anomaly_log" in svc_data:
                        profile.anomaly_log = svc_data["anomaly_log"]

            logger.info("ServiceMonitor: Loaded state with %d services", len(self.profiles))
        except Exception as e:
            logger.warning("ServiceMonitor: Failed to load state: %s", e)
