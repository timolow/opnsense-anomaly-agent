"""
NetworkClassifier — Auto-discovers and classifies WAN/LAN/VPN IPs from firewall logs.

Uses per-IP tracking (not per-interface) so it can distinguish:
  - Your own WAN IPs (via OWN_WAN_IPS env var)
  - All other external IPs (classified as WAN/attacker)
  - Internal/LAN IPs (RFC1918)
  - VPN connections (from config or heuristics)

The classifier auto-discovers every external IP it sees on any interface,
no matter how many there are. This means even unknown attacker IPs get
detected and tracked automatically.

Config:
  - OWN_WAN_IPS    : comma-separated list of your own WAN IPs
  - LAN_IPS        : comma-separated list of known LAN IPs  
  - VPN_IPS        : comma-separated list of VPN networks (CIDR)
  - CUSTOM_INTERFACES: iface=class mapping (fallback for unknown interfaces)
"""

import ipaddress
from typing import Set, Dict, Optional, List
from collections import defaultdict
import os


class NetworkClassifier:
    """Classifies traffic by per-IP WAN/LAN/VPN detection."""

    def __init__(self, opnsense_api_url: Optional[str] = None):
        self.opnsense_api_url = opnsense_api_url
        
        # ── Config-driven: our own WAN IPs (NOT attacks) ─────────────────
        # Comma-separated list of IPs that belong to us
        own_wan_str = os.getenv("OWN_WAN_IPS", "")
        self.own_wan_ips: Set[str] = set(
            ip.strip() for ip in own_wan_str.split(",") if ip.strip()
        )
        
        # ── OPNsense API interface classification ────────────────────────
        # Interface→class mapping from OPNsense gateway settings
        self._api_interface_map: Dict[str, str] = {}
        self._api_loaded = False
        self._load_api_interface_classification()
        
        # Config-driven LAN IPs
        lan_str = os.getenv("LAN_IPS", "")
        self.lan_ips: Set[str] = set(
            ip.strip() for ip in lan_str.split(",") if ip.strip()
        )
        
        # Config-driven VPN networks
        vpn_str = os.getenv("VPN_IPS", "")
        self._vpn_networks: list = []
        for net_str in vpn_str.split(","):
            net_str = net_str.strip()
            if net_str:
                try:
                    self._vpn_networks.append(ipaddress.ip_network(net_str, strict=False))
                except ValueError:
                    pass
        
        # Custom interface→class mapping (manual override)
        iface_str = os.getenv("CUSTOM_INTERFACES", "")
        self._interface_map: Dict[str, str] = {}
        for mapping in iface_str.split(","):
            mapping = mapping.strip()
            if "=" in mapping:
                iface, cls = mapping.split("=", 1)
                self._interface_map[iface.strip()] = cls.strip().lower()

        # ── Auto-discovered per-IP tracking ───────────────────────────────
        # WAN IPs: external (non-RFC1918) IPs we've seen, indexed by IP
        self.wan_ips: Dict[str, Dict] = {}
        
        # LAN IPs: private IPs we've seen
        self.lan_ips_auto: Dict[str, Dict] = {}
        
        # VPN IPs: VPN tunnel IPs we've seen
        self.vpn_ips_auto: Dict[str, Dict] = {}
        
        # Per-interface stats for fallback classification
        self._interface_events: Dict[str, Dict] = defaultdict(lambda: {
            "total": 0,
            "blocked": 0,
            "passed": 0,
        })

        # ── Thresholds ────────────────────────────────────────────────────
        self.min_events_for_tracking = int(os.getenv("WAN_IP_MIN_EVENTS", "10"))
        self.max_wan_ips = int(os.getenv("MAX_WAN_IPS", "10000"))

    # ── OPNsense API interface classification ────────────────────────────

    def _load_api_interface_classification(self):
        """Fetch gateway info from OPNsense API and populate interface→class mapping.
        
        Reads /api/routing/settings/searchGateway to determine:
        - WAN interfaces: upstream=true, gateway_interface=false
        - VPN interfaces: upstream=false, gateway_interface=true  
        - LAN interfaces: everything else
        
        Uses OPN_HOST, OPN_PORT, OPN_API_KEY, OPN_API_SECRET from env.
        Falls back gracefully if API unavailable (classifies via log data only).
        """
        if not self.opnsense_api_url:
            # Build API URL from env vars
            host = os.getenv("OPN_HOST", "192.168.1.1")
            port = os.getenv("OPN_PORT", "6666")
            self.opnsense_api_url = f"https://{host}:{port}"
        
        import requests
        import base64
        
        host = os.getenv("OPN_HOST", "192.168.1.1")
        port = os.getenv("OPN_PORT", "6666")
        key = os.getenv("OPN_API_KEY", "")
        secret = os.getenv("OPN_API_SECRET", "")
        
        if not key or not secret:
            import sys
            sys.stderr.write(f"[network_classifier] WARNING: OPNsense API key not configured, skipping interface classification\n")
            sys.stderr.flush()
            return  # No API credentials configured
        
        try:
            url = f"https://{host}:{port}/api/routing/settings/searchGateway"
            creds = base64.b64encode(f"{key}:{secret}".encode()).decode()
            headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
            
            import sys
            sys.stderr.write(f"[network_classifier] INFO: Fetching OPNsense gateway info from {url}...\n")
            sys.stderr.flush()
            
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code != 200:
                sys.stderr.write(f"[network_classifier] WARNING: OPNsense API returned {resp.status_code}, skipping interface classification\n")
                sys.stderr.flush()
                return  # API not available or auth failed
            
            data = resp.json()
            rows = data.get("rows", [])
            
            wan_interfaces = set()
            vpn_interfaces = set()
            
            for gw in rows:
                if gw.get("disabled"):
                    continue
                
                if_interface = gw.get("if", "") or gw.get("interface", "")
                if not if_interface:
                    continue
                
                upstream = gw.get("upstream", False)
                gateway_interface = gw.get("gateway_interface", False)
                
                if upstream and not gateway_interface:
                    wan_interfaces.add(if_interface)
                elif not upstream and gateway_interface:
                    vpn_interfaces.add(if_interface)
            
            if wan_interfaces or vpn_interfaces:
                self._api_interface_map = {
                    **{iface: "WAN" for iface in wan_interfaces},
                    **{iface: "VPN" for iface in vpn_interfaces},
                }
                self._api_loaded = True
                sys.stderr.write(f"[network_classifier] INFO: OPNsense API interface classification loaded: WAN={wan_interfaces}, VPN={vpn_interfaces}\n")
                for iface, cls in self._api_interface_map.items():
                    sys.stderr.write(f"[network_classifier] INFO:   {iface} → {cls}\n")
                sys.stderr.flush()
                
        except Exception as e:
            import sys
            sys.stderr.write(f"[network_classifier] WARNING: OPNsense API classification failed: {e}\n")
            sys.stderr.flush()
            pass  # Fail gracefully, fall back to log-driven classification

    # ── Per-IP classification ─────────────────────────────────────────────

    def classify_ip(self, ip_str: str, interface: Optional[str] = None) -> str:
        """Classify an IP as OWN, WAN, LAN, VPN, INTERNAL, or UNKNOWN.

        Priority:
        1. Own WAN IPs (from OWN_WAN_IPS env) → OWN
        2. LAN IPs (from LAN_IPS env) → LAN
        3. VPN networks (from VPN_IPS env) → VPN
        4. API-driven interface classification → WAN/VPN/lan
        5. Auto-discovered WAN IPs → WAN
        6. Auto-discovered LAN IPs → LAN  
        7. Auto-discovered VPN IPs → VPN
        8. Heuristic: RFC1918 private → LAN, link-local → INTERNAL, else → WAN
        
        Args:
            ip_str: The IP to classify
            interface: The firewall interface the event came on (for API-driven classification)
        
        Returns: 'OWN', 'WAN', 'LAN', 'VPN', 'INTERNAL', 'UNKNOWN'
        """
        if not ip_str:
            return "UNKNOWN"
        
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "UNKNOWN"

        # 1. Our own WAN IPs (explicitly configured)
        if ip_str in self.own_wan_ips:
            return "OWN"

        # 2. Configured LAN IPs
        if ip_str in self.lan_ips:
            return "LAN"

        # 3. Configured VPN networks
        for vpn_net in self._vpn_networks:
            if ip in vpn_net:
                return "VPN"

        # 4. API-driven interface classification
        if self._api_loaded and interface:
            iface_class = self._api_interface_map.get(interface)
            if iface_class:
                # If event comes FROM a WAN interface, the source is external (WAN)
                # If event comes FROM a VPN interface, the destination is VPN
                if iface_class == "WAN":
                    # Could be src (external attacker) or dst (our WAN IP)
                    # If IP is in own_wan_ips, it's OWN; otherwise it's external WAN
                    if ip_str not in self.own_wan_ips:
                        return "WAN"  # External IP on WAN interface
                elif iface_class == "VPN":
                    return "VPN"

        # 4. Auto-discovered WAN IPs
        if ip_str in self.wan_ips:
            return "WAN"

        # 5. Auto-discovered LAN IPs
        if ip_str in self.lan_ips_auto:
            return "LAN"

        # 6. Auto-discovered VPN IPs
        if ip_str in self.vpn_ips_auto:
            return "VPN"

        # 7. Heuristic fallback
        if ip.is_link_local:
            return "INTERNAL"
        if ip.is_private:
            return "LAN"

        # Everything else is external/WAN
        return "WAN"

    # ── Event processing ──────────────────────────────────────────────────

    def record_interface_event(self, event: Dict):
        """Record an event for interface-level stats (fallback classification)."""
        interface = event.get("interface")
        if not interface or interface == "":
            return

        stats = self._interface_events[interface]
        stats["total"] += 1
        action = event.get("action", "").upper()
        if action == "BLOCK":
            stats["blocked"] += 1
        elif action == "PASS":
            stats["passed"] += 1

    def record_ip(self, ip_str: str, event: Dict):
        """Track a single IP across all interfaces."""
        if not ip_str:
            return

        interface = event.get("interface")
        classification = self.classify_ip(ip_str, interface=interface)
        
        record = {
            "count": 0,
            "interfaces": set(),
            "dst_ports": set(),
            "src_ips": set(),
            "dst_ips": set(),
            "protocols": set(),
            "actions": defaultdict(int),
        }

        # Merge into existing or create new
        if classification == "WAN":
            if ip_str not in self.wan_ips:
                self.wan_ips[ip_str] = record
            else:
                record = self.wan_ips[ip_str]
            
            # Check if we've exceeded max WAN IPs (drop least active)
            if len(self.wan_ips) > self.max_wan_ips and record["count"] < self.min_events_for_tracking:
                return  # Skip tracking very low-count IPs when at cap
        elif classification == "LAN":
            if ip_str not in self.lan_ips_auto:
                self.lan_ips_auto[ip_str] = record
            else:
                record = self.lan_ips_auto[ip_str]
        elif classification == "VPN":
            if ip_str not in self.vpn_ips_auto:
                self.vpn_ips_auto[ip_str] = record
            else:
                record = self.vpn_ips_auto[ip_str]
        elif classification == "OWN":
            # Track own IPs with full stats (in wan_ips so get_own_wan_ips() finds them)
            if ip_str not in self.wan_ips:
                self.wan_ips[ip_str] = record
            else:
                record = self.wan_ips[ip_str]

        # Update record
        record["count"] += 1
        record["interfaces"].add(event.get("interface", ""))
        
        if event.get("dst_port"):
            record["dst_ports"].add(int(event["dst_port"]))
        if event.get("src_ip") and event["src_ip"] != ip_str:
            record["src_ips"].add(event["src_ip"])
        if event.get("dst_ip") and event["dst_ip"] != ip_str:
            record["dst_ips"].add(event["dst_ip"])
        if event.get("protocol"):
            record["protocols"].add(event["protocol"].upper())
        
        action = event.get("action", "").upper()
        if action:
            record["actions"][action] += 1

    def classify_event(self, event: Dict) -> Dict:
        """Add classification to an event.

        Enriches the event with:
        - src_class: 'OWN', 'WAN', 'LAN', 'VPN', 'INTERNAL', 'UNKNOWN'
        - dst_class: same
        - src_direction: 'inbound', 'outbound', 'internal', 'localhost', 'unknown'
        - dst_direction: same
        - is_trusted: True if both src and dst are OWN/LAN
        - is_external: True if either is WAN/OWN
        """
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        interface = event.get("interface")

        # Classify each IP (pass interface for API-driven classification)
        src_class = self.classify_ip(src_ip, interface=interface) if src_ip else "UNKNOWN"
        dst_class = self.classify_ip(dst_ip, interface=interface) if dst_ip else "UNKNOWN"

        # Directions
        direction_map = {
            "OWN": "outbound",
            "WAN": "inbound",
            "LAN": "internal",
            "VPN": "internal",
            "INTERNAL": "internal",
            "UNKNOWN": "unknown",
        }

        src_direction = direction_map.get(src_class, "unknown")
        dst_direction = direction_map.get(dst_class, "unknown")

        # Special case: localhost
        if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
            src_direction = "localhost"
            dst_direction = "localhost"

        # Trusted = both sides are internal or our own
        is_trusted = src_class in ("OWN", "LAN", "INTERNAL") and dst_class in ("OWN", "LAN", "INTERNAL")
        
        # External = either side is WAN (external attacker) or OWN (our infrastructure)
        is_external = src_class in ("WAN", "OWN") or dst_class in ("WAN", "OWN")

        event["src_class"] = src_class
        event["dst_class"] = dst_class
        event["src_direction"] = src_direction
        event["dst_direction"] = dst_direction
        event["is_trusted"] = is_trusted
        event["is_external"] = is_external

        return event

    def record_event(self, event: Dict):
        """Full event processing: classify IPs and enrich the event."""
        # Classify source and destination IPs
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")

        # Record both IPs
        if src_ip:
            self.record_ip(src_ip, event)
        if dst_ip and dst_ip != src_ip:
            self.record_ip(dst_ip, event)

        # Classify the event for the pipeline
        return self.classify_event(event)

    # ── Discovery & visibility ────────────────────────────────────────────

    def get_all_wan_ips(self, min_events: Optional[int] = None, 
                        exclude_own: bool = True) -> List[Dict]:
        """Return all discovered WAN IPs sorted by event count.

        Args:
            min_events: Minimum events to include (defaults to WAN_IP_MIN_EVENTS)
            exclude_own: If True, exclude IPs in OWN_WAN_IPS from results
        
        Returns: List of dicts with ip, count, interfaces, ports, protocols, actions
        """
        if min_events is None:
            min_events = self.min_events_for_tracking

        results = []
        for ip, data in self.wan_ips.items():
            if exclude_own and ip in self.own_wan_ips:
                continue
            if data["count"] < min_events:
                continue
            results.append({
                "ip": ip,
                "count": data["count"],
                "interfaces": list(data["interfaces"]),
                "ports": len(data["dst_ports"]),
                "protocols": list(data["protocols"]),
                "actions": dict(data["actions"]),
            })

        # Sort by event count descending
        results.sort(key=lambda x: x["count"], reverse=True)
        return results

    def get_own_wan_ips(self) -> List[Dict]:
        """Return stats for our own WAN IPs."""
        results = []
        for ip, data in self.wan_ips.items():
            if ip in self.own_wan_ips:
                results.append({
                    "ip": ip,
                    "count": data["count"],
                    "interfaces": list(data["interfaces"]),
                    "ports": len(data["dst_ports"]),
                    "protocols": list(data["protocols"]),
                    "actions": dict(data["actions"]),
                })
        return sorted(results, key=lambda x: x["count"], reverse=True)

    def is_own_wan_ip(self, ip_str: str) -> bool:
        """Check if an IP is one of our own WAN addresses."""
        return ip_str in self.own_wan_ips

    def is_external_wan(self, ip_str: str) -> bool:
        """Check if an IP is an external WAN IP (attacker/scanner)."""
        return ip_str in self.wan_ips and ip_str not in self.own_wan_ips

    def get_stats(self) -> Dict:
        """Return classification stats for status logging."""
        wan_list = self.get_all_wan_ips(min_events=1)
        own_list = self.get_own_wan_ips()
        
        return {
            "wan_ips_count": len(wan_list),
            "own_wan_ips_count": len(own_list),
            "wan_ips_top5": [w["ip"] for w in wan_list[:5]],
            "own_wan_ips": [w["ip"] for w in own_list],
            "lan_ips_count": len(self.lan_ips_auto),
            "vpn_ips_count": len(self.vpn_ips_auto),
            "interface_events": dict(
                (k, v["total"]) for k, v in self._interface_events.items()
            ),
            "wan_ips": {w["ip"]: w["count"] for w in wan_list},
        }

    def print_wan_summary(self):
        """Print a human-readable summary of discovered WAN IPs."""
        wan_list = self.get_all_wan_ips(min_events=1)
        own_list = self.get_own_wan_ips()

        print("\n" + "=" * 70)
        print("NETWORK CLASSIFICATION SUMMARY")
        print("=" * 70)

        print(f"\nOur WAN IPs ({len(own_list)}):")
        for ip in own_list:
            print(f"  {ip:<20s} {ip['count']:>8,d} events | "
                  f"ports={ip['ports']} | actions={ip['actions']}")

        print(f"\nExternal WAN IPs ({len(wan_list)} total):")
        top = wan_list[:20]
        for ip in top:
            actions_str = ", ".join(f"{k}={v}" for k, v in ip['actions'].items())
            print(f"  {ip['ip']:<20s} {ip['count']:>8,d} events | "
                  f"ports={ip['ports']} | {actions_str}")
        
        if len(wan_list) > 20:
            print(f"  ... and {len(wan_list) - 20} more WAN IPs")

        print(f"\nLAN IPs: {len(self.lan_ips_auto)}")
        print(f"VPN IPs: {len(self.vpn_ips_auto)}")
        print("=" * 70)
