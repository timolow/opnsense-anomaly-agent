"""
NetworkClassifier — Classifies IPs as WAN, LAN, VPN, or UNKNOWN.

Uses two methods:
1. Config-driven: env vars WAN_IPS/LAN_IPS/CUSTOM_INTERFACES
2. Log-driven: auto-discovers from firewall interface data in events

This replaces the OPNsense API dependency for WAN/LAN classification.
The API key permissions are too restrictive (endpoint-scoped in OPNsense);
instead we extract interface information directly from the filterlog data
that flows through the agent.
"""

import ipaddress
from typing import Set, Dict, Optional, List
from collections import defaultdict
import os


class NetworkClassifier:
    """Classifies traffic as WAN, LAN, VPN, internal, or unknown."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}

        # Method 1: Config-driven IPs (from env)
        wan_ips = os.getenv("WAN_IPS", "")
        self._wan_ips: Set[str] = set()
        if wan_ips:
            for ip_or_cidr in wan_ips.split(","):
                ip_or_cidr = ip_or_cidr.strip()
                if ip_or_cidr:
                    try:
                        if "/" in ip_or_cidr:
                            network = ipaddress.ip_network(ip_or_cidr, strict=False)
                            self._wan_ips.add(ip_or_cidr)
                        else:
                            self._wan_ips.add(ip_or_cidr)
                    except ValueError:
                        pass

        # Local IP ranges (RFC 1918 + common)
        self._lan_networks = [
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
        ]

        # Config-driven LAN IPs
        lan_ips_str = os.getenv("LAN_IPS", "")
        self._lan_ips: Set[str] = set()
        if lan_ips_str:
            for ip_or_cidr in lan_ips_str.split(","):
                ip_or_cidr = ip_or_cidr.strip()
                if ip_or_cidr:
                    self._lan_ips.add(ip_or_cidr)

        # Config-driven VPN networks
        vpn_ips_str = os.getenv("VPN_IPS", "")
        self._vpn_networks = []
        if vpn_ips_str:
            for net_str in vpn_ips_str.split(","):
                net_str = net_str.strip()
                if net_str:
                    try:
                        self._vpn_networks.append(ipaddress.ip_network(net_str, strict=False))
                    except ValueError:
                        pass

        # Custom interface-to-class mapping
        # Format: "interface=class" comma-separated
        iface_str = os.getenv("CUSTOM_INTERFACES", "")
        self._interface_map: Dict[str, str] = {}
        if iface_str:
            for mapping in iface_str.split(","):
                mapping = mapping.strip()
                if "=" in mapping:
                    iface, cls = mapping.split("=", 1)
                    self._interface_map[iface.strip()] = cls.strip().lower()

        # Method 2: Auto-discovered interfaces from log data
        # Track: interface -> set of src_ips, dst_ips, action counts
        self._interface_stats: Dict[str, Dict] = defaultdict(lambda: {
            "src_ips": defaultdict(int),
            "dst_ips": defaultdict(int),
            "action_pass": 0,
            "action_block": 0,
            "total": 0,
        })

        self._auto_discovered = False
        self._wan_interfaces: Set[str] = set()
        self._lan_interfaces: Set[str] = set()
        self._vpn_interfaces: Set[str] = set()

        # Thresholds for auto-discovery
        self._external_ratio_threshold = 0.5  # 50% external IPs = WAN
        self._min_events_for_discovery = 100

    # ── Config-driven classification ────────────────────────────────────

    def classify_ip(self, ip_str: str, interface: Optional[str] = None) -> str:
        """Classify a single IP address as WAN, LAN, VPN, INTERNAL, or UNKNOWN.

        Uses a prioritized approach:
        1. Config-driven (WAN_IPS, LAN_IPS env vars)
        2. Interface-based classification (WAN interface = external, LAN = internal)
        3. RFC 1918 heuristic (private = LAN, else = WAN)
        
        Returns one of: 'WAN', 'LAN', 'VPN', 'INTERNAL', 'UNKNOWN'
        """
        if not ip_str:
            return "UNKNOWN"

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "UNKNOWN"

        # Check if this is our own WAN IP (config-driven)
        if ip_str in self._wan_ips:
            return "WAN"

        # Check if this is a known LAN IP (config-driven)
        if ip_str in self._lan_ips:
            return "LAN"

        # Check if it's in a VPN network (config-driven)
        for vpn_net in self._vpn_networks:
            if ip in vpn_net:
                return "VPN"

        # Interface-based classification (from log data)
        if interface and interface in self._interface_map:
            iface_class = self._interface_map[interface]
            if iface_class == "WAN":
                # Traffic came from a WAN interface, so source is external
                # But verify it's not our own WAN IP going outbound
                if ip_str in self._wan_ips:
                    return "LAN"  # Our own WAN IP acting as source
                return "WAN"
            elif iface_class in ("LAN", "INTERNAL"):
                # Traffic came from a LAN interface, source is internal
                return "LAN"
            elif iface_class == "VPN":
                return "VPN"

        # RFC 1918 heuristic (final fallback)
        if ip.is_link_local:
            return "INTERNAL"
        if ip.is_private:
            return "LAN"

        # Anything else is external/WAN
        return "WAN"

    def classify_event(self, event: Dict, interface: Optional[str] = None) -> Dict:
        """Add direction classification to an event.

        Returns the event dict with added:
        - src_direction: 'inbound', 'outbound', 'internal', 'localhost'
        - dst_direction: 'inbound', 'outbound', 'internal', 'localhost'
        - src_class: 'WAN', 'LAN', 'VPN', 'INTERNAL', 'UNKNOWN'
        - dst_class: 'WAN', 'LAN', 'VPN', 'INTERNAL', 'UNKNOWN'
        - is_trusted: bool (both directions are internal/lan)
        - is_external: bool (either direction is external/wan)
        """
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")

        src_class = self.classify_ip(src_ip, interface=interface) if src_ip else "UNKNOWN"
        dst_class = self.classify_ip(dst_ip, interface=interface) if dst_ip else "UNKNOWN"

        # Direction logic
        src_direction = self._ip_to_direction(src_class)
        dst_direction = self._ip_to_direction(dst_class)

        # Trusted = both sides are internal/LAN
        is_trusted = src_class in ("LAN", "INTERNAL") and dst_class in ("LAN", "INTERNAL")
        is_external = src_class in ("WAN", "VPN") or dst_class in ("WAN", "VPN")

        # Localhost check
        if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
            src_direction = "localhost"
            dst_direction = "localhost"

        event["src_direction"] = src_direction
        event["dst_direction"] = dst_direction
        event["src_class"] = src_class
        event["dst_class"] = dst_class
        event["is_trusted"] = is_trusted
        event["is_external"] = is_external

        return event

    # ── Log-driven auto-discovery ────────────────────────────────────────

    def record_interface_event(self, event: Dict):
        """Record an event's interface data for auto-discovery."""
        interface = event.get("interface")
        if not interface or interface == "":
            return

        stats = self._interface_stats[interface]
        stats["total"] += 1

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        action = event.get("action", "").upper()

        if src_ip:
            stats["src_ips"][src_ip] += 1
        if dst_ip:
            stats["dst_ips"][dst_ip] += 1
        if action == "PASS":
            stats["action_pass"] += 1
        elif action == "BLOCK":
            stats["action_block"] += 1

    def auto_discover_interfaces(self) -> Dict[str, Set[str]]:
        """Auto-discover which interfaces are WAN vs LAN based on traffic patterns.

        Returns dict mapping:
        - 'wan': set of interface names
        - 'lan': set of interface names
        - 'vpn': set of interface names
        """
        if self._auto_discovered:
            return {
                "wan": self._wan_interfaces,
                "lan": self._lan_interfaces,
                "vpn": self._vpn_interfaces,
            }

        for iface, stats in self._interface_stats.items():
            if stats["total"] < self._min_events_for_discovery:
                continue

            # Check for OpenVPN/WireGuard interfaces
            if any(tag in iface.lower() for tag in ("ovpn", "wg", "vpn")):
                self._vpn_interfaces.add(iface)
                continue

            # Calculate ratio of external vs internal IPs
            external_count = 0
            internal_count = 0

            for ip, count in stats["src_ips"].items():
                if self._is_external_ip(ip):
                    external_count += count
                else:
                    internal_count += count

            for ip, count in stats["dst_ips"].items():
                if self._is_external_ip(ip):
                    external_count += count
                else:
                    internal_count += count

            # High block rate + external traffic = WAN
            total_blocked = stats["action_block"]
            total_events = stats["total"]

            if total_blocked > 1000 and total_events > 5000:
                # Likely WAN interface
                self._wan_interfaces.add(iface)
            elif external_count > 0 and (external_count / max(total_events, 1)) > self._external_ratio_threshold:
                # Mostly external traffic
                self._wan_interfaces.add(iface)
            else:
                # Mostly internal traffic
                self._lan_interfaces.add(iface)

        # Also check interface name heuristics
        for iface in list(self._lan_interfaces):
            if any(tag in iface.lower() for tag in ("wan", "ppp", "pptp")):
                self._lan_interfaces.discard(iface)
                self._wan_interfaces.add(iface)

        for iface in list(self._wan_interfaces):
            if any(tag in iface.lower() for tag in ("lan", "vlan", "internal")):
                self._wan_interfaces.discard(iface)
                self._lan_interfaces.add(iface)

        self._auto_discovered = True

        return {
            "wan": self._wan_interfaces,
            "lan": self._lan_interfaces,
            "vpn": self._vpn_interfaces,
        }

    def classify_by_interface(self, interface: str) -> str:
        """Classify an interface as WAN, LAN, or VPN based on config or auto-discovery.

        Priority:
        1. Config-driven (CUSTOM_INTERFACES)
        2. Auto-discovered
        3. Interface name heuristics
        4. UNKNOWN
        """
        # Check config first
        if interface in self._interface_map:
            return self._interface_map[interface]

        # Check auto-discovered
        if interface in self._wan_interfaces:
            return "WAN"
        if interface in self._lan_interfaces:
            return "LAN"
        if interface in self._vpn_interfaces:
            return "VPN"

        # Heuristic fallback
        iface_lower = interface.lower()
        if any(tag in iface_lower for tag in ("wan", "ppp", "pptp", "pppoe", "igb0", "igb1")):
            return "WAN"
        if any(tag in iface_lower for tag in ("lan", "vlan", "br0")):
            return "LAN"
        if any(tag in iface_lower for tag in ("ovpn", "wg", "vpn")):
            return "VPN"

        return "UNKNOWN"

    # ── Helpers ──────────────────────────────────────────────────────────

    def _is_external_ip(self, ip_str: str) -> bool:
        """Check if an IP is external (not RFC 1918, not link-local)."""
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            # Link-local
            if ip.is_link_local:
                return False
            # Private/RFC1918
            if ip.is_private:
                return False
            return True
        except ValueError:
            return False

    def _ip_to_direction(self, ip_class: str) -> str:
        """Map IP class to traffic direction."""
        mapping = {
            "WAN": "inbound",
            "LAN": "internal",
            "VPN": "internal",
            "INTERNAL": "internal",
            "UNKNOWN": "unknown",
        }
        return mapping.get(ip_class, "unknown")

    def get_stats(self) -> Dict:
        """Return classification stats."""
        return {
            "wan_ips_count": len(self._wan_ips),
            "lan_ips_count": len(self._lan_ips),
            "wan_interfaces": list(self._wan_interfaces),
            "lan_interfaces": list(self._lan_interfaces),
            "interface_stats": {
                k: {
                    "total": v["total"],
                    "unique_src_ips": len(v["src_ips"]),
                    "unique_dst_ips": len(v["dst_ips"]),
                    "blocked": v["action_block"],
                    "passed": v["action_pass"],
                }
                for k, v in self._interface_stats.items()
                if v["total"] > 0
            },
        }
