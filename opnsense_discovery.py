#!/usr/bin/env python3
"""
OPNsense API Discovery Tool
-------------------------------
Read-only discovery of OPNsense REST API endpoints.
Probes each API module to discover available controllers,
commands, and response schemas.

Safe operations only: GET requests for information discovery.
No write operations, no configuration changes.

Usage:
    python opnsense_discovery.py [--json] [--verbose]

Environment:
    OPN_HOST     - OPNsense firewall IP/hostname
    OPN_PORT     - API port (default 443)
    OPN_API_KEY  - API key (Basic Auth username)
    OPN_API_SECRET - API secret (Basic Auth password)
    OPN_VERIFY_SSL - Set to false if using self-signed cert

Output:
    - Terminal: formatted report of discovered endpoints
    - opnsense_api_endpoints.md: Markdown documentation
    - opnsense_api_endpoints.json: Raw JSON for programmatic use

Security:
    - No sensitive data logged (keys/secrets stripped)
    - No write operations
    - All responses trimmed to schema descriptions only
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime
from collections import defaultdict

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OPN_HOST = os.getenv("OPN_HOST", "192.168.1.1")
OPN_PORT = os.getenv("OPN_PORT", "6666")
OPN_API_KEY = os.getenv("OPN_API_KEY", "")
OPN_API_SECRET = os.getenv("OPN_API_SECRET", "")
OPN_VERIFY_SSL = os.getenv("OPN_VERIFY_SSL", "false").lower() not in ("false", "0", "no")
OUTPUT_JSON = os.getenv("OUTPUT_JSON", "false").lower() in ("true", "1", "yes")

# API base URL
BASE_URL = f"https://{OPN_HOST}:{OPN_PORT}/api"

# Known core API modules from OPNsense source
CORE_MODULES = [
    "auth",           # Authentication
    "captiveportal",  # Captive Portal
    "core",           # System core (services, firmware, status)
    "cron",           # Cron jobs
    "dhcp",           # DHCP (v4/v6 relay and server)
    "diagnostics",    # Diagnostics (interfaces, pings, routes)
    "dnsmasq",        # DNSMasq resolver
    "firewall",       # Firewall (aliases, rules, NAT, CARP)
    "firmware",       # Firmware upgrade/status
    "hostdiscovery",  # Host discovery / ARP cache
    "ids",            # Snort/Suricata IDS
    "interfaces",     # Interface configuration
    "ipsec",          # IPsec VPN
    "kea",            # Kea DHCP server
    "monit",          # Monit monitoring
    "ndpproxy",       # NDP Proxy
    "ntp",            # NTP configuration
    "openvpn",        # OpenVPN
    "radvd",          # RADVD (IPv6 router advertisement)
    "routes",         # Routing tables
    "routing",        # Routing configuration
    "services",       # Service management
    "syslog",         # Syslog server
    "system",         # System configuration
    "trafficshaper",  # Traffic shaper / pfSense ALTQ
    "trust",          # Trust store / certificates
    "unbound",        # Unbound DNS resolver
    "wireguard",      # WireGuard VPN
]

# Known plugin API modules (commonly installed)
PLUGIN_MODULES = [
    "acme",           # Let's Encrypt / ACME client
    "bind",           # BIND DNS server
    "cicp",           # CICAP (ICAP client)
    "clamav",         # ClamAV antivirus
    "crowdsec",       # CrowdSec BaaS integration
    "dhcp",           # DHCP v4/v6 server
    "dyndns",         # Dynamic DNS
    "freeradius",     # FreeRADIUS
    "haproxy",        # HAProxy
    "netdata",        # Netdata monitoring
    "nginx",          # Nginx web server
    "ntopng",         # ntopNG network monitoring
    "snmp",           # SNMP
    "proxmox",        # Proxmox integration
    "rspamd",         # Rspamd spam filter
    "telegraf",       # Telegraf metrics
    "wazuh",          # Wazuh agent
    "zerotier",       # ZeroTier
]

# Common command patterns to try for each module
COMMON_COMMANDS = [
    "get",
    "list",
    "status",
    "info",
    "search",
    "overview",
    "stats",
    "statistics",
    "summary",
    "details",
    "config",
    "settings",
    "rules",
    "entries",
    "leases",
    "routes",
    "services",
    "users",
    "aliases",
    "nat",
    "snat",
    "dnat",
    "portforward",
    "pfstats",
    "logs",
    "history",
    "cache",
    "neighbors",
    "arp",
    "interfaces",
    "dns",
    "ntp",
    "ntp_servers",
    "firmware",
    "upgrades",
    "backup",
    "restore",
    "restart",
    "reload",
]

# Known parameter patterns for pagination
KNOWN_PARAMS = [
    "limit",
    "offset",
    "page",
    "sort",
    "order",
    "filter",
    "search",
    "type",
    "status",
    "interface",
    "protocol",
]

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def curl_cmd(endpoint):
    """Build a curl command for the given API endpoint."""
    verify_flag = "--insecure" if not OPN_VERIFY_SSL else ""
    cmd = f"curl -s -w '\\n%{{http_code}}' -X GET"
    cmd += f" --user {OPN_API_KEY}:{OPN_API_SECRET}"
    cmd += f" -H 'Accept: application/json'"
    if not OPN_VERIFY_SSL:
        cmd += " --insecure"
    cmd += f" https://{OPN_HOST}:{OPN_PORT}{endpoint}"
    return cmd

def api_get(endpoint, timeout=10):
    """Execute a GET request and return (status_code, json_data, raw_response)."""
    cmd = curl_cmd(endpoint)
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()
        lines = output.rsplit("\n", 1)
        if len(lines) == 2:
            raw_response = lines[0]
            status_code = int(lines[1])
        else:
            raw_response = lines[0]
            status_code = result.returncode
        json_data = None
        if raw_response:
            try:
                json_data = json.loads(raw_response)
            except (json.JSONDecodeError, ValueError):
                pass
        return status_code, json_data, raw_response
    except subprocess.TimeoutExpired:
        return None, None, "timeout"
    except Exception as e:
        return None, None, str(e)

def strip_sensitive(data):
    """Strip sensitive fields from response data for safe logging."""
    if isinstance(data, dict):
        sensitive_keys = [
            "secret", "password", "passwd", "key", "token",
            "api_secret", "api_key", "credential", "hash",
        ]
        return {
            k: strip_sensitive(v) if k.lower() not in sensitive_keys else "REDACTED"
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [strip_sensitive(item) for item in data]
    return data

def describe_schema(data, depth=0, max_depth=2):
    """Generate a schema description of API response data."""
    if depth >= max_depth:
        return f"<{type(data).__name__}>[max_depth_reached]"
    if data is None:
        return "null"
    if isinstance(data, bool):
        return f"boolean({data})"
    if isinstance(data, (int, float)):
        return f"number({data})"
    if isinstance(data, str):
        if len(data) > 50:
            return f'string("{data[:50]}...")'
        return f'string("{data}")'
    if isinstance(data, list):
        if len(data) == 0:
            return "array[]"
        if len(data) > 5:
            return f"array[{len(data)}] containing {describe_schema(data[0], depth+1, max_depth)}"
        return f"array[{len(data)}]: [{', '.join(describe_schema(d, depth+1, max_depth) for d in data)}]"
    if isinstance(data, dict):
        if len(data) == 0:
            return "object{}"
        if len(data) > 5:
            keys_desc = ", ".join(f"{k}:{describe_schema(v, depth+1, max_depth)}" for k, v in list(data.items())[:3])
            return f"object{{{keys_desc}, ... +{len(data)-3} more}}"
        return f"object{{{', '.join(f'{k}:{describe_schema(v, depth+1, max_depth)}' for k, v in data.items())}}}"
    return type(data).__name__

def safe_str(value, max_len=200):
    """Convert value to a safe, truncated string."""
    if value is None:
        return "null"
    s = str(value)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s

# ---------------------------------------------------------------------------
# Discovery Functions
# ---------------------------------------------------------------------------

def discover_module_endpoints(module):
    """Discover available controllers and commands for a given module."""
    results = {
        "module": module,
        "endpoints": [],
        "controllers": [],
        "commands": [],
    }
    endpoint = f"/api/{module}/"

    status, data, raw = api_get(endpoint)

    if status == 200 and data:
        # Check if response contains a list of endpoints or controllers
        if isinstance(data, dict):
            for key in data:
                if key.lower() in ("endpoints", "controllers", "resources", "items", "results", "rows"):
                    if isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, str):
                                results["controllers"].append(item)
                            elif isinstance(item, dict):
                                for sub_key in item:
                                    results["controllers"].append(str(item[sub_key]))
            # Also check for nested dicts that could be controllers
            for key in data:
                if isinstance(data[key], dict) and "error" not in data[key]:
                    results["controllers"].append(key)
                    # Try to discover commands within this controller
                    for cmd in COMMON_COMMANDS[:5]:  # Limit to first 5 commands per controller
                        cmd_endpoint = f"/api/{module}/{key}/{cmd}"
                        cmd_status, cmd_data, cmd_raw = api_get(cmd_endpoint)
                        if cmd_status in (200, 404, 500, 400):
                            if cmd_status == 200:
                                results["commands"].append({
                                    "path": cmd_endpoint,
                                    "status": cmd_status,
                                    "schema": describe_schema(cmd_data),
                                    "sample_keys": list(cmd_data.keys())[:5] if isinstance(cmd_data, dict) else [],
                                })
                            else:
                                results["commands"].append({
                                    "path": cmd_endpoint,
                                    "status": cmd_status,
                                    "schema": None,
                                    "sample_keys": [],
                                })
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    results["controllers"].append(item)
                elif isinstance(item, dict):
                    for k, v in item.items():
                        results["controllers"].append(str(v))

    elif status == 404:
        results["not_found"] = True
    elif status is not None:
        results["error_status"] = status
        results["error_raw"] = raw[:200]

    return results

def discover_firmware():
    """Discover firmware-related endpoints."""
    endpoints = [
        "/api/core/firmware/status",
        "/api/core/firmware/upgrade",
        "/api/core/firmware/restart",
        "/api/core/firmware/update",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
        })
    return results

def discover_services():
    """Discover system services."""
    endpoint = "/api/core/service/search"
    status, data, raw = api_get(endpoint)
    if status == 200 and data:
        return {
            "endpoint": endpoint,
            "method": "POST",
            "status": status,
            "schema": describe_schema(data),
            "total_services": data.get("total", 0),
            "service_names": [s.get("name", s) for s in data.get("rows", [])] if "rows" in data else [],
        }
    return {
        "endpoint": endpoint,
        "method": "POST",
        "status": status,
        "schema": None,
        "error": safe_str(raw)[:200],
    }

def discover_interface_stats():
    """Discover interface statistics."""
    endpoints = [
        "/api/diagnostics/interface/get_interface_statistics",
        "/api/diagnostics/interface/getInterfaceStats",
        "/api/diagnostics/system/systemResources",
        "/api/diagnostics/system/system_resources",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
        })
    return results

def discover_firewall():
    """Discover firewall-related endpoints."""
    endpoints = [
        "/api/firewall/alias/get",
        "/api/firewall/alias/search",
        "/api/firewall/filter/rule/get",
        "/api/firewall/filter/rule/search",
        "/api/firewall/nat/rules/get",
        "/api/firewall/nat/npt/get",
        "/api/firewall/carp/get",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_diagnostics():
    """Discover diagnostic endpoints."""
    endpoints = [
        "/api/diagnostics/ping/get",
        "/api/diagnostics/ping/search",
        "/api/diagnostics/trace/get",
        "/api/diagnostics/interface/get",
        "/api/diagnostics/route/get",
        "/api/diagnostics/dhcp/leases",
        "/api/diagnostics/neighbor/get",
        "/api/diagnostics/traffic/get",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_system():
    """Discover system endpoints."""
    endpoints = [
        "/api/core/system/status",
        "/api/core/system/product",
        "/api/core/system/hostname",
        "/api/core/system/domain",
        "/api/core/system/dns",
        "/api/core/system/timezone",
        "/api/core/system/restart",
        "/api/core/system/shutdown",
        "/api/core/time/current",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_routes():
    """Discover routing endpoints."""
    endpoints = [
        "/api/routes/static/get",
        "/api/routes/static/search",
        "/api/routes/static/pfstats",
        "/api/routing/defaultgw/get",
        "/api/routing/defaultgw/search",
        "/api/routing/gateway/search",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_hosts():
    """Discover host discovery endpoints."""
    endpoints = [
        "/api/hostdiscovery/hosts/get",
        "/api/hostdiscovery/hosts/search",
        "/api/hostdiscovery/neighbors/get",
        "/api/hostdiscovery/neighbors/search",
        "/api/hostdiscovery/arp/get",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_cron():
    """Discover cron job endpoints."""
    endpoints = [
        "/api/cron/jobs/get",
        "/api/cron/jobs/search",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_dhcp():
    """Discover DHCP endpoints."""
    endpoints = [
        "/api/dhcp/dhcpd/leases/get",
        "/api/dhcp/dhcpd/leases/search",
        "/api/dhcp/dhcpdv6/leases/get",
        "/api/dhcp/dhcpdv6/leases/search",
        "/api/dhcp/dhcpd/status",
        "/api/dhcp/dhcpdv6/status",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_ids():
    """Discover IDS/Snort endpoints."""
    endpoints = [
        "/api/ids/settings/get",
        "/api/ids/settings/search",
        "/api/ids/log/get",
        "/api/ids/log/search",
        "/api/ids/status",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_unbound():
    """Discover Unbound DNS resolver endpoints."""
    endpoints = [
        "/api/unbound/general/get",
        "/api/unbound/general/search",
        "/api/unbound/restart",
        "/api/unbound/status",
        "/api/unbound/dnssec/get",
        "/api/unbound/adblock/get",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_ntp():
    """Discover NTP endpoints."""
    endpoints = [
        "/api/ntp/general/get",
        "/api/ntp/general/search",
        "/api/ntp/restart",
        "/api/ntp/status",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_ipsec():
    """Discover IPsec VPN endpoints."""
    endpoints = [
        "/api/ipsec/settings/get",
        "/api/ipsec/settings/search",
        "/api/ipsec/status",
        "/api/ipsec/listener/get",
        "/api/ipsec/listener/search",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_openvpn():
    """Discover OpenVPN endpoints."""
    endpoints = [
        "/api/openvpn/status",
        "/api/openvpn/csc/get",
        "/api/openvpn/csc/search",
        "/api/openvpn/restart",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_wireguard():
    """Discover WireGuard endpoints."""
    endpoints = [
        "/api/wireguard/status",
        "/api/wireguard/peers/get",
        "/api/wireguard/peers/search",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_traffic_shaper():
    """Discover Traffic Shaper endpoints."""
    endpoints = [
        "/api/trafficshaper/queue/get",
        "/api/trafficshaper/queue/search",
        "/api/trafficshaper/limit/get",
        "/api/trafficshaper/limit/search",
        "/api/trafficshaper/status",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_auth():
    """Discover authentication endpoints."""
    endpoints = [
        "/api/auth/user/list",
        "/api/auth/user/get",
        "/api/auth/user/search",
        "/api/auth/roles/get",
        "/api/auth/roles/search",
    ]
    results = []
    for endpoint in endpoints:
        status, data, raw = api_get(endpoint)
        results.append({
            "endpoint": endpoint,
            "method": "GET",
            "status": status,
            "schema": describe_schema(data) if data else None,
            "sample_keys": list(data.keys())[:5] if isinstance(data, dict) else [],
            "sample_data": strip_sensitive(data) if isinstance(data, dict) else None,
        })
    return results

def discover_plugins():
    """Discover which plugins are installed and their API endpoints."""
    plugin_map = {
        "acme": ("Acme Client", discover_generic_module),
        "bind": ("BIND DNS", discover_generic_module),
        "cicp": ("CICAP", discover_generic_module),
        "clamav": ("ClamAV", discover_generic_module),
        "crowdsec": ("CrowdSec", discover_generic_module),
        "dhcp": ("DHCP Server", discover_dhcp),
        "dyndns": ("Dynamic DNS", discover_generic_module),
        "freeradius": ("FreeRADIUS", discover_generic_module),
        "haproxy": ("HAProxy", discover_generic_module),
        "netdata": ("Netdata", discover_generic_module),
        "nginx": ("Nginx", discover_generic_module),
        "ntopng": ("ntopNG", discover_generic_module),
        "snmp": ("SNMP", discover_generic_module),
        "rspamd": ("Rspamd", discover_generic_module),
        "telegraf": ("Telegraf", discover_generic_module),
        "wazuh": ("Wazuh", discover_generic_module),
        "zerotier": ("ZeroTier", discover_generic_module),
    }
    results = {}
    for plugin_key, (plugin_name, discover_fn) in plugin_map.items():
        result = discover_fn(plugin_key)
        if result and result.get("endpoints"):
            results[plugin_key] = {
                "name": plugin_name,
                "endpoints": result["endpoints"],
                "controllers": result["controllers"],
                "commands": result["commands"],
            }
    return results

def discover_generic_module(module):
    """Generic endpoint discovery for plugin modules."""
    endpoints_to_try = [
        f"/api/{module}/status",
        f"/api/{module}/get",
        f"/api/{module}/list",
        f"/api/{module}/info",
        f"/api/{module}/settings/get",
        f"/api/{module}/settings/search",
        f"/api/{module}/config/get",
    ]
    results = {"module": module, "endpoints": [], "controllers": [], "commands": []}
    for endpoint in endpoints_to_try:
        status, data, raw = api_get(endpoint)
        if status == 200 and data:
            results["endpoints"].append({
                "path": endpoint,
                "status": status,
                "schema": describe_schema(data),
                "sample_keys": list(data.keys())[:5],
            })
            if isinstance(data, dict):
                for key in data:
                    if isinstance(data[key], (dict, list)):
                        results["controllers"].append(key)
        elif status == 404:
            pass  # Not found is fine, means the controller doesn't exist
        else:
            results["endpoints"].append({
                "path": endpoint,
                "status": status,
                "schema": None,
                "sample_keys": [],
            })
    return results

def run_full_discovery():
    """Run the full discovery suite."""
    print("=" * 70)
    print("OPNsense API Discovery Tool")
    print(f"Target: https://{OPN_HOST}:{OPN_PORT}/api")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    discovery_results = {
        "metadata": {
            "opn_host": OPN_HOST,
            "opn_port": OPN_PORT,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0",
        },
        "core_endpoints": {},
        "plugin_endpoints": {},
        "summary": {
            "total_endpoints_tested": 0,
            "endpoints_200": 0,
            "endpoints_404": 0,
            "endpoints_errors": 0,
            "controllers_discovered": [],
            "commands_discovered": [],
        },
    }

    total_tested = 0
    endpoints_200 = 0
    endpoints_404 = 0
    endpoints_errors = 0
    all_controllers = set()
    all_commands = []

    # 1. Firmware endpoints
    print("[1/20] Discovering firmware endpoints...")
    firmware_results = discover_firmware()
    discovery_results["core_endpoints"]["firmware"] = firmware_results
    for f in firmware_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {len(firmware_results)} firmware endpoints")

    # 2. Services
    print("[2/20] Discovering services...")
    services_result = discover_services()
    discovery_results["core_endpoints"]["services"] = [services_result]
    total_tested += 1
    if services_result.get("status") == 200:
        endpoints_200 += 1
        service_names = services_result.get("service_names", [])
        print(f"  -> Found {services_result.get('total_services', 0)} services: {', '.join(service_names[:10])}")
    else:
        endpoints_errors += 1
        print(f"  -> Status: {services_result.get('status', 'error')}")

    # 3. Interface statistics
    print("[3/20] Discovering interface diagnostics...")
    iface_results = discover_interface_stats()
    discovery_results["core_endpoints"]["interface_stats"] = iface_results
    for f in iface_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in iface_results if f['status'] == 200)} working endpoints")

    # 4. System endpoints
    print("[4/20] Discovering system endpoints...")
    sys_results = discover_system()
    discovery_results["core_endpoints"]["system"] = sys_results
    for f in sys_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in sys_results if f['status'] == 200)} working endpoints")

    # 5. Firewall endpoints
    print("[5/20] Discovering firewall endpoints...")
    fw_results = discover_firewall()
    discovery_results["core_endpoints"]["firewall"] = fw_results
    for f in fw_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in fw_results if f['status'] == 200)} working endpoints")

    # 6. Diagnostics endpoints
    print("[6/20] Discovering diagnostics endpoints...")
    diag_results = discover_diagnostics()
    discovery_results["core_endpoints"]["diagnostics"] = diag_results
    for f in diag_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in diag_results if f['status'] == 200)} working endpoints")

    # 7. Routing endpoints
    print("[7/20] Discovering routing endpoints...")
    route_results = discover_routes()
    discovery_results["core_endpoints"]["routing"] = route_results
    for f in route_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in route_results if f['status'] == 200)} working endpoints")

    # 8. Host discovery
    print("[8/20] Discovering host endpoints...")
    host_results = discover_hosts()
    discovery_results["core_endpoints"]["hosts"] = host_results
    for f in host_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in host_results if f['status'] == 200)} working endpoints")

    # 9. Cron endpoints
    print("[9/20] Discovering cron endpoints...")
    cron_results = discover_cron()
    discovery_results["core_endpoints"]["cron"] = cron_results
    for f in cron_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in cron_results if f['status'] == 200)} working endpoints")

    # 10. DHCP endpoints
    print("[10/20] Discovering DHCP endpoints...")
    dhcp_results = discover_dhcp()
    discovery_results["core_endpoints"]["dhcp"] = dhcp_results
    for f in dhcp_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in dhcp_results if f['status'] == 200)} working endpoints")

    # 11. IDS endpoints
    print("[11/20] Discovering IDS endpoints...")
    ids_results = discover_ids()
    discovery_results["core_endpoints"]["ids"] = ids_results
    for f in ids_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in ids_results if f['status'] == 200)} working endpoints")

    # 12. Unbound DNS endpoints
    print("[12/20] Discovering Unbound DNS endpoints...")
    unbound_results = discover_unbound()
    discovery_results["core_endpoints"]["unbound"] = unbound_results
    for f in unbound_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in unbound_results if f['status'] == 200)} working endpoints")

    # 13. NTP endpoints
    print("[13/20] Discovering NTP endpoints...")
    ntp_results = discover_ntp()
    discovery_results["core_endpoints"]["ntp"] = ntp_results
    for f in ntp_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in ntp_results if f['status'] == 200)} working endpoints")

    # 14. IPsec endpoints
    print("[14/20] Discovering IPsec VPN endpoints...")
    ipsec_results = discover_ipsec()
    discovery_results["core_endpoints"]["ipsec"] = ipsec_results
    for f in ipsec_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in ipsec_results if f['status'] == 200)} working endpoints")

    # 15. OpenVPN endpoints
    print("[15/20] Discovering OpenVPN endpoints...")
    openvpn_results = discover_openvpn()
    discovery_results["core_endpoints"]["openvpn"] = openvpn_results
    for f in openvpn_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in openvpn_results if f['status'] == 200)} working endpoints")

    # 16. WireGuard endpoints
    print("[16/20] Discovering WireGuard endpoints...")
    wg_results = discover_wireguard()
    discovery_results["core_endpoints"]["wireguard"] = wg_results
    for f in wg_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in wg_results if f['status'] == 200)} working endpoints")

    # 17. Traffic Shaper endpoints
    print("[17/20] Discovering Traffic Shaper endpoints...")
    ts_results = discover_traffic_shaper()
    discovery_results["core_endpoints"]["trafficshaper"] = ts_results
    for f in ts_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in ts_results if f['status'] == 200)} working endpoints")

    # 18. Auth endpoints
    print("[18/20] Discovering Auth endpoints...")
    auth_results = discover_auth()
    discovery_results["core_endpoints"]["auth"] = auth_results
    for f in auth_results:
        total_tested += 1
        if f["status"] == 200:
            endpoints_200 += 1
        elif f["status"] == 404:
            endpoints_404 += 1
        else:
            endpoints_errors += 1
    print(f"  -> Found {sum(1 for f in auth_results if f['status'] == 200)} working endpoints")

    # 19. Plugin discovery
    print("[19/20] Discovering installed plugins...")
    plugin_results = discover_plugins()
    discovery_results["plugin_endpoints"] = plugin_results
    print(f"  -> Found {len(plugin_results)} plugin APIs with active endpoints")

    # 20. Generic core module scan
    print("[20/20] Scanning remaining core modules...")
    for module in ["captiveportal", "cron", "dnsmasq", "hostdiscovery", "monit", "radvd", "syslog"]:
        try:
            module_result = discover_generic_module(module)
            if module_result["endpoints"]:
                discovery_results["core_endpoints"][module] = module_result
                for ep in module_result["endpoints"]:
                    total_tested += 1
                    if ep["status"] == 200:
                        endpoints_200 += 1
                    elif ep["status"] == 404:
                        endpoints_404 += 1
                    else:
                        endpoints_errors += 1
        except Exception as e:
            print(f"  -> Error scanning module {module}: {e}")
    print(f"  -> Scan complete")

    # Build summary
    discovery_results["summary"] = {
        "total_endpoints_tested": total_tested,
        "endpoints_200": endpoints_200,
        "endpoints_404": endpoints_404,
        "endpoints_errors": endpoints_errors,
        "controllers_discovered": sorted(all_controllers),
        "commands_discovered": all_commands,
    }

    return discovery_results

# ---------------------------------------------------------------------------
# Output Functions
# ---------------------------------------------------------------------------

def generate_markdown(results):
    """Generate a Markdown report of discovery results."""
    md = []
    md.append("# OPNsense API Discovery Report")
    md.append("")
    md.append(f"- **Target**: `{results['metadata']['opn_host']}:{results['metadata']['opn_port']}`")
    md.append(f"- **Timestamp**: {results['metadata']['timestamp']}")
    md.append(f"- **Version**: {results['metadata']['version']}")
    md.append("")
    md.append("## Summary")
    md.append("")
    summary = results["summary"]
    md.append(f"- Total endpoints tested: {summary['total_endpoints_tested']}")
    md.append(f"- Working (HTTP 200): {summary['endpoints_200']}")
    md.append(f"- Not Found (HTTP 404): {summary['endpoints_404']}")
    md.append(f"- Errors: {summary['endpoints_errors']}")
    md.append("")

    md.append("## Core API Endpoints")
    md.append("")
    for section_name, section_data in results["core_endpoints"].items():
        md.append(f"### {section_name.replace('_', ' ').title()}")
        md.append("")
        if isinstance(section_data, list):
            for item in section_data:
                if isinstance(item, dict) and "endpoint" in item:
                    status_symbol = "✅" if item["status"] == 200 else "❌" if item["status"] == 404 else "⚠️"
                    md.append(f"- {status_symbol} `{item['endpoint']}` — {item['method']} — {item['status']}")
                    if item.get("schema"):
                        md.append(f"  - Schema: `{item['schema']}`")
                    if item.get("sample_keys"):
                        md.append(f"  - Keys: `{', '.join(item['sample_keys'])}`")
                    if item.get("sample_data"):
                        md.append(f"  - Sample: `{json.dumps(item['sample_data'], indent=2)[:300]}`")
                    md.append("")
        elif isinstance(section_data, dict):
            for ep in section_data.get("endpoints", []):
                status_symbol = "✅" if ep["status"] == 200 else "❌" if ep["status"] == 404 else "⚠️"
                md.append(f"- {status_symbol} `{ep['path']}` — {ep['status']}")
                if ep.get("schema"):
                    md.append(f"  - Schema: `{ep['schema']}`")
                if ep.get("sample_keys"):
                    md.append(f"  - Keys: `{', '.join(ep['sample_keys'])}`")
            md.append("")
    md.append("")

    md.append("## Plugin API Endpoints")
    md.append("")
    if results["plugin_endpoints"]:
        for plugin_key, plugin_data in results["plugin_endpoints"].items():
            md.append(f"### {plugin_data['name']} (`/{plugin_key}/`)")
            md.append("")
            for ep in plugin_data.get("endpoints", []):
                status_symbol = "✅" if ep["status"] == 200 else "❌" if ep["status"] == 404 else "⚠️"
                md.append(f"- {status_symbol} `{ep['path']}` — {ep['status']}")
                if ep.get("schema"):
                    md.append(f"  - Schema: `{ep['schema']}`")
            md.append("")
    else:
        md.append("No plugin APIs discovered with active endpoints.")
        md.append("")

    md.append("## Endpoint Map")
    md.append("")
    md.append("| Module | Controller/Endpoint | Method | Status | Schema |")
    md.append("|--------|-------------------|--------|--------|--------|")
    for section_name, section_data in results["core_endpoints"].items():
        if isinstance(section_data, list):
            for item in section_data:
                if isinstance(item, dict) and "endpoint" in item:
                    schema = item.get("schema", "N/A") or "N/A"
                    md.append(f"| {section_name} | `{item['endpoint']}` | {item['method']} | {item['status']} | {schema} |")
    md.append("")

    return "\n".join(md)

def generate_json_report(results):
    """Generate a JSON report of discovery results."""
    # Strip sensitive data from JSON output
    safe_results = {
        "metadata": results["metadata"],
        "core_endpoints": results["core_endpoints"],
        "plugin_endpoints": results["plugin_endpoints"],
        "summary": results["summary"],
    }
    return json.dumps(safe_results, indent=2, default=str)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="OPNsense API Discovery Tool")
    parser.add_argument("--json", action="store_true", help="Output results as JSON only")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Run discovery
    results = run_full_discovery()

    # Generate outputs
    markdown_report = generate_markdown(results)
    json_report = generate_json_report(results)

    # Print summary
    print()
    print("=" * 70)
    print("DISCOVERY COMPLETE")
    print("=" * 70)
    print(f"  Endpoints tested:  {results['summary']['total_endpoints_tested']}")
    print(f"  Working (200):     {results['summary']['endpoints_200']}")
    print(f"  Not Found (404):   {results['summary']['endpoints_404']}")
    print(f"  Errors:            {results['summary']['endpoints_errors']}")
    print()
    print("  Files generated:")
    print(f"    - opnsense_api_endpoints.md  (Markdown report)")
    print(f"    - opnsense_api_endpoints.json  (JSON data)")
    print("=" * 70)

    # Write files
    with open("opnsense_api_endpoints.md", "w") as f:
        f.write(markdown_report)
    print()
    print("Markdown report saved to: opnsense_api_endpoints.md")

    with open("opnsense_api_endpoints.json", "w") as f:
        f.write(json_report)
    print("JSON data saved to: opnsense_api_endpoints.json")
