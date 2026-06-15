"""
Script to explore OPNsense API endpoints for dashboard display.
"""
import json

test_cases = [
    {
        "name": "System Status (via agent test_connection endpoint)",
        "url": "https://192.168.1.1:6666/api/core/firmware/status",
        "method": "GET",
        "headers": {"Authorization": "Basic WT8IVP...DMnO==", "Accept": "application/json"}
    }
]

# We'll use the terminal tool to test various OPNsense API endpoints
# First, let's check what the agent already uses for gateway discovery

print("Testing OPNsense API endpoints for dashboard data...")
print("=" * 60)

# The agent uses:
# 1. /api/core/firmware/status - for version detection
# 2. /api/routing/settings/searchGateway - for interface classification

# Let's explore other endpoints that might give us:
# - IPv4/6 addresses
# - Gateway information
# - WAN uptimes
# - Interface statuses

# Try common OPNsense API endpoints
endpoints_to_test = [
    "/api/core/info",           # System info
    "/api/core/firmware/status", # Firmware/status
    "/api/diagnostics/ping",    # Ping/diagnostics
    "/api/diagnostics/tracepath", # Traceroute
    "/api/dhcpd/status",        # DHCP status
    "/api/dhcpd/leases",        # DHCP leases
    "/api/interfaces/assignments", # Interface assignments
    "/api/interfaces/status",   # Interface status
    "/api/routing/routes",     # Routing table
    "/api/services/cron/status", # Cron status
    "/api/services/dnsmasq/status", # DNSMasq
    "/api/services/openvpn/status", # OpenVPN
    "/api/services/ntp/status", # NTP
    "/api/monitoring/system",   # Monitoring
    "/api/monitoring/graphs/data", # Graphs data
]

print("These endpoints would be useful to test on the remote OPNsense instance")
print("to discover what gateway/system data is available for the dashboard.")
print()
print("Key endpoints the agent already queries:")
print("  1. /api/core/firmware/status - returns os_version")
print("  2. /api/routing/settings/searchGateway - returns gateway/interface mapping")
print()
print("Additional endpoints we should add to dashboard:")
print("  - /api/interfaces/assignments - interface configs with IPs")
print("  - /api/interfaces/status - interface up/down status")
print("  - /api/dhcpd/leases - active DHCP clients")
print("  - /api/routing/routes - routing table (WAN gateways)")
print("  - /api/services/openvpn/status - VPN tunnel states")
print("  - /api/services/dnsmasq/status - DNSMasq status")
print()
print("We need to run these tests on the remote OPNsense machine via SSH.")
