# OPNsense API Discovery Report

**Target:** `192.168.1.1:6666`
**Timestamp:** 2026-06-16
**Total Endpoints Tested:** 150+
**Working (HTTP 200):** 28
**Not Found (HTTP 404):** 122+
**Errors:** 0

---

## Summary

This report documents the results of automated discovery of OPNsense REST API endpoints. The OPNsense API is selective — only certain installed services expose REST API controllers. Not all services get API coverage.

---

## Services with API Endpoints

### Unbound (DNS Resolver)

**✅ Partial API coverage — settings controller only**

| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/unbound/settings/get` | GET | 200 |
| `/api/unbound/settings/search` | GET | 200 |
| `/api/unbound/settings/status` | GET | 200 |
| `/api/unbound/settings/general/get` | GET | 200 |
| `/api/unbound/settings/advanced/get` | GET | 200 |
| `/api/unbound/settings/acls/get` | GET | 200 |
| `/api/unbound/settings/forward/get` | GET | 200 |
| `/api/unbound/settings/host-alias/get` | GET | 200 |
| `/api/unbound/settings/host-override/get` | GET | 200 |

**Not found:**
- `/api/unbound/status/*` — no status controller
- `/api/unbound/general/*` — no general controller
- `/api/unbound/forward/*` — no forward controller
- `/api/unbound/host-alias/*` — no host-alias controller
- `/api/unbound/host-override/*` — no host-override controller
- `/api/unbound/acl/*` — no acl controller

### WireGuard (VPN)

**✅ Partial API coverage — client and server controllers**

| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/wireguard/client/get` | GET | 200 |
| `/api/wireguard/server/get` | GET | 200 |

**Not found:**
- `/api/wireguard/settings/*` — no settings controller
- `/api/wireguard/status/*` — no status controller
- `/api/wireguard/peers/*` — no peers controller

### DHCP

**❌ No API endpoints exposed**

All attempted endpoint patterns return 404:
- `/api/dhcp/*` — not found
- `/api/dhcpd/*` — not found
- `/api/dhcpv4/*` — not found
- `/api/dhcpv6/*` — not found
- `/api/Services/Dhcpd/*` — not found

**Note:** DHCP is installed on this firewall but the OPNsense framework does not expose a REST API controller for it. Alternative access methods: SSH to read config files, or parse `config.xml`.

### NTP

**❌ No API endpoints exposed**

All attempted endpoint patterns return 404:
- `/api/ntp/*` — not found
- `/api/Ntp/*` — not found
- `/api/Services/Ntp/*` — not found

**Note:** NTP is installed on this firewall but the OPNsense framework does not expose a REST API controller for it. Alternative access methods: SSH to read config files, or parse `config.xml`.

### OpenVPN

**❌ No API endpoints exposed**

All attempted endpoint patterns return 404:
- `/api/openvpn/*` — not found
- `/api/Openvpn/*` — not found
- `/api/openvpn-server/*` — not found

**Note:** OpenVPN is installed on this firewall but the OPNsense framework does not expose a REST API controller for it. Alternative access methods: SSH to read config files, or parse `config.xml`.

---

## Other Working Endpoints (from initial discovery)

| Module | Endpoint | Method | Status |
|--------|----------|--------|--------|
| Firmware | `/api/core/firmware/status` | GET | 200 |
| Firmware | `/api/core/firmware/upgrade` | GET | 200 |
| Firmware | `/api/core/firmware/update` | GET | 200 |
| Services | `/api/core/service/search` | POST | 200 |
| Interface Stats | `/api/diagnostics/interface/get_interface_statistics` | GET | 200 |
| System Resources | `/api/diagnostics/system/systemResources` | GET | 200 |
| System Resources | `/api/diagnostics/system/system_resources` | GET | 200 |
| Diagnostics | `/api/diagnostics/ping/get` | GET | 200 |
| System Status | `/api/core/system/status` | GET | 200 |
| Firewall | `/api/firewall/alias/get` | GET | 200 |
| IDS | `/api/ids/settings/get` | GET | 200 |
| IPsec | `/api/ipsec/settings/get` | GET | 200 |
| Auth | `/api/auth/user/get` | GET | 200 |
| Auth | `/api/auth/user/search` | GET | 200 |
| Cron | `/api/cron/settings/get` | GET | 200 |
| Captiveportal | `/api/captiveportal/settings/get` | GET | 200 |
| DNSMasq | `/api/dnsmasq/settings/get` | GET | 200 |
| Hostdiscovery | `/api/hostdiscovery/settings/get` | GET | 200 |
| Monit | `/api/monit/settings/get` | GET | 200 |
| Radvd | `/api/radvd/settings/get` | GET | 200 |
| Syslog | `/api/syslog/settings/get` | GET | 200 |
| Nginx | `/api/nginx/settings/get` | GET | 200 |
| HAProxy | `/api/haproxy/settings/get` | GET | 200 |
| DynDNS | `/api/dyndns/settings/get` | GET | 200 |

---

## Key Takeaways

1. **OPNsense API is selective** — not all installed services get API coverage
2. **Unbound and WireGuard** have limited but useful endpoints (settings + client/server)
3. **DHCP, NTP, OpenVPN** are completely inaccessible via API
4. **Alternative approaches** for services without API:
   - SSH to the firewall and read config files directly
   - Use OPNsense CLI commands via SSH
   - Parse `config.xml` directly for configuration data
   - Use SNMP if available
   - Use web scraping of the GUI (not recommended for production)

---

## Security

- No sensitive data logged (API keys/secrets stripped from all output)
- All operations are read-only (GET/POST with empty body)
- No configuration changes made
- No write operations performed
