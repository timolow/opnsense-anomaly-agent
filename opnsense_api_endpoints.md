# OPNsense API Discovery Report

- **Target**: `192.168.1.1:6666`
- **Timestamp**: 2026-06-16T08:54:44.517040
- **Version**: 1.0

## Summary

- Total endpoints tested: 96
- Working (HTTP 200): 21
- Not Found (HTTP 404): 75
- Errors: 0

## Core API Endpoints

### Firmware

- ✅ `/api/core/firmware/status` — GET — 200
  - Schema: `object{api_version:string("2"), connection:string("ok"), downgrade_packages:array[], ... +22 more}`
  - Keys: `api_version, connection, downgrade_packages, download_size, last_check`

- ✅ `/api/core/firmware/upgrade` — GET — 200
  - Schema: `object{status:string("failure")}`
  - Keys: `status`

- ❌ `/api/core/firmware/restart` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`

- ✅ `/api/core/firmware/update` — GET — 200
  - Schema: `object{status:string("failure")}`
  - Keys: `status`

### Services

- ✅ `/api/core/service/search` — POST — 200
  - Schema: `object{total:number(44), rowCount:number(44), current:number(1), rows:array[44] containing <dict>[max_depth_reached]}`

### Interface Stats

- ✅ `/api/diagnostics/interface/get_interface_statistics` — GET — 200
  - Schema: `object{statistics:object{[Backup_Internet] (igb0) / 3c:ec:ef:43:18:6c:<dict>[max_depth_reached], [Backup_Internet] (igb0) / fe80::3eec:efff:fe43:186c%igb0:<dict>[max_depth_reached], [Backup_Internet] (igb0) / 70.121.112.102:<dict>[max_depth_reached], ... +74 more}}`
  - Keys: `statistics`

- ❌ `/api/diagnostics/interface/getInterfaceStats` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`

- ✅ `/api/diagnostics/system/systemResources` — GET — 200
  - Schema: `object{memory:object{total:<str>[max_depth_reached], total_frmt:<str>[max_depth_reached], used:<int>[max_depth_reached], ... +4 more}}`
  - Keys: `memory`

- ✅ `/api/diagnostics/system/system_resources` — GET — 200
  - Schema: `object{memory:object{total:<str>[max_depth_reached], total_frmt:<str>[max_depth_reached], used:<int>[max_depth_reached], ... +4 more}}`
  - Keys: `memory`

### System

- ✅ `/api/core/system/status` — GET — 200
  - Schema: `object{metadata:object{system:<dict>[max_depth_reached], translations:<dict>[max_depth_reached], subsystems:<list>[max_depth_reached]}}`
  - Keys: `metadata`
  - Sample: `{
  "metadata": {
    "system": {
      "status": 2,
      "message": "No pending messages",
      "title": "System"
    },
    "translations": {
      "dialogTitle": "System Status",
      "dialogCloseButton": "Close"
    },
    "subsystems": []
  }
}`

- ❌ `/api/core/system/product` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/system/hostname` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/system/domain` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/system/dns` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/system/timezone` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/system/restart` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/system/shutdown` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/core/time/current` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Firewall

- ✅ `/api/firewall/alias/get` — GET — 200
  - Schema: `object{alias:object{geoip:<dict>[max_depth_reached], aliases:<dict>[max_depth_reached]}}`
  - Keys: `alias`
  - Sample: `{
  "alias": {
    "geoip": {
      "url": "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=o4FOELZ1hcj9&suffix=zip"
    },
    "aliases": {
      "alias": {
        "472d38cf-29fb-43e5-aaf2-2881dafe0f75": {
          "enabled": "1",
          "name": "HTT`

- ❌ `/api/firewall/alias/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/firewall/filter/rule/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/firewall/filter/rule/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/firewall/nat/rules/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/firewall/nat/npt/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/firewall/carp/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Diagnostics

- ✅ `/api/diagnostics/ping/get` — GET — 200
  - Schema: `object{ping:object{settings:<dict>[max_depth_reached]}}`
  - Keys: `ping`
  - Sample: `{
  "ping": {
    "settings": {
      "hostname": "",
      "fam": {
        "ip": {
          "value": "IPv4",
          "selected": 1
        },
        "ip6": {
          "value": "IPv6",
          "selected": 0
        }
      },
      "source_address": "",
      "packetsize": "",
      "disable`

- ❌ `/api/diagnostics/ping/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/diagnostics/trace/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/diagnostics/interface/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/diagnostics/route/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/diagnostics/dhcp/leases` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/diagnostics/neighbor/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/diagnostics/traffic/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Routing

- ❌ `/api/routes/static/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/routes/static/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/routes/static/pfstats` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/routing/defaultgw/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/routing/defaultgw/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/routing/gateway/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Hosts

- ❌ `/api/hostdiscovery/hosts/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/hostdiscovery/hosts/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/hostdiscovery/neighbors/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/hostdiscovery/neighbors/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/hostdiscovery/arp/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Cron

- ✅ `/api/cron/settings/get` — 200
  - Schema: `object{job:object{jobs:<dict>[max_depth_reached]}}`
  - Keys: `job`

### Dhcp

- ❌ `/api/dhcp/dhcpd/leases/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/dhcp/dhcpd/leases/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/dhcp/dhcpdv6/leases/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/dhcp/dhcpdv6/leases/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/dhcp/dhcpd/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/dhcp/dhcpdv6/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Ids

- ✅ `/api/ids/settings/get` — GET — 200
  - Schema: `object{ids:object{general:<dict>[max_depth_reached]}}`
  - Keys: `ids`
  - Sample: `{
  "ids": {
    "general": {
      "enabled": "1",
      "mode": {
        "pcap": {
          "value": "PCAP live mode (IDS)",
          "selected": 0
        },
        "netmap": {
          "value": "Netmap (IPS)",
          "selected": 1
        },
        "divert": {
          "value": "Divert`

- ❌ `/api/ids/settings/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ids/log/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ids/log/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ids/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Unbound

- ❌ `/api/unbound/general/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/unbound/general/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/unbound/restart` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/unbound/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/unbound/dnssec/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/unbound/adblock/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Ntp

- ❌ `/api/ntp/general/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ntp/general/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ntp/restart` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ntp/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Ipsec

- ✅ `/api/ipsec/settings/get` — GET — 200
  - Schema: `object{ipsec:object{general:<dict>[max_depth_reached], charon:<dict>[max_depth_reached]}}`
  - Keys: `ipsec`
  - Sample: `{
  "ipsec": {
    "general": {
      "enabled": "",
      "preferred_oldsa": "0",
      "disablevpnrules": "0",
      "passthrough_networks": {
        "": {
          "value": "",
          "selected": 1
        }
      },
      "user_source": {
        "Local Database": {
          "value": "Loca`

- ❌ `/api/ipsec/settings/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ipsec/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ipsec/listener/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/ipsec/listener/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Openvpn

- ❌ `/api/openvpn/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/openvpn/csc/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/openvpn/csc/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/openvpn/restart` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Wireguard

- ❌ `/api/wireguard/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/wireguard/peers/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/wireguard/peers/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Trafficshaper

- ❌ `/api/trafficshaper/queue/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/trafficshaper/queue/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/trafficshaper/limit/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/trafficshaper/limit/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/trafficshaper/status` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Auth

- ❌ `/api/auth/user/list` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ✅ `/api/auth/user/get` — GET — 200
  - Schema: `object{user:object{uid:<str>[max_depth_reached], name:<str>[max_depth_reached], disabled:<str>[max_depth_reached], ... +18 more}}`
  - Keys: `user`
  - Sample: `{
  "user": {
    "uid": "2003",
    "name": "",
    "disabled": "0",
    "scope": "user",
    "expires": "",
    "authorizedkeys": "",
    "otp_seed": "",
    "shell": {
      "": {
        "value": "Default (none for all but root)",
        "selected": 1
      },
      "/bin/csh": {
        "value`

- ✅ `/api/auth/user/search` — GET — 200
  - Schema: `object{rows:array[4]: [<dict>[max_depth_reached], <dict>[max_depth_reached], <dict>[max_depth_reached], <dict>[max_depth_reached]], rowCount:number(4), total:number(4), current:number(1)}`
  - Keys: `rows, rowCount, total, current`
  - Sample: `{
  "rows": [
    {
      "uuid": "1268c969-85a5-4377-bfd2-9ae4ab23c153",
      "uid": "0",
      "name": "root",
      "disabled": "0",
      "scope": "system",
      "expires": "",
      "authorizedkeys": "",
      "otp_seed": "",
      "shell": "",
      "password": "REDACTED",
      "%password":`

- ❌ `/api/auth/roles/get` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

- ❌ `/api/auth/roles/search` — GET — 404
  - Schema: `object{errorMessage:string("Endpoint not found")}`
  - Keys: `errorMessage`
  - Sample: `{
  "errorMessage": "Endpoint not found"
}`

### Captiveportal

- ✅ `/api/captiveportal/settings/get` — 200
  - Schema: `object{zone:object{zones:<dict>[max_depth_reached], templates:<dict>[max_depth_reached]}}`
  - Keys: `zone`

### Dnsmasq

- ✅ `/api/dnsmasq/settings/get` — 200
  - Schema: `object{dnsmasq:object{enable:<str>[max_depth_reached], regdhcp:<str>[max_depth_reached], regdhcpstatic:<str>[max_depth_reached], ... +27 more}}`
  - Keys: `dnsmasq`

### Hostdiscovery

- ✅ `/api/hostdiscovery/settings/get` — 200
  - Schema: `object{hostdiscovery:object{general:<dict>[max_depth_reached]}}`
  - Keys: `hostdiscovery`

### Monit

- ✅ `/api/monit/settings/get` — 200
  - Schema: `object{monit:object{general:<dict>[max_depth_reached], alert:<dict>[max_depth_reached], service:<dict>[max_depth_reached], test:<dict>[max_depth_reached]}}`
  - Keys: `monit`

### Radvd

- ✅ `/api/radvd/settings/get` — 200
  - Schema: `object{radvd:object{entries:<list>[max_depth_reached]}}`
  - Keys: `radvd`

### Syslog

- ✅ `/api/syslog/settings/get` — 200
  - Schema: `object{syslog:object{general:<dict>[max_depth_reached], destinations:<dict>[max_depth_reached]}}`
  - Keys: `syslog`


## Plugin API Endpoints

### Dynamic DNS (`/dyndns/`)

- ✅ `/api/dyndns/settings/get` — 200
  - Schema: `object{ddclient:object{general:<dict>[max_depth_reached]}}`

### HAProxy (`/haproxy/`)

- ✅ `/api/haproxy/settings/get` — 200
  - Schema: `object{haproxy:object{general:<dict>[max_depth_reached], frontends:<dict>[max_depth_reached], backends:<dict>[max_depth_reached], ... +14 more}}`

### Nginx (`/nginx/`)

- ✅ `/api/nginx/settings/get` — 200
  - Schema: `object{nginx:object{general:<dict>[max_depth_reached], webgui:<dict>[max_depth_reached], http:<dict>[max_depth_reached], ... +24 more}}`

## Endpoint Map

| Module | Controller/Endpoint | Method | Status | Schema |
|--------|-------------------|--------|--------|--------|
| firmware | `/api/core/firmware/status` | GET | 200 | object{api_version:string("2"), connection:string("ok"), downgrade_packages:array[], ... +22 more} |
| firmware | `/api/core/firmware/upgrade` | GET | 200 | object{status:string("failure")} |
| firmware | `/api/core/firmware/restart` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firmware | `/api/core/firmware/update` | GET | 200 | object{status:string("failure")} |
| services | `/api/core/service/search` | POST | 200 | object{total:number(44), rowCount:number(44), current:number(1), rows:array[44] containing <dict>[max_depth_reached]} |
| interface_stats | `/api/diagnostics/interface/get_interface_statistics` | GET | 200 | object{statistics:object{[Backup_Internet] (igb0) / 3c:ec:ef:43:18:6c:<dict>[max_depth_reached], [Backup_Internet] (igb0) / fe80::3eec:efff:fe43:186c%igb0:<dict>[max_depth_reached], [Backup_Internet] (igb0) / 70.121.112.102:<dict>[max_depth_reached], ... +74 more}} |
| interface_stats | `/api/diagnostics/interface/getInterfaceStats` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| interface_stats | `/api/diagnostics/system/systemResources` | GET | 200 | object{memory:object{total:<str>[max_depth_reached], total_frmt:<str>[max_depth_reached], used:<int>[max_depth_reached], ... +4 more}} |
| interface_stats | `/api/diagnostics/system/system_resources` | GET | 200 | object{memory:object{total:<str>[max_depth_reached], total_frmt:<str>[max_depth_reached], used:<int>[max_depth_reached], ... +4 more}} |
| system | `/api/core/system/status` | GET | 200 | object{metadata:object{system:<dict>[max_depth_reached], translations:<dict>[max_depth_reached], subsystems:<list>[max_depth_reached]}} |
| system | `/api/core/system/product` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/system/hostname` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/system/domain` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/system/dns` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/system/timezone` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/system/restart` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/system/shutdown` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| system | `/api/core/time/current` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firewall | `/api/firewall/alias/get` | GET | 200 | object{alias:object{geoip:<dict>[max_depth_reached], aliases:<dict>[max_depth_reached]}} |
| firewall | `/api/firewall/alias/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firewall | `/api/firewall/filter/rule/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firewall | `/api/firewall/filter/rule/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firewall | `/api/firewall/nat/rules/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firewall | `/api/firewall/nat/npt/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| firewall | `/api/firewall/carp/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/ping/get` | GET | 200 | object{ping:object{settings:<dict>[max_depth_reached]}} |
| diagnostics | `/api/diagnostics/ping/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/trace/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/interface/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/route/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/dhcp/leases` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/neighbor/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| diagnostics | `/api/diagnostics/traffic/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| routing | `/api/routes/static/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| routing | `/api/routes/static/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| routing | `/api/routes/static/pfstats` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| routing | `/api/routing/defaultgw/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| routing | `/api/routing/defaultgw/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| routing | `/api/routing/gateway/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| hosts | `/api/hostdiscovery/hosts/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| hosts | `/api/hostdiscovery/hosts/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| hosts | `/api/hostdiscovery/neighbors/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| hosts | `/api/hostdiscovery/neighbors/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| hosts | `/api/hostdiscovery/arp/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| dhcp | `/api/dhcp/dhcpd/leases/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| dhcp | `/api/dhcp/dhcpd/leases/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| dhcp | `/api/dhcp/dhcpdv6/leases/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| dhcp | `/api/dhcp/dhcpdv6/leases/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| dhcp | `/api/dhcp/dhcpd/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| dhcp | `/api/dhcp/dhcpdv6/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ids | `/api/ids/settings/get` | GET | 200 | object{ids:object{general:<dict>[max_depth_reached]}} |
| ids | `/api/ids/settings/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ids | `/api/ids/log/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ids | `/api/ids/log/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ids | `/api/ids/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| unbound | `/api/unbound/general/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| unbound | `/api/unbound/general/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| unbound | `/api/unbound/restart` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| unbound | `/api/unbound/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| unbound | `/api/unbound/dnssec/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| unbound | `/api/unbound/adblock/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ntp | `/api/ntp/general/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ntp | `/api/ntp/general/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ntp | `/api/ntp/restart` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ntp | `/api/ntp/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ipsec | `/api/ipsec/settings/get` | GET | 200 | object{ipsec:object{general:<dict>[max_depth_reached], charon:<dict>[max_depth_reached]}} |
| ipsec | `/api/ipsec/settings/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ipsec | `/api/ipsec/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ipsec | `/api/ipsec/listener/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| ipsec | `/api/ipsec/listener/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| openvpn | `/api/openvpn/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| openvpn | `/api/openvpn/csc/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| openvpn | `/api/openvpn/csc/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| openvpn | `/api/openvpn/restart` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| wireguard | `/api/wireguard/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| wireguard | `/api/wireguard/peers/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| wireguard | `/api/wireguard/peers/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| trafficshaper | `/api/trafficshaper/queue/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| trafficshaper | `/api/trafficshaper/queue/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| trafficshaper | `/api/trafficshaper/limit/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| trafficshaper | `/api/trafficshaper/limit/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| trafficshaper | `/api/trafficshaper/status` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| auth | `/api/auth/user/list` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| auth | `/api/auth/user/get` | GET | 200 | object{user:object{uid:<str>[max_depth_reached], name:<str>[max_depth_reached], disabled:<str>[max_depth_reached], ... +18 more}} |
| auth | `/api/auth/user/search` | GET | 200 | object{rows:array[4]: [<dict>[max_depth_reached], <dict>[max_depth_reached], <dict>[max_depth_reached], <dict>[max_depth_reached]], rowCount:number(4), total:number(4), current:number(1)} |
| auth | `/api/auth/roles/get` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
| auth | `/api/auth/roles/search` | GET | 404 | object{errorMessage:string("Endpoint not found")} |
