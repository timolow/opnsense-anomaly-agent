# OPNsense Syslog Audit — What's Sent vs. What's Captured

## OPNsense Syslog Configuration

OPNsense sends syslog via UDP to configured remote log hosts. The following log sources can be configured in **System > Settings > Log Settings > Log Targets**:

### Log Sources Available in OPNsense

| Source | Process/Tag | Description | Currently Captured |
|--------|-------------|-------------|-------------------|
| **Filterlog** | `filterlog` | Firewall rules — all ALLOW and BLOCK events | ✅ Fully parsed |
| **ZenArmor** | `zenarmor` / `zen_guard` | ZenArmor security gateway rules | ⚠️ Parsed, no classification |
| **IDS/Snort** | `ids` / `suricata` / `snort` | Intrusion detection system alerts | ⚠️ Parsed, no tracking |
| **Unbound** | `unbound` / `dns` | DNS server logs | ✅ Via system log classifier |
| **DHCPD** | `dhcpd` / `dhcpleases` | DHCP lease changes | ✅ Via system log classifier |
| **NTPD** | `ntpd` | NTP sync events | ✅ Via system log classifier |
| **OpenVPN** | `openvpn` | VPN tunnel events | ✅ Via system log classifier |
| **WireGuard** | `wg` | VPN tunnel events | ✅ Via system log classifier |
| **System** | `system` / `kernel` | General system events | ✅ Via system log classifier |
| **Cron** | `cron` | Scheduled task events | ✅ Via system log classifier |
| **SSH** | `sshd` | SSH login events | ✅ Via system log classifier |
| **Nginx** | `nginx` | WebUI access logs | ⚠️ Parsed, no analysis |

### Syslog Configuration Location

On the OPNsense firewall, configure syslog output:
- **System > Settings > Log Settings > Log Targets** — Add remote target
- **System > Settings > Log Settings > Remote Log Host** — Enter agent IP and port 1514
- **System > Settings > Log Settings > Log Level** — Select sources to send

### What OPNsense Actually Sends

The syslog listener on port 1514 receives raw syslog lines in this format:
```
<priority>timestamp hostname process[pid]: message
```

#### Filterlog Format
```
<134>Jun 17 10:00:00 opnsense filterlog[12345]: 17,0,,pflog0,match,pass,in,4,0x00,4605,0,DF,6,tcp,0,1.2.3.4,5.6.7.8,12345,443,SYN,0,0,0,0
```
CSV: flag, empty, empty, ruid, interface, match, action, direction, ip_version, 0x0, empty, length, 0, 0, flags, proto_num, proto_name, window, src_ip, dst_ip, sport, dport, tcp_options...

#### ZenArmor Format
```
<134>Jun 17 10:00:00 opnsense zenarmor[1234]: blocked from 1.2.3.4 port 80 by policy "Block External"
<134>Jun 17 10:00:00 opnsense zenarmor[1234]: allowed from 1.2.3.4 port 443 by policy "Allow HTTPS"
```

#### IDS/Snort Format
```
<134>Jun 17 10:00:00 opnsense ids.snort.rule[1234]: [1:2001219:20] ET SCAN Potential SSH Scan 1.2.3.4:5678 -> 5.6.7.8:22
```

## Current State Assessment

### ✅ Fully Working
1. **Filterlog parsing** — Full CSV parsing, all fields extracted
2. **Firewall rule classification** — `rule_classifier.py` classifies GOOD/SUSPICIOUS/ABUSIVE
3. **Attack detection** — Port scans, brute force, SYN floods, probes all work
4. **Service monitoring** — DHCP, Unbound, NTP, OpenVPN, WireGuard
5. **Statistical baselines** — Per-IP/port baselines for all events
6. **Reverse DNS** — IP-to-hostname resolution for all log types
7. **Geo lookup** — IP geolocation for all events
8. **Web dashboard** — All event types displayed (merged, not separated)

### ⚠️ Partially Working (Parsed but not classified)
1. **ZenArmor events** — IPs, ports, actions extracted but:
   - No ZenArmor rule/policy classification
   - No policy change detection
   - No ZenArmor-specific anomaly detection (block rate spikes, new policies)
   - Not separated from filterlog in dashboard

2. **IDS events** — SRC/DST IPs, ports, signatures extracted but:
   - No signature frequency tracking
   - No new signature detection
   - No anomaly detection (signature spike, unusual targets)
   - Not separated from filterlog in dashboard

3. **Nginx events** — Client IPs, requests, status codes extracted but:
   - No web access pattern analysis
   - No brute force detection on web endpoints

### ❌ Not Working
1. **ZenArmor/IDS alerting** — No Discord/Slack alerts for these
2. **ZenArmor/IDS dashboard tabs** — No dedicated tabs
3. **API endpoints** — No ZenArmor or IDS-specific API endpoints
4. **ML learning** — ZenArmor and IDS events don't contribute to the self-learning engine

## Recommendations

### Phase 1: Classification & Tracking
- **ZenArmor Rule Classifier** — Track policy usage, detect new/changed policies, classify by behavior (like `rule_classifier.py`)
- **IDS Signature Analyzer** — Track signature frequency, detect anomalies (spikes, new signatures, unusual targets)

### Phase 2: Alerting
- Discord alerts for: new ZenArmor policies, policy changes, IDS signature spikes, new IDS signatures
- Dashboard tabs for ZenArmor and IDS events

### Phase 3: ML Integration
- Include ZenArmor and IDS events in the self-learning engine
- Statistical baselines per ZenArmor policy and IDS signature

## Implementation Plan

See `zenarmor_classifier.py` and `ids_signature_analyzer.py` for implementation.
