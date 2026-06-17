#!/usr/bin/env python3
"""
Adaptive log parser for OPNsense firewall data.
Auto-detects log types and extracts features.
Periodically re-analyzes raw data to discover new patterns.

Log types supported:
- filterlog: OPNsense filterlog (firewall rules)
- zenarmor: ZenArmor (security gateway)
- nginx: Nginx reverse proxy
- ids: IDS (suricata/snort)
- system: System/daemon messages (ntpd, rtsold, etc.)

The parser auto-discovers new log types and adapts its feature extraction
based on what it sees.
"""

import re
import json
import logging
import ipaddress
from datetime import datetime, timezone
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# ── Syslog header patterns ──────────────────────────────────────────────
SYSLOG_HEADER_RE = re.compile(
    r'<(\d+)>'              # priority
    r'(\w{3}\s+\d{1,2}\s+\d+:\d+:\d+)\s+'  # timestamp
    r'(\S+)\s+'             # hostname
    r'(\S+?)(?:\[(\d+)\])?:\s+'  # process[pid]:
    r'(.*)'                 # message
)

# ── Log type detection patterns ──────────────────────────────────────────
TYPE_PATTERNS = [
    ('filterlog', re.compile(r'filterlog\[\d+\]:')),
    ('zenarmor', re.compile(r'zenarmor|zen[ _]?guard', re.IGNORECASE)),
    ('nginx', re.compile(r'nginx|/usr/sbin/cron.*nginx|ngx_autoblock', re.IGNORECASE)),
    ('ids', re.compile(r'suricata|snort|ids\.\w+\.rule|ids\.list\.rule', re.IGNORECASE)),
]

# ── IP extraction ───────────────────────────────────────────────────────
IPV4_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
IPV6_RE = re.compile(r'([0-9a-fA-F:]{3,39})')

# ── Port extraction ─────────────────────────────────────────────────────
PORT_RE = re.compile(r'(?:port[s]?|D?PT|DPT)[\s:=]*(\d+)')
SPORT_RE = re.compile(r'(?:SPT|sport)[\s:=]*(\d+)')

# ── Action extraction ───────────────────────────────────────────────────
ACTION_RE = re.compile(
    r'\b(pass|block|drop|deny|reject|allow|permit|alert|reject|log)\b',
    re.IGNORECASE
)
ACTION_MAP = {
    'pass': 'PASS', 'allow': 'PASS', 'permit': 'PASS',
    'block': 'BLOCK', 'drop': 'BLOCK', 'deny': 'BLOCK',
    'reject': 'BLOCK', 'alert': 'ALERT', 'log': 'LOG',
}


class AdaptiveParser:
    """Auto-detects log types and extracts normalized features."""

    def __init__(self):
        # Track discovered patterns for adaptation
        self.pattern_history = defaultdict(list)  # feature_name -> [values]
        self.discovered_patterns = set()
        self.log_type_distribution = Counter()
        self.adaptation_counter = 0
        self.adaptation_interval = 1000  # adapt every N events
        
    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a raw log line and return normalized event features."""
        raw_line = raw_line.strip()
        if not raw_line:
            return None
        
        # Step 1: Extract syslog header
        header = self._parse_header(raw_line)
        if not header:
            return None
        
        # Step 2: Detect log type
        log_type = self._detect_type(raw_line, header['process'])
        self.log_type_distribution[log_type] += 1
        
        # Step 3: Extract features based on type
        features = {
            'timestamp': header['timestamp'],
            'log_type': log_type,
            'hostname': header['hostname'],
            'process': header['process'],
            'priority': header['priority'],
            'raw': raw_line,
        }
        
        if log_type == 'filterlog':
            features.update(self._parse_filterlog(raw_line))
        elif log_type == 'zenarmor':
            features.update(self._parse_zenarmor(raw_line))
        elif log_type == 'nginx':
            features.update(self._parse_nginx(raw_line))
        elif log_type == 'ids':
            features.update(self._parse_ids(raw_line))
        else:
            # System messages - extract IPs if any
            features.update(self._extract_system_features(raw_line))
        
        # Remove None values and normalize
        features = {k: v for k, v in features.items() if v is not None}
        
        # Record patterns for adaptation
        if features.get('src_ip'):
            self.pattern_history['src_ip'].append(features['src_ip'])
        if features.get('dst_ip'):
            self.pattern_history['dst_ip'].append(features['dst_ip'])
        if features.get('dport'):
            self.pattern_history['dport'].append(features['dport'])
        
        return features
    
    def _parse_header(self, raw: str) -> Optional[Dict[str, Any]]:
        """Extract syslog header components."""
        m = SYSLOG_HEADER_RE.match(raw)
        if not m:
            return None
        pri, ts, host, process, pid, message = m.groups()
        return {
            'priority': pri,
            'timestamp': ts,
            'hostname': host,
            'process': process.split('/')[-1],  # Just the program name
            'pid': int(pid) if pid else None,
            'message': message,
        }
    
    def _detect_type(self, raw: str, process: str) -> str:
        """Detect log type from content and process name."""
        # Check content patterns
        for log_type, pattern in TYPE_PATTERNS:
            if pattern.search(raw):
                return log_type
        
        # Check process name
        proc_lower = process.lower()
        if 'nginx' in proc_lower:
            return 'nginx'
        if 'suricata' in proc_lower or 'snort' in proc_lower:
            return 'ids'
        if 'zen' in proc_lower or 'guard' in proc_lower:
            return 'zenarmor'
        if 'filterlog' in proc_lower:
            return 'filterlog'
        
        return 'system'
    
    def _parse_filterlog(self, raw: str) -> Dict[str, Any]:
        """Parse OPNsense filterlog CSV format.
        
        Actual OPNsense filterlog CSV format (space-delimited within syslog):
        [0] flag        - event flags (230=pass, 234=pass/v6, 235=block, 233=block/v6)
        [1]             - empty
        [2]             - empty
        [3] ruid        - rule unique identifier (e.g., 'fae559338f...')
        [4] interface   - e.g., igb1, ixl2, ixl3_vlan1003
        [5] match       - always 'match'
        [6] action      - 'pass' or 'block'
        [7] direction   - 'in' or 'out'
        [8] ip_version  - '4' or '6'
        [9]             - 0x0
        [10]           - empty
        [11] length    - packet length
        [12]           - 0
        [13]           - 0
        [14] flags     - DF or 'none'
        [15] proto_num - '6'=TCP, '17'=UDP, '1'=ICMP (IPv4)
                        For IPv6: this IS the src_ip
        [16] proto_name - 'tcp', 'udp', 'icmp' (IPv4)
                        For IPv6: this IS the dst_ip
        [17]           - varies (length for non-IP, tcp window for TCP)
        [18] src_ip    - source IP (IPv4 only)
        [19] dst_ip    - destination IP (IPv4 only)
        [20] sport     - source port (IPv4 TCP/UDP only)
        [21] dport     - destination port (IPv4 TCP/UDP only)
        [22+]         - TCP options, seq numbers, etc. (IPv4 only)
        
        IPv4 entries: 29 parts (TCP), 23 parts (UDP), 21 parts (ICMP)
        IPv6 entries: 26 parts (TCP) - IPs at positions 15/16 instead of 18/19
        """
        features = {}
        
        # Extract CSV portion after filterlog[pid]:
        m = re.search(r'filterlog\[\d+\]:\s*(.*)', raw)
        if not m:
            return self._extract_system_features(raw)
        
        csv_data = m.group(1).strip()
        parts = [p.strip() for p in csv_data.split(',')]
        
        if len(parts) >= 4:
            # Interface at index 4
            features['interface'] = parts[4] if len(parts) > 4 else None
            
            # Action at index 6: 'pass' or 'block'
            action = parts[6].lower() if len(parts) > 6 else ''
            if action in ('pass', 'permit'):
                features['action'] = 'PASS'
            elif action in ('block', 'drop', 'deny', 'reject'):
                features['action'] = 'BLOCK'
            
            # IP version at index 8: '4' or '6'
            ip_version = parts[8].lower() if len(parts) > 8 else ''
            
            if ip_version == '4':
                # IPv4: proto fields vary by protocol length
                # TCP (29 parts): proto at [13]=num, [14]=name
                # UDP (22 parts): proto at [13]=num, [14]=name
                proto_num = parts[13] if len(parts) > 13 else ''
                proto_name = parts[14].lower() if len(parts) > 14 else ''
                
                # Determine protocol from proto_num or proto_name
                if proto_num in ('6',) or proto_name == 'tcp':
                    features['proto'] = 'TCP'
                elif proto_num in ('17',) or proto_name == 'udp':
                    features['proto'] = 'UDP'
                elif proto_num in ('1',) or proto_name == 'icmp':
                    features['proto'] = 'ICMP'
                
                # IPs and ports at fixed positions for IPv4
                if proto_name == 'udp' and len(parts) > 18:
                    # UDP: [16]=src_ip, [17]=dst_ip, [18]=sport, [19]=dport
                    features['src_ip'] = parts[16] if len(parts) > 16 else None
                    features['dst_ip'] = parts[17] if len(parts) > 17 else None
                    try:
                        features['sport'] = int(parts[18]) if parts[18].isdigit() else None
                    except (ValueError, IndexError):
                        features['sport'] = None
                    try:
                        features['dport'] = int(parts[19]) if parts[19].isdigit() else None
                    except (ValueError, IndexError):
                        features['dport'] = None
                elif len(parts) > 19:
                    # TCP with enough parts: [16]=src_ip, [17]=dst_ip, [18]=sport, [19]=dport
                    features['src_ip'] = parts[16] if len(parts) > 16 else None
                    features['dst_ip'] = parts[17] if len(parts) > 17 else None
                    try:
                        features['sport'] = int(parts[18]) if parts[18].isdigit() else None
                    except (ValueError, IndexError):
                        features['sport'] = None
                    try:
                        features['dport'] = int(parts[19]) if parts[19].isdigit() else None
                    except (ValueError, IndexError):
                        features['dport'] = None
                    # TCP options at [20+]
            elif ip_version == '6':
                # IPv6: src/dst IPs at positions 15/16 (different from IPv4!)
                if len(parts) > 16:
                    features['src_ip'] = parts[15] if len(parts) > 15 else None
                    features['dst_ip'] = parts[16] if len(parts) > 16 else None
                    
                    # For IPv6, the proto field may not be explicit in the CSV.
                    # Detect protocol from TCP indicators:
                    tcp_flags = ('S', 'S-A', 'SA', 'A', 'F', 'R', 'P', 'U')
                    tcp_options = ('mss', 'nop', 'wscale', 'sackOK', 'ts')
                    
                    proto_detected = False
                    # First check remaining parts for explicit proto name
                    if len(parts) > 17:
                        for p in parts[17:]:
                            if p in ('tcp', 'udp', 'icmp', 'ipv6-icmp', 'ipv6'):
                                features['proto'] = {'tcp': 'TCP', 'udp': 'UDP', 'icmp': 'ICMP',
                                                    'ipv6-icmp': 'ICMPV6', 'ipv6': 'IPv6'}.get(p.lower(), 'UNKNOWN')
                                proto_detected = True
                                break
                    
                    # If not detected, look for TCP-specific indicators
                    if not proto_detected and len(parts) > 17:
                        remaining = ','.join(parts[17:])
                        # Check for TCP flags (S, S-A, A, etc.) or TCP options
                        for token in parts[17:]:
                            if token in tcp_flags:
                                features['proto'] = 'TCP'
                                proto_detected = True
                                break
                            if token.lower() in tcp_options:
                                features['proto'] = 'TCP'
                                proto_detected = True
                                break
                        
                        # If still not detected, check if port-like number exists after IPs
                        # TCP/UDP will have port numbers; ICMP/IPv6-Hop-by-Hop etc won't
                        if not proto_detected and len(parts) > 18:
                            try:
                                candidate = int(parts[17])
                                # If the first field after IPs is a valid port (1-65535) and
                                # we have sequence numbers/flags, it's TCP or UDP
                                if 1 <= candidate <= 65535:
                                    # Check for more TCP-like fields
                                    has_tcp_field = False
                                    for p in parts[18:]:
                                        if p in tcp_flags or p.lower().replace(';', ' ').split()[-1] in tcp_options:
                                            has_tcp_field = True
                                            break
                                    # Try to determine if TCP or UDP from flags/options
                                    if has_tcp_field:
                                        features['proto'] = 'TCP'
                                    else:
                                        features['proto'] = 'UDP'
                                    proto_detected = True
                            except (ValueError, IndexError):
                                # No port-like number — likely ICMPv6
                                if not proto_detected:
                                    features['proto'] = 'ICMPV6'
                    
                    # Last resort fallback
                    if not proto_detected:
                        found_ips = []
                        for i, p in enumerate(parts):
                            try:
                                ipaddress.ip_address(p)
                                found_ips.append((i, p))
                            except ValueError:
                                pass
                        if len(found_ips) >= 2:
                            features['src_ip'] = found_ips[0][1]
                            features['dst_ip'] = found_ips[1][1]
            
            # No rule_name in standard OPNsense filterlog CSV — only RUID at [3]
            # Use RUID as a fallback identifier
            if len(parts) > 3 and parts[3]:
                features['ruid'] = parts[3]
        
        # Try key=value format as fallback (for non-CSV filterlog entries)
        if not features.get('src_ip'):
            src_match = re.search(r'SRC=(\S+)', csv_data)
            dst_match = re.search(r'DST=(\S+)', csv_data)
            if src_match and dst_match:
                features['src_ip'] = src_match.group(1)
                features['dst_ip'] = dst_match.group(1)
                proto_m = re.search(r'PROTO=(\S+)', csv_data)
                if proto_m:
                    features['proto'] = proto_m.group(1).upper()
        
        return features
    
    def _parse_zenarmor(self, raw: str) -> Dict[str, Any]:
        """Parse ZenArmor logs - extract IPs, ports, rules."""
        features = {}
        
        # Extract IPs
        ips = IPV4_RE.findall(raw)
        if len(ips) >= 2:
            features['src_ip'] = ips[0]
            features['dst_ip'] = ips[1]
        elif len(ips) == 1:
            features['src_ip'] = ips[0]
        
        # Extract ports
        ports = PORT_RE.findall(raw)
        if ports:
            try:
                features['dport'] = int(ports[0])
            except (ValueError, IndexError):
                pass
        
        # Extract rule/action
        rule_match = re.search(r'(?:rule|action|policy)\s*[:=]\s*(\S+)', raw, re.IGNORECASE)
        if rule_match:
            features['rule'] = rule_match.group(1)
        
        # Action
        action_m = ACTION_RE.search(raw)
        if action_m:
            features['action'] = ACTION_MAP.get(action_m.group(1).lower(), action_m.group(1).upper())
        
        return features
    
    def _parse_nginx(self, raw: str) -> Dict[str, Any]:
        """Parse Nginx logs - extract client IP, request, status."""
        features = {}
        
        # Standard Nginx log format
        m = re.match(
            r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)',
            raw
        )
        if m:
            features['src_ip'] = m.group(1)
            features['timestamp'] = m.group(2)
            features['request'] = m.group(3)
            features['status_code'] = int(m.group(4))
            features['bytes'] = int(m.group(5))
            
            # Method from request
            req_parts = m.group(3).split()
            if len(req_parts) >= 1:
                features['method'] = req_parts[0]
            if len(req_parts) >= 2:
                features['path'] = req_parts[1]
        
        return features
    
    def _parse_ids(self, raw: str) -> Dict[str, Any]:
        """Parse IDS logs (suricata/snort) - extract alert details."""
        features = {}
        
        # Extract IPs
        src_match = re.search(r'SRC=(\S+)', raw)
        dst_match = re.search(r'DST=(\S+)', raw)
        if src_match and dst_match:
            features['src_ip'] = src_match.group(1)
            features['dst_ip'] = dst_match.group(1)
        
        # Extract ports
        spt_match = re.search(r'SPT=(\d+)', raw)
        dpt_match = re.search(r'DPT=(\d+)', raw)
        if spt_match:
            features['sport'] = int(spt_match.group(1))
        if dpt_match:
            features['dport'] = int(dpt_match.group(1))
        
        # Alert rule/metadata
        rule_match = re.search(r'(?:signature|alert|rule)[s]?\s*[:=]?\s*(\S+)', raw, re.IGNORECASE)
        if rule_match:
            features['rule'] = rule_match.group(1)
        
        # Priority
        pri_match = re.search(r'priority\s*[:=]?\s*(\d+)', raw, re.IGNORECASE)
        if pri_match:
            features['priority_score'] = int(pri_match.group(1))
        
        return features
    
    def _extract_system_features(self, raw: str) -> Dict[str, Any]:
        """Extract common features (IPs, ports) from system logs."""
        features = {}
        
        # Extract IPv4 addresses
        ipv4_matches = IPV4_RE.findall(raw)
        if len(ipv4_matches) >= 2:
            features['src_ip'] = ipv4_matches[0]
            features['dst_ip'] = ipv4_matches[1]
        elif len(ipv4_matches) == 1:
            features['src_ip'] = ipv4_matches[0]
        
        # Extract ports
        port_matches = PORT_RE.findall(raw)
        if port_matches:
            try:
                features['dport'] = int(port_matches[0])
            except (ValueError, IndexError):
                pass
        
        # Extract status/message type
        if 'error' in raw.lower():
            features['log_level'] = 'error'
        elif 'warn' in raw.lower():
            features['log_level'] = 'warning'
        elif 'info' in raw.lower():
            features['log_level'] = 'info'
        
        return features
    
    def adapt(self, sample_lines: List[str]) -> Dict[str, Any]:
        """Periodically re-analyze raw log types and update detection."""
        logger.info(f"Adapting parser with {len(sample_lines)} new log samples...")
        
        # Reclassify samples
        type_counts = Counter()
        discovered_patterns = set()
        
        for line in sample_lines:
            log_type = self._detect_type(line, '')
            type_counts[log_type] += 1
            
            # Look for new field patterns
            features = self.parse_line(line)
            if features:
                for key in features:
                    if key not in ('timestamp', 'log_type', 'hostname', 'process',
                                  'priority', 'raw', 'action', 'rule'):
                        discovered_patterns.add(key)
        
        self.discovered_patterns = discovered_patterns
        
        logger.info(f"Adaptation complete. Log type distribution: {dict(type_counts)}")
        logger.info(f"Discovered features: {discovered_patterns}")
        
        return {
            'log_type_distribution': dict(type_counts),
            'discovered_patterns': list(discovered_patterns),
            'total_sampled': len(sample_lines),
        }


# Module-level parser instance for syslog_listener compatibility
_parser = AdaptiveParser()
