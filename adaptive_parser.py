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
        """Parse OPNsense filterlog - supports CSV and key=value formats."""
        features = {}
        
        # Extract CSV portion after filterlog[pid]:
        m = re.search(r'filterlog\[\d+\]:\s*(.*)', raw)
        if not m:
            return self._extract_system_features(raw)
        
        csv_data = m.group(1).strip()
        
        # Split by comma
        parts = [p.strip() for p in csv_data.split(',')]
        
        # Basic fields from CSV
        if len(parts) >= 10:
            interface = parts[4] if len(parts) > 4 else None
            action = parts[6].lower() if len(parts) > 6 else None
            
            # Map action
            if action:
                features['action'] = ACTION_MAP.get(action, action.upper())
            
            # Find protocol - position depends on IP version
            proto = None
            proto_idx = None
            version_idx = 8
            version = parts[version_idx] if len(parts) > version_idx else ''
            
            if version == '4':
                # IPv4: proto_name at index 16
                if len(parts) > 16 and parts[16] and parts[16].lower() in ('tcp', 'udp', 'icmp'):
                    proto = parts[16].upper()
                    proto_idx = 16
                elif len(parts) > 15 and parts[15] in ('1', '6', '17'):
                    proto_map = {'1': 'ICMP', '6': 'TCP', '17': 'UDP'}
                    proto = proto_map.get(parts[15], 'UNKNOWN')
                    proto_idx = 15
            elif version == '6':
                # IPv6: proto_name at index 12 (different from IPv4!)
                if len(parts) > 12 and parts[12] and parts[12].lower() in ('tcp', 'udp', 'ipv6-icmp'):
                    proto = parts[12].upper()
                    if proto == 'IPV6-ICMP':
                        proto = 'ICMPV6'
                    proto_idx = 12
                elif len(parts) > 13 and parts[13] in ('1', '6', '17', '41', '58'):
                    proto_map = {'1': 'ICMP', '6': 'TCP', '17': 'UDP', '41': 'IPv6', '58': 'ICMPV6'}
                    proto = proto_map.get(parts[13], 'UNKNOWN')
                    proto_idx = 13
            
            # Fallback: check proto_num anywhere
            if not proto:
                for i, p in enumerate(parts):
                    if p in ('1', '6', '17', '41', '47', '58') and i > 10 and i < 20:
                        proto_map = {'1': 'ICMP', '6': 'TCP', '17': 'UDP', '41': 'IPv6', '47': 'GRE', '58': 'ICMPV6'}
                        proto = proto_map.get(p, 'UNKNOWN')
                        proto_idx = i
                        break
            
            features['proto'] = proto
            
            # Find IPs and ports based on version
            if version in ('4', '6'):
                if version == '6':
                    # IPv6: src=15, dst=16, sport=17, dport=18 (TCP/UDP)
                    if proto in ('TCP', 'UDP'):
                        src_raw = parts[15] if len(parts) > 15 else None
                        dst_raw = parts[16] if len(parts) > 16 else None
                        if src_raw:
                            try:
                                ipaddress.ip_address(src_raw)
                                features['src_ip'] = src_raw
                            except ValueError:
                                pass
                        if dst_raw:
                            try:
                                ipaddress.ip_address(dst_raw)
                                features['dst_ip'] = dst_raw
                            except ValueError:
                                pass
                        features['sport'] = int(parts[17]) if len(parts) > 17 and parts[17].isdigit() else None
                        features['dport'] = int(parts[18]) if len(parts) > 18 and parts[18].isdigit() else None
                    elif proto in ('ICMPV6', 'ICMP'):
                        src_raw = parts[15] if len(parts) > 15 else None
                        dst_raw = parts[16] if len(parts) > 16 else None
                        if src_raw:
                            try:
                                ipaddress.ip_address(src_raw)
                                features['src_ip'] = src_raw
                            except ValueError:
                                pass
                        if dst_raw:
                            try:
                                ipaddress.ip_address(dst_raw)
                                features['dst_ip'] = dst_raw
                            except ValueError:
                                pass
                    elif proto == 'GRE':
                        # GRE has no ports, just src/dst IP at 15/16
                        src_raw = parts[15] if len(parts) > 15 else None
                        dst_raw = parts[16] if len(parts) > 16 else None
                        if src_raw:
                            try:
                                ipaddress.ip_address(src_raw)
                                features['src_ip'] = src_raw
                            except ValueError:
                                pass
                        if dst_raw:
                            try:
                                ipaddress.ip_address(dst_raw)
                                features['dst_ip'] = dst_raw
                            except ValueError:
                                pass
                elif version == '4':
                    # IPv4: src=18, dst=19, sport=20, dport=21 (TCP/UDP)
                    if proto in ('TCP', 'UDP'):
                        features['src_ip'] = parts[18] if len(parts) > 18 else None
                        features['dst_ip'] = parts[19] if len(parts) > 19 else None
                        features['sport'] = int(parts[20]) if len(parts) > 20 and parts[20].isdigit() else None
                        features['dport'] = int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else None
                    elif proto in ('ICMP', 'ICMPV6'):
                        features['src_ip'] = parts[18] if len(parts) > 18 else None
                        features['dst_ip'] = parts[19] if len(parts) > 19 else None
                    elif proto == 'GRE':
                        # GRE has no ports, just src/dst IP at 18/19
                        features['src_ip'] = parts[18] if len(parts) > 18 else None
                        features['dst_ip'] = parts[19] if len(parts) > 19 else None
            
            features['interface'] = interface
        
        # Try key=value format as fallback
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
