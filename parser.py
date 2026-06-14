"""
OPNsense filterlog CSV parser.

Handles both IPv4 and IPv6 filterlog formats, extracts TCP flags,
option fields, and validates all parsed IPs.

OPNsense filterlog CSV columns (split by comma):

IPv4 TCP:
  [0]   count
  [1]   (empty - tag)
  [2]   (empty - match #)
  [3]   uid
  [4]   interface
  [5]   rule_match
  [6]   action
  [7]   direction
  [8]   version (4)
  [9]   tos
  [10]  (empty)
  [11]  total_length
  [12]  ttl
  [13]  ip_id
  [14]  ip_flags
  [15]  proto_num
  [16]  proto_name
  [17]  hdr_len
  [18]  src_ip
  [19]  dst_ip
  [20]  sport
  [21]  dport
  [22]  seq (TCP)
  [23]  tcp_flags (TCP)
  [24]  ack (TCP)
  [25]  (empty)
  [26]  window (TCP)
  [27]  (empty)
  [28]  options (TCP)

IPv4 UDP:
  [0]   count
  ...
  [8]   version (4)
  ...
  [18]  src_ip
  [19]  dst_ip
  [20]  sport
  [21]  dport
  [22]  datalength
  [23+] optional trailing fields

IPv6 TCP:
  [0]   count
  [1]   (empty)
  [2]   (empty)
  [3]   uid
  [4]   interface
  [5]   rule_match
  [6]   action
  [7]   direction
  [8]   version (6)
  [9]   traffic_class
  [10]  flow_label
  [11]  total_length
  [12]  proto_name (tcp)
  [13]  proto_num (6)
  [14]  hdr_len
  [15]  src_ip
  [16]  dst_ip
  [17]  sport
  [18]  dport
  [19]  seq (TCP)
  [20]  tcp_flags (TCP)
  [21]  ack (TCP)
  [22]  (empty)
  [23]  window (TCP)
  [24]  (empty)
  [25]  options (TCP)

IPv6 UDP:
  [0]   count
  ...
  [8]   version (6)
  ...
  [15]  src_ip
  [16]  dst_ip
  [17]  sport
  [18]  dport
  [19]  datalength

IPv6 ICMP/ICMPV6:
  [0]   count
  ...
  [8]   version (6)
  ...
  [11]  total_length
  [12]  proto_name (ipv6-icmp)
  [13]  proto_num (58)
  [14]  datalength
  [15]  src_ip
  [16]  dst_ip
  [17]  datalength=NN (trailing)
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple


# IPv4 address pattern
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# IPv6 address pattern (simplified - catches common formats)
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')

# Syslog timestamp pattern
_SYSLOG_TS_RE = re.compile(
    r'^(?:<\d+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):'
)

# TCP flag mapping
_TCP_FLAG_BITS = {
    'FIN': 0x01,
    'SYN': 0x02,
    'RST': 0x04,
    'PSH': 0x08,
    'ACK': 0x10,
    'URG': 0x20,
    'ECE': 0x40,
    'CWR': 0x80,
    'NS': 0x100,
}

# Known protocol numbers
_PROTO_NUMBERS = {
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP',
    '41': 'IPv6',
    '58': 'ICMPV6',
    '50': 'ESP',
    '51': 'AH',
}


def is_valid_ip(addr: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    if not addr:
        return False
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def parse_flags(raw_flags: str) -> Dict[str, bool]:
    """Parse TCP flag field into individual flag booleans.
    
    OPNsense may output flags as individual letters (S, SA, F, R, etc.)
    or as numeric values.
    """
    if not raw_flags:
        return {}
    
    result = {}
    
    # Individual letters: S, SA, SF, FA, R, FA, etc.
    for c in raw_flags.upper():
        if c in 'FSRAPUECWN':
            flag_map = {
                'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
                'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR',
                'N': 'NS',
            }
            flag_name = flag_map.get(c, c)
            if flag_name:
                result[flag_name] = True
    
    # Numeric flags
    try:
        num = int(raw_flags)
        for name, bit in _TCP_FLAG_BITS.items():
            result[name] = bool(num & bit)
    except ValueError:
        pass
    
    return result


def parse_tcp_flags(flags_str: str, seq_str: str = "", ack_str: str = "") -> str:
    """Determine the primary TCP flag action from the flags field."""
    if not flags_str:
        return ""
    
    f = flags_str.upper().strip()
    
    # Known compound flags OPNsense uses
    if f in ('S', 'SYN'):
        return 'SYN'
    elif f in ('SA', 'S-A', 'S A'):
        return 'SYN-ACK'
    elif f in ('SF',):
        return 'SYN-FIN'
    elif f in ('F', 'FA'):
        return 'FIN-ACK'
    elif f in ('R', 'RA'):
        return 'RST'
    elif f in ('RA', 'R-A'):
        return 'RST-ACK'
    elif f in ('A', 'ACK', 'PA', 'PSH'):
        return 'PSH-ACK'
    elif f in ('U', 'URG'):
        return 'URG'
    elif f in ('NULL', 'FN'):
        return 'NULL'
    elif f in ('XS', 'XMAS'):
        return 'XMAS'
    elif f in ('E', 'ECE'):
        return 'ECE'
    elif f in ('SEC', 'S-E-C'):
        # S=SYN, E=ECE, C=CWR
        return 'SYN-CEC'
    elif f in ('SEF', 'S-E-F'):
        return 'SYN-URG'
    else:
        return f


def parse_syslog_timestamp(raw_line: str) -> Optional[datetime]:
    """Extract and parse syslog timestamp from a raw syslog line."""
    m = _SYSLOG_TS_RE.search(raw_line)
    if m:
        ts_str = m.group(1)
        year = datetime.now().year  # Syslog doesn't include year
        try:
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def parse_filterlog_line(raw_line: str) -> Optional[Dict[str, Any]]:
    """Parse an OPNsense filterlog CSV line into a structured event dict.
    
    Handles IPv4 and IPv6 for TCP, UDP, ICMP/ICMPV6.
    Returns None for non-filterlog lines.
    """
    # Check if this is a filterlog line
    if 'filterlog[' not in raw_line:
        return None
    
    # Split the CSV part (everything after filterlog[pid]:)
    idx = raw_line.find('filterlog[')
    colon_idx = raw_line.find(':', idx)
    if colon_idx == -1:
        return None
    
    csv_part = raw_line[colon_idx + 1:].strip()
    
    # Split by comma
    parts = [p.strip() for p in csv_part.split(',')]
    
    # We need at least the basic fields
    if len(parts) < 10:
        return None
    
    # Determine protocol version (field [8] for both IPv4 and IPv6)
    version_str = parts[8] if len(parts) > 8 else ""
    
    if version_str == '6':
        return _parse_ipv6(parts)
    elif version_str == '4':
        return _parse_ipv4(parts)
    
    return None


def _parse_ipv4(parts: list) -> Optional[Dict[str, Any]]:
    """Parse an IPv4 filterlog CSV.
    
    Verified offsets from sample data:
      [4]=interface [6]=action [7]=direction [8]=version(4)
      [18]=src_ip [19]=dst_ip [20]=sport [21]=dport
      [22]=seq [23]=tcp_flags [24]=ack [26]=window [28]=options
      [11]=total_length [12]=ttl [15]=proto_num [16]=proto_name
      [9]=tos [14]=ip_flags
    """
    action = parts[6] if len(parts) > 6 else ""
    interface = parts[4] if len(parts) > 4 else ""
    direction = parts[7] if len(parts) > 7 else ""
    version = '4'
    
    src_ip = _safe_ip(parts[18], 'IPv4') if len(parts) > 18 else None
    dst_ip = _safe_ip(parts[19], 'IPv4') if len(parts) > 19 else None
    sport = _safe_int(parts[20]) if len(parts) > 20 else None
    dport = _safe_int(parts[21]) if len(parts) > 21 else None
    
    # Protocol detection
    proto_name = None
    proto_num = None
    if len(parts) > 16 and parts[16] and parts[16].lower() in ('tcp', 'udp', 'icmp'):
        proto_name = parts[16].lower()
    elif len(parts) > 15 and parts[15] in _PROTO_NUMBERS:
        proto_num = parts[15]
        proto_name = _PROTO_NUMBERS[parts[15]].lower()
    
    if not proto_name:
        proto_name = proto_num or "UNKNOWN"
    
    result = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'sport': sport,
        'dport': dport,
        'proto': proto_name.upper(),
        'action': action.upper() if action else None,
        'interface': interface,
        'direction': direction,
        'version': version,
        'tcp_flags_raw': '',
        'tcp_flags': '',
        'tcp_seq': None,
        'tcp_ack': None,
        'tcp_window': None,
        'tcp_options': '',
        'ip_ttl': None,
        'ip_total_length': None,
    }
    
    # TCP-specific fields
    if proto_name == 'tcp':
        result['tcp_flags_raw'] = parts[23] if len(parts) > 23 else ""
        result['tcp_flags'] = parse_tcp_flags(result['tcp_flags_raw'])
        result['tcp_seq'] = _safe_int(parts[22]) if len(parts) > 22 else None
        result['tcp_ack'] = _safe_int(parts[24]) if len(parts) > 24 else None
        result['tcp_window'] = _safe_int(parts[26]) if len(parts) > 26 else None
        result['tcp_options'] = parts[28] if len(parts) > 28 else ""
    elif proto_name == 'udp':
        result['udp_datalen'] = _safe_int(parts[22]) if len(parts) > 22 else None
    elif proto_name == 'icmp':
        result['icmp_datalen'] = _safe_int(parts[17]) if len(parts) > 17 else None
    
    # IP-specific fields
    result['ip_ttl'] = _safe_int(parts[12]) if len(parts) > 12 else None
    result['ip_total_length'] = _safe_int(parts[11]) if len(parts) > 11 else None
    result['ip_tos'] = parts[9] if len(parts) > 9 else None
    result['ip_flags'] = parts[14] if len(parts) > 14 else None
    
    return result


def _parse_ipv6(parts: list) -> Optional[Dict[str, Any]]:
    """Parse an IPv6 filterlog CSV.
    
    Verified offsets from sample data:
      [4]=interface [6]=action [7]=direction [8]=version(6)
      [12]=proto_name(tcp/udp/ipv6-icmp) [13]=proto_num
      [15]=src_ip [16]=dst_ip [17]=sport [18]=dport
      [19]=seq [20]=tcp_flags [21]=ack [23]=window [25]=options
      [9]=traffic_class [10]=flow_label [11]=total_length
      [17] also used for ICMP datalength
    """
    action = parts[6] if len(parts) > 6 else ""
    interface = parts[4] if len(parts) > 4 else ""
    direction = parts[7] if len(parts) > 7 else ""
    version = '6'
    
    # Determine protocol
    proto_name = None
    if len(parts) > 12 and parts[12] and parts[12].lower() in ('tcp', 'udp', 'ipv6-icmp'):
        proto_name = parts[12].lower()
        if proto_name == 'ipv6-icmp':
            proto_name = 'icmpv6'
    elif len(parts) > 13 and parts[13] in _PROTO_NUMBERS:
        proto_name = _PROTO_NUMBERS[parts[13]].lower()
    
    if not proto_name:
        return None
    
    src_ip = _safe_ip(parts[15], 'IPv6') if len(parts) > 15 else None
    dst_ip = _safe_ip(parts[16], 'IPv6') if len(parts) > 16 else None
    
    result = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'sport': None,
        'dport': None,
        'proto': proto_name.upper(),
        'action': action.upper() if action else None,
        'interface': interface,
        'direction': direction,
        'version': version,
        'tcp_flags_raw': '',
        'tcp_flags': '',
        'tcp_seq': None,
        'tcp_ack': None,
        'tcp_window': None,
        'tcp_options': '',
        'ip_total_length': None,
    }
    
    if proto_name == 'tcp':
        result['sport'] = _safe_int(parts[17]) if len(parts) > 17 else None
        result['dport'] = _safe_int(parts[18]) if len(parts) > 18 else None
        result['tcp_flags_raw'] = parts[20] if len(parts) > 20 else ""
        result['tcp_flags'] = parse_tcp_flags(result['tcp_flags_raw'])
        result['tcp_seq'] = _safe_int(parts[19]) if len(parts) > 19 else None
        result['tcp_ack'] = _safe_int(parts[21]) if len(parts) > 21 else None
        result['tcp_window'] = _safe_int(parts[23]) if len(parts) > 23 else None
        result['tcp_options'] = parts[25] if len(parts) > 25 else ""
    elif proto_name == 'udp':
        result['sport'] = _safe_int(parts[17]) if len(parts) > 17 else None
        result['dport'] = _safe_int(parts[18]) if len(parts) > 18 else None
        result['udp_datalen'] = _safe_int(parts[19]) if len(parts) > 19 else None
    elif proto_name in ('icmp', 'icmpv6'):
        # ICMP: src=15, dst=16, datalength field is parts[17] like "datalength=32"
        result['icmp_datalen'] = None
        if len(parts) > 17 and parts[17].startswith('datalength='):
            result['icmp_datalen'] = int(parts[17].split('=')[1])
    
    result['ip_total_length'] = _safe_int(parts[11]) if len(parts) > 11 else None
    result['ip_traffic_class'] = parts[9] if len(parts) > 9 else None
    result['ip_flow_label'] = parts[10] if len(parts) > 10 else None
    
    return result


def _safe_ip(value: str, ip_type: str) -> Optional[str]:
    """Validate and return an IP address, or None."""
    if not value:
        return None
    # Fast check with regex before expensive ipaddress parsing
    if ip_type == 'IPv4' and not _IPV4_RE.match(value):
        return None
    if ip_type == 'IPv6' and ':' not in value:
        return None
    # Double check with ipaddress module
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def _safe_int(value: str) -> Optional[int]:
    """Safely convert a string to int."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None
