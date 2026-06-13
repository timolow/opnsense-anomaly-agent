#!/usr/bin/env python3
"""Syslog listener for OPNsense firewall logs.
Runs on the Mac host to receive UDP syslog, writes to shared JSONL file.
The Docker agent reads events from this file.
"""

import socket
import os
import json
import threading
import logging
from datetime import datetime
import re
from pathlib import Path

# Configuration
# Configuration (overridable via environment variables)
UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "1514"))
DATA_DIR = os.getenv("DATA_DIR", str(Path(__file__).parent / "agent_data"))
OUTPUT_FILE = os.getenv("JSONL_PATH", os.path.join(DATA_DIR, "syslog_events.jsonl"))
LOG_FILE = os.path.join(DATA_DIR, "syslog_listener.log")
EVENT_COUNT_FILE = os.path.join(DATA_DIR, "syslog_event_count.txt")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Initialize event counter
if not os.path.exists(EVENT_COUNT_FILE):
    with open(EVENT_COUNT_FILE, 'w') as f:
        f.write('0')

def get_event_count():
    try:
        with open(EVENT_COUNT_FILE, 'r') as f:
            return int(f.read().strip())
    except:
        return 0

def set_event_count(count):
    with open(EVENT_COUNT_FILE, 'w') as f:
        f.write(str(count))

# OPNsense filterlog CSV format:
# count,,tag,interface,match,action,direction,proto,proto_hdr,len,ttl,flags,proto_name,len,src_ip,dst_ip,sport,dport,...
# Example: 234,,,0178edf29ab05b331c29b8e9ded6f0b4,igb1,match,pass,out,6,0x00,0x625eb,64,tcp,6,40,2605:6000:ffc0:62:55de:454b:d2b7:e07c,2620:fe::fe:11,37955,853,0,S,2490836389,,65228,,mss;nop;wscale;sackOK;TS
FILTERLOG_FIELDS = [
    "count", "rule_no", "sub_rule", "tag", "interface", "match_status",
    "action", "direction", "proto_num", "proto_hdr", "total_len",
    "ttl", "flags", "proto_name", "ip_len", "src_ip", "dst_ip",
    "src_port", "dst_port", "flags_2", "tcp_flags", "seq_num",
    "ack_num", "win_size", "options"
]

PROTO_MAP = {
    "6": "TCP", "17": "UDP", "1": "ICMP", "41": "IPv6", "58": "ICMPV6",
    "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP", "ICMPV6": "ICMPV6"
}

def parse_syslog_line(line):
    """Parse OPNsense filterlog (CSV format) into structured data."""
    try:
        event = {
            "raw": line.strip(),
            "timestamp": datetime.now().isoformat(),
            "src_ip": None,
            "dst_ip": None,
            "sport": None,
            "dport": None,
            "proto": None,
            "action": None,
            "interface": None
        }
        
        # Strip syslog prefix if present: <134>Jun 13 00:21:14 hostname filterlog[pid]: ...
        # Look for the part after "filterlog[" or just use the whole line
        csv_line = line.strip()
        
        # Try to extract the CSV portion after "filterlog["
        idx = csv_line.find("filterlog[")
        if idx != -1:
            csv_line = csv_line[idx + len("filterlog["):]
            # Remove trailing ] if present
            bracket = csv_line.find("]")
            if bracket != -1:
                csv_line = csv_line[bracket + 1:].strip()
        
        # Also try old SRC=/DST= format (fallback)
        src_match = re.search(r'SRC=(\S+)', csv_line)
        dst_match = re.search(r'DST=(\S+)', csv_line)
        proto_match = re.search(r'PROTO=(\S+)', csv_line)
        spt_match = re.search(r'SPT=(\d+)', csv_line)
        dpt_match = re.search(r'DPT=(\d+)', csv_line)
        
        if src_match and dst_match:
            # Old KEY=VALUE format
            event["src_ip"] = src_match.group(1)
            event["dst_ip"] = dst_match.group(1)
            event["proto"] = (proto_match.group(1).upper() if proto_match else None)
            event["sport"] = int(spt_match.group(1)) if spt_match else None
            event["dport"] = int(dpt_match.group(1)) if dpt_match else None
            
            if "pass" in csv_line.lower() or "permit" in csv_line.lower():
                event["action"] = "PASS"
            elif "block" in csv_line.lower() or "drop" in csv_line.lower() or "deny" in csv_line.lower():
                event["action"] = "BLOCK"
            else:
                event["action"] = "UNKNOWN"
            
            if_match = re.search(r'on\s+(\w+)', csv_line)
            if if_match:
                event["interface"] = if_match.group(1)
            return event
        
        # CSV format: comma-separated
        parts = [p.strip() for p in csv_line.split(",")]
        
        if len(parts) >= 10:
            # interface is typically at index 4 (0-based) or index 3
            event["interface"] = parts[4] if len(parts) > 4 else None
            
            # action at index 6 or 5 depending on format
            if len(parts) > 6:
                act = parts[6].lower()
                if act in ("pass", "permit"):
                    event["action"] = "PASS"
                elif act in ("block", "drop", "deny", "reject"):
                    event["action"] = "BLOCK"
                elif act in ("log", "logrev"):
                    event["action"] = "LOG"
                else:
                    event["action"] = act.upper()
            
            # direction at index 7
            if len(parts) > 7:
                event["direction"] = parts[7]
            
            # OPNsense filterlog CSV format (from grep -m5):
            # [0]count [1]rule [2]sub_rule [3]tag [4]if [5]match [6]action [7]dir
            # [8]proto_num [9]hdr [10]len [11]ttl [12]flags1 [13]flags2 [14]flags3
            # [15]proto_num [16]proto_name [17]ip_len
            # [18]src_ip [19]dst_ip [20]sport [21]dport [22]extra
            
            # Protocol: index 15 = numeric proto, index 16 = name
            if len(parts) > 15 and parts[15].isdigit():
                event["proto"] = PROTO_MAP.get(parts[15])
            elif len(parts) > 16 and parts[16] and parts[16].lower() in PROTO_MAP:
                event["proto"] = PROTO_MAP[parts[16].lower()]
            elif len(parts) > 15 and parts[15] and parts[15].upper() in PROTO_MAP:
                event["proto"] = PROTO_MAP[parts[15].upper()]
            
            # src_ip, dst_ip, sport, dport at indices 18,19,20,21
            if len(parts) > 21 and parts[18] and parts[19]:
                event["src_ip"] = parts[18]
                event["dst_ip"] = parts[19]
                try:
                    event["sport"] = int(parts[20]) if parts[20] else None
                except (ValueError, IndexError):
                    pass
                try:
                    event["dport"] = int(parts[21]) if parts[21] else None
                except (ValueError, IndexError):
                    pass
        
        # Only return event if we actually parsed a filterlog entry
        if event["src_ip"] is None and event["dst_ip"] is None and event["proto"] is None:
            return None
        
        return event
    except Exception as e:
        logger.warning(f"Error parsing syslog line: {e}")
        return None

def write_event(event):
    """Append event to JSONL file atomically."""
    try:
        with open(OUTPUT_FILE, 'a') as f:
            f.write(json.dumps(event) + '\n')
            f.flush()
        return True
    except Exception as e:
        logger.error(f"Error writing event: {e}")
        return False

def run_syslog_listener():
    """Run the syslog UDP listener."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('0.0.0.0', UDP_PORT))
        logger.info(f"Syslog listener started on UDP port {UDP_PORT}")
        logger.info(f"Events will be written to: {OUTPUT_FILE}")
        
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                line = data.decode('utf-8', errors='replace').strip()
                
                if not line:
                    continue
                
                logger.debug(f"Received from {addr}: {line[:100]}...")
                
                event = parse_syslog_line(line)
                if event:
                    if write_event(event):
                        count = get_event_count() + 1
                        set_event_count(count)
                        logger.info(f"Event #{count}: {event.get('src_ip')}:{event.get('sport')} -> {event.get('dst_ip')}:{event.get('dport')} ({event.get('action')})")
            
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error receiving data: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Failed to start listener: {e}")
    finally:
        sock.close()
        logger.info("Syslog listener stopped")

if __name__ == '__main__':
    logger.info("Starting OPNsense Syslog Listener")
    run_syslog_listener()
