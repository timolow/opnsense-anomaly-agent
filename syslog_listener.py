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

# Use the adaptive parser which handles all log types
from adaptive_parser import AdaptiveParser

_parser = AdaptiveParser()

def _convert_timestamp(raw_ts):
    """Convert raw syslog timestamp to ISO format for PostgreSQL.
    
    Syslog format: 'Jun 14 14:06:24'
    PostgreSQL format: '2026-06-14T14:06:24'
    """
    if not raw_ts or 'T' in raw_ts:
        return raw_ts
    try:
        dt = datetime.strptime(raw_ts, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return raw_ts


def parse_syslog_line(line):
    """Parse any log line using the adaptive parser."""
    try:
        event = _parser.parse_line(line.strip())
        if event:
            # Convert raw syslog timestamp to ISO format for PostgreSQL
            event['timestamp'] = _convert_timestamp(event.get('timestamp', ''))
            event['_received_at'] = datetime.now().isoformat()
        return event
    except Exception as e:
        logger.warning("Error parsing syslog line: %s", e)
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


# ============================================================
# Agent.py compatibility wrapper
# ============================================================


class SyslogListener:
    """UDP syslog listener that passes parsed events directly to a callback."""
    
    def __init__(self, config, event_callback=None):
        """
        Args:
            config: Config object with syslog_port
            event_callback: callable(event_dict) -> None
                           Called directly for each parsed event.
                           If None, falls back to writing JSONL (legacy).
        """
        self.config = config
        self.event_callback = event_callback
        self._thread = None
        self._running = False
    
    def start(self):
        """Start the syslog UDP listener in a background thread. Returns True on success."""
        try:
            # Override defaults from config
            self.UDP_PORT = self.config.syslog_port
            
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            logger.info("Syslog listener started on UDP port %s", self.UDP_PORT)
            return True
        except Exception as e:
            logger.warning("Failed to start syslog listener: %s", e)
            self._running = False
            return False
    
    def _run(self):
        """Run the syslog listener loop."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', self.UDP_PORT))
            
            count = 0
            while self._running:
                try:
                    sock.settimeout(1.0)
                    data, addr = sock.recvfrom(65535)
                    line = data.decode('utf-8', errors='replace').strip()
                    
                    if not line:
                        continue
                    
                    event = parse_syslog_line(line)
                    if event:
                        count += 1
                        if self.event_callback:
                            # Direct callback — no JSONL file
                            self.event_callback(event)
                            logger.debug("Event #%d: %s -> %s", count,
                                         event.get('src_ip'), event.get('dst_ip'))
                        else:
                            # Legacy fallback: write JSONL
                            write_event(event)
                            event_count = get_event_count() + 1
                            set_event_count(event_count)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.warning("Syslog listener error: %s", e)
            sock.close()
        except Exception as e:
            logger.error("Syslog listener thread failed: %s", e)
    
    def stop(self):
        """Stop the syslog listener."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
