#!/usr/bin/env python3
"""
OPNsense Anomaly Detection Agent

Reads firewall events from JSONL file (written by an external syslog listener)
or runs a built-in UDP syslog listener when SYSLOG_ENABLED=true.
Detects anomalies, sends Discord alerts, responds to chat commands.

Two operational modes:
  - JSONL mode (default): reads from agent_data/syslog_events.jsonl
  - Syslog mode (SYSLOG_ENABLED=true): receives UDP syslog on port 1514,
    parses it, writes to JSONL, then feeds events through detection pipeline

Optional vLLM integration for future LLM-based anomaly analysis.
"""

import os
import sys
import json
import time
import logging
import socket
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from threading import Thread, Event
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Project paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "agent_data"
DATA_DIR.mkdir(exist_ok=True)

# ============================================================
# CONFIG
# ============================================================

class Config:
    def __init__(self):
        self.opnsense = {
            "host": os.getenv("OPN_HOST", "192.168.1.1"),
            "api_key": os.getenv("OPN_API_KEY", ""),
            "api_secret": os.getenv("OPN_API_SECRET", ""),
            "port": int(os.getenv("OPN_PORT", "6666")),
            "verify_ssl": False,
        }
        # Syslog listener config
        self.syslog_enabled = os.getenv("SYSLOG_ENABLED", "false").lower() == "true"
        self.syslog_port = int(os.getenv("SYSLOG_UDP_PORT", "1514"))
        # vLLM config (optional - for future LLM-based anomaly analysis)
        self.vllm_base_url = os.getenv("VLLM_BASE_URL", "")
        self.vllm_model = os.getenv("VLLM_MODEL", "QuantTrio/Qwen3.6-35B-A3B-AWQ")
        # ML parameters
        self.window_sizes = {
            "short": 60,       # 1 minute
            "medium": 300,      # 5 minutes
            "long": 3600,       # 1 hour
        }
        self.thresholds = {
            "rate_per_minute": 100,
            "new_source_ip": 3,        # 3 new IPs in short window
            "new_dest_port": 10,       # 10 new ports in short window
            "failed_connections": 20,  # 20 failed in short window
            "unique_destinations": 50, # 50 unique destinations
        }
        self.learn_interval = 300   # Learn every 5 minutes
        self.save_interval = 300    # Save patterns every 5 minutes
        self.verbose = True
        # JSONL event file
        self.jsonl_path = DATA_DIR / "syslog_events.jsonl"
        self.jsonl_marker_path = DATA_DIR / "jsonl_read_marker.json"
        # Discord
        self.discord_token = os.getenv("DISCORD_TOKEN", "")
        self.discord_channel_id = os.getenv("DISCORD_CHANNEL_ID", "")
        # Fallback to config.json if env vars are empty
        config_path = BASE_DIR / "config.json"
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    cfg = json.load(f)
                discord_cfg = cfg.get("discord", {})
                if not self.discord_token:
                    self.discord_token = discord_cfg.get("bot_token", "")
                if not self.discord_channel_id:
                    self.discord_channel_id = discord_cfg.get("channel_id", "")
            except Exception as e:
                logger.warning(f"Could not load Discord config from {config_path}: {e}")
        # Chat command server
        self.chat_port = int(os.getenv("CHAT_PORT", "8765"))


# ============================================================
# OPNSENSE FILTERLOG PARSER (also used by standalone syslog_listener.py)
# ============================================================

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

        csv_line = line.strip()

        # Try to extract the CSV portion after "filterlog["
        idx = csv_line.find("filterlog[")
        if idx != -1:
            csv_line = csv_line[idx + len("filterlog["):]
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
            event["interface"] = parts[4] if len(parts) > 4 else None

            # action at index 6
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

        return event
    except Exception as e:
        logger.warning(f"Error parsing syslog line: {e}")
        return None


# ============================================================
# VLLM CLIENT (optional - for LLM-based anomaly analysis)
# ============================================================

class VLLMClient:
    """Client for interacting with a vLLM inference server."""

    def __init__(self, config):
        self.config = config
        self.enabled = bool(config.vllm_base_url)
        self.base_url = config.vllm_base_url.rstrip('/')
        self.model = config.vllm_model

    def health_check(self):
        """Check if the vLLM server is reachable."""
        if not self.enabled:
            logger.info("vLLM not configured (set VLLM_BASE_URL)")
            return False
        try:
            import requests
            resp = requests.get(f"{self.base_url}/health", timeout=5)
            if resp.status_code == 200:
                logger.info(f"vLLM server healthy at {self.base_url}")
                return True
        except Exception as e:
            logger.warning(f"vLLM health check failed: {e}")
        return False

    def list_models(self):
        """List available models from the vLLM server."""
        if not self.enabled:
            return []
        try:
            import requests
            resp = requests.get(f"{self.base_url}/models", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return [m["id"] for m in data.get("data", [])]
        except Exception as e:
            logger.warning(f"vLLM models list failed: {e}")
        return []

    def chat_completion(self, prompt, system_prompt="", max_tokens=256):
        """Send a chat completion request to the vLLM server."""
        if not self.enabled:
            return None
        try:
            import requests
            resp = requests.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt or "You are a security analyst."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.1,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"vLLM chat completion failed: {e}")
        return None


# ============================================================
# IN-BUILT SYSLOG UDP LISTENER (optional)
# ============================================================

class SyslogListener:
    """Built-in UDP syslog listener for OPNsense filterlog.

    Receives UDP packets, parses OPNsense CSV format, writes to JSONL file
    and returns parsed events to the caller for direct anomaly detection.
    """

    def __init__(self, config):
        self.config = config
        self.jsonl_path = config.jsonl_path
        self.sock = None
        self.running = False
        self.event_count = 0
        self._shutdown = Event()

    def start(self):
        """Start the UDP listener in a background thread."""
        if not self.config.syslog_enabled:
            return False

        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('0.0.0.0', self.config.syslog_port))
            self.sock.settimeout(1.0)  # Allow shutdown polling

            self._thread = Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            logger.info(f"Builtin syslog listener started on UDP port {self.config.syslog_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start builtin syslog listener: {e}")
            self.running = False
            return False

    def stop(self):
        """Stop the UDP listener."""
        self.running = False
        self._shutdown.set()
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        logger.info("Builtin syslog listener stopped")

    def _listen_loop(self):
        """Main UDP receive loop."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                line = data.decode('utf-8', errors='replace').strip()
                if not line:
                    continue

                event = parse_syslog_line(line)
                if event and event.get("src_ip") and event.get("proto"):
                    self._write_event(event)
                    self.event_count += 1
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving syslog: {e}")

    def _write_event(self, event):
        """Append event to JSONL file."""
        try:
            with open(self.jsonl_path, 'a') as f:
                f.write(json.dumps(event) + '\n')
                f.flush()
        except Exception as e:
            logger.warning(f"Error writing event to JSONL: {e}")

    def get_stats(self):
        """Return listener stats."""
        return {
            "running": self.running,
            "port": self.config.syslog_port,
            "events_received": self.event_count,
        }


# ============================================================
# JSONL EVENT READER
# ============================================================

class JSONLReader:
    """Reads new events from the JSONL file written by syslog_listener."""

    def __init__(self, config):
        self.config = config
        self.marker_path = config.jsonl_marker_path
        self._load_marker()

    def _load_marker(self):
        """Load the last read line number."""
        if self.marker_path.exists():
            try:
                with open(self.marker_path, 'r') as f:
                    data = json.load(f)
                    self.last_line = data.get("last_line", 0)
                    logger.info(f"Loaded read marker: line {self.last_line}")
            except:
                self.last_line = 0
        else:
            self.last_line = 0

    def _save_marker(self):
        """Save the current read position."""
        data = {"last_line": self.last_line, "timestamp": datetime.now().isoformat()}
        with open(self.marker_path, 'w') as f:
            json.dump(data, f)

    def read_events(self, max_events=100):
        """Read new events from the JSONL file since last position."""
        events = []
        if not self.config.jsonl_path.exists():
            return events

        try:
            current_size = self.config.jsonl_path.stat().st_size
            if hasattr(self, '_file_size') and current_size == self._file_size:
                return events
            self._file_size = current_size

            # Clamp marker to actual file line count - handle truncated/rotated files
            with open(self.config.jsonl_path, 'r') as f:
                actual_line_count = sum(1 for _ in f)
            if self.last_line > actual_line_count:
                logger.info(
                    f"JSONL file was truncated/rotated: marker {self.last_line} "
                    f"exceeds actual lines {actual_line_count}, resetting to 0"
                )
                self.last_line = 0
                self._save_marker()

            with open(self.config.jsonl_path, 'r') as f:
                skip_count = self.last_line
                for i in range(skip_count):
                    f.readline()

                count = 0
                for read_line_num, line in enumerate(f, start=skip_count):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get("src_ip") and event.get("proto"):
                            event["_read_time"] = datetime.now().isoformat()
                            event["_line_number"] = read_line_num
                            events.append(event)
                            count += 1
                            if count >= max_events:
                                break
                    except json.JSONDecodeError:
                        pass
                self.last_line = self.last_line + count
                self._save_marker()
        except Exception as e:
            logger.warning(f"Error reading JSONL: {e}")

        return events


# ============================================================
# OPNSENSE API CLIENT (kept for status lookups, not event polling)
# ============================================================

class OPNsenseClient:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.opnsense["verify_ssl"]

    def _basic_auth(self, user, password):
        import base64
        return base64.b64encode(f"{user}:{password}".encode()).decode()

    def get_auth_headers(self):
        return {
            "Authorization": f"Basic {self._basic_auth(self.config.opnsense['api_key'], self.config.opnsense['api_secret'])}",
            "Accept": "application/json",
            "User-Agent": "opnsense-agent/1.0",
        }

    def get_api_url(self, endpoint=""):
        return f"https://{self.config.opnsense['host']}:{self.config.opnsense['port']}{endpoint}"

    def test_connection(self):
        try:
            import requests
            resp = requests.get(
                self.get_api_url("/api/core/firmware/status"),
                headers=self.get_auth_headers(),
                timeout=10,
                verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                ver = data.get("os_version", "unknown")
                logger.info(f"Connected to OPNsense {ver}")
                return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
        return False

    def get_top_blocked_ips(self, n=10):
        """Get top blocked source IPs from filterlog."""
        try:
            import requests
            resp = requests.get(
                self.get_api_url("/api/core/filterlog?count=1000"),
                headers=self.get_auth_headers(),
                timeout=10,
                verify=False
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("filterlog", [])[:n]
        except Exception as e:
            logger.warning(f"Error fetching blocked IPs: {e}")
        return []

    def get_status(self):
        """Get overall OPNsense status."""
        try:
            import requests
            resp = requests.get(
                self.get_api_url("/api/core/uptime"),
                headers=self.get_auth_headers(),
                timeout=10,
                verify=False
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning(f"Error fetching status: {e}")
        return None


# ============================================================
# PATTERN LEARNER
# ============================================================

class PatternLearner:
    def __init__(self, config):
        self.config = config
        self.patterns = {
            "normal_hours": self._get_normal_hours(),
            "known_ips": defaultdict(int),
            "known_ports": defaultdict(int),
            "known_protocols": defaultdict(int),
            "event_rate": defaultdict(int),
            "failed_connections": defaultdict(int),
            "source_to_dest": defaultdict(set),
            "new_sources_window": deque(),
        }
        self._load()

    def _get_normal_hours(self):
        return {"start": 0, "end": 24}

    def learn_from_events(self, events):
        """Learn patterns from events."""
        now = datetime.now()
        minute_key = now.strftime("%Y-%m-%d %H:%M")

        for event in events:
            src_ip = event.get("src_ip")
            dst_ip = event.get("dst_ip")
            proto = event.get("proto", "unknown")
            src_port = event.get("sport", 0)
            dst_port = event.get("dport", 0)
            action = event.get("action", "unknown").lower()

            if src_ip:
                self.patterns["known_ips"][src_ip] += 1
                self.patterns["source_to_dest"][src_ip].add(dst_ip)

            if dst_ip:
                self.patterns["known_ips"][dst_ip] += 1

            if dst_port:
                self.patterns["known_ports"][int(dst_port)] += 1

            if proto:
                self.patterns["known_protocols"][proto] += 1

            self.patterns["event_rate"][minute_key] += 1

            if action in ("block", "drop", "deny", "reject"):
                self.patterns["failed_connections"][minute_key] += 1

            if src_ip and self.patterns["known_ips"][src_ip] == 1:
                self.patterns["new_sources_window"].append((event.get("_read_time", now), src_ip))

        logger.debug(f"Learned from {len(events)} events")

    def detect_anomalies(self, events):
        """Check events against learned patterns."""
        anomalies = []
        now = datetime.now()
        minute_key = now.strftime("%Y-%m-%d %H:%M")
        failed_count = self.patterns["failed_connections"].get(minute_key, 0)

        for event in events:
            src_ip = event.get("src_ip")
            dst_port = event.get("dport", 0)
            action = event.get("action", "unknown").lower()

            if src_ip and self.patterns["known_ips"][src_ip] < self.config.thresholds["new_source_ip"]:
                anomalies.append({
                    "type": "new_source_ip",
                    "severity": "low",
                    "details": f"New/rare source IP: {src_ip} (count: {self.patterns['known_ips'][src_ip]})",
                    "event": event,
                })

            if dst_port:
                port_count = self.patterns["known_ports"].get(int(dst_port), 0)
                if port_count < 5:
                    anomalies.append({
                        "type": "unusual_port",
                        "severity": "low",
                        "details": f"Uncommon destination port: {dst_port} (count: {port_count})",
                        "event": event,
                    })

            if action in ("block", "drop", "deny", "reject"):
                if failed_count > self.config.thresholds["failed_connections"]:
                    anomalies.append({
                        "type": "brute_force",
                        "severity": "high",
                        "details": f"High failed connection rate: {failed_count}/minute",
                        "event": event,
                    })

        return anomalies

    def save_patterns(self):
        """Save learned patterns to disk."""
        path = DATA_DIR / "learned_patterns.json"
        patterns = {}
        for key, value in self.patterns.items():
            if isinstance(value, deque):
                patterns[key] = list(value)
            else:
                patterns[key] = dict(value) if hasattr(value, 'items') else value

        with open(path, 'w') as f:
            json.dump(patterns, f, indent=2, default=str)
        logger.info(f"Saved patterns to {path}")

    def _load(self):
        """Load patterns from disk."""
        path = DATA_DIR / "learned_patterns.json"
        if path.exists():
            try:
                with open(path, 'r') as f:
                    loaded = json.load(f)
                for key, value in loaded.items():
                    if isinstance(value, list):
                        if key == "new_sources_window":
                            self.patterns[key] = deque(value)
                        elif key in ("known_ips", "known_ports", "known_protocols", "event_rate", "failed_connections"):
                            self.patterns[key] = defaultdict(int, value)
                        else:
                            self.patterns[key] = defaultdict(int, value)
                    elif isinstance(value, dict):
                        if key in ("known_ips", "known_ports", "known_protocols", "event_rate", "failed_connections"):
                            self.patterns[key] = defaultdict(int, value)
                        elif key == "source_to_dest":
                            self.patterns[key] = defaultdict(set, value)
                        else:
                            self.patterns[key] = value
                    else:
                        self.patterns[key] = value
                logger.info(f"Loaded patterns from {path}")
            except Exception as e:
                logger.warning(f"Failed to load patterns: {e}")

    def get_stats(self):
        """Get current pattern statistics."""
        return {
            "total_events_learned": sum(self.patterns["known_ips"].values()),
            "unique_ips": len(self.patterns["known_ips"]),
            "unique_ports": len(self.patterns["known_ports"]),
            "unique_protocols": len(self.patterns["known_protocols"]),
            "current_minute_rate": self.patterns["event_rate"].get(
                datetime.now().strftime("%Y-%m-%d %H:%M"), 0
            ),
            "failed_connections_minute": self.patterns["failed_connections"].get(
                datetime.now().strftime("%Y-%m-%d %H:%M"), 0
            ),
            "top_blocked_sources": dict(
                sorted(
                    [
                        (k, v)
                        for k, v in self.patterns["known_ips"].items()
                        if k not in (
                            "192.168.", "10.", "172.16.", "172.17.", "172.18.",
                            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                            "172.29.", "172.30.", "172.31.",
                        )
                    ],
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]
            )
            if hasattr(self.patterns["known_ips"], "items")
            else {},
        }


# ============================================================
# ANOMALY DETECTOR
# ============================================================

class AnomalyDetector:
    def __init__(self, config, learner):
        self.config = config
        self.learner = learner
        self.notified = set()
        self.notified_times = {}

    def detect(self, events):
        """Detect anomalies in events with cooldown deduplication."""
        anomalies = self.learner.detect_anomalies(events)
        results = []
        now = time.time()

        for anomaly in anomalies:
            key = hash(json.dumps(anomaly["details"], sort_keys=True))
            if key in self.notified_times:
                if now - self.notified_times[key] < 300:
                    continue
            self.notified_times[key] = now
            results.append(anomaly)

        return results


# ============================================================
# USER NOTIFIER (console + file)
# ============================================================

class UserNotifier:
    def __init__(self, config):
        self.config = config
        self.last_alert_time = 0
        self.alert_cooldown = 60
        self.agent = None

    def send_alert(self, anomaly):
        """Send alert to user."""
        now = time.time()
        if now - self.last_alert_time < self.alert_cooldown:
            return

        severity = anomaly["severity"].upper()
        atype = anomaly["type"]
        details = anomaly["details"]
        event = anomaly.get("event", {})

        msg = f"[OPNSENSE ALERT] [{severity}] {atype}: {details}"

        print(f"\n{'='*60}")
        print(f"OPNSENSE ANOMALY DETECTED")
        print(f"{'='*60}")
        print(f"  Type:     {atype}")
        print(f"  Severity: {severity}")
        print(f"  Details:  {details}")
        if event.get("src_ip"):
            print(f"  Source:   {event['src_ip']}:{event.get('sport', '?')}")
            print(f"  Dest:     {event['dst_ip']}:{event.get('dport', '?')}")
            print(f"  Proto:    {event.get('proto', '?')}")
            print(f"  Action:   {event.get('action', '?')}")
        print(f"  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        # Log to file
        log_file = DATA_DIR / "anomaly_log.jsonl"
        record = {
            "timestamp": datetime.now().isoformat(),
            "type": atype,
            "severity": severity,
            "details": details,
        }
        with open(log_file, 'a') as f:
            f.write(json.dumps(record) + '\n')

        self.last_alert_time = now


# ============================================================
# DISCORD BOT
# ============================================================

class DiscordBot:
    """Sends Discord alerts and handles chat commands."""

    def __init__(self, config):
        self.config = config
        self.discord_token = config.discord_token
        self.discord_channel_id = config.discord_channel_id
        self.bot = None
        self.running = False
        self._shutdown = Event()
        self.notifier = None
        # Deduplication: cache of (type, src_ip, dport) -> last_alert_timestamp
        # Alerts with the same signature are suppressed for ALERT_COOLDOWN_SECONDS
        from datetime import datetime, timedelta
        self._alert_cache: dict[tuple[str, str, int], datetime] = {}
        self._alert_cooldown = timedelta(minutes=5)
        # Global rate limiter: max 1 alert per 60 seconds to prevent Discord 429
        self._last_global_alert: datetime | None = None
        self._global_alert_interval = 60  # seconds

    def send_alert(self, anomaly):
        """Send an anomaly alert to Discord channel."""
        if not self.discord_token or not self.discord_channel_id:
            return

        severity = anomaly["severity"].upper()
        atype = anomaly["type"]
        details = anomaly["details"]
        event = anomaly.get("event", {})

        # --- Alert Deduplication ---
        src_ip = event.get("src_ip", "") or ""
        dport = event.get("dport", 0) or 0
        alert_sig = (atype, src_ip, dport)
        now = datetime.now()
        
        # Global rate limiter: max 1 alert per 60 seconds to prevent Discord 429
        if self._last_global_alert is not None:
            elapsed = (now - self._last_global_alert).total_seconds()
            if elapsed < self._global_alert_interval:
                logger.debug(
                    f"Rate limit: suppressing {atype} (only {elapsed:.0f}s since last alert)"
                )
                return
        
        # Per-sig dedup: suppress repeated alerts for same type+src_ip+dport within 5 min
        if alert_sig in self._alert_cache:
            last_alert = self._alert_cache[alert_sig]
            if now - last_alert < self._alert_cooldown:
                logger.debug(
                    f"Dedup: suppressing {atype} from {src_ip}:{dport} "
                    f"(last alert {int((now - last_alert).total_seconds())}s ago)"
                )
                return
        self._alert_cache[alert_sig] = now
        self._last_global_alert = now

        # Clean up cache entries older than 1 hour to prevent unbounded growth
        cutoff = now - timedelta(hours=1)
        self._alert_cache = {
            k: v for k, v in self._alert_cache.items() if v > cutoff
        }

        embed = {
            "title": f"[{severity}] {atype}",
            "description": details,
            "color": self._severity_color(severity),
            "fields": [],
            "timestamp": datetime.now().isoformat(),
        }

        if event.get("src_ip"):
            embed["fields"].append({
                "name": "Source",
                "value": f"{event['src_ip']}:{event.get('sport', '?')}",
                "inline": True,
            })
            embed["fields"].append({
                "name": "Destination",
                "value": f"{event['dst_ip']}:{event.get('dport', '?')}",
                "inline": True,
            })
        if event.get("proto"):
            embed["fields"].append({
                "name": "Protocol",
                "value": event["proto"],
                "inline": True,
            })
        if event.get("action"):
            embed["fields"].append({
                "name": "Action",
                "value": event["action"],
                "inline": True,
            })

        try:
            import requests
            url = f"https://discord.com/api/v9/channels/{self.discord_channel_id}/messages"
            payload = {
                "embeds": [embed],
                "content": f"\U0001f6a8 OPNsense Alert: {atype} - {severity}"
            }
            resp = requests.post(
                url,
                headers={"Authorization": f"Bot {self.discord_token}"},
                json=payload,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info(f"Discord alert sent: {atype}")
            else:
                logger.warning(f"Discord alert failed: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"Discord alert error: {e}")

    def _severity_color(self, severity):
        colors = {
            "LOW": 0x3498DB,
            "MEDIUM": 0xF39C12,
            "HIGH": 0xE74C3C,
        }
        return colors.get(severity.upper(), 0x95A5A6)

    def start_bot(self):
        """Start the Discord bot in a background thread."""
        if not self.discord_token:
            logger.warning("Discord token not configured, skipping Discord bot")
            return

        self.running = True
        thread = Thread(target=self._run_bot, daemon=True)
        thread.start()
        logger.info("Discord bot thread started")

    def _run_bot(self):
        """Run the Discord bot loop."""
        try:
            import discord
        except ImportError:
            logger.warning("discord.py not installed. Install with: pip install discord.py")
            return

        intents = discord.Intents.default()
        intents.message_content = True
        intents.messages = True

        bot = discord.Client(intents=intents)

        @bot.event
        async def on_ready():
            logger.info(f"Discord bot logged in as {bot.user}")
            logger.info(f"Connected to {len(bot.guilds)} guild(s)")
            self.bot = bot

        @bot.event
        async def on_message(message):
            if message.author == bot.user:
                return

            if not self.discord_channel_id or str(message.channel.id) != self.discord_channel_id:
                return

            content = message.content.strip().lower()

            if content.startswith("!status"):
                mode = "syslog" if self.config.syslog_enabled else "jsonl"
                await message.channel.send(f"\U0001f4ca **OPNsense Agent Status**\n`Running - mode: {mode}`")

            elif content.startswith("!stats"):
                if self.notifier and self.notifier.agent:
                    stats = self.notifier.agent.learner.get_stats()
                    msg = (
                        f"\U0001f4ca **Agent Stats**\n"
                        f"Events learned: {stats.get('total_events_learned', 0):,}\n"
                        f"Unique IPs: {stats.get('unique_ips', 0):,}\n"
                        f"Unique ports: {stats.get('unique_ports', 0):,}\n"
                        f"Current/min rate: {stats.get('current_minute_rate', 0)}\n"
                        f"Failed/min: {stats.get('failed_connections_minute', 0)}"
                    )
                    await message.channel.send(msg)
                else:
                    await message.channel.send("Stats not available yet (still learning)")

            elif content.startswith("!topblocked"):
                if self.notifier and self.notifier.agent:
                    stats = self.notifier.agent.learner.get_stats()
                    top = stats.get("top_blocked_sources", {})
                    if top:
                        lines = [f"**{ip}**: {count} events" for ip, count in list(top.items())[:5]]
                        msg = "\U0001f512 **Top Blocked Sources**\n" + "\n".join(lines)
                    else:
                        msg = "No blocked sources detected yet"
                    await message.channel.send(msg)
                else:
                    await message.channel.send("No data available yet")

            elif content.startswith("!help"):
                await message.channel.send(
                    "\U0001f4cb **Commands**\n"
                    "`!status` - Agent status\n"
                    "`!stats` - Learning statistics\n"
                    "`!topblocked` - Top blocked source IPs\n"
                    "`!help` - This message"
                )

        try:
            bot.run(self.discord_token)
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

    def stop(self):
        self.running = False
        if self.bot:
            self._shutdown.set()


# ============================================================
# CHAT COMMAND HTTP SERVER
# ============================================================

class ChatCommandHandler(BaseHTTPRequestHandler):
    """HTTP endpoint for chat commands."""

    agent = None  # Set by main

    def do_POST(self):
        if self.path != "/command":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}

        command = data.get("command", "").lower()
        response = {}

        if command == "status":
            mode = "syslog" if self.config.syslog_enabled else "jsonl"
            response = {"status": "running", "mode": mode}
        elif command == "stats":
            if self.agent and self.agent.learner:
                response = self.agent.learner.get_stats()
            else:
                response = {"error": "no data"}
        elif command == "topblocked":
            if self.agent and self.agent.learner:
                stats = self.agent.learner.get_stats()
                response = stats.get("top_blocked_sources", {})
            else:
                response = {}
        elif command == "vllm_health":
            if self.agent and self.agent.vllm_client:
                response = {"vllm": self.agent.vllm_client.health_check()}
            else:
                response = {"vllm": False, "error": "not configured"}
        else:
            response = {"error": f"unknown command: {command}", "help": ["status", "stats", "topblocked", "vllm_health", "help"]}

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        self.do_POST()

    def log_message(self, format, *args):
        pass  # Suppress access logs


# ============================================================
# MAIN AGENT
# ============================================================

class OPNsenseAgent:
    def __init__(self):
        self.config = Config()
        self.learner = PatternLearner(self.config)
        self.detector = AnomalyDetector(self.config, self.learner)
        self.notifier = UserNotifier(self.config)

        self.event_count = 0
        self.anomaly_count = 0
        self.start_time = time.time()
        self.last_save = time.time()
        self.last_learn = time.time()

        # Link notifier back to agent for Discord stats
        self.notifier.agent = self

        # Discord bot
        self.discord_bot = DiscordBot(self.config)
        self.discord_bot.notifier = self.notifier

        # Chat command handler needs config access
        ChatCommandHandler.config = self.config

        # OPNsense API client
        self.opn_client = OPNsenseClient(self.config)

        # vLLM client
        self.vllm_client = VLLMClient(self.config)

        # Syslog listener (built-in UDP)
        self.syslog_listener = SyslogListener(self.config)

        # JSONL reader (used when syslog_listener is NOT active)
        self.jsonl_reader = JSONLReader(self.config)

    def run(self):
        """Run the agent."""
        print("OPNsense Anomaly Detection Agent v2.0")
        print("=" * 50)

        mode = "syslog (built-in UDP)" if self.config.syslog_enabled else "JSONL file"
        print(f"Mode: {mode}")
        if self.config.syslog_enabled:
            print(f"Syslog port: {self.config.syslog_port}")
        else:
            print(f"Events file: {self.config.jsonl_path}")

        # OPNsense API connection test (optional)
        logger.info("Testing OPNsense API connection...")
        self.opn_client.test_connection()

        # vLLM health check (optional)
        if self.vllm_client.enabled:
            self.vllm_client.health_check()
            models = self.vllm_client.list_models()
            if models:
                logger.info(f"vLLM models available: {', '.join(models)}")

        # Start syslog listener if enabled
        if self.config.syslog_enabled:
            if self.syslog_listener.start():
                logger.info("Builtin syslog listener active - events stream directly to detector")
            else:
                logger.warning("Failed to start builtin syslog listener, falling back to JSONL mode")

        # Start Discord bot
        self.discord_bot.start_bot()

        # Start chat command HTTP server
        self._start_chat_server()

        logger.info("Starting anomaly detection loop...")

        while True:
            try:
                # Get events - either from syslog listener or JSONL reader
                events = []
                if self.config.syslog_enabled and self.syslog_listener.running:
                    # Events are handled via UDP directly in the listener
                    # The listener writes to JSONL file; we read from file too
                    # for persistence. For real-time detection, we'd need a queue.
                    events = self.jsonl_reader.read_events(max_events=50)
                    logger.debug(f"Syslog mode: read {len(events)} events from JSONL")
                else:
                    events = self.jsonl_reader.read_events(max_events=50)

                if events:
                    self.event_count += len(events)
                    now = time.time()

                    # Learn patterns
                    if now - self.last_learn >= self.config.learn_interval:
                        self.learner.learn_from_events(events)
                        self.last_learn = now
                        logger.info(f"Learned from {len(events)} events (total learned: {self.event_count})")

                    # Detect anomalies on all events
                    anomalies = self.detector.detect(events)
                    for anomaly in anomalies:
                        self.anomaly_count += 1
                        self.notifier.send_alert(anomaly)
                        self.discord_bot.send_alert(anomaly)

                    # Save patterns periodically
                    if now - self.last_save >= self.config.save_interval:
                        self.learner.save_patterns()
                        self.last_save = now

                    # Print status periodically
                    if self.event_count % 100 == 0:
                        uptime = int(time.time() - self.start_time)
                        mode = "syslog" if self.config.syslog_enabled else "jsonl"
                        listener_stats = self.syslog_listener.get_stats() if self.config.syslog_enabled else {}
                        logger.info(
                            f"Status: {self.event_count} events, "
                            f"{self.anomaly_count} anomalies, "
                            f"uptime: {uptime}s | mode: {mode} | "
                            f"listener events: {listener_stats.get('events_received', 0)}"
                        )

                time.sleep(2)

            except KeyboardInterrupt:
                logger.info("\nShutting down...")
                self.learner.save_patterns()
                self.syslog_listener.stop()
                logger.info(f"Final stats: {self.event_count} events, {self.anomaly_count} anomalies")
                self.discord_bot.stop()
                break
            except Exception as e:
                logger.error(f"Error: {e}", exc_info=True)
                time.sleep(5)

    def _start_chat_server(self):
        """Start HTTP server for chat commands."""
        try:
            server = HTTPServer(("", self.config.chat_port), ChatCommandHandler)
            logger.info(f"Chat command server running on port {self.config.chat_port}")

            def run_server():
                server.serve_forever()

            thread = Thread(target=run_server, daemon=True)
            thread.start()
        except Exception as e:
            logger.warning(f"Could not start chat server on port {self.config.chat_port}: {e}")


if __name__ == "__main__":
    import requests  # Ensure requests is imported for Discord and OPNsense

    agent = OPNsenseAgent()
    agent.run()
