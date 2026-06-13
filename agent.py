#!/usr/bin/env python3
"""
OPNsense Anomaly Detection Agent
Reads firewall events from JSONL file written by syslog_listener.
Detects anomalies, sends Discord alerts, responds to chat commands.
"""

import os
import sys
import json
import time
import logging
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
            # Use file size to detect new data (much faster than reading entire file)
            current_size = self.config.jsonl_path.stat().st_size
            if hasattr(self, '_file_size') and current_size == self._file_size:
                return events
            self._file_size = current_size
            
            # Track absolute byte positions to avoid seek+iteration conflict
            with open(self.config.jsonl_path, 'r') as f:
                # Read line by line, skipping to last_line
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
                        # Only process filterlog entries (have src_ip and proto)
                        if event.get("src_ip") and event.get("proto"):
                            event["_read_time"] = datetime.now().isoformat()
                            event["_line_number"] = read_line_num
                            events.append(event)
                            count += 1
                            if count >= max_events:
                                break
                    except json.JSONDecodeError:
                        pass
                # Save current position
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
            "known_ips": defaultdict(int),      # IP -> frequency
            "known_ports": defaultdict(int),     # port -> frequency
            "known_protocols": defaultdict(int), # proto -> frequency
            "event_rate": defaultdict(int),      # minute_key -> count
            "failed_connections": defaultdict(int), # minute_key -> count
            "source_to_dest": defaultdict(set),  # src -> set of dest_ips
            "new_sources_window": deque(),       # recent new sources
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
            
            # Count IP frequencies
            if src_ip:
                self.patterns["known_ips"][src_ip] += 1
                self.patterns["source_to_dest"][src_ip].add(dst_ip)
            
            if dst_ip:
                self.patterns["known_ips"][dst_ip] += 1
                
            # Count port frequencies
            if dst_port:
                self.patterns["known_ports"][int(dst_port)] += 1
                
            # Count protocol frequencies
            if proto:
                self.patterns["known_protocols"][proto] += 1
                
            # Track event rates
            self.patterns["event_rate"][minute_key] += 1
            
            # Track failed connections
            if action in ("block", "drop", "deny", "reject"):
                self.patterns["failed_connections"][minute_key] += 1
                
            # Track new sources
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
            
            # Check for new source IPs
            if src_ip and self.patterns["known_ips"][src_ip] < self.config.thresholds["new_source_ip"]:
                anomalies.append({
                    "type": "new_source_ip",
                    "severity": "low",
                    "details": f"New/rare source IP: {src_ip} (count: {self.patterns['known_ips'][src_ip]})",
                    "event": event,
                })
            
            # Check for unusual ports
            if dst_port:
                port_count = self.patterns["known_ports"].get(int(dst_port), 0)
                if port_count < 5:
                    anomalies.append({
                        "type": "unusual_port",
                        "severity": "low",
                        "details": f"Uncommon destination port: {dst_port} (count: {port_count})",
                        "event": event,
                    })
            
            # Check for high failed connection rate
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
                            # Preserve defaultdict type so .get() and [] work correctly
                            self.patterns[key] = defaultdict(int, value)
                        else:
                            self.patterns[key] = defaultdict(int, value)
                    elif isinstance(value, dict):
                        # When loaded from JSON as a dict, restore defaultdict type
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
                            "192.168.",
                            "10.",
                            "172.16.",
                            "172.17.",
                            "172.18.",
                            "172.19.",
                            "172.20.",
                            "172.21.",
                            "172.22.",
                            "172.23.",
                            "172.24.",
                            "172.25.",
                            "172.26.",
                            "172.27.",
                            "172.28.",
                            "172.29.",
                            "172.30.",
                            "172.31.",
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
            # Cooldown: don't notify same anomaly within 300 seconds
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
    
    def send_alert(self, anomaly):
        """Send an anomaly alert to Discord channel."""
        if not self.discord_token or not self.discord_channel_id:
            return
        
        severity = anomaly["severity"].upper()
        atype = anomaly["type"]
        details = anomaly["details"]
        event = anomaly.get("event", {})
        
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
                "content": f"🚨 OPNsense Alert: {atype} - {severity}"
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
            
            # Chat commands
            if content.startswith("!status"):
                await message.channel.send("📊 **OPNsense Agent Status**\n`Running - reading events`")
            
            elif content.startswith("!stats"):
                if self.notifier and self.notifier.agent:
                    stats = self.notifier.agent.learner.get_stats()
                    msg = (
                        f"📊 **Agent Stats**\n"
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
                        msg = "🔒 **Top Blocked Sources**\n" + "\n".join(lines)
                    else:
                        msg = "No blocked sources detected yet"
                    await message.channel.send(msg)
                else:
                    await message.channel.send("No data available yet")
            
            elif content.startswith("!help"):
                await message.channel.send(
                    "📋 **Commands**\n"
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
            response = {"status": "running", "mode": "jsonl"}
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
        else:
            response = {"error": f"unknown command: {command}", "help": ["status", "stats", "topblocked", "help"]}
        
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
        self.jsonl_reader = JSONLReader(self.config)
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
    
    def run(self):
        """Run the agent."""
        print("OPNsense Anomaly Detection Agent v2.0")
        print("=" * 50)
        print(f"Mode: JSONL event stream (syslog_listener)")
        print(f"Events file: {self.config.jsonl_path}")
        
        # Test OPNsense API connection (optional, for status lookups)
        logger.info("Testing OPNsense API connection...")
        client = OPNsenseClient(self.config)
        client.test_connection()
        
        # Start Discord bot
        self.discord_bot.start_bot()
        
        # Start chat command HTTP server
        self._start_chat_server()
        
        logger.info("Starting anomaly detection loop...")
        logger.info(f"Read marker at line 0 (will read from current file end)")
        
        while True:
            try:
                # Read events from JSONL
                events = self.jsonl_reader.read_events(max_events=50)
                
                if events:
                    self.event_count += len(events)
                    now = time.time()
                    
                    # Learn patterns every learn_interval seconds
                    if now - self.last_learn >= self.config.learn_interval:
                        self.learner.learn_from_events(events)
                        self.last_learn = now
                        logger.info(f"Learned from {len(events)} events (total learned: {self.event_count})")
                    
                    # Detect anomalies on all events
                    anomalies = self.detector.detect(events)
                    for anomaly in anomalies:
                        self.anomaly_count += 1
                        self.notifier.send_alert(anomaly)
                        # Also send to Discord
                        self.discord_bot.send_alert(anomaly)
                    
                    # Save patterns periodically
                    if now - self.last_save >= self.config.save_interval:
                        self.learner.save_patterns()
                        self.last_save = now
                    
                    # Print status periodically
                    if self.event_count % 100 == 0:
                        uptime = int(time.time() - self.start_time)
                        logger.info(
                            f"Status: {self.event_count} events, "
                            f"{self.anomaly_count} anomalies, "
                            f"uptime: {uptime}s"
                        )
                
                time.sleep(2)
                
            except KeyboardInterrupt:
                logger.info("\nShutting down...")
                self.learner.save_patterns()
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
