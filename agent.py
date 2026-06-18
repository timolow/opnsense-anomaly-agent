#!/usr/bin/env python3
from __future__ import annotations
"""
OPNsense Anomaly Detection Agent — Orchestrator

Wires together all detection modules:
  parser           → structured events from syslog
  eventdb          → PostgreSQL persistent storage
  attack_detectors → port scan, SYN flood, brute force, probe detection
  statistical_model → z-scores, seasonal baselines, deviation scoring
  geo_lookup       → geographic anomaly detection
  discord_bot      → rich Discord alerts + chat commands
  syslog_listener  → optional built-in UDP syslog receiver

Mode: Syslog — receives UDP syslog, parses, feeds pipeline directly
"""

import os
import sys
import json
import time
import base64
import signal
import logging
import socket
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict
import threading
from threading import Thread, Event, Condition, Lock
from typing import Dict, Any, Optional, List

try:
    import redis as redis_lib
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    import redis
    redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), socket_timeout=2, decode_responses=True)
    redis_client.ping()
except Exception:
    redis_client = None

import requests

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "agent_data"
DATA_DIR.mkdir(exist_ok=True)

# Import submodules
from adaptive_parser import AdaptiveParser
from eventdb import EventDatabase
from attack_detectors import AttackDetector
from statistical_model import StatisticalModel
from geo_lookup import GeoLookup
from discord_bot import DiscordBot
from syslog_listener import SyslogListener
from server import run_server as start_dashboard
from reverse_dns import ReverseDNSResolver
from network_classifier import NetworkClassifier
from state_persistence import StatePersistence
from rule_classifier import RuleClassifier
from system_log_classifier import SystemLogClassifier
from service_monitor import ServiceMonitor
from apprise_notifier import AppriseNotifier
from zenarmor_classifier import ZenArmorClassifier
from ids_signature_analyzer import IDSSignatureAnalyzer


# ── Config ─────────────────────────────────────────────────────────────
class Config:
    """All agent configuration via env vars with .json fallback."""

    def __init__(self):
        self.opnsense = {
            "host": os.getenv("OPN_HOST", "192.168.1.1"),
            "api_key": os.getenv("OPN_API_KEY", ""),
            "api_secret": os.getenv("OPN_API_SECRET", ""),
            "port": int(os.getenv("OPN_PORT", "6666")),
            "verify_ssl": False,
        }
        self.syslog_enabled = os.getenv("SYSLOG_ENABLED", "false").lower() == "true"
        self.syslog_port = int(os.getenv("SYSLOG_UDP_PORT", "1514"))
        self.vllm_base_url = os.getenv("VLLM_BASE_URL", "")
        self.vllm_model = os.getenv("VLLM_MODEL", "QuantTrio/Qwen3.6-35B-A3B-AWQ")
        self.discord_token = os.getenv("DISCORD_TOKEN", "")
        self.discord_channel_id = os.getenv("DISCORD_CHANNEL_ID", "")
        # Apprise multi-platform notifications (optional)
        self.apprise_urls = os.getenv("APPRISE_URLS", "")
        config_path = BASE_DIR / "config.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                d = cfg.get("discord", {})
                if not self.discord_token:
                    self.discord_token = d.get("bot_token", "")
                if not self.discord_channel_id:
                    self.discord_channel_id = d.get("channel_id", "")
            except Exception as e:
                logger.warning("Could not load Discord config: %s", e)
        self.chat_port = int(os.getenv("CHAT_PORT", "8765"))
        # Database
        self.db_host = os.getenv("DB_HOST", "localhost")
        self.db_port = int(os.getenv("DB_PORT", "5432"))
        self.db_name = os.getenv("DB_NAME", "opnsense")
        self.db_user = os.getenv("DB_USER", "opnsense")
        self.db_password = os.getenv("DB_PASSWORD", "opnsense")
        # Geo lookup
        self.geo_db_path = os.getenv("GEO_DB_PATH", str(DATA_DIR / "GeoLite2-Country.mmdb"))
        # Attack thresholds
        self.portscan_window = int(os.getenv("PORTSCAN_WINDOW", "60"))
        self.portscan_threshold = int(os.getenv("PORTSCAN_THRESHOLD", "5"))
        self.syn_window = int(os.getenv("SYN_WINDOW", "60"))
        self.syn_threshold = int(os.getenv("SYN_THRESHOLD", "100"))
        self.auth_window = int(os.getenv("AUTH_WINDOW", "60"))
        self.auth_threshold = int(os.getenv("AUTH_THRESHOLD", "15"))
        self.stat_window = int(os.getenv("STAT_WINDOW", "60"))
        self.stat_zscore = float(os.getenv("STAT_ZSCORE", "3.0"))
        self.stat_deviation = float(os.getenv("STAT_DEVIATION", "0.8"))
        self.geo_anomaly_threshold = int(os.getenv("GEO_ANOMALY_THRESHOLD", "10"))
        # Dedup
        self.dedup_seconds = int(os.getenv("DEDUP_SECONDS", "300"))
        # Reverse DNS
        # Reverse DNS (persistent cache via Redis)
        self.reverse_dns_enabled = os.getenv("REVERSE_DNS_ENABLED", "false").lower() == "true"
        self.reverse_dns_server = os.getenv("REVERSE_DNS_SERVER", "")
        self.reverse_dns_cache_ttl = int(os.getenv("REVERSE_DNS_CACHE_TTL", "3600"))
        self.reverse_dns_static_map = os.getenv("REVERSE_DNS_STATIC_MAP", "")
        self.redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        # Polling
        self.poll_interval = int(os.getenv("POLL_INTERVAL", "2"))
        self.batch_size = int(os.getenv("BATCH_SIZE", "50"))
        self.learn_interval = int(os.getenv("LEARN_INTERVAL", "300"))
        # Network classification (WAN/LAN detection)
        # Comma-separated list of known WAN IPs (your external IPs)
        self.wan_ips_str = os.getenv("WAN_IPS", "")
        # Comma-separated list of known LAN IP ranges (CIDR or individual)
        self.lan_ips_str = os.getenv("LAN_IPS", "")
        # Comma-separated list of VPN networks (CIDR)
        self.vpn_ips_str = os.getenv("VPN_IPS", "")
        # Custom interface-to-class mapping: "iface=class,iface2=class2"
        self.custom_interfaces_str = os.getenv("CUSTOM_INTERFACES", "")
        self.network_auto_discover = os.getenv("NETWORK_AUTO_DISCOVER", "true").lower() == "true"
        
        # WAN flap detection
        from wan_flap_detector import WANFlapDetector
        self.wan_flap_detector = WANFlapDetector()
        self.last_gateway_states = {}


# ── vLLM client (optional) ─────────────────────────────────────────────
class VLLMClient:
    """Optional LLM-based anomaly analysis via vLLM server."""

    def __init__(self, config: Config):
        self.config = config
        self.enabled = bool(config.vllm_base_url)
        self.base_url = config.vllm_base_url.rstrip("/")
        self.model = config.vllm_model

    def health_check(self) -> bool:
        if not self.enabled:
            logger.info("vLLM not configured (set VLLM_BASE_URL)")
            return False
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=5)
            if resp.status_code == 200:
                logger.info("vLLM server healthy at %s", self.base_url)
                return True
        except Exception as e:
            logger.warning("vLLM health check failed: %s", e)
        return False

    def analyze_anomaly(self, event: dict, attack_type: str, context: str = "") -> str | None:
        if not self.enabled:
            return None
        try:
            resp = requests.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a network security analyst."},
                        {"role": "user", "content": (
                            f"Anomaly detected: type={attack_type}\n"
                            f"Event: {json.dumps(event, default=str)}\n"
                            f"Context: {context}\n"
                            "Provide a brief analysis and severity assessment."
                        )},
                    ],
                    "max_tokens": 128,
                    "temperature": 0.1,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning("vLLM analysis failed: %s", e)
        return None


# ── OPNsense API client ────────────────────────────────────────────────
class OPNsenseClient:
    """Requests-based OPNsense API client for status lookups."""

    def __init__(self, config: Config):
        self.config = config
        self.base_url = f"https://{config.opnsense['host']}:{config.opnsense['port']}"

    def _auth_headers(self):
        creds = f"{self.config.opnsense['api_key']}:{self.config.opnsense['api_secret']}"
        return {
            "Authorization": f"Basic {base64.b64encode(creds.encode()).decode()}",
            "Accept": "application/json",
            "User-Agent": "opnsense-agent/1.0",
        }

    def test_connection(self) -> bool:
        try:
            resp = requests.get(
                f"{self.base_url}/api/core/firmware/status",
                headers=self._auth_headers(),
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200:
                ver = resp.json().get("os_version", "unknown")
                logger.info("Connected to OPNsense %s", ver)
                return True
        except Exception as e:
            logger.warning("OPNsense API connection failed: %s", e)
        return False
    
    def fetch_rules(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all firewall rules from OPNsense API and index by UUID."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/firewall/filter/search_rule",
                headers=self._auth_headers(),
                timeout=30,
                verify=False,
            )
            if resp.status_code != 200:
                logger.warning("OPNsense firewall rules fetch failed: HTTP %d", resp.status_code)
                return {}
            
            data = resp.json()
            rules_list = data.get("rows", [])
            rules_by_uuid: Dict[str, Dict[str, Any]] = {}
            
            for rule in rules_list:
                rule_uuid = rule.get("uuid", "")
                rule_short_id = rule.get("id", "")
                
                # Index by full UUID
                if rule_uuid:
                    rules_by_uuid[rule_uuid] = rule
                
                # Also index by short ID for partial matching
                if rule_short_id and rule_short_id not in rules_by_uuid:
                    rules_by_uuid[rule_short_id] = rules_by_uuid.get(rule_uuid, rule)
            
            logger.info("Fetched %d firewall rules from OPNsense, indexed %d by UUID", 
                       len(rules_list), len(rules_by_uuid))
            return rules_by_uuid
        except Exception as e:
            logger.error("OPNsense firewall rules fetch failed: %s", e)
            return {}
    
    def build_rule_name_mapping(self, rules: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
        """Build a mapping from rule UUID to human-readable name from API."""
        name_map: Dict[str, str] = {}
        
        for uuid_or_id, rule in rules.items():
            try:
                # Use source_net as the human-readable rule name
                source_net = rule.get("source_net", "")
                if source_net:
                    name_map[uuid_or_id] = source_net
                # Also map by short ID if available
                rule_id = rule.get("id", "")
                if rule_id and rule_id != uuid_or_id:
                    name_map[rule_id] = source_net or f"Rule {rule_id}"
            except Exception as e:
                logger.debug("Failed to get rule name for %s: %s", uuid_or_id, e)
                continue
        
        logger.info("Built rule name mapping from API: %d rules", len(name_map))
        return name_map


# ── HTTP chat command server ───────────────────────────────────────────
def _start_chat_server(agent: OPNsenseAgent, port: int) -> Thread:
    """Start HTTP server for chat commands."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        agent_ref = None  # set below on construction

        def _send(self, code: int, obj: dict):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(obj).encode())

        def do_POST(self):
            if self.path != "/command":
                self._send(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {}
            cmd = data.get("command", "").lower()
            self._send(200, self._handle(cmd))

        def do_GET(self):
            self.do_POST()

        def _handle(self, cmd: str):
            a = self.agent_ref
            if cmd == "status":
                mode = "syslog" if a.config.syslog_enabled else "direct"
                return {"status": "running", "mode": mode}
            elif cmd == "stats":
                return {
                    "event_count": a.event_count,
                    "anomaly_count": a.anomaly_count,
                    "uptime": int(time.time() - a.start_time),
                }
            elif cmd == "topblocked":
                return a._get_top_blocked()
            elif cmd == "vllm_health":
                return {"vllm": a.vllm_client.enabled}
            else:
                return {"error": f"unknown command: {cmd}", "help": ["status", "stats", "topblocked", "vllm_health"]}

        def log_message(self, *args, **kwargs):
            pass  # suppress

    server = http.server.HTTPServer(("", port), Handler)
    Handler.agent_ref = agent
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Chat command server running on port %s", port)
    return thread


# ── Orchestrator ───────────────────────────────────────────────────────
class OPNsenseAgent:
    """Main orchestrator — wires all modules into a processing pipeline."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

        # Sub-modules
        # In-memory event buffer and condition for callback → main loop signal
        self._event_cond = Condition()
        self._event_buffer: list[dict] = []

        # DB connection with retry (postgres may take 5-10s to initialize)
        self.db = None
        for attempt in range(1, 11):
            try:
                self.db = EventDatabase(
                    host=self.config.db_host,
                    port=self.config.db_port,
                    database=self.config.db_name,
                    user=self.config.db_user,
                    password=self.config.db_password,
                )
                self.db.ensure_tables()
                self.db.ensure_indexes()
                self.db.ensure_hostnames_migration()
                logger.info("Connected to PostgreSQL %s:%s (%s)", self.config.db_host, self.config.db_port, self.config.db_name)
                break
            except Exception as e:
                logger.warning("PostgreSQL attempt %d/10 failed: %s", attempt, e)
                if attempt == 10:
                    logger.error("PostgreSQL connection failed after 10 attempts — agent cannot run without DB")
                    raise
                time.sleep(3)
        assert self.db is not None  # type: ignore[unreachable]
        self.stat_model = StatisticalModel(window_minutes=self.config.stat_window)
        self.geo_lookup = GeoLookup(db_path=self.config.geo_db_path)
        
        # Attack detector with built-in dedup
        self.attack_detector = AttackDetector(
            dedup_seconds=self.config.dedup_seconds,
            config={
                'port_scan_window': self.config.portscan_window,
                'port_scan_threshold': self.config.portscan_threshold,
                'syn_flood_window': self.config.syn_window,
                'syn_flood_threshold': self.config.syn_threshold,
                'brute_force_window': self.config.auth_window,
                'brute_force_threshold': self.config.auth_threshold,
            },
        )

        # vLLM (optional)
        self.vllm_client = VLLMClient(self.config)

        # Syslog listener (built-in UDP)
        self.syslog_listener = SyslogListener(self.config, event_callback=self._on_event)

        # Discord bot
        self.discord_bot = DiscordBot(self.config)
        # Wire up the agent so /status and other commands work
        self.discord_bot.set_agent(self)

        # Apprise notifier (multi-platform notifications)
        self.apprise_notifier = AppriseNotifier(self.config.apprise_urls)

        # OPNsense API client
        self.opn_client = OPNsenseClient(self.config)
        
        # Fetch firewall rules and build name mapping from API
        self.rules_mapping: Dict[str, str] = {}
        try:
            rules = self.opn_client.fetch_rules()
            # Build rule name mapping using source_net from API
            self.rules_mapping = self.opn_client.build_rule_name_mapping(rules)
            if self.rules_mapping:
                logger.info("Built rule name mapping: %d rules", len(self.rules_mapping))
        except Exception as e:
            logger.error("Failed to fetch firewall rules: %s", e)

        # Chat command server
        self.chat_thread = _start_chat_server(self, self.config.chat_port)

        # Dashboard API server (runs on port 8766, reads from PostgreSQL)
        dashboard_thread = Thread(target=start_dashboard, kwargs={"port": 8766}, daemon=True)
        dashboard_thread.start()
        logger.info("Dashboard API server started on port 8766")

        # Adaptive parser instance
        self.adaptive_parser = AdaptiveParser()
        
        # Reverse DNS resolver (persistent cache via Redis + static map)
        self.reverse_dns = ReverseDNSResolver(
            dns_server=self.config.reverse_dns_server,
            enabled=self.config.reverse_dns_enabled,
            cache_ttl=self.config.reverse_dns_cache_ttl,
            redis_url=self.config.redis_url,
            static_map_file=self.config.reverse_dns_static_map or None,
        )

        # Network classification (WAN/LAN/VPN detection) — per-IP auto-discovery
        # Config: OWN_WAN_IPS (your WAN addresses), LAN_IPS, VPN_IPS, CUSTOM_INTERFACES
        self.network_classifier = NetworkClassifier()

        # Counters
        self.event_count = 0
        self.anomaly_count = 0
        self.start_time = time.time()
        self.last_save = time.time()
        self.last_learn = time.time()
        self.last_status = time.time()
        self.last_syslog_anomaly_check = time.time()
        self.last_wan_flap_check = time.time()
        self._adapt_cycle = 0

        # Shutdown
        self._shutdown = Event()
        
        # State persistence
        self.persistence = StatePersistence()
        self.rule_classifier = RuleClassifier()
        self.system_log_classifier = SystemLogClassifier()
        # Service monitor — DHCP, Unbound, NTP, OpenVPN, WireGuard
        self.service_monitor = ServiceMonitor(None)
        self.service_monitor.load()
        
        # ZenArmor policy classifier — tracks security gateway policies
        self.zenarmor_classifier = ZenArmorClassifier()
        self.zenarmor_classifier.load_state()
        
        # IDS signature analyzer — tracks IDS/Snort/Suricata signatures
        self.ids_analyzer = IDSSignatureAnalyzer()
        self.ids_analyzer.load_state()
        
        # State persistence
        self.persistence.load(self)
        
        # Startup health checks
        self._check_startup_health()
        self._start_maintenance_thread()

    def _check_startup_health(self):
        """Verify connectivity to critical services before starting."""
        logger.info("Running startup health checks...")
        
        # Check Database
        max_retries = 5
        for i in range(max_retries):
            if self.db:
                try:
                    self.db.connect()
                    logger.info("Database connection successful")
                    break
                except Exception as e:
                    if i == max_retries - 1:
                        logger.error(f"Database connection failed after {max_retries} attempts: {e}")
                    time.sleep(2)
            else:
                break
        
        # Check Redis (if enabled)
        if redis_client:
            for i in range(max_retries):
                try:
                    redis_client.ping()
                    logger.info("Redis connection successful")
                    break
                except Exception as e:
                    if i == max_retries - 1:
                        logger.warning(f"Redis connection failed: {e}")
                    time.sleep(2)
        
        # Check OPNsense API
        try:
            self.opn_client.test_connection()
            logger.info("OPNsense API connection successful")
        except Exception as e:
            logger.warning(f"OPNsense API connection failed: {e} (will retry during operation)")
        
        logger.info("Startup health checks complete")

    def _start_maintenance_thread(self):
        """Start background thread for periodic maintenance tasks."""
        def maintenance_loop():
            while not self._shutdown.is_set():
                try:
                    # Prune old events from database (keep 30 days)
                    self._prune_events()
                except Exception as e:
                    logger.warning(f"Maintenance task failed: {e}")
                self._shutdown.wait(3600)  # Run every hour
        
        t = threading.Thread(target=maintenance_loop, daemon=True)
        t.start()
        logger.info("Background maintenance thread started")

    def _prune_events(self):
        """Prune old events from the database to prevent unlimited growth."""
        try:
            if self.db:
                conn = self.db.connect()
                if conn:
                    cur = conn.cursor()
                    # Delete events older than 30 days
                    cur.execute("DELETE FROM events WHERE timestamp < NOW() - INTERVAL '30 days'")
                    deleted = cur.rowcount
                    conn.commit()
                    cur.close()
                    if deleted > 0:
                        logger.info(f"Pruned {deleted} old events from database")
        except Exception as e:
            logger.error(f"Event pruning failed: {e}")

    # ── event callback (from syslog listener thread) ─────────────────
    def _on_event(self, event: dict):
        """Callback from syslog listener — adds event to in-memory buffer."""
        with self._event_cond:
            self._event_buffer.append(event)
            self._event_cond.notify()

    # ── helpers ──────────────────────────────────────────────────────
    def _process_event(self, event: dict):
        """Single-event pipeline: classify → reverse DNS → store → stat model → attack detectors → geo → alert."""
        event["processed_at"] = datetime.now(timezone.utc).isoformat()
        
        # Map parser 'ruid' to PG column 'rule_name' (the CSV field at position 3)
        if 'ruid' in event:
            ruid = event.pop('ruid')
            # Look up human-readable rule name from OPNsense API mapping
            rule_name = self.rules_mapping.get(ruid, ruid)
            event['rule_name'] = rule_name
        
        # Tag event with log_type for DB storage
        log_type = event.get('log_type', '')
        event['log_type'] = log_type
        
        # Network classification: track IPs and classify event (per-IP auto-discovery)
        if self.network_classifier is not None:
            event = self.network_classifier.record_event(event)
        
        # Reverse DNS lookup (before storing/enriching)
        if self.reverse_dns.enabled:
            for field in ("src_ip", "dst_ip"):
                ip = event.get(field)
                if ip:
                    hostname = self.reverse_dns.lookup(ip)
                    if hostname:
                        event[f"{field}_hostname"] = hostname

        # Store in DB (includes log_type column)
        self.db.insert_event(event)
        
        # System log classifier — learns all events, especially system/non-firewall logs
        self.system_log_classifier.process_event(event)
        
        # System log anomaly detection
        # We batch-check system log anomalies every learn_interval to avoid overhead
        now = time.time()
        if now - self.last_syslog_anomaly_check >= self.config.learn_interval:
            self._check_system_log_anomalies()
            self.last_syslog_anomaly_check = now

        # Rule-based learning (firewall rules only)
        self.rule_classifier.process_event(event)

        # ZenArmor policy classifier — tracks security gateway policies
        log_type = event.get('log_type', '')
        if log_type == 'zenarmor':
            self.zenarmor_classifier.process_event(event)
        
        # IDS signature analyzer — tracks IDS/Snort/Suricata signatures
        if log_type == 'ids':
            self.ids_analyzer.process_event(event)

        # Service monitor — DHCP, Unbound, NTP, OpenVPN, WireGuard
        self.service_monitor.process_event(event)

        # Statistical model
        self.stat_model.add_event(event)

        # Attack detectors (dedup is built-in)
        attacks = self.attack_detector.check_event(event)
        if attacks:
            for attack in attacks:
                attack.setdefault("timestamp", event.get("timestamp", ""))
                self.anomaly_count += 1
                llm_analysis = None
                if self.vllm_client.enabled:
                    llm_analysis = self.vllm_client.analyze_anomaly(
                        event, attack.get("attack_type", ""), attack.get("description", "")
                    )
                self.discord_bot.send_alert(attack, llm_analysis=llm_analysis)
                # Apprise notifier (multi-platform)
                self.apprise_notifier.send_alert(attack)

        # Geo lookup
        geo_result = self.geo_lookup.check_event(event)
        if geo_result:
            self.anomaly_count += 1
            self.discord_bot.send_alert(geo_result)
            self.apprise_notifier.send_alert(geo_result)

        # Track geo anomalies
        if geo_result and geo_result.get("type") == "geo_country_anomaly":
            cc = geo_result.get("country_code", "XX")
            logger.info(
                "New country detected: %s — %s events", cc, self.geo_lookup.country_events.get(cc, 0)
            )

    def _process_batch(self, events: list[dict]):
        """Process a batch of events."""
        for event in events:
            try:
                self._process_event(event)
            except Exception as e:
                logger.warning("Error processing event: %s", e)
        self.event_count += len(events)

    def _get_top_blocked(self) -> dict:
        """Return top blocked source IPs."""
        # Read from eventdb if available, otherwise from local counts
        return {}

    def _check_system_log_anomalies(self):
        """Check system log classifier for anomalies and send alerts."""
        anomalies = self.system_log_classifier.detect_anomalies()
        if not anomalies:
            return
        
        for anomaly in anomalies:
            self.anomaly_count += 1
            logger.info("System log anomaly: %s — %s", anomaly.get('type'), anomaly.get('description'))
            self.discord_bot.send_alert(anomaly)
            self.apprise_notifier.send_alert(anomaly)

    def _check_service_anomalies(self):
        """Check service monitor for anomalies and send alerts."""
        anomalies = self.service_monitor.check_all()
        if not anomalies:
            return
        
        for anomaly in anomalies:
            self.anomaly_count += 1
            logger.info("Service anomaly: %s — %s", anomaly.get('type'), anomaly.get('description'))
            self.discord_bot.send_alert(anomaly)
            self.apprise_notifier.send_alert(anomaly)
    
    def _check_wan_flaps(self):
        """Check OPNsense gateway states for flapping and send alerts."""
        import urllib.request
        import ssl
        import json
        import base64
        
        # Fetch gateway states from OPNsense API
        try:
            host = os.getenv("OPN_HOST", "192.168.1.1")
            port = int(os.getenv("OPN_PORT", "6666"))
            opn_url = f"https://{host}:{port}"
            
            key = os.getenv("OPN_API_KEY", "")
            secret = os.getenv("OPN_API_SECRET", "")
            if not key or not secret:
                return
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            auth_string = f"{key}:{secret}"
            auth_b64 = base64.b64encode(auth_string.encode()).decode()
            auth_header = f"Basic {auth_b64}"
            
            # Fetch gateway settings
            req = urllib.request.Request(
                f"{opn_url}/api/routing/settings/searchGateway",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                gw_data = json.loads(resp.read().decode())
            
            rows = gw_data.get("rows", gw_data.get("gateways", []))
            
            for gw in rows:
                if gw.get("disabled"):
                    continue
                name = gw.get("name", gw.get("id", "unknown"))
                interface = gw.get("if", gw.get("interface", ""))
                state = gw.get("state", gw.get("status", "unknown"))
                
                # Determine if this is a WAN gateway
                is_wan = gw.get("upstream", False) or (not gw.get("vpn_gateway", False) and interface)
                if not is_wan:
                    continue
                
                # Normalize state
                if state.lower() in ("up", "online", "active", "running"):
                    new_state = "up"
                elif state.lower() in ("down", "offline", "inactive", "disconnected"):
                    new_state = "down"
                else:
                    continue
                
                old_state = self.last_gateway_states.get(name)
                if old_state is not None:
                    alert = self.wan_flap_detector.check_gateway_state(name, old_state, new_state)
                    if alert:
                        self.anomaly_count += 1
                        logger.warning("WAN flap detected: %s — %s", name, alert['description'])
                        self.discord_bot.send_alert(alert)
                        self.apprise_notifier.send_alert(alert)
                
                self.last_gateway_states[name] = new_state
                
        except Exception as e:
            logger.error("WAN flap check failed: %s", e)

    def _check_zenarmor_anomalies(self):
        """Check ZenArmor classifier for anomalies and send alerts."""
        anomalies = self.zenarmor_classifier.detect_anomalies()
        if not anomalies:
            return
        
        for anomaly in anomalies:
            self.anomaly_count += 1
            logger.info("ZenArmor anomaly: %s — %s", anomaly.get('type'), anomaly.get('description'))
            self.discord_bot.send_alert(anomaly)
            self.apprise_notifier.send_alert(anomaly)

    def _check_ids_anomalies(self):
        """Check IDS analyzer for anomalies and send alerts."""
        anomalies = self.ids_analyzer.detect_anomalies()
        if not anomalies:
            return
        
        for anomaly in anomalies:
            self.anomaly_count += 1
            logger.info("IDS anomaly: %s — %s", anomaly.get('type'), anomaly.get('description'))
            self.discord_bot.send_alert(anomaly)
            self.apprise_notifier.send_alert(anomaly)

    def _send_status(self):
        """Log periodic status."""
        uptime = int(time.time() - self.start_time)
        mode = "syslog" if self.config.syslog_enabled else "direct"
        stats = self.stat_model.get_stats()
        dns_stats = self.reverse_dns.get_stats() if self.reverse_dns.enabled else None
        net_parts = []
        if self.network_classifier is not None:
            net_s = self.network_classifier.get_stats()
            net_parts.append(
                f"own_wan={net_s.get('own_wan_ips_count', 0)}, "
                f"ext_wan={net_s.get('wan_ips_count', 0)}"
            )
        extra = " | ".join(net_parts) + (
            f" | reverse_dns: resolves={dns_stats['resolve_count']} misses={dns_stats['miss_count']}"
            if dns_stats else ""
        )
        logger.info(
            "Status: %s events, %s anomalies, uptime: %ds | mode: %s | "
            "unique_ips: %s | ports_tracked: %s | country_events: %s%s",
            self.event_count,
            self.anomaly_count,
            uptime,
            mode,
            stats.get("unique_ips", 0),
            stats.get("unique_ports", 0),
            stats.get("country_events", 0),
            f" | {extra}" if extra else "",
        )

    def _periodic_adapt(self):
        """Every N learn cycles, sample raw logs and let the adaptive parser discover new patterns."""
        logger.info("Running periodic adaptation check...")
        with self._event_cond:
            samples = [e.get("raw", "") for e in self._event_buffer if e.get("raw")]
        if samples:
            report = self.adaptive_parser.adapt(samples)
            logger.info("Adaptation report: %s", report)

    # ── main loop ────────────────────────────────────────────────────
    def run(self):
        """Start the agent."""
        print("OPNsense Anomaly Detection Agent v2.0")
        print("=" * 50)

        mode = "syslog (built-in UDP)" if self.config.syslog_enabled else "direct"
        print(f"Mode: {mode}")
        if self.config.syslog_enabled:
            print(f"Syslog port: {self.config.syslog_port}")

        # OPNsense API connection test
        logger.info("Testing OPNsense API connection...")
        self.opn_client.test_connection()

        # vLLM health check (optional)
        if self.vllm_client.enabled:
            logger.info("vLLM enabled, checking health...")
            self.vllm_client.health_check()

        # Start syslog listener
        if self.config.syslog_enabled:
            if self.syslog_listener.start():
                logger.info("Builtin syslog listener active")
            else:
                logger.warning("Failed to start syslog listener, falling back to JSONL")

        # Start Discord bot
        self.discord_bot.start_bot()

        # Start chat command server (already started in __init__)
        logger.info("Chat command server running on port %s", self.config.chat_port)

        logger.info("Starting anomaly detection loop...")

        while not self._shutdown.is_set():
            try:
                with self._event_cond:
                    if not self._event_buffer:
                        self._event_cond.wait(timeout=self.config.poll_interval)
                    events = self._event_buffer[:self.config.batch_size]
                    del self._event_buffer[:len(events)]

                if events:
                    now = time.time()
                    # Learn patterns
                    if now - self.last_learn >= self.config.learn_interval:
                        self.stat_model.learn(events)
                        self.last_learn = now
                        logger.info("Learned from %s events (total: %s)", len(events), self.event_count)

                        # Periodic adaptation: every 3 learn cycles, re-analyze raw patterns
                        self._adapt_cycle += 1
                        if self._adapt_cycle >= 3:
                            self._periodic_adapt()
                            self._adapt_cycle = 0

                    # Detect anomalies on all events
                    self._process_batch(events)
                    
                    # Check WAN flap detection periodically
                    if now - self.last_wan_flap_check >= self.config.learn_interval:
                        self.last_wan_flap_check = now
                        try:
                            self._check_wan_flaps()
                        except Exception as e:
                            logger.warning("WAN flap check failed: %s", e)

                    # Check ZenArmor policy anomalies periodically
                    if now - self.last_syslog_anomaly_check >= self.config.learn_interval:
                        try:
                            self._check_zenarmor_anomalies()
                            self._check_ids_anomalies()
                        except Exception as e:
                            logger.warning("ZenArmor/IDS anomaly check failed: %s", e)

                    # Save state periodically (every learn_interval, alongside baseline save)
                    if now - self.last_save >= self.config.learn_interval:
                        self.last_save = now
                        # Get baseline summary to persist
                        baseline_summary = self.stat_model.get_baseline_summary()
                        self.db._save_baselines(baseline_summary)
                        # Persist all ML/tracking state to JSON file
                        self.persistence.save(self)
                        self.service_monitor.save()
                        self.zenarmor_classifier.save_state()
                        self.ids_analyzer.save_state()

                    # Periodic status (time-based every 60s)
                    now = time.time()
                    if now - self.last_status >= 60:
                        self.last_status = now
                        try:
                            self._send_status()
                        except Exception as e:
                            logger.warning("Status log failed: %s", e)

                time.sleep(self.config.poll_interval)

            except KeyboardInterrupt:
                logger.info("\nShutting down...")
                self.syslog_listener.stop()
                self._send_status()
                self.discord_bot.stop()
                self._shutdown.set()
                break
            except Exception as e:
                logger.error("Error in main loop: %s", e, exc_info=True)
                time.sleep(5)

    def shutdown(self):
        """Clean shutdown."""
        self._shutdown.set()
        self.syslog_listener.stop()
        self._send_status()
        self.discord_bot.stop()


# ── Main ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="OPNsense Anomaly Detection Agent")
    parser.add_argument("--config", type=str, default=None, help="Path to config.json")
    parser.add_argument("--portscan-window", type=int, default=None)
    parser.add_argument("--syn-threshold", type=int, default=None)
    args, unknown = parser.parse_known_args()

    cfg = Config()
    agent = OPNsenseAgent(cfg)
    agent.run()


if __name__ == "__main__":
    main()
