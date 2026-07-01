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
from typing import Dict, Any, Optional, List, Tuple

import requests

# Structured JSON logging
from json_logging import setup_json_logging, get_structured_logger

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "agent_data"
DATA_DIR.mkdir(exist_ok=True)
LOG_FILE_PATH = os.environ.get("LOG_FILE", str(DATA_DIR / "agent.log"))

setup_json_logging(level=logging.INFO, log_file=LOG_FILE_PATH)
logger = logging.getLogger(__name__)
slogger = get_structured_logger(__name__)

# ── Lazy Redis client ──────────────────────────────────────────────────
_redis_client = None
_redis_available = False


def _get_redis_client():
    """Return a Redis client, initializing lazily. Returns None if unavailable."""
    global _redis_client, _redis_available
    if _redis_available and _redis_client is not None:
        return _redis_client
    try:
        import redis
        _redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"),
                                       socket_timeout=3, decode_responses=True)
        _redis_client.ping()
        _redis_available = True
        return _redis_client
    except Exception:
        _redis_available = False
        _redis_client = None
        return None


redis_client = _get_redis_client()  # Initial attempt (cached for backward compat)


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
from flow_classifier import FlowClassifier
from signal_bus import SignalBus
from correlation_engine import CorrelationEngine
from system_log_classifier import SystemLogClassifier
from service_monitor import ServiceMonitor
from apprise_notifier import AppriseNotifier
from zenarmor_classifier import ZenArmorClassifier
from ids_signature_analyzer import IDSSignatureAnalyzer
from nginx_monitor import NginxMonitor
from unifi_monitor import UniFiMonitor
from baseline_engine import BaselineEngine
from anomaly_detector import AnomalyDetector
from threshold_tuner import ThresholdTuner
from concept_drift import ConceptDriftDetector, DriftEvent
from unified_behavioral_engine import UnifiedBehavioralEngine

# P2-6: SSE queue access (imported from server module)
_sse_publish_fn = None

def _get_sse_publisher():
    """Lazily import the SSE publisher from server module."""
    global _sse_publish_fn
    if _sse_publish_fn is None:
        try:
            from server import publish_anomaly_sse
            _sse_publish_fn = publish_anomaly_sse
        except ImportError:
            _sse_publish_fn = lambda x: None  # No-op if server not available
    return _sse_publish_fn


# ── Config ─────────────────────────────────────────────────────────────
class Config:
    """Agent configuration via environment variables.

    All settings are read from env vars (set via .env file or docker-compose).
    No JSON config fallback — see .env.example for all available options.
    """

    def __init__(self):
        self.opnsense = {
            "host": os.getenv("OPN_HOST", "192.168.1.1"),
            "api_key": os.getenv("OPN_API_KEY", ""),
            "api_secret": os.getenv("OPN_API_SECRET", ""),
            "port": int(os.getenv("OPN_PORT", "6666")),
            "verify_ssl": False,
        }
        self.syslog_enabled = os.getenv("SYSLOG_ENABLED", "true").lower() == "true"
        self.syslog_port = int(os.getenv("SYSLOG_UDP_PORT", "1514"))
        self.vllm_base_url = os.getenv("VLLM_BASE_URL", "")
        self.vllm_model = os.getenv("VLLM_MODEL", "QuantTrio/Qwen3.6-35B-A3B-AWQ")
        self.discord_token = os.getenv("DISCORD_TOKEN", "")
        self.discord_channel_id = os.getenv("DISCORD_CHANNEL_ID", "")
        # Apprise multi-platform notifications (optional)
        self.apprise_urls = os.getenv("APPRISE_URLS", "")
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
        # DB retention: configurable via env vars (default 30 days)
        self.db_retention_days = int(os.getenv("DB_RETENTION_DAYS", "7"))
        self.db_retention_incident_days = int(os.getenv("DB_RETENTION_INCIDENT_DAYS", "14"))
        # Reverse DNS
        # Reverse DNS (persistent cache via Redis)
        self.reverse_dns_enabled = os.getenv("REVERSE_DNS_ENABLED", "false").lower() == "true"
        self.reverse_dns_server = os.getenv("REVERSE_DNS_SERVER", "")
        self.reverse_dns_cache_ttl = int(os.getenv("REVERSE_DNS_CACHE_TTL", "3600"))
        self.reverse_dns_static_map = os.getenv("REVERSE_DNS_STATIC_MAP", "")
        self.redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        # Redis Stream consumer group configuration
        self.redis_stream_enabled = os.getenv("REDIS_STREAM_ENABLED", "false").lower() in ("true", "1", "yes")
        self.redis_stream_name = os.getenv("REDIS_STREAM_NAME", "event_ingest")
        self.redis_stream_group = os.getenv("REDIS_STREAM_GROUP", "agent_group")
        self.redis_stream_consumer = os.getenv("REDIS_STREAM_CONSUMER", f"consumer_{os.getpid()}")
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
            # Use OPNsense search_rule API (only endpoint that returns firewall rules)
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
    import os

    class Handler(http.server.BaseHTTPRequestHandler):
        agent_ref = None  # set below on construction

        def _send(self, code: int, obj: dict):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(obj).encode())

        def _send_html(self, html: str):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())

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
            # Serve dashboard
            if self.path == "/dashboard":
                dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "index.html")
                if os.path.exists(dashboard_path):
                    with open(dashboard_path, "r") as f:
                        self._send_html(f.read())
                else:
                    self._send(404, {"error": "dashboard not found"})
                return
            # Serve dashboard assets
            if self.path.startswith("/dashboard/"):
                asset_path = os.path.join(os.path.dirname(__file__), self.path[1:])
                if os.path.exists(asset_path):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/css" if asset_path.endswith(".css") else "application/javascript")
                    self.end_headers()
                    with open(asset_path, "r") as f:
                        self.wfile.write(f.read().encode())
                else:
                    self._send(404, {"error": "asset not found"})
                return
            # API endpoints
            if self.path.startswith("/api/"):
                endpoint = self.path[5:]
                a = self.agent_ref
                if endpoint == "stats":
                    self._send(200, {
                        "event_count": a.event_count,
                        "anomaly_count": a.anomaly_count,
                        "uptime": int(time.time() - a.start_time),
                        "unique_ips": len(a.stat_model._src_ips_per_min),
                        "baselines": len(a.baseline_engine._baselines) if a.baseline_engine else 0,
                        "ip_baselines": len(a.behavior_profiler._ip_baselines) if a.behavior_profiler else 0
                    })
                elif endpoint == "anomalies":
                    # Get recent anomalies from DB
                    conn = None
                    try:
                        conn = a.db.connect()
                        cur = conn.cursor()
                        cur.execute("""
                            SELECT id, type, severity, description, timestamp
                            FROM anomalies ORDER BY id DESC LIMIT 100
                        """)
                        anomalies = []
                        for row in cur.fetchall():
                            anomalies.append({
                                "id": row[0],
                                "type": row[1],
                                "severity": row[2],
                                "description": row[3],
                                "timestamp": str(row[4]) if row[4] else ""
                            })
                        cur.close()
                        self._send(200, {"anomalies": anomalies})
                    except Exception as e:
                        self._send(500, {"error": str(e)})
                    finally:
                        if conn:
                            a.db.putconn(conn)
                elif endpoint == "volume":
                    # Get hourly volume for last 24 hours
                    conn = None
                    try:
                        conn = a.db.connect()
                        cur = conn.cursor()
                        cur.execute("""
                            SELECT DATE_TRUNC('hour', timestamp) as hour, COUNT(*)
                            FROM normalized_events
                            WHERE timestamp > NOW() - INTERVAL '24 hours'
                            GROUP BY hour ORDER BY hour
                        """)
                        volume = []
                        for row in cur.fetchall():
                            volume.append({
                                "hour": str(row[0]),
                                "count": row[1]
                            })
                        cur.close()
                        self._send(200, {"volume": volume})
                    except Exception as e:
                        self._send(500, {"error": str(e)})
                    finally:
                        if conn:
                            a.db.putconn(conn)
                else:
                    self._send(404, {"error": f"unknown endpoint: {endpoint}"})
                return
            # Fallback to command handler
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
        self.logger = logging.getLogger(__name__)

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
                self.db.ensure_tables()  # Creates tables + runs versioned schema migrations
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

        # Resource health monitoring (memory, CPU, DB size, disk)
        try:
            from health_monitor import HealthMonitor
            self.health_monitor = HealthMonitor(self, self.discord_bot, interval=300, alert_cooldown=3600)
            self.health_monitor.start()
            logger.info("Resource health monitor started (interval=300s)")
        except Exception as e:
            logger.warning("Failed to start resource health monitor: %s", e)

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
        self.last_unifi_check = time.time()
        self.last_backup = time.time()
        # Scheduled backups: daily by default, configurable via BACKUP_INTERVAL_SECONDS
        self.backup_interval = int(os.getenv("BACKUP_INTERVAL_SECONDS", "86400"))

        try:
            # Unified behavioral engine replaces ThreatEngine + BehaviorProfiler + BaselineEngine + StatisticalModel
            self.baseline_engine = BaselineEngine(self.db)
            logger.info("Initialized baseline_engine")
            # Initialize threshold auto-tuner (Phase 5)
            self.threshold_tuner = ThresholdTuner(self.db)
            logger.info("Threshold auto-tuner initialized")

            # Initialize anomaly detector with baselines + threshold tuner
            self.anomaly_detector = AnomalyDetector(self.baseline_engine._baselines,
                                                     threshold_tuner=self.threshold_tuner)
            logger.info("Anomaly detector initialized with %d baselines", len(self.baseline_engine._baselines))
        except Exception as e:
            logger.warning("Failed to initialize threat/baseline engines: %s", e)
            self.baseline_engine = None
            self.threshold_tuner = None
            self.anomaly_detector = None
        self._adapt_cycle = 0

        # Incident manager — lifecycle, feedback, grouping for correlated incidents
        try:
            from incident_manager import IncidentManager
            self.incident_manager = IncidentManager(self.db, self.anomaly_detector)
            logger.info("Incident manager initialized")
        except Exception as e:
            logger.warning("Failed to initialize incident manager: %s", e)
            self.incident_manager = None

        # Concept drift detector — monitors traffic distribution changes
        self.drift_detector = ConceptDriftDetector()
        self.last_drift_check = time.time()
        self.last_drift_retrain = time.time()
        logger.info("Concept drift detector initialized")

        # IP behavior profiler — per-IP behavioral profiling with EMA baselines
        try:
            self.behavior_profiler = UnifiedBehavioralEngine(self.db)
            logger.info("IP behavior profiler initialized")
        except Exception as e:
            logger.warning("Failed to initialize behavior profiler: %s", e)
            self.behavior_profiler = None

        # Shutdown
        self._shutdown = Event()
        
        # State persistence
        self.persistence = StatePersistence()
        self.flow_classifier = FlowClassifier()

        # Signal bus — unified signal architecture for all detectors
        self.signal_bus = SignalBus(self.db)

        # Correlation engine — groups signals into incidents
        self.correlation_engine = CorrelationEngine(self.db, signal_bus=self.signal_bus)
        def _on_signal(sig):
            self.correlation_engine.process_signal(sig)
        self.signal_bus.subscribe("all", _on_signal)
        logger.info("Signal bus subscribed: _on_signal callback registered for correlation engine")

        # Auto-resolve stale incidents every 5 minutes via maintenance thread
        # (wired below in _start_maintenance_thread)

        self.system_log_classifier = SystemLogClassifier()
        # Service monitor — DHCP, Unbound, NTP, OpenVPN, WireGuard
        self.service_monitor = ServiceMonitor(None)
        self.service_monitor.load()
        
        # ZenArmor policy classifier — tracks security gateway policies
        self.zenarmor_classifier = ZenArmorClassifier()

        # IDS signature analyzer — tracks IDS/Snort/Suricata signatures
        self.ids_analyzer = IDSSignatureAnalyzer()

        # Nginx web server monitor — tracks requests, detects attacks
        self.nginx_monitor = NginxMonitor(signal_bus=self.signal_bus)
        self.nginx_monitor.db = self.db

        # UniFi controller monitor — polls API for events, clients, devices
        self.unifi_monitor = UniFiMonitor()
        self.unifi_monitor.db = self.db

        # Load consolidated state (covers zenarmor, ids, nginx, unifi + all other modules)
        self.persistence.load(self)
        
        # Redis Stream consumer group — primary event source (P1-T4)
        self._redis_stream_ready = False
        if self.config.redis_stream_enabled:
            self._init_redis_stream()
        else:
            logger.info("Redis Stream consumer disabled (set REDIS_STREAM_ENABLED=true)")
        
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
                conn = None
                try:
                    conn = self.db.connect()
                    logger.info("Database connection successful")
                    break
                except Exception as e:
                    if i == max_retries - 1:
                        logger.error(f"Database connection failed after {max_retries} attempts: {e}")
                    time.sleep(2)
                finally:
                    if conn:
                        self.db.putconn(conn)
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
                    # DB retention: prune old events + resolved incidents
                    self._db_retention_cleanup()
                except Exception as e:
                    logger.warning(f"DB retention cleanup failed: {e}")

                # Scheduled database backup
                now = time.time()
                if now - self.last_backup >= self.backup_interval:
                    try:
                        self._scheduled_backup()
                    except Exception as e:
                        logger.warning(f"Scheduled backup failed: {e}")
                    self.last_backup = now

                # Auto-resolve stale incidents every hour
                try:
                    if self.correlation_engine:
                        resolved = self.correlation_engine.auto_resolve_stale()
                        if resolved:
                            logger.info("Auto-resolved %d stale incidents", resolved)
                except Exception as e:
                    logger.warning("Incident auto-resolve failed: %s", e)

                self._shutdown.wait(3600)  # Run every hour
        
        t = threading.Thread(target=maintenance_loop, daemon=True)
        t.start()
        logger.info("Background maintenance thread started (interval=1h, retention=%d days)", self.config.db_retention_days)

    def _db_retention_cleanup(self):
        """Run full DB retention cleanup: events, anomalies, incidents, drift_events, baselines.

        Uses configurable retention periods from env vars:
          DB_RETENTION_DAYS           — events, anomalies, drift_events, baselines (default 30)
          DB_RETENTION_INCIDENT_DAYS  — resolved incidents (default 30)

        Deletes in dependency order to respect foreign keys (anomalies → events).
        """
        events_days = self.config.db_retention_days
        incident_days = self.config.db_retention_incident_days

        stats = {"events": 0, "anomalies": 0, "drift_events": 0, "baselines": 0, "incidents": 0}

        # ── 1. Anomalies (before events due to FK) ──
        cur = self.db._new_cursor()
        try:
            cur.execute(
                "DELETE FROM anomalies WHERE created_at < NOW() - INTERVAL %s",
                (f"{events_days} days",),
            )
            stats["anomalies"] = cur.rowcount or 0
        except Exception as e:
            logger.warning("Anomaly retention failed: %s", e)
        finally:
            cur.close()

        # ── 2. Events ──
        cur = self.db._new_cursor()
        try:
            cur.execute(
                "DELETE FROM normalized_events WHERE timestamp < NOW() - INTERVAL %s",
                (f"{events_days} days",),
            )
            stats["events"] = cur.rowcount or 0
        except Exception as e:
            logger.warning("Event retention failed: %s", e)
        finally:
            cur.close()

        # ── 3. Resolved incidents (older than retention) ──
        cur = self.db._new_cursor()
        try:
            cur.execute(
                """DELETE FROM incidents
                   WHERE is_active = FALSE
                     AND resolved_at IS NOT NULL
                     AND resolved_at < NOW() - INTERVAL %s""",
                (f"{incident_days} days",),
            )
            stats["incidents"] = cur.rowcount or 0
        except Exception as e:
            logger.warning("Incident retention failed: %s", e)
        finally:
            cur.close()

        # ── 4. Drift events ──
        cur = self.db._new_cursor()
        try:
            cur.execute(
                "DELETE FROM drift_events WHERE timestamp < NOW() - INTERVAL %s",
                (f"{events_days} days",),
            )
            stats["drift_events"] = cur.rowcount or 0
        except Exception as e:
            logger.warning("Drift event retention failed: %s", e)
        finally:
            cur.close()

        # ── 5. Baselines ──
        cur = self.db._new_cursor()
        try:
            cur.execute(
                "DELETE FROM baselines WHERE updated_at < NOW() - INTERVAL %s",
                (f"{events_days} days",),
            )
            stats["baselines"] = cur.rowcount or 0
        except Exception as e:
            logger.warning("Baseline retention failed: %s", e)
        finally:
            cur.close()

        total = sum(stats.values())
        if total > 0:
            logger.info(
                "DB retention cleanup: events=%d anomalies=%d incidents=%d drift=%d baselines=%d (total=%d)",
                stats["events"], stats["anomalies"], stats["incidents"],
                stats["drift_events"], stats["baselines"], total,
            )
            # Run VACUUM ANALYZE on pruned tables to reclaim disk space
            try:
                cur2 = self.db._new_cursor()
                try:
                    cur2.execute("VACUUM ANALYZE events")
                    cur2.execute("VACUUM ANALYZE anomalies")
                    cur2.execute("VACUUM ANALYZE incidents")
                    cur2.execute("VACUUM ANALYZE drift_events")
                    cur2.execute("VACUUM ANALYZE baselines")
                finally:
                    cur2.close()
            except Exception as e:
                logger.warning("VACUUM ANALYZE failed: %s", e)
        else:
            logger.debug("DB retention: nothing to prune (all data within %d days)", events_days)

        return stats

    def _scheduled_backup(self):
        """Run a scheduled in-container backup using psycopg2 COPY."""
        try:
            from backup_restore import quick_backup, cleanup_old_backups
            result = quick_backup()
            if result.get("success"):
                logger.info(f"Scheduled backup completed: {result.get('filename', 'unknown')} ({result.get('size_human', '?')})")
                # Enforce retention after successful backup
                cleanup_result = cleanup_old_backups()
                if cleanup_result["count"] > 0:
                    logger.info(f"Backup cleanup: removed {cleanup_result['count']} old backup(s)")
            else:
                logger.error(f"Scheduled backup failed: {result.get('error', 'unknown')}")
        except Exception as e:
            logger.error(f"Scheduled backup error: {e}")

    # ── Redis Stream consumer group ────────────────────────────────────
    def _init_redis_stream(self):
        """Initialize Redis Stream consumer group. Creates group if missing."""
        rc = _get_redis_client()
        if rc is None:
            logger.warning("Redis unavailable — agent will fall back to in-memory buffer")
            return

        stream = self.config.redis_stream_name
        group = self.config.redis_stream_group
        consumer = self.config.redis_stream_consumer

        try:
            # Create consumer group if it doesn't exist (MKSTREAM=False so we don't
            # blow up if the stream was already created by syslog_listener)
            rc.xgroup_create(stream, group, id="0", mkstream=False)
        except Exception:
            # Group already exists — that's fine
            pass

        self._redis_stream_ready = True
        logger.info(
            "Redis Stream consumer initialized: stream=%s group=%s consumer=%s",
            stream, group, consumer,
        )

    def _read_redis_batch(self, block_ms: int = 2000, count: int = 50) -> list[dict]:
        """Read a batch of events from the Redis Stream consumer group.

        Returns a list of parsed event dicts.  Falls back to the in-memory
        buffer if Redis is unavailable.
        """
        # Fast-path: try Redis first if enabled
        if self._redis_stream_ready:
            rc = _get_redis_client()
            if rc is not None:
                stream = self.config.redis_stream_name
                group = self.config.redis_stream_group
                consumer = self.config.redis_stream_consumer
                try:
                    # XREADGROUP returns: [(stream_name, [(msg_id, {field: value}), ...])]
                    response = rc.xreadgroup(
                        group,
                        consumer,
                        {stream: ">"},  # '>' = only new messages
                        count=count,
                        block=block_ms,
                    )
                    if not response:
                        return []

                    _, messages = response[0]
                    events: list[dict] = []
                    for _msg_id, fields in messages:
                        # syslog_listener pushes { "event": json_str }
                        event_json = fields.get("event", "{}")
                        try:
                            event = json.loads(event_json) if isinstance(event_json, str) else event_json
                            if not isinstance(event, dict):
                                event = {"raw": str(event)}
                        except (json.JSONDecodeError, TypeError):
                            event = {"raw": str(event_json)}
                        events.append(event)

                        # ACK each message individually
                        try:
                            rc.xack(stream, group, _msg_id)
                        except Exception:
                            pass

                    if events:
                        logger.debug("Read %d events from Redis Stream", len(events))
                    return events

                except Exception as e:
                    # Redis connection dropped — fall through to in-memory buffer
                    if self._redis_stream_ready:
                        logger.warning("Redis XREADGROUP failed (falling back to buffer): %s", e)
                        self._redis_stream_ready = False

        # Fallback: read from in-memory buffer (legacy path)
        with self._event_cond:
            if not self._event_buffer:
                self._event_cond.wait(timeout=block_ms / 1000)
            batch = self._event_buffer[:count]
            del self._event_buffer[:len(batch)]

        return batch

    # ── event callback (from syslog listener thread) ─────────────────
    def _on_event(self, event: dict):
        """Callback from syslog listener — adds event to in-memory buffer."""
        with self._event_cond:
            self._event_buffer.append(event)
            self._event_cond.notify()

    # ── Batch processing ──────────────────────────────────────────────
    def _process_batch(self, events: list) -> Dict[str, float]:
        """Process a batch of events using batch-optimized operations.

        Batches DB inserts, attack detection, geo lookup, concept drift,
        and classifier updates to minimize per-event overhead at high volume.

        Returns timing breakdown (ms) for monitoring.
        """
        if not events:
            return {}

        timing: Dict[str, float] = {}
        t_start = time.time()
        processed_at = datetime.now(timezone.utc).isoformat()
        db_tuples: list = []

        # ── Phase 1: Pre-process all events ──────────────────────────
        for event in events:
            event["processed_at"] = processed_at

            # Map parser 'ruid' to PG column 'rule_name'
            if "ruid" in event:
                ruid = event.pop("ruid")
                event["rule_name"] = self.rules_mapping.get(ruid, ruid)

            # Tag event with log_type for DB storage
            event.setdefault("log_type", "")

            # Network classification
            if self.network_classifier is not None:
                event = self.network_classifier.record_event(event)

            # Reverse DNS lookup
            if self.reverse_dns.enabled:
                for field in ("src_ip", "dst_ip"):
                    ip = event.get(field)
                    if ip:
                        hostname = self.reverse_dns.lookup(ip)
                        if hostname:
                            event[f"{field}_hostname"] = hostname

            # Build DB tuple for batch insert into normalized_events
            raw = event.get("raw", "")

            # Build payload_context for source-specific fields
            payload = {}
            if event.get("version"):
                payload["version"] = event["version"]
            for key in ("ip_ttl", "ip_total_length"):
                if event.get(key) is not None:
                    payload[key] = event[key]
            for key in ("tcp_flags_raw", "tcp_seq", "tcp_ack", "tcp_window",
                         "tcp_options", "udp_datalen", "icmp_datalen"):
                val = event.get(key)
                if val is not None:
                    payload[key] = val
            for key in ("method", "path", "status_code", "response_size",
                         "user_agent", "request_time"):
                if event.get(key) is not None:
                    payload[key] = event[key]
            for key in ("signature_id", "signature_msg", "signature_gen",
                         "signature_rev", "classification"):
                if event.get(key):
                    payload[key] = event[key]

            # Auto-detect source
            src = event.get("source", "")
            if not src:
                if event.get("unifi_event_key"):
                    src = "unifi"
                elif event.get("method") and event.get("path"):
                    src = "nginx"
                elif event.get("signature_id") or event.get("ids_event"):
                    src = "ids"
                elif event.get("policy") or event.get("zenarmor"):
                    src = "zenarmor"
                else:
                    src = "firewall"

            db_tuples.append((
                event.get("timestamp"),
                event.get("src_ip"),
                event.get("dst_ip"),
                event.get("sport"),
                event.get("dport"),
                event.get("protocol"),
                event.get("action"),
                event.get("interface"),
                event.get("direction"),
                event.get("src_hostname"),
                event.get("dst_hostname"),
                json.dumps(payload) if payload else None,
                src,
                event.get("log_type", ""),
                event.get("rule_name"),
                event.get("severity"),
                raw,
            ))

        # ── Phase 2: Batch DB insert ─────────────────────────────────
        try:
            self.db.insert_events_batch(db_tuples)
        except Exception as e:
            logger.error("Batch DB insert failed: %s", e)
            # Fallback: insert individually so events aren't lost
            for i, event in enumerate(events):
                try:
                    self.db.insert_event(event, event.get("raw", ""))
                except Exception:
                    pass

        # ── Phase 3: Batch classifier updates ────────────────────────
        self.system_log_classifier.process_events(events)

        # System log anomaly detection (periodic)
        now = time.time()
        if now - self.last_syslog_anomaly_check >= self.config.learn_interval:
            self._check_system_log_anomalies()
            self.last_syslog_anomaly_check = now

        # Service monitor — process all events
        self.service_monitor.process_events(events)

        # Statistical model — now handled by UnifiedBehavioralEngine.ingest_batch()
        # (stat_model kept for backward compat during transition)

        # Pre-filter firewall events for downstream consumers
        fw_events = [e for e in events if e.get("log_type") in ("firewall", "filterlog")]

        # Flow-based behavioral classification (firewall events only)
        for fw_event in fw_events:
            src_ip = fw_event.get("src_ip", "")
            threat_score = 0.0
            country = ""
            if src_ip:
                if self.behavior_profiler:
                    threat_score = self.behavior_profiler.get_behavioral_score(src_ip)
                try:
                    cc = self.geo_lookup._detector.lookup_country(src_ip)
                    if cc:
                        country = cc
                except Exception:
                    pass
            self.flow_classifier.process_event(fw_event, threat_score=threat_score, country=country)

        # Auto-retrain flow classifier ML model
        if self.flow_classifier.should_retrain_ml():
            self.flow_classifier.train_ml_model()

        # Concept drift detection — batch process firewall events
        if self.drift_detector and fw_events:
            self.drift_detector.process_batch(fw_events)

        # ── Phase 4: Conditional log-type processing ─────────────────
        for event in events:
            log_type = event.get("log_type", "")
            if log_type == "zenarmor":
                self.zenarmor_classifier.process_event(event)
            elif log_type == "ids":
                self.ids_analyzer.process_event(event)
            elif log_type == "nginx":
                self.nginx_monitor.process_event(event)

        # Behavior profiler — ingest all events for behavioral profiling
        # UnifiedBehavioralEngine.ingest_batch() handles IP baselines internally,
        # so the explicit update_ip_baseline loop below is no longer needed.
        if self.behavior_profiler and events:
            behavior_signals = self.behavior_profiler.ingest_batch(events)
            # Emit behavior signals to signal bus
            for ip, signals in behavior_signals.items():
                for sig in signals:
                    # UnifiedSignal has: .signal_type, .score, .details, .source
                    severity = "high" if sig.score >= 0.7 else "medium" if sig.score >= 0.4 else "low"
                    self.signal_bus.emit(
                        source=sig.source,
                        signal_type=sig.signal_type,
                        severity=severity,
                        ip=ip,
                        metadata=sig.details,
                    )

        # ── Phase 5: Batch attack detection ──────────────────────────
        attacks = self.attack_detector.check_events_batch(events)
        if attacks:
            for attack in attacks:
                attack.setdefault("timestamp", events[0].get("timestamp", ""))
                src_ip = attack.get("src_ip", "")
                attack_type = attack.get("attack_type", "")
                if self._is_muted(src_ip, attack_type):
                    slogger.info(
                        "Alert suppressed (muted)",
                        ip=src_ip, attack_type=attack_type,
                    )
                    continue
                self.anomaly_count += 1
                llm_analysis = None
                if self.vllm_client.enabled:
                    # Use first event as context for LLM analysis
                    llm_analysis = self.vllm_client.analyze_anomaly(
                        events[0], attack.get("attack_type", ""), attack.get("description", "")
                    )
                slogger.warning(
                    "Attack detected",
                    ip=src_ip, attack_type=attack_type,
                    severity=attack.get("severity", "medium"),
                    description=attack.get("description", ""),
                )
                # Emit signal to signal bus
                self.signal_bus.emit(
                    source="attack_detector",
                    signal_type=attack_type.lower().replace(" ", "_"),
                    severity=attack.get("severity", "medium"),
                    ip=src_ip,
                    metadata={
                        "description": attack.get("description", ""),
                        "dst_ip": attack.get("dst_ip"),
                        "dst_port": attack.get("dst_port"),
                        "protocol": attack.get("protocol"),
                    },
                )
                self.discord_bot.send_alert(attack, llm_analysis=llm_analysis)
                self.apprise_notifier.send_alert(attack)

        # ── Phase 6: Batch geo lookup ────────────────────────────────
        geo_results = self.geo_lookup.check_events_batch(events)
        if geo_results:
            for geo_result in geo_results:
                src_ip = geo_result.get("src_ip", "")
                if self._is_muted(src_ip, "GEO_ANOMALY"):
                    slogger.info(
                        "Geo alert suppressed (muted)",
                        ip=src_ip, attack_type="GEO_ANOMALY",
                    )
                    continue
                self.anomaly_count += 1
                # Emit geo anomaly signal
                self.signal_bus.emit(
                    source="geo",
                    signal_type=geo_result.get("type", "geo_anomaly").replace(" ", "_"),
                    severity=geo_result.get("severity", "medium"),
                    ip=src_ip,
                    metadata={
                        "country_code": geo_result.get("country_code"),
                        "country_name": geo_result.get("country_name"),
                    },
                )
                self.discord_bot.send_alert(geo_result)
                self.apprise_notifier.send_alert(geo_result)

                # Track geo anomalies
                if geo_result.get("type") == "geo_country_anomaly":
                    cc = geo_result.get("country_code", "XX")
                    slogger.info(
                        "New country detected",
                        ip=src_ip, country_code=cc, attack_type="GEO_ANOMALY",
                        event_count=self.geo_lookup.country_events.get(cc, 0),
                    )

        self.event_count += len(events)

        # ── Timing ───────────────────────────────────────────────────
        elapsed_ms = (time.time() - t_start) * 1000
        timing["total_ms"] = elapsed_ms
        timing["events_per_sec"] = len(events) / (elapsed_ms / 1000) if elapsed_ms > 0 else 0

        if elapsed_ms > 200:
            slogger.info(
                "Batch processed",
                event_count=len(events),
                elapsed_ms=elapsed_ms,
                events_per_sec=timing["events_per_sec"],
            )

        return timing

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
            anomaly_type = anomaly.get('type', 'SYSTEM_ANOMALY').lower().replace(' ', '_')
            signal_type = (
                {'NEW_SERVICE': 'new_service', 'VOLUME_SPIKE': 'system_volume_spike', 'ERROR_BURST': 'error_burst', 'HIGH_IP_DIVERSITY': 'high_ip_diversity'}
                .get(anomaly_type, anomaly_type) or 'system_anomaly'
            )
            slogger.warning(
                "System log anomaly detected",
                attack_type=anomaly_type,
                severity=anomaly.get('severity', 'medium'),
                description=anomaly.get('description', ''),
            )
            self.signal_bus.emit(
                source="system_log",
                signal_type=signal_type,
                severity=anomaly.get('severity', 'medium').lower(),
                ip=anomaly.get('src_ip', ''),
                metadata={
                    "service": anomaly.get('service'),
                    "description": anomaly.get('description', ''),
                },
            )
            self.discord_bot.send_alert(anomaly)
            self.apprise_notifier.send_alert(anomaly)

    def _check_service_anomalies(self):
        """Check service monitor for anomalies and send alerts."""
        anomalies = self.service_monitor.check_all()
        if not anomalies:
            return
        
        for anomaly in anomalies:
            self.anomaly_count += 1
            slogger.warning(
                "Service anomaly detected",
                attack_type=anomaly.get('type'),
                severity=anomaly.get('severity', 'medium'),
                description=anomaly.get('description', ''),
            )
            self.signal_bus.emit(
                source="service_monitor",
                signal_type=anomaly.get('signal_type', anomaly.get('type', 'service_anomaly').lower().replace(' ', '_')),
                severity=anomaly.get('severity', 'medium').lower(),
                ip=anomaly.get('src_ip', ''),
                metadata={
                    "service": anomaly.get('service'),
                    "description": anomaly.get('description', ''),
                },
            )

    # ── mute list helpers (cached) ───────────────────────────────────
    def _load_mutes(self) -> list[dict]:
        """Load active mutes from mutes.json (cold load only)."""
        mutes_path = DATA_DIR / "mutes.json"
        if not mutes_path.exists():
            return []
        try:
            with open(mutes_path) as f:
                data = json.load(f)
            now = datetime.now(timezone.utc)
            active = []
            for m in data:
                try:
                    exp = datetime.fromisoformat(m["expires"])
                    if exp > now:
                        active.append(m)
                except (KeyError, ValueError):
                    pass
            return active
        except Exception:
            return []

    def _refresh_mute_cache(self):
        """Reload mute list into in-memory cache."""
        self._mute_cache = self._load_mutes()
        self._mute_cache_time = time.time()
        self._mute_cache_ips = set()
        self._mute_cache_ip_type: Dict[str, set] = defaultdict(set)
        for m in self._mute_cache:
            ip = m.get("ip", "")
            atype = m.get("attack_type", "")
            if ip:
                self._mute_cache_ips.add(ip)
                self._mute_cache_ip_type[ip].add(atype)

    def _is_muted(self, src_ip: str, attack_type: str = "") -> bool:
        """Check if an IP/attack_type combo is muted (cached lookup).

        Cache is refreshed every 10s so mute command changes propagate
        without requiring a file read on every single event.
        """
        now = time.time()
        if now - getattr(self, '_mute_cache_time', 0) >= 10:
            self._refresh_mute_cache()

        if src_ip not in self._mute_cache_ips:
            return False
        types = self._mute_cache_ip_type.get(src_ip, set())
        return "ALL" in types or attack_type in types
    
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
                        self.signal_bus.emit(
                            source="wan_flap",
                            signal_type="wan_flap",
                            severity=alert.get('severity', 'high').lower(),
                            ip='',
                            metadata={
                                "gateway": name,
                                "flap_count": alert.get('flap_count'),
                                "current_state": alert.get('current_state'),
                                "description": alert.get('description', ''),
                            },
                        )
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
            # Map anomaly types to signal types
            zen_signal_map = {
                'NEW_POLICY': 'new_policy',
                'POLICY_CHANGE': 'policy_change',
                'BLOCK_SPIKE': 'block_spike',
                'MIXED_POLICY': 'mixed_policy',
                'SYSTEM_BLOCK_SPIKE': 'system_block_spike',
            }
            self.signal_bus.emit(
                source="zenarmor",
                signal_type=zen_signal_map.get(anomaly.get('type', ''), anomaly.get('type', 'policy_violation').lower().replace(' ', '_') or 'policy_violation'),
                severity=anomaly.get('severity', 'medium').lower(),
                ip='',
                metadata={
                    "policy_name": anomaly.get('policy_name'),
                    "description": anomaly.get('description', ''),
                },
            )
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
            # Map anomaly types to signal types
            ids_signal_map = {
                'NEW_SIGNATURE': 'ids_new_signature',
                'SIGNATURE_SPIKE': 'ids_signature_spike',
                'TARGET_CHANGE': 'ids_target_change',
                'CROSS_NETWORK': 'ids_cross_network',
                'MULTIPLE_NEW_SIGNATURES': 'ids_new_signature',
            }
            self.signal_bus.emit(
                source="ids",
                signal_type=ids_signal_map.get(anomaly.get('type', ''), anomaly.get('type', 'ids_alert').lower().replace(' ', '_') or 'ids_alert'),
                severity=anomaly.get('severity', 'medium').lower(),
                ip=anomaly.get('src_ip', ''),
                metadata={
                    "signature": anomaly.get('signature'),
                    "priority": anomaly.get('priority'),
                    "description": anomaly.get('description', ''),
                },
            )
            self.discord_bot.send_alert(anomaly)
            self.apprise_notifier.send_alert(anomaly)

    def _check_unifi(self):
        """Poll UniFi controller and process events/anomalies."""
        if not self.unifi_monitor.enabled:
            return
        if not self.unifi_monitor.host:
            return

        import asyncio
        loop = asyncio.new_event_loop()
        try:
            events = loop.run_until_complete(self.unifi_monitor.poll())
        finally:
            loop.close()

        if not events:
            return

        # Insert into DB and alert on anomalies
        for event in events:
            # Insert to normalized_events (insert_unifi_event delegates to insert_event)
            try:
                self.db.insert_unifi_event(event)
            except Exception as e:
                logger.warning("Failed to insert UniFi event: %s", e)

            # Alert on HIGH/CRITICAL severity
            severity = event.get("severity", "").upper()
            if severity in ("HIGH", "CRITICAL"):
                self.anomaly_count += 1
                logger.warning("UniFi anomaly: %s — %s", event.get("event_type"), event.get("description"))
                self.discord_bot.send_alert(event)
                self.apprise_notifier.send_alert(event)
                # P2-6: Publish to SSE stream
                try:
                    _get_sse_publisher()(event)
                except Exception:
                    pass

    def _send_status(self):
        """Log periodic status."""
        uptime = int(time.time() - self.start_time)
        mode = "syslog" if self.config.syslog_enabled else "direct"

        # Prefer unified engine stats; fall back to stat_model for backward compat
        if self.behavior_profiler:
            stats = self.behavior_profiler.get_stats()
        else:
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

        # Country events from geo_lookup regardless of stats source
        country_events = getattr(self.geo_lookup, 'country_events', {})

        logger.info(
            "Status: %s events, %s anomalies, uptime: %ds | mode: %s | "
            "unique_ips: %s | ports_tracked: %s | country_events: %s%s",
            self.event_count,
            self.anomaly_count,
            uptime,
            mode,
            stats.get("unique_ips", 0),
            stats.get("unique_ports", 0),
            len(country_events),
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
                # P1-T4: Read from Redis Stream consumer group (falls back to in-memory buffer)
                events = self._read_redis_batch(
                    block_ms=int(self.config.poll_interval * 1000),
                    count=self.config.batch_size,
                )

                if events:
                    now = time.time()
                    # Learn patterns — use unified engine when available
                    if now - self.last_learn >= self.config.learn_interval:
                        if self.behavior_profiler:
                            learn_result = self.behavior_profiler.learn(events)
                            logger.info("Learned from %s events (total: %s, profiles: %s)",
                                        len(events), self.event_count, learn_result.get("total_profiles", 0))
                        else:
                            self.stat_model.learn(events)
                        self.last_learn = now

                        # Periodic adaptation: every 3 learn cycles, re-analyze raw patterns
                        self._adapt_cycle += 1
                        if self._adapt_cycle >= 3:
                            self._periodic_adapt()
                            self._adapt_cycle = 0

                    # Detect anomalies on all events
                    self._process_batch(events)

                    # Anomaly detection against baselines
                    if self.anomaly_detector and self.baseline_engine and self.db:
                        anomalies = self.anomaly_detector.analyze(events)
                        if anomalies:
                            for anomaly in anomalies:
                                src_ip = anomaly.get("src_ip", "")
                                anomaly_type = anomaly.get("type", "")
                                # Check mute list before alerting
                                if self._is_muted(src_ip, anomaly_type):
                                    logger.info("Anomaly alert suppressed (muted): %s from %s", anomaly_type, src_ip)
                                    continue
                                self.anomaly_count += 1
                                logger.info("Anomaly detected: %s - %s", anomaly.get("type"), anomaly.get("description"))
                                # Emit signal to signal bus
                                anomaly_type = anomaly.get("type", "unknown")
                                anomaly_signal_map = {
                                    "volume_spike": "anomaly_volume",
                                    "temporal_anomaly": "anomaly_temporal",
                                    "new_ip": "anomaly_new_ip",
                                    "port_scan": "anomaly_port_scan",
                                }
                                self.signal_bus.emit(
                                    source="anomaly_detector",
                                    signal_type=anomaly_signal_map.get(anomaly_type, anomaly_type) or anomaly_type,
                                    severity=anomaly.get("severity", "medium").lower(),
                                    ip=anomaly.get("src_ip", ""),
                                    metadata={
                                        "description": anomaly.get("description", ""),
                                        "z_score": anomaly.get("z_score"),
                                        "dst_ip": anomaly.get("dst_ip"),
                                        "dst_port": anomaly.get("dst_port"),
                                    },
                                )
                                # Save anomaly to database
                                anomaly_id = None
                                try:
                                    # Map anomaly detector output to database schema
                                    db_anomaly = {
                                        "attack_type": anomaly.get("type", "unknown"),
                                        "severity": anomaly.get("severity", "MEDIUM"),
                                        "src_ip": anomaly.get("src_ip"),
                                        "dst_ip": anomaly.get("dst_ip"),
                                        "dst_port": anomaly.get("dst_port"),
                                        "protocol": anomaly.get("protocol"),
                                        "description": anomaly.get("description", ""),
                                        "detail": {k: v for k, v in anomaly.items() if k not in ("attack_type", "severity", "src_ip", "dst_ip", "dst_port", "protocol", "description")}
                                    }
                                    anomaly_id = self.db.insert_anomaly(db_anomaly)
                                except Exception as e:
                                    logger.warning("Failed to save anomaly to DB: %s", e)

                                # Record detection with threshold tuner (for auto-tuning)
                                if self.threshold_tuner and anomaly_id:
                                    score = anomaly.get("z_score") or anomaly.get("ports_count") or anomaly.get("event_count") or 1.0
                                    self.threshold_tuner.record_detection(
                                        anomaly_type=anomaly_type,
                                        score=abs(float(score)),
                                        anomaly_id=anomaly_id,
                                    )
                                self.discord_bot.send_alert(anomaly)
                                self.apprise_notifier.send_alert(anomaly)
                                # P2-6: Publish to SSE stream
                                try:
                                    _get_sse_publisher()(anomaly)
                                except Exception:
                                    pass

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

                    # Check UniFi controller periodically
                    if now - self.last_unifi_check >= self.config.learn_interval:
                        self.last_unifi_check = now
                        try:
                            self._check_unifi()
                        except Exception as e:
                            logger.warning("UniFi check failed: %s", e)

                    # Save state periodically (every learn_interval, alongside baseline save)
                    if now - self.last_save >= self.config.learn_interval:
                        self.last_save = now
                        # Get baseline summary from unified engine when available
                        if self.behavior_profiler:
                            baseline_summary = self.behavior_profiler.get_baseline_summary()
                        else:
                            baseline_summary = self.stat_model.get_baseline_summary()
                        self.db._save_baselines(baseline_summary)
                        # Persist all ML/tracking state to consolidated state.json
                        self.persistence.save(self)
                        self.service_monitor.save()

                    # Phase 5: Periodic threshold auto-tuning (every 2 learn intervals)
                    if self.threshold_tuner and now - self.last_save >= self.config.learn_interval * 2:
                        try:
                            adjustments = self.threshold_tuner.tune()
                            if adjustments:
                                adj_summary = ", ".join(
                                    f"{a['type']}: {a['old_value']:.2f} -> {a['new_value']:.2f}"
                                    for a in adjustments if a['old_value'] != a['new_value']
                                )
                                if adj_summary:
                                    logger.info("Threshold auto-tune: %s", adj_summary)
                        except Exception as e:
                            logger.warning("Threshold auto-tune failed: %s", e)

                    # Periodic status (time-based every 60s)
                    now = time.time()
                    if now - self.last_status >= 60:
                        self.last_status = now
                        try:
                            self._send_status()
                        except Exception as e:
                            logger.warning("Status log failed: %s", e)

                # _read_redis_batch already blocks via BLOCK or cond.wait — no extra sleep

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
        """Clean shutdown: flush pending events, save state, stop services."""
        logger.info("Shutting down agent...")
        self._shutdown.set()

        # Flush any remaining events in the buffer
        events_to_flush: list[dict] = []
        with self._event_cond:
            pending = len(self._event_buffer)
            if pending:
                logger.info("Processing %d pending events before shutdown...", pending)
                events_to_flush = self._event_buffer[:]
                del self._event_buffer[:]
        # Process outside the lock to avoid deadlock
        if events_to_flush:
            self._process_batch(events_to_flush)

        # Save final state
        try:
            # Get baseline summary from unified engine when available
            if self.behavior_profiler:
                baseline_summary = self.behavior_profiler.get_baseline_summary()
            else:
                baseline_summary = self.stat_model.get_baseline_summary()
            if self.db:
                self.db._save_baselines(baseline_summary)
            self.persistence.save(self)
            self.service_monitor.save()
            logger.info("State saved successfully")
        except Exception as e:
            logger.warning("Failed to save state during shutdown: %s", e)

        # Gracefully shutdown dashboard server (drain in-flight requests)
        try:
            from server import shutdown_server
            shutdown_server(timeout=15)
            logger.info("Dashboard server shutdown initiated")
        except Exception as e:
            logger.warning("Failed to shutdown dashboard server gracefully: %s", e)

        # Stop services
        self.syslog_listener.stop()
        self._send_status()
        self.discord_bot.stop()
        # Stop resource health monitor
        if hasattr(self, "health_monitor") and self.health_monitor is not None:
            self.health_monitor.stop()
        logger.info("Agent shutdown complete")


# ── Main ───────────────────────────────────────────────────────────────
def _signal_handler(signum, frame, agent_ref):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    logger.info("%s received — initiating graceful shutdown...", sig_name)
    if agent_ref:
        agent_ref.shutdown()


def main():
    parser = argparse.ArgumentParser(description="OPNsense Anomaly Detection Agent")
    parser.add_argument("--portscan-window", type=int, default=None)
    parser.add_argument("--syn-threshold", type=int, default=None)
    args, unknown = parser.parse_known_args()

    cfg = Config()
    agent = OPNsenseAgent(cfg)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, lambda s, f: _signal_handler(s, f, agent))
    signal.signal(signal.SIGINT, lambda s, f: _signal_handler(s, f, agent))

    agent.run()


if __name__ == "__main__":
    main()
