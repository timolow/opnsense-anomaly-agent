#!/usr/bin/env python3
"""Dashboard API server - reads from PostgreSQL + state file."""

import base64
import hmac
import json
import logging
import os
import queue
import sys
import time
import urllib.parse
import threading as threading_lib
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any, Dict

sys.path.insert(0, '/app')

from eventdb import EventDatabase

# Drain mode (imported from standalone module for testability)
from drain import (
    _drain_mode, _active_requests, _active_requests_lock,
    _drained_event, _drain_initiated_at, _MAX_DRAIN_WAIT,
    enter_drain_mode, is_draining, get_active_request_count,
    wait_for_drain, graceful_shutdown, _request_enter, _request_exit,
)

logger = logging.getLogger(__name__)

# Rate limiter for API requests
from collections import defaultdict
import time as time_module

class RateLimiter:
    """Simple token bucket rate limiter."""
    def __init__(self, max_requests=60, window=60):
        self.max_requests = max_requests
        self.window = window
        self.clients = defaultdict(list)
    
    def is_allowed(self, client_ip):
        now = time_module.time()
        # Remove old requests
        self.clients[client_ip] = [t for t in self.clients[client_ip] if now - t < self.window]
        if len(self.clients[client_ip]) >= self.max_requests:
            return False
        self.clients[client_ip].append(now)
        return True

rate_limiter = RateLimiter(max_requests=120, window=60)

# ─── Basic Auth Configuration ─────────────────────────────────────
DASHBOARD_API_USER = os.environ.get("DASHBOARD_API_USER", "")
DASHBOARD_API_PASS = os.environ.get("DASHBOARD_API_PASS", "")
_BASIC_AUTH_ENABLED = bool(DASHBOARD_API_USER and DASHBOARD_API_PASS)

def _check_basic_auth(headers):
    """Check HTTP Basic Auth credentials. Returns True if auth is not required or credentials are valid."""
    if not _BASIC_AUTH_ENABLED:
        return True
    auth_header = headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        user, _, password = decoded.partition(":")
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(user, DASHBOARD_API_USER) and hmac.compare_digest(password, DASHBOARD_API_PASS)
    except Exception:
        return False

def _require_auth(handler):
    """Send 401 if basic auth fails."""
    if _check_basic_auth(handler.headers):
        return True
    handler.send_response(401)
    handler.send_header("WWW-Authenticate", 'Basic realm="Dashboard API"')
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
    return False

# ─── SSE (Server-Sent Events) Queue ──────────────────────────────────
_sse_queue: queue.Queue = queue.Queue(maxsize=1000)
_sse_clients: list = []
_sse_clients_lock = threading_lib.Lock()

def publish_anomaly_sse(anomaly_data: dict):
    """Publish an anomaly to the SSE queue (called by agent.py)."""
    try:
        _sse_queue.put_nowait({
            "type": anomaly_data.get("type", anomaly_data.get("attack_type", "unknown")),
            "severity": anomaly_data.get("severity", "MEDIUM"),
            "description": anomaly_data.get("description", ""),
            "src_ip": anomaly_data.get("src_ip", ""),
            "timestamp": anomaly_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })
    except queue.Full:
        logger.warning("SSE queue full, dropping anomaly event")

def sse_background_cleaner():
    """Background thread to clean up dead SSE connections."""
    while True:
        time.sleep(60)
        with _sse_clients_lock:
            _sse_clients[:] = [c for c in _sse_clients if c.get("alive", False)]

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False
    print("WARNING: psycopg2 not installed - falling back to state file")

try:
    import redis as redis_lib
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    print("WARNING: redis not installed - caching disabled")
    redis_lib = None  # type: ignore

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
_CACHE_TTL = 60  # seconds

# Global Redis connection pool
_redis_pool = None

def get_redis():
    """Get Redis connection (singleton)."""
    global _redis_pool
    if not HAS_REDIS or _redis_pool:
        return _redis_pool
    try:
        if redis_lib is None:
            return None
        _redis_pool = redis_lib.from_url(REDIS_URL, socket_timeout=2, decode_responses=True)
        _redis_pool.ping()
        logger.info("Redis cache connected: %s", REDIS_URL)
        return _redis_pool
    except Exception as e:
        logger.warning("Redis connection failed, caching disabled: %s", e)
        return None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE_DIR, "agent_data", "state.json")
MUTES_PATH = os.path.join(BASE_DIR, "agent_data", "mutes.json")
WATCHLIST_PATH = os.path.join(BASE_DIR, "agent_data", "watchlist.json")
DATA_DIR = os.path.join(BASE_DIR, "agent_data")

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "opnsense")
DB_USER = os.environ.get("DB_USER", "opnsense")
DB_PASS = os.environ.get("DB_PASSWORD", "opnsense")

WAN_INTERFACES = {"ixl2", "igb1"}
LAN_INTERFACES = {"ixl3_vlan1003", "ixl3_vlan666"}
VPN_INTERFACES = {"ovpnc4", "openvpn4"}

def classify_interface(iface):
    if not iface:
        return "UNKNOWN"
    iface_lower = iface.lower()
    for w in WAN_INTERFACES:
        if iface_lower.startswith(w):
            return "WAN"
    for l in LAN_INTERFACES:
        if iface_lower.startswith(l):
            return "LAN"
    for v in VPN_INTERFACES:
        if iface_lower.startswith(v):
            return "VPN"
    return "UNKNOWN"

_db_cache = {}

def _get_db_once():
    conn_str = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASS}"
    for attempt in range(3):
        try:
            return psycopg2.connect(conn_str)
        except Exception as e:
            print(f"DB connection attempt {attempt+1}/3 failed: {e}")
            time.sleep(2)
    return None

def get_db():
    cache_key = f"{DB_HOST}:{DB_PORT}:{DB_NAME}"
    if cache_key in _db_cache:
        try:
            _db_cache[cache_key].cursor().execute("SELECT 1")
            return _db_cache[cache_key]
        except Exception:
            _db_cache.pop(cache_key, None)
    if not HAS_PSYCOPG:
        return None
    conn = _get_db_once()
    if conn:
        _db_cache[cache_key] = conn
    return conn

def close_db(conn):
    if conn:
        try:
            conn.close()
        except Exception:
            pass

def load_state():
    if not os.path.exists(STATE_PATH):
        return None
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return None

def load_mutes():
    if os.path.exists(MUTES_PATH):
        try:
            with open(MUTES_PATH) as f:
                data = json.load(f)
            now = datetime.datetime.now(datetime.timezone.utc)
            active = []
            for m in data:
                try:
                    exp = datetime.datetime.fromisoformat(m["expires"])
                    if exp > now:
                        active.append(m)
                except Exception:
                    pass
            if len(active) < len(data):
                save_mutes(active)
            return active
        except Exception:
            return []
    return []

def save_mutes(mutes):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(MUTES_PATH, "w") as f:
        json.dump(mutes, f, indent=2, default=str)


def load_watchlist():
    """Load watched IPs from JSON file."""
    if os.path.exists(WATCHLIST_PATH):
        try:
            with open(WATCHLIST_PATH) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_watchlist(watchlist):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(WATCHLIST_PATH, "w") as f:
        json.dump(watchlist, f, indent=2, default=str)


def add_to_watchlist(ip: str, reason: str = ""):
    """Add an IP to the watchlist."""
    watchlist = load_watchlist()
    # Avoid duplicates
    if any(w.get("ip") == ip for w in watchlist if isinstance(w, dict)):
        return {"success": False, "message": "IP already in watchlist", "ip": ip}
    entry = {
        "ip": ip,
        "reason": reason,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    watchlist.append(entry)
    save_watchlist(watchlist)
    return {"success": True, "ip": ip}


def remove_from_watchlist(ip: str):
    """Remove an IP from the watchlist."""
    watchlist = load_watchlist()
    watchlist = [w for w in watchlist if w.get("ip") != ip]
    save_watchlist(watchlist)


def block_ip_in_firewall(ip: str, reason: str = "Manual block from dashboard"):
    """Attempt to block an IP via OPNsense API. Creates a temporary alias or rule."""
    opn_url, opn_key, opn_secret, verify_ssl = _read_opn_config()
    if not opn_url:
        return {"success": False, "message": "OPNsense API not configured", "ip": ip}

    try:
        import requests as _req
        # Try to create/update an alias for blocked IPs
        # First search for our managed alias
        resp = _req.get(
            f"{opn_url}/api/firewall/alias/search",
            headers={
                "X-Api-Key": opn_key,
                "X-Api-Secret": opn_secret,
            },
            params={"name": "AGENT_BLOCKLIST"},
            verify=verify_ssl,
            timeout=10,
        )
        alias_id = None
        alias_data = None
        if resp.status_code == 200:
            aliases = resp.json().get("data", [])
            if aliases:
                alias_id = aliases[0].get("uid")
                alias_data = aliases[0]

        if alias_id and alias_data:
            existing_entries = alias_data.get("address", "").split("\n")
            if ip in existing_entries:
                return {"success": False, "message": "IP already in blocklist alias", "ip": ip}
            new_entries = "\n".join(existing_entries + [ip])
            update_resp = _req.post(
                f"{opn_url}/api/firewall/alias/{alias_id}",
                json={"address": new_entries, "description": reason},
                headers={
                    "X-Api-Key": opn_key,
                    "X-Api-Secret": opn_secret,
                },
                verify=verify_ssl,
                timeout=10,
            )
            if update_resp.status_code == 200:
                # Trigger rule reload
                _req.post(
                    f"{opn_url}/api/firewall/rules/reload",
                    headers={
                        "X-Api-Key": opn_key,
                        "X-Api-Secret": opn_secret,
                    },
                    verify=verify_ssl,
                    timeout=15,
                )
                return {"success": True, "message": "IP added to blocklist alias and rules reloaded", "ip": ip}
            else:
                return {"success": False, "message": f"Alias update failed: {update_resp.status_code}", "ip": ip}
        else:
            # Create new alias
            create_resp = _req.post(
                f"{opn_url}/api/firewall/alias/",
                json={
                    "name": "AGENT_BLOCKLIST",
                    "type": "host",
                    "address": ip,
                    "description": reason,
                },
                headers={
                    "X-Api-Key": opn_key,
                    "X-Api-Secret": opn_secret,
                },
                verify=verify_ssl,
                timeout=10,
            )
            if create_resp.status_code == 200:
                return {"success": True, "message": "Blocklist alias created with IP", "ip": ip}
            else:
                return {"success": False, "message": f"Alias creation failed: {create_resp.status_code}", "ip": ip}

    except Exception as e:
        return {"success": False, "message": f"Firewall block failed: {str(e)}", "ip": ip}


def load_ml_model_info():
    """Load ML model info from persisted model file for Prometheus metrics."""
    try:
        import joblib
        model_path = os.path.join(DATA_DIR, "rule_classifier_model.pkl")
        if not os.path.exists(model_path):
            return None
        data = joblib.load(model_path)
        return {
            "model_trained": True,
            "metrics": data.get("metrics", {}),
            "feature_importances": data.get("feature_importances", {}),
            "samples_since_retrain": 0,  # live value from agent
        }
    except Exception:
        return None


def add_mute(ip, attack_type, port=None, duration=3600, source="manual"):
    mutes = load_mutes()
    mute = {
        "id": f"mute_{int(time.time()*1000)}",
        "ip": ip, "attack_type": attack_type, "port": port,
        "duration_seconds": duration,
        "created": datetime.now(timezone.utc).isoformat(),
        "expires": datetime.now(timezone.utc).isoformat(),
        "source": source,
    }
    mutes.append(mute)
    save_mutes(mutes)
    return mute

def remove_mute(mute_id):
    mutes = load_mutes()
    mutes = [m for m in mutes if m["id"] != mute_id]
    save_mutes(mutes)

def _get_event_count(record):
    if isinstance(record, dict):
        return record.get("count", record.get("event_count", 0))
    return 0

def _parse_ip_first_octet(ip):
    if not ip:
        return None
    try:
        return int(ip.split(".")[0])
    except (ValueError, IndexError):
        return None

def _calc_uptime(agent_counters):
    start = agent_counters.get("start_time")
    if start and isinstance(start, (int, float)):
        return max(0, int(time.time() - start))
    return agent_counters.get("uptime", 0)

def _read_opn_config():
    """Read OPNsense config from environment variables (docker-compose)."""
    host = os.environ.get("OPN_HOST", "192.168.1.1")
    port = int(os.environ.get("OPN_PORT", "443"))
    api_key = os.environ.get("OPN_API_KEY", "")
    api_secret = os.environ.get("OPN_API_SECRET", "")
    verify_ssl = os.environ.get("OPN_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
    url = f"https://{host}:{port}"
    if api_key:
        return url, api_key, api_secret, verify_ssl
    return "", "", "", True

# ─── PostgreSQL queries ────────────────────────────────────────────

def query_stats():
    conn = get_db()
    state = load_state()
    agent_counters = {}
    if state:
        agent_counters = state.get("agent_counters", {})
    counters = {
        "events_processed": agent_counters.get("event_count", 0),
        "anomalies_detected": agent_counters.get("anomaly_count", 0),
        "alerts_sent": agent_counters.get("alert_count", 0),
    }
    db_event_count = 0
    by_type = defaultdict(int)
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_sources = []
    categories = defaultdict(int)
    total_events = 0
    if conn:
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT COUNT(*) as cnt FROM events")
            row = cur.fetchone()
            if row:
                db_event_count = row["cnt"]
            cur.execute("""
                SELECT src_ip, COUNT(*) as event_count,
                       COUNT(DISTINCT dst_ip) as unique_destinations,
                       COUNT(DISTINCT dst_port) as unique_ports,
                       interface, proto
                FROM events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY src_ip, interface, proto
                ORDER BY event_count DESC
                LIMIT 100
            """)
            rows = cur.fetchall()
            for row in rows:
                ip = row["src_ip"] or "0.0.0.0"
                cnt = row["event_count"]
                iface = row["interface"]
                proto = row["proto"] or "ip"
                total_events += cnt
                category = classify_interface(iface)
                if category == "UNKNOWN" and ip and not ip.startswith(("10.", "192.168.", "172.")):
                    category = "WAN"
                if category == "WAN": by_type["external"] += cnt
                elif category == "LAN": by_type["internal"] += cnt
                elif category == "VPN": by_type["vpn"] += cnt
                else: by_type["unknown"] += cnt
                categories[category] += 1
                top_sources.append({
                    "ip": ip, "count": cnt, "category": category,
                    "interface": iface, "unique_destinations": row["unique_destinations"],
                    "unique_ports": row["unique_ports"], "protocol": proto,
                })
            by_severity = {
                "CRITICAL": sum(1 for s in top_sources if s["count"] > 10000),
                "HIGH": sum(1 for s in top_sources if 1000 <= s["count"] <= 10000),
                "MEDIUM": sum(1 for s in top_sources if 100 < s["count"] < 1000),
                "LOW": sum(1 for s in top_sources if s["count"] <= 100),
            }
            cur.close()
        except Exception as e:
            print(f"Stats query failed: {e}")
    nc = state.get("network_classifier", {}) if state else {}
    ip_data = nc.get("ip_data", {})
    ip_classifications = len([v for v in ip_data.values() if isinstance(v, dict) and _get_event_count(v) > 0])
    
    # 24h action counts for blocked/passed + unique IPs
    blocked_24h = 0
    passed_24h = 0
    unique_ips = ip_classifications  # fallback
    if conn:
        try:
            cur2 = conn.cursor()
            cur2.execute("SELECT COUNT(*) FROM events WHERE action = 'BLOCK' AND timestamp > NOW() - INTERVAL '24 hours'")
            blocked_24h = cur2.fetchone()[0]
            cur2.execute("SELECT COUNT(*) FROM events WHERE action = 'PASS' AND timestamp > NOW() - INTERVAL '24 hours'")
            passed_24h = cur2.fetchone()[0]
            cur2.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE timestamp > NOW() - INTERVAL '24 hours' AND src_ip IS NOT NULL AND src_ip != ''")
            unique_ips = cur2.fetchone()[0]
            cur2.close()
        except Exception:
            pass
    
    # Rules classified count from network_classifier
    rules_classified = 0
    if state and "network_classifier" in state:
        nc = state["network_classifier"]
        if "rule_data" in nc:
            rules_classified = len(nc["rule_data"])
        elif "classifications" in nc:
            rules_classified = len(nc["classifications"])
    geo_data = query_geo()
    top_countries = [g["country"] for g in geo_data]
    
    # Hourly sparkline data (last 24h) — single efficient query
    sparklines = {
        "events": [],
        "blocked": [],
        "passed": [],
        "unique_ips": [],
        "anomalies": [],
    }
    if conn:
        try:
            cur3 = conn.cursor()
            # Events + blocked + passed per hour (single query with conditional aggregation)
            cur3.execute("""
                SELECT
                    DATE_TRUNC('hour', timestamp) AS hour,
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE action = 'BLOCK') AS blocked,
                    COUNT(*) FILTER (WHERE action = 'PASS') AS passed
                FROM events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY hour
                ORDER BY hour
            """)
            hourly_rows = cur3.fetchall()
            for row in hourly_rows:
                sparklines["events"].append({"time": row[0].isoformat(), "count": row[1]})
                sparklines["blocked"].append({"time": row[0].isoformat(), "count": row[2]})
                sparklines["passed"].append({"time": row[0].isoformat(), "count": row[3]})
            
            # Unique IPs per hour
            cur3.execute("""
                SELECT
                    DATE_TRUNC('hour', timestamp) AS hour,
                    COUNT(DISTINCT src_ip) AS unique_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                    AND src_ip IS NOT NULL AND src_ip != ''
                GROUP BY hour
                ORDER BY hour
            """)
            for row in cur3.fetchall():
                sparklines["unique_ips"].append({"time": row[0].isoformat(), "count": row[1]})
            
            # Anomalies per hour
            cur3.execute("""
                SELECT
                    DATE_TRUNC('hour', timestamp) AS hour,
                    COUNT(*) AS anomaly_count
                FROM anomalies
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY hour
                ORDER BY hour
            """)
            for row in cur3.fetchall():
                sparklines["anomalies"].append({"time": row[0].isoformat(), "count": row[1]})
            cur3.close()
        except Exception:
            pass
    
    return {
        "counters": counters, "by_type": dict(by_type),
        "by_severity": by_severity, "top_sources": top_sources[:20],
        "categories": dict(categories), "active_mutes": len(load_mutes()),
        "ip_classifications": ip_classifications,
        "unique_ips": unique_ips,
        "total_ips": total_events,
        "total_events": db_event_count,
        "time_range": "24h",
        "top_countries": top_countries,
        "blocked_24h": blocked_24h,
        "passed_24h": passed_24h,
        "rules_classified": rules_classified,
        "sparklines": sparklines,
    }

def _fallback_stats():
    state = load_state()
    if not state:
        return {"counters": {"events_processed": 0, "anomalies_detected": 0, "alerts_sent": 0}, "by_type": {}, "top_sources": [], "active_mutes": 0, "ip_classifications": 0, "top_countries": []}
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    by_type = defaultdict(int)
    top_sources = []
    for ip, info in ip_data.items():
        if not isinstance(info, dict): continue
        cnt = _get_event_count(info)
        cat = info.get("category", "UNKNOWN")
        if cat == "WAN": by_type["external"] += cnt
        elif cat == "LAN": by_type["internal"] += cnt
        elif cat == "VPN": by_type["vpn"] += cnt
        if cnt > 0: top_sources.append({"ip": ip, "count": cnt, "category": cat})
    top_sources.sort(key=lambda x: x["count"], reverse=True)
    return {"counters": {"events_processed": 0, "anomalies_detected": 0, "alerts_sent": 0}, "by_type": dict(by_type), "top_sources": top_sources[:20], "active_mutes": len(load_mutes()), "ip_classifications": len([v for v in ip_data.values() if isinstance(v, dict) and _get_event_count(v) > 0]), "top_countries": []}

def query_heatmap():
    conn = get_db()
    if not conn: return _fallback_heatmap()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as event_count
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, EXTRACT(HOUR FROM timestamp)
            ORDER BY src_ip, hour
        """)
        rows = cur.fetchall()
        ip_hour = defaultdict(lambda: defaultdict(int))
        for row in rows:
            ip = row["src_ip"] or "0.0.0.0"
            hour = int(row["hour"])
            ip_hour[ip][hour] += row["event_count"]
        ip_totals = {ip: sum(hours.values()) for ip, hours in ip_hour.items()}
        sorted_ips = sorted(ip_totals.keys(), key=lambda x: ip_totals[x], reverse=True)[:50]
        matrix = [[ip_hour[ip].get(h, 0) for h in range(24)] for ip in sorted_ips]
        return {"labels_x": [f"{h:02d}:00" for h in range(24)], "labels_y": sorted_ips, "data": matrix, "total_events": sum(sum(row) for row in matrix)}
    except Exception as e:
        print(f"Heatmap query failed: {e}")
        return _fallback_heatmap()
    finally: close_db(conn)

def _fallback_heatmap():
    state = load_state()
    if not state: return {"labels_x": [], "labels_y": [], "data": []}
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    ip_hour = defaultdict(lambda: defaultdict(int))
    for ip, info in ip_data.items():
        if not isinstance(info, dict): continue
        cnt = _get_event_count(info)
        if cnt == 0: continue
        per_hour = cnt // 24
        for h in range(24): ip_hour[ip][h] += per_hour
    ip_totals = {ip: sum(hours.values()) for ip, hours in ip_hour.items()}
    sorted_ips = sorted(ip_totals.keys(), key=lambda x: ip_totals[x], reverse=True)[:50]
    matrix = [[ip_hour[ip].get(h, 0) for h in range(24)] for ip in sorted_ips]
    return {"labels_x": [f"{h:02d}:00" for h in range(24)], "labels_y": sorted_ips, "data": matrix, "total_events": sum(sum(row) for row in matrix)}

def query_ip_flow():
    conn = get_db()
    if not conn: return _fallback_flow()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, dst_ip, COUNT(*) as connection_count,
                   ARRAY_AGG(DISTINCT dst_port) as ports,
                   ARRAY_AGG(DISTINCT interface) as interfaces
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
            GROUP BY src_ip, dst_ip
            HAVING COUNT(*) > 1
            ORDER BY connection_count DESC
            LIMIT 500
        """)
        links = cur.fetchall()
        cur.execute("""
            SELECT src_ip, interface
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            AND src_ip IS NOT NULL
            GROUP BY src_ip, interface
        """)
        iface_rows = cur.fetchall()
        iface_by_ip = defaultdict(set)
        for row in iface_rows: iface_by_ip[row["src_ip"]].add(row["interface"])
        nodes = []
        node_map = {}
        colors = {"WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7", "SOURCE": "#3b82f6", "TARGET": "#f59e0b", "UNKNOWN": "#6b7280"}
        connections = []
        for row in links:
            src_ip = row["src_ip"] or "0.0.0.0"
            dst_ip = row["dst_ip"] or "0.0.0.0"
            count = row["connection_count"]
            if src_ip not in node_map:
                src_iface = iface_by_ip.get(src_ip, set())
                src_cat = classify_interface(list(src_iface)[0] if src_iface else None)
                if src_cat == "UNKNOWN": src_cat = "SOURCE"
                nodes.append({"id": src_ip, "label": src_ip, "category": src_cat, "color": colors.get(src_cat, "#3b82f6"), "size": min(6 + count, 24)})
                node_map[src_ip] = len(nodes) - 1
            if dst_ip not in node_map:
                dst_iface = iface_by_ip.get(dst_ip, set())
                dst_cat = classify_interface(list(dst_iface)[0] if dst_iface else None)
                if dst_cat == "UNKNOWN": dst_cat = "TARGET"
                nodes.append({"id": dst_ip, "label": dst_ip, "category": dst_cat, "color": colors.get(dst_cat, "#f59e0b"), "size": min(4 + count, 18)})
                node_map[dst_ip] = len(nodes) - 1
            ports = [str(p) for p in (row["ports"] or [])[:5]]
            connections.append({"source": src_ip, "target": dst_ip, "value": count, "ports": ports, "type": "traffic"})
        if len(nodes) > 60:
            node_conn = defaultdict(int)
            for c in connections:
                node_conn[c["source"]] += 1
                node_conn[c["target"]] += 1
            top_ids = sorted(node_conn.keys(), key=lambda x: node_conn[x], reverse=True)[:60]
            nodes = [n for n in nodes if n["id"] in top_ids]
            node_map = {n["id"]: i for i, n in enumerate(nodes)}
            connections = [c for c in connections if c["source"] in top_ids or c["target"] in top_ids]
        return {"nodes": nodes, "links": connections}
    except Exception as e:
        print(f"IP flow query failed: {e}")
        return _fallback_flow()
    finally: close_db(conn)

def _fallback_flow():
    state = load_state()
    if not state: return {"nodes": [], "links": []}
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    nodes = []
    node_map = {}
    connections = []
    colors = {"WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7", "UNKNOWN": "#6b7280"}
    ips = [(ip, info) for ip, info in ip_data.items() if isinstance(info, dict) and _get_event_count(info) > 0]
    ips.sort(key=lambda x: x[1].get("count", 0), reverse=True)
    for src_ip, src_info in ips[:60]:
        src_cat = src_info.get("category", "UNKNOWN")
        if src_ip not in node_map:
            nodes.append({"id": src_ip, "label": src_ip, "category": src_cat, "color": colors.get(src_cat, "#6b7280"), "size": min(6 + _get_event_count(src_info), 24)})
            node_map[src_ip] = len(nodes) - 1
        for dst_ip, dst_info in ips[:60]:
            if src_ip == dst_ip: continue
            cnt = _get_event_count(dst_info)
            if cnt > 0:
                link_val = min(_get_event_count(src_info), cnt) // 10
                if link_val > 0:
                    if dst_ip not in node_map:
                        dst_cat = dst_info.get("category", "UNKNOWN")
                        nodes.append({"id": dst_ip, "label": dst_ip, "category": dst_cat, "color": colors.get(dst_cat, "#6b7280"), "size": min(4 + cnt, 18)})
                        node_map[dst_ip] = len(nodes) - 1
                    connections.append({"source": src_ip, "target": dst_ip, "value": link_val, "type": "traffic"})
    return {"nodes": nodes, "links": connections}

# ── Clustered flow endpoint ──
NETWORK_CLUSTER_COLORS = {
    "WAN": "#ff006e",
    "LAN": "#00ff88",
    "VPN": "#8338ec",
    "INTERNAL": "#ffbe0b",
    "OWN": "#00e5ff",
}

def classify_ip_to_cluster(ip: str, iface_by_ip: dict) -> str:
    """Classify an IP into one of 5 network clusters."""
    if not ip or ip == "0.0.0.0":
        return "OWN"
    # Interface-based classification (from DB)
    ifaces = iface_by_ip.get(ip, set())
    for iface in ifaces:
        cat = classify_interface(iface)
        if cat == "WAN":
            return "WAN"
        if cat == "LAN":
            return "LAN"
        if cat == "VPN":
            return "VPN"
    # Fallback: classify by IP range
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3"):
        return "LAN"
    if ip.startswith("169.254."):
        return "INTERNAL"
    if ip.startswith("127."):
        return "INTERNAL"
    return "WAN"

def query_ip_flow_clusters(expand_cluster: str = None, edge_threshold: int = 0):
    """
    Return IP flow data aggregated into 5 network clusters (WAN, LAN, VPN, INTERNAL, OWN).
    Supports expanding a single cluster to individual IPs via ?expand=LAN.
    Edge threshold: edges below this value are hidden.
    """
    conn = get_db()
    if not conn:
        return {"nodes": [], "edges": [], "clusters": {}, "expand_cluster": expand_cluster, "edge_threshold": edge_threshold}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        # Get all connections
        cur.execute("""
            SELECT src_ip, dst_ip, COUNT(*) as connection_count,
                   ARRAY_AGG(DISTINCT dst_port) as ports
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
            GROUP BY src_ip, dst_ip
            HAVING COUNT(*) > 1
            ORDER BY connection_count DESC
            LIMIT 1000
        """)
        links = cur.fetchall()

        # Get interface mapping for classification
        cur.execute("""
            SELECT src_ip, interface
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            AND src_ip IS NOT NULL
            GROUP BY src_ip, interface
        """)
        iface_rows = cur.fetchall()
        iface_by_ip = defaultdict(set)
        for row in iface_rows:
            iface_by_ip[row["src_ip"]].add(row["interface"])

        # Build IP → cluster mapping + event counts
        ip_cluster = {}
        ip_events = defaultdict(int)
        for row in links:
            src = row["src_ip"] or "0.0.0.0"
            dst = row["dst_ip"] or "0.0.0.0"
            cnt = row["connection_count"]
            ip_events[src] += cnt
            ip_events[dst] += cnt
            if src not in ip_cluster:
                ip_cluster[src] = classify_ip_to_cluster(src, iface_by_ip)
            if dst not in ip_cluster:
                ip_cluster[dst] = classify_ip_to_cluster(dst, iface_by_ip)

        # Build cluster metadata
        clusters = {}
        for cat in ["WAN", "LAN", "VPN", "INTERNAL", "OWN"]:
            cat_ips = [ip for ip, c in ip_cluster.items() if c == cat]
            cat_events = sum(ip_events.get(ip, 0) for ip in cat_ips)
            if cat_ips:
                clusters[cat] = {
                    "id": f"cluster:{cat}",
                    "label": cat,
                    "category": cat,
                    "color": NETWORK_CLUSTER_COLORS[cat],
                    "ip_count": len(cat_ips),
                    "event_count": cat_events,
                }

        # Aggregate edges between clusters
        cluster_edges: dict = defaultdict(int)
        for row in links:
            src = row["src_ip"] or "0.0.0.0"
            dst = row["dst_ip"] or "0.0.0.0"
            cnt = row["connection_count"]
            src_cat = ip_cluster.get(src, "OWN")
            dst_cat = ip_cluster.get(dst, "OWN")
            if src_cat == dst_cat:
                continue  # skip intra-cluster edges
            edge_key = (src_cat, dst_cat)
            cluster_edges[edge_key] += cnt

        # Apply threshold
        cluster_edges = {k: v for k, v in cluster_edges.items() if v >= edge_threshold}

        # Build nodes
        nodes = []
        for cat in ["WAN", "LAN", "VPN", "INTERNAL", "OWN"]:
            if cat in clusters:
                clusters[cat]["size"] = min(8 + clusters[cat]["event_count"] // 100, 24)
                node = {
                    "id": clusters[cat]["id"],
                    "label": clusters[cat]["label"],
                    "category": cat,
                    "color": clusters[cat]["color"],
                    "size": clusters[cat]["size"],
                    "count": clusters[cat]["event_count"],
                    "is_cluster": True,
                    "ip_count": clusters[cat]["ip_count"],
                }
                nodes.append(node)

        edges = []
        for (src_cat, dst_cat), val in sorted(cluster_edges.items(), key=lambda x: x[1], reverse=True):
            edges.append({
                "source": f"cluster:{src_cat}",
                "target": f"cluster:{dst_cat}",
                "value": val,
            })

        # Handle cluster expansion: replace expanded cluster node with individual IPs
        if expand_cluster and expand_cluster in clusters:
            # Remove the cluster node
            nodes = [n for n in nodes if n["id"] != f"cluster:{expand_cluster}"]

            # Get all IPs in this cluster
            exp_ips = [(ip, ip_events.get(ip, 0)) for ip, c in ip_cluster.items() if c == expand_cluster]
            exp_ips.sort(key=lambda x: x[1], reverse=True)
            for ip, evt_count in exp_ips[:15]:
                nodes.append({
                    "id": ip,
                    "label": ip,
                    "category": expand_cluster,
                    "color": NETWORK_CLUSTER_COLORS[expand_cluster],
                    "size": min(6 + evt_count // 10, 16),
                    "count": evt_count,
                    "is_cluster": False,
                })

            # Rebuild edges: for each original edge touching this cluster,
            # fan out into per-IP edges by scanning the links.
            cluster_node_id = f"cluster:{expand_cluster}"
            new_edges = []
            for edge in edges:
                is_src_expanded = edge["source"] == cluster_node_id
                is_tgt_expanded = edge["target"] == cluster_node_id

                if is_src_expanded or is_tgt_expanded:
                    # Determine the other cluster
                    other_cluster_id = edge["target"] if is_src_expanded else edge["source"]
                    other_cat = other_cluster_id.replace("cluster:", "")

                    for exp_ip, _ in exp_ips:
                        ip_val = 0
                        for row in links:
                            src = row["src_ip"] or "0.0.0.0"
                            dst = row["dst_ip"] or "0.0.0.0"
                            cnt = row["connection_count"]
                            if is_src_expanded and src == exp_ip and ip_cluster.get(dst, "OWN") == other_cat:
                                ip_val += cnt
                            if is_tgt_expanded and dst == exp_ip and ip_cluster.get(src, "OWN") == other_cat:
                                ip_val += cnt

                        if ip_val >= edge_threshold:
                            if is_src_expanded:
                                new_edges.append({"source": exp_ip, "target": other_cluster_id, "value": ip_val})
                            else:
                                new_edges.append({"source": other_cluster_id, "target": exp_ip, "value": ip_val})
                else:
                    new_edges.append(edge)
            edges = new_edges

        return {
            "nodes": nodes,
            "edges": edges,
            "clusters": clusters,
            "expand_cluster": expand_cluster,
            "edge_threshold": edge_threshold,
        }
    except Exception as e:
        print(f"IP flow clusters query failed: {e}")
        return {"nodes": [], "edges": [], "clusters": {}, "expand_cluster": expand_cluster, "edge_threshold": edge_threshold}
    finally:
        close_db(conn)

def query_geo():
    conn = get_db()
    if not conn: return _fallback_geo()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, COUNT(*) as cnt
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            AND src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY cnt DESC
            LIMIT 1000
        """)
        rows = cur.fetchall()
        regions = defaultdict(int)
        for row in rows:
            ip, cnt = row["src_ip"], row["cnt"]
            first = _parse_ip_first_octet(ip)
            if first is None: regions["Other"] += cnt
            elif 114 <= first <= 125: regions["China"] += cnt
            elif first in [45, 64, 66, 70, 72, 74, 98, 99, 104, 108]: regions["US"] += cnt
            elif 5 <= first < 94: regions["Europe/Russia"] += cnt
            elif 14 <= first < 62: regions["Japan/Korea"] += cnt
            else: regions["Other"] += cnt
        flag_map = {"China": "China", "US": "US", "Europe/Russia": "Russia", "Japan/Korea": "Japan/Korea", "Other": "Other"}
        color_map = {"China": "#ef4444", "US": "#3b82f6", "Europe/Russia": "#f59e0b", "Japan/Korea": "#f43f5e", "Other": "#6b7280"}
        return [{"country": r, "count": c, "color": color_map.get(r, "#6b7280"), "flag": flag_map.get(r, "Other")} for r, c in sorted(regions.items(), key=lambda x: x[1], reverse=True)]
    except Exception as e:
        print(f"Geo query failed: {e}")
        return _fallback_geo()
    finally: close_db(conn)

def _fallback_geo():
    state = load_state()
    if not state: return []
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    regions = defaultdict(int)
    for ip, info in ip_data.items():
        if not isinstance(info, dict): continue
        cnt = _get_event_count(info)
        if cnt == 0: continue
        first = _parse_ip_first_octet(ip)
        if first is not None:
            if 114 <= first <= 125: regions["China"] += cnt
            elif first in [45, 64, 66, 70, 72, 74, 98, 99, 104, 108]: regions["US"] += cnt
            else: regions["Other"] += cnt
        else: regions["Other"] += cnt
    return [{"country": r, "count": c, "color": "#6b7280", "flag": "Other"} for r, c in sorted(regions.items(), key=lambda x: x[1], reverse=True)]

def query_events():
    conn = get_db()
    if not conn: return _fallback_events()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, COUNT(*) as event_count,
                   COUNT(DISTINCT dst_ip) as unique_dst,
                   COUNT(DISTINCT dst_port) as unique_ports,
                   interface
            FROM events
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            AND src_ip IS NOT NULL
            GROUP BY src_ip, interface
            HAVING COUNT(*) > 100
            ORDER BY event_count DESC
            LIMIT 20
        """)
        rows = cur.fetchall()
        events = []
        for row in rows:
            ip, cnt = row["src_ip"], row["event_count"]
            severity = "CRITICAL" if cnt > 10000 else "WARNING" if cnt > 1000 else "INFO"
            iface = row["interface"] or "unknown"
            category = classify_interface(iface)
            events.append({
                "attack_type": f"{category} traffic from {ip}",
                "details": f"{cnt:,} events, {row['unique_dst']} destinations, {row['unique_ports']} ports",
                "severity": severity, "count": cnt, "ip": ip, "category": category, "interface": iface,
            })
        cur.close()
        return events
    except Exception as e:
        print(f"Events query failed: {e}")
        return _fallback_events()
    finally: close_db(conn)

def _fallback_events():
    state = load_state()
    if not state: return []
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    events = []
    for ip, info in ip_data.items():
        if not isinstance(info, dict): continue
        cnt = _get_event_count(info)
        if cnt > 50:
            events.append({"attack_type": f"{info.get('category', 'UNKNOWN')} traffic", "details": f"{cnt:,} events", "severity": "CRITICAL" if cnt > 500 else "WARNING", "count": cnt, "ip": ip})
    events.sort(key=lambda e: e["count"], reverse=True)
    return events[:20]

def query_opnsense_status():
    opn_url, opn_key, opn_secret, verify_ssl = _read_opn_config()
    if not opn_url:
        return {"status": "disconnected", "error": "No OPNsense config found"}
    try:
        import urllib.request
        import urllib.error
        import ssl
        import base64

        ssl_context = ssl.create_default_context()
        if not verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        auth_string = f"{opn_key}:{opn_secret}"
        auth_b64 = base64.b64encode(auth_string.encode()).decode()
        auth_header = f"Basic {auth_b64}"

        results = {"status": "connected"}

        def _api_get(path):
            """Helper to GET an OPNsense API endpoint."""
            req = urllib.request.Request(
                f"{opn_url}{path}",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                return json.loads(resp.read().decode())

        # 1. Firmware/Version info
        try:
            sys_info = _api_get("/api/core/firmware/status")
            if isinstance(sys_info, dict):
                product = sys_info.get("product", {})
                results["opnsense_version"] = product.get("CORE_VERSION", product.get("CORE_SERIES", "unknown"))
                results["os_version"] = sys_info.get("os_version", "")
            else:
                results["opnsense_version"] = "unknown"
                results["os_version"] = ""
            results["status"] = "connected"
        except Exception as e:
            print(f"OPNsense firmware status failed: {e}")
            results["opnsense_version"] = "error"
            results["os_version"] = ""

        # 2. Gateways — PRIMARY source (works on OPNsense 26.4)
        results["gateways"] = []
        raw_gateways = []
        try:
            gw_data = _api_get("/api/routing/settings/searchGateway")
            raw_gateways = gw_data.get("rows", gw_data.get("gateways", []))
            for gw in raw_gateways:
                if gw.get("disabled"):
                    continue
                name = gw.get("name", gw.get("id", "unknown"))
                interface = gw.get("interface", "")
                iface_phys = gw.get("if", "")
                interface_descr = gw.get("interface_descr", "")
                gateway_ip = gw.get("gateway", "")
                ip_protocol = gw.get("ipprotocol", "inet")
                upstream = gw.get("upstream", False)
                status = gw.get("status", "unknown")
                # Parse delay/loss from string format "5.8 ms" / "0.0 %"
                delay_raw = gw.get("delay", "~")
                loss_raw = gw.get("loss", "~")
                try:
                    delay_val = float(str(delay_raw).replace(" ms", "").replace(" ", "")) if str(delay_raw) != "~" else 0
                except (ValueError, TypeError):
                    delay_val = 0
                try:
                    loss_val = float(str(loss_raw).replace(" %", "").replace(" ", "")) if str(loss_raw) != "~" else 0
                except (ValueError, TypeError):
                    loss_val = 0
                results["gateways"].append({
                    "name": name,
                    "interface": interface_descr or interface,
                    "interface_phys": iface_phys,
                    "gateway_ip": gateway_ip,
                    "ip_protocol": ip_protocol,
                    "upstream": upstream,
                    "vpn_gateway": bool(gw.get("gateway_interface", False)),
                    "status": status.lower() if status else "unknown",
                    "delay": delay_val,
                    "loss": loss_val,
                })
        except Exception as e:
            print(f"OPNsense gateways failed: {e}")

        # 3. Derive interfaces from gateways (works on all OPNsense versions)
        # /api/interfaces/assignments returns 404 on OPNsense 26.4
        results["interfaces"] = []
        iface_map = {}
        for gw in raw_gateways:
            if gw.get("disabled"):
                continue
            iface_phys = gw.get("if", "")
            if not iface_phys:
                continue
            interface = gw.get("interface", "")
            interface_descr = gw.get("interface_descr", "")
            ip_protocol = gw.get("ipprotocol", "inet")
            gateway_ip = gw.get("gateway", "")
            upstream = gw.get("upstream", False)
            gw_name = gw.get("name", "").upper()

            if iface_phys not in iface_map:
                # Detect type
                is_vpn = (
                    "VPN" in gw_name or "WG" in gw_name or
                    iface_phys.startswith("ovpn") or iface_phys.startswith("wg") or
                    iface_phys.startswith("tun") or gw.get("gateway_interface", False)
                )
                iface_type = "VPN" if is_vpn else ("WAN" if upstream else "LAN")
                iface_map[iface_phys] = {
                    "name": iface_phys,
                    "description": interface_descr or interface or iface_type,
                    "type": iface_type,
                    "ipv4": "",
                    "ipv6": "",
                    "mac": "",
                    "status": "online",  # default — update below
                }

            # Collect gateway IPs per interface
            if gateway_ip:
                if ":" in gateway_ip:
                    if not iface_map[iface_phys]["ipv6"]:
                        iface_map[iface_phys]["ipv6"] = gateway_ip
                else:
                    if not iface_map[iface_phys]["ipv4"]:
                        iface_map[iface_phys]["ipv4"] = gateway_ip

        # Update interface status from gateway status
        for gw in raw_gateways:
            if gw.get("disabled"):
                continue
            iface_phys = gw.get("if", "")
            gw_status = (gw.get("status") or "").lower()
            if iface_phys in iface_map and gw_status:
                if gw_status == "online":
                    iface_map[iface_phys]["status"] = "online"
                elif gw_status in ("down", "offline", "fault"):
                    iface_map[iface_phys]["status"] = gw_status
                elif iface_map[iface_phys]["status"] != "online":
                    iface_map[iface_phys]["status"] = gw_status

        results["interfaces"] = list(iface_map.values())

        # 4. System Resources — memory, CPU, uptime
        # OPNsense 26.4 systemResources only returns 'memory' — no loadavg or uptime.
        results["cpu_usage"] = -1  # -1 means "not available"
        results["memory_usage"] = 0
        results["memory_total_gb"] = 0
        results["memory_used_gb"] = 0
        results["uptime"] = ""
        results["uptime_seconds"] = 0
        try:
            sys_res = _api_get("/api/diagnostics/system/systemResources")
            if isinstance(sys_res, dict):
                # Memory — handle both string and int values
                mem = sys_res.get("memory", {})
                total_mem_str = str(mem.get("total", 0))
                used_mem_str = str(mem.get("used", 0))
                try:
                    total_mem = int(total_mem_str)
                    used_mem = int(used_mem_str)
                except (ValueError, TypeError):
                    total_mem = 0
                    used_mem = 0
                if total_mem > 0:
                    results["memory_usage"] = round(used_mem / total_mem * 100, 1)
                    results["memory_total_gb"] = round(total_mem / (1024**3), 1)
                    results["memory_used_gb"] = round(used_mem / (1024**3), 1)
                # CPU load — only available on older OPNsense
                load_avg = sys_res.get("loadavg", None)
                if load_avg and isinstance(load_avg, dict):
                    try:
                        load1 = float(load_avg.get("loadavg_1m", load_avg.get("1", 0)))
                        results["cpu_usage"] = round(load1 * 100, 1)
                    except (ValueError, TypeError):
                        pass
                # Uptime — only available on older OPNsense
                uptime_raw = sys_res.get("uptime", None)
                if isinstance(uptime_raw, dict):
                    uptime_secs = int(uptime_raw.get("raw", 0))
                    results["uptime_seconds"] = uptime_secs
                    days = uptime_secs // 86400
                    hours = (uptime_secs % 86400) // 3600
                    mins = (uptime_secs % 3600) // 60
                    if days > 0:
                        results["uptime"] = f"{days}d {hours}h"
                    elif hours > 0:
                        results["uptime"] = f"{hours}h {mins}m"
                    else:
                        results["uptime"] = f"{mins}m"
        except Exception as e:
            print(f"OPNsense system resources failed: {e}")

        # 4b. Try alternate endpoints for CPU/uptime on OPNsense 26.4
        # /api/diagnostics/system/system_information has hostname + version
        try:
            sys_info = _api_get("/api/diagnostics/system/system_information")
            if isinstance(sys_info, dict):
                results["hostname"] = sys_info.get("name", "")
        except Exception as e:
            print(f"OPNsense system_information failed: {e}")

        # Try /api/diagnostics/system/memory for vmstat (CPU threads as proxy)
        try:
            vm_data = _api_get("/api/diagnostics/system/memory")
            if isinstance(vm_data, dict):
                vmstat = vm_data.get("vmstat", {})
                malloc_stats = vmstat.get("malloc-statistics", {}).get("memory", [])
                # Sum malloc requests as a rough activity indicator
                total_requests = sum(m.get("requests", 0) for m in malloc_stats)
                results["malloc_requests"] = total_requests
        except Exception as e:
            print(f"OPNsense vmstat failed: {e}")

        # 5. Interface statistics — bandwidth data
        # /api/diagnostics/interface/getInterfaceStatistics returns bytes/packets per interface
        interface_stats = {}
        try:
            stats_data = _api_get("/api/diagnostics/interface/getInterfaceStatistics")
            if isinstance(stats_data, dict):
                stats = stats_data.get("statistics", {})
                for key, val in stats.items():
                    if not isinstance(val, dict):
                        continue
                    iface_name = val.get("name", "")
                    if not iface_name:
                        continue
                    if iface_name not in interface_stats:
                        interface_stats[iface_name] = {
                            "received_bytes": 0,
                            "sent_bytes": 0,
                            "received_packets": 0,
                            "sent_packets": 0,
                            "received_errors": 0,
                            "send_errors": 0,
                            "dropped_packets": 0,
                        }
                    current = interface_stats[iface_name]
                    # Only count from the link-level entry (Link#N), skip IP-level dupes
                    if "<Link" in str(val.get("network", "")):
                        current["received_bytes"] = int(str(val.get("received-bytes", 0)))
                        current["sent_bytes"] = int(str(val.get("sent-bytes", 0)))
                        current["received_packets"] = int(str(val.get("received-packets", 0)))
                        current["sent_packets"] = int(str(val.get("sent-packets", 0)))
                        current["received_errors"] = int(str(val.get("received-errors", 0)))
                        current["send_errors"] = int(str(val.get("send-errors", 0)))
                        current["dropped_packets"] = int(str(val.get("dropped-packets", 0)))
                    # Collect MAC from the link-level entry
                    mac = val.get("address", "")
                    if mac and "<Link" in str(val.get("network", "")):
                        current["mac"] = mac
        except Exception as e:
            print(f"OPNsense interface stats failed: {e}")

        # Enrich interface data with bandwidth stats
        for iface in results.get("interfaces", []):
            name = iface.get("name", "")
            if name in interface_stats:
                st = interface_stats[name]
                iface["received_bytes"] = st.get("received_bytes", 0)
                iface["sent_bytes"] = st.get("sent_bytes", 0)
                iface["received_packets"] = st.get("received_packets", 0)
                iface["sent_packets"] = st.get("sent_packets", 0)
                iface["received_errors"] = st.get("received_errors", 0)
                iface["send_errors"] = st.get("send_errors", 0)
                iface["dropped_packets"] = st.get("dropped_packets", 0)
                mac = st.get("mac", "")
                if mac and not iface.get("mac"):
                    iface["mac"] = mac

        # 6. Services count
        results["services_total"] = 0
        results["services_running"] = 0
        results["services"] = []
        try:
            svc_data = _api_get("/api/core/service/search")
            if isinstance(svc_data, dict):
                svc_rows = svc_data.get("rows", [])
                results["services_total"] = svc_data.get("total", len(svc_rows))
                running_count = sum(1 for s in svc_rows if s.get("running") == 1)
                results["services_running"] = running_count
                # Include top services in response
                for svc in svc_rows[:10]:
                    results["services"].append({
                        "name": svc.get("name", svc.get("id", "")),
                        "status": "running" if svc.get("running") == 1 else "stopped",
                        "description": svc.get("description", ""),
                    })
        except Exception as e:
            print(f"OPNsense service search failed: {e}")

        # 7. Firewall rules count
        results["firewall_rules"] = 0
        try:
            rules_data = _api_get("/api/firewall/rules/search")
            if isinstance(rules_data, dict):
                results["firewall_rules"] = rules_data.get("total", 0)
            elif isinstance(rules_data, list):
                results["firewall_rules"] = len(rules_data)
        except Exception as e:
            print(f"OPNsense rules failed: {e}")

        # 6. OpenVPN status
        results["openvpn_tunnels"] = []
        try:
            vpn_data = _api_get("/api/services/openvpn/status")
            if isinstance(vpn_data, dict):
                for key, status in vpn_data.items():
                    if isinstance(status, dict):
                        results["openvpn_tunnels"].append({
                            "type": "client" if "client" in key.lower() else "server",
                            "status": status.get("status", status.get("state", "unknown")),
                            "peer": status.get("peer", status.get("remote_host", "")),
                            "local": status.get("local", status.get("local_host", "")),
                            "bytes_in": status.get("bytes_in", 0),
                            "bytes_out": status.get("bytes_out", 0),
                            "uptime": status.get("uptime", ""),
                        })
        except Exception as e:
            print(f"OPNsense OpenVPN failed: {e}")

        # 7. NTP status
        results["ntp_status"] = {}
        try:
            ntp_data = _api_get("/api/services/ntp/status")
            if isinstance(ntp_data, dict):
                results["ntp_status"] = {
                    "status": ntp_data.get("status", ntp_data.get("state", "unknown")),
                    "servers": ntp_data.get("servers", ntp_data.get("config", [])),
                    "last_sync": ntp_data.get("last_sync", ntp_data.get("last_update", "")),
                }
        except Exception as e:
            print(f"OPNsense NTP failed: {e}")

        # 8. DNS status (try dnsmasq first, then unbound)
        results["dns_status"] = {}
        try:
            dns_data = _api_get("/api/services/dnsmasq/status")
            if isinstance(dns_data, dict):
                results["dns_status"] = {
                    "status": dns_data.get("status", dns_data.get("state", "unknown")),
                    "type": "dnsmasq",
                }
        except Exception:
            try:
                dns_data = _api_get("/api/services/unbound/status")
                if isinstance(dns_data, dict):
                    results["dns_status"] = {
                        "status": dns_data.get("status", dns_data.get("state", "unknown")),
                        "type": "unbound",
                    }
            except Exception:
                pass

        return results
    except Exception as e:
        return {
            "status": "disconnected", "error": str(e),
            "opnsense_version": "unknown", "os_version": "",
            "interfaces": [], "gateways": [],
            "cpu_usage": -1, "memory_usage": 0, "uptime": "", "uptime_seconds": 0,
            "memory_total_gb": 0, "memory_used_gb": 0,
            "hostname": "",
            "firewall_rules": 0, "openvpn_tunnels": [],
            "services_total": 0, "services_running": 0, "services": [],
            "ntp_status": {}, "dns_status": {},
        }

def query_alerts():
    conn = get_db()
    if not conn: return _fallback_alerts()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, COUNT(*) as cnt, COUNT(DISTINCT dst_ip) as unique_dst, interface, MAX(timestamp) as latest_timestamp
            FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, interface
            HAVING COUNT(*) > 1000
            ORDER BY cnt DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        alerts = []
        for row in rows:
            cnt = row["cnt"]
            severity = "CRITICAL" if cnt > 10000 else "WARNING"
            alerts.append({
                "ip": row["src_ip"] or "0.0.0.0",
                "attack_type": f"{classify_interface(row['interface'])} traffic",
                "count": cnt,
                "severity": severity,
                "unique_destinations": row["unique_dst"],
                "interface": row["interface"],
                "timestamp": str(row["latest_timestamp"]) if row["latest_timestamp"] else "",
                "_fix": "v2",  # debug marker
            })
        return alerts
    except Exception as e:
        print(f"Alerts query failed: {e}")
        return _fallback_alerts()
    finally: close_db(conn)

def _fallback_alerts():
    state = load_state()
    if not state: return []
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    alerts = []
    for ip, info in ip_data.items():
        if not isinstance(info, dict): continue
        cnt = _get_event_count(info)
        if cnt > 50:
            alerts.append({"ip": ip, "attack_type": f"{info.get('category', 'UNKNOWN')} traffic", "count": cnt, "severity": "CRITICAL" if cnt > 500 else "WARNING"})
    alerts.sort(key=lambda a: a["count"], reverse=True)
    return alerts[:50]

def query_anomalies():
    """Query recent anomalies from database."""
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, attack_type, severity, description, src_ip, dst_ip, timestamp
            FROM anomalies
            ORDER BY id DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        anomalies = []
        for row in rows:
            anomalies.append({
                "id": row["id"],
                "type": row.get("attack_type", "UNKNOWN"),
                "severity": row["severity"],
                "description": row["description"],
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "timestamp": str(row["timestamp"]) if row["timestamp"] else ""
            })
        return anomalies
    except Exception as e:
        print(f"Anomalies query failed: {e}")
        return []
    finally: close_db(conn)

def query_new_since(since_ts: str):
    """Query what's changed since a given timestamp (epoch seconds or ISO).
    Returns new events count, new anomalies, new unique IPs, new rule matches,
    and baseline breaches since the given time.
    """
    conn = get_db()
    state = load_state()
    agent_counters = {}
    if state:
        agent_counters = state.get("agent_counters", {})

    # Current counters (total ever)
    current_event_count = agent_counters.get("event_count", 0)
    current_anomaly_count = agent_counters.get("anomaly_count", 0)

    # Parse since_ts to a PostgreSQL timestamp
    try:
        since_epoch = float(since_ts)
        since_dt = datetime.fromtimestamp(since_epoch, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return {
            "since_ts": None,
            "hours_since": None,
            "new_events": 0,
            "new_anomalies": 0,
            "new_blocked": 0,
            "new_unique_ips": [],
            "new_rule_matches": [],
            "new_baseline_breaches": [],
            "first_time": False,
        }

    is_first_time = False

    if not conn:
        return {
            "since_ts": since_ts,
            "hours_since": round((time.time() - since_epoch) / 3600, 1),
            "new_events": 0,
            "new_anomalies": 0,
            "new_blocked": 0,
            "new_unique_ips": [],
            "new_rule_matches": [],
            "new_baseline_breaches": [],
            "first_time": True,
        }

    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # New events since timestamp
        cur.execute(
            "SELECT COUNT(*) as cnt FROM events WHERE timestamp > %s",
            (since_dt,),
        )
        new_events = cur.fetchone()["cnt"]

        # New blocked since timestamp
        cur.execute(
            "SELECT COUNT(*) as cnt FROM events WHERE timestamp > %s AND action = 'BLOCK'",
            (since_dt,),
        )
        new_blocked = cur.fetchone()["cnt"]

        # New anomalies since timestamp
        cur.execute(
            "SELECT COUNT(*) as cnt FROM anomalies WHERE created_at > %s",
            (since_dt,),
        )
        new_anomalies = cur.fetchone()["cnt"]

        # New unique source IPs (not seen before this timestamp)
        cur.execute(
            """
            SELECT e.src_ip, COUNT(*) as cnt
            FROM events e
            WHERE e.timestamp > %s AND e.src_ip IS NOT NULL AND e.src_ip != ''
              AND NOT EXISTS (
                SELECT 1 FROM events e2
                WHERE e2.src_ip = e.src_ip AND e2.timestamp <= %s
              )
            GROUP BY e.src_ip
            ORDER BY cnt DESC
            LIMIT 20
            """,
            (since_dt, since_dt),
        )
        new_unique_ips = [
            {"ip": row["src_ip"], "count": row["cnt"]}
            for row in cur.fetchall()
        ]

        # New rule matches (rules that started triggering since timestamp)
        cur.execute(
            """
            SELECT e.rule_name, COUNT(*) as cnt, MAX(e.timestamp) as last_seen
            FROM events e
            WHERE e.timestamp > %s AND e.rule_name IS NOT NULL AND e.rule_name != ''
              AND NOT EXISTS (
                SELECT 1 FROM events e2
                WHERE e2.rule_name = e.rule_name AND e2.timestamp <= %s
              )
            GROUP BY e.rule_name
            ORDER BY cnt DESC
            LIMIT 15
            """,
            (since_dt, since_dt),
        )
        new_rule_matches = [
            {"rule": row["rule_name"], "count": row["cnt"], "last_seen": str(row["last_seen"])}
            for row in cur.fetchall()
        ]

        # Baseline breaches (rules with high deviation since timestamp)
        cur.execute(
            """
            SELECT rb.rule_name, rb.current_rate, rb.baseline_rate,
                   (rb.current_rate / NULLIF(rb.baseline_rate, 0)) as deviation
            FROM rule_baselines rb
            WHERE rb.last_updated > %s
              AND rb.current_rate > 0
              AND rb.baseline_rate > 0
              AND (rb.current_rate / NULLIF(rb.baseline_rate, 0)) > 2.0
            ORDER BY deviation DESC
            LIMIT 10
            """,
            (since_dt,),
        )
        new_baseline_breaches = [
            {
                "rule_name": row["rule_name"],
                "current_rate": row["current_rate"],
                "baseline_rate": row["baseline_rate"],
                "deviation": round(float(row["deviation"]) if row["deviation"] else 0, 1),
            }
            for row in cur.fetchall()
        ]

        cur.close()

        hours_since = round((time.time() - since_epoch) / 3600, 1)

        return {
            "since_ts": since_ts,
            "hours_since": hours_since,
            "new_events": new_events,
            "new_anomalies": new_anomalies,
            "new_blocked": new_blocked,
            "new_unique_ips": new_unique_ips,
            "new_rule_matches": new_rule_matches,
            "new_baseline_breaches": new_baseline_breaches,
            "first_time": False,
        }

    except Exception as e:
        logger.error(f"New-since query failed: {e}")
        return {
            "since_ts": since_ts,
            "hours_since": None,
            "new_events": 0,
            "new_anomalies": 0,
            "new_blocked": 0,
            "new_unique_ips": [],
            "new_rule_matches": [],
            "new_baseline_breaches": [],
            "first_time": False,
        }
    finally:
        close_db(conn)

def query_ip_detail(ip: str):
    """Comprehensive drill-down for a single IP address."""
    if not ip or ip == "0.0.0.0":
        return {"error": "Invalid IP", "ip": ip}

    # Network classification
    category = classify_ip_to_cluster(ip, {})

    # Default result structure
    result = {
        "ip": ip,
        "category": category,
        "is_private": ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3"),
        "total_events": 0,
        "total_blocked": 0,
        "total_passed": 0,
        "unique_sources": 0,
        "unique_destinations": 0,
        "unique_ports": 0,
        "protocols": [],
        "top_ports": [],
        "top_counterparts": [],
        "interfaces": [],
        "recent_events": [],
        "timeline": [],
        "threat_indicators": [],
        "dns_reverse": None,
        "geo_hint": None,
    }

    # Try persistent DB first
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Total event counts
            cur.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) as blocked,
                       SUM(CASE WHEN action = 'pass' THEN 1 ELSE 0 END) as passed
                FROM events
                WHERE src_ip = %s OR dst_ip = %s
                AND timestamp > NOW() - INTERVAL '24 hours'
            """, (ip, ip))
            row = cur.fetchone()
            result["total_events"] = row["total"] or 0
            result["total_blocked"] = row["blocked"] or 0
            result["total_passed"] = row["passed"] or 0

            # Unique sources/destinations
            cur.execute("""
                SELECT COUNT(DISTINCT src_ip) as src_count, COUNT(DISTINCT dst_ip) as dst_count, COUNT(DISTINCT dst_port) as port_count
                FROM events
                WHERE src_ip = %s OR dst_ip = %s
                AND timestamp > NOW() - INTERVAL '24 hours'
            """, (ip, ip))
            row = cur.fetchone()
            result["unique_sources"] = row["src_count"] or 0
            result["unique_destinations"] = row["dst_count"] or 0
            result["unique_ports"] = row["port_count"] or 0

            # Protocol distribution
            cur.execute("""
                SELECT proto, COUNT(*) as cnt
                FROM events WHERE (src_ip = %s OR dst_ip = %s)
                AND timestamp > NOW() - INTERVAL '24 hours'
                AND proto IS NOT NULL AND proto != ''
                GROUP BY proto ORDER BY cnt DESC
            """, (ip, ip))
            result["protocols"] = [{"proto": r["proto"], "count": r["cnt"]} for r in cur.fetchall()]

            # Top destination ports
            cur.execute("""
                SELECT dst_port, COUNT(*) as cnt
                FROM events WHERE (src_ip = %s OR dst_ip = %s)
                AND timestamp > NOW() - INTERVAL '24 hours'
                AND dst_port IS NOT NULL
                GROUP BY dst_port ORDER BY cnt DESC LIMIT 10
            """, (ip, ip))
            result["top_ports"] = [{"port": r["dst_port"], "count": r["cnt"]} for r in cur.fetchall()]

            # Top counterpart IPs (if this is source, show dests; if dest, show sources)
            cur.execute("""
                SELECT dst_ip as ip, COUNT(*) as cnt
                FROM events WHERE src_ip = %s
                AND timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY dst_ip ORDER BY cnt DESC LIMIT 10
            """, (ip,))
            result["top_counterparts"] = [{"ip": r["ip"], "count": r["cnt"], "role": "destination"} for r in cur.fetchall()]

            # Also top sources targeting this IP
            cur.execute("""
                SELECT src_ip as ip, COUNT(*) as cnt
                FROM events WHERE dst_ip = %s
                AND timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
            """, (ip,))
            for r in cur.fetchall():
                result["top_counterparts"].append({"ip": r["ip"], "count": r["cnt"], "role": "source"})

            # Interfaces
            cur.execute("""
                SELECT interface, COUNT(*) as cnt
                FROM events WHERE (src_ip = %s OR dst_ip = %s)
                AND timestamp > NOW() - INTERVAL '24 hours'
                AND interface IS NOT NULL
                GROUP BY interface ORDER BY cnt DESC
            """, (ip, ip))
            result["interfaces"] = [{"name": r["interface"], "count": r["cnt"]} for r in cur.fetchall()]

            # Recent events (last 20)
            cur.execute("""
                SELECT timestamp, action, proto, src_ip, dst_ip, dst_port, rule_name, interface
                FROM events WHERE (src_ip = %s OR dst_ip = %s)
                AND timestamp > NOW() - INTERVAL '24 hours'
                ORDER BY timestamp DESC LIMIT 20
            """, (ip, ip))
            result["recent_events"] = [{
                "timestamp": str(r["timestamp"]),
                "action": r["action"] or "",
                "protocol": r["proto"] or "",
                "src_ip": r["src_ip"] or "",
                "dst_ip": r["dst_ip"] or "",
                "dst_port": r["dst_port"],
                "rule": r["rule_name"] or "",
                "interface": r["interface"] or "",
            } for r in cur.fetchall()]

            # Timeline (hourly for 24h)
            cur.execute("""
                SELECT DATE_TRUNC('hour', timestamp) as hour, COUNT(*) as cnt
                FROM events WHERE (src_ip = %s OR dst_ip = %s)
                AND timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY DATE_TRUNC('hour', timestamp)
                ORDER BY hour
            """, (ip, ip))
            result["timeline"] = [{"hour": str(r["hour"]), "count": r["cnt"]} for r in cur.fetchall()]

            # Check anomalies for this IP
            cur.execute("""
                SELECT type, severity, description, src_ip, timestamp
                FROM anomalies WHERE src_ip = %s
                ORDER BY timestamp DESC LIMIT 10
            """, (ip,))
            result["threat_indicators"] = [{
                "type": r["type"],
                "severity": r["severity"],
                "description": r["description"],
                "timestamp": str(r["timestamp"]),
            } for r in cur.fetchall()]

            cur.close()
        except Exception as e:
            print(f"IP detail query failed: {e}")
        finally:
            close_db(conn)

    # Geo hint from first octet
    first = _parse_ip_first_octet(ip)
    if first is not None:
        if 114 <= first <= 125:
            result["geo_hint"] = "Asia (China range)"
        elif first in [45, 64, 66, 70, 72, 74, 98, 99, 104, 108]:
            result["geo_hint"] = "North America (US range)"
        elif 5 <= first < 94:
            result["geo_hint"] = "Europe/Russia"
        elif 14 <= first < 62:
            result["geo_hint"] = "Japan/Korea"

    # Try reverse DNS from cached state
    state = load_state()
    if state:
        rdns_cache = state.get("reverse_dns", {})
        if ip in rdns_cache:
            entry = rdns_cache[ip]
            if isinstance(entry, dict):
                result["dns_reverse"] = entry.get("hostname")
            elif isinstance(entry, str):
                result["dns_reverse"] = entry

    # Mute/watchlist status
    mutes = load_mutes()
    is_muted = any(m.get("ip") == ip for m in mutes if isinstance(m, dict))
    result["is_muted"] = is_muted
    watchlist = load_watchlist()
    is_watched = any(w.get("ip") == ip for w in watchlist if isinstance(w, dict))
    result["is_watched"] = is_watched

    return result

def query_service_status():
    """Read service monitor state from JSON file."""
    state_path = os.path.join(DATA_DIR, "service_monitor.json")
    if not os.path.exists(state_path):
        return {
            "services": {},
            "services_tracked": 5,
            "services_monitored": 0,
            "api_polls": 0,
        }
    
    try:
        with open(state_path) as f:
            state = json.load(f)
        
        services = state.get("services", {})
        total_events = sum(s.get("total_events", 0) for s in services.values())
        
        # Count monitored vs not monitored
        services_monitored = sum(s.get("monitored", False) for s in services.values())
        
        # Build summary with API-based metrics
        services_summary = {}
        for name, svc_data in services.items():
            metrics = svc_data.get("metrics", {})
            service_metrics = {}
            
            # Unbound-specific metrics (from API)
            if "unbound_settings" in metrics:
                settings = metrics["unbound_settings"]
                service_metrics["unbound_enabled"] = settings.get("enabled", False)
                service_metrics["unbound_port"] = settings.get("port", "53")
                service_metrics["unbound_dnssec"] = settings.get("dnssec_enabled", False)
                service_metrics["unbound_acl_count"] = settings.get("acl_count", 0)
                service_metrics["unbound_forward_zones"] = settings.get("forward_zone_count", 0)
                service_metrics["unbound_poll_count"] = settings.get("poll_count", 0)
            else:
                settings = {}
            
            # WireGuard-specific metrics (from API)
            if "wg_peers" in metrics:
                wg = metrics["wg_peers"]
                service_metrics["wg_server_count"] = len(wg.get("servers", []))
                service_metrics["wg_client_count"] = len(wg.get("clients", []))
                service_metrics["wg_total_peers"] = wg.get("total_peers", 0)
                # List client names (safe — no keys exposed)
                client_names = [c.get("name", "") for c in wg.get("clients", []) if c.get("enabled") == "1"]
                service_metrics["wg_active_clients"] = client_names
                server_info = [{"name": s.get("name", ""), "enabled": s.get("enabled", False)}
                              for s in wg.get("servers", [])]
                service_metrics["wg_servers"] = server_info
                service_metrics["wg_poll_count"] = settings.get("poll_count", 0)
            
            services_summary[name] = {
                "total_events": svc_data.get("total_events", 0),
                "anomaly_count": len(svc_data.get("anomaly_log", [])),
                "first_seen": svc_data.get("first_seen"),
                "last_seen": svc_data.get("last_seen"),
                "monitored": svc_data.get("monitored", False),
                "metrics": service_metrics,
                "anomalies": svc_data.get("anomaly_log", []),
            }
        
        return {
            "services_tracked": len(services),
            "services_monitored": services_monitored,
            "total_events": total_events,
            "services": services_summary,
        }
    except Exception as e:
        return {"error": str(e), "services_tracked": 0, "services_monitored": 0}

def query_resources():
    """Resource monitoring endpoint — memory, CPU, DB size, disk usage, Redis.

    Returns structured resource data with threshold status.
    Thresholds: memory > 80% warning / > 95% critical, disk > 90% warning / > 95% critical.
    """
    from health_monitor import get_system_metrics

    try:
        metrics = get_system_metrics(db_size=True, disk=True, redis_memory=True)
    except Exception as e:
        return {"error": str(e), "resources": {}}

    # Determine threshold status
    status = "ok"
    warnings: list[str] = []

    # Memory check (> 80% warning, > 95% critical)
    mem = metrics.get("memory", {})
    if "error" not in mem:
        pct = mem.get("pct_used", 0)
        if pct >= 95.0:
            mem["status"] = "critical"
            status = "critical"
        elif pct >= 80.0:
            mem["status"] = "warning"
            warnings.append(f"Memory at {pct}%")
            if status == "ok":
                status = "warning"
        else:
            mem["status"] = "ok"

    # CPU check
    cpu = metrics.get("cpu", {})
    if "error" not in cpu:
        usage = cpu.get("usage_pct", 0)
        if usage >= 98.0:
            cpu["status"] = "critical"
            status = "critical"
        elif usage >= 90.0:
            cpu["status"] = "warning"
            warnings.append(f"CPU at {usage}%")
            if status == "ok":
                status = "warning"
        else:
            cpu["status"] = "ok"

    # DB size check
    db = metrics.get("db_size", {})
    if "error" not in db:
        db_mb = db.get("mb", 0)
        if db_mb >= 5120:
            db["status"] = "critical"
            status = "critical"
        elif db_mb >= 2048:
            db["status"] = "warning"
            warnings.append(f"Database size {db_mb:.0f} MB")
            if status == "ok":
                status = "warning"
        else:
            db["status"] = "ok"

    # Disk check (> 90% warning, > 95% critical)
    disk = metrics.get("disk", {})
    if "error" not in disk:
        pct = disk.get("pct_used", 0)
        if pct >= 95.0:
            disk["status"] = "critical"
            status = "critical"
        elif pct >= 90.0:
            disk["status"] = "warning"
            warnings.append(f"Disk at {pct}%")
            if status == "ok":
                status = "warning"
        else:
            disk["status"] = "ok"

    # Redis memory check
    redis = metrics.get("redis", {})
    redis_status = redis.get("status", "ok")
    if redis_status == "warning":
        warnings.append(f"Redis memory at {redis.get('pct_of_max', 'N/A')}% of max")
        if status == "ok":
            status = "warning"
    elif redis_status == "critical":
        status = "critical"
        warnings.append(f"Redis memory critical at {redis.get('pct_of_max', 'N/A')}% of max")

    return {
        "status": status,
        "warnings": warnings,
        "resources": metrics,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def query_health():
    """Aggregated health check for all subsystems."""
    import requests as req_lib
    
    state = load_state()
    agent_counters = {}
    if state:
        agent_counters = state.get("agent_counters", {})
    uptime = _calc_uptime(agent_counters)
    
    subsystems = {}
    overall_status = "healthy"
    event_count = 0
    anomaly_count = 0
    
    # --- PostgreSQL ---
    db_conn = get_db()
    if db_conn:
        try:
            cur = db_conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events")
            event_count = (cur.fetchone() or (0,))[0]
            cur.execute("SELECT COUNT(*) FROM anomalies")
            anomaly_count = (cur.fetchone() or (0,))[0]
            cur.close()
            close_db(db_conn)
            subsystems["database"] = {"status": "connected", "message": f"{event_count:,} events, {anomaly_count:,} anomalies"}
        except Exception as e:
            close_db(db_conn)
            subsystems["database"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
    else:
        subsystems["database"] = {"status": "disconnected", "message": "Cannot connect to PostgreSQL"}
        overall_status = "degraded"

    # --- Connection pool metrics ---
    try:
        from eventdb import EventDatabase as _ED
        _pool = _ED._pool
        if _pool:
            _used = len(getattr(_pool, "_used", {}))
            _avail = len(getattr(_pool, "_pool", []))
            _max = _pool.maxconn
            subsystems["pool"] = {
                "status": "ok",
                "message": f"Pool: {_used}/{_max} active, {_avail} available",
                "active": _used,
                "available": _avail,
                "max": _max,
                "utilization_pct": round(_used / _max * 100, 1) if _max else 0,
            }
    except Exception:
        subsystems["pool"] = {"status": "unknown", "message": "Could not read pool metrics"}
    
    # --- Redis ---
    r = get_redis()
    if r:
        try:
            r.ping()
            info = r.info("memory")
            mem_used = info.get("used_memory_human", "unknown")
            subsystems["redis"] = {"status": "connected", "message": f"Memory: {mem_used}"}
        except Exception as e:
            subsystems["redis"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
    else:
        subsystems["redis"] = {"status": "disconnected", "message": "Redis not available"}
        # Redis is optional for non-critical features
    
    # --- OPNsense API ---
    opn_host = os.environ.get("OPN_HOST", "")
    opn_port = os.environ.get("OPN_PORT", "6666")
    opn_key = os.environ.get("OPN_API_KEY", "")
    opn_secret = os.environ.get("OPN_API_SECRET", "")
    if opn_host and opn_key and opn_secret:
        try:
            import base64 as b64
            creds = f"{opn_key}:{opn_secret}"
            auth = f"Basic {b64.b64encode(creds.encode()).decode()}"
            resp = req_lib.get(
                f"https://{opn_host}:{opn_port}/api/core/firmware/status",
                headers={"Authorization": auth},
                timeout=5,
                verify=False,
            )
            if resp.status_code == 200:
                version = resp.json().get("os_version", "unknown")
                subsystems["opnsense"] = {"status": "connected", "message": f"OPNsense {version}"}
            else:
                subsystems["opnsense"] = {"status": "error", "message": f"HTTP {resp.status_code}"}
                overall_status = "degraded"
        except Exception as e:
            subsystems["opnsense"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
    else:
        subsystems["opnsense"] = {"status": "configured", "message": "OPNsense API not configured (no credentials)"}
    
    # --- Syslog listener ---
    syslog_enabled = os.environ.get("SYSLOG_ENABLED", "false").lower() == "true"
    syslog_port = os.environ.get("SYSLOG_UDP_PORT", "1514")
    if syslog_enabled:
        # Check if the port is actually listening by trying a local connection
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", int(syslog_port)))
        sock.close()
        # UDP port, so we can't truly check — rely on event count growth
        if event_count > 0:
            subsystems["syslog"] = {"status": "active", "message": f"UDP listener on port {syslog_port} (events flowing)"}
        else:
            subsystems["syslog"] = {"status": "questionable", "message": f"UDP listener on port {syslog_port} (no events yet)"}
    else:
        subsystems["syslog"] = {"status": "disabled", "message": "Syslog listener not enabled"}
    
    # --- Discord bot ---
    discord_token = os.environ.get("DISCORD_TOKEN", "")
    if discord_token:
        subsystems["discord"] = {"status": "configured", "message": "Discord bot token set (connection state checked via bot gateway)"}
    else:
        subsystems["discord"] = {"status": "disabled", "message": "Discord bot not configured"}
    
    # --- Disk space (agent_data dir) ---
    try:
        import shutil
        total, used, free = shutil.disk_usage(DATA_DIR)
        free_gb = free / (1024**3)
        if free_gb < 1:
            subsystems["disk"] = {"status": "warning", "message": f"{free_gb:.1f} GB free"}
            if overall_status == "healthy":
                overall_status = "degraded"
        else:
            subsystems["disk"] = {"status": "ok", "message": f"{free_gb:.1f} GB free"}
    except Exception:
        subsystems["disk"] = {"status": "unknown", "message": "Could not check disk space"}
    
    # Determine overall status
    if overall_status == "healthy" and event_count > 0:
        overall_status = "healthy"
    elif overall_status == "healthy" and event_count == 0:
        overall_status = "cold-start"
    
    return {
        "status": overall_status,
        "subsystems": subsystems,
        "events_processed": event_count,
        "anomalies_detected": agent_counters.get("anomaly_count", 0),
        "uptime_seconds": uptime,
        "draining": is_draining(),
        "active_requests": get_active_request_count(),
    }


def query_schema_migrations():
    """Return schema migration status for admin dashboard."""
    from schema_migrations import get_schema_version, get_migration_status, CURRENT_SCHEMA_VERSION
    
    db = get_db()
    if not db:
        return {
            "current_version": "unknown",
            "target_version": CURRENT_SCHEMA_VERSION,
            "is_current": False,
            "error": "Database not connected",
        }
    
    try:
        return get_migration_status(db)
    except Exception as e:
        return {
            "current_version": "unknown",
            "target_version": CURRENT_SCHEMA_VERSION,
            "is_current": False,
            "error": str(e),
        }
    finally:
        close_db(db)


def query_version():
    """Return deployment version info (git commit, build time, deploy state)."""
    import subprocess

    result = {"version": "unknown", "commit": "unknown", "build_time": "unknown"}

    # Git commit SHA
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, cwd="/app").decode().strip()
        result["commit"] = commit
    except Exception:
        pass

    # Build time from image label or file
    try:
        import os as _os
        if _os.path.exists("/app/deploy_state.json"):
            with open("/app/deploy_state.json") as f:
                import json as _json
                deploy = _json.load(f)
                result["deploy_timestamp"] = deploy.get("timestamp", "unknown")
                result["deploy_commit"] = deploy.get("commit_sha", "unknown")
    except Exception:
        pass

    # Build time from Dockerfile COPY timestamp
    try:
        # Use __file__ of a known source file as proxy
        import os as _os
        mtime = _os.path.getmtime("/app/server.py")
        from datetime import datetime, timezone
        result["build_time"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    except Exception:
        pass

    return result


# ──────────────────────────────────────────────────────────────────────
# ZenArmor query helpers
# ──────────────────────────────────────────────────────────────────────

STATE_FILE = os.path.join(os.environ.get("AGENT_DATA_DIR", "/app/agent_data"), "state.json")

def load_consolidated_state():
    """Load the consolidated state.json, returning empty dict on failure."""
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def load_json_state(filepath):
    """Legacy: Load a JSON state file, returning empty dict on failure."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _get_zenarmor_state():
    """Get ZenArmor classifier state from consolidated state.json."""
    state = load_consolidated_state()
    return state.get("zenarmor_classifier", {})

def _get_ids_state():
    """Get IDS analyzer state from consolidated state.json."""
    state = load_consolidated_state()
    return state.get("ids_analyzer", {})

def query_zenarmor_summary():
    """Return ZenArmor policy summary matching frontend types."""
    state = _get_zenarmor_state()
    if not state:
        return {
            "total_events": 0,
            "policies_count": 0,
            "anomalies_detected": 0,
            "events_24h": 0,
        }
    policies_count = len(state.get("policies", {}))
    total_events = state.get("total_events", 0)
    return {
        "total_events": total_events,
        "policies_count": policies_count,
        "anomalies_detected": 0,  # tracked via DB anomalies table
        "events_24h": total_events,  # fallback: same as total
    }

def query_zenarmor_policies():
    """Return all known ZenArmor policies matching frontend types."""
    state = _get_zenarmor_state()
    if not state:
        return []
    policies = []
    for name, data in state.get("policies", {}).items():
        total_events = data.get("total_events", 0)
        actions = data.get("actions", {})
        action = "block" if actions.get("BLOCK", 0) > actions.get("PASS", 0) else "pass"
        policies.append({
            "id": name[:8],
            "name": name,
            "category": "general",
            "status": "active",
            "action": action,
            "description": "",
            "events": total_events,
        })
    return sorted(policies, key=lambda x: -x["events"])

def query_zenarmor_events(limit=100, offset=0):
    """Return recent ZenArmor events from the database."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT timestamp, src_ip, dst_ip, dst_port, proto, action,
                   rule_name, log_type
            FROM events
            WHERE log_type = 'zenarmor'
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        rows = cur.fetchall()
        close_db(conn)
        return [dict(r) for r in rows]
    except Exception as e:
        close_db(conn)
        return []

def query_zenarmor_anomalies():
    """Return recent ZenArmor anomalies from the database."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT timestamp, attack_type, severity, src_ip, dst_ip,
                   description, detail
            FROM anomalies
            WHERE (detail::text LIKE '%%zenarmor%%' OR description::text LIKE '%%ZenArmor%%' OR description::text LIKE '%%Policy%%')
              AND (detail::text LIKE '%%NEW_POLICY%%' OR detail::text LIKE '%%POLICY_CHANGE%%'
                   OR detail::text LIKE '%%BLOCK_SPIKE%%' OR detail::text LIKE '%%MIXED_POLICY%%'
                   OR description::text LIKE '%%NEW ZenArmor%%' OR description::text LIKE '%%Policy%% changed%%'
                   OR description::text LIKE '%%blocking%%' OR description::text LIKE '%%mixed%%'
                   OR description::text LIKE '%%SYSTEM_BLOCK%%')
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
        close_db(conn)
        return [dict(r) for r in rows]
    except Exception as e:
        close_db(conn)
        return []

# ──────────────────────────────────────────────────────────────────────
# IDS query helpers
# ──────────────────────────────────────────────────────────────────────

def query_ids_summary():
    """Return IDS signature summary — from DB + state file."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events WHERE log_type = 'ids'")
        db_total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM events WHERE log_type = 'ids' AND timestamp > NOW() - INTERVAL '24 hours'")
        db_24h = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT rule_name) FROM events WHERE log_type = 'ids' AND rule_name IS NOT NULL AND rule_name != ''")
        db_signatures = cur.fetchone()[0]
        cur.close()
    except Exception:
        db_total = 0
        db_24h = 0
        db_signatures = 0
    finally:
        if conn:
            close_db(conn)

    state = _get_ids_state()
    sig_count = len(state.get("signatures", {})) if state else 0

    return {
        "total_events": max(db_total, sig_count),
        "signatures": max(db_signatures, sig_count),
        "anomalies_detected": 0,  # tracked via DB anomalies table
        "events_24h": db_24h,
    }

def query_ids_signatures():
    """Return all known IDS signatures — from DB + state file."""
    conn = get_db()
    db_sigs = {}
    try:
        cur = conn.cursor()
        # Group events by rule_name (signature name)
        cur.execute("""
            SELECT rule_name, COUNT(*) as cnt, MAX(timestamp) as last_seen
            FROM events
            WHERE log_type = 'ids' AND rule_name IS NOT NULL AND rule_name != ''
            GROUP BY rule_name
            ORDER BY cnt DESC
        """)
        for row in cur.fetchall():
            db_sigs[row[0]] = {
                "id": row[0][:8],
                "name": row[0],
                "category": "IDS_ALERT",
                "severity": "MEDIUM",
                "triggered_count": row[1],
                "last_triggered": row[2].isoformat() if row[2] else "",
            }
        cur.close()
    except Exception:
        pass
    finally:
        if conn:
            close_db(conn)

    # Merge with state file signatures (state file may have more details)
    state = _get_ids_state()
    if state:
        for name, data in state.get("signatures", {}).items():
            if name in db_sigs:
                # Update with state file details if available
                pri = data.get("priority", 0)
                db_sigs[name]["priority"] = pri
                db_sigs[name]["severity"] = "HIGH" if pri <= 1 else "MEDIUM" if pri <= 3 else "LOW"
            else:
                pri = data.get("priority", 0)
                db_sigs[name] = {
                    "id": name[:8],
                    "name": name,
                    "category": "unknown",
                    "severity": "HIGH" if pri <= 1 else "MEDIUM" if pri <= 3 else "LOW",
                    "triggered_count": data.get("trigger_count", 0),
                    "last_triggered": data.get("last_seen", ""),
                }

    return sorted(db_sigs.values(), key=lambda x: -x["triggered_count"])

def query_ids_events(limit=100, offset=0):
    """Return recent IDS events from the database."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT timestamp, src_ip, dst_ip, dst_port, proto, action,
                   rule_name, log_type
            FROM events
            WHERE log_type = 'ids'
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        rows = cur.fetchall()
        close_db(conn)
        return [dict(r) for r in rows]
    except Exception as e:
        close_db(conn)
        return []

def query_ids_anomalies():
    """Return recent IDS anomalies from the database."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT timestamp, attack_type, severity, src_ip, dst_ip,
                   description, detail
            FROM anomalies
            WHERE (detail::text LIKE '%%ids%%' OR description::text LIKE '%%IDS%%' OR description::text LIKE '%%signature%%')
              AND (detail::text LIKE '%%NEW_SIGNATURE%%' OR detail::text LIKE '%%SIGNATURE_SPIKE%%'
                   OR detail::text LIKE '%%TARGET_CHANGE%%' OR detail::text LIKE '%%CROSS_NETWORK%%'
                   OR detail::text LIKE '%%MULTIPLE_NEW%%'
                   OR description::text LIKE '%%New IDS%%' OR description::text LIKE '%%signature%% spike%%'
                   OR description::text LIKE '%%targets%% distinct%%')
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
        close_db(conn)
        return [dict(r) for r in rows]
    except Exception as e:
        close_db(conn)
        return []


# ──────────────────────────────────────────────────────────────────────
# Nginx query helpers
# ──────────────────────────────────────────────────────────────────────

def query_nginx_summary():
    """Return nginx traffic summary from DB."""
    conn = get_db()
    if not conn:
        return {
            'total_requests': 0, 'by_method': {}, 'by_status': {},
            'status_ok': 0, 'status_client_err': 0, 'status_server_err': 0,
            'unique_ips': 0, 'top_ips': [], 'top_paths': [],
            'not_found_404': 0, 'anomalies_by_type': {},
        }
    try:
        cur = conn.cursor()
        cutoff = datetime.now(timezone.utc).isoformat()
        
        # Total requests
        cur.execute(
            "SELECT COUNT(*) FROM nginx_events WHERE timestamp > %s",
            (cutoff,)
        )
        total_requests = cur.fetchone()[0]
        
        # By method
        cur.execute(
            "SELECT method, COUNT(*) FROM nginx_events WHERE timestamp > %s AND method IS NOT NULL GROUP BY method ORDER BY COUNT(*) DESC",
            (cutoff,)
        )
        by_method = {r[0]: r[1] for r in cur.fetchall()}
        
        # By status code
        cur.execute(
            "SELECT status_code, COUNT(*) FROM nginx_events WHERE timestamp > %s AND status_code IS NOT NULL GROUP BY status_code ORDER BY COUNT(*) DESC",
            (cutoff,)
        )
        by_status = {str(r[0]): r[1] for r in cur.fetchall()}
        
        # Status categories
        cur.execute(
            "SELECT COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END), COUNT(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 END), COUNT(CASE WHEN status_code >= 500 THEN 1 END) FROM nginx_events WHERE timestamp > %s",
            (cutoff,)
        )
        ok, client_err, server_err = cur.fetchone()
        
        # Unique IPs
        cur.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM nginx_events WHERE timestamp > %s AND src_ip IS NOT NULL",
            (cutoff,)
        )
        unique_ips = cur.fetchone()[0]
        
        # Top IPs
        cur.execute(
            "SELECT src_ip, COUNT(*) FROM nginx_events WHERE timestamp > %s AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10",
            (cutoff,)
        )
        top_ips = [{"ip": r[0], "requests": r[1]} for r in cur.fetchall()]
        
        # Top paths
        cur.execute(
            "SELECT path, COUNT(*) FROM nginx_events WHERE timestamp > %s AND path IS NOT NULL GROUP BY path ORDER BY COUNT(*) DESC LIMIT 10",
            (cutoff,)
        )
        top_paths = [{"path": r[0], "requests": r[1]} for r in cur.fetchall()]
        
        # 404s
        cur.execute(
            "SELECT COUNT(*) FROM nginx_events WHERE timestamp > %s AND status_code = 404",
            (cutoff,)
        )
        not_found = cur.fetchone()[0]
        
        # Anomalies by type
        cur.execute(
            "SELECT attack_type, severity, COUNT(*) FROM nginx_anomalies WHERE created_at > %s GROUP BY attack_type, severity ORDER BY COUNT(*) DESC",
            (cutoff,)
        )
        anomalies_by_type = {}
        for at, sev, cnt in cur.fetchall():
            if at not in anomalies_by_type:
                anomalies_by_type[at] = {}
            anomalies_by_type[at][sev] = cnt
        
        return {
            'total_requests': total_requests,
            'by_method': by_method,
            'by_status': by_status,
            'status_ok': ok or 0,
            'status_client_err': client_err or 0,
            'status_server_err': server_err or 0,
            'unique_ips': unique_ips,
            'top_ips': top_ips,
            'top_paths': top_paths,
            'not_found_404': not_found,
            'anomalies_by_type': anomalies_by_type,
        }
    except Exception as e:
        close_db(conn)
        return {'total_requests': 0, 'error': str(e)}
    finally:
        close_db(conn)


def query_nginx_anomalies():
    """Return recent nginx anomalies."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT timestamp, attack_type, severity, src_ip, path, status_code, description, detail
            FROM nginx_anomalies
            ORDER BY created_at DESC LIMIT 100
        """)
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        close_db(conn)
        return []
    finally:
        close_db(conn)


def query_nginx_top_paths():
    """Return top requested paths."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT path, COUNT(*) as cnt, 
                   COUNT(CASE WHEN status_code >= 400 THEN 1 END) as errors
            FROM nginx_events 
            WHERE path IS NOT NULL
            GROUP BY path ORDER BY cnt DESC LIMIT 20
        """)
        return [{"path": r[0], "requests": r[1], "errors": r[2]} for r in cur.fetchall()]
    except Exception as e:
        close_db(conn)
        return []
    finally:
        close_db(conn)


def query_nginx_timeline(hours=24):
    """Return nginx request counts by hour for timeline chart."""
    conn = get_db()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT date_trunc('hour', timestamp)::text as hour, COUNT(*) as count
            FROM nginx_events 
            WHERE timestamp > NOW() - INTERVAL '%s hours'
            GROUP BY hour ORDER BY hour ASC
        """, (hours,))
        return [{"hour": r[0], "requests": r[1]} for r in cur.fetchall()]
    except Exception as e:
        close_db(conn)
        return []
    finally:
        close_db(conn)


# Request Handler
class DashboardHandler(BaseHTTPRequestHandler):
    # Override handle_one_request to track active requests and check drain mode
    def handle_one_request(self):
        """Parse one request, track it, and reject if draining (except /api/drain)."""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            # Check drain mode for API endpoints (but not /api/drain itself)
            path = self.path.split('?')[0] if hasattr(self, 'path') else ''
            if path.startswith('/api/') and path != '/api/drain' and is_draining():
                self._send_json({
                    "error": "service draining",
                    "draining": True,
                    "active_requests": get_active_request_count(),
                    "message": "Server is draining — please retry shortly"
                }, 503)
                return
            _request_enter()
            try:
                mname = 'do_' + self.command
                if not hasattr(self, mname):
                    self.send_error(501, "Unsupported method (%r)" % self.command)
                    return
                method = getattr(self, mname)
                method()
                self.wfile.flush()
            finally:
                _request_exit()
        except TimeoutError as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    def _check_drain(self) -> bool:
        """Return True if request should be rejected due to drain mode."""
        if is_draining():
            self._send_json({
                "error": "service draining",
                "draining": True,
                "active_requests": get_active_request_count(),
                "message": "Server is draining"
            }, 503)
            return True
        return False

    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _serve_html(self):
        # Try new React SPA dist first, then fall back to app.html
        html_path = os.path.join(BASE_DIR, "webui", "dist", "index.html")
        if os.path.exists(html_path):
            with open(html_path, "rb") as f:
                html_bytes = f.read()
            html = html_bytes.decode('utf-8')
            # Add version query to bust browser cache
            html = html.replace('.js">', '.js?v=' + str(int(time.time())) + '">')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        else:
            html_path = os.path.join(BASE_DIR, "app.html")
            if os.path.exists(html_path):
                with open(html_path, "rb") as f:
                    html = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.end_headers()
                self.wfile.write(html)
            else:
                self.send_response(404)
                self.end_headers()

    def _serve_static(self):
        """Serve static files from webui/dist for React SPA."""
        dist_path = os.path.join(BASE_DIR, "webui", "dist")
        if not os.path.exists(dist_path):
            return False
        
        # Parse the path
        path = self.path.split("?")[0]
        
        # Remove leading /assets/ prefix
        clean_path = path
        if clean_path.startswith("/assets/"):
            clean_path = clean_path[8:]  # Strip "/assets/"
        
        # Look in assets subdirectory
        file_path = os.path.join(dist_path, "assets", clean_path)
        
        # Security: prevent path traversal (simple check)
        if '..' in clean_path or clean_path.startswith('/'):
            self.send_response(403)
            self.end_headers()
            return True
        
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # Determine content type
            ext = os.path.splitext(file_path)[1].lower()
            content_types = {
                ".html": "text/html",
                ".js": "application/javascript",
                ".css": "text/css",
                ".json": "application/json",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".svg": "image/svg+xml",
                ".woff": "font/woff",
                ".woff2": "font/woff2",
                ".ttf": "font/ttf",
                ".ico": "image/x-icon",
            }
            content_type = content_types.get(ext, "application/octet-stream")
            
            with open(file_path, "rb") as f:
                data = f.read()
            
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            self.end_headers()
            self.wfile.write(data)
            return True
        
        return False

    # ─── P2-3: Prometheus metrics ──────────────────────────────────────
    def _send_prometheus_metrics(self):
        """Send Prometheus-format metrics."""
        out = []
        try:
            state = load_state()
            agent_counters = state.get("agent_counters", {}) if state else {}
            events_processed = agent_counters.get("event_count", 0)
            anomalies_detected = agent_counters.get("anomaly_count", 0)
            alerts_sent = agent_counters.get("alert_count", 0)
            mutes_count = len(load_mutes())
            baseline_count = 0
            anomaly_by_type = {}
            anomaly_by_severity = {}

            conn = get_db()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT attack_type, COUNT(*) as cnt FROM anomalies GROUP BY attack_type")
                    for row in cur.fetchall():
                        anomaly_by_type[str(row[0]).lower().replace(" ", "_")] = row[1]

                    cur.execute("SELECT severity, COUNT(*) as cnt FROM anomalies GROUP BY severity")
                    for row in cur.fetchall():
                        anomaly_by_severity[row[0]] = row[1]

                    row = cur.fetchone if False else None
                    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE baseline_updated = TRUE")
                    row = cur.fetchone()
                    baseline_count = row[0] if row and row[0] else 0
                    cur.close()
                except Exception as e:
                    logger.warning("Metrics query failed: %s", e)
                finally:
                    close_db(conn)

            out.append("# HELP events_processed_total Total events processed by the agent")
            out.append("# TYPE events_processed_total counter")
            out.append(f"events_processed_total {events_processed}")

            out.append("# HELP anomalies_detected_total Total anomalies detected by type")
            out.append("# TYPE anomalies_detected_total counter")
            out.append(f'anomalies_detected_total{{type="total"}} {anomalies_detected}')
            for atype, cnt in anomaly_by_type.items():
                out.append(f'anomalies_detected_total{{type="{atype}"}} {cnt}')

            out.append("# HELP alert_sent_total Total alerts sent by severity")
            out.append("# TYPE alert_sent_total counter")
            for sev, cnt in anomaly_by_severity.items():
                out.append(f'alert_sent_total{{severity="{sev}"}} {cnt}')
            out.append(f'alert_sent_total{{severity="total"}} {alerts_sent}')

            out.append("# HELP baseline_count Number of baselines currently tracked")
            out.append("# TYPE baseline_count gauge")
            out.append(f"baseline_count {baseline_count}")

            out.append("# HELP mute_count Number of active mutes")
            out.append("# TYPE mute_count gauge")
            out.append(f"mute_count {mutes_count}")

            out.append("# HELP agent_uptime_seconds Agent uptime in seconds")
            out.append("# TYPE agent_uptime_seconds gauge")
            out.append(f"agent_uptime_seconds {_calc_uptime(agent_counters)}")

            # ML model metrics
            try:
                from rule_classifier import RuleClassifier
                ml_info = load_ml_model_info()
                if ml_info:
                    out.append("# HELP ml_model_trained Whether ML model is trained")
                    out.append("# TYPE ml_model_trained gauge")
                    out.append(f"ml_model_trained {1 if ml_info.get('model_trained') else 0}")
                    out.append("# HELP ml_model_accuracy ML model accuracy")
                    out.append("# TYPE ml_model_accuracy gauge")
                    out.append(f"ml_model_accuracy {ml_info.get('metrics', {}).get('cv_accuracy_mean', 0)}")
                    out.append("# HELP ml_model_precision_macro ML model macro precision")
                    out.append("# TYPE ml_model_precision_macro gauge")
                    out.append(f"ml_model_precision_macro {ml_info.get('metrics', {}).get('precision_macro', 0)}")
                    out.append("# HELP ml_model_recall_macro ML model macro recall")
                    out.append("# TYPE ml_model_recall_macro gauge")
                    out.append(f"ml_model_recall_macro {ml_info.get('metrics', {}).get('recall_macro', 0)}")
                    out.append("# HELP ml_model_f1_macro ML model macro F1 score")
                    out.append("# TYPE ml_model_f1_macro gauge")
                    out.append(f"ml_model_f1_macro {ml_info.get('metrics', {}).get('f1_macro', 0)}")
                    out.append("# HELP ml_model_train_samples Number of training samples")
                    out.append("# TYPE ml_model_train_samples gauge")
                    out.append(f"ml_model_train_samples {ml_info.get('metrics', {}).get('train_samples', 0)}")
                    out.append("# HELP ml_model_samples_since_retrain Samples since last retrain")
                    out.append("# TYPE ml_model_samples_since_retrain gauge")
                    out.append(f"ml_model_samples_since_retrain {ml_info.get('samples_since_retrain', 0)}")
            except Exception as ml_err:
                logger.debug("Could not add ML metrics: %s", ml_err)

            # Resource monitoring metrics
            try:
                from health_monitor import get_system_metrics
                res = get_system_metrics(db_size=True, disk=True, redis_memory=True)

                # Memory metrics
                mem = res.get("memory", {})
                if "error" not in mem:
                    out.append("# HELP agent_memory_usage_bytes Agent memory usage in bytes")
                    out.append("# TYPE agent_memory_usage_bytes gauge")
                    out.append(f"agent_memory_usage_bytes {int(mem.get('used_mb', 0) * 1024 * 1024)}")
                    out.append("# HELP agent_memory_total_bytes Agent total memory in bytes")
                    out.append("# TYPE agent_memory_total_bytes gauge")
                    out.append(f"agent_memory_total_bytes {int(mem.get('total_mb', 0) * 1024 * 1024)}")
                    out.append("# HELP agent_memory_usage_pct Agent memory usage percentage")
                    out.append("# TYPE agent_memory_usage_pct gauge")
                    out.append(f"agent_memory_usage_pct {mem.get('pct_used', 0)}")

                # CPU metrics
                cpu = res.get("cpu", {})
                if "error" not in cpu:
                    out.append("# HELP agent_cpu_usage_pct Agent CPU usage percentage")
                    out.append("# TYPE agent_cpu_usage_pct gauge")
                    out.append(f"agent_cpu_usage_pct {cpu.get('usage_pct', 0)}")

                # Load average metrics
                load = res.get("load_avg", {})
                if "error" not in load:
                    out.append("# HELP agent_load_avg_1m Agent 1-minute load average")
                    out.append("# TYPE agent_load_avg_1m gauge")
                    out.append(f"agent_load_avg_1m {load.get('1m', 0)}")
                    out.append("# HELP agent_load_avg_5m Agent 5-minute load average")
                    out.append("# TYPE agent_load_avg_5m gauge")
                    out.append(f"agent_load_avg_5m {load.get('5m', 0)}")
                    out.append("# HELP agent_load_avg_15m Agent 15-minute load average")
                    out.append("# TYPE agent_load_avg_15m gauge")
                    out.append(f"agent_load_avg_15m {load.get('15m', 0)}")

                # DB size metrics
                db = res.get("db_size", {})
                if "error" not in db:
                    out.append("# HELP agent_db_size_bytes Agent database size in bytes")
                    out.append("# TYPE agent_db_size_bytes gauge")
                    out.append(f"agent_db_size_bytes {db.get('bytes', 0)}")

                # Disk metrics
                disk = res.get("disk", {})
                if "error" not in disk:
                    out.append("# HELP agent_disk_usage_pct Agent disk usage percentage")
                    out.append("# TYPE agent_disk_usage_pct gauge")
                    out.append(f"agent_disk_usage_pct {disk.get('pct_used', 0)}")
                    out.append("# HELP agent_disk_free_bytes Agent disk free space in bytes")
                    out.append("# TYPE agent_disk_free_bytes gauge")
                    out.append(f"agent_disk_free_bytes {int(disk.get('free_mb', 0) * 1024 * 1024)}")

                # Redis memory metrics
                rinfo = res.get("redis", {})
                if "error" not in rinfo and rinfo.get("status") != "unavailable":
                    out.append("# HELP agent_redis_memory_used_bytes Redis RSS memory in bytes")
                    out.append("# TYPE agent_redis_memory_used_bytes gauge")
                    out.append(f"agent_redis_memory_used_bytes {int(rinfo.get('used_mb', 0) * 1024 * 1024)}")
                    out.append("# HELP agent_redis_memory_peak_bytes Redis peak RSS memory in bytes")
                    out.append("# TYPE agent_redis_memory_peak_bytes gauge")
                    out.append(f"agent_redis_memory_peak_bytes {int(rinfo.get('peak_mb', 0) * 1024 * 1024)}")
                    out.append("# HELP agent_redis_connected_clients Redis connected clients")
                    out.append("# TYPE agent_redis_connected_clients gauge")
                    out.append(f"agent_redis_connected_clients {rinfo.get('connected_clients', 0)}")
                    if rinfo.get("max_mb", 0) > 0:
                        out.append("# HELP agent_redis_memory_usage_pct Redis memory usage percentage of maxmemory")
                        out.append("# TYPE agent_redis_memory_usage_pct gauge")
                        out.append(f"agent_redis_memory_usage_pct {rinfo.get('pct_of_max', 0)}")
            except Exception as res_err:
                logger.debug("Could not add resource metrics: %s", res_err)

        except Exception as e:
            logger.error("Prometheus metrics generation failed: %s", e)
            out = [f"# ERROR: {e}"]

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.end_headers()
        self.wfile.write(("\n".join(out) + "\n").encode())

    # ─── P2-6: SSE handler ─────────────────────────────────────────────
    def _handle_sse(self):
        """Handle SSE streaming connection."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        client_id = int(time.time() * 1000000)
        client_ref = {"alive": True, "client_id": client_id}
        with _sse_clients_lock:
            _sse_clients.append(client_ref)

        try:
            # Send initial connection event
            self._sse_write(f"event: connected\ndata: {{\"client_id\": {client_id}}}\n\n")

            while client_ref["alive"]:
                try:
                    data = _sse_queue.get(timeout=5)
                    if not client_ref["alive"]:
                        break
                    self._sse_write(f"event: anomaly\ndata: {json.dumps(data, default=str)}\n\n")
                except queue.Empty:
                    # Send heartbeat every 5 seconds
                    self._sse_write(": heartbeat\n\n")
        except (BrokenPipeError, ConnectionResetError, Exception) as e:
            logger.debug("SSE client disconnected: %s", e)
        finally:
            client_ref["alive"] = False
            with _sse_clients_lock:
                if client_ref in _sse_clients:
                    _sse_clients.remove(client_ref)

    def _sse_write(self, text):
        """Write SSE data to the client connection."""
        try:
            self.wfile.write(text.encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            raise

    # ═══════════════════════════════════════════════
    # Phase 5: Threshold Auto-Tuning API handlers
    # ═══════════════════════════════════════════════

    def _handle_thresholds_get(self):
        """GET /api/thresholds — return current threshold values."""
        try:
            from threshold_tuner import ThresholdTuner, DEFAULT_THRESHOLDS
            tuner = ThresholdTuner()
            thresholds = tuner.get_all_thresholds()
            result = {}
            for name, cfg in DEFAULT_THRESHOLDS.items():
                result[name] = {
                    'current_value': thresholds.get(name, cfg['value']),
                    'min': cfg['min'],
                    'max': cfg['max'],
                    'step': cfg['step'],
                    'description': cfg['description'],
                }
            self._send_json({'thresholds': result})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_threshold_metrics_get(self):
        """GET /api/threshold-metrics — return performance metrics."""
        try:
            from threshold_tuner import ThresholdTuner
            tuner = ThresholdTuner()
            metrics = tuner.get_metrics()
            self._send_json({'metrics': metrics})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_threshold_history_get(self):
        """GET /api/threshold-history — return tuning history."""
        try:
            from threshold_tuner import ThresholdTuner
            tuner = ThresholdTuner()
            history = tuner.get_tuning_history(limit=50)
            self._send_json({'history': history})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_threshold_roc_get(self, threshold_type: str):
        """GET /api/threshold-roc?type=volume_zscore — return ROC curve points."""
        try:
            from threshold_tuner import ThresholdTuner
            tuner = ThresholdTuner()
            curve = tuner.get_roc_curve(threshold_type)
            self._send_json({
                'threshold_type': threshold_type,
                'curve': curve,
            })
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def do_GET(self):
        path = self.path.split("?")[0]
        
        # Serve static files (JS, CSS, etc.) from webui/dist — NO AUTH required
        if path.startswith("/assets/"):
            if self._serve_static():
                return
        
        # Serve API endpoints — requires basic auth if configured
        if path.startswith("/api/"):
            if not _require_auth(self):
                return
            # Drain status endpoint (always available, no tracking)
            if path == "/api/drain":
                self._send_json({
                    "draining": is_draining(),
                    "active_requests": get_active_request_count(),
                    "drain_initiated_at": _drain_initiated_at if _drain_mode else None,
                    "seconds_draining": round(time.time() - _drain_initiated_at, 1) if _drain_mode else 0,
                })
                return

            if path == "/api/stats":
                self._send_json(query_stats())
            # ═══════════════════════════════════════════════
            # -style visualizations (read from PostgreSQL)
            # ═══════════════════════════════════════════════
            elif path == "/api/traffic-flow":
                self._send_json(query__traffic_flow())
            elif path == "/api/protocols":
                self._send_json(query__protocol_distribution())
            elif path == "/api/actions":
                self._send_json(query__action_distribution())
            elif path == "/api/timeline":
                query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                period = query.get("period", ["7d"])[0]
                granularity = query.get("granularity", ["hour"])[0]
                start = int(query["start"][0]) if "start" in query else None
                end = int(query["end"][0]) if "end" in query else None
                self._send_json(query__timeline(period=period, granularity=granularity, start=start, end=end))
            elif path == "/api/blocked-ips":
                self._send_json(query__blocked_ips())
            elif path == "/api/top-ports":
                self._send_json(query__top_ports())
            elif path == "/api/rule-heatmap":
                self._send_json(query__rule_heatmap())
            elif path == "/api/directions":
                self._send_json(query__direction_distribution())
            elif path == "/api/rule-actions":
                self._send_json(query__rule_action_breakdown())
            elif path == "/api/heatmap":
                self._send_json(query_heatmap())
            elif path == "/api/ip-flow":
                self._send_json(query_ip_flow())
            elif path == "/api/ip-flow-clusters":
                cluster_query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                expand = cluster_query.get("expand", [None])[0]
                threshold = int(cluster_query.get("threshold", ["0"])[0] or "0")
                self._send_json(query_ip_flow_clusters(expand_cluster=expand, edge_threshold=threshold))
            elif path == "/api/events":
                self._send_json(query_events())
            elif path == "/api/mutes":
                self._send_json(load_mutes())
            elif path == "/api/geo":
                self._send_json(query_geo())
            elif path == "/api/health":
                self._send_json(query_health())
            elif path == "/api/schema-migrations":
                try:
                    self._send_json(query_schema_migrations())
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/resources":
                try:
                    self._send_json(query_resources())
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/version":
                self._send_json(query_version())
            elif path == "/api/alerts":
                self._send_json(query_alerts())
            elif path == "/api/anomalies":
                self._send_json(query_anomalies())
            elif path.startswith("/api/ip-detail/"):
                ip = urllib.parse.unquote(path.split("/api/ip-detail/")[-1])
                if ip:
                    self._send_json(query_ip_detail(ip))
                else:
                    self._send_json({"error": "No IP specified"}, 400)
            elif path == "/api/flows":
                self._send_json(query_flows())
            elif path == "/api/logs":
                self._send_json(query_logs())
            elif path == "/api/system_logs":
                self._send_json(query_system_logs())
            elif path == "/api/opnsense":
                self._send_json(query_opnsense_status())
            elif path == "/api/rules":
                self._send_json(query_opnsense_firewall_rules())
            elif path == "/api/ml-summary":
                try:
                    data = api_ml_summary()
                    self._send_json(data)
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            # P2-3: Prometheus metrics endpoint
            elif path == "/api/metrics":
                try:
                    self._send_prometheus_metrics()
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            # ML model endpoints
            elif path == "/api/ml-model":
                if self.command == "POST":
                    try:
                        data = api_train_ml_model()
                        self._send_json(data)
                    except Exception as e:
                        self._send_json({'error': str(e)}, 500)
                else:
                    try:
                        data = api_ml_model_info()
                        self._send_json(data)
                    except Exception as e:
                        self._send_json({'error': str(e)}, 500)
            elif path == "/api/ml-classifications":
                try:
                    data = api_ml_classifications()
                    self._send_json(data)
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            # P2-6: SSE streaming endpoint
            elif path == "/api/sse":
                self._handle_sse()
            # P2-4: Active learning queue items (DB-backed)
            elif path == "/api/active-learning-queue/items":
                try:
                    data = api_active_learning_queue_items()
                    self._send_json(data)
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/active-learning-queue":
                try:
                    data = api_active_learning_queue_status()
                    self._send_json(data)
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            # P3: Concept drift detection endpoints
            elif path == "/api/drift":
                try:
                    from concept_drift import ConceptDriftDetector
                    detector = ConceptDriftDetector()
                    status = detector.get_status()
                    self._send_json({
                        'status': 'active',
                        'metrics': status.get('metrics', {}),
                        'drift_events': status.get('drift_events', []),
                        'is_drifting': status.get('is_drifting', False),
                        'needs_retraining': detector.needs_retraining()
                    })
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            # P3: Threshold tuning endpoints
            elif path == "/api/threshold":
                try:
                    from threshold_tuner import ThresholdTuner
                    tuner = ThresholdTuner()
                    self._send_json({
                        'thresholds': tuner.get_all_thresholds(),
                        'metrics': tuner.get_metrics(),
                        'roc_curve': tuner.get_roc_curve('default')
                    })
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/active-learning/feedback":
                try:
                    data = api_active_learning_feedback()
                    self._send_json(data)
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/sse-stats":
                self._send_json(query_stats())
            elif path == "/api/rules-classified":
                query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                force_refresh = query.get("refresh", [False])[0] == "true"
                cache_key = "rules-classified"
                redis_client = get_redis()
                if redis_client and not force_refresh:
                    cached = redis_client.get(cache_key)
                    if cached:
                        self._send_json(json.loads(cached))
                        return
                result = query_rules_classified()
                if redis_client:
                    try:
                        redis_client.setex(cache_key, _CACHE_TTL, json.dumps(result))
                    except Exception:
                        pass
                self._send_json(result)
            elif path == "/api/zenarmor":
                self._send_json(query_zenarmor_summary())
            elif path == "/api/zenarmor-policies":
                self._send_json(query_zenarmor_policies())
            elif path == "/api/zenarmor-events":
                query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                limit = int(query.get("limit", [100])[0])
                offset = int(query.get("offset", [0])[0])
                self._send_json(query_zenarmor_events(limit=limit, offset=offset))
            elif path == "/api/zenarmor-anomalies":
                self._send_json(query_zenarmor_anomalies())
            elif path == "/api/zenarmor-summary":
                self._send_json(query_zenarmor_summary())
            elif path == "/api/ids-summary":
                self._send_json(query_ids_summary())
            elif path == "/api/ids-signatures":
                self._send_json(query_ids_signatures())
            elif path == "/api/ids-events":
                query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                limit = int(query.get("limit", [100])[0])
                offset = int(query.get("offset", [0])[0])
                self._send_json(query_ids_events(limit=limit, offset=offset))
            elif path == "/api/ids-anomalies":
                self._send_json(query_ids_anomalies())
            # ═══════════════════════════════════════════════
            # Nginx web server monitoring
            # ═══════════════════════════════════════════════
            elif path == "/api/nginx-summary":
                self._send_json(query_nginx_summary())
            elif path == "/api/nginx-anomalies":
                self._send_json(query_nginx_anomalies())
            elif path == "/api/nginx-top-paths":
                self._send_json(query_nginx_top_paths())
            elif path == "/api/nginx-timeline":
                self._send_json(query_nginx_timeline())
            elif path == "/api/wan-flap":
                self._send_json(query_wan_flaps())
            elif path == "/api/wan-flap-status":
                try:
                    import importlib
                    wan_detector = importlib.import_module("wan_flap_detector")
                    detector = wan_detector.WANFlapDetector()
                    status = detector.get_flap_status()
                    self._send_json({"flap_status": status})
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/wan-flap-history":
                try:
                    import importlib
                    wan_detector = importlib.import_module("wan_flap_detector")
                    detector = wan_detector.WANFlapDetector()
                    flaps = detector.get_recent_flaps(hours=24)
                    self._send_json({"recent_flaps": flaps})
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
            elif path == "/api/service-status":
                self._send_json(query_service_status())
            elif path == "/api//events":
                self.__query_events()
            elif path == "/api/settings":
                self._handle_settings_get()
            elif path == "/api/heartbeat":
                state = load_state()
                counters = state.get("agent_counters", {}) if state else {}
                self._send_json({
                    "ok": True,
                    "timestamp": time.time(),
                    "events_processed": counters.get("event_count", 0),
                    "anomalies_detected": counters.get("anomaly_count", 0),
                })
            elif path == "/api/new-since":
                query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                since_ts = query.get("timestamp", [None])[0]
                if since_ts:
                    self._send_json(query_new_since(since_ts))
                else:
                    self._send_json({"error": "Missing timestamp parameter"}, 400)
            elif path.startswith("/api/rule-detail/"):
                rule_name = urllib.parse.unquote(path.split("/api/rule-detail/")[-1])
                if rule_name:
                    self._send_json(query_rule_detail(rule_name))
                else:
                    self._send_json({"error": "No rule name specified"}, 400)
            # ═══════════════════════════════════════════════
            # Phase 5: Threshold Auto-Tuning API
            # ═══════════════════════════════════════════════
            elif path == "/api/thresholds":
                self._send_json(api_thresholds())
            elif path == "/api/threshold-metrics":
                self._send_json(api_threshold_metrics())
            elif path == "/api/threshold-history":
                self._send_json(api_threshold_history())
            elif path == "/api/threshold-roc":
                query = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
                threshold_type = query.get("type", ["volume_zscore"])[0]
                self._send_json(api_threshold_roc(threshold_type))
            # ═══════════════════════════════════════════════
            # Backup/Restore API endpoints
            # ═══════════════════════════════════════════════
            elif path == "/api/backups":
                try:
                    from backup_restore import list_backups, get_status
                    result = list_backups()
                    result["status"] = get_status()
                    self._send_json(result)
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            elif path == "/api/backup/status":
                try:
                    from backup_restore import get_status
                    self._send_json(get_status())
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            elif path == "/api/backup/cleanup":
                try:
                    from backup_restore import cleanup_old_backups
                    result = cleanup_old_backups()
                    self._send_json(result)
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self.send_response(404)
                self.end_headers()
            return
        
        # Catch-all for SPA: serve index.html for client-side routing
        self._serve_html()

    def do_POST(self):
        path = self.path.split("?")[0]
        # Auth check for API endpoints
        if path.startswith("/api/"):
            if not _require_auth(self):
                return
        # Drain trigger endpoint
        if path == "/api/drain":
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl) if cl else b"{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            timeout = data.get("timeout", _MAX_DRAIN_WAIT)
            enter_drain_mode()
            drained = wait_for_drain(timeout=float(timeout))
            self._send_json({
                "draining": True,
                "drained": drained,
                "active_requests": get_active_request_count(),
                "message": "Drain triggered" if drained else "Drain timed out"
            })
            return
        if path == "/api/mutes":
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            mute = add_mute(ip=data.get("ip", ""), attack_type=data.get("attack_type", "ALL"), port=data.get("port"), duration=data.get("duration_seconds", 3600))
            self._send_json(mute, 201)
        elif path == "/api/ip-actions":
            # Unified IP actions: mute, unmute, watch, unwatch, block
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            action = data.get("action", "")
            ip = data.get("ip", "")
            if action == "mute":
                duration = int(data.get("duration_seconds", 3600))
                mute = add_mute(ip=ip, attack_type="ALL", duration=duration, source="dashboard")
                self._send_json({"success": True, "message": f"Muted {ip} for {duration}s", "ip": ip}, 201)
            elif action == "unmute":
                mutes = load_mutes()
                mutes = [m for m in mutes if m.get("ip") != ip]
                save_mutes(mutes)
                self._send_json({"success": True, "message": f"Unmuted {ip}", "ip": ip})
            elif action == "watch":
                result = add_to_watchlist(ip, data.get("reason", "Added from dashboard"))
                status_code = 201 if result.get("success") else 409
                self._send_json(result, status_code)
            elif action == "unwatch":
                remove_from_watchlist(ip)
                self._send_json({"success": True, "message": f"Removed {ip} from watchlist", "ip": ip})
            elif action == "block":
                result = block_ip_in_firewall(ip, data.get("reason", "Blocked from dashboard"))
                status_code = 201 if result.get("success") else 422
                self._send_json(result, status_code)
            else:
                self._send_json({"error": f"Unknown action: {action}"}, 400)
        elif path == "/api/rule-feedback":
            # Submit feedback for a rule classification (P2-2 feedback loop)
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            try:
                db = EventDatabase()
                db.save_feedback(
                    rule_name=data.get("rule_name", ""),
                    label=data.get("label", "incorrect"),
                    reason=data.get("reason", ""),
                    user_id=data.get("user_id", "dashboard")
                )
                self._send_json({"success": True, "message": "Feedback saved"}, 201)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/active-learning/resolved":
            # Mark an active learning queue item as resolved (P2-4)
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            try:
                db = EventDatabase()
                item_id = data.get("item_id")
                if item_id:
                    db.resolve_active_learning_item(item_id, data.get("classification", ""), data.get("notes", ""))
                self._send_json({"success": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        # ═══════════════════════════════════════════════
        # Phase 5: Threshold Auto-Tuning POST endpoints
        # ═══════════════════════════════════════════════
        elif path == "/api/threshold-feedback":
            # Submit feedback on a detected anomaly
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            try:
                from threshold_tuner import ThresholdTuner
                db = EventDatabase()
                tuner = ThresholdTuner(db)
                tuner.record_feedback(
                    anomaly_id=data.get("anomaly_id"),
                    label=data.get("label", "dismissed"),
                    reason=data.get("reason", ""),
                    user_id=data.get("user_id", "dashboard"),
                )
                self._send_json({"success": True, "message": "Feedback recorded"}, 201)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/threshold-tune":
            # Trigger manual threshold tuning
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl) if cl else b"{}"
            data = json.loads(body)
            try:
                from threshold_tuner import ThresholdTuner
                db = EventDatabase()
                tuner = ThresholdTuner(db)
                threshold_type = data.get("threshold_type")
                adjustments = tuner.tune(threshold_type)
                self._send_json({"success": True, "adjustments": adjustments})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/threshold-set":
            # Manually set a threshold value
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            try:
                from threshold_tuner import ThresholdTuner
                db = EventDatabase()
                tuner = ThresholdTuner(db)
                tuner.set_threshold(
                    threshold_type=data.get("threshold_type"),
                    value=float(data.get("value")),
                )
                self._send_json({
                    "success": True,
                    "threshold_type": data.get("threshold_type"),
                    "value": data.get("value"),
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        # ═══════════════════════════════════════════════
        # Backup/Restore POST endpoints
        # ═══════════════════════════════════════════════
        elif path == "/api/backup/trigger":
            # Trigger a manual backup (writes marker file for host cron)
            try:
                from backup_restore import trigger_backup
                result = trigger_backup()
                code = 202 if result.get("success") else 500
                self._send_json(result, code)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/backup/restore":
            # Restore from a specific backup file
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl) if cl else b"{}"
            data = json.loads(body)
            try:
                from backup_restore import restore_from_backup
                backup_file = data.get("backup_file", "")
                if not backup_file:
                    from backup_restore import list_backups
                    backups = list_backups()
                    self._send_json({
                        "success": False,
                        "error": "No backup_file specified",
                        "available_backups": [b["filename"] for b in backups.get("backups", [])],
                    }, 400)
                else:
                    result = restore_from_backup(backup_file)
                    code = 202 if result.get("success") else 500
                    self._send_json(result, code)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/backup/delete":
            # Delete a specific backup file
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl) if cl else b"{}"
            data = json.loads(body)
            try:
                from backup_restore import delete_backup
                backup_file = data.get("backup_file", "")
                if not backup_file:
                    self._send_json({"success": False, "error": "No backup_file specified"}, 400)
                else:
                    result = delete_backup(backup_file)
                    code = 200 if result.get("success") else 400
                    self._send_json(result, code)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self.send_response(405)
            self.end_headers()

    def do_DELETE(self):
        path = self.path.split("?")[0]
        # Auth check for API endpoints
        if path.startswith("/api/"):
            if not _require_auth(self):
                return
        if path.startswith("/api/mutes/"):
            mute_id = path.split("/api/mutes/")[-1]
            remove_mute(mute_id)
            self._send_json({"ok": True})
        else:
            self.send_response(405)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP request logging to reduce log noise


# ═══════════════════════════════════════════
# Module-level cache for OPNsense firewall rules
# Refreshes every 5 minutes to keep names up to date
# ═══════════════════════════════════════════
import threading
import time

_opnsense_cache = {
    "data": {},
    "last_refresh": 0,
    "lock": threading.Lock(),
    "_refresh_interval": 300,  # 5 minutes
}


def _cache_opnsense_rules():
    """Background cache refresh for OPNsense rules."""
    try:
        data = query_opnsense_firewall_rules()
        with _opnsense_cache["lock"]:
            _opnsense_cache["data"] = data
            _opnsense_cache["last_refresh"] = time.time()
    except Exception as e:
        print(f"[Cache] Failed to refresh OPNsense rules: {e}")


# Start cache refresh thread
def _start_cache_thread():
    """Start background cache refresh thread."""
    def refresh_loop():
        while True:
            _cache_opnsense_rules()
            time.sleep(_opnsense_cache["_refresh_interval"])

    t = threading.Thread(target=refresh_loop, daemon=True)
    t.start()
    # Do initial fetch immediately
    _cache_opnsense_rules()
    print("[Cache] OPNsense rules cache thread started")


def get_cached_opnsense_rules():
    """Get OPNsense rules from cache, refreshing if stale."""
    with _opnsense_cache["lock"]:
        if _opnsense_cache["last_refresh"] == 0 or (time.time() - _opnsense_cache["last_refresh"]) > _opnsense_cache["_refresh_interval"]:
            # Need to refresh
            pass  # Will be refreshed in next iteration
        return _opnsense_cache["data"]


def generate_rule_name(rule_data):
    """Generate a human-readable rule name from OPNsense rule attributes when description is empty."""
    if not rule_data:
        return None
    
    # Try to generate a meaningful name from available attributes
    # If no attributes, return None to trigger fallback logic
    
    protocol = rule_data.get("protocol", "").upper()
    src_port = rule_data.get("source_port", "")
    dst_port = rule_data.get("destination_port", "")
    src_net = rule_data.get("source_net", "")
    dst_net = rule_data.get("destination_net", "")
    action = rule_data.get("action", "").upper()
    interface = rule_data.get("interface", "")
    categories = rule_data.get("categories", "")
    
    # Only generate name if we have at least some meaningful data
    has_protocol = bool(protocol)
    has_ports = bool(dst_port or src_port)
    has_networks = bool(dst_net or src_net)
    
    if not (has_protocol or has_ports or has_networks):
        return None  # Not enough data to generate a name
    
    parts = []
    
    # Protocol + ports
    if protocol:
        if dst_port:
            parts.append(f"{protocol}:{dst_port}")
        else:
            parts.append(protocol)
    else:
        if dst_port:
            parts.append(f"port:{dst_port}")
        elif src_port:
            parts.append(f"port:{src_port}")
    
    # Network info
    if dst_net and dst_net != "any":
        parts.append(f"to:{dst_net}")
    elif src_net and src_net != "any":
        parts.append(f"from:{src_net}")
    
    # Interface
    if interface:
        parts.append(f"[{interface}]")
    
    # Action indicator
    if action:
        parts.append(f"({action})")
    
    if parts:
        return " ".join(parts)
    return None


def save_active_learning_feedback(rule_name, feedback_type):
    """Save user feedback for active learning."""
    # Load current feedback
    feedback_path = os.path.join(DATA_DIR, "active_learning_feedback.json")
    feedback = []
    if os.path.exists(feedback_path):
        with open(feedback_path) as f:
            feedback = json.load(f)
    
    # Append new feedback
    feedback.append({
        "rule_name": rule_name,
        "feedback_type": feedback_type,
        "timestamp": datetime.now().isoformat()
    })
    
    # Save back
    with open(feedback_path, 'w') as f:
        json.dump(feedback, f, indent=2)
    
    return {"status": "saved", "rule_name": rule_name}


# ═══════════════════════════════════════════════
# Phase 5: Threshold Auto-Tuning API
# ═══════════════════════════════════════════════

# Singleton tuner instance (avoids connection pool exhaustion)
_threshold_tuner_instance = None

def _get_threshold_tuner():
    """Get a ThresholdTuner instance (cached singleton)."""
    global _threshold_tuner_instance
    if _threshold_tuner_instance is None:
        from threshold_tuner import ThresholdTuner
        try:
            # Try EventDatabase first (uses connection pool)
            db = EventDatabase()
        except Exception:
            db = None
        _threshold_tuner_instance = ThresholdTuner(db)
    return _threshold_tuner_instance


def api_thresholds():
    """GET /api/thresholds — current threshold values."""
    tuner = _get_threshold_tuner()
    thresholds = tuner.get_all_thresholds()
    # Add metadata for each threshold
    from threshold_tuner import DEFAULT_THRESHOLDS
    result = {}
    for name, value in thresholds.items():
        cfg = DEFAULT_THRESHOLDS.get(name, {})
        result[name] = {
            'value': value,
            'min': cfg.get('min', 0),
            'max': cfg.get('max', 10),
            'default': cfg.get('value', value),
            'description': cfg.get('description', ''),
        }
    return {'thresholds': result}


def api_threshold_metrics():
    """GET /api/threshold-metrics — performance metrics per threshold type."""
    tuner = _get_threshold_tuner()
    metrics = tuner.get_metrics()
    return {'metrics': metrics}


def api_threshold_history(limit=50):
    """GET /api/threshold-history — tuning history."""
    tuner = _get_threshold_tuner()
    history = tuner.get_tuning_history(limit=limit)
    return {'history': history}


def api_threshold_roc(threshold_type='volume_zscore'):
    """GET /api/threshold-roc?type=volume_zscore — ROC curve data."""
    tuner = _get_threshold_tuner()
    curve = tuner.get_roc_curve(threshold_type)
    metrics = tuner.get_metrics(threshold_type)
    return {
        'threshold_type': threshold_type,
        'roc_curve': curve,
        'metrics': metrics.get(threshold_type, {}),
    }


def query_wan_flaps():
    """Query WAN flap data from anomaly detector history."""
    wan_flap_path = os.path.join(DATA_DIR, "wan_flap_history.json")
    flaps = []
    if os.path.exists(wan_flap_path):
        try:
            with open(wan_flap_path) as f:
                flaps = json.load(f)
        except Exception:
            pass
    
    total_flaps = len(flaps)
    last_flap = flaps[0].get("time", "N/A") if flaps else "N/A"
    avg_duration = sum(f.get("duration", 0) for f in flaps) / total_flaps if total_flaps > 0 else 0
    
    return {
        "flaps": flaps,
        "stats": {
            "total_flaps": total_flaps,
            "last_flap": last_flap,
            "avg_duration": round(avg_duration, 1),
        }
    }


def query_opnsense_firewall_rules():
    """Fetch actual firewall rules from OPNsense with descriptions."""
    opn_url, opn_key, opn_secret, verify_ssl = _read_opn_config()
    print(f"[OPNsense] Config: url={bool(opn_url)}, key={bool(opn_key)}")
    if not opn_url:
        print("[OPNsense] No URL configured, returning empty")
        return {}
    try:
        import urllib.request
        import ssl
        import base64

        ssl_context = ssl.create_default_context()
        if not verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        auth_string = f"{opn_key}:{opn_secret}"
        auth_b64 = base64.b64encode(auth_string.encode()).decode()
        auth_header = f"Basic {auth_b64}"

        # Use the correct OPNsense API endpoint for firewall rules
        req = urllib.request.Request(
            f"{opn_url}/api/firewall/filter/search_rule",
            headers={"Authorization": auth_header},
        )
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            rules_data = json.loads(resp.read().decode())

        rules_list = rules_data.get("rows", [])
        if not rules_list and isinstance(rules_data, dict):
            rules_list = rules_data.get("rules", {}).get("row", [])
            if not rules_list:
                rules_list = rules_data.get("row", [])

        # Index by source_net for easy lookup (human-readable rule names)
        # Also index by UUID for compatibility with existing RUID-based events
        rules_by_name: Dict[str, Dict[str, Any]] = {}
        rules_by_uuid: Dict[str, Dict[str, Any]] = {}
        
        for rule in rules_list:
            rule_uuid = rule.get("uuid", "")
            source_net = rule.get("source_net", "")
            rule_short_id = rule_uuid.split("-")[0] if rule_uuid else ""
            
            rule_meta = {
                "uuid": rule_uuid,
                "description": rule.get("description", ""),
                "action": rule.get("action", rule.get("%action", "")),
                "interface": rule.get("interface", ""),
                "source_net": source_net,
                "destination_net": rule.get("destination_net", ""),
                "enabled": rule.get("enabled", "1"),
                "log": rule.get("log", "0") == "1",
                "categories": rule.get("categories", ""),
                "source_port": rule.get("source_port", ""),
                "destination_port": rule.get("destination_port", ""),
                "protocol": rule.get("protocol", ""),
            }
            
            # Index by full UUID
            if rule_uuid:
                rules_by_uuid[rule_uuid] = rule_meta
            
            # Index by short UUID (first part before hyphen)
            if rule_short_id:
                rules_by_uuid[rule_short_id] = rule_meta
            
            # Index by source_net (human-readable rule name)
            if source_net:
                # source_net can be comma-separated (e.g., "ban_hammer" or "crowdsec_blacklists,crowdsec6_blacklists")
                for sn in source_net.split(","):
                    sn = sn.strip()
                    if sn:
                        rules_by_name[sn] = rule_meta
        
        # Merge both indexes: UUID index first, then source_net (which takes precedence)
        all_rules: Dict[str, Dict[str, Any]] = {}
        all_rules.update(rules_by_uuid)
        all_rules.update(rules_by_name)
        
        print(f"[OPNsense] Fetched {len(rules_list)} firewall rules, indexed {len(all_rules)} by name/UUID")
        if all_rules:
            sample_keys = list(all_rules.keys())[:3]
            print(f"[OPNsense] Sample keys: {sample_keys}")
            print(f"[OPNsense] Sample source_net: {all_rules.get(sample_keys[0], {}).get('source_net', 'N/A')}")
        return all_rules
    except Exception as e:
        print(f"OPNsense firewall rules fetch failed: {e}")
        import traceback
        traceback.print_exc()
        return {}


# Start background cache refresh thread (after query_opnsense_firewall_rules is defined)
_start_cache_thread()


def query_rule_detail(rule_name):
    """Drill-down detail for a specific firewall rule."""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Basic rule stats
        cur.execute("""
            SELECT action, COUNT(*)
            FROM events
            WHERE rule_name = %s
            GROUP BY action
        """, (rule_name,))
        actions = dict(cur.fetchall())
        
        # Top source IPs
        cur.execute("""
            SELECT src_ip, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 20
        """, (rule_name,))
        top_src_ips = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Top destination IPs
        cur.execute("""
            SELECT dst_ip, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND dst_ip IS NOT NULL AND dst_ip != ''
            GROUP BY dst_ip ORDER BY cnt DESC LIMIT 20
        """, (rule_name,))
        top_dst_ips = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Top destination ports
        cur.execute("""
            SELECT dst_port, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND dst_port IS NOT NULL
            GROUP BY dst_port ORDER BY cnt DESC LIMIT 20
        """, (rule_name,))
        top_ports = [{"port": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Top source ports
        cur.execute("""
            SELECT src_port, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND src_port IS NOT NULL
            GROUP BY src_port ORDER BY cnt DESC LIMIT 20
        """, (rule_name,))
        top_src_ports = [{"port": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Protocol distribution
        cur.execute("""
            SELECT proto, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND proto IS NOT NULL AND proto != ''
            GROUP BY proto ORDER BY cnt DESC
        """, (rule_name,))
        protocols = [{"proto": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Interface distribution
        cur.execute("""
            SELECT interface, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND interface IS NOT NULL AND interface != ''
            GROUP BY interface ORDER BY cnt DESC
        """, (rule_name,))
        interfaces = [{"interface": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Direction distribution
        cur.execute("""
            SELECT direction, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s AND direction IS NOT NULL AND direction != ''
            GROUP BY direction ORDER BY cnt DESC
        """, (rule_name,))
        directions = [{"direction": r[0], "count": r[1]} for r in cur.fetchall()]
        
        # Time distribution (by hour of day)
        cur.execute("""
            SELECT EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s
            GROUP BY hour ORDER BY hour
        """, (rule_name,))
        time_dist = {str(int(r[0])): r[1] for r in cur.fetchall()}
        
        # Daily count (last 7 days)
        cur.execute("""
            SELECT DATE(timestamp) as day, COUNT(*) as cnt
            FROM events
            WHERE rule_name = %s
            GROUP BY day ORDER BY day DESC LIMIT 7
        """, (rule_name,))
        daily = [{"day": str(r[0]), "count": r[1]} for r in cur.fetchall()]
        
        # Top 10 recent events
        cur.execute("""
            SELECT timestamp, src_ip, dst_ip, dst_port, src_port, action
            FROM events
            WHERE rule_name = %s
            ORDER BY timestamp DESC LIMIT 10
        """, (rule_name,))
        recent_events = []
        for r in cur.fetchall():
            recent_events.append({
                "timestamp": r[0].isoformat() if r[0] else None,
                "src_ip": r[1],
                "dst_ip": r[2],
                "dst_port": r[3],
                "src_port": r[4],
                "action": r[5],
            })
        
        # Unique IPs count
        cur.execute("""
            SELECT COUNT(DISTINCT src_ip) FROM events
            WHERE rule_name = %s AND src_ip IS NOT NULL AND src_ip != ''
        """, (rule_name,))
        unique_src = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(DISTINCT dst_ip) FROM events
            WHERE rule_name = %s AND dst_ip IS NOT NULL AND dst_ip != ''
        """, (rule_name,))
        unique_dst = cur.fetchone()[0]
        
        cur.close()
        
        total_events = sum(actions.values())
        
        # Enrich with OPNsense metadata
        opnsense_rules = query_opnsense_firewall_rules()
        meta = opnsense_rules.get(rule_name, {})
        if not meta:
            short_id = rule_name[:8] if rule_name else ''
            meta = opnsense_rules.get(short_id, {})
        
        display_name = meta.get('description', rule_name) if meta else rule_name
        
        response = {
            "rule_name": rule_name,
            "rule_hash": rule_name,
            "display_name": display_name,
            "total_events": total_events,
            "actions": actions,
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "top_ports": top_ports,
            "top_src_ports": top_src_ports,
            "protocols": protocols,
            "interfaces": interfaces,
            "directions": directions,
            "time_distribution": time_dist,
            "daily": daily,
            "recent_events": recent_events,
            "unique_src_ips": unique_src,
            "unique_dst_ips": unique_dst,
            "human_readable_name": meta.get("description", ""),
            "rule_description": meta.get("description", ""),
            "rule_action": meta.get("action", ""),
            "rule_protocol": meta.get("protocol", ""),
            "rule_interface": meta.get("interface", ""),
            "source_address": meta.get("source_net", ""),
            "destination_address": meta.get("destination_net", ""),
        }
        return response
    except Exception as e:
        logger.error("query_rule_detail %s failed: %s", rule_name, e)
        return {"error": str(e), "rule_name": rule_name}


def query_rules_classified():
    """Query and classify firewall rules using ML engine."""
    try:
        from rule_classify import RuleClassifierML

        # Fetch OPNsense rule metadata for human-readable names
        opnsense_rules = query_opnsense_firewall_rules()

        conn = get_db()
        cur = conn.cursor()
        
        # Fetch all firewall events (recent window for performance)
        cur.execute("""
            SELECT timestamp, src_ip, dst_ip, dst_port, src_port,
                   action, rule_name, proto,
                   interface, direction
            FROM events
            WHERE action IN ('PASS', 'BLOCK')
              AND rule_name IS NOT NULL
              AND rule_name != ''
              AND rule_name != 'N/A'
            ORDER BY timestamp DESC
            LIMIT 50000
        """)
        rows = cur.fetchall()
        cur.close()
        
        # Build events list
        events = []
        for row in rows:
            events.append({
                'timestamp': row[0].isoformat() if row[0] else None,
                'src_ip': row[1],
                'dst_ip': row[2],
                'dport': row[3],
                'sport': row[4],
                'action': row[5],
                'rule_name': row[6],
                'proto': row[7],
                'interface': row[8],
                'direction': row[9],
            })
        
        # Run ML classification
        classifier = RuleClassifierML()
        classifier.ingest_events(events)
        summary = classifier.get_summary()
        classified_rules = classifier.get_classified_rules()
        
        # Enrich each classified rule with OPNsense metadata for human readability
        for rule in classified_rules:
            rname = rule.get('rule_name', '')
            # Try to match by UUID (first 8 chars of rule_name match first part of UUID)
            short_id = rname[:8] if rname else ''
            meta = opnsense_rules.get(rname, {})
            if not meta and short_id:
                meta = opnsense_rules.get(short_id, {})
            if meta:
                desc = meta.get('description', '') or meta.get('description', '') or rname[:12]
                rule['human_readable_name'] = desc
                rule['rule_description'] = meta.get('description', '')
                rule['rule_action'] = meta.get('action', '')
                rule['rule_protocol'] = meta.get('protocol', '')
                rule['rule_interface'] = meta.get('interface', '')
                rule['source_address'] = meta.get('source_net', '')
                rule['source_port'] = meta.get('source_port', '')
                rule['destination_address'] = meta.get('destination_net', '')
                rule['destination_port'] = meta.get('destination_port', '')
                rule['rule_disabled'] = meta.get('enabled', '1') != '1'
                rule['rule_log'] = meta.get('log', False)
                rule['rule_uuid'] = meta.get('uuid', '')
            else:
                rule['human_readable_name'] = rname[:12]
                rule['rule_description'] = ''
                rule['rule_action'] = rule.get('action', '')
                rule['rule_protocol'] = ''
                rule['rule_interface'] = ''
                rule['source_address'] = ''
                rule['source_port'] = ''
                rule['destination_address'] = ''
                rule['destination_port'] = ''
                rule['rule_disabled'] = False
                rule['rule_log'] = False
                rule['rule_uuid'] = ''
        
        # Save state
        classifier.save_state()
        
        return {
            'summary': summary,
            'classified_rules': classified_rules,
            'events_fetched': len(events),
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error("query_rules_classified failed: %s", e)
        return {
            'error': str(e),
            'summary': {'total_rules': 0},
            'classified_rules': [],
        }


# ── Self-Learning API Endpoints ──────────────────────────────────────────

def api_save_feedback(rule_name, label, reason=None, user_id=None):
    """Save user feedback for a rule classification (Week 1)."""
    try:
        db = EventDatabase()
        db.connect()
        db.save_feedback(rule_name, label, reason or "", user_id or "")
        if db._connection:
            db._connection.close()
        return {'success': True}
    except Exception as e:
        logger.error("save_feedback failed: %s", e)
        return {'error': str(e)}


def api_ml_summary():
    """Get ML summary statistics (Weeks 1-5)."""
    try:
        db = EventDatabase()
        db.connect()
        ml_stats = db.get_ml_summary_stats()
        if db._connection:
            db._connection.close()
        
        # Get rules classification summary
        summary = query_rules_classified()
        
        return {
            'ml_stats': ml_stats,
            'classification_summary': summary.get('summary', {}),
        }
    except Exception as e:
        logger.error("ml_summary failed: %s", e)
        return {'error': str(e)}


def api_ml_model_info():
    """GET /api/ml-model - Return ML model info and metrics."""
    try:
        # Load current rule classifier state to get model info
        from rule_classifier import RuleClassifier

        # Load persisted state
        classifier = RuleClassifier()
        classifier.load_state()

        info = classifier.get_model_info()

        # Add Prometheus-style metrics
        info["metrics"] = classifier.get_model_metrics()

        return info
    except Exception as e:
        logger.error("ml_model_info failed: %s", e)
        return {"error": str(e)}


def api_train_ml_model():
    """POST /api/ml-model - Trigger ML model training."""
    try:
        from rule_classifier import RuleClassifier

        # Load current state
        classifier = RuleClassifier()
        classifier.load_state()

        if len(classifier.rule_profiles) < 10:
            return {
                "success": False,
                "error": f"Insufficient data: {len(classifier.rule_profiles)} rules (need >= 10)",
            }

        metrics = classifier.train_ml_model()

        return {
            "success": "error" not in metrics,
            "metrics": metrics,
            "model_trained": "error" not in metrics,
        }
    except Exception as e:
        logger.error("train_ml_model failed: %s", e)
        return {"success": False, "error": str(e)}


def api_ml_classifications():
    """GET /api/ml-classifications - Return all rule classifications."""
    try:
        from rule_classifier import RuleClassifier

        classifier = RuleClassifier()
        classifier.load_state()

        classifications = classifier.get_all_classifications()

        return {
            "classifications": classifications,
            "total_rules": len(classifications),
            "model_trained": classifier.ml_classifier.model is not None,
            "model_metrics": classifier.get_model_metrics(),
        }
    except Exception as e:
        logger.error("ml_classifications failed: %s", e)
        return {"error": str(e)}


def api_active_learning_queue():
    """Get active learning queue (Week 4)."""
    try:
        from ml_learning import SelfLearningClassifier
        
        db = EventDatabase()
        db.connect()
        
        # Load classifier state
        classifier = SelfLearningClassifier(db)
        if not classifier.load_state():
            if db._connection:
                db._connection.close()
            return {'queue': [], 'message': 'No classification state available'}
        
        # Get active learning queue
        queue = classifier.get_active_learning_queue()
        
        result = {
            'queue': [
                {
                    'rule_name': item.rule_name,
                    'classification': item.classification,
                    'confidence': item.confidence,
                    'reasons': item.reasons,
                }
                for item in queue
            ],
            'count': len(queue),
        }
        
        if db._connection:
            db._connection.close()
        return result
    except Exception as e:
        logger.error("active_learning_queue failed: %s", e)
        return {'error': str(e), 'queue': []}


def api_active_learning_queue_items():
    """Get DB-backed active learning queue items (P2-4).
    
    Reads from the active_learning_queue table in the database.
    Returns items that are pending review.
    """
    try:
        db = EventDatabase()
        items = db.get_active_learning_queue()
        return {
            'items': items,
            'count': len(items),
            'pending': len([i for i in items if i.get('status') == 'pending']),
            'resolved': len([i for i in items if i.get('status') == 'resolved']),
        }
    except Exception as e:
        logger.error("active_learning_queue_items failed: %s", e)
        return {'error': str(e), 'items': [], 'count': 0}


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

# ═══════════════════════════════════════════════
# ═══════════════════════════════════════════════
# -style visualization queries
# Read from PostgreSQL and return data formatted
# for the React dashboard visualizations
# ═══════════════════════════════════════════════
def query__traffic_flow(hours=24, limit=50):
    """Top src→dst pairs for Sankey diagram."""
    conn = get_db()
    if not conn:
        return {"flow": []}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, dst_ip, COUNT(*) as event_count
            FROM events
            WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
              AND src_ip != '' AND dst_ip != ''
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, dst_ip
            ORDER BY event_count DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        cur.close()
        flow = [{
            "source": r["src_ip"],
            "target": r["dst_ip"],
            "value": r["event_count"]
        } for r in rows]
        return {"flow": flow, "time_range": f"{hours}h"}
    except Exception as e:
        print(f"Traffic flow query failed: {e}")
        return {"flow": []}


def query__protocol_distribution(hours=24):
    """Protocol distribution (TCP, UDP, ICMP, etc.)."""
    conn = get_db()
    if not conn:
        return {"protocols": [], "total": 0}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT proto, COUNT(*) as event_count
            FROM events
            WHERE proto IS NOT NULL AND proto != ''
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY proto
            ORDER BY event_count DESC
        """)
        rows = cur.fetchall()
        total = sum(r["event_count"] for r in rows)
        cur.close()
        protocols = [{
            "protocol": r["proto"],
            "count": r["event_count"],
            "percent": round(r["event_count"] / total * 100, 1) if total > 0 else 0
        } for r in rows]
        return {"protocols": protocols, "total": total}
    except Exception as e:
        print(f"Protocol distribution query failed: {e}")
        return {"protocols": [], "total": 0}


def query__action_distribution(hours=24):
    """Action distribution (PASS vs BLOCK, etc.)."""
    conn = get_db()
    if not conn:
        return {"actions": [], "total": 0}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT action, COUNT(*) as event_count
            FROM events
            WHERE action IS NOT NULL AND action != ''
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY action
            ORDER BY event_count DESC
        """)
        rows = cur.fetchall()
        total = sum(r["event_count"] for r in rows)
        cur.close()
        actions = [{
            "action": r["action"],
            "count": r["event_count"],
            "percent": round(r["event_count"] / total * 100, 1) if total > 0 else 0
        } for r in rows]
        return {"actions": actions, "total": total}
    except Exception as e:
        print(f"Action distribution query failed: {e}")
        return {"actions": [], "total": 0}


def query__timeline(period="7d", granularity="hour", start=None, end=None):
    """Traffic volume over time (line chart)."""
    conn = get_db()
    if not conn:
        return {"timeline": [], "blocked_timeline": []}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Compute the time window: prefer explicit start/end (unix ts), fallback to period
        if start and end:
            start_dt = datetime.fromtimestamp(start, tz=timezone.utc)
            end_dt = datetime.fromtimestamp(end, tz=timezone.utc)
        else:
            now = datetime.now(tz=timezone.utc)
            period_map = {
                "1h": timedelta(hours=1),
                "6h": timedelta(hours=6),
                "24h": timedelta(days=1),
                "7d": timedelta(days=7),
                "30d": timedelta(days=30),
            }
            delta = period_map.get(period, timedelta(days=7))
            end_dt = now
            start_dt = now - delta

        # Use the earlier of start_dt and (now - 7 days) so we always get recent data
        fallback_start = datetime.now(tz=timezone.utc) - timedelta(days=7)
        query_start = min(start_dt, fallback_start)

        # Build WHERE clause with proper timestamp parameters
        where_clause = "WHERE timestamp >= %s AND timestamp <= %s"
        query_params = [query_start, end_dt]

        # Total events per time bucket
        if granularity == "hour":
            cur.execute("""
                SELECT date_trunc('hour', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                %s
                GROUP BY bucket
                ORDER BY bucket
            """ % where_clause, query_params)
        else:
            cur.execute("""
                SELECT date_trunc('day', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                %s
                GROUP BY bucket
                ORDER BY bucket
            """ % where_clause, query_params)
        rows = cur.fetchall()
        timeline = [{"time": str(r["bucket"]), "count": r["event_count"]} for r in rows]

        # Blocked events per time bucket
        where_blocked = "WHERE timestamp >= %s AND timestamp <= %s AND action = 'BLOCK'"
        blocked_params = [query_start, end_dt]
        if granularity == "hour":
            cur.execute("""
                SELECT date_trunc('hour', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                %s
                GROUP BY bucket
                ORDER BY bucket
            """ % where_blocked, blocked_params)
        else:
            cur.execute("""
                SELECT date_trunc('day', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                %s
                GROUP BY bucket
                ORDER BY bucket
            """ % where_blocked, blocked_params)
        blocked_rows = cur.fetchall()
        blocked_timeline = [{"time": str(r["bucket"]), "count": r["event_count"]} for r in blocked_rows]

        cur.close()
        return {"timeline": timeline, "blocked_timeline": blocked_timeline, "period": period}
    except Exception as e:
        print(f"Timeline query failed: {e}")
        return {"timeline": [], "blocked_timeline": []}


def query__blocked_ips(hours=24, limit=20):
    """Top source IPs by blocked count (bar chart)."""
    conn = get_db()
    if not conn:
        return {"blocked_ips": [], "total_blocked": 0}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, COUNT(*) as block_count,
                   COUNT(DISTINCT dst_ip) as unique_targets,
                   COUNT(DISTINCT dst_port) as unique_ports
            FROM events
            WHERE src_ip IS NOT NULL AND src_ip != ''
              AND action = 'BLOCK'
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip
            ORDER BY block_count DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        total_blocked = sum(r["block_count"] for r in rows)
        cur.close()
        blocked_ips = [{
            "ip": r["src_ip"],
            "count": r["block_count"],
            "unique_targets": r["unique_targets"],
            "unique_ports": r["unique_ports"]
        } for r in rows]
        return {"blocked_ips": blocked_ips, "total_blocked": total_blocked}
    except Exception as e:
        print(f"Blocked IPs query failed: {e}")
        return {"blocked_ips": [], "total_blocked": 0}


def query__top_ports(hours=24, limit=20):
    """Top destination ports (bar chart)."""
    conn = get_db()
    if not conn:
        return {"ports": [], "total": 0}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT dst_port, COUNT(*) as event_count,
                   COUNT(DISTINCT src_ip) as unique_sources,
                   COUNT(DISTINCT CASE WHEN action = 'BLOCK' THEN 1 END) as block_count
            FROM events
            WHERE dst_port IS NOT NULL
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY dst_port
            ORDER BY event_count DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        total = sum(r["event_count"] for r in rows)
        cur.close()
        
        # Common port name mapping
        port_names = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            123: "NTP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        
        ports = [{
            "port": r["dst_port"],
            "name": port_names.get(r["dst_port"], str(r["dst_port"])),
            "count": r["event_count"],
            "unique_sources": r["unique_sources"],
            "block_count": r["block_count"],
            "percent": round(r["event_count"] / total * 100, 1) if total > 0 else 0
        } for r in rows]
        return {"ports": ports, "total": total}
    except Exception as e:
        print(f"Top ports query failed: {e}")
        return {"ports": [], "total": 0}


def query__rule_heatmap(hours=24, limit=30):
    """Rule activity heatmap (rules × hours)."""
    conn = get_db()
    if not conn:
        return {"heatmap": [], "rules": []}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get top rules by event count
        cur.execute("""
            SELECT rule_name, COUNT(*) as total_events
            FROM events
            WHERE rule_name IS NOT NULL AND rule_name != ''
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY rule_name
            ORDER BY total_events DESC
            LIMIT %s
        """, (limit,))
        top_rules = [r["rule_name"] for r in cur.fetchall()]
        
        # Get events per hour for each rule
        heatmap = []
        for rule in top_rules:
            cur.execute("""
                SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as event_count
                FROM events
                WHERE rule_name = %s AND timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY hour
                ORDER BY hour
            """, (rule,))
            hours_data = cur.fetchall()
            heatmap.append({
                "rule": rule,
                "hourly": [{"time": str(h["hour"]), "count": h["event_count"]} for h in hours_data]
            })
        
        cur.close()
        return {"heatmap": heatmap, "rules": top_rules}
    except Exception as e:
        print(f"Rule heatmap query failed: {e}")
        return {"heatmap": [], "rules": []}


def query__direction_distribution(hours=24):
    """Network direction distribution (in/out)."""
    conn = get_db()
    if not conn:
        return {"directions": [], "total": 0}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT direction, COUNT(*) as event_count
            FROM events
            WHERE direction IS NOT NULL AND direction != ''
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY direction
            ORDER BY event_count DESC
        """)
        rows = cur.fetchall()
        total = sum(r["event_count"] for r in rows)
        cur.close()
        directions = [{
            "direction": r["direction"],
            "count": r["event_count"],
            "percent": round(r["event_count"] / total * 100, 1) if total > 0 else 0
        } for r in rows]
        return {"directions": directions, "total": total}
    except Exception as e:
        print(f"Direction distribution query failed: {e}")
        return {"directions": [], "total": 0}


def query__rule_action_breakdown(hours=24, limit=30):
    """Top rules with pass/block breakdown."""
    conn = get_db()
    if not conn:
        return {"rules": []}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT rule_name, action, COUNT(*) as event_count
            FROM events
            WHERE rule_name IS NOT NULL AND rule_name != ''
              AND timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY rule_name, action
            ORDER BY rule_name, event_count DESC
        """)
        rows = cur.fetchall()
        
        # Group by rule_name
        rules_dict = {}
        for r in rows:
            name = r["rule_name"]
            if name not in rules_dict:
                rules_dict[name] = {"name": name, "pass": 0, "block": 0, "total": 0}
            act = r["action"].upper() if r["action"] else ""
            if act == "PASS":
                rules_dict[name]["pass"] = r["event_count"]
            elif act == "BLOCK":
                rules_dict[name]["block"] = r["event_count"]
            rules_dict[name]["total"] += r["event_count"]
        
        rules = sorted(rules_dict.values(), key=lambda x: -x["total"])[:limit]
        cur.close()
        return {"rules": rules}
    except Exception as e:
        print(f"Rule action breakdown query failed: {e}")
        return {"rules": []}

def run_server(host=None, port=8766):
    """Run the dashboard HTTP server.

    Binds to 0.0.0.0 (all interfaces) by default so the dashboard is
    accessible on the network. Override with DASHBOARD_BIND env var to
    restrict to a specific interface (e.g. '127.0.0.1' for localhost-only).
    """
    import logging
    logger = logging.getLogger(__name__)
    logger.info("run_server starting: host=%s, port=%s", host, port)
    
    bind_host = host or os.getenv("DASHBOARD_BIND", "0.0.0.0")
    logger.info("bind_host=%s port=%s", bind_host, port)

    # Start SSE background cleaner thread
    sse_cleaner = threading_lib.Thread(target=sse_background_cleaner, daemon=True)
    sse_cleaner.start()
    logger.info("SSE background cleaner started")

    global _server_instance
    try:
        _server_instance = ThreadedHTTPServer((bind_host, port), DashboardHandler)
        logger.info("Dashboard server listening on %s:%s", bind_host, port)
        _server_instance.serve_forever()
        _server_instance = None
    except Exception:
        logger.exception("Dashboard server crashed")
        raise


_server_instance = None  # Global reference for shutdown


def shutdown_server(timeout: float = _MAX_DRAIN_WAIT) -> None:
    """Trigger graceful shutdown of the dashboard server."""
    global _server_instance
    if _server_instance:
        threading_lib.Thread(target=_do_shutdown, args=(timeout,), daemon=True).start()


def _do_shutdown(timeout: float):
    """Internal: drain then stop server."""
    graceful_shutdown(timeout=timeout)
    global _server_instance
    if _server_instance:
        _server_instance.shutdown()
        _server_instance = None


if __name__ == "__main__":
    run_server()
