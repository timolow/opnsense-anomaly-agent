#!/usr/bin/env python3
"""Dashboard API server - reads from PostgreSQL + state file."""

import json
import os
import time
import urllib.parse
import logging
from datetime import datetime, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

import sys
from typing import Any, Dict
sys.path.insert(0, '/app')

from eventdb import EventDatabase

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

def add_mute(ip, attack_type, port=None, duration=3600, source="manual"):
    mutes = load_mutes()
    mute = {
        "id": f"mute_{int(time.time()*1000)}",
        "ip": ip, "attack_type": attack_type, "port": port,
        "duration_seconds": duration,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "expires": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
    """Read OPNsense config from env vars (docker-compose) or config.json fallback."""
    # Primary: environment variables from docker-compose
    host = os.environ.get("OPN_HOST", "192.168.1.1")
    port = int(os.environ.get("OPN_PORT", "443"))
    api_key = os.environ.get("OPN_API_KEY", "")
    api_secret = os.environ.get("OPN_API_SECRET", "")
    verify_ssl = os.environ.get("OPN_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
    url = f"https://{host}:{port}"
    # Only return full config if API key was set via env
    if api_key:
        return url, api_key, api_secret, verify_ssl
    # Fallback: read from config.json
    config_path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            opn = cfg.get("opnsense", {})
            h = opn.get("host", host)
            p = opn.get("port", port)
            k = opn.get("api_key", "")
            s = opn.get("api_secret", "")
            v = opn.get("verify_ssl", not verify_ssl)
            return f"https://{h}:{p}", k, s, v
        except Exception:
            pass
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
    
    # 24h action counts for blocked/passed
    blocked_24h = 0
    passed_24h = 0
    if conn:
        try:
            cur2 = conn.cursor()
            cur2.execute("SELECT COUNT(*) FROM events WHERE action = 'BLOCK' AND timestamp > NOW() - INTERVAL '24 hours'")
            blocked_24h = cur2.fetchone()[0]
            cur2.execute("SELECT COUNT(*) FROM events WHERE action = 'PASS' AND timestamp > NOW() - INTERVAL '24 hours'")
            passed_24h = cur2.fetchone()[0]
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
    return {
        "counters": counters, "by_type": dict(by_type),
        "by_severity": by_severity, "top_sources": top_sources[:20],
        "categories": dict(categories), "active_mutes": len(load_mutes()),
        "ip_classifications": ip_classifications,
        "total_ips": total_events,
        "total_events": db_event_count,
        "time_range": "24h",
        "top_countries": top_countries,
        "blocked_24h": blocked_24h,
        "passed_24h": passed_24h,
        "rules_classified": rules_classified,
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

        # 1. Firmware/Version info
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/core/firmware/status",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                sys_info = json.loads(resp.read().decode())
            if isinstance(sys_info, dict):
                results["opnsense_version"] = sys_info.get("os_version", "unknown")
            else:
                results["opnsense_version"] = "unknown"
            results["status"] = "connected"
        except Exception as e:
            print(f"OPNsense firmware status failed: {e}")
            results["opnsense_version"] = "error"

        # 2. Interfaces - get IPv4/6 addresses, up/down status
        results["interfaces"] = []
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/interfaces/assignments",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                iface_data = json.loads(resp.read().decode())
            rows = iface_data.get("interfaces", {}).get("row", [])
            if not rows and isinstance(iface_data, dict) and "row" in iface_data:
                rows = iface_data.get("row", [])
            for iface in rows:
                name = iface.get("if", iface.get("interface", "unknown"))
                description = iface.get("descr", "")
                mac = iface.get("mac", "")
                ipv4 = iface.get("ipaddr", "")
                ipv6 = iface.get("ipv6addr", "")
                subnet4 = iface.get("subnet", "")
                subnet6 = iface.get("ipv6mode", "")
                results["interfaces"].append({
                    "name": name,
                    "description": description,
                    "mac": mac,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "subnet4": subnet4,
                    "subnet6": subnet6,
                })
        except Exception as e:
            print(f"OPNsense interfaces failed: {e}")

        # 3. Gateways - get WAN gateways with IPv4/6
        results["gateways"] = []
        try:
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
                gateway_ip = gw.get("gateway", gw.get("gatewayv6", ""))
                source_ip = gw.get("source", "")
                upstream = gw.get("upstream", False)
                is_vpn = gw.get("vpn_gateway", False)
                results["gateways"].append({
                    "name": name,
                    "interface": interface,
                    "gateway_ip": gateway_ip,
                    "source_ip": source_ip,
                    "upstream": upstream,
                    "vpn_gateway": is_vpn,
                })
        except Exception as e:
            print(f"OPNsense gateways failed: {e}")

        # 3b. Derive interfaces from gateways if API didn't return any
        if not results["interfaces"]:
            iface_data = {}
            for gw in results["gateways"]:
                iface_name = gw.get("interface", "")
                gw_ip = gw.get("gateway_ip", "")
                gw_name = gw.get("name", "")
                if not iface_name:
                    continue
                if iface_name not in iface_data:
                    iface_data[iface_name] = {"ipv4": "", "ipv6": "", "upstream": False, "vpn": False}
                if gw_ip:
                    if gw_ip.startswith("fe80:") or gw_ip.startswith("fe8") or ":" in gw_ip:
                        # IPv6 address
                        if not iface_data[iface_name]["ipv6"]:
                            iface_data[iface_name]["ipv6"] = gw_ip
                    else:
                        # IPv4 address
                        if not iface_data[iface_name]["ipv4"]:
                            iface_data[iface_name]["ipv4"] = gw_ip
                # Track upstream flag
                if gw.get("upstream"):
                    iface_data[iface_name]["upstream"] = True
                # Detect VPN from gateway name or interface name pattern
                gw_name_upper = gw_name.upper()
                if ("VPN" in gw_name_upper or
                    "WG" in gw_name_upper or
                    iface_name.startswith("ovpn") or
                    iface_name.startswith("wg") or
                    iface_name.startswith("tun")):
                    iface_data[iface_name]["vpn"] = True
            for iface_name, data in iface_data.items():
                # Classify: WAN if upstream, VPN if vpn flag, otherwise LAN
                if data.get("upstream"):
                    desc = "WAN"
                elif data.get("vpn"):
                    desc = "VPN"
                elif not data.get("ipv4"):
                    desc = "LAN"
                else:
                    desc = "WAN"
                results["interfaces"].append({
                    "name": iface_name,
                    "description": desc,
                    "mac": "",
                    "ipv4": data.get("ipv4", ""),
                    "ipv6": data.get("ipv6", ""),
                    "subnet4": "",
                    "subnet6": "",
                })

        # 4. Interface status - up/down states
        results["interface_status"] = {}
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/interfaces/status",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                status_data = json.loads(resp.read().decode())
            rows = status_data.get("interfaces", {}).get("row", [])
            for row in rows:
                name = row.get("interface", row.get("name", ""))
                state = row.get("state", row.get("status", "unknown"))
                media = row.get("media", "")
                results["interface_status"][name] = {
                    "state": state,
                    "media": media,
                }
        except Exception as e:
            print(f"OPNsense interface status failed: {e}")

        # 5. DHCP leases count
        results["dhcp_leases"] = 0
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/dhcpd/status",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                dhcp_data = json.loads(resp.read().decode())
            leases_list = dhcp_data.get("leases", {}).get("row", [])
            if not leases_list and isinstance(dhcp_data, dict):
                leases_list = dhcp_data.get("row", [])
            results["dhcp_leases"] = len(leases_list)
        except Exception as e:
            print(f"OPNsense DHCP failed: {e}")

        # 6. Firewall rules count
        results["firewall_rules"] = 0
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/filter/rules",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                rules_data = json.loads(resp.read().decode())
            rules_list = rules_data.get("rules", {}).get("row", [])
            if not rules_list and isinstance(rules_data, dict):
                rules_list = rules_data.get("row", [])
            results["firewall_rules"] = len(rules_list)
        except Exception as e:
            print(f"OPNsense rules failed: {e}")

        # 7. OpenVPN status
        results["openvpn_tunnels"] = []
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/services/openvpn/status",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                vpn_data = json.loads(resp.read().decode())
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

        # 8. NTP status
        results["ntp_status"] = {}
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/services/ntp/status",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                ntp_data = json.loads(resp.read().decode())
            if isinstance(ntp_data, dict):
                results["ntp_status"] = {
                    "status": ntp_data.get("status", ntp_data.get("state", "unknown")),
                    "servers": ntp_data.get("servers", ntp_data.get("config", [])),
                    "last_sync": ntp_data.get("last_sync", ntp_data.get("last_update", "")),
                }
        except Exception as e:
            print(f"OPNsense NTP failed: {e}")

        # 9. DNSMasq status
        results["dnsmasq_status"] = {}
        try:
            req = urllib.request.Request(
                f"{opn_url}/api/services/dnsmasq/status",
                headers={"Authorization": auth_header},
            )
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                dns_data = json.loads(resp.read().decode())
            if isinstance(dns_data, dict):
                results["dnsmasq_status"] = {
                    "status": dns_data.get("status", dns_data.get("state", "unknown")),
                    "leases": dns_data.get("leases", dns_data.get("current_leases", 0)),
                }
        except Exception as e:
            print(f"OPNsense DNSMasq failed: {e}")

        return results
    except Exception as e:
        return {
            "status": "disconnected", "error": str(e),
            "opnsense_version": "unknown", "interfaces": [],
            "gateways": [], "interface_status": {},
            "dhcp_leases": 0, "firewall_rules": 0,
            "openvpn_tunnels": [], "ntp_status": {},
            "dnsmasq_status": {},
        }

def query_alerts():
    conn = get_db()
    if not conn: return _fallback_alerts()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT src_ip, COUNT(*) as cnt, COUNT(DISTINCT dst_ip) as unique_dst, interface
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
            alerts.append({"ip": row["src_ip"], "attack_type": f"{classify_interface(row['interface'])} traffic", "count": cnt, "severity": severity, "unique_destinations": row["unique_dst"], "interface": row["interface"]})
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
            SELECT id, type, severity, description, src_ip, timestamp
            FROM anomalies
            ORDER BY id DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        anomalies = []
        for row in rows:
            anomalies.append({
                "id": row["id"],
                "type": row["type"],
                "severity": row["severity"],
                "description": row["description"],
                "src_ip": row.get("src_ip", ""),
                "timestamp": str(row["timestamp"]) if row["timestamp"] else ""
            })
        return anomalies
    except Exception as e:
        print(f"Anomalies query failed: {e}")
        return []
    finally: close_db(conn)

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
        event_count = 0
    
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
    }


# ──────────────────────────────────────────────────────────────────────
# ZenArmor query helpers
# ──────────────────────────────────────────────────────────────────────

ZENARMOR_STATE_FILE = os.path.join(os.environ.get("AGENT_DATA_DIR", "/app/agent_data"), "zenarmor_state.json")
IDS_STATE_FILE = os.path.join(os.environ.get("AGENT_DATA_DIR", "/app/agent_data"), "ids_state.json")

def load_json_state(filepath):
    """Load a JSON state file, returning empty dict on failure."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def query_zenarmor_summary():
    """Return ZenArmor policy summary matching frontend types."""
    state = load_json_state(ZENARMOR_STATE_FILE)
    if not state:
        return {
            "total_events": 0,
            "policies_count": 0,
            "anomalies_detected": 0,
            "events_24h": 0,
        }
    policies_count = len(state.get("policies", {}))
    anomalies = state.get("summary", {}).get("anomalies_detected", 0)
    total_events = state.get("summary", {}).get("total_events", state.get("total_events", 0))
    return {
        "total_events": total_events,
        "policies_count": policies_count,
        "anomalies_detected": anomalies,
        "events_24h": total_events,  # fallback: same as total
    }

def query_zenarmor_policies():
    """Return all known ZenArmor policies matching frontend types."""
    state = load_json_state(ZENARMOR_STATE_FILE)
    if not state:
        return []
    policies = []
    for name, data in state.get("policies", {}).items():
        total_events = data.get("total_events", 0)
        actions = data.get("actions", {})
        action = "block" if actions.get("BLOCK", 0) > actions.get("PASS", 0) else "pass"
        policies.append({
            "id": data.get("policy_id", name[:8]),
            "name": data.get("policy_name", name),
            "category": data.get("category", "general"),
            "status": "active" if data.get("enabled", True) else "inactive",
            "action": action,
            "description": data.get("description", ""),
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

    state = load_json_state(IDS_STATE_FILE)
    sig_count = len(state.get("signatures", {})) if state else 0
    anomalies = state.get("summary", {}).get("anomalies_detected", 0) if state else 0

    return {
        "total_events": max(db_total, sig_count),
        "signatures": max(db_signatures, sig_count),
        "anomalies_detected": anomalies,
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
    state = load_json_state(IDS_STATE_FILE)
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
                    "id": data.get("id", name[:8]),
                    "name": data.get("name", name),
                    "category": data.get("category", "unknown"),
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

    def do_GET(self):
        path = self.path.split("?")[0]
        
        # Serve static files (JS, CSS, etc.) from webui/dist
        if path.startswith("/assets/"):
            if self._serve_static():
                return
        
        # Serve API endpoints
        if path.startswith("/api/"):
            if path == "/api/stats":
                self._send_json(query_stats())
            # ═══════════════════════════════════════════════
            # -style visualizations (read from PostgreSQL)
            # ═══════════════════════════════════════════════
            elif path == "/api//traffic-flow":
                self._send_json(query__traffic_flow())
            elif path == "/api//protocols":
                self._send_json(query__protocol_distribution())
            elif path == "/api//actions":
                self._send_json(query__action_distribution())
            elif path == "/api//timeline":
                self._send_json(query__timeline())
            elif path == "/api//blocked-ips":
                self._send_json(query__blocked_ips())
            elif path == "/api//top-ports":
                self._send_json(query__top_ports())
            elif path == "/api//rule-heatmap":
                self._send_json(query__rule_heatmap())
            elif path == "/api//directions":
                self._send_json(query__direction_distribution())
            elif path == "/api//rule-actions":
                self._send_json(query__rule_action_breakdown())
            elif path == "/api/heatmap":
                self._send_json(query_heatmap())
            elif path == "/api/ip-flow":
                self._send_json(query_ip_flow())
            elif path == "/api/events":
                self._send_json(query_events())
            elif path == "/api/mutes":
                self._send_json(load_mutes())
            elif path == "/api/geo":
                self._send_json(query_geo())
            elif path == "/api/health":
                self._send_json(query_health())
            elif path == "/api/alerts":
                self._send_json(query_alerts())
            elif path == "/api/anomalies":
                self._send_json(query_anomalies())
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
            elif path == "/api/active-learning-queue":
                try:
                    data = api_active_learning_queue()
                    self._send_json(data)
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
            elif path.startswith("/api/rule-detail/"):
                rule_name = urllib.parse.unquote(path.split("/api/rule-detail/")[-1])
                if rule_name:
                    self._send_json(query_rule_detail(rule_name))
                else:
                    self._send_json({"error": "No rule name specified"}, 400)
            else:
                self.send_response(404)
                self.end_headers()
            return
        
        # Catch-all for SPA: serve index.html for client-side routing
        self._serve_html()

    def do_POST(self):
        if self.path == "/api/mutes":
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            mute = add_mute(ip=data.get("ip", ""), attack_type=data.get("attack_type", "ALL"), port=data.get("port"), duration=data.get("duration_seconds", 3600))
            self._send_json(mute, 201)
        else:
            self.send_response(405)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/api/mutes/"):
            mute_id = self.path.split("/api/mutes/")[-1]
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


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


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


def query__timeline(period="7d", granularity="hour"):
    """Traffic volume over time (line chart)."""
    conn = get_db()
    if not conn:
        return {"timeline": [], "blocked_timeline": []}
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Total events per time bucket
        if granularity == "hour":
            cur.execute("""
                SELECT date_trunc('%s', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '7 days'
                GROUP BY bucket
                ORDER BY bucket
            """ % (granularity,))
        else:
            cur.execute("""
                SELECT date_trunc('day', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '7 days'
                GROUP BY bucket
                ORDER BY bucket
            """)
        rows = cur.fetchall()
        timeline = [{"time": str(r["bucket"]), "count": r["event_count"]} for r in rows]
        
        # Blocked events per time bucket
        if granularity == "hour":
            cur.execute("""
                SELECT date_trunc('%s', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '7 days' AND action = 'BLOCK'
                GROUP BY bucket
                ORDER BY bucket
            """ % (granularity,))
        else:
            cur.execute("""
                SELECT date_trunc('day', timestamp) as bucket, COUNT(*) as event_count
                FROM events
                WHERE timestamp > NOW() - INTERVAL '7 days' AND action = 'BLOCK'
                GROUP BY bucket
                ORDER BY bucket
            """)
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
    logger.info("bind_host=%s", bind_host)
    
    # Write a startup marker IMMEDIATELY - if this doesn't appear, import itself is crashing
    import traceback as tb
    marker = os.path.join(os.environ.get("AGENT_DATA_DIR", "/app/agent_data"), "server_debug.txt")
    logger.info("Creating marker at %s", marker)
    try:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, "w") as f:
            f.write("run_server entered\n")
            f.flush()
            f.write(f"PID={os.getpid()}\n")
            f.flush()
        logger.info("Marker created successfully")
    except Exception as e:
        logger.error("Failed to create marker: %s", e)
        tb.print_exc()
    
    try:
        server = ThreadedHTTPServer((bind_host, port), DashboardHandler)
        with open(marker, "a") as f:
            f.write("ThreadedHTTPServer created\n")
            f.flush()
        server.serve_forever()
        with open(marker, "a") as f:
            f.write("serve_forever entered\n")
            f.flush()
    except Exception as e:
        with open(marker, "a") as f:
            f.write(f"EXCEPTION: {e}\n")
            tb.print_exc(file=f)
            f.flush()
        raise

if __name__ == "__main__":
    run_server()
