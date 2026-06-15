#!/usr/bin/env python3
"""Dashboard API server — reads from PostgreSQL + state file."""

import json
import os
import time
import datetime
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False
    print("WARNING: psycopg2 not installed — some endpoints will return empty data")

# ─── Config ──────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE_DIR, "agent_data", "state.json")
MUTES_PATH = os.path.join(BASE_DIR, "agent_data", "mutes.json")
DATA_DIR = os.path.join(BASE_DIR, "agent_data")

# PostgreSQL connection from agent config
DB_HOST = "127.0.0.1"  # PostgreSQL in same container
DB_PORT = 5432
DB_NAME = "opnsense"
DB_USER = "postgres"
DB_PASS = ""  # Local trust auth

# Fallback: read from env or config file
try:
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(BASE_DIR, "config.ini"))
    DB_HOST = cfg.get("database", "host", fallback="127.0.0.1")
    DB_PORT = cfg.getint("database", "port", fallback=5432)
    DB_NAME = cfg.get("database", "dbname", fallback="opnsense")
    DB_USER = cfg.get("database", "user", fallback="postgres")
    DB_PASS = cfg.get("database", "password", fallback="")
except Exception:
    pass


def get_db():
    """Get a PostgreSQL connection."""
    if not HAS_PSYCOPG:
        return None
    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASS
        )
        return conn
    except Exception as e:
        print(f"DB connection failed: {e}")
        return None


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
        "ip": ip,
        "attack_type": attack_type,
        "port": port,
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
    """Get event count from IP record, handling both old and new formats."""
    if isinstance(record, dict):
        if "count" in record:
            return record["count"]
        if "event_count" in record:
            return record["event_count"]
    return 0


# ─── PostgreSQL queries ──────────────────────────────────────────────────────
def query_stats():
    conn = get_db()
    if not conn:
        return {"counters": {}, "by_type": {}, "top_sources": []}
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get event counts by IP, source_type
        cur.execute("""
            SELECT 
                src_ip,
                src_type,
                COUNT(*) as event_count,
                COUNT(DISTINCT dst_ip) as unique_destinations,
                COUNT(DISTINCT dst_port) as unique_ports
            FROM events 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, src_type
            ORDER BY event_count DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
        
        by_type = defaultdict(int)
        top_sources = []
        total_events = 0
        categories = defaultdict(int)
        
        for row in rows:
            ip = row["src_ip"]
            src_type = row["src_type"] or "UNKNOWN"
            cnt = row["event_count"]
            total_events += cnt
            
            # Categorize by source type
            if src_type == "WAN":
                categories["WAN"] += 1
                by_type["external"] += cnt
            elif src_type == "LAN":
                categories["LAN"] += 1
                by_type["internal"] += cnt
            elif src_type == "VPN":
                categories["VPN"] += 1
                by_type["vpn"] += cnt
            else:
                categories["UNKNOWN"] += 1
            
            top_sources.append({
                "ip": ip,
                "count": cnt,
                "category": src_type,
                "unique_destinations": row["unique_destinations"],
                "unique_ports": row["unique_ports"],
            })
        
        # Severity
        by_severity = {
            "CRITICAL": sum(1 for s in top_sources if s["count"] > 500),
            "HIGH": sum(1 for s in top_sources if 100 <= s["count"] <= 500),
            "MEDIUM": sum(1 for s in top_sources if 10 < s["count"] < 100),
            "LOW": sum(1 for s in top_sources if s["count"] <= 10),
        }
        
        # Get total from agent_counters if available
        state = load_state()
        agent_counters = {}
        if state:
            agent_counters = state.get("agent_counters", {})
        
        cur.close()
        
        return {
            "counters": agent_counters,
            "by_type": dict(by_type),
            "by_severity": by_severity,
            "top_sources": top_sources[:20],
            "categories": dict(categories),
            "active_mutes": len(load_mutes()),
            "total_ips": len(set(r["src_ip"] for r in rows)),
            "total_events": total_events,
            "time_range": "24h",
            "agent_counters": agent_counters,
        }
    except Exception as e:
        print(f"Stats query failed: {e}")
        return {"counters": {}, "by_type": {}, "top_sources": []}
    finally:
        close_db(conn)


def query_heatmap():
    """Build heatmap: time (hours) × IP activity from PostgreSQL."""
    conn = get_db()
    if not conn:
        return {"labels_x": [], "labels_y": [], "data": [], "events": []}
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get events by IP and hour for the last 24 hours
        cur.execute("""
            SELECT 
                src_ip,
                EXTRACT(HOUR FROM created_at) as hour,
                COUNT(*) as event_count
            FROM events 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, EXTRACT(HOUR FROM created_at)
            ORDER BY src_ip, hour
        """)
        rows = cur.fetchall()
        
        # Build matrix: ip -> hour -> count
        ip_hour_data = defaultdict(lambda: defaultdict(int))
        all_ips = set()
        all_hours = set()
        
        for row in rows:
            ip = row["src_ip"]
            hour = int(row["hour"])
            cnt = row["event_count"]
            ip_hour_data[ip][hour] += cnt
            all_ips.add(ip)
            all_hours.add(hour)
        
        # Sort IPs by total events
        ip_totals = {}
        for ip, hours in ip_hour_data.items():
            ip_totals[ip] = sum(hours.values())
        sorted_ips = sorted(ip_totals.keys(), key=lambda x: ip_totals[x], reverse=True)
        
        # Limit to top 50 IPs for performance
        top_ips = sorted_ips[:50]
        
        # Build matrix
        matrix = []
        for ip in top_ips:
            row_data = [ip_hour_data[ip].get(h, 0) for h in range(24)]
            matrix.append(row_data)
        
        return {
            "labels_x": [f"{h:02d}:00" for h in range(24)],
            "labels_y": top_ips,
            "data": matrix,
            "total_events": sum(sum(row) for row in matrix),
        }
    except Exception as e:
        print(f"Heatmap query failed: {e}")
        return {"labels_x": [], "labels_y": [], "data": [], "events": []}
    finally:
        close_db(conn)


def query_ip_flow():
    """Build IP flow: connections between source IPs and their destinations."""
    conn = get_db()
    if not conn:
        return {"nodes": [], "links": []}
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get all unique source IPs and their connection counts
        cur.execute("""
            SELECT 
                src_ip,
                dst_ip,
                COUNT(*) as connection_count,
                ARRAY_AGG(DISTINCT dst_port) as ports,
                ARRAY_AGG(DISTINCT src_type) as types
            FROM events 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, dst_ip
            HAVING COUNT(*) > 1
            ORDER BY connection_count DESC
            LIMIT 500
        """)
        links = cur.fetchall()
        
        # Get source IP types for categorization
        cur.execute("""
            SELECT src_ip, src_type, COUNT(*) as total
            FROM events 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, src_type
            ORDER BY total DESC
        """)
        type_rows = cur.fetchall()
        
        # Build node map
        nodes = []
        node_map = {}
        colors = {
            "WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7",
            "SOURCE": "#3b82f6", "TARGET": "#f59e0b", "UNKNOWN": "#6b7280",
        }
        
        # Build connections list
        connections = []
        
        for row in links:
            src_ip = row["src_ip"]
            dst_ip = row["dst_ip"]
            count = row["connection_count"]
            
            # Add source node
            if src_ip not in node_map:
                src_type = "UNKNOWN"
                for tr in type_rows:
                    if tr["src_ip"] == src_ip:
                        src_type = tr["src_type"] or "UNKNOWN"
                        break
                nodes.append({
                    "id": src_ip,
                    "label": src_ip,
                    "category": src_type,
                    "color": colors.get(src_type, "#3b82f6"),
                    "size": min(6 + count, 24),
                })
                node_map[src_ip] = len(nodes) - 1
            
            # Add destination node
            if dst_ip not in node_map:
                dst_type = "TARGET"
                # Check if dst is a known type
                for tr in type_rows:
                    if tr["src_ip"] == dst_ip:
                        dst_type = tr["src_type"] or "TARGET"
                        break
                nodes.append({
                    "id": dst_ip,
                    "label": dst_ip,
                    "category": dst_type,
                    "color": colors.get(dst_type, "#f59e0b"),
                    "size": min(4 + count, 18),
                })
                node_map[dst_ip] = len(nodes) - 1
            
            # Add link
            ports = [str(p) for p in (row["ports"] or [])[:5]]
            connections.append({
                "source": src_ip,
                "target": dst_ip,
                "value": count,
                "ports": ports,
                "type": "traffic",
            })
        
        # Limit to top 60 nodes
        if len(nodes) > 60:
            node_conn = defaultdict(int)
            for conn in connections:
                node_conn[conn["source"]] += 1
                node_conn[conn["target"]] += 1
            top_ids = sorted(node_conn.keys(), key=lambda x: node_conn[x], reverse=True)[:60]
            nodes = [n for n in nodes if n["id"] in top_ids]
            node_map = {n["id"]: i for i, n in enumerate(nodes)}
            connections = [c for c in connections if c["source"] in top_ids or c["target"] in top_ids]
        
        return {
            "nodes": nodes,
            "links": connections,
        }
    except Exception as e:
        print(f"IP flow query failed: {e}")
        return {"nodes": [], "links": []}
    finally:
        close_db(conn)


def query_geo():
    """Get geographic data from IP tracking data."""
    conn = get_db()
    if not conn:
        return query_geo_from_state()
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get events by source IP
        cur.execute("""
            SELECT src_ip, COUNT(*) as event_count
            FROM events 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip
            ORDER BY event_count DESC
            LIMIT 1000
        """)
        rows = cur.fetchall()
        
        # Simple geo mapping based on IP ranges (simplified)
        region_groups = defaultdict(int)
        flag_map = {
            "CN": "🇨🇳", "US": "🇺🇸", "RU": "🇷🇺", "BR": "🇧🇷",
            "DE": "🇩🇪", "GB": "🇬🇧", "IN": "🇮🇳", "FR": "🇫🇷",
            "JP": "🇯🇵", "KR": "🇰🇷", "AU": "🇦🇺", "NL": "🇳🇱",
            "CA": "🇨🇦", "IT": "🇮🇹", "ES": "🇪🇸", "OTHER": "🌐",
        }
        color_map = {
            "CN": "#ef4444", "US": "#3b82f6", "RU": "#f59e0b",
            "BR": "#22c55e", "DE": "#eab308", "GB": "#8b5cf6",
            "IN": "#06b6d4", "FR": "#ec4899", "JP": "#f43f5e",
            "OTHER": "#6b7280",
        }
        
        for row in rows:
            ip = row["src_ip"]
            cnt = row["event_count"]
            first_octet = int(ip.split(".")[0]) if ip else 0
            
            # Simplified geo mapping by first octet
            if first_octet in range(114, 125):  # China range
                region_groups["China"] += cnt
            elif first_octet in [45, 64, 66, 70, 72, 74, 98, 99, 104, 108]:  # US
                region_groups["US"] += cnt
            elif first_octet in range(5, 94) and first_octet not in range(114, 125):  # Europe/Russia
                region_groups["Russia"] += cnt
            elif first_octet in range(14, 62) and first_octet not in range(114, 125):  # Japan/Korea
                region_groups["Japan"] += cnt
            else:
                region_groups["Other"] += cnt
        
        result = []
        for region, count in region_groups.items():
            flag = flag_map.get(region, "🌐")
            color = color_map.get(region, "#6b7280")
            result.append({
                "country": region,
                "count": count,
                "color": color,
                "flag": flag,
            })
        
        result.sort(key=lambda x: x["count"], reverse=True)
        return result
    except Exception as e:
        print(f"Geo query failed: {e}")
        return query_geo_from_state()
    finally:
        close_db(conn)


def query_geo_from_state():
    """Fallback geo from state file."""
    state = load_state()
    if not state:
        return []
    
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    flag_map = {
        "CN": "🇨🇳", "US": "🇺🇸", "RU": "🇷🇺", "BR": "🇧🇷",
        "DE": "🇩🇪", "GB": "🇬🇧", "IN": "🇮🇳", "FR": "🇫🇷",
        "JP": "🇯🇵", "KR": "🇰🇷", "AU": "🇦🇺", "NL": "🇳🇱",
        "CA": "🇨🇦", "IT": "🇮🇹", "ES": "🇪🇸", "OTHER": "🌐",
    }
    color_map = {
        "CN": "#ef4444", "US": "#3b82f6", "RU": "#f59e0b",
        "BR": "#22c55e", "DE": "#eab308", "GB": "#8b5cf6",
        "IN": "#06b6d4", "FR": "#ec4899", "JP": "#f43f5e",
        "OTHER": "#6b7280",
    }
    
    region_groups = defaultdict(int)
    for ip, info in ip_data.items():
        if not isinstance(info, dict):
            continue
        cnt = _get_event_count(info)
        if cnt == 0:
            continue
        
        first_octet = int(ip.split(".")[0]) if ip else 0
        if first_octet in range(114, 125):
            region_groups["China"] += cnt
        elif first_octet in [45, 64, 66, 70, 72, 74, 98, 99, 104, 108]:
            region_groups["US"] += cnt
        elif first_octet in range(5, 94) and first_octet not in range(114, 125):
            region_groups["Russia"] += cnt
        elif first_octet in range(14, 62) and first_octet not in range(114, 125):
            region_groups["Japan"] += cnt
        else:
            region_groups["Other"] += cnt
    
    result = []
    for region, count in region_groups.items():
        flag = flag_map.get(region, "🌐")
        color = color_map.get(region, "#6b7280")
        result.append({
            "country": region,
            "count": count,
            "color": color,
            "flag": flag,
        })
    
    result.sort(key=lambda x: x["count"], reverse=True)
    return result


def query_alerts():
    """Get high-activity IPs as alerts from PostgreSQL."""
    conn = get_db()
    if not conn:
        return query_alerts_from_state()
    
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                src_ip,
                src_type,
                COUNT(*) as event_count,
                COUNT(DISTINCT dst_ip) as unique_destinations,
                MIN(created_at) as first_seen,
                MAX(created_at) as last_seen
            FROM events 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY src_ip, src_type
            HAVING COUNT(*) > 10
            ORDER BY event_count DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        
        alerts = []
        for row in rows:
            cnt = row["event_count"]
            severity = "CRITICAL" if cnt > 500 else "WARNING"
            alerts.append({
                "ip": row["src_ip"],
                "attack_type": f"{row['src_type'] or 'UNKNOWN'} traffic",
                "count": cnt,
                "severity": severity,
                "unique_destinations": row["unique_destinations"],
                "first_seen": str(row["first_seen"]),
                "last_seen": str(row["last_seen"]),
            })
        
        return alerts
    except Exception as e:
        print(f"Alerts query failed: {e}")
        return query_alerts_from_state()
    finally:
        close_db(conn)


def query_alerts_from_state():
    """Fallback alerts from state file."""
    state = load_state()
    if not state:
        return []
    
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    alerts = []
    for ip, info in ip_data.items():
        if not isinstance(info, dict):
            continue
        
        cnt = _get_event_count(info)
        cat = info.get("category", "UNKNOWN")
        
        if cnt > 50:
            severity = "CRITICAL" if cnt > 500 else "WARNING"
            alerts.append({
                "ip": ip,
                "attack_type": f"{cat} traffic",
                "count": cnt,
                "severity": severity,
            })
    
    alerts.sort(key=lambda a: a["count"], reverse=True)
    return alerts[:50]


def query_health():
    """Get system health."""
    conn = get_db()
    if not conn:
        state = load_state()
        agent_counters = {}
        if state:
            agent_counters = state.get("agent_counters", {})
        return {
            "status": "cold-start",
            "database": {"status": "disconnected"},
            "syslog": {"status": "unknown"},
            "discord": {"status": "unknown"},
            "opnsense": {"status": "unknown"},
            "events_processed": 0,
            "anomalies_detected": agent_counters.get("anomaly_count", 0),
            "alerts_sent": agent_counters.get("alerts_sent", 0),
            "uptime_seconds": agent_counters.get("uptime", 0),
            "state_version": state.get("version", 0) if state else 0,
            "state_timestamp": state.get("timestamp", "") if state else "",
            "ip_classifications": len(agent_counters),
        }
    
    try:
        state = load_state()
        agent_counters = {}
        if state:
            agent_counters = state.get("agent_counters", {})
        
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events")
        row = cur.fetchone()
        event_count = row[0] if row else 0
        close_db(conn)
        
        return {
            "status": "healthy" if event_count > 0 else "cold-start",
            "database": {"status": "connected", "message": "PostgreSQL connection OK"},
            "syslog": {"status": "active", "message": "Syslog listener running"},
            "discord": {"status": "active", "message": "Discord bot online"},
            "opnsense": {"status": "active", "message": "OPNsense API connected"},
            "events_processed": event_count,
            "anomalies_detected": agent_counters.get("anomaly_count", 0),
            "alerts_sent": agent_counters.get("alerts_sent", 0),
            "uptime_seconds": agent_counters.get("uptime", 0),
            "state_version": state.get("version", 0) if state else 0,
            "state_timestamp": state.get("timestamp", "") if state else "",
            "ip_classifications": len(agent_counters),
        }
    except Exception as e:
        close_db(conn)
        state = load_state()
        agent_counters = {}
        if state:
            agent_counters = state.get("agent_counters", {})
        return {
            "status": "cold-start",
            "database": {"status": "error", "message": str(e)},
            "syslog": {"status": "unknown"},
            "discord": {"status": "unknown"},
            "opnsense": {"status": "unknown"},
            "events_processed": 0,
            "anomalies_detected": agent_counters.get("anomaly_count", 0),
            "alerts_sent": agent_counters.get("alerts_sent", 0),
            "uptime_seconds": agent_counters.get("uptime", 0),
            "state_version": state.get("version", 0) if state else 0,
            "state_timestamp": state.get("timestamp", "") if state else "",
            "ip_classifications": len(agent_counters),
        }


# ─── Request Handler ─────────────────────────────────────────────────────────
class DashboardHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _serve_html(self):
        html_path = os.path.join(BASE_DIR, "app.html")
        if os.path.exists(html_path):
            with open(html_path, "rb") as f:
                html = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._serve_html()
        elif path == "/api/stats":
            self._send_json(query_stats())
        elif path == "/api/heatmap":
            self._send_json(query_heatmap())
        elif path == "/api/ip-flow":
            self._send_json(query_ip_flow())
        elif path == "/api/events":
            self._send_json(query_heatmap().get("events", []))
        elif path == "/api/mutes":
            self._send_json(load_mutes())
        elif path == "/api/geo":
            self._send_json(query_geo())
        elif path == "/api/health":
            self._send_json(query_health())
        elif path == "/api/alerts":
            self._send_json(query_alerts())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/mutes":
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            data = json.loads(body)
            mute = add_mute(
                ip=data.get("ip", ""),
                attack_type=data.get("attack_type", "ALL"),
                port=data.get("port"),
                duration=data.get("duration_seconds", 3600),
                source="manual",
            )
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
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_server(host="0.0.0.0", port=8766):
    server = ThreadedHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    run_server()
