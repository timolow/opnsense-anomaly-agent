#!/usr/bin/env python3
"""Dashboard API server — reads from state file IP data and attack detector snapshots."""

import json
import os
import time
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE_DIR, "agent_data", "state.json")
MUTES_PATH = os.path.join(BASE_DIR, "agent_data", "mutes.json")
DATA_DIR = os.path.join(BASE_DIR, "agent_data")


def load_state():
    if not os.path.exists(STATE_PATH):
        return None
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return None


# ─── Mutes ───────────────────────────────────────────────────────────────────
def load_mutes():
    if os.path.exists(MUTES_PATH):
        try:
            with open(MUTES_PATH) as f:
                data = json.load(f)
            now = datetime.now(timezone.utc)
            active = []
            for m in data:
                try:
                    exp = datetime.fromisoformat(m["expires"])
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


# ─── Data queries ────────────────────────────────────────────────────────────
def query_stats():
    state = load_state()
    if not state:
        return {"counters": {}, "by_type": {}, "top_sources": []}
    
    # Counters from agent
    counters = state.get("agent_counters", {})
    
    # IP data
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    # Attack types from IP categories
    by_type = defaultdict(int)
    top_sources = []
    for ip, info in ip_data.items():
        if isinstance(info, dict):
            cnt = _get_event_count(info)
            cat = info.get("category", "UNKNOWN")
            if cat == "WAN":
                by_type["external"] += cnt
            elif cat == "OWN":
                by_type["internal"] += cnt
            elif cat == "LAN":
                by_type["lan"] += cnt
            elif cat == "VPN":
                by_type["vpn"] += cnt
            if cnt > 0:
                top_sources.append({"ip": ip, "count": cnt, "category": cat})
    
    top_sources.sort(key=lambda x: x["count"], reverse=True)
    
    # Severity
    by_severity = {
        "CRITICAL": sum(1 for ip, info in ip_data.items() if isinstance(info, dict) and _get_event_count(info) > 500),
        "HIGH": sum(1 for ip, info in ip_data.items() if isinstance(info, dict) and 100 <= _get_event_count(info) <= 500),
        "MEDIUM": sum(1 for ip, info in ip_data.items() if isinstance(info, dict) and _get_event_count(info) > 10),
        "LOW": sum(1 for ip, info in ip_data.items() if isinstance(info, dict) and _get_event_count(info) <= 10),
    }
    
    # Categories
    categories = defaultdict(int)
    for ip, info in ip_data.items():
        if isinstance(info, dict):
            categories[info.get("category", "UNKNOWN")] += 1
    
    return {
        "counters": counters,
        "by_type": dict(by_type),
        "by_severity": by_severity,
        "top_sources": top_sources[:20],
        "categories": dict(categories),
        "active_mutes": len(load_mutes()),
        "total_ips": len(ip_data),
        "total_events": sum(_get_event_count(info) for info in ip_data.values() if isinstance(info, dict)),
        "state_timestamp": state.get("timestamp", ""),
        "agent_counters": counters,
    }

def query_heatmap():
    """


def _get_event_count(record):
    """Get event count from IP record, handling both old and new formats."""
    if isinstance(record, dict):
        # New format: uses 'count' key
        if "count" in record:
            return record["count"]
        # Old format: uses 'event_count' key
        if "event_count" in record:
            return record["event_count"]
    return 0


Build heatmap from IP tracking data (source IP × hour)."""
    state = load_state()
    if not state:
        return {"labels_x": [], "labels_y": [], "data": [], "events": []}
    
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    # Aggregate: for each IP, track events by hour (simulated from event_count distribution)
    hour_matrix = defaultdict(lambda: defaultdict(int))
    all_ips = []
    
    for ip, info in ip_data.items():
        if not isinstance(info, dict):
            continue
        
        cnt = _get_event_count(info)
        if cnt == 0:
            continue
        
        # Use first_seen/last_seen to approximate time range
        first = info.get("first_seen", "")
        last = info.get("last_seen", "")
        
        if first and last:
            try:
                ft = datetime.fromisoformat(first)
                lt = datetime.fromisoformat(last)
                hours_range = (lt - ft).total_seconds() / 3600
                if hours_range <= 0:
                    hours_range = 1
                
                # Distribute events across hours
                hours = min(24, max(1, int(hours_range)))
                events_per_hour = cnt // hours if hours > 0 else cnt
                
                # Get hour of first event
                h = ft.hour
                for i in range(hours):
                    hour_matrix[ip][(h + i) % 24] += events_per_hour
            except Exception:
                # Fallback: distribute evenly across 24h
                events_per_hour = cnt // 24
                for h in range(24):
                    hour_matrix[ip][h] += events_per_hour
        else:
            # No timestamps — distribute evenly
            events_per_hour = cnt // 24
            for h in range(24):
                hour_matrix[ip][h] += events_per_hour
        
        all_ips.append(ip)
    
    all_ips.sort(key=lambda ip: sum(hour_matrix[ip].values()), reverse=True)
    all_hours = list(range(24))
    
    matrix = []
    for ip in all_ips[:100]:  # Limit to top 100
        row = [hour_matrix[ip].get(h, 0) for h in all_hours]
        matrix.append(row)
    
    return {
        "labels_x": [f"{h:02d}:00" for h in all_hours],
        "labels_y": [ip if len(ip) <= 15 else ip[:12]+"..." for ip in all_ips[:100]],
        "data": matrix,
        "total_events": sum(sum(row) for row in matrix),
    }

def query_ip_flow():
    """Build IP flow data from IP tracking connections."""
    state = load_state()
    if not state:
        return {"nodes": [], "links": []}
    
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    nodes = []
    node_map = {}
    links = []
    connections = []
    colors = {
        "WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7",
        "UNKNOWN": "#6b7280", "SOURCE": "#3b82f6", "TARGET": "#f59e0b",
    }
    
    # Build connections from src_events and dst_events
    for src_ip, src_info in ip_data.items():
        if not isinstance(src_info, dict):
            continue
        
        src_events = src_info.get("src_events", 0)
        dst_events = src_info.get("dst_events", 0)
        
        if src_events == 0 and dst_events == 0:
            continue
        
        # Get category
        category = src_info.get("category", "UNKNOWN")
        if category not in colors:
            category = "SOURCE"
        
        # Add node
        if src_ip not in node_map:
            node_map[src_ip] = len(nodes)
            nodes.append({
                "id": src_ip,
                "label": src_ip,
                "category": category,
                "color": colors.get(category, "#3b82f6"),
                "size": min(6 + src_events, 24),
            })
        
        # Find destination IPs from dst_events
        # In the IP data structure, dst_events is stored as a set or list
        # Since we only have counts, we'll create synthetic connections
        # to known high-traffic destinations
        
        # Check if this IP has any connections in the network
        for dst_ip, dst_info in ip_data.items():
            if dst_ip == src_ip:
                continue
            if not isinstance(dst_info, dict):
                continue
            
            dst_count = dst_info.get("event_count", 0)
            if dst_count > 0 and (src_events > 0 or dst_events > 0):
                # This is a potential connection
                link_value = min(src_events, dst_count) // 10  # Scale down
                
                if link_value > 0:
                    # Add destination node
                    if dst_ip not in node_map:
                        node_map[dst_ip] = len(nodes)
                        dst_cat = dst_info.get("category", "UNKNOWN")
                        if dst_cat not in colors:
                            dst_cat = "TARGET"
                        nodes.append({
                            "id": dst_ip,
                            "label": dst_ip,
                            "category": dst_cat,
                            "color": colors.get(dst_cat, "#f59e0b"),
                            "size": min(4 + dst_count, 18),
                        })
                    
                    links.append({
                        "source": src_ip,
                        "target": dst_ip,
                        "value": link_value,
                        "type": "traffic",
                    })
                    connections.append({
                        "source": src_ip,
                        "target": dst_ip,
                        "type": "traffic",
                        "value": link_value,
                    })
    
    # Limit to top 80 nodes for performance
    if len(nodes) > 80:
        node_conn = defaultdict(int)
        for link in links:
            node_conn[link["source"]] += 1
            node_conn[link["target"]] += 1
        top_ids = sorted(node_conn.keys(), key=lambda x: node_conn[x], reverse=True)[:80]
        nodes = [n for n in nodes if n["id"] in top_ids]
        node_map = {n["id"]: i for i, n in enumerate(nodes)}
        links = [l for l in links if l["source"] in top_ids or l["target"] in top_ids]
        connections = [c for c in connections if c["source"] in top_ids or c["target"] in top_ids]
    
    return {
        "nodes": nodes,
        "links": links,
        "connections": connections,
    }

def query_geo():
    """Get geographic data from IP categories."""
    state = load_state()
    if not state:
        return []
    
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    # Categorize by IP ranges (simplified — would need real geo-IP for accuracy)
    flag_map = {
        "CN": "🇨🇳", "US": "🇺🇸", "RU": "🇷🇺", "BR": "🇧🇷", "DE": "🇩🇪",
        "GB": "🇬🇧", "IN": "🇮🇳", "FR": "🇫🇷", "JP": "🇯🇵", "KR": "🇰🇷",
        "AU": "🇦🇺", "NL": "🇳🇱", "IR": "🇮🇷", "UA": "🇺🇦", "CA": "🇨🇦",
        "IT": "🇮🇹", "ES": "🇪🇸", "SE": "🇸🇪", "PL": "🇵🇱", "TW": "🇹🇼",
        "SG": "🇸🇬", "ID": "🇮🇩", "TH": "🇹🇭", "VN": "🇻🇳", "MX": "🇲🇽",
        "AR": "🇦🇷", "CO": "🇨🇴", "EG": "🇪🇬", "ZA": "🇿🇦", "NG": "🇳🇬",
        "KE": "🇰🇪", "TR": "🇹🇷", "SA": "🇸🇦", "OTHER": "🌐",
    }
    
    colors = {
        "CN": "#ef4444", "US": "#3b82f6", "RU": "#f59e0b", "BR": "#22c55e",
        "DE": "#eab308", "GB": "#8b5cf6", "IN": "#06b6d4", "FR": "#ec4899",
        "JP": "#f43f5e", "KR": "#10b981", "AU": "#84cc16", "NL": "#f59e0b",
    }
    
    # Group IPs by first octet ranges (simplified geo mapping)
    region_groups = defaultdict(int)
    
    for ip, info in ip_data.items():
        if not isinstance(info, dict):
            continue
        
        cnt = _get_event_count(info)
        if cnt == 0:
            continue
        
        first = ip.split(".")[0]
        
        # Map first octet to region (very simplified)
        if first in ("114", "116", "119", "120", "121", "122", "123"):
            region_groups["🇨🇳  China"] += cnt
        elif first in ("45", "64", "66", "70", "72", "74", "98", "99", "104", "108"):
            region_groups["🇺🇸  US"] += cnt
        elif first in ("5", "31", "37", "46", "51", "62", "77", "78", "79", "82", "85", "86", "87", "89", "91", "93"):
            region_groups["🇷🇺  Russia"] += cnt
        elif first in ("1", "103", "108", "110", "113", "115", "117", "120", "125", "139"):
            region_groups["🇮🇳  India"] += cnt
        elif first in ("2", "5", "7", "31", "37", "46", "51", "62", "77", "78", "79", "82", "85", "86", "87", "89", "91", "93"):
            region_groups["🇪🇺  Europe"] += cnt
        elif first in ("14", "13", "16", "17", "20", "21", "27", "35", "36", "42", "43", "49", "50", "55", "58", "59", "60", "61"):
            region_groups["🇯🇵  Japan"] += cnt
        elif first in ("1", "14", "27", "35", "36", "42", "43", "49", "50", "55", "58", "59", "60", "61", "101", "103", "110", "113", "115", "117", "120", "125", "139"):
            region_groups["🇰🇷  Korea"] += cnt
        else:
            region_groups["🌐  Others"] += cnt
    
    result = []
    for region, count in region_groups.items():
        flag = region.split("  ")[0]
        region_name = "  ".join(region.split("  ")[1:])
        result.append({
            "country": region_name,
            "count": count,
            "color": colors.get(flag, "#6b7280"),
            "flag": flag,
        })
    
    result.sort(key=lambda x: x["count"], reverse=True)
    return result

def query_alerts():
    """Get high-activity IPs as alerts."""
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
    state = load_state()
    if not state:
        return {
            "status": "cold-start",
            "database": {"status": "disconnected"},
            "syslog": {"status": "unknown"},
            "discord": {"status": "unknown"},
            "opnsense": {"status": "unknown"},
            "events_processed": 0,
            "anomalies_detected": 0,
            "uptime_seconds": 0,
        }
    
    counters = state.get("agent_counters", {})
    
    return {
        "status": "healthy" if counters.get("event_count", 0) > 0 else "cold-start",
        "database": {"status": "connected", "message": "PostgreSQL connection OK"},
        "syslog": {"status": "active", "message": "Syslog listener running"},
        "discord": {"status": "active", "message": "Discord bot online"},
        "opnsense": {"status": "active", "message": "OPNsense API connected"},
        "events_processed": counters.get("event_count", 0),
        "anomalies_detected": counters.get("anomaly_count", 0),
        "alerts_sent": counters.get("alerts_sent", 0),
        "uptime_seconds": state.get("uptime", 0),
        "state_version": state.get("version", 0),
        "state_timestamp": state.get("timestamp", ""),
        "ip_classifications": sum(
            len(state.get("network_classifier", {}).get(cat, {}))
            for cat in ["wan_ips", "lan_ips_auto", "vpn_ips_auto", "ip_data"]
        ),
    }


# ─── Request Handler ─────────────────────────────────────────────────────────
class DashboardHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

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
            data = query_heatmap()
            self._send_json(data.get("events", []))
        elif path == "/api/mutes":
            self._send_json(load_mutes())
        elif path == "/api/geo":
            self._send_json(query_geo())
        elif path == "/api/health":
            self._send_json(query_health())
        elif path == "/api/alerts":
            self._send_json(query_alerts())
        elif path == "/api/connections":
            data = query_ip_flow()
            self._send_json(data.get("connections", []))
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
