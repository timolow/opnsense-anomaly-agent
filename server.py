#!/usr/bin/env python3
"""Flask API server for the firewall dashboard."""

import json
import os
import time
import threading
from datetime import datetime, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import socketserver

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE_DIR, "agent_data", "state.json")
MUTES_PATH = os.path.join(BASE_DIR, "agent_data", "mutes.json")
DATA_DIR = os.path.join(BASE_DIR, "agent_data")

# ─── Mutes ───────────────────────────────────────────────────────────────────

def load_mutes():
    """Load mutes from disk."""
    if os.path.exists(MUTES_PATH):
        try:
            with open(MUTES_PATH) as f:
                data = json.load(f)
            now = datetime.now(timezone.utc)
            # Remove expired mutes
            active = []
            for m in data:
                exp = datetime.fromisoformat(m["expires"])
                if exp > now:
                    active.append(m)
            if len(active) < len(data):
                save_mutes(active)
            return active
        except Exception:
            return []
    return []

def save_mutes(mutes):
    """Save mutes to disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(MUTES_PATH, "w") as f:
        json.dump(mutes, f, indent=2, default=str)

def add_mute(ip, attack_type, port=None, duration=3600, source="manual"):
    """Add a new mute."""
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
    """Remove a mute by ID."""
    mutes = load_mutes()
    mutes = [m for m in mutes if m["id"] != mute_id]
    save_mutes(mutes)

def is_muted(ip):
    """Check if an IP is currently muted."""
    mutes = load_mutes()
    now = datetime.now(timezone.utc)
    for m in mutes:
        if m["ip"] == ip:
            try:
                exp = datetime.fromisoformat(m["expires"])
                if exp > now:
                    return True
            except Exception:
                pass
    return False

# ─── State loading ───────────────────────────────────────────────────────────

def load_state():
    """Load agent state from JSON."""
    if not os.path.exists(STATE_PATH):
        return None
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return None

def get_heatmap_data():
    """Generate heatmap data from state file."""
    state = load_state()
    if not state:
        return {"labels_x": [], "labels_y": [], "data": []}

    # Aggregate events by source IP and time bucket
    buckets = defaultdict(lambda: defaultdict(int))
    
    # Try to extract from attack_detector events
    attack_data = state.get("attack_detector", {})
    
    # Port scan events (src_ip -> [(timestamp, dst, port)])
    ps_events = attack_data.get("port_scan_events", {})
    for src_ip, events in ps_events.items():
        for ts_str, dst, port in events:
            try:
                ts = datetime.fromisoformat(ts_str)
                hour = ts.hour
                buckets[src_ip[:8] + "..."][hour] += 1
            except Exception:
                pass
    
    # SYN flood events
    sf_dst = attack_data.get("syn_flood_dst_events", {})
    for dst_ip, data in sf_dst.items():
        for ts_tuple in data.get("events", []):
            try:
                ts = datetime.fromisoformat(ts_tuple[0])
                hour = ts.hour
                # Use dst_ip as key
                key = dst_ip[:8] + "..."
                buckets[key][hour] += 1
            except Exception:
                pass
    
    # Probe events
    pr_events = attack_data.get("probe_events", {})
    for src_ip, events in pr_events.items():
        for ts_str, flags in events:
            try:
                ts = datetime.fromisoformat(ts_str)
                hour = ts.hour
                buckets[src_ip[:8] + "..."][hour] += 1
            except Exception:
                pass
    
    # Build matrix
    all_ips = sorted(buckets.keys())
    all_hours = sorted(set().union(*[b.keys() for b in buckets.values()])) if buckets else list(range(24))
    
    data = []
    for ip in all_ips:
        row = []
        for hour in all_hours:
            row.append(buckets[ip].get(hour, 0))
        data.append(row)
    
    return {
        "labels_x": [f"{h:02d}:00" for h in all_hours],
        "labels_y": all_ips,
        "data": data,
    }

def get_ip_flow_data():
    """Generate IP flow data from state file."""
    state = load_state()
    if not state:
        return {"nodes": [], "links": []}
    
    nodes = []
    links = []
    node_map = {}
    
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    
    # Build nodes from classified IPs
    categories = {"WAN": 0, "LAN": 1, "VPN": 2, "UNKNOWN": 3}
    colors = {"WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7", "UNKNOWN": "#6b7280"}
    
    for ip, info in ip_data.items():
        if ip in node_map:
            continue
        node_map[ip] = len(nodes)
        nodes.append({
            "id": ip,
            "label": ip,
            "category": info.get("category", "UNKNOWN"),
            "color": colors.get(info.get("category", "UNKNOWN"), "#6b7280"),
            "size": min(10 + info.get("event_count", 0) / 10, 30),
        })
    
    # Generate synthetic links from attack detector data
    attack_data = state.get("attack_detector", {})
    ps_events = attack_data.get("port_scan_events", {})
    
    for src_ip, events in ps_events.items():
        if src_ip not in node_map:
            node_map[src_ip] = len(nodes)
            nodes.append({
                "id": src_ip,
                "label": src_ip,
                "category": "UNKNOWN",
                "color": "#6b7280",
                "size": 8,
            })
        for _, dst, port in events:
            if dst not in node_map:
                node_map[dst] = len(nodes)
                nodes.append({
                    "id": dst,
                    "label": dst,
                    "category": "TARGET",
                    "color": "#f59e0b",
                    "size": 6,
                })
            links.append({
                "source": src_ip,
                "target": dst,
                "value": 1,
                "type": "PORT_SCAN",
            })
    
    # Limit to top 50 nodes for performance
    if len(nodes) > 50:
        sorted_nodes = sorted(nodes, key=lambda n: n["size"], reverse=True)
        top_ids = {n["id"] for n in sorted_nodes[:50]}
        nodes = [n for n in nodes if n["id"] in top_ids]
        links = [l for l in links if l["source"] in top_ids or l["target"] in top_ids]
    
    return {"nodes": nodes, "links": links}

def get_geo_data():
    """Get country-level stats."""
    state = load_state()
    if not state:
        return []
    
    geo = state.get("geo_detector", {})
    countries = geo.get("country_events", {})
    
    # Country flag colors (approximate)
    colors = {
        "CN": "#ef4444", "US": "#3b82f6", "RU": "#f97316", "BR": "#22c55e",
        "DE": "#eab308", "GB": "#8b5cf6", "IN": "#06b6d4", "FR": "#ec4899",
        "JP": "#f43f5e", "KR": "#10b981", "AU": "#84cc16", "NL": "#f59e0b",
        "IR": "#dc2626", "UA": "#2563eb", "RO": "#7c3aed",
    }
    
    result = []
    for cc, info in countries.items():
        if isinstance(info, dict):
            result.append({
                "country": cc,
                "count": info.get("count", 0),
                "color": colors.get(cc, "#6b7280"),
            })
    
    result.sort(key=lambda x: x["count"], reverse=True)
    return result

def get_health_data():
    """Get system health status."""
    state = load_state()
    if not state:
        return {
            "status": "unknown",
            "database": {"status": "disconnected", "message": "No data loaded"},
            "syslog": {"status": "unknown", "message": "Cannot determine"},
            "discord": {"status": "unknown", "message": "Cannot determine"},
            "opnsense": {"status": "unknown", "message": "Cannot determine"},
        }
    
    counters = state.get("counters", {})
    uptime = state.get("uptime", 0)
    
    return {
        "status": "healthy" if counters.get("events_processed", 0) > 0 else "cold-start",
        "events_processed": counters.get("events_processed", 0),
        "anomalies_detected": counters.get("anomalies_detected", 0),
        "alerts_sent": counters.get("alerts_sent", 0),
        "uptime_seconds": uptime,
        "last_state_save": state.get("_timestamp", ""),
        "state_version": state.get("_version", 0),
        "ip_classifications": len(state.get("network_classifier", {}).get("ip_data", {})),
    }


# ─── Request Handler ─────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

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
            self._handle_stats()
        elif path == "/api/heatmap":
            self._handle_heatmap()
        elif path == "/api/ip-flow":
            self._handle_ip_flow()
        elif path == "/api/events":
            self._handle_events()
        elif path == "/api/mutes":
            self._handle_get_mutes()
        elif path == "/api/geo":
            self._handle_geo()
        elif path == "/api/health":
            self._handle_health()
        elif path == "/api/alerts":
            self._handle_alerts()
        elif path == "/dashboard.css":
            self._serve_css()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/mutes":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)
            mute = add_mute(
                ip=data.get("ip", ""),
                attack_type=data.get("attack_type", "ALL"),
                port=data.get("port"),
                duration=data.get("duration_seconds", 3600),
                source="manual",
            )
            self._send_json(mute, 201)
        elif self.path.startswith("/api/alerts/ack"):
            self._send_json({"ok": True})
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

    def _serve_html(self):
        """Serve the dashboard HTML."""
        html_path = os.path.join(BASE_DIR, "app.html")
        if not os.path.exists(html_path):
            self._send_json({"error": "app.html not found"}, 500)
            return
        with open(html_path) as f:
            html = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_css(self):
        """Serve the dashboard CSS."""
        css_path = os.path.join(BASE_DIR, "app.css")
        if os.path.exists(css_path):
            with open(css_path) as f:
                css = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.end_headers()
            self.wfile.write(css.encode())
        else:
            self._send_json({"error": "app.css not found"}, 404)

    def _handle_stats(self):
        """Handle /api/stats endpoint."""
        state = load_state()
        mutes = load_mutes()
        health = get_health_data()
        
        # Get geo data
        geo = get_geo_data()
        top_countries = [g["country"] for g in geo[:5]]
        
        # Count attack types from attack_detector
        attack_types = defaultdict(int)
        if state:
            for key in state.get("attack_detector", {}):
                if isinstance(state["attack_detector"][key], dict):
                    for ip_key, ip_data in state["attack_detector"][key].items():
                        if isinstance(ip_data, dict) and "count" in ip_data:
                            # Count based on data present
                            pass
        
        self._send_json({
            "counters": state.get("counters", {}),
            "health": health,
            "top_countries": top_countries,
            "active_mutes": len(mutes),
            "ip_classifications": len(geo),
        })

    def _handle_heatmap(self):
        """Handle /api/heatmap endpoint."""
        data = get_heatmap_data()
        self._send_json(data)

    def _handle_ip_flow(self):
        """Handle /api/ip-flow endpoint."""
        data = get_ip_flow_data()
        self._send_json(data)

    def _handle_events(self):
        """Handle /api/events endpoint."""
        limit = int(self.headers.get("X-Event-Limit", 50))
        state = load_state()
        if not state:
            self._send_json([])
            return
        
        alerts = []
        attack_data = state.get("attack_detector", {})
        for attack_type, data in attack_data.items():
            if isinstance(data, dict):
                for key, info in data.items():
                    if isinstance(info, dict) and "events" in info:
                        # Count events
                        count = info.get("count", 0)
                        if count > 0:
                            alerts.append({
                                "attack_type": attack_type.replace("_", " ").title(),
                                "details": key[:20],
                                "count": count,
                                "severity": "HIGH" if count > 10 else "MEDIUM",
                            })
        
        self._send_json(alerts[:limit])

    def _handle_get_mutes(self):
        """Handle GET /api/mutes endpoint."""
        mutes = load_mutes()
        self._send_json(mutes)

    def _handle_geo(self):
        """Handle /api/geo endpoint."""
        data = get_geo_data()
        self._send_json(data)

    def _handle_health(self):
        """Handle /api/health endpoint."""
        data = get_health_data()
        self._send_json(data)

    def _handle_alerts(self):
        """Handle /api/alerts endpoint."""
        state = load_state()
        if not state:
            self._send_json([])
            return
        
        alerts = []
        nc = state.get("network_classifier", {})
        ip_data = nc.get("ip_data", {})
        
        # Find high-activity IPs
        for ip, info in ip_data.items():
            if isinstance(info, dict):
                event_count = info.get("event_count", 0)
                if event_count > 50:
                    alerts.append({
                        "ip": ip,
                        "event_count": event_count,
                        "category": info.get("category", "UNKNOWN"),
                        "severity": "CRITICAL" if event_count > 200 else "WARNING",
                    })
        
        alerts.sort(key=lambda a: a["event_count"], reverse=True)
        self._send_json(alerts)

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for concurrent requests."""
    allow_reuse_address = True
    daemon_threads = True


def run_server(host="0.0.0.0", port=8766):
    """Start the dashboard server."""
    server = ThreadedHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    run_server()
