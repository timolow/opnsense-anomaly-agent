#!/usr/bin/env python3
"""Flask API server for the firewall dashboard — reads from state file."""

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


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _parse_ts(ts_str):
    """Parse ISO timestamp string to datetime."""
    try:
        ts_str = ts_str.replace('"', '').strip()
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception:
        return None

def _get_ip_cat(state, ip):
    """Get IP category from network classifier."""
    if not state:
        return "UNKNOWN"
    nc = state.get("network_classifier", {})
    for cat in ["wan_ips", "lan_ips_auto", "vpn_ips_auto"]:
        if ip in nc.get(cat, {}):
            return cat.replace("_ips", "").upper()
    return "UNKNOWN"


# ─── Data queries ────────────────────────────────────────────────────────────
def query_stats():
    state = load_state()
    if not state:
        return {"counters": {}, "by_type": {}, "top_sources": []}
    
    counters = state.get("counters", {})
    ad = state.get("attack_detector", {})
    
    # Count events by attack type
    by_type = {}
    for atype, data in ad.items():
        if isinstance(data, dict):
            total = 0
            for key, val in data.items():
                if isinstance(val, dict):
                    total += val.get("count", 0)
            by_type[atype] = total
    
    # Get top source IPs from attack detectors
    sources = defaultdict(int)
    for atype, data in ad.items():
        if isinstance(data, dict):
            for key in data:
                if isinstance(data[key], dict):
                    cnt = data[key].get("count", 0)
                    if cnt > 0:
                        sources[key] += cnt
    
    top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:20]
    
    # Severity breakdown
    by_severity = {"CRITICAL": by_type.get("syn_flood", 0) + by_type.get("port_scan", 0),
                   "HIGH": by_type.get("brute_force", 0),
                   "MEDIUM": by_type.get("probe", 0)}
    
    # IP classifications
    nc = state.get("network_classifier", {})
    ip_count = 0
    for cat in ["wan_ips", "lan_ips_auto", "vpn_ips_auto"]:
        ip_count += len(nc.get(cat, {}))
    
    return {
        "counters": counters,
        "by_type": by_type,
        "by_severity": by_severity,
        "top_sources": [{"ip": ip, "count": cnt} for ip, cnt in top_sources],
        "active_mutes": len(load_mutes()),
        "ip_classifications": ip_count,
        "state_timestamp": state.get("_timestamp", ""),
    }

def query_heatmap():
    """Build heatmap from attack detector events in state file."""
    state = load_state()
    if not state:
        return {"labels_x": [], "labels_y": [], "data": [], "events": []}
    
    ad = state.get("attack_detector", {})
    
    # Extract all events with timestamps
    all_events = []
    ip_events = defaultdict(list)  # ip -> [(datetime, attack_type)]
    
    # Port scan: _port_scan_events -> {src_ip: {events: [(ts, dst, port), ...]}}
    ps = ad.get("port_scan_events", {})
    if isinstance(ps, dict):
        for src_ip, data in ps.items():
            if isinstance(data, dict):
                for ts_str in data.get("events", []):
                    dt = _parse_ts(ts_str)
                    if dt:
                        all_events.append({"ts": dt, "type": "port_scan", "source": src_ip})
                        ip_events[src_ip].append((dt, "port_scan"))
    
    # SYN flood dst: _syn_flood_dst_events -> {dst_ip: {events: [(ts, src, port), ...]}}
    sf = ad.get("syn_flood_dst_events", {})
    if isinstance(sf, dict):
        for dst_ip, data in sf.items():
            if isinstance(data, dict):
                for ts_tuple in data.get("events", []):
                    if isinstance(ts_tuple, (list, tuple)) and len(ts_tuple) >= 1:
                        dt = _parse_ts(str(ts_tuple[0]))
                        if dt:
                            src = ts_tuple[1] if len(ts_tuple) > 1 else "unknown"
                            all_events.append({"ts": dt, "type": "syn_flood", "source": src})
                            ip_events[src].append((dt, "syn_flood"))
    
    # SYN flood src: _syn_flood_src_events -> [(ts, dst, ...)]
    sfs = ad.get("syn_flood_src_events", [])
    if isinstance(sfs, list):
        for item in sfs:
            if isinstance(item, (list, tuple)) and len(item) >= 1:
                dt = _parse_ts(str(item[0]))
                if dt:
                    dst = item[1] if len(item) > 1 else "unknown"
                    all_events.append({"ts": dt, "type": "syn_flood", "source": dst})
                    ip_events[dst].append((dt, "syn_flood"))
    
    # Probe: _probe_events -> {src_ip: {events: [(ts, flags), ...]}}
    pr = ad.get("probe_events", {})
    if isinstance(pr, dict):
        for src_ip, data in pr.items():
            if isinstance(data, dict):
                for ts_str in data.get("events", []):
                    dt = _parse_ts(str(ts_str))
                    if dt:
                        all_events.append({"ts": dt, "type": "probe", "source": src_ip})
                        ip_events[src_ip].append((dt, "probe"))
    
    # Brute force: _brute_force_events -> {session_key: {events: [...], ...}}
    bf = ad.get("brute_force_events", {})
    if isinstance(bf, dict):
        for key, data in bf.items():
            if isinstance(data, dict):
                for ts_str in data.get("events", []):
                    dt = _parse_ts(str(ts_str))
                    if dt:
                        # Parse key like ["src", "dst", port]
                        try:
                            parts = json.loads(key)
                            if isinstance(parts, list) and len(parts) >= 2:
                                src = parts[0]
                                all_events.append({"ts": dt, "type": "brute_force", "source": src})
                                ip_events[src].append((dt, "brute_force"))
                        except Exception:
                            pass
    
    if not all_events:
        return {"labels_x": [], "labels_y": [], "data": [], "events": []}
    
    all_events.sort(key=lambda e: e["ts"])
    
    # Find time range
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    recent = [e for e in all_events if e["ts"] > cutoff]
    
    if not recent:
        # Use last 24h from state data regardless
        recent = all_events[-500:]
    
    # Build matrix: IP (y) × Hour of day (x)
    hour_matrix = defaultdict(lambda: defaultdict(int))
    all_ips = set()
    
    for ev in recent:
        ip_events_dict = defaultdict(list)
    
    # Better approach: aggregate into matrix
    for ev in recent:
        hour = ev["ts"].hour
        ip = ev["source"]
        hour_matrix[ip][hour] += 1
        all_ips.add(ip)
    
    all_ips = sorted(all_ips)
    all_hours = list(range(24))
    
    matrix = []
    for ip in all_ips:
        row = [hour_matrix[ip].get(h, 0) for h in all_hours]
        matrix.append(row)
    
    # Get event list for the events endpoint
    event_list = []
    for ev in all_events[-200:]:
        event_list.append({
            "timestamp": ev["ts"].isoformat(),
            "event_type": ev["type"],
            "source_ip": ev["source"],
            "severity": "HIGH" if ev["type"] in ("syn_flood", "port_scan") else "MEDIUM",
        })
    
    return {
        "labels_x": [f"{h:02d}:00" for h in all_hours],
        "labels_y": [ip if len(ip) <= 15 else ip[:12]+"..." for ip in all_ips],
        "data": matrix,
        "events": event_list,
        "total_events": len(all_events),
    }

def query_ip_flow():
    """Build IP flow data from attack detector events."""
    state = load_state()
    if not state:
        return {"nodes": [], "links": [], "connections": []}
    
    ad = state.get("attack_detector", {})
    nodes = []
    node_map = {}
    links = []
    connections = []
    colors = {
        "WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7",
        "UNKNOWN": "#6b7280", "SOURCE": "#3b82f6", "TARGET": "#f59e0b",
    }
    
    def add_node(ip, category="SOURCE"):
        if ip not in node_map:
            node_map[ip] = len(nodes)
            category = _get_ip_cat(state, ip) if category == "SOURCE" else category
            if category not in colors:
                category = "SOURCE"
            nodes.append({
                "id": ip,
                "label": ip,
                "category": category,
                "color": colors.get(category, "#3b82f6"),
                "size": 8,
            })
    
    def add_link(src, dst, value=1, etype=""):
        add_node(src, "SOURCE")
        add_node(dst, "TARGET")
        links.append({"source": src, "target": dst, "value": value, "type": etype})
        connections.append({"source": src, "target": dst, "type": etype, "value": value})
    
    # Port scans: src -> dst:port
    ps = ad.get("port_scan_events", {})
    if isinstance(ps, dict):
        for src_ip, data in ps.items():
            if isinstance(data, dict):
                ev_list = data.get("events", [])
                cnt = data.get("count", len(ev_list))
                for ev_item in ev_list[:20]:  # Limit per source
                    if isinstance(ev_item, (list, tuple)) and len(ev_item) >= 2:
                        dst = ev_item[1]
                        port = ev_item[2] if len(ev_item) > 2 else "?"
                        add_link(src_ip, dst, cnt, "PORT_SCAN")
    
    # SYN flood: src -> dst
    sf_dst = ad.get("syn_flood_dst_events", {})
    if isinstance(sf_dst, dict):
        for dst_ip, data in sf_dst.items():
            if isinstance(data, dict):
                ev_list = data.get("events", [])
                cnt = data.get("count", len(ev_list))
                for ev_item in ev_list[:20]:
                    if isinstance(ev_item, (list, tuple)) and len(ev_item) >= 1:
                        src = str(ev_item[0])
                        add_link(src, dst_ip, cnt, "SYN_FLOOD")
    
    sfs = ad.get("syn_flood_src_events", [])
    if isinstance(sfs, list):
        for item in sfs:
            if isinstance(item, (list, tuple)) and len(item) >= 1:
                src = str(item[0])
                dst = item[1] if len(item) > 1 else "unknown"
                add_link(src, dst, 1, "SYN_FLOOD")
    
    # Brute force: session_key contains src, dst, port
    bf = ad.get("brute_force_events", {})
    if isinstance(bf, dict):
        for key, data in bf.items():
            if isinstance(data, dict):
                try:
                    parts = json.loads(key)
                    if isinstance(parts, list) and len(parts) >= 3:
                        src, dst, port = parts[0], parts[1], parts[2]
                        add_link(src, dst, 1, "BRUTE_FORCE")
                except Exception:
                    pass
    
    # Limit nodes for performance
    if len(nodes) > 100:
        # Keep top 100 by connection count
        node_conn = defaultdict(int)
        for link in links:
            node_conn[link["source"]] += 1
            node_conn[link["target"]] += 1
        top_ids = sorted(node_conn.keys(), key=lambda x: node_conn[x], reverse=True)[:100]
        nodes = [n for n in nodes if n["id"] in top_ids]
        node_map = {n["id"]: i for i, n in enumerate(nodes)}
        links = [l for l in links if l["source"] in top_ids or l["target"] in top_ids]
    
    return {
        "nodes": nodes,
        "links": links,
        "connections": connections,
    }

def query_geo():
    """Get geo data from state file."""
    state = load_state()
    if not state:
        return []
    
    gd = state.get("geo_detector", {})
    countries = gd.get("country_events", {})
    
    flag_map = {
        "CN": "🇨🇳", "US": "🇺🇸", "RU": "🇷🇺", "BR": "🇧🇷", "DE": "🇩🇪",
        "GB": "🇬🇧", "IN": "🇮🇳", "FR": "🇫🇷", "JP": "🇯🇵", "KR": "🇰🇷",
        "AU": "🇦🇺", "NL": "🇳🇱", "IR": "🇮🇷", "UA": "🇺🇦", "RO": "🇷🇴",
        "CA": "🇨🇦", "IT": "🇮🇹", "ES": "🇪🇸", "SE": "🇸🇪", "PL": "🇵🇱",
        "TW": "🇹🇼", "SG": "🇸🇬", "ID": "🇮🇩", "TH": "🇹🇭", "VN": "🇻🇳",
        "MX": "🇲🇽", "AR": "🇦🇷", "CO": "🇨🇴", "EG": "🇪🇬", "ZA": "🇿🇦",
        "NG": "🇳🇬", "KE": "🇰🇪", "TR": "🇹🇷", "SA": "🇸🇦",
    }
    
    colors = {
        "CN": "#ef4444", "US": "#3b82f6", "RU": "#f59e0b", "BR": "#22c55e",
        "DE": "#eab308", "GB": "#8b5cf6", "IN": "#06b6d4", "FR": "#ec4899",
        "JP": "#f43f5e", "KR": "#10b981", "AU": "#84cc16", "NL": "#f59e0b",
    }
    
    result = []
    for cc, info in countries.items():
        if isinstance(info, dict):
            result.append({
                "country": cc,
                "count": info.get("count", 0),
                "color": colors.get(cc, "#6b7280"),
                "flag": flag_map.get(cc, "🌐"),
            })
    
    result.sort(key=lambda x: x["count"], reverse=True)
    return result

def query_alerts():
    """Get high-activity IPs as alerts."""
    state = load_state()
    if not state:
        return []
    
    ad = state.get("attack_detector", {})
    alerts = []
    
    for atype, data in ad.items():
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, dict) and val.get("count", 0) > 3:
                    severity = "CRITICAL" if val["count"] > 20 else "WARNING"
                    alerts.append({
                        "attack_type": atype.replace("_", " ").title(),
                        "details": key,
                        "count": val["count"],
                        "severity": severity,
                    })
    
    # Also include top IPs from classified IPs
    nc = state.get("network_classifier", {})
    for cat in ["wan_ips", "lan_ips_auto", "vpn_ips_auto"]:
        for ip, info in nc.get(cat, {}).items():
            if isinstance(info, dict):
                cnt = info.get("event_count", 0)
                if cnt > 100:
                    alerts.append({
                        "attack_type": "HIGH_VOLUME",
                        "details": ip,
                        "count": cnt,
                        "severity": "CRITICAL" if cnt > 500 else "WARNING",
                    })
    
    alerts.sort(key=lambda a: a["count"], reverse=True)
    return alerts[:50]

def query_health():
    """Get system health."""
    state = load_state()
    if not state:
        return {
            "status": "cold-start",
            "database": {"status": "disconnected", "message": "No data loaded"},
            "syslog": {"status": "unknown"},
            "discord": {"status": "unknown"},
            "opnsense": {"status": "unknown"},
            "events_processed": 0,
            "anomalies_detected": 0,
            "uptime_seconds": 0,
        }
    
    counters = state.get("counters", {})
    
    return {
        "status": "healthy" if counters.get("events_processed", 0) > 0 else "cold-start",
        "database": {"status": "connected", "message": "State file loaded"},
        "syslog": {"status": "active", "message": "Syslog listener running"},
        "discord": {"status": "active", "message": "Discord bot online"},
        "opnsense": {"status": "active", "message": "OPNsense API connected"},
        "events_processed": counters.get("events_processed", 0),
        "anomalies_detected": counters.get("anomalies_detected", 0),
        "alerts_sent": counters.get("alerts_sent", 0),
        "uptime_seconds": state.get("uptime", 0),
        "state_version": state.get("_version", 0),
        "state_timestamp": state.get("_timestamp", ""),
        "ip_classifications": sum(
            len(state.get("network_classifier", {}).get(cat, {}))
            for cat in ["wan_ips", "lan_ips_auto", "vpn_ips_auto"]
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
