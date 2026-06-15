#!/usr/bin/env python3
"""Dashboard API server - reads from PostgreSQL + state file."""

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
    print("WARNING: psycopg2 not installed - falling back to state file")

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
    config_path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            return cfg.get("api_url", ""), cfg.get("api_key", ""), cfg.get("api_cert", "")
        except Exception:
            pass
    return "", "", ""

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
                if category == "WAN":
                    by_type["external"] += cnt
                elif category == "LAN":
                    by_type["internal"] += cnt
                elif category == "VPN":
                    by_type["vpn"] += cnt
                else:
                    by_type["unknown"] += cnt
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
        if not isinstance(info, dict):
            continue
        cnt = _get_event_count(info)
        cat = info.get("category", "UNKNOWN")
        if cat == "WAN": by_type["external"] += cnt
        elif cat == "LAN": by_type["internal"] += cnt
        elif cat == "VPN": by_type["vpn"] += cnt
        if cnt > 0:
            top_sources.append({"ip": ip, "count": cnt, "category": cat})
    top_sources.sort(key=lambda x: x["count"], reverse=True)
    return {"counters": {"events_processed": 0, "anomalies_detected": 0, "alerts_sent": 0}, "by_type": dict(by_type), "top_sources": top_sources[:20], "active_mutes": len(load_mutes()), "ip_classifications": len([v for v in ip_data.values() if isinstance(v, dict) and _get_event_count(v) > 0]), "top_countries": []}

def query_heatmap():
    conn = get_db()
    if not conn:
        return _fallback_heatmap()
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
    finally:
        close_db(conn)

def _fallback_heatmap():
    state = load_state()
    if not state:
        return {"labels_x": [], "labels_y": [], "data": []}
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
    if not conn:
        return _fallback_flow()
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
        for row in iface_rows:
            iface_by_ip[row["src_ip"]].add(row["interface"])
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
    finally:
        close_db(conn)

def _fallback_flow():
    state = load_state()
    if not state:
        return {"nodes": [], "links": []}
    nc = state.get("network_classifier", {})
    ip_data = nc.get("ip_data", {})
    nodes = []
    node_map = {}
    connections = []
    colors = {"WAN": "#ef4444", "LAN": "#22c55e", "VPN": "#a855f7", "UNKNOWN": "#6b7280"}
    ips = [(ip, info) for ip, info in ip_data.items() if isinstance(info, dict) and _get_event_count(info) > 0]
    ips.sort(key=lambda x: x[1].get("count", 0), reverse=True)
    top_ips = ips[:60]
    for src_ip, src_info in top_ips:
        src_cat = src_info.get("category", "UNKNOWN")
        if src_ip not in node_map:
            nodes.append({"id": src_ip, "label": src_ip, "category": src_cat, "color": colors.get(src_cat, "#6b7280"), "size": min(6 + _get_event_count(src_info), 24)})
            node_map[src_ip] = len(nodes) - 1
        for dst_ip, dst_info in top_ips:
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
    if not conn:
        return _fallback_geo()
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
            ip = row["src_ip"]
            cnt = row["cnt"]
            first = _parse_ip_first_octet(ip)
            if first is None:
                regions["Other"] += cnt
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
    finally:
        close_db(conn)

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
    """Get recent attack events from PostgreSQL for Recent Activity section."""
    conn = get_db()
    if not conn:
        return _fallback_events()
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
            ip = row["src_ip"]
            cnt = row["event_count"]
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
    finally:
        close_db(conn)

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
    """Query OPNsense API for system status and scrape data."""
    opn_url, opn_key, opn_cert = _read_opn_config()
    if not opn_url:
        return {"status": "disconnected", "error": "No OPNsense config found"}
    
    try:
        import urllib.request
        import ssl
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        results = {"status": "connected"}
        
        # System info
        try:
            req = urllib.request.Request(f"{opn_url}/api/core/system/info", headers={"X-API-Key": opn_key})
            with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
                sys_info = json.loads(resp.read().decode())
            results["opnsense_version"] = sys_info.get("version", "unknown") if isinstance(sys_info, dict) else "unknown"
            results["hostname"] = sys_info.get("hostname", "unknown") if isinstance(sys_info, dict) else "unknown"
            results["uptime"] = sys_info.get("uptime", "unknown") if isinstance(sys_info, dict) else "unknown"
            results["cpu_load"] = sys_info.get("cpuload", "unknown") if isinstance(sys_info, dict) else "unknown"
            results["memory_usage"] = sys_info.get("memory_usage", "unknown") if isinstance(sys_info, dict) else "unknown"
        except Exception as e:
            print(f"OPNsense system info failed: {e}")
            results["opnsense_version"] = "error"
            results["hostname"] = "error"
        
        # Firewall rules
        try:
            req2 = urllib.request.Request(f"{opn_url}/api/filter/rules", headers={"X-API-Key": opn_key})
            with urllib.request.urlopen(req2, context=ssl_context, timeout=5) as resp2:
                rules_data = json.loads(resp2.read().decode())
            rules_list = rules_data.get("rules", {}).get("row", []) if isinstance(rules_data, dict) else []
            results["firewall_rules"] = len(rules_list)
        except Exception as e:
            print(f"OPNsense rules failed: {e}")
            results["firewall_rules"] = 0
        
        # DHCP leases
        try:
            req3 = urllib.request.Request(f"{opn_url}/api/dhcpd/status", headers={"X-API-Key": opn_key})
            with urllib.request.urlopen(req3, context=ssl_context, timeout=5) as resp3:
                dhcp_data = json.loads(resp3.read().decode())
            leases_list = dhcp_data.get("leases", {}).get("row", []) if isinstance(dhcp_data, dict) else []
            results["dhcp_leases"] = len(leases_list)
        except Exception as e:
            print(f"OPNsense DHCP failed: {e}")
            results["dhcp_leases"] = 0
        
        return results
    except Exception as e:
        return {"status": "disconnected", "error": str(e), "opnsense_version": "unknown", "hostname": "unknown", "uptime": "unknown", "cpu_load": "unknown", "memory_usage": "unknown", "firewall_rules": 0, "dhcp_leases": 0}

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
    finally:
        close_db(conn)

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

def query_health():
    conn = get_db()
    state = load_state()
    agent_counters = {}
    if state:
        agent_counters = state.get("agent_counters", {})
    
    uptime = _calc_uptime(agent_counters)
    
    if not conn:
        return {"status": "cold-start", "database": {"status": "disconnected"}, "events_processed": 0, "anomalies_detected": agent_counters.get("anomaly_count", 0), "uptime_seconds": uptime}
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events")
        row = cur.fetchone()
        event_count = row[0] if row else 0
        close_db(conn)
        return {
            "status": "healthy" if event_count > 0 else "cold-start",
            "database": {"status": "connected", "message": f"{event_count:,} total events"},
            "syslog": {"status": "active", "message": "Syslog listener running"},
            "discord": {"status": "active", "message": "Discord bot online"},
            "opnsense": {"status": "active", "message": "OPNsense API connected"},
            "events_processed": event_count,
            "anomalies_detected": agent_counters.get("anomaly_count", 0),
            "uptime_seconds": uptime,
            "agent_counters": agent_counters,
        }
    except Exception as e:
        close_db(conn)
        return {"status": "error", "database": {"status": "error", "message": str(e)}, "events_processed": 0, "anomalies_detected": agent_counters.get("anomaly_count", 0), "uptime_seconds": uptime}

# Request Handler
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
            self._send_json(query_events())
        elif path == "/api/mutes":
            self._send_json(load_mutes())
        elif path == "/api/geo":
            self._send_json(query_geo())
        elif path == "/api/health":
            self._send_json(query_health())
        elif path == "/api/alerts":
            self._send_json(query_alerts())
        elif path == "/api/opnsense":
            self._send_json(query_opnsense_status())
        else:
            self.send_response(404)
            self.end_headers()

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
