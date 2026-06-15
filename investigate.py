#!/usr/bin/env python3
"""Investigate state file and DB."""
import json, os, sys
try:
    import psycopg2
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False

path = '/home/tim/opnsense-anomaly-agent/agent_data/state.json'
if not os.path.exists(path):
    print("No state file")
    sys.exit(0)

state = json.load(open(path))

print("=== TOP KEYS ===")
for k in state:
    v = state[k]
    if isinstance(v, dict):
        print(f"{k}: dict({len(v)} keys)")
    elif isinstance(v, list):
        print(f"{k}: list({len(v)})")
    elif isinstance(v, (int, float)):
        print(f"{k}: {v}")

print()
print("=== ATTACK DETECTOR ===")
ad = state.get("attack_detector", {})
for k, v in ad.items():
    if isinstance(v, dict):
        print(f"  {k}: {len(v)} entries")
        sample = list(v.items())[0] if v else None
        if sample:
            key, val = sample
            print(f"    sample key: {key[:50]}")
            if isinstance(val, dict):
                print(f"      count: {val.get('count',0)}")
                ev = val.get("events", [])
                if isinstance(ev, list):
                    print(f"      events: {len(ev)} items")
                    if ev:
                        print(f"      first: {str(ev[0])[:150]}")
                elif isinstance(val, dict) and "events" in val:
                    ev2 = val["events"]
                    if isinstance(ev2, dict):
                        print(f"      events: dict({len(ev2)} keys)")

print()
print("=== NETWORK CLASSIFIER ===")
nc = state.get("network_classifier", {})
for k, v in nc.items():
    if isinstance(v, dict):
        print(f"  {k}: {len(v)} entries")
        sample = list(v.items())[0] if v else None
        if sample:
            key, val = sample
            print(f"    sample key: {key}")
            if isinstance(val, dict):
                for kk, vv in list(val.items())[:5]:
                    print(f"      {kk}: {str(vv)[:100]}")

print()
print("=== GEO ===")
gd = state.get("geo_detector", {})
for k, v in gd.items():
    if isinstance(v, dict):
        print(f"  {k}: {len(v)} entries")
        for key, val in list(v.items())[:3]:
            if isinstance(val, dict):
                print(f"    {key}: count={val.get('count',0)}")

print()
print("=== REVERSE DNS ===")
rd = state.get("reverse_dns", {})
if isinstance(rd, dict):
    print(f"  {len(rd)} entries")
    for key in list(rd.keys())[:3]:
        print(f"    {key}: {str(rd[key])[:80]}")

print()
print("=== DEDUP ===")
dd = state.get("dedup", {})
if isinstance(dd, dict):
    print(f"  {len(dd)} entries")

print()
print("=== COUNTERS ===")
print(json.dumps(state.get("counters", {}), indent=2))
print(f"=== UPTIME: {state.get('uptime', 0)} seconds ===")
print(f"=== STATE SIZE: {os.path.getsize(path)} bytes ===")

# DB check
if HAS_PSYCOPG:
    print()
    print("=== PostgreSQL ===")
    try:
        conn = psycopg2.connect(host="192.168.1.50", port=5432,
                                dbname="anomaly_agent", user="anomaly_agent",
                                password="anomaly_pass")
        cur = conn.cursor()
        
        cur.execute("SELECT count(*) FROM events")
        total = cur.fetchone()[0]
        print(f"  Total events: {total}")
        
        cur.execute("SELECT event_type, count(*) FROM events GROUP BY event_type ORDER BY count(*) DESC LIMIT 10")
        print("  By type:")
        for r in cur.fetchall():
            print(f"    {r[0]}: {r[1]}")
        
        cur.execute("SELECT timestamp, event_type, source_ip, dest_ip, dest_port, severity FROM events ORDER BY timestamp DESC LIMIT 5")
        print("  Recent events:")
        for r in cur.fetchall():
            print(f"    {r[0]} | {r[1]:15s} | {r[2]:15s} -> {r[3]:15s}:{r[4]} | {r[5]}")
        
        cur.execute("SELECT source_ip, count(*) FROM events GROUP BY source_ip ORDER BY count(*) DESC LIMIT 10")
        print("  Top sources:")
        for r in cur.fetchall():
            print(f"    {r[0]}: {r[1]}")
        
        cur.execute("SELECT action, count(*) FROM events GROUP BY action ORDER BY count(*) DESC")
        print("  Actions:")
        for r in cur.fetchall():
            print(f"    {r[0]}: {r[1]}")
        
        cur.execute("SELECT timestamp, count(*) FROM events GROUP BY date_trunc('hour', timestamp) ORDER BY 1 DESC LIMIT 5")
        print("  Events per hour (last 5):")
        for r in cur.fetchall():
            print(f"    {r[0]}: {r[1]}")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"  DB error: {e}")
else:
    print()
    print("=== psycopg2 not installed ===")
