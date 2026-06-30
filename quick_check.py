#!/usr/bin/env python3
"""Check live event flow and anomaly detection."""
from eventdb import EventDatabase

db = EventDatabase()
db.connect()
cur = db.connect().cursor()

# Recent events
cur.execute("""
    SELECT COUNT(*) FROM normalized_events 
    WHERE timestamp > NOW() - INTERVAL '5 minutes'
""")
print(f"Events in last 5 min: {cur.fetchone()[0]}")

# Top rules
cur.execute("""
    SELECT rule_name, COUNT(*) as cnt, COUNT(DISTINCT src_ip) as ips, COUNT(DISTINCT dst_port) as ports
    FROM normalized_events WHERE timestamp > NOW() - INTERVAL '5 minutes'
    GROUP BY rule_name ORDER BY cnt DESC LIMIT 10
""")
print("\nTop rules (5 min):")
for row in cur.fetchall():
    print(f"  Rule {row[0]:10s}: {row[1]:5d} events | {row[2]:4d} IPs | {row[3]:4d} ports")

# Log types
cur.execute("""
    SELECT log_type, COUNT(*) FROM normalized_events
    WHERE timestamp > NOW() - INTERVAL '5 minutes'
    GROUP BY log_type ORDER BY COUNT(*) DESC
""")
print("\nLog types:")
for row in cur.fetchall():
    print(f"  {row[0]:15s}: {row[1]}")

# Anomalies in last hour
cur.execute("""
    SELECT attack_type, severity, COUNT(*) FROM anomalies
    WHERE created_at > NOW() - INTERVAL '1 hour'
    GROUP BY attack_type, severity ORDER BY COUNT(*) DESC LIMIT 10
""")
print("\nAnomalies (last hour):")
for row in cur.fetchall():
    print(f"  {row[0]:25s} {row[1]:10s}: {row[2]}")

cur.close()