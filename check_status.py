#!/usr/bin/env python3
"""Check live events and baseline status."""
from eventdb import EventDatabase

db = EventDatabase()
db.connect()
cur = db.connect().cursor()

# Recent events
cur.execute("""
    SELECT COUNT(*) FROM normalized_events 
    WHERE timestamp > NOW() - INTERVAL '5 minutes'
""")
recent = cur.fetchone()[0]
print(f"Events in last 5 min: {recent}")

# Top rules in last 5 minutes
cur.execute("""
    SELECT rule_name, COUNT(*) as cnt,
           COUNT(DISTINCT src_ip) as ips,
           COUNT(DISTINCT dst_port) as ports
    FROM normalized_events
    WHERE timestamp > NOW() - INTERVAL '5 minutes'
    GROUP BY rule_name
    ORDER BY cnt DESC
    LIMIT 10
""")
print("\nTop rules (5 min window):")
for row in cur.fetchall():
    print(f"  Rule {row[0]:10s} | {row[1]:5d} events | {row[2]:4d} IPs | {row[3]:4d} ports")

# Recent anomalies
cur.execute("""
    SELECT attack_type, severity, COUNT(*)
    FROM anomalies
    WHERE created_at > NOW() - INTERVAL '1 hour'
    GROUP BY attack_type, severity
    ORDER BY COUNT(*) DESC
    LIMIT 10
""")
print("\nAnomalies (last hour):")
for row in cur.fetchall():
    print(f"  {row[0]:20s} {row[1]:10s} | {row[2]} events")

# Baseline status
cur.execute("""
    SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL
""")
baselines = cur.fetchone()[0]
print(f"\nBaselines in DB: {baselines}")

# Show baseline stats for top rules
cur.execute("""
    SELECT rule, sample_count, avg_events_per_hour, std_events_per_hour,
           protocol_distribution, hourly_distribution
    FROM rule_baselines
    WHERE rule IS NOT NULL AND ip IS NULL AND hour IS NULL
    ORDER BY sample_count DESC
    LIMIT 5
""")
print("\nBaseline stats (top 5 rules):")
for row in cur.fetchall():
    rule, samples, avg_hr, std_hr, protocol, hourly = row
    print(f"  Rule {rule}: {samples:,} samples | avg={avg_hr:.0f}/hr std={std_hr:.0f}")
    print(f"    Protocols: {protocol}")
    if hourly:
        peak = max(range(24), key=lambda h: hourly[h])
        print(f"    Peak hour: {peak}:00 ({hourly[peak]:.0f} events)")

cur.close()