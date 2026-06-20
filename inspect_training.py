#!/usr/bin/env python3
"""Inspect trained baselines."""
from eventdb import EventDatabase

db = EventDatabase()
db.connect()
cur = db.connect().cursor()

print("=" * 80)
print("BASELINE ENGINE LEARNING REPORT")
print("=" * 80)

# Total baselines
cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
total = cur.fetchone()[0]
print(f"\nTotal baselines in DB: {total}")

# Rule-level baselines
cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL AND ip IS NULL AND hour IS NULL")
rule_only = cur.fetchone()[0]
print(f"Rule-level baselines: {rule_only}")

# IP-level baselines
cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL AND ip IS NOT NULL")
ip_level = cur.fetchone()[0]
print(f"IP-level baselines: {ip_level}")

# Hour-level baselines
cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL AND hour IS NOT NULL AND ip IS NULL")
hour_level = cur.fetchone()[0]
print(f"Hour-level baselines: {hour_level}")

# Top rules by sample count
print("\n" + "-" * 80)
print("TOP RULES BY SAMPLE COUNT")
print("-" * 80)

cur.execute("""
    SELECT rule, sample_count, avg_events_per_hour, std_events_per_hour,
           max_events_per_hour, min_events_per_hour,
           pass_ratio, block_ratio, avg_dst_ports, avg_unique_dst_ips,
           protocol_distribution, hourly_distribution
    FROM rule_baselines
    WHERE rule IS NOT NULL AND ip IS NULL AND hour IS NULL
    ORDER BY sample_count DESC
    LIMIT 20
""")

for row in cur.fetchall():
    rule, samples, avg_hr, std_hr, max_hr, min_hr, pass_r, block_r, ports, dst_ips, proto, hourly = row
    print(f"\nRule {rule} ({samples:,} samples):")
    print(f"  Volume: {avg_hr:.1f} events/hr (std={std_hr:.1f}, max={max_hr}, min={min_hr})")
    print(f"  Actions: pass={pass_r:.2f} block={block_r:.2f}")
    print(f"  Diversity: {ports:.0f} dst ports, {dst_ips:.0f} unique dst IPs")
    print(f"  Protocols: {proto}")
    # Peak hours
    if hourly and len(hourly) == 24:
        peak = max(range(24), key=lambda h: hourly[h])
        peak_val = hourly[peak]
        print(f"  Peak hour: {peak}:00 ({peak_val} events)")

# Top IP baselines
print("\n" + "-" * 80)
print("TOP IPs BY SAMPLE COUNT (per-rule)")
print("-" * 80)

cur.execute("""
    SELECT rule, ip, sample_count, avg_events_per_hour, pass_ratio, block_ratio
    FROM rule_baselines
    WHERE rule IS NOT NULL AND ip IS NOT NULL
    ORDER BY sample_count DESC
    LIMIT 20
""")

for row in cur.fetchall():
    rule, ip, samples, avg_hr, pass_r, block_r = row
    print(f"  Rule {rule}/{ip:40s} | {samples:5d} samples | {avg_hr:8.1f} events/hr | pass={pass_r:.2f} block={block_r:.2f}")

# Hourly distribution for top rule
print("\n" + "-" * 80)
print("HOURLY DISTRIBUTION FOR RULE 230 (top rule)")
print("-" * 80)

cur.execute("""
    SELECT hourly_distribution FROM rule_baselines
    WHERE rule = '230' AND ip IS NULL AND hour IS NULL
    LIMIT 1
""")

row = cur.fetchone()
if row and row[0]:
    hourly = row[0]
    if isinstance(hourly, list) and len(hourly) == 24:
        max_val = max(hourly)
        for h in range(24):
            val = hourly[h]
            bar_len = int((val / max_val) * 50) if max_val > 0 else 0
            bar = "#" * bar_len
            print(f"  {h:02d}:00 | {bar} ({val})")

cur.close()
print("\n" + "=" * 80)
print("BASELINE ENGINE LEARNING REPORT COMPLETE")
print("=" * 80)