#!/usr/bin/env python3
"""Train baselines from live events in PostgreSQL."""
import json
from collections import defaultdict

def main():
    from eventdb import EventDatabase
    db = EventDatabase()
    db.connect()
    cur = db.connect().cursor()

    # Get recent events (last 7 days for training)
    print("Training baselines from live events...")
    cur.execute("""
        SELECT rule_name, src_ip, dst_ip, src_port, dst_port, proto, action, timestamp
        FROM events
        WHERE timestamp > NOW() - INTERVAL '7 days'
        ORDER BY timestamp ASC
    """)
    events = cur.fetchall()
    print(f"Loaded {len(events)} events from last 7 days")

    # Group by rule
    rule_events = defaultdict(list)
    for e in events:
        rule = e[0] or ""
        if rule:
            rule_events[rule].append(e)

    print(f"Rules to train: {len(rule_events)}")

    # Calculate baselines
    saved = 0
    for rule, evts in rule_events.items():
        if len(evts) < 50:  # Skip rules with too few events
            continue

        # Calculate metrics
        hours = defaultdict(int)
        proto_counts = defaultdict(int)
        dst_ports = set()
        src_ports = set()
        dst_ips = set()
        blocks = 0

        for e in evts:
            ts = e[7]  # timestamp
            if ts:
                hours[ts.hour] += 1
            if e[5]:  # proto
                proto_counts[e[5]] += 1
            if e[4]:  # dst_port
                dst_ports.add(e[4])
            if e[3]:  # src_port
                src_ports.add(e[3])
            if e[2]:  # dst_ip
                dst_ips.add(e[2])
            if e[6] == "block":
                blocks += 1

        total = len(evts)
        avg_dst = len(dst_ports)
        avg_src = len(src_ports)
        avg_dst_ips = len(dst_ips)
        pass_r = (total - blocks) / total if total > 0 else 0
        block_r = blocks / total if total > 0 else 0

        # Protocol distribution
        proto_dist = {}
        for p, c in proto_counts.items():
            proto_dist[p] = c / total

        # Hourly distribution
        hourly_dist = [hours.get(h, 0) for h in range(24)]
        max_h = max(hourly_dist) if hourly_dist else 0
        min_h = min(hourly_dist) if hourly_dist else 0
        avg_h = total / 24 if total > 0 else 0

        # Save to DB
        cur.execute("""
            INSERT INTO rule_baselines (rule, ip, hour, avg_events_per_hour, std_events_per_hour,
                                      max_events_per_hour, min_events_per_hour, protocol_distribution,
                                      avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio,
                                      block_ratio, hourly_distribution, sample_count, last_updated)
            VALUES (%s, NULL, NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (rule, ip, hour) DO UPDATE SET
                avg_events_per_hour = EXCLUDED.avg_events_per_hour,
                std_events_per_hour = EXCLUDED.std_events_per_hour,
                max_events_per_hour = EXCLUDED.max_events_per_hour,
                min_events_per_hour = EXCLUDED.min_events_per_hour,
                protocol_distribution = EXCLUDED.protocol_distribution,
                avg_dst_ports = EXCLUDED.avg_dst_ports,
                avg_src_ports = EXCLUDED.avg_src_ports,
                avg_unique_dst_ips = EXCLUDED.avg_unique_dst_ips,
                pass_ratio = EXCLUDED.pass_ratio,
                block_ratio = EXCLUDED.block_ratio,
                hourly_distribution = EXCLUDED.hourly_distribution,
                sample_count = EXCLUDED.sample_count,
                last_updated = NOW()
        """, (
            rule,
            avg_h,
            avg_h * 0.5,  # std estimate
            max_h,
            min_h,
            proto_dist,
            avg_dst,
            avg_src,
            avg_dst_ips,
            pass_r,
            block_r,
            hourly_dist,
            total
        ))
        saved += 1
        print(f"  Rule {rule}: {total} events | avg={avg_h:.0f}/hr std={avg_h*0.5:.0f} | "
              f"pass={pass_r:.0%} block={block_r:.0%}")

    cur.execute("COMMIT")
    print(f"\nSaved {saved} rule baselines from live events")

    # Show what we now have
    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
    print(f"Total baselines in database: {cur.fetchone()[0]}")
    cur.close()

if __name__ == "__main__":
    main()