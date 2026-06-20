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
        SELECT rule_name, proto, action, timestamp
        FROM events
        WHERE timestamp > NOW() - INTERVAL '7 days'
          AND rule_name IS NOT NULL
        ORDER BY timestamp ASC
    """)
    events = cur.fetchall()
    print(f"Loaded {len(events)} events from last 7 days")

    # Group by rule
    rule_events = defaultdict(list)
    for e in events:
        rule_events[e[0]].append(e)

    print(f"Rules to train: {len(rule_events)}")

    # Calculate baselines
    saved = 0
    for rule, evts in rule_events.items():
        if len(evts) < 50:  # Skip rules with too few events
            continue

        # Calculate metrics
        hours = defaultdict(int)
        proto_counts = defaultdict(int)
        blocks = 0

        for e in evts:
            if e[3]:  # timestamp
                hours[e[3].hour] += 1
            if e[1]:  # proto
                proto_counts[e[1]] += 1
            if e[2] == "block":
                blocks += 1

        total = len(evts)
        avg = total / 7  # per day
        std = avg * 0.5  # estimate
        pass_r = (total - blocks) / total
        block_r = blocks / total

        proto_dist = {k: v/total for k, v in proto_counts.items()}
        hourly_dist = [hours.get(i, 0) for i in range(24)]

        # Save to DB
        cur.execute("""
            INSERT INTO rule_baselines (rule, ip, hour, avg_events_per_hour, std_events_per_hour,
                                      max_events_per_hour, min_events_per_hour, protocol_distribution,
                                      avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio,
                                      block_ratio, hourly_distribution, sample_count, last_updated)
            VALUES (%s, NULL, NULL, %s, %s, %s, %s, %s, 0, 0, 0, %s, %s, %s, %s, NOW())
            ON CONFLICT (rule, ip, hour) DO UPDATE SET
                avg_events_per_hour = EXCLUDED.avg_events_per_hour,
                std_events_per_hour = EXCLUDED.std_events_per_hour,
                max_events_per_hour = EXCLUDED.max_events_per_hour,
                min_events_per_hour = EXCLUDED.min_events_per_hour,
                protocol_distribution = EXCLUDED.protocol_distribution,
                pass_ratio = EXCLUDED.pass_ratio,
                block_ratio = EXCLUDED.block_ratio,
                hourly_distribution = EXCLUDED.hourly_distribution,
                sample_count = EXCLUDED.sample_count
        """, (
            rule,
            avg, std,
            max(hourly_dist) if hourly_dist else 0,
            min(hourly_dist) if hourly_dist else 0,
            json.dumps(proto_dist),
            pass_r, block_r,
            json.dumps(hourly_dist),
            total
        ))
        saved += 1
        print(f"  Rule {rule}: {total} events | avg={avg:.0f}/day std={std:.0f} | "
              f"pass={pass_r:.0%} block={block_r:.0%}")

    cur.execute("COMMIT")
    print(f"\nSaved {saved} rule baselines from live events")

    # Show what we now have
    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
    print(f"Total baselines in database: {cur.fetchone()[0]}")
    cur.close()

if __name__ == "__main__":
    main()