#!/usr/bin/env python3
"""Full training run with inspection."""
from graylog_training_extractor import GraylogTrainingExtractor
from baseline_engine import BaselineEngine
from eventdb import EventDatabase

def main():
    print("=" * 70)
    print("FULL TRAINING RUN")
    print("=" * 70)

    # Initialize
    extractor = GraylogTrainingExtractor()
    if not extractor.connect():
        print("FAIL: Cannot connect to OpenSearch")
        return 1

    db = EventDatabase()
    db.connect()
    baseline_engine = BaselineEngine(db)

    # Count existing baselines
    cur = db.connect().cursor()
    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
    existing = cur.fetchone()[0]
    print(f"\nExisting baselines in DB: {existing}")

    # Clear old baselines for fresh training
    cur.execute("DELETE FROM rule_baselines WHERE rule IS NOT NULL")
    cur.close()
    print("Cleared old baselines for fresh training")

    # Extract all available firewall events
    print("\n--- Extracting firewall events ---")
    firewall_events = extractor.extract_firewall_events(sample_size=200000)
    print(f"Extracted {len(firewall_events):,} firewall events")

    # Learn baselines
    print("\n--- Learning baselines ---")
    learned = baseline_engine.learn_from_training_data(firewall_events)
    print(f"Learned {learned} baselines")

    # Save to database
    print("\n--- Saving baselines ---")
    baseline_engine.save_baselines()

    # Verify
    cur = db.connect().cursor()
    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
    saved = cur.fetchone()[0]
    print(f"Baselines in DB: {saved}")

    # Inspect what was learned
    print("\n" + "=" * 70)
    print("BASELINE INSPECTION")
    print("=" * 70)

    # Top rules
    print("\n--- Top 20 rules by sample count ---")
    cur.execute("""
        SELECT rule, sample_count, avg_events_per_hour, std_events_per_hour,
               max_events_per_hour, min_events_per_hour,
               pass_ratio, block_ratio, avg_dst_ports, avg_unique_dst_ips,
               protocol_distribution
        FROM rule_baselines
        WHERE rule IS NOT NULL AND ip IS NULL AND hour IS NULL
        ORDER BY sample_count DESC
        LIMIT 20
    """)
    for row in cur.fetchall():
        rule, samples, avg_hr, std_hr, max_hr, min_hr, pass_r, block_r, ports, dst_ips, proto = row
        print(f"Rule {rule:6s} | {samples:6,} samples | avg={avg_hr:8.1f} std={std_hr:8.1f} max={max_hr:5} min={min_hr:5} | "
              f"pass={pass_r:.1%} block={block_r:.1%} | ports={ports:.0f} ips={dst_ips:.0f}")
        if proto:
            proto_str = ", ".join(f"{k}={v:.1%}" for k, v in sorted(proto.items(), key=lambda x: -x[1])[:3])
            print(f"         Protocols: {proto_str}")

    # IP baselines
    print("\n--- Top 15 IP-level baselines ---")
    cur.execute("""
        SELECT rule, ip, sample_count, avg_events_per_hour, pass_ratio, block_ratio
        FROM rule_baselines
        WHERE rule IS NOT NULL AND ip IS NOT NULL
        ORDER BY sample_count DESC
        LIMIT 15
    """)
    for row in cur.fetchall():
        rule, ip, samples, avg_hr, pass_r, block_r = row
        ip_short = ip[:20] + "..." if len(ip) > 20 else ip
        print(f"  Rule {rule}/{ip_short:25s} | {samples:5,} samples | {avg_hr:8.1f} events/hr | pass={pass_r:.1%}")

    # Temporal patterns
    print("\n--- Hourly distribution for top rules ---")
    cur.execute("""
        SELECT rule, hourly_distribution FROM rule_baselines
        WHERE rule IS NOT NULL AND ip IS NULL AND hour IS NULL
        ORDER BY sample_count DESC LIMIT 3
    """)
    for row in cur.fetchall():
        rule, hourly = row
        if hourly and len(hourly) == 24:
            hourly_list = [float(h) for h in hourly]
            peak = max(range(24), key=lambda h: hourly_list[h])
            low = min(range(24), key=lambda h: hourly_list[h])
            print(f"\n  Rule {rule}:")
            print(f"  Peak: {peak:02d}:00 ({hourly_list[peak]:.0f} events)")
            print(f"  Low:  {low:02d}:00 ({hourly_list[low]:.0f} events)")
            # Simple ASCII histogram
            max_val = max(hourly_list) or 1
            for h in range(24):
                val = hourly_list[h]
                bar_len = int((val / max_val) * 40)
                bar = "█" * bar_len
                print(f"  {h:02d}:00 | {bar} ({val:.0f})")

    cur.close()
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()