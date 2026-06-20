#!/usr/bin/env python3
"""
Live anomaly detection demo.
Feeds recent events through the threat engine and shows detected anomalies.
"""
import json
from datetime import datetime, timezone
from eventdb import EventDatabase
from baseline_engine import BaselineEngine
from threat_engine import ThreatEngine

def main():
    print("=" * 80)
    print("LIVE ANOMALY DETECTION DEMO")
    print("=" * 80)

    # Initialize engines
    db = EventDatabase()
    db.connect()
    be = BaselineEngine(db)
    te = ThreatEngine(db, baseline_engine=be)

    # Load baselines
    cur = db.connect().cursor()
    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
    baselines = cur.fetchone()[0]
    print(f"\nBaselines loaded: {baselines}")

    # Get recent events
    print("\nFetching recent events...")
    cur.execute("""
        SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, proto,
               action, rule_name, interface, direction, raw_message
        FROM events
        ORDER BY timestamp DESC
        LIMIT 1000
    """)

    events = []
    for row in cur.fetchall():
        events.append({
            "id": row[0],
            "timestamp": str(row[1]),
            "src_ip": row[2],
            "dst_ip": row[3],
            "src_port": row[4],
            "dst_port": row[5],
            "protocol": row[6],
            "action": row[7],
            "rule": str(row[8]) if row[8] else "",
            "interface": row[9],
            "direction": row[10],
        })

    cur.close()
    print(f"Processing {len(events)} recent events...")

    # Process events through threat engine
    anomalies_found = 0
    for event in events:
        te.ingest_firewall_event(event)

    # Check IP profiles for high threats
    print("\n" + "-" * 80)
    print("TOP THREAT PROFILES (from recent events)")
    print("-" * 80)

    # Sort IPs by number of baseline deviations
    scored_ips = []
    for ip, profile in te._ip_profiles.items():
        if profile.baseline_deviations:
            max_dev = max(profile.baseline_deviations)
            avg_dev = sum(profile.baseline_deviations) / len(profile.baseline_deviations)
            scored_ips.append((ip, profile, max_dev, avg_dev))

    # Sort by max deviation
    scored_ips.sort(key=lambda x: x[2], reverse=True)

    if scored_ips:
        for ip, profile, max_dev, avg_dev in scored_ips[:15]:
            if max_dev > 1.0:  # Show deviations > 1 sigma
                print(f"\n  IP: {ip}")
                print(f"    Events: {profile.total_events} | Deviations: {len(profile.baseline_deviations)}")
                print(f"    Max deviation: {max_dev:.1f} sigma | Avg: {avg_dev:.1f} sigma")
                anomalies_found += 1
            else:
                break

    # Check for port scan patterns
    print("\n" + "-" * 80)
    print("PORT SCAN DETECTION")
    print("-" * 80)

    # Find IPs with many unique dst_ports
    ip_ports: dict[str, set] = {}
    for event in events:
        ip = event.get("src_ip")
        port = event.get("dst_port")
        if ip and port:
            if ip not in ip_ports:
                ip_ports[ip] = set()
            ip_ports[ip].add(port)

    port_scanners = [(ip, ports) for ip, ports in ip_ports.items() if len(ports) > 5]
    port_scanners.sort(key=lambda x: len(x[1]), reverse=True)

    if port_scanners:
        for ip, ports in port_scanners[:5]:
            print(f"  {ip}: {len(ports)} unique ports")
            print(f"    Ports: {', '.join(str(p) for p in sorted(ports)[:10])}...")
    else:
        print("  No port scans detected in recent events")

    # Show baseline comparison
    print("\n" + "-" * 80)
    print("BASELINE vs ACTUAL (recent events)")
    print("-" * 80)

    # Count events by rule in recent batch
    rule_counts: dict[str, int] = {}
    for event in events:
        rule = event.get("rule", "unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1

    # Compare to baselines
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        baseline = be.get_baseline(rule)
        if baseline:
            # Events per hour (assuming these are from ~5 min window)
            actual_hr = count * 12  # Extrapolate to hourly
            status = ""
            if baseline.std_events_per_hour > 0:
                z = (actual_hr - baseline.avg_events_per_hour) / baseline.std_events_per_hour
                if abs(z) > 2:
                    status = f" *** ANOMALY (z={z:+.1f}) ***"
                    anomalies_found += 1

            print(f"  Rule {rule}: {count:4d} events ({actual_hr:6.0f}/hr) | "
                  f"baseline: {baseline.avg_events_per_hour:.0f}/hr (std={baseline.std_events_per_hour:.0f}){status}")
        else:
            print(f"  Rule {rule}: {count:4d} events | no baseline")

    print("\n" + "=" * 80)
    print(f"DEMO COMPLETE - Found {anomalies_found} potential anomalies")
    print("=" * 80)

if __name__ == "__main__":
    main()