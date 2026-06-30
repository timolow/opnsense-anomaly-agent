#!/usr/bin/env python3
"""
Real-time anomaly detection monitor.
Compares live events against learned baselines and prints anomalies.
"""
import time
import json
from datetime import datetime, timezone
from collections import defaultdict
from eventdb import EventDatabase
from baseline_engine import BaselineEngine

def main():
    print("=" * 70)
    print("REAL-TIME ANOMALY DETECTION MONITOR")
    print("=" * 70)

    db = EventDatabase()
    db.connect()
    be = BaselineEngine(db)

    # Load baselines
    cur = db.connect().cursor()
    cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL")
    total = cur.fetchone()[0]
    print(f"\nLoaded {total} baselines from database")
    cur.close()

    # Track live events
    rule_counts: dict[str, int] = defaultdict(int)
    rule_last_reset: dict[str, float] = {}
    ip_counts: dict[str, int] = defaultdict(int)
    ip_ports: dict[str, set] = defaultdict(set)
    anomalies_detected = 0
    start_time = time.time()

    WINDOW_SECONDS = 30  # Check every 30 seconds

    print(f"\nMonitoring live events (window: {WINDOW_SECONDS}s)...")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            now = time.time()

            # Get events from the last window
            cur = db.connect().cursor()
            cur.execute("""
                SELECT rule_name, src_ip, dst_port, timestamp
                FROM normalized_events
                WHERE timestamp > NOW() - INTERVAL '%d seconds'
                ORDER BY timestamp DESC
            """, (WINDOW_SECONDS,))

            rows = cur.fetchall()
            if rows:
                # Count by rule
                for rule, src_ip, dst_port, _ts in rows:
                    if rule:
                        rule_counts[rule] += 1
                    if src_ip:
                        ip_counts[src_ip] += 1
                        if dst_port:
                            ip_ports[src_ip].add(dst_port)

                print(f"\n[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] "
                      f"Events in window: {len(rows)} | Rules: {len(rule_counts)} | IPs: {len(ip_counts)}")

                # Check for anomalies
                for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]:
                    baseline = be.get_rule_baseline(rule)
                    if baseline and baseline.avg_events_per_hour:
                        # Convert window count to hourly rate
                        hourly_rate = count * (3600 / WINDOW_SECONDS)
                        z_score = (hourly_rate - baseline.avg_events_per_hour) / (baseline.std_events_per_hour or 1)
                        
                        anomaly_flag = ""
                        if abs(z_score) > 3:
                            anomaly_flag = " *** ANOMALY ***"
                            anomalies_detected += 1

                        print(f"  Rule {rule}: {count:4d} events ({hourly_rate:7.1f}/hr) "
                              f"baseline={baseline.avg_events_per_hour:.0f}/hr "
                              f"z={z_score:+.1f}{anomaly_flag}")

                # Check for port scans
                for ip, ports in sorted(ip_ports.items(), key=lambda x: -len(x[1]))[:3]:
                    if len(ports) > 10:
                        print(f"  PORT SCAN: {ip} -> {len(ports)} ports "
                              f"({', '.join(str(p) for p in list(ports)[:5])}...)")
                        anomalies_detected += 1

                # Check for new IPs
                if len(ip_counts) > 20:
                    suspicious = [(ip, cnt) for ip, cnt in ip_counts.items() if cnt > 50]
                    if suspicious:
                        for ip, cnt in sorted(suspicious, key=lambda x: -x[1])[:3]:
                            if not be.get_ip_baseline(ip):
                                print(f"  NEW IP: {ip} ({cnt} events, no baseline)")
                                anomalies_detected += 1

            else:
                print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] No events in window")

            cur.close()

            # Reset counters
            rule_counts.clear()
            ip_counts.clear()
            ip_ports.clear()

            # Wait for next window
            for _ in range(WINDOW_SECONDS):
                time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n\nMonitor stopped after {time.time() - start_time:.0f}s")
        print(f"Total anomalies detected: {anomalies_detected}")

if __name__ == "__main__":
    main()