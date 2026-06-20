#!/usr/bin/env python3
"""Show anomaly detection working with live events."""
import json
from collections import defaultdict

def main():
    from eventdb import EventDatabase
    db = EventDatabase()
    db.connect()

    print("=" * 80)
    print("ANOMALY DETECTION - LIVE EVENTS vs BASELINES")
    print("=" * 80)

    # Load baselines
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule, ip, avg_events_per_hour, std_events_per_hour,
               protocol_distribution, hourly_distribution, sample_count
        FROM rule_baselines WHERE rule IS NOT NULL
    """)

    baselines = {}
    for row in cur.fetchall():
        key = row[0]
        if row[1]:  # IP-level baseline
            key = f"{row[0]}:{row[1]}"
        baselines[key] = {
            "rule": row[0], "ip": row[1],
            "avg": row[2] or 0, "std": row[3] or 0,
            "proto": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if isinstance(row[4], str) else {},
            "hourly": row[5] if isinstance(row[5], list) else json.loads(row[5]) if isinstance(row[5], str) else [],
            "samples": row[6] or 0
        }

    cur.close()
    print(f"\nLoaded {len(baselines)} baselines")

    # Show top baselines
    rule_baselines = {k: v for k, v in baselines.items() if v["ip"] is None}
    top = sorted(rule_baselines.values(), key=lambda b: b["samples"], reverse=True)[:5]

    print("\n--- TOP BASELINES ---")
    for b in top:
        protos = ", ".join(f"{k}={v:.0%}" for k, v in sorted(b["proto"].items(), key=lambda x: -x[1])[:3]) if b["proto"] else "N/A"
        peak_h = max(range(24), key=lambda h: b["hourly"][h]) if b["hourly"] and max(b["hourly"]) > 0 else 0
        print(f"Rule {b['rule']:6s}: {b['samples']:6,} samples | avg={b['avg']:7.0f}/hr std={b['std']:6.0f} | pass={b['pass_r']:.0%}")
        print(f"         Protocols: {protos}")
        print(f"         Peak: {peak_h}:00 ({max(b['hourly'])} events)")

    # Pull recent events (last 10K)
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule_name, src_ip, dst_port, proto, action
        FROM events ORDER BY id DESC LIMIT 10000
    """)
    events = [{"rule": r[0] or "", "src_ip": r[1] or "", "dst_port": r[2], "proto": r[3] or "", "action": r[4] or ""} for r in cur.fetchall()]
    cur.close()

    print(f"\n--- ANALYZING {len(events)} RECENT EVENTS ---")

    # Collect stats
    rule_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    ip_ports = defaultdict(set)

    for e in events:
        rule_counts[e["rule"]] += 1
        ip_counts[e["src_ip"]] += 1
        if e["src_ip"] and e["dst_port"]:
            ip_ports[e["src_ip"]].add(e["dst_port"])

    anomalies = []

    # 1. Volume analysis
    print("\n" + "-" * 80)
    print("VOLUME ANALYSIS")
    print("-" * 80)

    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        b = baselines.get(rule)
        if b:
            hourly = count * 12  # extrapolate
            std = b["std"] or (b["avg"] * 0.5)
            z = (hourly - b["avg"]) / std if std > 0 else 0

            sev = "OK"
            marker = ""
            if abs(z) >= 5:
                sev = "CRITICAL"
                marker = " *** CRITICAL SPIKE ***"
                anomalies.append({"type": "volume", "rule": rule, "z": z, "sev": sev})
            elif abs(z) >= 3:
                sev = "HIGH"
                marker = " ** HIGH ANOMALY **"
                anomalies.append({"type": "volume", "rule": rule, "z": z, "sev": sev})
            elif abs(z) >= 2:
                sev = "MEDIUM"
                marker = " * MODERATE *"

            print(f"Rule {rule:6s}: {count:4d} events ({hourly:6.0f}/hr) | "
                  f"baseline: {b['avg']:7.0f}/hr (std={std:.0f}) | z={z:+.1f} [{sev}]{marker}")
        else:
            print(f"Rule {rule:6s}: {count:4d} events | NO BASELINE")

    # 2. Port scan detection
    print("\n" + "-" * 80)
    print("PORT SCAN DETECTION")
    print("-" * 80)

    scanners = [(ip, ports) for ip, ports in ip_ports.items() if len(ports) > 5]
    scanners.sort(key=lambda x: len(x[1]), reverse=True)

    if scanners:
        for ip, ports in scanners[:5]:
            sev = "CRITICAL" if len(ports) > 20 else "HIGH" if len(ports) > 10 else "MEDIUM"
            marker = " *** ANOMALY ***" if sev in ("CRITICAL", "HIGH") else ""
            anomalies.append({"type": "port_scan", "ip": ip, "ports": len(ports), "sev": sev})
            print(f"{ip}: {len(ports)} unique ports | [{sev}]{marker}")
            print(f"  Ports: {', '.join(str(p) for p in sorted(ports)[:10])}...")
    else:
        print("No port scan patterns detected")

    # 3. New IP detection
    print("\n" + "-" * 80)
    print("NEW IP DETECTION")
    print("-" * 80)

    known_ips = set(b["ip"] for b in baselines.values() if b["ip"])
    new_ips = [(ip, cnt) for ip, cnt in ip_counts.items() if ip not in known_ips and cnt > 3]
    new_ips.sort(key=lambda x: -x[1])

    if new_ips:
        for ip, cnt in new_ips[:10]:
            print(f"NEW IP: {ip} ({cnt} events) | NO BASELINE")
            anomalies.append({"type": "new_ip", "ip": ip, "count": cnt, "sev": "MEDIUM"})
    else:
        print("All active IPs have baselines")

    # Summary
    print("\n" + "=" * 80)
    print(f"SUMMARY: {len(anomalies)} anomalies detected")
    print("=" * 80)

    if anomalies:
        by_sev = defaultdict(int)
        for a in anomalies:
            by_sev[a.get("sev", "LOW")] += 1
        print(f"  CRITICAL: {by_sev.get('CRITICAL', 0)}")
        print(f"  HIGH:     {by_sev.get('HIGH', 0)}")
        print(f"  MEDIUM:   {by_sev.get('MEDIUM', 0)}")
        print(f"  LOW:      {by_sev.get('LOW', 0)}")
        print("\nTop anomalies:")
        for a in anomalies[:10]:
            print(f"  [!] {a}")
    else:
        print("  No anomalies - traffic matches learned baselines!")

if __name__ == "__main__":
    main()