#!/usr/bin/env python3
"""
Real-time anomaly detection demo.
Loads baselines, pulls recent events, and shows what the system detects.
"""
import json
from collections import defaultdict
from eventdb import EventDatabase
from baseline_engine import BaselineEngine

def main():
    print("=" * 80)
    print("REAL-TIME ANOMALY DETECTION DEMO")
    print("=" * 80)

    db = EventDatabase()
    db.connect()
    be = BaselineEngine(db)

    # How many baselines loaded?
    print(f"\nBaselines loaded: {len(be._baselines)}")

    # Show top baselines
    rule_baselines = {k: v for k, v in be._baselines.items() if v.ip is None and v.hour is None}
    print(f"Rule-level baselines: {len(rule_baselines)}")
    ip_baselines = {k: v for k, v in be._baselines.items() if v.ip is not None}
    print(f"IP-level baselines: {len(ip_baselines)}")

    # Pull recent events
    print("\nPulling recent events from database...")
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule_name, src_ip, dst_ip, src_port, dst_port, protocol, action,
               interface, timestamp
        FROM events
        WHERE timestamp > NOW() - INTERVAL '10 minutes'
        ORDER BY timestamp DESC
    """)
    events = []
    for row in cur.fetchall():
        events.append({
            "rule": row[0] or "",
            "src_ip": row[1],
            "dst_ip": row[2],
            "src_port": row[3],
            "dst_port": row[4],
            "protocol": row[5],
            "action": row[6],
            "interface": row[7],
            "timestamp": str(row[8])
        })
    cur.close()

    print(f"Recent events (10 min): {len(events)}")
    if not events:
        print("No recent events - agent may not be receiving syslog yet.")
        return

    # Count by rule
    rule_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    ip_ports = defaultdict(set)
    anomalies = []

    for e in events:
        rule = e["rule"]
        src_ip = e["src_ip"]
        dst_port = e["dst_port"]

        if rule:
            rule_counts[rule] += 1
        if src_ip:
            ip_counts[src_ip] += 1
        if src_ip and dst_port:
            ip_ports[src_ip].add(dst_port)

    # 1. VOLUME ANOMALIES
    print("\n" + "-" * 80)
    print("VOLUME ANALYSIS (comparing recent rates to baselines)")
    print("-" * 80)

    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        baseline = be.get_baseline(rule)
        if baseline:
            # Extrapolate to hourly rate (10 min window)
            hourly_rate = count * 6
            avg = baseline.avg_events_per_hour
            std = baseline.std_events_per_hour or (avg * 0.5)
            z_score = (hourly_rate - avg) / std

            status = "OK"
            if abs(z_score) > 3:
                status = "*** SPIKE ***"
                anomalies.append(f"Volume spike: Rule {rule} at {hourly_rate:.0f}/hr (z={z_score:.1f})")
            elif abs(z_score) > 2:
                status = "elevated"

            print(f"  Rule {rule}: {count:4d} events -> {hourly_rate:6.0f}/hr | "
                  f"baseline: {avg:6.0f}/hr (std={std:.0f}) | z={z_score:+.1f} | {status}")
        else:
            print(f"  Rule {rule}: {count:4d} events -> no baseline (unknown rule)")

    # 2. PORT SCAN DETECTION
    print("\n" + "-" * 80)
    print("PORT SCAN DETECTION (IPs hitting many unique ports)")
    print("-" * 80)

    scanners = [(ip, ports) for ip, ports in ip_ports.items() if len(ports) > 5]
    scanners.sort(key=lambda x: len(x[1]), reverse=True)

    if scanners:
        for ip, ports in scanners[:5]:
            ports_list = sorted(ports)
            print(f"  {ip}: {len(ports)} unique ports | "
                  f"{', '.join(str(p) for p in ports_list[:8])}...")
            if len(ports) > 10:
                anomalies.append(f"Port scan: {ip} hit {len(ports)} ports")
    else:
        print("  No port scans detected")

    # 3. IP ANOMALIES
    print("\n" + "-" * 80)
    print("IP ANALYSIS (comparing IP behavior to baselines)")
    print("-" * 80)

    # Find IPs not in baselines (new IPs)
    known_ips = set()
    for key, b in be._baselines.items():
        if b.ip:
            known_ips.add(b.ip)

    new_ips = [ip for ip in ip_counts if ip not in known_ips and ip_counts[ip] > 3]
    if new_ips:
        for ip in sorted(new_ips, key=lambda x: -ip_counts[x])[:10]:
            print(f"  NEW IP: {ip} ({ip_counts[ip]} events)")
            anomalies.append(f"New IP: {ip} with {ip_counts[ip]} events")
    else:
        print("  All active IPs have baselines")

    # 4. PROTOCOL ANOMALIES
    print("\n" + "-" * 80)
    print("PROTOCOL ANALYSIS (checking protocol distributions)")
    print("-" * 80)

    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]:
        baseline = be.get_baseline(rule)
        if baseline and baseline.protocol_distribution:
            # Count protocols for this rule in recent events
            rule_events = [e for e in events if e["rule"] == rule]
            protos = defaultdict(int)
            for e in rule_events:
                if e["protocol"]:
                    protos[e["protocol"]] += 1

            if protos:
                for proto, pcount in protos.items():
                    ratio = pcount / len(rule_events)
                    baseline_ratio = baseline.protocol_distribution.get(proto, 0)
                    shift = abs(ratio - baseline_ratio)
                    if shift > 0.15:  # 15% shift
                        print(f"  Rule {rule}: {proto} shift from {baseline_ratio:.1%} -> {ratio:.1%} "
                              f"(delta={shift:.1%})")
                        if shift > 0.3:
                            anomalies.append(f"Protocol shift: Rule {rule} {proto} {baseline_ratio:.0%}->{ratio:.0%}")

    # 5. BLOCK RATIO ANOMALIES
    print("\n" + "-" * 80)
    print("BLOCK RATIO ANALYSIS")
    print("-" * 80)

    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]:
        baseline = be.get_baseline(rule)
        if baseline:
            rule_events = [e for e in events if e["rule"] == rule]
            blocks = sum(1 for e in rule_events if e["action"] == "block")
            current_block_ratio = blocks / len(rule_events) if rule_events else 0

            if baseline.block_ratio > 0 and current_block_ratio > baseline.block_ratio * 2:
                print(f"  Rule {rule}: block ratio {current_block_ratio:.1%} vs baseline {baseline.block_ratio:.1%} "
                      f"(SPIKE)")
            else:
                print(f"  Rule {rule}: block ratio {current_block_ratio:.1%} (baseline: {baseline.block_ratio:.1%})")

    # SUMMARY
    print("\n" + "=" * 80)
    print(f"DETECTION SUMMARY: {len(anomalies)} anomalies found")
    print("=" * 80)
    if anomalies:
        for a in anomalies[:15]:
            print(f"  [!] {a}")
    else:
        print("  No anomalies detected - traffic is within normal baselines")

if __name__ == "__main__":
    main()