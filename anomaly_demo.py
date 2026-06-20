#!/usr/bin/env python3
"""
Anomaly Detection Demo - Real-time event analysis against learned baselines.

Loads baselines from DB, pulls recent events, and shows what the system detects.
"""
import json
from collections import defaultdict

# Fix for JSONB columns returning native Python types
def safe_json_loads(value):
    """Handle psycopg2 JSONB columns that are already dicts/lists."""
    if isinstance(value, (dict, list)):
        return value
    elif isinstance(value, str):
        return json.loads(value)
    return []

def safe_datetime(value):
    """Handle psycopg2 timestamp columns."""
    if isinstance(value, str):
        from datetime import datetime
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value  # Already a datetime

class Baseline:
    """Simple baseline class."""
    def __init__(self, row):
        self.rule = row[0]
        self.ip = row[1]
        self.hour = row[2]
        self.avg_events_per_hour = row[3] or 0
        self.std_events_per_hour = row[4] or 0
        self.max_events_per_hour = row[5] or 0
        self.min_events_per_hour = row[6] or 0
        self.protocol_distribution = safe_json_loads(row[7])
        self.avg_dst_ports = row[8] or 0
        self.avg_src_ports = row[9] or 0
        self.avg_unique_dst_ips = row[10] or 0
        self.pass_ratio = row[11] or 0
        self.block_ratio = row[12] or 0
        self.hourly_distribution = safe_json_loads(row[13])
        self.sample_count = row[14] or 0
        self.last_updated = safe_datetime(row[15])

    def confidence_score(self):
        if self.sample_count < 10:
            return 0.0
        import math
        return min(1.0, math.log(self.sample_count) / math.log(1000))

def main():
    print("=" * 80)
    print("ANOMALY DETECTION DEMO - LIVE EVENTS vs LEARNED BASELINES")
    print("=" * 80)

    # Connect to DB
    from eventdb import EventDatabase
    db = EventDatabase()
    db.connect()

    # Load baselines
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule, ip, hour, avg_events_per_hour, std_events_per_hour,
               max_events_per_hour, min_events_per_hour, protocol_distribution,
               avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio,
               block_ratio, hourly_distribution, sample_count, last_updated
        FROM rule_baselines
        WHERE rule IS NOT NULL
    """)

    baselines = {}
    for row in cur.fetchall():
        b = Baseline(row)
        key = b.rule
        if b.ip:
            key = f"{b.rule}:{b.ip}"
        baselines[key] = b

    cur.close()
    print(f"\nLoaded {len(baselines)} baselines")

    # Show top baselines
    rule_baselines = {k: v for k, v in baselines.items() if v.ip is None}
    print(f"Rule-level baselines: {len(rule_baselines)}")

    top_rules = sorted(rule_baselines.values(), key=lambda b: b.sample_count, reverse=True)[:5]
    print("\n--- TOP BASELINES ---")
    for b in top_rules:
        print(f"Rule {b.rule:6s}: {b.sample_count:6,} samples | avg={b.avg_events_per_hour:7.0f}/hr "
              f"std={b.std_events_per_hour:6.0f} | max={b.max_events_per_hour:5} "
              f"pass={b.pass_ratio:.0%} block={b.block_ratio:.0%}")
        if b.protocol_distribution:
            protos = ", ".join(f"{k}={v:.0%}" for k, v in sorted(b.protocol_distribution.items(), key=lambda x: -x[1])[:3])
            print(f"         Protocols: {protos}")
        if b.hourly_distribution:
            peak = max(range(24), key=lambda h: b.hourly_distribution[h])
            print(f"         Peak hour: {peak}:00 ({max(b.hourly_distribution)} events)")

    # Pull recent events
    print("\n--- PULLING RECENT EVENTS ---")
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule_name, src_ip, dst_ip, src_port, dst_port, protocol, action, timestamp
        FROM events
        WHERE timestamp > NOW() - INTERVAL '5 minutes'
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
        })
    cur.close()
    print(f"Recent events (5 min window): {len(events)}")

    if not events:
        print("No recent events - waiting for syslog data...")
        return

    # Analyze events
    rule_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    ip_ports = defaultdict(set)
    rule_protos = defaultdict(lambda: defaultdict(int))

    for e in events:
        rule_counts[e["rule"]] += 1
        ip_counts[e["src_ip"]] += 1
        if e["src_ip"] and e["dst_port"]:
            ip_ports[e["src_ip"]].add(e["dst_port"])
        if e["rule"] and e["protocol"]:
            rule_protos[e["rule"]][e["protocol"]] += 1

    anomalies = []

    # 1. Volume anomalies
    print("\n--- VOLUME ANALYSIS ---")
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        baseline = baselines.get(rule)
        if baseline:
            # Extrapolate to hourly rate
            hourly_rate = count * 12  # 5 min -> 60 min
            avg = baseline.avg_events_per_hour
            std = baseline.std_events_per_hour or (avg * 0.5)
            z_score = (hourly_rate - avg) / std if std > 0 else 0

            status = "OK"
            severity = "LOW"
            if abs(z_score) > 3:
                status = "*** CRITICAL SPIKE ***"
                severity = "CRITICAL"
                anomalies.append(f"Volume CRITICAL: Rule {rule} at {hourly_rate:.0f}/hr (z={z_score:.1f})")
            elif abs(z_score) > 2:
                status = "** HIGH ANOMALY **"
                severity = "HIGH"
                anomalies.append(f"Volume HIGH: Rule {rule} at {hourly_rate:.0f}/hr (z={z_score:.1f})")
            elif abs(z_score) > 1:
                status = "* MODERATE *"
                severity = "MEDIUM"

            print(f"Rule {rule:6s}: {count:4d} events ({hourly_rate:6.0f}/hr) | "
                  f"baseline: {avg:7.0f}/hr (std={std:.0f}) | z={z_score:+.1f} | [{severity}] {status}")
        else:
            print(f"Rule {rule:6s}: {count:4d} events | NO BASELINE (unknown rule)")

    # 2. Port scan detection
    print("\n--- PORT SCAN DETECTION ---")
    scanners = [(ip, ports) for ip, ports in ip_ports.items() if len(ports) > 5]
    scanners.sort(key=lambda x: len(x[1]), reverse=True)

    if scanners:
        for ip, ports in scanners[:5]:
            ports_list = sorted(ports)
            severity = "LOW"
            if len(ports) > 20:
                severity = "CRITICAL"
                anomalies.append(f"Port scan CRITICAL: {ip} hit {len(ports)} ports")
            elif len(ports) > 10:
                severity = "HIGH"
                anomalies.append(f"Port scan HIGH: {ip} hit {len(ports)} ports")
            elif len(ports) > 5:
                severity = "MEDIUM"

            print(f"{ip}: {len(ports)} unique ports | {severity} | "
                  f"{', '.join(str(p) for p in ports_list[:8])}...")
    else:
        print("No port scan patterns detected")

    # 3. IP anomaly detection
    print("\n--- IP ANOMALY DETECTION ---")
    known_ips = set()
    for b in baselines.values():
        if b.ip:
            known_ips.add(b.ip)

    new_ips = [ip for ip in ip_counts if ip not in known_ips and ip_counts[ip] > 3]
    if new_ips:
        for ip in sorted(new_ips, key=lambda x: -ip_counts[x])[:10]:
            print(f"NEW IP: {ip} ({ip_counts[ip]} events) | NO BASELINE")
            anomalies.append(f"New IP: {ip} with {ip_counts[ip]} events")
    else:
        print("All active IPs have baselines")

    # 4. Protocol anomaly detection
    print("\n--- PROTOCOL ANOMALY DETECTION ---")
    for rule, protos in sorted(rule_protos.items(), key=lambda x: -sum(x[1].values()))[:5]:
        baseline = baselines.get(rule)
        if baseline and baseline.protocol_distribution:
            total = sum(protos.values())
            for proto, count in protos.items():
                actual_ratio = count / total
                baseline_ratio = baseline.protocol_distribution.get(proto, 0)
                shift = abs(actual_ratio - baseline_ratio)
                if shift > 0.15:
                    print(f"Rule {rule}: {proto} actual={actual_ratio:.1%} vs baseline={baseline_ratio:.1%} "
                          f"(shift={shift:.1%}) ** ANOMALY **")
                    anomalies.append(f"Protocol shift: Rule {rule} {proto} {baseline_ratio:.0%}->{actual_ratio:.0%}")

    # 5. Block ratio anomalies
    print("\n--- BLOCK RATIO ANALYSIS ---")
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]:
        baseline = baselines.get(rule)
        if baseline:
            rule_events = [e for e in events if e["rule"] == rule]
            blocks = sum(1 for e in rule_events if e["action"] == "block")
            current_block_ratio = blocks / len(rule_events) if rule_events else 0
            baseline_block = baseline.block_ratio

            if baseline_block > 0 and current_block_ratio > baseline_block * 3:
                print(f"Rule {rule}: block ratio {current_block_ratio:.1%} vs baseline {baseline_block:.1%} *** SPIKE ***")
                anomalies.append(f"Block ratio spike: Rule {rule} {baseline_block:.0%}->{current_block_ratio:.0%}")
            else:
                print(f"Rule {rule}: block ratio {current_block_ratio:.1%} (baseline: {baseline_block:.1%})")

    # Summary
    print("\n" + "=" * 80)
    print(f"SUMMARY: {len(anomalies)} anomalies detected")
    print("=" * 80)
    if anomalies:
        for a in anomalies[:15]:
            print(f"  [!] {a}")
    else:
        print("  No anomalies detected - traffic matches learned baselines")

if __name__ == "__main__":
    main()