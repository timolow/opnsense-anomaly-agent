#!/usr/bin/env python3
"""
Self-contained anomaly detection demo.
Loads baselines, pulls recent events, analyzes them.
"""
import json
from collections import defaultdict

def main():
    from eventdb import EventDatabase
    db = EventDatabase()
    db.connect()

    print("=" * 80)
    print("ANOMALY DETECTION DEMO")
    print("=" * 80)

    # Load baselines from DB
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule, ip, hour, avg_events_per_hour, std_events_per_hour,
               max_events_per_hour, min_events_per_hour, protocol_distribution,
               avg_dst_ports, avg_src_ports, avg_unique_dst_ips, pass_ratio,
               block_ratio, hourly_distribution, sample_count
        FROM rule_baselines WHERE rule IS NOT NULL
    """)

    baselines = {}
    for row in cur.fetchall():
        rule = row[0]
        ip = row[1]
        proto = row[7] if isinstance(row[7], dict) else json.loads(row[7]) if isinstance(row[7], str) else {}
        hourly = row[13] if isinstance(row[13], list) else json.loads(row[13]) if isinstance(row[13], str) else []
        key = f"{rule}:{ip}" if ip else rule
        baselines[key] = {
            "rule": rule, "ip": ip, "hour": row[2],
            "avg": row[3] or 0, "std": row[4] or 0,
            "max": row[5] or 0, "min": row[6] or 0,
            "proto": proto, "ports": row[8] or 0,
            "pass_r": row[11] or 0, "block_r": row[12] or 0,
            "hourly": hourly, "samples": row[14] or 0
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
        print(f"Rule {b['rule']:6s}: {b['samples']:6,} samples | avg={b['avg']:7.0f}/hr std={b['std']:6.0f} | "
              f"max={b['max']:5} | pass={b['pass_r']:.0%} block={b['block_r']:.0%}")
        print(f"         Protocols: {protos}")
        print(f"         Peak: {peak_h}:00 ({max(b['hourly'])} events)" if b["hourly"] else "")

    # Pull recent events
    cur = db.connect().cursor()
    cur.execute("""
        SELECT rule_name, src_ip, dst_port, protocol, action
        FROM events WHERE timestamp > NOW() - INTERVAL '5 minutes'
        ORDER BY timestamp DESC
    """)
    events = [{"rule": r[0] or "", "src_ip": r[1] or "", "dst_port": r[2], "proto": r[3] or "", "action": r[4] or ""} for r in cur.fetchall()]
    cur.close()

    print(f"\n--- RECENT EVENTS (5 min) ---")
    print(f"Events: {len(events)} | Rules: {len(set(e['rule'] for e in events))} | IPs: {len(set(e['src_ip'] for e in events))}")

    if not events:
        print("No recent events - agent may not be receiving syslog.")
        return

    # Collect stats
    rule_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    ip_ports = defaultdict(set)
    rule_protos = defaultdict(lambda: defaultdict(int))

    for e in events:
        rule_counts[e["rule"]] += 1
        ip_counts[e["src_ip"]] += 1
        if e["src_ip"] and e["dst_port"]:
            ip_ports[e["src_ip"]].add(e["dst_port"])
        if e["rule"] and e["proto"]:
            rule_protos[e["rule"]][e["proto"]] += 1

    anomalies = []

    # 1. Volume analysis
    print("\n" + "-" * 80)
    print("VOLUME ANALYSIS")
    print("-" * 80)

    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        b = baselines.get(rule)
        if b:
            hourly = count * 12  # extrapolate 5min -> 60min
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
            elif abs(z) >= 1:
                sev = "ELEVATED"

            print(f"Rule {rule:6s}: {count:4d} events ({hourly:6.0f}/hr) | "
                  f"baseline: {b['avg']:7.0f}/hr (std={std:.0f}) | z={z:+.1f} [{sev}]{marker}")
        else:
            print(f"Rule {rule:6s}: {count:4d} events | NO BASELINE (unknown rule)")
            anomalies.append({"type": "no_baseline", "rule": rule, "count": count, "sev": "LOW"})

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

    # 4. Protocol anomaly detection
    print("\n" + "-" * 80)
    print("PROTOCOL ANOMALY DETECTION")
    print("-" * 80)

    found_proto = False
    for rule, protos in sorted(rule_protos.items(), key=lambda x: -sum(x[1].values()))[:5]:
        b = baselines.get(rule)
        if b and b["proto"]:
            total = sum(protos.values())
            for proto, cnt in protos.items():
                actual = cnt / total
                baseline_r = b["proto"].get(proto, 0)
                shift = abs(actual - baseline_r)
                if shift > 0.15:
                    found_proto = True
                    sev = "HIGH" if shift > 0.3 else "MEDIUM"
                    anomalies.append({"type": "protocol_shift", "rule": rule, "proto": proto, "shift": shift, "sev": sev})
                    marker = " *** ANOMALY ***" if sev == "HIGH" else ""
                    print(f"Rule {rule}: {proto} actual={actual:.1%} vs baseline={baseline_r:.1%} (shift={shift:.1%}) [{sev}]{marker}")

    if not found_proto:
        print("No protocol anomalies detected")

    # 5. Block ratio analysis
    print("\n" + "-" * 80)
    print("BLOCK RATIO ANALYSIS")
    print("-" * 80)

    found_block = False
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]:
        b = baselines.get(rule)
        if b:
            rule_events = [e for e in events if e["rule"] == rule]
            blocks = sum(1 for e in rule_events if e["action"] == "block")
            current_block = blocks / len(rule_events) if rule_events else 0

            if b["block_r"] > 0 and current_block > b["block_r"] * 3:
                found_block = True
                anomalies.append({"type": "block_spike", "rule": rule, "baseline": b["block_r"], "current": current_block, "sev": "HIGH"})
                print(f"Rule {rule}: block ratio {current_block:.1%} vs baseline {b['block_r']:.1%} *** SPIKE ***")
            else:
                print(f"Rule {rule}: block ratio {current_block:.1%} (baseline: {b['block_r']:.1%})")

    if not found_block:
        print("No block ratio anomalies")

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