#!/usr/bin/env python3
"""Fix incident narratives with actual behavioral data."""

import json
import psycopg2
import psycopg2.extras

conn = psycopg2.connect(
    host='postgres', port=5432,
    dbname='opnsense', user='opnsense', password='opnsense'
)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

cur.execute("""
    SELECT i.id, i.ip, i.signal_count, i.signal_types, i.severity
    FROM incidents i
    WHERE i.is_active
    ORDER BY i.signal_count DESC
    LIMIT 200
""")
incidents = cur.fetchall()

fixed = 0
for inc in incidents:
    ip = inc['ip']
    # Look up profile
    cur.execute("""
        SELECT behavior_score, threat_level, total_events, profile_data
        FROM ip_behavior_profiles WHERE ip = %s
    """, (ip,))
    profile = cur.fetchone()

    if not profile or not profile['profile_data']:
        continue

    try:
        pd = profile['profile_data']
        if isinstance(pd, str):
            pd = json.loads(pd)
    except Exception:
        continue

    score = profile['behavior_score'] or 0
    level = profile['threat_level'] or 'info'
    events = profile['total_events'] or 0
    actions = pd.get('actions', {})
    dst_ports = pd.get('dst_ports', {})
    dst_ips = pd.get('dst_ips', {})
    protocols = pd.get('protocols', {})
    blocked = actions.get('block', 0) + actions.get('BLOCK', 0)
    passed = actions.get('pass', 0) + actions.get('PASS', 0)
    unique_ports = len(dst_ports)
    unique_ips = len(dst_ips)
    proto_list = ', '.join(list(protocols.keys())[:3])
    block_ratio = blocked / max(events, 1)

    # Build narrative
    narrative = f"IP {ip[:30]} has behavior score {score}/100 ({level} level). "
    narrative += f"Over {events:,} events: {blocked} blocked, {passed} passed. "
    narrative += f"Targeting {unique_ports} unique ports across {unique_ips} destinations via {proto_list}."

    # Build explanation
    explanation = ""
    if block_ratio > 0.8:
        explanation += "Heavily blocked by firewall (>80% block rate) - aggressive attacker. "
    elif block_ratio > 0.5:
        explanation += "More than half of traffic blocked - likely hostile. "
    elif block_ratio > 0.2:
        explanation += "Significant portion blocked - suspicious activity. "

    if unique_ports > 20:
        explanation += f"High port diversity ({unique_ports} ports) suggests scanning or reconnaissance. "
    elif unique_ports > 5:
        explanation += f"Moderate port diversity ({unique_ports} ports). "

    if unique_ips > 10:
        explanation += f"Spreading across {unique_ips} destinations - possible lateral movement. "

    if score >= 60:
        explanation += "HIGH PRIORITY: Score indicates significant threat behavior."
    elif score >= 30:
        explanation += "MEDIUM PRIORITY: Elevated threat indicators warrant investigation."
    elif score >= 10:
        explanation += "LOW PRIORITY: Minor anomalies detected, monitor for escalation."

    signal_types = inc.get('signal_types', []) or []
    if signal_types:
        explanation += f" Signals detected: {', '.join(signal_types[:5])}."

    if not explanation:
        explanation = f"Behavioral analysis: {events:,} events processed. {proto_list} traffic. Block ratio: {block_ratio:.1%}."

    cur.execute("""
        UPDATE incidents
        SET narrative = %s, explanation = %s
        WHERE id = %s
    """, (narrative, explanation, inc['id']))
    fixed += 1

conn.commit()
print(f"Updated {fixed} incidents with detailed narratives")

# Verify
cur.execute("""
    SELECT id, ip, narrative, explanation
    FROM incidents WHERE is_active ORDER BY signal_count DESC LIMIT 3
""")
for r in cur.fetchall():
    print(f"\n--- ID {r['id']} IP {r['ip']} ---")
    print(f"Narrative: {r['narrative'][:150]}")
    print(f"Explanation: {r['explanation'][:200]}")

cur.close()
conn.close()
