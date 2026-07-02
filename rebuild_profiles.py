#!/usr/bin/env python3
"""
Bulk rebuild IP behavior profiles from events table.
Fix: use dst_port (not dport), src_port (not sport).
"""

import json
import logging
import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)


def rebuild_profiles():
    conn = psycopg2.connect(
        host='postgres', port=5432,
        dbname='opnsense', user='opnsense', password='opnsense'
    )
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # 1. Get all IPs with >10 events
    cur.execute("""
        SELECT src_ip, COUNT(*) as cnt
        FROM events
        GROUP BY src_ip
        HAVING COUNT(*) > 10
        ORDER BY cnt DESC
    """)
    ip_rows = cur.fetchall()
    print(f"Found {len(ip_rows)} IPs with >10 events")

    rebuilt = 0
    errors = 0

    for row in ip_rows:
        ip = row['src_ip']
        if not ip or ip == '':
            continue
        try:
            # Aggregates
            cur.execute("""
                SELECT COUNT(*) as total_events,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       COALESCE(SUM(ip_total_length), 0) as total_bytes
                FROM events WHERE src_ip = %(ip)s
            """, {'ip': ip})
            agg = cur.fetchone()

            # Actions
            cur.execute("""
                SELECT action, COUNT(*) as cnt
                FROM events WHERE src_ip = %(ip)s
                AND action IS NOT NULL AND action != ''
                GROUP BY action
            """, {'ip': ip})
            actions = {r['action']: r['cnt'] for r in cur.fetchall()}

            # Dest ports
            cur.execute("""
                SELECT dst_port, COUNT(*) as cnt
                FROM events WHERE src_ip = %(ip)s AND dst_port IS NOT NULL
                GROUP BY dst_port ORDER BY cnt DESC LIMIT 50
            """, {'ip': ip})
            dst_ports = {str(r['dst_port']): r['cnt'] for r in cur.fetchall()}

            # Dest IPs
            cur.execute("""
                SELECT dst_ip, COUNT(*) as cnt
                FROM events WHERE src_ip = %(ip)s
                AND dst_ip IS NOT NULL AND dst_ip != ''
                GROUP BY dst_ip ORDER BY cnt DESC LIMIT 50
            """, {'ip': ip})
            dst_ips = {r['dst_ip']: r['cnt'] for r in cur.fetchall()}

            # Protocols
            cur.execute("""
                SELECT proto, COUNT(*) as cnt
                FROM events WHERE src_ip = %(ip)s
                AND proto IS NOT NULL AND proto != ''
                GROUP BY proto
            """, {'ip': ip})
            protocols = {r['proto']: r['cnt'] for r in cur.fetchall()}

            # Interfaces
            cur.execute("""
                SELECT interface, COUNT(*) as cnt
                FROM events WHERE src_ip = %(ip)s
                AND interface IS NOT NULL AND interface != ''
                GROUP BY interface
            """, {'ip': ip})
            interfaces = {r['interface']: r['cnt'] for r in cur.fetchall()}

            # Hour distribution
            cur.execute("""
                SELECT EXTRACT(HOUR FROM timestamp)::int as h, COUNT(*) as cnt
                FROM events WHERE src_ip = %(ip)s
                GROUP BY h
            """, {'ip': ip})
            hour_dist = {str(r['h']): r['cnt'] for r in cur.fetchall()}

            profile_data = {
                'actions': actions,
                'dst_ports': dst_ports,
                'dst_ips': dst_ips,
                'protocols': protocols,
                'interfaces': interfaces,
                'hour_distribution': hour_dist,
                'daily_distribution': {},
                'total_bytes': agg['total_bytes'],
                'total_packets': agg['total_events'],
                'countries': {},
                'unique_dst_ports': len(dst_ports),
                'unique_dst_ips': len(dst_ips),
                'nginx_paths': {},
                'ids_signatures': {},
                'zenarmor_policies': {},
                'firewall_events': agg['total_events'],
                'http_events': 0,
                'ids_events': 0,
                'zenarmor_events': 0,
                'nginx_events': 0,
                'blocked_events': actions.get('block', 0) + actions.get('BLOCK', 0),
            }

            cur.execute("""
                INSERT INTO ip_behavior_profiles
                    (ip, first_seen, last_seen, profile_data, baseline_data,
                     threat_level, total_events, behavior_score, updated_at)
                VALUES (%(ip)s, %(first_seen)s, %(last_seen)s, %(profile_data)s::jsonb,
                        %(baseline_data)s::jsonb, 'info', %(total_events)s, 0.0, NOW())
                ON CONFLICT (ip) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    profile_data = EXCLUDED.profile_data,
                    total_events = EXCLUDED.total_events,
                    behavior_score = 0.0,
                    updated_at = NOW()
            """, {
                'ip': ip,
                'first_seen': agg['first_seen'],
                'last_seen': agg['last_seen'],
                'profile_data': json.dumps(profile_data),
                'baseline_data': '{}',
                'total_events': agg['total_events'],
            })

            rebuilt += 1
            if rebuilt % 100 == 0:
                print(f"  Rebuilt {rebuilt} profiles...")

        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"  Failed for {ip}: {e}")
            conn.rollback()

        conn.commit()

    print(f"\nDone: rebuilt={rebuilt}, errors={errors}")
    cur.close()
    conn.close()
    return rebuilt, errors


def compute_scores():
    conn = psycopg2.connect(
        host='postgres', port=5432,
        dbname='opnsense', user='opnsense', password='opnsense'
    )
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT ip, total_events,
               profile_data->>'actions' as actions_json,
               profile_data->>'dst_ports' as dst_ports_json,
               profile_data->>'dst_ips' as dst_ips_json,
               (profile_data->>'total_bytes')::bigint as total_bytes,
               (profile_data->>'blocked_events')::bigint as blocked_events
        FROM ip_behavior_profiles
        WHERE total_events >= 10
    """)

    scored = 0
    for row in cur.fetchall():
        ip = row['ip']
        total_events = row['total_events']
        if total_events < 10:
            continue

        try:
            actions = json.loads(row['actions_json']) if row['actions_json'] else {}
            dst_ports = json.loads(row['dst_ports_json']) if row['dst_ports_json'] else {}
            dst_ips = json.loads(row['dst_ips_json']) if row['dst_ips_json'] else {}
            total_bytes = row['total_bytes'] or 0
            blocked_events = row['blocked_events'] or 0
        except Exception:
            continue

        block_ratio = blocked_events / max(total_events, 1)
        score = 0.0

        if block_ratio > 0.8:
            score += 30
        elif block_ratio > 0.5:
            score += 15
        elif block_ratio > 0.2:
            score += 5

        port_diversity = len(dst_ports) / max(total_events, 1)
        if port_diversity > 0.5:
            score += 30
        elif port_diversity > 0.2:
            score += 15
        elif port_diversity > 0.05:
            score += 5

        dst_diversity = len(dst_ips) / max(total_events, 1)
        if dst_diversity > 0.5:
            score += 20
        elif dst_diversity > 0.2:
            score += 10

        if total_events > 100:
            avg_bytes = total_bytes / max(total_events, 1)
            if avg_bytes > 10000:
                score += 20
            elif avg_bytes > 5000:
                score += 10

        score = round(min(score, 100.0), 1)

        if score >= 80:
            threat_level = 'critical'
        elif score >= 50:
            threat_level = 'high'
        elif score >= 20:
            threat_level = 'medium'
        elif score > 0:
            threat_level = 'low'
        else:
            threat_level = 'info'

        cur.execute("""
            UPDATE ip_behavior_profiles
            SET behavior_score = %s, threat_level = %s, updated_at = NOW()
            WHERE ip = %s
        """, (score, threat_level, ip))
        scored += 1

    conn.commit()
    print(f"Scored {scored} profiles")

    cur.execute("""
        SELECT
            CASE
                WHEN behavior_score = 0 THEN '0'
                WHEN behavior_score BETWEEN 0.1 AND 10 THEN '0.1-10'
                WHEN behavior_score BETWEEN 10 AND 30 THEN '10-30'
                WHEN behavior_score BETWEEN 30 AND 60 THEN '30-60'
                WHEN behavior_score > 60 THEN '60+'
            END as bucket, COUNT(*)
        FROM ip_behavior_profiles
        GROUP BY bucket ORDER BY bucket
    """)
    print("\nScore distribution:")
    for r in cur.fetchall():
        print(f"  {r['bucket']:<10s} {r['count']} profiles")

    cur.execute("""
        SELECT ip, total_events, behavior_score, threat_level
        FROM ip_behavior_profiles
        ORDER BY behavior_score DESC LIMIT 10
    """)
    print("\nTop 10 scoring IPs:")
    for r in cur.fetchall():
        print(f"  {r['ip'][:35]:<35s} score={r['behavior_score']:.1f} events={r['total_events']} level={r['threat_level']}")

    cur.close()
    conn.close()


if __name__ == '__main__':
    print("=== PHASE 1: Rebuilding profiles ===")
    rebuild_profiles()
    print("\n=== PHASE 2: Computing scores ===")
    compute_scores()
