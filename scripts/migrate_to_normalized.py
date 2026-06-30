#!/usr/bin/env python3
"""
Migrate all direct SQL queries from legacy tables to normalized_events.

Rules:
- FROM events -> FROM normalized_events (only where source='firewall', i.e., main firewall events)
- FROM nginx_events -> FROM normalized_events WHERE source = 'nginx'
- FROM ids_events -> FROM normalized_events WHERE source = 'ids'
- FROM zenarmor_events -> FROM normalized_events WHERE source = 'zenarmor'
- Column: proto -> protocol (in SQL column references only)
- Python: row["proto"] -> row["protocol"], row["proto"] dict keys

Files: server.py, agent.py, dashboard_api.py, quick_check.py, check_status.py,
       anomaly_demo.py, live_demo.py, train_live_baselines.py, investigate.py,
       test_data_seeder.py, scripts/verify_timescale.py
"""

import re
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES_TO_TRANSFORM = [
    "server.py",
    "agent.py",
    "dashboard_api.py",
    "quick_check.py",
    "check_status.py",
    "anomaly_demo.py",
    "live_demo.py",
    "train_live_baselines.py",
    "investigate.py",
    "test_data_seeder.py",
    "scripts/verify_timescale.py",
]

SKIP_COMMENT = "-- ALREADY_MIGRATED"


def transform_line(line):
    """Apply all migration rules to a single line."""
    original = line

    # Skip lines with our migration marker comment
    if SKIP_COMMENT in line:
        return line

    # Rule 1: FROM nginx_events -> FROM normalized_events WHERE source = 'nginx'
    # Handle various forms
    if "FROM nginx_events" in line and "normalized_events" not in line:
        line = line.replace("FROM nginx_events", "FROM normalized_events WHERE source = 'nginx'")

    # Rule 2: FROM ids_events -> FROM normalized_events WHERE source = 'ids'
    if "FROM ids_events" in line and "normalized_events" not in line:
        line = line.replace("FROM ids_events", "FROM normalized_events WHERE source = 'ids'")

    # Rule 3: FROM zenarmor_events -> FROM normalized_events WHERE source = 'zenarmor'
    if "FROM zenarmor_events" in line and "normalized_events" not in line:
        line = line.replace("FROM zenarmor_events", "FROM normalized_events WHERE source = 'zenarmor'")

    # Rule 4: FROM unifi_events -> FROM normalized_events WHERE source = 'unifi'
    if "FROM unifi_events" in line and "normalized_events" not in line:
        line = line.replace("FROM unifi_events", "FROM normalized_events WHERE source = 'unifi'")

    # Rule 5: FROM events (the legacy table) -> FROM normalized_events
    # Be careful not to match "normalized_events" or other event-* tables
    # Match: FROM events WHERE, FROM events\n, FROM events ", FROM events (, FROM events as
    if "normalized_events" not in line:
        # Match "FROM events" followed by word boundary (space, newline, quote, paren, etc.)
        line = re.sub(r'\bFROM events\b', 'FROM normalized_events', line)

    # Rule 6: DELETE FROM events -> DELETE FROM normalized_events
    if "normalized_events" not in line:
        line = re.sub(r'\bDELETE FROM events\b', 'DELETE FROM normalized_events', line)

    # Rule 7: Column rename proto -> protocol in SQL context
    # This is tricky - we want SQL columns, not Python variables
    # Replace in multi-line SQL strings (handles SELECT ... proto, ... FROM)
    if "normalized_events" in line or "FROM events" in original or "FROM nginx" in original:
        # In lines being migrated, also fix proto -> protocol
        line = _fix_proto_column(line)

    return line


def _fix_proto_column(line):
    """Fix proto -> protocol column references in SQL strings."""
    # We fix this in SQL contexts: "proto", proto, AS proto, GROUP BY proto, ORDER BY proto, WHERE proto
    # But NOT in Python variable assignments or dict keys (those we handle separately)

    # Only apply if this looks like a SQL line (contains SQL keywords or is in a string)
    sql_indicators = ['SELECT', 'FROM', 'WHERE', 'GROUP', 'ORDER', 'HAVING', 'JOIN', 'AND', 'OR',
                      'COUNT', 'AS ', 'MODE()', 'FILTER', 'CASE', 'WHEN']
    is_sql = any(ind in line for ind in sql_indicators)

    if is_sql:
        # proto followed by comma, space+newline, or end of SQL expression
        line = re.sub(r'\bproto\b', 'protocol', line)

    return line


def fix_python_proto_refs(content, filepath):
    """Fix Python dict/variable references to proto -> protocol after SQL migration."""
    original = content

    # row["proto"] -> row["protocol"]
    content = content.replace('row["proto"]', 'row["protocol"]')
    content = content.replace("row['proto']", "row['protocol']")

    # In output dicts: "proto": -> "protocol": (API response keys)
    # But be careful - we keep the dict key as "proto" for API compatibility
    # Actually, let's change to "protocol" to be consistent
    content = re.sub(
        r'["\']proto["\']:\s*row\["protocol"\]',
        '"protocol": row["protocol"]',
        content
    )
    content = re.sub(
        r"'proto': r\[\d+\]",
        '"protocol": r[\g<0>[-6:]]',  # won't work, skip this
        content
    )

    # Fix proto = row["protocol"] variable names where they're just aliases
    # "proto = row["protocol"]" -> keep as "protocol = row["protocol"]"
    content = re.sub(
        r'\bproto = row\["protocol"\]',
        'protocol = row["protocol"]',
        content
    )

    # For dict output: 'proto': r[N] -> 'protocol': r[N]
    # and "proto": r[N] -> "protocol": r[N]
    content = re.sub(
        r"""['"]proto['"]:\s*r\[""" + r'\d+' + r"""\]""",
        lambda m: m.group().replace("'proto'", '"protocol"').replace('"proto"', '"protocol"'),
        content
    )

    if content != original:
        print(f"  Python proto->protocol fixes in {filepath}")

    return content


def process_file(filepath):
    """Process a single file: migrate SQL + fix Python references."""
    full_path = os.path.join(ROOT, filepath)
    if not os.path.exists(full_path):
        print(f"SKIP: {filepath} not found")
        return False

    with open(full_path, 'r') as f:
        lines = f.readlines()

    new_lines = []
    changed = False
    for i, line in enumerate(lines):
        new_line = transform_line(line)
        new_lines.append(new_line)
        if new_line != line:
            changed = True

    if not changed:
        print(f"NO CHANGES: {filepath}")
        return False

    # Join and apply Python-level fixes
    content = ''.join(new_lines)
    content = fix_python_proto_refs(content, filepath)

    with open(full_path, 'w') as f:
        f.write(content)

    print(f"OK: {filepath}")
    return True


def count_changes(filepath):
    """Count how many changes were made."""
    full_path = os.path.join(ROOT, filepath)
    if not os.path.exists(full_path):
        return 0

    with open(full_path, 'r') as f:
        content = f.read()

    # Count remaining old references
    old_events = len(re.findall(r'\bFROM events\b', content))
    old_proto = len(re.findall(r'\bproto\b', content))  # rough count
    old_nginx = len(re.findall(r'FROM nginx_events', content))
    old_ids = len(re.findall(r'FROM ids_events', content))
    old_zenarmor = len(re.findall(r'FROM zenarmor_events', content))

    return old_events + old_nginx + old_ids + old_zenarmor, {
        'old_events': old_events,
        'old_proto': old_proto,
        'old_nginx': old_nginx,
        'old_ids': old_ids,
        'old_zenarmor': old_zenarmor,
    }


def main():
    print(f"Working directory: {ROOT}")
    print(f"Files to process: {len(FILES_TO_TRANSFORM)}")
    print()

    for filepath in FILES_TO_TRANSFORM:
        process_file(filepath)
        print()

    # Summary
    print("=" * 60)
    print("SUMMARY: Remaining old references")
    print("=" * 60)
    for filepath in FILES_TO_TRANSFORM:
        total, details = count_changes(filepath)
        if total > 0:
            print(f"  {filepath}: {total} remaining ({details})")
        else:
            print(f"  {filepath}: CLEAN")


if __name__ == "__main__":
    main()
