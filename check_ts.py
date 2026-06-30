#!/usr/bin/env python3
"""Check timestamps."""
from eventdb import EventDatabase
db = EventDatabase()
db.connect()
cur = db.connect().cursor()
cur.execute("SELECT MAX(timestamp), NOW(), COUNT(*) FROM normalized_events")
row = cur.fetchone()
print(f"Max event timestamp: {row[0]}")
print(f"Current time:        {row[1]}")
print(f"Total events:        {row[2]}")

# Check some recent events
cur.execute("SELECT timestamp, rule_name, src_ip FROM normalized_events ORDER BY id DESC LIMIT 5")
for r in cur.fetchall():
    print(f"  ts={r[0]} rule={r[1]} src={r[2]}")

cur.close()