#!/usr/bin/env python3
"""Inspect rule_baselines table schema."""
from eventdb import EventDatabase

db = EventDatabase()
db.connect()
conn = db.connect()
cur = conn.cursor()

cur.execute("""
    SELECT column_name, data_type, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_name = 'rule_baselines'
    ORDER BY ordinal_position
""")
for row in cur.fetchall():
    print(f'{row[0]:30s} {row[1]:20s} nullable={row[2]} default={row[3]}')

cur.close()