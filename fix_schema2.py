#!/usr/bin/env python3
"""Fix rule_baselines table: drop NOT NULL constraint on legacy columns."""
from eventdb import EventDatabase

db = EventDatabase()
db.connect()
conn = db.connect()
cur = conn.cursor()

# Drop NOT NULL constraint on rule_name (legacy column, we use 'rule' now)
try:
    cur.execute("ALTER TABLE rule_baselines ALTER COLUMN rule_name DROP NOT NULL")
    print("Dropped NOT NULL constraint on rule_name")
except Exception as e:
    print(f"rule_name constraint error: {e}")

# Set default for rule_name to match rule
try:
    cur.execute("ALTER TABLE rule_baselines ALTER COLUMN rule_name SET DEFAULT ''")
    print("Set default for rule_name")
except Exception as e:
    print(f"rule_name default error: {e}")

# Verify
cur.execute("""
    SELECT column_name, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_name = 'rule_baselines' AND column_name = 'rule_name'
""")
for row in cur.fetchall():
    print(f"rule_name: nullable={row[1]}, default={row[2]}")

cur.close()
print("Schema fix complete!")