#!/usr/bin/env python3
"""Fix rule_baselines table schema."""
from eventdb import EventDatabase

db = EventDatabase()
db.connect()

conn = db.connect()
cur = conn.cursor()

try:
    # Check existing columns
    cur.execute('''
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = 'rule_baselines'
    ''')
    existing = {row[0] for row in cur.fetchall()}
    print('Existing columns:', existing)
    
    # Add missing columns
    columns_to_add = [
        ('rule', 'TEXT'),
        ('ip', 'TEXT'),
        ('hour', 'INTEGER'),
        ('avg_events_per_hour', 'DOUBLE PRECISION'),
        ('std_events_per_hour', 'DOUBLE PRECISION'),
        ('max_events_per_hour', 'INTEGER'),
        ('min_events_per_hour', 'INTEGER'),
        ('protocol_distribution', 'JSONB'),
        ('avg_dst_ports', 'DOUBLE PRECISION'),
        ('avg_src_ports', 'DOUBLE PRECISION'),
        ('avg_unique_dst_ips', 'DOUBLE PRECISION'),
        ('pass_ratio', 'DOUBLE PRECISION'),
        ('block_ratio', 'DOUBLE PRECISION'),
        ('hourly_distribution', 'JSONB'),
        ('sample_count', 'INTEGER'),
        ('last_updated', 'TIMESTAMPTZ'),
    ]
    
    added = []
    for col_name, col_type in columns_to_add:
        if col_name not in existing:
            cur.execute(f'ALTER TABLE rule_baselines ADD COLUMN {col_name} {col_type}')
            added.append(col_name)
    
    print('Added columns:', added)
    
    # Add unique constraint if not exists
    try:
        cur.execute('ALTER TABLE rule_baselines ADD CONSTRAINT unique_rule_baselines UNIQUE (rule, ip, hour)')
        print('Added unique constraint')
    except Exception as e:
        print('Constraint error (may already exist):', e)
        
except Exception as e:
    print('Error:', e)
finally:
    cur.close()