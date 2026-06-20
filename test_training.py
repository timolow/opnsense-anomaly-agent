#!/usr/bin/env python3
"""Test full training pipeline end-to-end."""
from graylog_training_extractor import GraylogTrainingExtractor
from baseline_engine import BaselineEngine
from eventdb import EventDatabase

# Initialize
extractor = GraylogTrainingExtractor()
if not extractor.connect():
    print('Failed to connect to OpenSearch')
    exit(1)

db = EventDatabase()
db.connect()
baseline_engine = BaselineEngine(db)

# Extract and learn
print('Extracting 50000 firewall events...')
events = extractor.extract_firewall_events(sample_size=50000)
print(f'Extracted {len(events)} events')

print('Learning baselines...')
learned = baseline_engine.learn_from_training_data(events)
print(f'Learned {learned} baselines')

print('Saving baselines...')
baseline_engine.save_baselines()

# Verify from database
cur = db.connect().cursor()
cur.execute('SELECT COUNT(*) FROM rule_baselines WHERE rule IS NOT NULL')
count = cur.fetchone()[0]
print(f'Baselines in database: {count}')

cur.execute("""
    SELECT rule, sample_count, avg_events_per_hour
    FROM rule_baselines
    WHERE rule IS NOT NULL
    ORDER BY sample_count DESC
    LIMIT 10
""")
for row in cur.fetchall():
    print(f'  Rule {row[0]}: {row[1]} samples, {row[2]:.1f} events/hr')

cur.close()
print('Training pipeline test PASSED!')