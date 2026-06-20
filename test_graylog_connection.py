#!/usr/bin/env python3
"""
Test script for Graylog/OpenSearch connection and training pipeline.

Usage:
    python test_graylog_connection.py
"""

import json
import sys
from datetime import datetime, timezone

def test_connection():
    """Test connection to OpenSearch cluster."""
    try:
        from opensearchpy import OpenSearch
        
        hosts = [
            "http://192.168.1.32:9200",
            "http://192.168.1.33:9200",
            "http://192.168.1.35:9200"
        ]
        
        es = OpenSearch(
            hosts=hosts,
            http_auth=("elastic", "changeme"),
            verify_certs=False
        )
        
        # Test connection
        info = es.info()
        print("✓ Connected to OpenSearch cluster")
        print(f"  Version: {info.get('version', {}).get('number', 'unknown')}")
        print(f"  Cluster name: {info.get('cluster_name', 'unknown')}")
        
        # Get index stats
        indices = es.indices.get(index="*")
        print(f"\n✓ Found {len(indices)} indices")
        
        # Show firewall indices
        firewall_indices = [i for i in indices if "filterlog" in i]
        print(f"  Firewall indices: {len(firewall_indices)}")
        
        for idx in firewall_indices[:5]:
            try:
                stats = es.indices.stats(index=idx)
                for i in stats['indices']:
                    docs = i['primaries']['docs']
                    store = i['primaries']['store']
                    print(f"    {idx}: {docs.get('count', 0):,} docs, {store.get('size_in_bytes', 0) / (1024*1024):.1f} MB")
            except Exception as e:
                print(f"    {idx}: stats failed - {e}")
        
        # Get sample firewall event
        print("\n✓ Sample firewall event:")
        result = es.search(
            index="opnsense_filterlog-351",
            body={
                "size": 1,
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}]
            }
        )
        
        if result['hits']['hits']:
            event = result['hits']['hits'][0]['_source']
            print(json.dumps(event, indent=2, default=str)[:500])
        
        return True
        
    except ImportError:
        print("✗ opensearch-py not installed. Run: pip install opensearch-py")
        return False
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_training_pipeline():
    """Test the training pipeline."""
    try:
        from graylog_training_extractor import GraylogTrainingExtractor
        from baseline_engine import BaselineEngine
        from eventdb import EventDatabase
        
        print("\n✓ Testing training pipeline...")
        
        # Initialize components
        extractor = GraylogTrainingExtractor()
        if not extractor.connect():
            print("  ✗ Failed to connect to OpenSearch")
            return False
        
        # Initialize database
        db = EventDatabase()
        db.connect()
        
        # Initialize baseline engine
        baseline_engine = BaselineEngine(db)
        
        print("  ✓ All components initialized")
        
        # Extract sample data
        print("\n  Extracting sample data...")
        firewall_events = extractor.extract_firewall_events(sample_size=1000)
        print(f"  ✓ Extracted {len(firewall_events)} firewall events")
        
        # Learn baselines
        if firewall_events:
            print("\n  Learning baselines...")
            baselines_learned = baseline_engine.learn_from_training_data(firewall_events)
            print(f"  ✓ Learned {baselines_learned} baselines")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("Graylog/OpenSearch Connection Test")
    print("=" * 50)
    
    # Test connection
    if not test_connection():
        print("\nConnection test failed. Exiting.")
        return 1
    
    # Test pipeline
    if not test_training_pipeline():
        print("\nPipeline test failed. Exiting.")
        return 1
    
    print("\n" + "=" * 50)
    print("All tests passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())