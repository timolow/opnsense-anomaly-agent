#!/usr/bin/env python3
"""
Graylog Training Pipeline

Extracts historical data from Graylog/OpenSearch and feeds it to the baseline engine
to learn traffic patterns. This is a one-time or periodic training job, not ongoing integration.

Usage:
    python graylog_training_pipeline.py --start-date 2026-01-01 --end-date 2026-06-01
    python graylog_training_pipeline.py --sample-size 100000 --output /tmp/training_data.jsonl
"""

import json
import logging
import time
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from eventdb import EventDatabase
from baseline_engine import BaselineEngine
from graylog_training_extractor import GraylogTrainingExtractor

logger = logging.getLogger(__name__)

class GraylogTrainingPipeline:
    """Pipeline to extract, transform, and load Graylog training data."""
    
    def __init__(self, es_hosts: List[str], es_user: str, es_password: str,
                 db_connection: Any, baseline_engine: BaselineEngine):
        self.extractor = GraylogTrainingExtractor(es_hosts, es_user, es_password)
        self.db = db_connection
        self.baseline_engine = baseline_engine
        self.stats = {
            "firewall_events": 0,
            "http_events": 0,
            "alert_events": 0,
            "total_events": 0,
            "baselines_learned": 0,
            "start_time": None,
            "end_time": None,
            "training_time_seconds": 0
        }
    
    def run_training(self, start_date: Optional[str] = None, end_date: Optional[str] = None,
                    sample_size: int = 100000, output_file: Optional[str] = None) -> Dict[str, Any]:
        """Run the full training pipeline."""
        start_time = datetime.now(timezone.utc)
        
        logger.info("Starting Graylog training pipeline...")
        
        # Step 1: Extract training data
        logger.info("Step 1: Extracting training data from OpenSearch...")
        training_data = self._extract_training_data(start_date, end_date, sample_size)
        
        # Step 2: Save raw training data to file if requested
        if output_file:
            logger.info(f"Saving raw training data to {output_file}...")
            with open(output_file, 'w') as f:
                for event in training_data:
                    f.write(json.dumps(event) + '\n')
        
        # Step 3: Learn baselines
        logger.info("Step 3: Learning baselines from training data...")
        baselines_learned = self.baseline_engine.learn_from_training_data(training_data)
        self.stats["baselines_learned"] = baselines_learned
        
        # Step 4: Save baselines to database
        logger.info("Step 4: Saving baselines to database...")
        self.baseline_engine.save_baselines()
        
        # Calculate training time
        end_time = datetime.now(timezone.utc)
        self.stats["training_time_seconds"] = (end_time - start_time).total_seconds()
        
        # Return results
        results = {
            "status": "success",
            "stats": self.stats,
            "training_summary": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": self.stats["training_time_seconds"],
                "total_events_processed": len(training_data),
                "baselines_learned": baselines_learned
            }
        }
        
        logger.info(f"Training pipeline completed in {self.stats['training_time_seconds']:.2f} seconds")
        logger.info(f"Processed {len(training_data)} events, learned {baselines_learned} baselines")
        
        return results
    
    def _extract_training_data(self, start_date: Optional[str] = None,
                              end_date: Optional[str] = None,
                              sample_size: int = 100000) -> List[Dict[str, Any]]:
        """Extract training data from all sources."""
        all_events = []
        
        # Extract firewall events
        logger.info("Extracting firewall events...")
        firewall_events = self.extractor.extract_firewall_events(
            start_time=start_date,
            end_time=end_date,
            sample_size=sample_size
        )
        all_events.extend(firewall_events)
        self.stats["firewall_events"] = len(firewall_events)
        logger.info(f"Extracted {len(firewall_events)} firewall events")
        
        # Extract HTTP events
        logger.info("Extracting HTTP events...")
        http_events = self.extractor.extract_http_events(
            sample_size=min(sample_size // 2, 50000)
        )
        all_events.extend(http_events)
        self.stats["http_events"] = len(http_events)
        logger.info(f"Extracted {len(http_events)} HTTP events")
        
        # Extract alert events
        logger.info("Extracting alert events...")
        alert_events = self.extractor.extract_alerts(
            sample_size=min(sample_size // 4, 25000)
        )
        all_events.extend(alert_events)
        self.stats["alert_events"] = len(alert_events)
        logger.info(f"Extracted {len(alert_events)} alert events")
        
        return all_events

def main():
    parser = argparse.ArgumentParser(description="Graylog Training Pipeline")
    parser.add_argument("--es-hosts", nargs="+", default=["http://192.168.1.32:9200",
                                                         "http://192.168.1.33:9200",
                                                         "http://192.168.1.35:9200"],
                        help="OpenSearch hosts")
    parser.add_argument("--es-user", default="elastic", help="OpenSearch user")
    parser.add_argument("--es-password", default="changeme", help="OpenSearch password")
    parser.add_argument("--start-date", help="Start date for extraction (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="End date for extraction (YYYY-MM-DD)")
    parser.add_argument("--sample-size", type=int, default=100000, help="Max events to extract")
    parser.add_argument("--output", help="Output JSONL file")
    parser.add_argument("--all-data", action="store_true", help="Extract all available data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    from json_logging import setup_json_logging
    setup_json_logging(level=logging.DEBUG if args.verbose else logging.INFO)

    try:
        # Initialize database
        db = EventDatabase()
        db.connect()
        
        # Initialize baseline engine
        baseline_engine = BaselineEngine(db)
        
        # Create pipeline
        pipeline = GraylogTrainingPipeline(
            es_hosts=args.es_hosts,
            es_user=args.es_user,
            es_password=args.es_password,
            db_connection=db,
            baseline_engine=baseline_engine
        )
        
        # Run training
        results = pipeline.run_training(
            start_date=args.start_date,
            end_date=args.end_date,
            sample_size=args.sample_size if not args.all_data else 1000000,
            output_file=args.output
        )
        
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == "__main__":
    exit(main())