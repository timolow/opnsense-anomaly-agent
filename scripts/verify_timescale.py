#!/usr/bin/env python3
"""
TimescaleDB hypertable verification and backfill script.

Verifies that existing events are properly distributed into TimescaleDB
hypertable chunks after V20 migration, runs ANALYZE for updated statistics,
and reports chunk distribution.

Usage:
    # As standalone script (requires DB connection env vars)
    python scripts/verify_timescale.py

    # As module from within the agent
    from scripts.verify_timescale import verify_hypertable
    result = verify_hypertable(db)

Environment variables:
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD (same as docker-compose)
"""

import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def get_db_config() -> Dict[str, str]:
    """Read database connection config from environment."""
    return {
        "host": os.environ.get("DB_HOST", "postgres"),
        "port": os.environ.get("DB_PORT", "5432"),
        "dbname": os.environ.get("DB_NAME", "opnsense"),
        "user": os.environ.get("DB_USER", "opnsense"),
        "password": os.environ.get("DB_PASSWORD", "opnsense"),
    }


def verify_hypertable(db_conn: Any) -> Dict[str, Any]:
    """Verify TimescaleDB hypertable state and run maintenance.

    Args:
        db_conn: A raw psycopg2 connection (NOT EventDatabase).

    Returns:
        Dict with verification results:
        {
            "is_hypertable": bool,
            "event_count": int,
            "chunk_count": int,
            "chunks": [...],
            "analyze_completed": bool,
            "estimated_row_count": int,
            "status": "ok" | "warning" | "error",
            "messages": [...]
        }
    """
    result: Dict[str, Any] = {
        "is_hypertable": False,
        "event_count": 0,
        "chunk_count": 0,
        "chunks": [],
        "analyze_completed": False,
        "estimated_row_count": 0,
        "status": "ok",
        "messages": [],
    }

    cur = db_conn.cursor()
    try:
        # 1. Check if events is a hypertable
        cur.execute("""
            SELECT hypertable_schema, hypertable_name
            FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'events'
        """)
        hypertable_row = cur.fetchone()
        if not hypertable_row:
            result["status"] = "error"
            result["messages"].append(
                "ERROR: 'events' is NOT a hypertable. "
                "Run V20 migration first (schema_migrations.py)."
            )
            logger.error("events is not a hypertable — V20 migration may not have run")
            return result

        result["is_hypertable"] = True
        result["messages"].append(
            f"Hypertable confirmed: {hypertable_row[0]}.{hypertable_row[1]}"
        )
        logger.info("Hypertable confirmed: %s.%s", hypertable_row[0], hypertable_row[1])

        # 2. Count actual events
        cur.execute("SELECT count(*) FROM normalized_events")
        event_count = cur.fetchone()[0]
        result["event_count"] = event_count
        result["messages"].append(f"Total events in hypertable: {event_count:,}")
        logger.info("Total events in hypertable: %d", event_count)

        # 3. Check pg_stat_user_tables for estimated row count (post-ANALYZE accuracy)
        cur.execute("""
            SELECT n_live_tup, last_analyze, last_autoanalyze
            FROM pg_stat_user_tables
            WHERE relname = 'events'
        """)
        stat_row = cur.fetchone()
        if stat_row:
            result["estimated_row_count"] = stat_row[0]
            last_analyze = stat_row[1]
            last_autoanalyze = stat_row[2]
            if last_analyze:
                result["messages"].append(
                    f"Last ANALYZE: {last_analyze}"
                )
            elif last_autoanalyze:
                result["messages"].append(
                    f"Last AUTO-ANALYZE: {last_autoanalyze} (manual ANALYZE recommended)"
                )
            else:
                result["messages"].append(
                    "WARNING: No ANALYZE has run yet — running now"
                )
                logger.warning("No ANALYZE history — statistics will be stale until we run it")

        # 4. Verify chunking
        cur.execute("""
            SELECT chunk_schema, chunk_name, range_start, range_end
            FROM timescaledb_information.chunks
            WHERE table_name = 'events'
            ORDER BY range_start
        """)
        chunks = cur.fetchall()
        result["chunk_count"] = len(chunks)
        result["chunks"] = [
            {
                "schema": row[0],
                "name": row[1],
                "range_start": str(row[2]) if row[2] else None,
                "range_end": str(row[3]) if row[3] else None,
            }
            for row in chunks
        ]

        if chunks:
            result["messages"].append(
                f"Chunks: {len(chunks)} "
                f"(range {chunks[0][2]} to {chunks[-1][3]})"
            )
            logger.info(
                "Chunk distribution: %d chunks from %s to %s",
                len(chunks),
                chunks[0][2],
                chunks[-1][3],
            )
        else:
            # No chunks = no data yet, which is fine for a fresh instance
            if event_count == 0:
                result["messages"].append(
                    "No chunks yet — no events have been ingested (fresh instance)"
                )
            else:
                result["status"] = "warning"
                result["messages"].append(
                    f"WARNING: {event_count} events exist but 0 chunks — "
                    "hypertable may not have distributed data"
                )

        # 5. Run ANALYZE to update planner statistics
        logger.info("Running ANALYZE on events table...")
        cur.execute("ANALYZE events")
        result["analyze_completed"] = True
        result["messages"].append("ANALYZE events completed successfully")
        logger.info("ANALYZE events completed")

        # 6. Post-ANALYZE: re-check estimated row count for consistency
        cur.execute("""
            SELECT n_live_tup
            FROM pg_stat_user_tables
            WHERE relname = 'events'
        """)
        post_analyze_count = cur.fetchone()[0]
        if post_analyze_count != event_count and post_analyze_count > 0:
            result["messages"].append(
                f"Post-ANALYZE estimated rows: {post_analyze_count:,} "
                f"(actual count: {event_count:,})"
            )

        # 7. Summary
        if result["status"] == "ok":
            logger.info(
                "Verification PASSED: hypertable=%s, events=%d, chunks=%d, analyzed=%s",
                result["is_hypertable"],
                result["event_count"],
                result["chunk_count"],
                result["analyze_completed"],
            )

    finally:
        cur.close()

    return result


def main():
    """Standalone entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        import psycopg2
    except ImportError:
        logger.error("psycopg2 not installed — run: pip install psycopg2-binary")
        sys.exit(1)

    config = get_db_config()
    logger.info("Connecting to PostgreSQL at %s:%s/%s", config["host"], config["port"], config["dbname"])

    try:
        conn = psycopg2.connect(
            host=config["host"],
            port=config["port"],
            dbname=config["dbname"],
            user=config["user"],
            password=config["password"],
        )
        conn.set_session(autocommit=True)  # ANALYZE requires autocommit
    except Exception as exc:
        logger.error("Failed to connect: %s", exc)
        sys.exit(1)

    try:
        result = verify_hypertable(conn)

        # Print JSON summary
        print("\n" + "=" * 60)
        print("TIMESCALEDB HYPERTABLE VERIFICATION REPORT")
        print("=" * 60)
        for msg in result["messages"]:
            print(f"  {msg}")
        print(f"\n  Status: {result['status'].upper()}")
        print("=" * 60)

        if result["status"] == "error":
            sys.exit(2)
        elif result["status"] == "warning":
            sys.exit(1)
        else:
            sys.exit(0)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
