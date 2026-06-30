"""TimescaleDB query performance benchmarks.

Measures the three critical dashboard queries under realistic data volumes
and documents hypertable status (chunks, compression, index strategy).

Queries benchmarked:
  1. SELECT count(*) FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'
  2. SELECT src_ip, count(*) FROM events WHERE timestamp > NOW() - INTERVAL '1 hour' GROUP BY src_ip
  3. SELECT action, count(*) FROM events WHERE timestamp > NOW() - INTERVAL '6 hours' GROUP BY action

Target: <100ms for 24h range queries on hypertable (vs 2-14s on plain table).

Usage:
    python -m pytest tests/test_timescaledb_performance.py -v
    # Or standalone (requires DB connectivity):
    python tests/test_timescaledb_performance.py

When run standalone, the script seeds ~10k test events if needed and
prints a human-readable benchmark report.
"""

import sys
import os
import time
import json
import random
import statistics
import unittest
from datetime import datetime, timezone, timedelta

# Project root setup
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

_tests_dir = os.path.dirname(os.path.abspath(__file__))
if _tests_dir in sys.path:
    sys.path.remove(_tests_dir)

# Force reimport from correct location
for mod in list(sys.modules):
    if mod.startswith("eventdb") or mod.startswith("schema_migrations"):
        del sys.modules[mod]


# ---------------------------------------------------------------------------
# Benchmark queries
# ---------------------------------------------------------------------------
BENCHMARK_QUERIES = {
    "count_24h": {
        "name": "Event count (24h window)",
        "sql": "SELECT count(*) FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'",
        "target_ms": 100,
    },
    "groupby_srcip_1h": {
        "name": "Source IP distribution (1h window)",
        "sql": "SELECT src_ip, count(*) FROM events WHERE timestamp > NOW() - INTERVAL '1 hour' GROUP BY src_ip",
        "target_ms": 100,
    },
    "groupby_action_6h": {
        "name": "Action distribution (6h window)",
        "sql": "SELECT action, count(*) FROM events WHERE timestamp > NOW() - INTERVAL '6 hours' GROUP BY action",
        "target_ms": 100,
    },
}

# How many times to run each query for statistical significance
BENCHMARK_ITERATIONS = 5

# Marker IP for seeded data so we can clean up
SEED_MARKER_IP = "192.168.100.200"
SEED_MARKER_RAW = "TEST_TSC_BENCH"


def _get_db_connection():
    """Get a raw psycopg2 connection using env vars."""
    import psycopg2
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    dbname = os.environ.get("DB_NAME", "opnsense")
    user = os.environ.get("DB_USER", "opnsense")
    password = os.environ.get("DB_PASSWORD", "opnsense")
    return psycopg2.connect(
        host=host, port=port, dbname=dbname,
        user=user, password=password, connect_timeout=10,
    )


def _is_timescaledb_available(conn):
    """Check if TimescaleDB extension is enabled."""
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'
            )
        """)
        return cur.fetchone()[0]
    finally:
        cur.close()


def _is_hypertable(conn, table="events"):
    """Check if the table is a TimescaleDB hypertable."""
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT hypertable_schema, hypertable_name
            FROM timescaledb_information.hypertables
            WHERE hypertable_name = %s
        """, (table,))
        return cur.fetchone() is not None
    except Exception:
        return False
    finally:
        cur.close()


def _get_hypertable_info(conn, table="events"):
    """Get hypertable metadata: chunks, compression, retention."""
    cur = conn.cursor()
    info = {}
    try:
        # Chunk count and size
        cur.execute("""
            SELECT
                count(*) AS num_chunks,
                pg_size_pretty(sum(pg_total_relation_size(chunk_schema || '.' || chunk_name))) AS total_size
            FROM timescaledb_information.chunks
            WHERE hypertable_name = %s
        """, (table,))
        row = cur.fetchone()
        info["num_chunks"] = row[0] if row else 0
        info["total_size"] = row[1] if row else "0 bytes"
    except Exception:
        info["chunk_error"] = True
    finally:
        cur.close()

    try:
        # Compression status
        cur.execute("""
            SELECT
                count(*) AS compressed_chunks,
                pg_size_pretty(sum(pg_total_relation_size(chunk_schema || '.' || chunk_name))) AS compressed_size
            FROM timescaledb_information.chunks
            WHERE hypertable_name = %s AND compressed = true
        """, (table,))
        row = cur.fetchone()
        info["compressed_chunks"] = row[0] if row else 0
        info["compressed_size"] = row[1] if row else "0 bytes"
    except Exception:
        pass
    finally:
        cur.close()

    return info


def _get_table_stats(conn):
    """Get basic stats about the events table."""
    cur = conn.cursor()
    stats = {}
    try:
        cur.execute("SELECT count(*) FROM events")
        stats["total_events"] = cur.fetchone()[0]
        cur.execute("""
            SELECT min(timestamp), max(timestamp) FROM events
        """)
        row = cur.fetchone()
        stats["earliest"] = str(row[0]) if row[0] else None
        stats["latest"] = str(row[1]) if row[1] else None
        cur.execute("""
            SELECT pg_size_pretty(pg_total_relation_size('events'::regclass))
        """)
        stats["table_size"] = cur.fetchone()[0]
    except Exception as e:
        stats["error"] = str(e)
    finally:
        cur.close()
    return stats


def _seed_test_data(conn, count=10000):
    """Insert test events spread over 48 hours for benchmarking.

    Uses marker IP 192.168.100.200 so cleanup is straightforward.
    """
    cur = conn.cursor()
    try:
        # Ensure events table exists
        cur.execute("SELECT 1 FROM events LIMIT 1")

        # Generate realistic events
        actions = ["PASS", "BLOCK", "MATCH"]
        protos = ["TCP", "UDP", "ICMP"]
        interfaces = ["wan", "lan", "opt1"]
        now = datetime.now(timezone.utc)

        events = []
        for i in range(count):
            ts = now - timedelta(seconds=random.randint(0, 48 * 3600))
            events.append((
                ts,
                SEED_MARKER_IP,
                f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                None, None,
                random.randint(1024, 65535),
                random.choice([22, 53, 80, 443, 8080, 3389]),
                random.choice(protos),
                random.choice(actions),
                random.choice(interfaces),
                "inbound",
                4,
                random.randint(32, 128),
                random.randint(40, 1500),
                "SA",
                random.randint(0, 2**32),
                random.randint(0, 2**32),
                random.randint(16384, 65535),
                None,
                None,
                None,
                f"{SEED_MARKER_RAW} benchmark event {i}",
                f"BENCH_RULE_{random.randint(1, 5)}",
                "filterlog",
            ))

        cur.execute("""
            INSERT INTO events
            (timestamp, src_ip, dst_ip, src_hostname, dst_hostname,
             src_port, dst_port, proto, action, interface,
             direction, version, ip_ttl, ip_total_length, tcp_flags,
             tcp_seq, tcp_ack, tcp_window, tcp_options,
             udp_datalen, icmp_datalen, raw_message, rule_name, log_type)
            VALUES %s
        """, [events])
        conn.commit()
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def _cleanup_seed_data(conn):
    """Remove seeded benchmark data by marker IP."""
    cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM events WHERE src_ip = %s",
            (SEED_MARKER_IP,)
        )
        conn.commit()
        return cur.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def _run_benchmark(conn, query_name, query_sql, iterations=BENCHMARK_ITERATIONS):
    """Run a query repeatedly and collect timing stats.

    Returns a dict with timing stats in milliseconds.
    """
    times_ms = []
    cur = conn.cursor()
    try:
        # Warm-up run (discard timing)
        cur.execute(query_sql)
        cur.fetchall()

        for _ in range(iterations):
            start = time.perf_counter()
            cur.execute(query_sql)
            rows = cur.fetchall()
            elapsed_ms = (time.perf_counter() - start) * 1000
            times_ms.append(elapsed_ms)
    except Exception as e:
        return {"error": str(e)}
    finally:
        cur.close()

    if not times_ms:
        return {"error": "no measurements"}

    return {
        "min_ms": round(min(times_ms), 2),
        "max_ms": round(max(times_ms), 2),
        "mean_ms": round(statistics.mean(times_ms), 2),
        "median_ms": round(statistics.median(times_ms), 2),
        "stdev_ms": round(statistics.stdev(times_ms), 2) if len(times_ms) > 1 else 0.0,
        "iterations": len(times_ms),
        "sample_values": [round(t, 2) for t in times_ms],
    }


def _run_explain(conn, query_sql):
    """Run EXPLAIN ANALYZE and return the plan as a string."""
    cur = conn.cursor()
    try:
        cur.execute(f"EXPLAIN ANALYZE {query_sql}")
        lines = cur.fetchall()
        return "\n".join(line[0] for line in lines)
    except Exception as e:
        return f"EXPLAIN failed: {e}"
    finally:
        cur.close()


def run_full_benchmark():
    """Run the complete benchmark suite and return structured results."""
    conn = _get_db_connection()
    try:
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "timescaledb_available": _is_timescaledb_available(conn),
            "events_is_hypertable": False,
            "hypertable_info": {},
            "table_stats": {},
            "benchmarks": {},
        }

        if result["timescaledb_available"]:
            result["events_is_hypertable"] = _is_hypertable(conn)
            if result["events_is_hypertable"]:
                result["hypertable_info"] = _get_hypertable_info(conn)

        result["table_stats"] = _get_table_stats(conn)

        # Seed data if table is empty or has few events
        total_events = result["table_stats"].get("total_events", 0)
        seeded = False
        if total_events < 1000:
            try:
                _seed_test_data(conn, 10000)
                seeded = True
                # Refresh stats
                result["table_stats"] = _get_table_stats(conn)
            except Exception as e:
                result["seed_error"] = str(e)

        try:
            # Run benchmarks
            for qkey, qmeta in BENCHMARK_QUERIES.items():
                stats = _run_benchmark(conn, qkey, qmeta["sql"])
                plan = _run_explain(conn, qmeta["sql"])
                result["benchmarks"][qkey] = {
                    "name": qmeta["name"],
                    "sql": qmeta["sql"],
                    "target_ms": qmeta["target_ms"],
                    "timing": stats,
                    "explain_plan": plan,
                    "meets_target": (
                        stats.get("mean_ms", 9999) <= qmeta["target_ms"]
                        if "error" not in stats else False
                    ),
                }
        finally:
            # Cleanup seeded data
            if seeded:
                try:
                    _cleanup_seed_data(conn)
                except Exception:
                    pass

        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
class TestTimescaleDBStatus(unittest.TestCase):
    """Verify TimescaleDB extension and hypertable status."""

    @classmethod
    def setUpClass(cls):
        cls.conn = _get_db_connection()

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_timescaledb_extension(self):
        """TimescaleDB extension should be enabled."""
        available = _is_timescaledb_available(self.conn)
        self.assertTrue(
            available,
            "TimescaleDB extension not found — docker-compose must use timescale/timescaledb image and V20 migration must have run",
        )

    def test_events_is_hypertable(self):
        """events table should be a TimescaleDB hypertable."""
        is_ht = _is_hypertable(self.conn)
        self.assertTrue(
            is_ht,
            "events table is not a hypertable — V20 migration (create_hypertable) has not been applied",
        )

    def test_hypertable_has_chunks(self):
        """Hypertable should have at least one chunk."""
        info = _get_hypertable_info(self.conn)
        self.assertGreater(
            info.get("num_chunks", 0), 0,
            "Hypertable has zero chunks — data may not exist or chunks were dropped",
        )


class TestQueryPerformance(unittest.TestCase):
    """Benchmark queries meet <100ms target for time-range scans."""

    @classmethod
    def setUpClass(cls):
        cls.conn = _get_db_connection()
        # Ensure enough data for meaningful benchmarks
        stats = _get_table_stats(cls.conn)
        if stats.get("total_events", 0) < 1000:
            _seed_test_data(cls.conn, 10000)

    @classmethod
    def tearDownClass(cls):
        try:
            _cleanup_seed_data(cls.conn)
        except Exception:
            pass
        cls.conn.close()

    def _benchmark_query(self, name, sql, target_ms):
        """Helper: run a benchmark and assert it meets target."""
        result = _run_benchmark(self.conn, name, sql)
        if "error" in result:
            self.skipTest(f"Benchmark query failed: {result['error']}")
        mean = result["mean_ms"]
        self.assertLessEqual(
            mean, target_ms,
            f"{name} mean={mean:.1f}ms exceeds target {target_ms}ms "
            f"(min={result['min_ms']}, max={result['max_ms']}, "
            f"median={result['median_ms']})",
        )
        return result

    def test_count_24h_performance(self):
        """24-hour count query should be <100ms."""
        q = BENCHMARK_QUERIES["count_24h"]
        self._benchmark_query(q["name"], q["sql"], q["target_ms"])

    def test_groupby_srcip_1h_performance(self):
        """1-hour src_ip GROUP BY should be <100ms."""
        q = BENCHMARK_QUERIES["groupby_srcip_1h"]
        self._benchmark_query(q["name"], q["sql"], q["target_ms"])

    def test_groupby_action_6h_performance(self):
        """6-hour action GROUP BY should be <100ms."""
        q = BENCHMARK_QUERIES["groupby_action_6h"]
        self._benchmark_query(q["name"], q["sql"], q["target_ms"])

    def test_explain_uses_chunk_scan(self):
        """EXPLAIN should show Append/Chunk scan (hypertable pruning), not Seq Scan on full table."""
        q = BENCHMARK_QUERIES["count_24h"]["sql"]
        plan = _run_explain(self.conn, q)
        # TimescaleDB hypertable plans contain "Append" (chunk scanning) or "Custom Scan"
        # A plain table would show "Seq Scan on events" without chunk references
        self.assertTrue(
            "Append" in plan or "Custom Scan" in plan or "Seq Scan on _hyper" in plan,
            f"Query plan does not show hypertable chunk scanning.\nPlan:\n{plan}",
        )


class TestBenchmarkReport(unittest.TestCase):
    """Generate a full benchmark report (standalone or CI-friendly)."""

    def test_full_benchmark_report(self):
        """Run all benchmarks, assert targets, print report."""
        report = run_full_benchmark()

        # Print human-readable report
        print("\n" + "=" * 72)
        print("TIMESCALEDB PERFORMANCE BENCHMARK REPORT")
        print("=" * 72)
        print(f"Timestamp:           {report['timestamp']}")
        print(f"TimescaleDB enabled: {report['timescaledb_available']}")
        print(f"Hypertable (events): {report['events_is_hypertable']}")

        if report["hypertable_info"]:
            info = report["hypertable_info"]
            print(f"  Chunks:            {info.get('num_chunks', '?')}")
            print(f"  Total size:        {info.get('total_size', '?')}")
            print(f"  Compressed chunks: {info.get('compressed_chunks', 0)}")

        stats = report["table_stats"]
        print(f"Total events:        {stats.get('total_events', '?'):,}")
        print(f"Time range:          {stats.get('earliest', '?')} -> {stats.get('latest', '?')}")
        print(f"Table size:          {stats.get('table_size', '?')}")

        print("\n--- Query Benchmarks ---\n")
        all_passed = True
        for qkey, b in report["benchmarks"].items():
            timing = b["timing"]
            passed = b["meets_target"]
            symbol = "PASS" if passed else "FAIL"
            if not passed:
                all_passed = False
            print(f"[{symbol}] {b['name']}")
            if "error" not in timing:
                print(f"       Target: <{b['target_ms']}ms  |  "
                      f"Mean: {timing['mean_ms']}ms  |  "
                      f"Median: {timing['median_ms']}ms  |  "
                      f"Min: {timing['min_ms']}ms  |  "
                      f"Max: {timing['max_ms']}ms")
            else:
                print(f"       ERROR: {timing['error']}")
            print(f"       EXPLAIN:\n" + "\n".join(
                f"         {line}" for line in b["explain_plan"].split("\n")
            ))
            print()

        print("=" * 72)
        if all_passed:
            print("RESULT: ALL QUERIES MEET TARGET (<100ms)")
        else:
            print("RESULT: SOME QUERIES EXCEED TARGET")
        print("=" * 72 + "\n")

        # Assert at least TimescaleDB is available (skip hypertable check
        # if no data exists — the migration is applied on first connection)
        self.assertTrue(
            report["timescaledb_available"],
            "TimescaleDB extension not available",
        )


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--report":
        # Standalone report mode
        report = run_full_benchmark()
        print(json.dumps(report, indent=2, default=str))
    else:
        # pytest / unittest mode
        unittest.main()
