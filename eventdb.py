"""
PostgreSQL event database for OPNsense anomaly detection agent.

Provides persistent storage for firewall events, detected anomalies,
and statistical baselines. Supports time-series partitioning-ready
schema with proper indexes for high-throughput ingestion and queries.
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict

import psycopg2
import psycopg2.extras
import psycopg2.pool  # type: ignore

from schema_migrations import run_migrations as _run_migrations, CURRENT_SCHEMA_VERSION as _SCHEMA_VERSION

logger = logging.getLogger(__name__)

# Default PostgreSQL connection config
DEFAULT_PG_HOST = os.environ.get("DB_HOST", "postgres")
DEFAULT_PG_PORT = int(os.environ.get("DB_PORT", "5432"))
DEFAULT_PG_DB = os.environ.get("DB_NAME", "anomaly_agent")
DEFAULT_PG_USER = os.environ.get("DB_USER", "anomaly_agent")
DEFAULT_PG_PASS = os.environ.get("DB_PASSWORD") or os.environ.get("DB_PASS", "anomaly_agent_secret")

# All table definitions live in schema_migrations.py (versioned migrations).
# eventdb.py is the data access layer — schema is managed centrally.


class EventDatabase:
    """Manages PostgreSQL connection pool and all database operations."""
    
    # Module-level pool singleton (shared across instances)
    _pool = None
    _pool_lock = None  # type: ignore
    
    def __init__(self, host=None, port=None, database=None, user=None, password=None):
        self.host = host or DEFAULT_PG_HOST
        self.port = port or DEFAULT_PG_PORT
        self.database = database or DEFAULT_PG_DB
        self.user = user or DEFAULT_PG_USER
        self.password = password or DEFAULT_PG_PASS
        self._initialized = False
        
        # Initialize connection pool (singleton)
        pool_key = f"{self.host}:{self.port}/{self.database}"
        if EventDatabase._pool is None or EventDatabase._pool_key != pool_key:
            if EventDatabase._pool is not None:
                EventDatabase._pool.closeall()
            EventDatabase._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                host=self.host,
                port=self.port,
                dbname=self.database,
                user=self.user,
                password=self.password,
            )
            EventDatabase._pool_key = pool_key
            logger.info("PostgreSQL connection pool initialized (%s, max=%d)", pool_key, EventDatabase._pool.maxconn)
    
    def connect(self):
        """Get a connection from the pool."""
        conn = EventDatabase._pool.getconn()
        conn.autocommit = True
        return conn
    
    def putconn(self, conn):
        """Return a connection to the pool."""
        if conn:
            try:
                EventDatabase._pool.putconn(conn)
            except Exception:
                pass
    
    def close_all(self):
        """Close all connections in the pool."""
        if EventDatabase._pool:
            EventDatabase._pool.closeall()
            EventDatabase._pool = None
    
    def ensure_tables(self):
        """Ensure all database tables exist and run pending schema migrations.

        Schema is managed entirely by versioned migrations in schema_migrations.py.
        This method runs all pending migrations in order, ensuring the database
        schema is up to date.
        """
        if self._initialized:
            return

        _run_migrations(self)
        self._initialized = True
        logger.info("Database schema ensured (v%d)", _SCHEMA_VERSION)

    def ensure_indexes(self):
        """Ensure database indexes exist.

        Indexes are created alongside tables in schema_migrations.py
        via CREATE INDEX IF NOT EXISTS. This method is called
        separately by agent.py for compatibility.
        """
        # Tables + indexes are already ensured by ensure_tables / run_migrations
        # This method exists for agent.py compatibility
        pass
    
    def close(self):
        """Close the database connection (return to pool)."""
        # No-op with connection pooling — connections are managed by the pool
    
    class _PoolCursor:
        """Cursor wrapper that returns the underlying connection to the pool on close()."""
        __slots__ = ("_conn", "_pool", "_cur")
        def __init__(self, conn, pool, cur):
            self._conn = conn
            self._pool = pool
            self._cur = cur
        def execute(self, *a, **kw): return self._cur.execute(*a, **kw)
        def executemany(self, *a, **kw): return self._cur.executemany(*a, **kw)
        def fetchone(self): return self._cur.fetchone()
        def fetchmany(self, *a, **kw): return self._cur.fetchmany(*a, **kw)
        def fetchall(self): return self._cur.fetchall()
        def close(self):
            self._cur.close()
            try:
                self._pool.putconn(self._conn)
            except Exception:
                pass
        @property
        def rowcount(self): return self._cur.rowcount
        def __getattr__(self, name): return getattr(self._cur, name)

    def _new_cursor(self):
        """Get a new cursor that auto-returns the connection to the pool on close()."""
        conn = self.connect()
        cur = conn.cursor()
        return self._PoolCursor(conn, EventDatabase._pool, cur)
    
    def insert_event(self, event_data: Dict[str, Any], raw_message: str = "") -> int:
        """Insert a single parsed event and return its ID."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO events
                   (timestamp, src_ip, dst_ip, src_hostname, dst_hostname,
                    src_port, dst_port, proto, action, interface,
                    direction, version, ip_ttl, ip_total_length, tcp_flags,
                    tcp_seq, tcp_ack, tcp_window, tcp_options,
                    udp_datalen, icmp_datalen, raw_message, rule_name, log_type)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    event_data.get('timestamp'),
                    event_data.get('src_ip'),
                    event_data.get('dst_ip'),
                    event_data.get('src_hostname'),
                    event_data.get('dst_hostname'),
                    event_data.get('sport'),
                    event_data.get('dport'),
                    event_data.get('proto'),
                    event_data.get('action'),
                    event_data.get('interface'),
                    event_data.get('direction'),
                    event_data.get('version'),
                    event_data.get('ip_ttl'),
                    event_data.get('ip_total_length'),
                    event_data.get('tcp_flags_raw') or event_data.get('tcp_flags'),
                    event_data.get('tcp_seq'),
                    event_data.get('tcp_ack'),
                    event_data.get('tcp_window'),
                    event_data.get('tcp_options'),
                    event_data.get('udp_datalen'),
                    event_data.get('icmp_datalen'),
                    raw_message,
                    event_data.get('rule_name'),
                    event_data.get('log_type', ''),
                )
            )
            event_id = cur.fetchone()[0]
            return event_id
        finally:
            cur.close()
    
    def insert_events_batch(self, events: List[Tuple]) -> int:
        """Insert a batch of events.
        
        events: list of tuples matching the INSERT column order.
        """
        if not events:
            return 0
        
        conn = self.connect()
        cur = conn.cursor()
        try:
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO events
                   (timestamp, src_ip, dst_ip, src_hostname, dst_hostname,
                    src_port, dst_port, proto, action, interface,
                    direction, version, ip_ttl, ip_total_length, tcp_flags,
                    tcp_seq, tcp_ack, tcp_window, tcp_options,
                    udp_datalen, icmp_datalen, raw_message, rule_name, log_type)
                   VALUES %s""",
                events,
                page_size=1000
            )
            return len(events)
        finally:
            cur.close()
            self.putconn(conn)
    
    def insert_anomaly(self, anomaly_data: Dict[str, Any]) -> int:
        """Insert a detected anomaly."""
        cur = self._new_cursor()
        try:
            detail = anomaly_data.pop('detail', None)
            # Ensure timestamp is set (required by DB schema)
            if not anomaly_data.get('timestamp'):
                anomaly_data['timestamp'] = datetime.now(timezone.utc).isoformat()
            cur.execute(
                """INSERT INTO anomalies
                   (event_id, timestamp, attack_type, severity,
                    src_ip, dst_ip, dst_port, proto,
                    description, detail, alert_sent, discord_sent)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    anomaly_data.get('event_id'),
                    anomaly_data.get('timestamp'),
                    anomaly_data.get('attack_type'),
                    anomaly_data.get('severity'),
                    anomaly_data.get('src_ip'),
                    anomaly_data.get('dst_ip'),
                    anomaly_data.get('dst_port'),
                    anomaly_data.get('proto'),
                    anomaly_data.get('description'),
                    json.dumps(detail) if detail else None,
                    anomaly_data.get('alert_sent', False),
                    anomaly_data.get('discord_sent', False),
                )
            )
            return cur.fetchone()[0]
        finally:
            cur.close()
    
    def insert_anomalies_batch(self, anomalies: List[Dict[str, Any]]) -> int:
        """Insert a batch of anomalies."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            values = []
            for a in anomalies:
                detail = a.pop('detail', None)
                values.append((
                    a.get('event_id'),
                    a.get('timestamp'),
                    a.get('attack_type'),
                    a.get('severity'),
                    a.get('src_ip'),
                    a.get('dst_ip'),
                    a.get('dst_port'),
                    a.get('proto'),
                    a.get('description'),
                    json.dumps(detail) if detail else None,
                    a.get('alert_sent', False),
                    a.get('discord_sent', False),
                ))
            
            if values:
                insert_sql = """
                    INSERT INTO anomalies
                    (event_id, timestamp, attack_type, severity,
                     src_ip, dst_ip, dst_port, proto,
                     description, detail, alert_sent, discord_sent)
                    VALUES %s
                """
                psycopg2.extras.execute_values(
                    cur, insert_sql, values,
                    template=(
                        "(%%s, %%s, %%s, %%s, %%s, %%s, %%s, %%s, "
                        "%%s, %%s, %%s, %%s)"
                    ),
                    template_values=(
                        "EXCLUDED.event_id, EXCLUDED.timestamp, "
                        "EXCLUDED.attack_type, EXCLUDED.severity, "
                        "EXCLUDED.src_ip, EXCLUDED.dst_ip, EXCLUDED.dst_port, "
                        "EXCLUDED.proto, EXCLUDED.description, "
                        "EXCLUDED.detail, EXCLUDED.alert_sent, EXCLUDED.discord_sent"
                    ),
                    page_size=500
                )
            return len(values)
        finally:
            cur.close()
            self.putconn(conn)
    
    def update_alert_status(self, anomaly_id: int, alert_sent: bool = False, discord_sent: bool = False):
        """Mark an anomaly as having alerts sent."""
        cur = self._new_cursor()
        try:
            if alert_sent:
                cur.execute("UPDATE anomalies SET alert_sent = TRUE WHERE id = %s", (anomaly_id,))
            if discord_sent:
                cur.execute("UPDATE anomalies SET discord_sent = TRUE WHERE id = %s", (anomaly_id,))
        finally:
            cur.close()

    def insert_drift_event(self, metric: str, scope: str, old_mean: float,
                           new_mean: float, drift_magnitude: float, window_size: int,
                           severity: str, description: str,
                           timestamp: Optional[datetime] = None) -> int:
        """Insert a concept drift event."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO drift_events
                   (metric, scope, old_mean, new_mean, drift_magnitude, window_size,
                    severity, description, timestamp)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (metric, scope, old_mean, new_mean, drift_magnitude, window_size,
                 severity, description, timestamp or datetime.now(timezone.utc))
            )
            drift_id = cur.fetchone()[0]
            return drift_id
        finally:
            cur.close()

    def mark_drift_retrained(self, drift_id: int):
        """Mark a drift event as having triggered retraining."""
        cur = self._new_cursor()
        try:
            cur.execute(
                "UPDATE drift_events SET triggered_retrain = TRUE WHERE id = %s",
                (drift_id,)
            )
        finally:
            cur.close()

    def get_recent_drift_events(self, hours: int = 24, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent drift events for dashboard/history."""
        cur = self._new_cursor()
        result = []
        try:
            cur.execute(
                """SELECT id, metric, scope, old_mean, new_mean, drift_magnitude,
                          window_size, severity, description, triggered_retrain, timestamp
                   FROM drift_events
                   ORDER BY timestamp DESC
                   LIMIT %s""",
                (limit,)
            )
            for row in cur.fetchall():
                result.append({
                    "id": row[0],
                    "metric": row[1],
                    "scope": row[2],
                    "old_mean": row[3],
                    "new_mean": row[4],
                    "drift_magnitude": row[5],
                    "window_size": row[6],
                    "severity": row[7],
                    "description": row[8],
                    "triggered_retrain": row[9],
                    "timestamp": str(row[10]) if row[10] else "",
                })
        finally:
            cur.close()
        return result

    def get_drift_stats(self) -> Dict[str, Any]:
        """Get drift statistics for dashboard."""
        cur = self._new_cursor()
        result = {"total": 0, "by_metric": {}, "by_severity": {}, "recent_count": 0}
        try:
            # Total count
            cur.execute("SELECT COUNT(*) FROM drift_events")
            result["total"] = cur.fetchone()[0]

            # By metric
            cur.execute(
                "SELECT metric, COUNT(*) FROM drift_events GROUP BY metric ORDER BY COUNT(*) DESC"
            )
            result["by_metric"] = {row[0]: row[1] for row in cur.fetchall()}

            # By severity
            cur.execute(
                "SELECT severity, COUNT(*) FROM drift_events GROUP BY severity ORDER BY COUNT(*) DESC"
            )
            result["by_severity"] = {row[0]: row[1] for row in cur.fetchall()}

            # Last 24h count
            cur.execute(
                "SELECT COUNT(*) FROM drift_events WHERE timestamp > NOW() - INTERVAL '24 hours'"
            )
            result["recent_count"] = cur.fetchone()[0]
        finally:
            cur.close()
        return result

    def upsert_baseline(self, metric: str, time_window: datetime, mean: float, stddev: float, count: int):
        """Insert or update a baseline measurement."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO baselines (metric, time_window, mean_value, stddev, sample_count, updated_at)
                   VALUES (%s, %s, %s, %s, %s, NOW())
                   ON CONFLICT DO NOTHING""",  # No unique constraint yet, simple insert
                (metric, time_window, mean, stddev, count)
            )
        finally:
            cur.close()
    
    def get_recent_baseline(self, metric: str, window_minutes: int = 60) -> Optional[Dict]:
        """Get the latest baseline for a metric within the time window."""
        cur = self._new_cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
            cur.execute(
                """SELECT metric, time_window, mean_value, stddev, sample_count, updated_at
                   FROM baselines
                   WHERE metric = %s AND time_window > %s
                   ORDER BY time_window DESC
                   LIMIT 1""",
                (metric, cutoff)
            )
            row = cur.fetchone()
            if row:
                return {
                    'metric': row[0],
                    'time_window': row[1],
                    'mean_value': row[2],
                    'stddev': row[3],
                    'sample_count': row[4],
                    'updated_at': row[5],
                }
            return None
        finally:
            cur.close()
    
    def get_event_count_windowed(self, window_minutes: int = 1) -> int:
        """Count events in the last N minutes."""
        cur = self._new_cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp > %s",
                (cutoff,)
            )
            return cur.fetchone()[0]
        finally:
            cur.close()
    
    def get_new_events_since(self, since_id: int = 0, limit: int = 1000) -> List[Dict]:
        """Get events with ID > since_id, ordered by ID."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                          proto, action, interface, direction, version,
                          ip_ttl, ip_total_length, tcp_flags, tcp_seq,
                          tcp_ack, tcp_window, tcp_options,
                          udp_datalen, icmp_datalen
                   FROM events
                   WHERE id > %s
                   ORDER BY id ASC
                   LIMIT %s""",
                (since_id, limit)
            )
            cols = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row)) for row in rows]
        finally:
            cur.close()
    
    def get_anomaly_stats(self, since_hours: int = 24) -> Dict[str, Any]:
        """Get anomaly statistics for the given window."""
        cur = self._new_cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
            
            cur.execute(
                """SELECT attack_type, severity, COUNT(*)
                   FROM anomalies
                   WHERE created_at > %s
                   GROUP BY attack_type, severity
                   ORDER BY COUNT(*) DESC""",
                (cutoff,)
            )
            attack_counts = {}
            for attack, severity, count in cur.fetchall():
                if attack not in attack_counts:
                    attack_counts[attack] = {}
                attack_counts[attack][severity] = count
            
            # Total stats
            cur.execute(
                """SELECT COUNT(*),
                   COUNT(DISTINCT src_ip),
                   COUNT(DISTINCT attack_type),
                   SUM(CASE WHEN discord_sent THEN 1 ELSE 0 END)
                   FROM anomalies
                   WHERE created_at > %s""",
                (cutoff,)
            )
            row = cur.fetchone()
            
            return {
                'total_anomalies': row[0] or 0,
                'unique_src_ips': row[1] or 0,
                'unique_attack_types': row[2] or 0,
                'discord_sent': row[3] or 0,
                'by_type': attack_counts,
            }
        finally:
            cur.close()
    
    def get_recent_anomalies(self, limit: int = 10) -> List[Dict]:
        """Get the N most recent anomalies."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT id, attack_type, severity, src_ip, dst_ip,
                          dst_port, proto, description, detail, discord_sent
                   FROM anomalies
                   ORDER BY created_at DESC
                   LIMIT %s""",
                (limit,)
            )
            cols = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row)) for row in rows]
        finally:
            cur.close()
    
    def prune_events(self, older_than_days: int = 30) -> int:
        """Delete events older than the specified number of days.
        
        Returns the number of deleted events.
        """
        cur = self._new_cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            cur.execute("DELETE FROM events WHERE timestamp < %s", (cutoff,))
            deleted = cur.rowcount
            return deleted
        finally:
            cur.close()
    
    def health_check(self) -> Dict[str, Any]:
        """Check database connectivity and return status."""
        conn = None
        try:
            conn = self.connect()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            
            event_count = self.get_event_count_windowed(window_minutes=60)
            
            # Pool metrics
            pool = EventDatabase._pool
            pool_stats = {
                'pool_max': pool.maxconn if pool else 0,
                'pool_min': pool.minconn if pool else 0,
            }
            if pool:
                # _used tracks checked-out connections, _pool tracks available
                used = len(getattr(pool, '_used', {}))
                available = len(getattr(pool, '_pool', []))
                pool_stats['pool_active'] = used
                pool_stats['pool_available'] = available
                pool_stats['pool_total'] = used + available
                pool_stats['pool_utilization_pct'] = round(used / pool.maxconn * 100, 1) if pool.maxconn else 0.0
            
            db_status = {
                'connected': True,
                'events_last_hour': event_count,
                'host': self.host,
                'database': self.database,
                'pool': pool_stats,
            }
            return db_status
        except Exception as e:
            return {
                'connected': False,
                'error': str(e),
                'pool': {
                    'pool_active': len(getattr(EventDatabase._pool, '_used', {})) if EventDatabase._pool else 0,
                    'pool_available': len(getattr(EventDatabase._pool, '_pool', [])) if EventDatabase._pool else 0,
                    'pool_max': EventDatabase._pool.maxconn if EventDatabase._pool else 0,
                },
            }
        finally:
            if conn:
                self.putconn(conn)

    def search_anomalies(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search anomalies by IP, attack_type, rule_name, or description.
        
        Searches across multiple fields using ILIKE matching. Returns matching
        anomalies ordered by creation time (newest first).
        
        Args:
            query: Free-text search string (matches IP, type, description, etc.)
            limit: Maximum number of results to return
            
        Returns:
            List of anomaly dicts matching the query.
        """
        cur = self._new_cursor()
        try:
            search_pattern = f"%{query}%"
            cur.execute(
                """SELECT id, attack_type, severity, src_ip, dst_ip,
                          dst_port, proto, description, detail, discord_sent, created_at
                   FROM anomalies
                   WHERE src_ip ILIKE %s
                      OR dst_ip ILIKE %s
                      OR attack_type ILIKE %s
                      OR COALESCE(description, '') ILIKE %s
                   ORDER BY created_at DESC
                   LIMIT %s""",
                (search_pattern, search_pattern, search_pattern, search_pattern, limit),
            )
            cols = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            results = []
            for row in rows:
                d = dict(zip(cols, row))
                # Format timestamp for display
                if d.get('created_at'):
                    d['created_at_str'] = d['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')
                results.append(d)
            return results
        finally:
            cur.close()
    
    def get_top_threat_ips(self, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
        """Get top N source IPs ranked by threat score.
        
        Threat score is computed as weighted sum of anomaly counts by severity:
          CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
        
        Args:
            limit: Number of top IPs to return
            hours: Time window in hours (default 24)
            
        Returns:
            List of dicts with ip, threat_score, anomaly_count, attack_types, severity_breakdown.
        """
        cur = self._new_cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            cur.execute(
                """SELECT src_ip,
                          COUNT(*) as total,
                          SUM(CASE WHEN severity = 'CRITICAL' THEN 10
                                   WHEN severity = 'HIGH' THEN 5
                                   WHEN severity = 'MEDIUM' THEN 2
                                   ELSE 1 END) as threat_score,
                          COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_count,
                          COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_count,
                          COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium_count,
                          COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low_count,
                          STRING_AGG(DISTINCT attack_type, ', ' ORDER BY attack_type) as attack_types
                   FROM anomalies
                   WHERE created_at > %s AND src_ip IS NOT NULL
                   GROUP BY src_ip
                   ORDER BY threat_score DESC, total DESC
                   LIMIT %s""",
                (cutoff, limit),
            )
            cols = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row)) for row in rows]
        finally:
            cur.close()

    def _save_baselines(self, baselines_data: Optional[Dict[str, Any]] = None):
        """Persist statistical baselines to the database.
        
        Called periodically by the agent to save learned patterns
        so they survive container restarts.
        
        Args:
            baselines_data: Optional dict of {metric_name: {mean, stddev, count}}.
                          If None, logs a warning.
        """
        try:
            if not baselines_data:
                logger.warning("No baselines data provided to _save_baselines")
                return
            
            conn = self.connect()
            cur = conn.cursor()
            try:
                for metric_name, stats in baselines_data.items():
                    cur.execute(
                        """INSERT INTO baselines 
                           (metric, time_window, mean_value, stddev, sample_count, updated_at)
                           VALUES (%s, NOW(), %s, %s, %s, NOW())
                           ON CONFLICT (metric, time_window)
                           DO UPDATE SET 
                               mean_value = EXCLUDED.mean_value,
                               stddev = EXCLUDED.stddev,
                               sample_count = EXCLUDED.sample_count,
                               updated_at = EXCLUDED.updated_at""",
                        (
                            metric_name,
                            stats.get('mean', 0),
                            stats.get('stddev', 0),
                            stats.get('count', 0),
                        )
                    )
                conn.commit()
                logger.info("Baselines saved to database: %s metrics", len(baselines_data))
            finally:
                cur.close()
                self.putconn(conn)
        except Exception as e:
            logger.warning("Failed to save baselines: %s", e)
    
    # ── Week 1: User Feedback Methods ────────────────────────────────────
    
    def save_feedback(self, rule_name: str, label: str, reason: str = None, user_id: str = None):
        """Save user feedback for a rule classification."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO rule_feedback 
                   (rule_name, timestamp, label, reason, user_id)
                   VALUES (%s, NOW(), %s, %s, %s)""",
                (rule_name, label, reason or "", user_id or "")
            )
            return True
        finally:
            cur.close()
    
    def get_feedback_records(self, rule_name: str, limit: int = 50) -> List[Dict]:
        """Get feedback records for a specific rule."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT id, rule_name, timestamp, label, reason, user_id
                   FROM rule_feedback
                   WHERE rule_name = %s
                   ORDER BY timestamp DESC
                   LIMIT %s""",
                (rule_name, limit)
            )
            if cur.description:
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                return [dict(zip(cols, row)) for row in rows]
            return []
        finally:
            cur.close()
    
    def get_feedback_stats(self, rule_name: str) -> Dict[str, Any]:
        """Get feedback statistics for a rule."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT COUNT(*) as total,
                          SUM(CASE WHEN label = 'correct' THEN 1 ELSE 0 END) as correct,
                          SUM(CASE WHEN label = 'incorrect' THEN 1 ELSE 0 END) as incorrect
                   FROM rule_feedback
                   WHERE rule_name = %s""",
                (rule_name,)
            )
            row = cur.fetchone()
            if row:
                total = row[0] or 0
                correct = row[1] or 0
                incorrect = row[2] or 0
            else:
                total = 0
                correct = 0
                incorrect = 0
            
            agreement_rate = correct / total if total > 0 else 1.0
            
            return {
                'total_records': total,
                'correct_count': correct,
                'incorrect_count': incorrect,
                'agreement_rate': agreement_rate,
            }
        finally:
            cur.close()
    
    # ── Week 2: Baseline Methods ────────────────────────────────────────
    
    def save_rule_baseline(self, rule_name: str, baseline_data: Dict[str, Any]):
        """Save baseline statistics for a rule."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO rule_baselines
                   (rule_name, avg_port_diversity, avg_dest_diversity, avg_volume,
                    avg_block_ratio, baseline_goodness, sample_count, baseline_updated,
                    window_start, window_end)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (rule_name)
                   DO UPDATE SET
                       avg_port_diversity = EXCLUDED.avg_port_diversity,
                       avg_dest_diversity = EXCLUDED.avg_dest_diversity,
                       avg_volume = EXCLUDED.avg_volume,
                       avg_block_ratio = EXCLUDED.avg_block_ratio,
                       baseline_goodness = EXCLUDED.baseline_goodness,
                       sample_count = EXCLUDED.sample_count,
                       baseline_updated = EXCLUDED.baseline_updated,
                       window_start = EXCLUDED.window_start,
                       window_end = EXCLUDED.window_end,
                       updated_at = NOW()""",
                (
                    rule_name,
                    baseline_data.get('avg_port_diversity', 0),
                    baseline_data.get('avg_dest_diversity', 0),
                    baseline_data.get('avg_volume', 0),
                    baseline_data.get('avg_block_ratio', 0),
                    baseline_data.get('baseline_goodness', 0),
                    baseline_data.get('sample_count', 0),
                    baseline_data.get('baseline_updated', False),
                    baseline_data.get('window_start'),
                    baseline_data.get('window_end'),
                )
            )
            return True
        finally:
            cur.close()
    
    def get_rule_baseline(self, rule_name: str) -> Optional[Dict]:
        """Get baseline statistics for a rule."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT rule_name, avg_port_diversity, avg_dest_diversity,
                          avg_volume, avg_block_ratio, baseline_goodness,
                          sample_count, baseline_updated, window_start, window_end
                   FROM rule_baselines
                   WHERE rule_name = %s""",
                (rule_name,)
            )
            row = cur.fetchone()
            if row and cur.description:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
            return None
        finally:
            cur.close()
    
    def update_rule_baselines_from_events(self, rules_data: Dict[str, Dict]):
        """Update all rule baselines from current events."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            for rule_name, data in rules_data.items():
                cur.execute(
                    """INSERT INTO rule_baselines
                       (rule_name, avg_port_diversity, avg_dest_diversity, avg_volume,
                        avg_block_ratio, baseline_goodness, sample_count, baseline_updated)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (rule_name)
                       DO UPDATE SET
                           avg_port_diversity = EXCLUDED.avg_port_diversity,
                           avg_dest_diversity = EXCLUDED.avg_dest_diversity,
                           avg_volume = EXCLUDED.avg_volume,
                           avg_block_ratio = EXCLUDED.avg_block_ratio,
                           baseline_goodness = EXCLUDED.baseline_goodness,
                           sample_count = EXCLUDED.sample_count,
                           baseline_updated = EXCLUDED.baseline_updated,
                           updated_at = NOW()""",
                    (
                        rule_name,
                        data.get('avg_port_diversity', 0),
                        data.get('avg_dest_diversity', 0),
                        data.get('avg_volume', 0),
                        data.get('avg_block_ratio', 0),
                        data.get('baseline_goodness', 0),
                        data.get('sample_count', 0),
                        data.get('baseline_updated', False),
                    )
                )
            conn.commit()
            logger.info(f"Updated baselines for {len(rules_data)} rules")
        except Exception as e:
            conn.rollback()
            logger.warning(f"Failed to update rule baselines: {e}")
        finally:
            cur.close()
            self.putconn(conn)
    
    # ── Week 3: Temporal Pattern Methods ────────────────────────────────
    
    def save_temporal_pattern(self, rule_name: str, hour_distribution: Dict[int, float], total_samples: int):
        """Save temporal pattern for a rule."""
        cur = self._new_cursor()
        try:
            import json
            cur.execute(
                """INSERT INTO rule_temporal_patterns
                   (rule_name, hour_distribution, total_samples)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (rule_name)
                   DO UPDATE SET
                       hour_distribution = EXCLUDED.hour_distribution,
                       total_samples = EXCLUDED.total_samples,
                       updated_at = NOW()""",
                (rule_name, json.dumps(hour_distribution), total_samples)
            )
            return True
        finally:
            cur.close()
    
    def get_temporal_pattern(self, rule_name: str) -> Optional[Dict]:
        """Get temporal pattern for a rule."""
        cur = self._new_cursor()
        try:
            import json
            cur.execute(
                """SELECT rule_name, hour_distribution, total_samples, updated_at
                   FROM rule_temporal_patterns
                   WHERE rule_name = %s""",
                (rule_name,)
            )
            row = cur.fetchone()
            if row and cur.description:
                cols = [desc[0] for desc in cur.description]
                result = dict(zip(cols, row))
                # Parse JSONB column
                result['hour_distribution'] = json.loads(result.get('hour_distribution', '{}') or '{}')
                return result
            return None
        finally:
            cur.close()
    
    def update_temporal_patterns_from_events(self, rules_data: Dict[str, Dict]):
        """Update all temporal patterns from current events."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            import json
            for rule_name, data in rules_data.items():
                cur.execute(
                    """INSERT INTO rule_temporal_patterns
                       (rule_name, hour_distribution, total_samples)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (rule_name)
                       DO UPDATE SET
                           hour_distribution = EXCLUDED.hour_distribution,
                           total_samples = EXCLUDED.total_samples,
                           updated_at = NOW()""",
                    (rule_name, json.dumps(data.get('hour_distribution', {})), data.get('total_samples', 0))
                )
            conn.commit()
            logger.info(f"Updated temporal patterns for {len(rules_data)} rules")
        except Exception as e:
            conn.rollback()
            logger.warning(f"Failed to update temporal patterns: {e}")
        finally:
            cur.close()
            self.putconn(conn)
    
    # ── Nginx Monitoring Methods ─────────────────────────────────────────

    def insert_nginx_event(self, event_data: Dict[str, Any]):
        """Insert a single nginx web request event."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO nginx_events
                   (timestamp, src_ip, method, path, status_code, bytes_sent, request, user_agent, raw_message)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    event_data.get('timestamp'),
                    event_data.get('src_ip'),
                    event_data.get('method'),
                    event_data.get('path'),
                    event_data.get('status_code'),
                    event_data.get('bytes'),
                    event_data.get('request'),
                    event_data.get('user_agent'),
                    event_data.get('raw'),
                )
            )
            return cur.fetchone()[0]
        finally:
            cur.close()

    def insert_nginx_anomaly(self, anomaly_data: Dict[str, Any]) -> int:
        """Insert a detected nginx anomaly."""
        cur = self._new_cursor()
        try:
            detail = anomaly_data.pop('detail', None)
            cur.execute(
                """INSERT INTO nginx_anomalies
                   (timestamp, attack_type, severity, src_ip, path, status_code, description, detail, alert_sent)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    anomaly_data.get('timestamp'),
                    anomaly_data.get('attack_type'),
                    anomaly_data.get('severity'),
                    anomaly_data.get('src_ip'),
                    anomaly_data.get('path'),
                    anomaly_data.get('status_code'),
                    anomaly_data.get('description'),
                    json.dumps(detail) if detail else None,
                    anomaly_data.get('alert_sent', False),
                )
            )
            return cur.fetchone()[0]
        finally:
            cur.close()

    def get_nginx_summary(self, since_hours: int = 24) -> Dict[str, Any]:
        """Get nginx traffic summary for the given window."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
            
            # Total requests
            cur.execute(
                "SELECT COUNT(*) FROM nginx_events WHERE timestamp > %s",
                (cutoff,)
            )
            total_requests = cur.fetchone()[0]
            
            # Requests by method
            cur.execute(
                """SELECT method, COUNT(*) as cnt FROM nginx_events 
                   WHERE timestamp > %s AND method IS NOT NULL 
                   GROUP BY method ORDER BY cnt DESC""",
                (cutoff,)
            )
            by_method = {r[0]: r[1] for r in cur.fetchall()}
            
            # Requests by status code
            cur.execute(
                """SELECT status_code, COUNT(*) as cnt FROM nginx_events 
                   WHERE timestamp > %s AND status_code IS NOT NULL 
                   GROUP BY status_code ORDER BY cnt DESC""",
                (cutoff,)
            )
            by_status = {str(r[0]): r[1] for r in cur.fetchall()}
            
            # Status category breakdown
            cur.execute(
                """SELECT 
                   COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) as ok,
                   COUNT(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 END) as client_err,
                   COUNT(CASE WHEN status_code >= 500 THEN 1 END) as server_err
                   FROM nginx_events WHERE timestamp > %s""",
                (cutoff,)
            )
            row = cur.fetchone()
            
            # Unique source IPs
            cur.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM nginx_events WHERE timestamp > %s AND src_ip IS NOT NULL",
                (cutoff,)
            )
            unique_ips = cur.fetchone()[0]
            
            # Top source IPs
            cur.execute(
                """SELECT src_ip, COUNT(*) as cnt FROM nginx_events 
                   WHERE timestamp > %s AND src_ip IS NOT NULL 
                   GROUP BY src_ip ORDER BY cnt DESC LIMIT 10""",
                (cutoff,)
            )
            top_ips = [{"ip": r[0], "requests": r[1]} for r in cur.fetchall()]
            
            # Top paths
            cur.execute(
                """SELECT path, COUNT(*) as cnt FROM nginx_events 
                   WHERE timestamp > %s AND path IS NOT NULL 
                   GROUP BY path ORDER BY cnt DESC LIMIT 10""",
                (cutoff,)
            )
            top_paths = [{"path": r[0], "requests": r[1]} for r in cur.fetchall()]
            
            # 404 errors (potential scanning)
            cur.execute(
                """SELECT COUNT(*) FROM nginx_events 
                   WHERE timestamp > %s AND status_code = 404""",
                (cutoff,)
            )
            not_found_count = cur.fetchone()[0]
            
            # Recent nginx anomalies
            cur.execute(
                """SELECT attack_type, severity, COUNT(*) as cnt 
                   FROM nginx_anomalies 
                   WHERE created_at > %s 
                   GROUP BY attack_type, severity ORDER BY cnt DESC""",
                (cutoff,)
            )
            anomaly_by_type = {}
            for at, sev, cnt in cur.fetchall():
                if at not in anomaly_by_type:
                    anomaly_by_type[at] = {}
                anomaly_by_type[at][sev] = cnt
            
            return {
                'total_requests': total_requests,
                'by_method': by_method,
                'by_status': by_status,
                'status_ok': row[0] or 0,
                'status_client_err': row[1] or 0,
                'status_server_err': row[2] or 0,
                'unique_ips': unique_ips,
                'top_ips': top_ips,
                'top_paths': top_paths,
                'not_found_404': not_found_count,
                'anomalies_by_type': anomaly_by_type,
            }
        finally:
            cur.close()
            self.putconn(conn)

    def get_nginx_anomalies(self, limit: int = 50) -> List[Dict]:
        """Get recent nginx anomalies."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT id, timestamp, attack_type, severity, src_ip, path, 
                          status_code, description, detail
                   FROM nginx_anomalies
                   ORDER BY created_at DESC
                   LIMIT %s""",
                (limit,)
            )
            cols = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row)) for row in rows]
        finally:
            cur.close()

    def get_nginx_top_paths_timeline(self, hours: int = 24) -> List[Dict]:
        """Get top path request counts over time (for heatmap)."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cur.execute(
                """SELECT date_trunc('hour', timestamp) as hour, 
                          path, COUNT(*) as cnt 
                   FROM nginx_events 
                   WHERE timestamp > %s AND path IS NOT NULL
                   GROUP BY hour, path 
                   ORDER BY hour DESC, cnt DESC""",
                (cutoff,)
            )
            return [dict(zip(['hour', 'path', 'count'], r)) for r in cur.fetchall()]
        finally:
            cur.close()
            self.putconn(conn)

    # ── Utility Methods ─────────────────────────────────────────────────
    
    def get_ml_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for ML self-learning."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            # Feedback stats
            cur.execute(
                """SELECT COUNT(*) as total,
                          SUM(CASE WHEN label = 'correct' THEN 1 ELSE 0 END) as correct
                   FROM rule_feedback"""
            )
            row = cur.fetchone()
            if row:
                feedback_total = row[0] or 0
                feedback_correct = row[1] or 0
            else:
                feedback_total = 0
                feedback_correct = 0
            feedback_agreement = feedback_correct / feedback_total if feedback_total > 0 else 1.0
            
            # Baselines count
            cur.execute("SELECT COUNT(*) FROM rule_baselines WHERE baseline_updated = TRUE")
            row = cur.fetchone()
            baselines_updated = row[0] or 0 if row else 0
            
            # Temporal patterns count (may not exist on older schemas)
            temporal_patterns = 0
            try:
                cur.execute("SELECT COUNT(*) FROM rule_temporal_patterns WHERE total_samples > 0")
                row = cur.fetchone()
                temporal_patterns = row[0] or 0 if row else 0
            except Exception:
                pass
            
            return {
                'feedback_total': feedback_total,
                'feedback_correct': feedback_correct,
                'feedback_agreement': feedback_agreement,
                'baselines_updated': baselines_updated,
                'temporal_patterns': temporal_patterns,
            }
        finally:
            cur.close()
            self.putconn(conn)

    # ── P2-4: Active Learning Queue Methods ─────────────────────────────

    def queue_for_review(self, rule_name: str, classification: str,
                         confidence: float, reasons: str = "",
                         rule_description: str = "") -> int:
        """Add a rule to the active learning queue for human review.
        
        Uses INSERT ... ON CONFLICT to avoid duplicates for the same rule.
        Returns the queue item ID.
        """
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO active_learning_queue
                   (rule_name, rule_description, classification, confidence, reasons, status)
                   VALUES (%s, %s, %s, %s, %s, 'pending')
                   ON CONFLICT (rule_name) DO UPDATE SET
                       classification = EXCLUDED.classification,
                       confidence = EXCLUDED.confidence,
                       reasons = EXCLUDED.reasons,
                       status = CASE WHEN active_learning_queue.status = 'resolved' 
                           THEN 'resolved' ELSE 'pending' END,
                       updated_at = NOW()
                   RETURNING id""",
                (rule_name, rule_description or "", classification, confidence, reasons)
            )
            row = cur.fetchone()
            return row[0] if row else 0
        finally:
            cur.close()

    def get_active_learning_queue(self, status: str = None, limit: int = 100) -> List[Dict]:
        """Get active learning queue items."""
        cur = self._new_cursor()
        try:
            if status:
                cur.execute(
                    """SELECT id, rule_name, rule_description, classification, confidence,
                              reasons, status, resolved_classification, resolved_notes,
                              created_at, resolved_at
                       FROM active_learning_queue
                       WHERE status = %s
                       ORDER BY created_at DESC
                       LIMIT %s""",
                    (status, limit)
                )
            else:
                cur.execute(
                    """SELECT id, rule_name, rule_description, classification, confidence,
                              reasons, status, resolved_classification, resolved_notes,
                              created_at, resolved_at
                       FROM active_learning_queue
                       ORDER BY 
                           CASE status WHEN 'pending' THEN 0 ELSE 1 END,
                           created_at DESC
                       LIMIT %s""",
                    (limit,)
                )
            if cur.description:
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                result = []
                for row in rows:
                    item = dict(zip(cols, row))
                    # Serialize datetime objects
                    for k in ('created_at', 'resolved_at'):
                        if item.get(k):
                            item[k] = item[k].isoformat() if hasattr(item[k], 'isoformat') else str(item[k])
                    result.append(item)
                return result
            return []
        finally:
            cur.close()

    def resolve_active_learning_item(self, item_id: int,
                                      classification: str = "",
                                      notes: str = ""):
        """Mark an active learning queue item as resolved."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """UPDATE active_learning_queue
                   SET status = 'resolved',
                       resolved_classification = %s,
                       resolved_notes = %s,
                       resolved_at = NOW()
                   WHERE id = %s""",
                (classification, notes, item_id)
            )
        finally:
            cur.close()

    def dismiss_active_learning_item(self, item_id: int):
        """Remove an item from the active learning queue."""
        cur = self._new_cursor()
        try:
            cur.execute("DELETE FROM active_learning_queue WHERE id = %s", (item_id,))
        finally:
            cur.close()

    # ── UniFi controller monitoring methods ─────────────────────────────

    def insert_unifi_event(self, event: Dict) -> Optional[int]:
        """Insert a UniFi controller event into the unifi_events table.
        Returns the row ID or None on failure.
        """
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO unifi_events
                   (timestamp, event_key, event_type, severity, mac, ip, device, ap, ssid, message, metadata)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    event.get("timestamp"),
                    event.get("unifi_event_key", ""),
                    event.get("event_type", ""),
                    event.get("severity", "MEDIUM"),
                    event.get("mac", ""),
                    event.get("src_ip", ""),
                    event.get("device", ""),
                    event.get("ap", ""),
                    event.get("ssid", ""),
                    event.get("description", ""),
                    json.dumps(event.get("metadata", {})),
                ),
            )
            row = cur.fetchone()
            self._conn.commit()
            return row[0] if row else None
        except Exception as e:
            logger.error("Failed to insert UniFi event: %s", e)
            return None
        finally:
            cur.close()

    def insert_unifi_client(self, client: Dict) -> Optional[int]:
        """Insert a UniFi client snapshot. Returns row ID or None."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO unifi_clients
                   (mac, ip, hostname, is_wired, essid, ap_mac, rssi, rx_bytes, tx_bytes, connected_at, metadata)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    client.get("mac", ""),
                    client.get("ip", ""),
                    client.get("hostname", ""),
                    client.get("is_wired", False),
                    client.get("essid", ""),
                    client.get("ap_mac", ""),
                    client.get("rssi"),
                    client.get("rx_bytes", 0),
                    client.get("tx_bytes", 0),
                    client.get("connected_at"),
                    json.dumps(client.get("metadata", {})),
                ),
            )
            row = cur.fetchone()
            self._conn.commit()
            return row[0] if row else None
        except Exception as e:
            logger.error("Failed to insert UniFi client: %s", e)
            return None
        finally:
            cur.close()

    def insert_unifi_device(self, device: Dict) -> Optional[int]:
        """Insert a UniFi device snapshot. Returns row ID or None."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO unifi_devices
                   (device_id, mac, ip, name, model, type, state, adopted, uptime, channel, num_sta, metadata)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    device.get("device_id", ""),
                    device.get("mac", ""),
                    device.get("ip", ""),
                    device.get("name", ""),
                    device.get("model", ""),
                    device.get("type", ""),
                    device.get("state", ""),
                    device.get("adopted", False),
                    device.get("uptime"),
                    device.get("channel"),
                    device.get("num_sta", 0),
                    json.dumps(device.get("metadata", {})),
                ),
            )
            row = cur.fetchone()
            self._conn.commit()
            return row[0] if row else None
        except Exception as e:
            logger.error("Failed to insert UniFi device: %s", e)
            return None
        finally:
            cur.close()

    def query_unifi_events(self, limit: int = 100) -> List[Dict]:
        """Get recent UniFi events for dashboard."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """SELECT id, timestamp, event_key, event_type, severity, mac, ip, device, ap, ssid, message
                   FROM unifi_events
                   ORDER BY timestamp DESC LIMIT %s""",
                (limit,),
            )
            if cur.description:
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                result = []
                for row in rows:
                    item = dict(zip(cols, row))
                    if item.get("timestamp"):
                        item["timestamp"] = item["timestamp"].isoformat() if hasattr(item["timestamp"], "isoformat") else str(item["timestamp"])
                    result.append(item)
                return result
            return []
        except Exception as e:
            logger.error("Failed to query UniFi events: %s", e)
            return []
        finally:
            cur.close()

    def query_unifi_summary(self) -> Dict:
        """Get UniFi monitoring summary stats for the dashboard."""
        cur = self._new_cursor()
        try:
            # Event counts by severity
            cur.execute(
                """SELECT severity, COUNT(*) FROM unifi_events
                   WHERE timestamp > NOW() - INTERVAL '24 hours'
                   GROUP BY severity"""
            )
            by_severity = {row[0]: row[1] for row in cur.fetchall()}

            # Event counts by type
            cur.execute(
                """SELECT event_type, COUNT(*) FROM unifi_events
                   WHERE timestamp > NOW() - INTERVAL '24 hours'
                   GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10"""
            )
            by_type = {row[0]: row[1] for row in cur.fetchall()}

            # Unique clients
            cur.execute(
                "SELECT COUNT(DISTINCT mac) FROM unifi_clients WHERE last_seen > NOW() - INTERVAL '24 hours'"
            )
            unique_clients = cur.fetchone()[0]

            # Unique devices
            cur.execute(
                "SELECT COUNT(DISTINCT device_id) FROM unifi_devices WHERE last_seen > NOW() - INTERVAL '24 hours'"
            )
            unique_devices = cur.fetchone()[0]

            # Total events last 24h
            cur.execute(
                "SELECT COUNT(*) FROM unifi_events WHERE timestamp > NOW() - INTERVAL '24 hours'"
            )
            total_events = cur.fetchone()[0]

            return {
                "total_events_24h": total_events,
                "by_severity": by_severity,
                "by_type": by_type,
                "unique_clients_24h": unique_clients,
                "unique_devices_24h": unique_devices,
            }
        except Exception as e:
            logger.error("Failed to query UniFi summary: %s", e)
            return {}
        finally:
            cur.close()


