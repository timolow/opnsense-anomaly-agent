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

logger = logging.getLogger(__name__)

# Default PostgreSQL connection config
DEFAULT_PG_HOST = os.environ.get("DB_HOST", "postgres")
DEFAULT_PG_PORT = int(os.environ.get("DB_PORT", "5432"))
DEFAULT_PG_DB = os.environ.get("DB_NAME", "anomaly_agent")
DEFAULT_PG_USER = os.environ.get("DB_USER", "anomaly_agent")
DEFAULT_PG_PASS = os.environ.get("DB_PASSWORD") or os.environ.get("DB_PASS", "anomaly_agent_secret")


# SQL schema definition
CREATE_TABLES_SQL = """
-- Events table: every parsed firewall event
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_hostname TEXT,
    dst_hostname TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT,
    action TEXT,
    interface TEXT,
    direction TEXT,
    version INTEGER,
    ip_ttl INTEGER,
    ip_total_length INTEGER,
    tcp_flags TEXT,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    tcp_window INTEGER,
    tcp_options TEXT,
    udp_datalen INTEGER,
    icmp_datalen INTEGER,
    raw_message TEXT,
    rule_name TEXT,
    ingested_at TIMESTAMPTZ DEFAULT NOW()
);

-- Anomalies table: detected suspicious activity
CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(id),
    timestamp TIMESTAMPTZ NOT NULL,
    attack_type TEXT NOT NULL,       -- PORT_SCAN, SYN_FLOOD, BRUTE_FORCE, PROBE, GEO_ANOMALY, etc.
    severity TEXT NOT NULL,          -- LOW, MEDIUM, HIGH, CRITICAL
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    proto TEXT,
    description TEXT,
    detail JSONB,                    -- structured attack data
    alert_sent BOOLEAN DEFAULT FALSE,
    discord_sent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Baselines table: statistical baselines for normal traffic
CREATE TABLE IF NOT EXISTS baselines (
    id SERIAL PRIMARY KEY,
    metric TEXT NOT NULL,            -- e.g. "inbound_events_per_minute", "unique_dst_ports_per_hour"
    time_window TIMESTAMPTZ NOT NULL,
    mean_value DOUBLE PRECISION NOT NULL,
    stddev DOUBLE PRECISION NOT NULL,
    sample_count INTEGER NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip) WHERE dst_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port) WHERE dst_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_proto ON events(proto);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_interface ON events(interface);
CREATE INDEX IF NOT EXISTS idx_events_rule_name ON events(rule_name) WHERE rule_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_anomalies_attack_type ON anomalies(attack_type);
CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_created_at ON anomalies(created_at);
CREATE INDEX IF NOT EXISTS idx_anomalies_alert_sent ON anomalies(alert_sent);
CREATE INDEX IF NOT EXISTS idx_baselines_metric ON baselines(metric, time_window);
CREATE UNIQUE INDEX IF NOT EXISTS idx_baselines_metric_window ON baselines(metric, time_window);
CREATE INDEX IF NOT EXISTS idx_anomalies_src_ip ON anomalies(src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);

-- Week 1: User feedback table for ML classification feedback
CREATE TABLE IF NOT EXISTS rule_feedback (
    id SERIAL PRIMARY KEY,
    rule_name TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    label TEXT NOT NULL,              -- "correct" or "incorrect"
    reason TEXT,                      -- optional explanation
    user_id TEXT,                     -- optional user identifier
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Rule baselines table: learned traffic patterns per rule (consolidated schema)
CREATE TABLE IF NOT EXISTS rule_baselines (
    id SERIAL PRIMARY KEY,
    rule TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    ip TEXT,
    hour INTEGER,
    avg_events_per_hour DOUBLE PRECISION DEFAULT 0,
    std_events_per_hour DOUBLE PRECISION DEFAULT 0,
    max_events_per_hour INTEGER DEFAULT 0,
    min_events_per_hour INTEGER DEFAULT 0,
    protocol_distribution JSONB DEFAULT '{}',
    avg_dst_ports DOUBLE PRECISION DEFAULT 0,
    avg_src_ports DOUBLE PRECISION DEFAULT 0,
    avg_unique_dst_ips DOUBLE PRECISION DEFAULT 0,
    pass_ratio DOUBLE PRECISION DEFAULT 0,
    block_ratio DOUBLE PRECISION DEFAULT 0,
    hourly_distribution JSONB DEFAULT '[]',
    sample_count INTEGER DEFAULT 0,
    avg_port_diversity DOUBLE PRECISION DEFAULT 0,
    avg_dest_diversity DOUBLE PRECISION DEFAULT 0,
    avg_volume DOUBLE PRECISION DEFAULT 0,
    avg_block_ratio DOUBLE PRECISION DEFAULT 0,
    baseline_goodness DOUBLE PRECISION DEFAULT 0,
    baseline_updated BOOLEAN DEFAULT FALSE,
    window_start TIMESTAMPTZ,
    window_end TIMESTAMPTZ,
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure unique constraint on rule_name for consistent lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_baselines_rule_name ON rule_baselines(rule_name) WHERE ip IS NULL AND hour IS NULL;

-- IP threat profiles table: unified threat scores per IP
CREATE TABLE IF NOT EXISTS ip_threat_profiles (
    id SERIAL PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    unified_score DOUBLE PRECISION DEFAULT 0,
    total_events INTEGER DEFAULT 0,
    firewall_events INTEGER DEFAULT 0,
    http_events INTEGER DEFAULT 0,
    ids_events INTEGER DEFAULT 0,
    zenarmor_events INTEGER DEFAULT 0,
    nginx_events INTEGER DEFAULT 0,
    baseline_deviations JSONB DEFAULT '[]',
    geo_info JSONB,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ
);

-- Indexes for baseline tables
CREATE INDEX IF NOT EXISTS idx_rule_baselines_rule ON rule_baselines(rule);
CREATE INDEX IF NOT EXISTS idx_rule_baselines_ip ON rule_baselines(ip) WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ip_threat_profiles_score ON ip_threat_profiles(unified_score DESC);
"""


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
        """Create database tables if they don't exist."""
        if self._initialized:
            return
        
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(CREATE_TABLES_SQL)
        cur.close()
        self._initialized = True
        logger.info("Database tables ensured")
    
    def ensure_hostnames_migration(self):
        """Add src_hostname/dst_hostname columns if they don't exist (migration)."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            # Check if columns exist
            cur.execute("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'events' AND column_name IN ('src_hostname', 'dst_hostname')
            """)
            existing = {row[0] for row in cur.fetchall()}
            
            added = []
            for col in ('src_hostname', 'dst_hostname'):
                if col not in existing:
                    cur.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
                    added.append(col)
                    logger.info("Added column: %s to events table", col)
            
            if added:
                logger.info("Migration complete: added columns %s", ", ".join(added))
            else:
                logger.debug("Hostname columns already present in events table")
        finally:
            cur.close()
    
    def ensure_indexes(self):
        """Ensure database indexes exist.
        
        Indexes are created alongside tables in CREATE_TABLES_SQL
        via CREATE INDEX IF NOT EXISTS. This method is called
        separately by agent.py for compatibility.
        """
        # Tables + indexes are already ensured by ensure_tables
        # This method exists for agent.py compatibility
        pass
    
    def close(self):
        """Close the database connection (return to pool)."""
        # No-op with connection pooling — connections are managed by the pool
    
    def _new_cursor(self):
        """Get a new cursor from the connection."""
        return self.connect().cursor()
    
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
        try:
            conn = self.connect()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            
            event_count = self.get_event_count_windowed(window_minutes=60)
            db_status = {
                'connected': True,
                'events_last_hour': event_count,
                'host': self.host,
                'database': self.database,
            }
            return db_status
        except Exception as e:
            return {
                'connected': False,
                'error': str(e),
            }

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
                conn.close()
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
            conn.close()
    
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
            conn.close()
    
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
            conn.close()

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
            
            # Temporal patterns count
            cur.execute("SELECT COUNT(*) FROM rule_temporal_patterns WHERE total_samples > 0")
            row = cur.fetchone()
            temporal_patterns = row[0] or 0 if row else 0
            
            return {
                'feedback_total': feedback_total,
                'feedback_correct': feedback_correct,
                'feedback_agreement': feedback_agreement,
                'baselines_updated': baselines_updated,
                'temporal_patterns': temporal_patterns,
            }
        finally:
            cur.close()
            conn.close()

