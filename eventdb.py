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

logger = logging.getLogger(__name__)

# Default PostgreSQL connection config
DEFAULT_PG_HOST = os.environ.get("DB_HOST", "postgres")
DEFAULT_PG_PORT = int(os.environ.get("DB_PORT", "5432"))
DEFAULT_PG_DB = os.environ.get("DB_NAME", "anomaly_agent")
DEFAULT_PG_USER = os.environ.get("DB_USER", "anomaly_agent")
DEFAULT_PG_PASS = os.environ.get("DB_PASS", "anomaly_agent_secret")


# SQL schema definition
CREATE_TABLES_SQL = """
-- Events table: every parsed firewall event
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
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
CREATE INDEX IF NOT EXISTS idx_anomalies_attack_type ON anomalies(attack_type);
CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_created_at ON anomalies(created_at);
CREATE INDEX IF NOT EXISTS idx_anomalies_alert_sent ON anomalies(alert_sent);
CREATE INDEX IF NOT EXISTS idx_baselines_metric ON baselines(metric, time_window);
CREATE INDEX IF NOT EXISTS idx_anomalies_src_ip ON anomalies(src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);
"""


class EventDatabase:
    """Manages PostgreSQL connection and all database operations."""
    
    def __init__(self, host=None, port=None, database=None, user=None, password=None):
        self.host = host or DEFAULT_PG_HOST
        self.port = port or DEFAULT_PG_PORT
        self.database = database or DEFAULT_PG_DB
        self.user = user or DEFAULT_PG_USER
        self.password = password or DEFAULT_PG_PASS
        self._connection = None
        self._initialized = False
    
    def connect(self):
        """Create or return a database connection."""
        if self._connection and self._connection.closed == 0:
            return self._connection
        
        self._connection = psycopg2.connect(
            host=self.host,
            port=self.port,
            dbname=self.database,
            user=self.user,
            password=self.password
        )
        self._connection.autocommit = True
        return self._connection
    
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
        """Close the database connection."""
        if self._connection and self._connection.closed == 0:
            self._connection.close()
    
    def _new_cursor(self):
        """Get a new cursor from the connection."""
        return self.connect().cursor()
    
    def insert_event(self, event_data: Dict[str, Any], raw_message: str = "") -> int:
        """Insert a single parsed event and return its ID."""
        cur = self._new_cursor()
        try:
            cur.execute(
                """INSERT INTO events
                   (timestamp, src_ip, dst_ip, src_port, dst_port,
                    proto, action, interface, direction, version,
                    ip_ttl, ip_total_length, tcp_flags, tcp_seq,
                    tcp_ack, tcp_window, tcp_options,
                    udp_datalen, icmp_datalen, raw_message)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    event_data.get('timestamp'),
                    event_data.get('src_ip'),
                    event_data.get('dst_ip'),
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
                   (timestamp, src_ip, dst_ip, src_port, dst_port,
                    proto, action, interface, direction, version,
                    ip_ttl, ip_total_length, tcp_flags, tcp_seq,
                    tcp_ack, tcp_window, tcp_options,
                    udp_datalen, icmp_datalen, raw_message)
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
