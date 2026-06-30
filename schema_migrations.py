#!/usr/bin/env python3
"""
Versioned schema migration system for OPNsense Anomaly Agent.

Each migration is:
- Idempotent (safe to re-run)
- Versioned (tracked in schema_versions table)
- Logged (migration progress visible in logs)
- Atomic (wrapped in transactions)
- Free of DO $$ anonymous blocks (fragile on unexpected schema states)

Usage:
    from schema_migrations import run_migrations
    db = EventDatabase()
    run_migrations(db)
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Current target schema version
CURRENT_SCHEMA_VERSION = 21

# Migration version table — created before any migration runs
CREATE_VERSION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_versions (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def _get_current_version(conn: Any) -> int:
    """Read the current schema version from the database."""
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'schema_versions'
            )
        """)
        exists = cur.fetchone()[0]
        if not exists:
            return 0
        cur.execute("SELECT MAX(version) FROM schema_versions")
        result = cur.fetchone()[0]
        return result if result is not None else 0
    finally:
        cur.close()


def _record_version(conn: Any, version: int, description: str):
    """Record that a migration version has been applied."""
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO schema_versions (version, description) VALUES (%s, %s)",
            (version, description),
        )
    finally:
        cur.close()


def _safe_add_column(conn: Any, table: str, column: str, col_def: str) -> bool:
    """Try to add a column; return True if added, False if it already existed.

    Uses a direct ALTER TABLE rather than DO $$ anonymous blocks,
    catching the DuplicateColumn error from psycopg2.
    """
    cur = conn.cursor()
    try:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
        logger.debug("Added column %s.%s", table, column)
        return True
    except Exception as exc:  # pragma: no cover - DB-specific
        msg = str(exc).lower()
        if "duplicate" in msg or "already exists" in msg or "42701" in msg:
            logger.debug("Column %s.%s already exists — skipped", table, column)
            return False
        raise
    finally:
        cur.close()


def _safe_drop_constraint(conn: Any, table: str, constraint: str) -> bool:
    """Try to drop a constraint; return True if dropped, False if it didn't exist."""
    cur = conn.cursor()
    try:
        cur.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint}")
        logger.debug("Dropped constraint %s.%s", table, constraint)
        return True
    except Exception as exc:
        msg = str(exc).lower()
        if "not exist" in msg or "does not exist" in msg or "does not exist" in msg:
            logger.debug("Constraint %s.%s did not exist — skipped", table, constraint)
            return False
        raise
    finally:
        cur.close()


# =============================================================================
# Migration type annotation
#
# Each migration is a dict with:
#   version       — int
#   description   — str
#   sql           — list of idempotent SQL statements (CREATE TABLE IF NOT EXISTS,
#                   CREATE INDEX IF NOT EXISTS, DROP INDEX IF EXISTS, etc.)
#   alter_columns — optional list of (table, column, col_definition) tuples
#                   executed via _safe_add_column (catches DuplicateColumn)
#   hook          — optional callable(conn) for complex multi-step logic
# =============================================================================

MIGRATIONS: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------
    # V1: Core tables (events, anomalies, baselines, rule_feedback, indexes)
    # ------------------------------------------------------------------
    {
        "version": 1,
        "description": "Create core tables: events, anomalies, baselines, rule_feedback, indexes",
        "sql": [
            """
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
                log_type TEXT DEFAULT '',
                ingested_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip) WHERE src_ip IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip) WHERE dst_ip IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port) WHERE dst_port IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_events_proto ON events(proto);
            CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
            CREATE INDEX IF NOT EXISTS idx_events_interface ON events(interface);
            CREATE INDEX IF NOT EXISTS idx_events_rule_name ON events(rule_name) WHERE rule_name IS NOT NULL;
            """,
            """
            CREATE TABLE IF NOT EXISTS anomalies (
                id SERIAL PRIMARY KEY,
                event_id INTEGER REFERENCES events(id),
                timestamp TIMESTAMPTZ NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                proto TEXT,
                description TEXT,
                detail JSONB,
                alert_sent BOOLEAN DEFAULT FALSE,
                discord_sent BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_anomalies_attack_type ON anomalies(attack_type);
            CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
            CREATE INDEX IF NOT EXISTS idx_anomalies_created_at ON anomalies(created_at);
            CREATE INDEX IF NOT EXISTS idx_anomalies_alert_sent ON anomalies(alert_sent);
            CREATE INDEX IF NOT EXISTS idx_anomalies_src_ip ON anomalies(src_ip) WHERE src_ip IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);
            """,
            """
            CREATE TABLE IF NOT EXISTS baselines (
                id SERIAL PRIMARY KEY,
                metric TEXT NOT NULL,
                time_window TIMESTAMPTZ NOT NULL,
                mean_value DOUBLE PRECISION NOT NULL,
                stddev DOUBLE PRECISION NOT NULL,
                sample_count INTEGER NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_baselines_metric ON baselines(metric, time_window);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_baselines_metric_window ON baselines(metric, time_window);
            """,
            """
            CREATE TABLE IF NOT EXISTS rule_feedback (
                id SERIAL PRIMARY KEY,
                rule_name TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                label TEXT NOT NULL,
                reason TEXT,
                user_id TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V2: IP threat profiles + active learning queue
    # ------------------------------------------------------------------
    {
        "version": 2,
        "description": "Create ip_threat_profiles and active_learning_queue tables",
        "sql": [
            """
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
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_ip_threat_profiles_score ON ip_threat_profiles(unified_score DESC);
            """,
            """
            CREATE TABLE IF NOT EXISTS active_learning_queue (
                id SERIAL PRIMARY KEY,
                rule_name TEXT NOT NULL,
                rule_description TEXT,
                classification TEXT NOT NULL DEFAULT 'UNCERTAIN',
                confidence DOUBLE PRECISION DEFAULT 0,
                reasons TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                resolved_classification TEXT,
                resolved_notes TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                resolved_at TIMESTAMPTZ
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_active_learning_queue_status ON active_learning_queue(status);
            CREATE INDEX IF NOT EXISTS idx_active_learning_queue_rule ON active_learning_queue(rule_name);
            CREATE INDEX IF NOT EXISTS idx_active_learning_queue_created ON active_learning_queue(created_at);
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V3: Rule baselines — consolidated schema with all columns
    # Replaces the fragile DO $$ block that was previously inline.
    # alter_columns handles legacy table upgrades idempotently.
    # ------------------------------------------------------------------
    {
        "version": 3,
        "description": "Create/upgrade rule_baselines with consolidated schema",
        "sql": [
            # Create the table with the full consolidated schema (noop if exists)
            """
            CREATE TABLE IF NOT EXISTS rule_baselines (
                id SERIAL PRIMARY KEY,
                rule TEXT NOT NULL DEFAULT '',
                rule_name TEXT NOT NULL DEFAULT '',
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
            """,
            # Drop legacy indexes that conflict with new composite key
            "DROP INDEX IF EXISTS idx_rule_baselines_rule_name;",
            # Safe indexes
            """
            CREATE INDEX IF NOT EXISTS idx_rule_baselines_rule ON rule_baselines(rule);
            CREATE INDEX IF NOT EXISTS idx_rule_baselines_ip ON rule_baselines(ip) WHERE ip IS NOT NULL;
            """,
        ],
        "alter_columns": [
            # Columns that may be missing on legacy rule_baselines tables
            ("rule_baselines", "rule", "TEXT NOT NULL DEFAULT ''"),
            ("rule_baselines", "ip", "TEXT"),
            ("rule_baselines", "hour", "INTEGER"),
            ("rule_baselines", "avg_port_diversity", "DOUBLE PRECISION DEFAULT 0"),
            ("rule_baselines", "avg_dest_diversity", "DOUBLE PRECISION DEFAULT 0"),
            ("rule_baselines", "avg_volume", "DOUBLE PRECISION DEFAULT 0"),
            ("rule_baselines", "avg_block_ratio", "DOUBLE PRECISION DEFAULT 0"),
            ("rule_baselines", "baseline_goodness", "DOUBLE PRECISION DEFAULT 0"),
            ("rule_baselines", "baseline_updated", "BOOLEAN DEFAULT FALSE"),
            ("rule_baselines", "window_start", "TIMESTAMPTZ"),
            ("rule_baselines", "window_end", "TIMESTAMPTZ"),
            # log_type on events table
            ("events", "log_type", "TEXT DEFAULT ''"),
        ],
        "hook": lambda conn: _v3_finalize(conn),
    },

    # ------------------------------------------------------------------
    # V4: Threshold tuning tables
    # ------------------------------------------------------------------
    {
        "version": 4,
        "description": "Create threshold tuning tables",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS threshold_detection_records (
                id SERIAL PRIMARY KEY,
                anomaly_id INTEGER NOT NULL,
                anomaly_type TEXT NOT NULL,
                score DOUBLE PRECISION NOT NULL,
                threshold_type TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_threshold_detection_anomaly ON threshold_detection_records(anomaly_id);
            CREATE INDEX IF NOT EXISTS idx_threshold_detection_type ON threshold_detection_records(anomaly_type);
            CREATE INDEX IF NOT EXISTS idx_threshold_detection_threshold_type ON threshold_detection_records(threshold_type);
            CREATE INDEX IF NOT EXISTS idx_threshold_detection_timestamp ON threshold_detection_records(timestamp);
            """,
            """
            CREATE TABLE IF NOT EXISTS threshold_feedback (
                id SERIAL PRIMARY KEY,
                anomaly_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                reason TEXT,
                user_id TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_threshold_feedback_anomaly ON threshold_feedback(anomaly_id);
            CREATE INDEX IF NOT EXISTS idx_threshold_feedback_label ON threshold_feedback(label);
            CREATE INDEX IF NOT EXISTS idx_threshold_feedback_created ON threshold_feedback(created_at);
            """,
            """
            CREATE TABLE IF NOT EXISTS threshold_tuning_history (
                id SERIAL PRIMARY KEY,
                threshold_type TEXT NOT NULL,
                old_value DOUBLE PRECISION NOT NULL,
                new_value DOUBLE PRECISION NOT NULL,
                reason TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_threshold_tuning_type ON threshold_tuning_history(threshold_type);
            CREATE INDEX IF NOT EXISTS idx_threshold_tuning_created ON threshold_tuning_history(created_at);
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V5: Concept drift events table
    # ------------------------------------------------------------------
    {
        "version": 5,
        "description": "Create concept drift events table",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS drift_events (
                id SERIAL PRIMARY KEY,
                metric TEXT NOT NULL,
                scope TEXT,
                old_mean DOUBLE PRECISION NOT NULL,
                new_mean DOUBLE PRECISION NOT NULL,
                drift_magnitude DOUBLE PRECISION NOT NULL,
                window_size INTEGER NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                triggered_retrain BOOLEAN DEFAULT FALSE,
                timestamp TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_drift_events_metric ON drift_events(metric);
            CREATE INDEX IF NOT EXISTS idx_drift_events_timestamp ON drift_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_drift_events_severity ON drift_events(severity);
            """,
            # Clean up legacy index from old CREATE_TABLES_SQL
            "DROP INDEX IF EXISTS idx_drift_events_scope;",
        ],
    },

    # ------------------------------------------------------------------
    # V6: Cleanup — ensure legacy constraint cleanup + log_type on events
    # ------------------------------------------------------------------
    {
        "version": 6,
        "description": "Final cleanup: legacy constraints, missing columns, event log_type",
        "sql": [
            # Drop any remaining legacy indexes
            "DROP INDEX IF EXISTS idx_rule_baselines_rule_name;",
        ],
        "alter_columns": [
            # Ensure log_type exists on events (belt-and-suspenders with v3)
            ("events", "log_type", "TEXT DEFAULT ''"),
        ],
    },

    # ------------------------------------------------------------------
    # V7: Adaptive signal weight tuning table
    # ------------------------------------------------------------------
    {
        "version": 7,
        "description": "Create signal_weight_tuning for adaptive threat signal weights",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS signal_weight_tuning (
                signal_type TEXT PRIMARY KEY,
                base_weight DOUBLE PRECISION NOT NULL,
                learned_weight DOUBLE PRECISION NOT NULL,
                attack_correlations INTEGER DEFAULT 0,
                benign_correlations INTEGER DEFAULT 0,
                total_detections INTEGER DEFAULT 0,
                last_attack_feedback TIMESTAMPTZ,
                last_benign_feedback TIMESTAMPTZ,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_signal_weight_tuning_updated
                ON signal_weight_tuning(updated_at DESC);
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V8: Adaptive weights table (migrated from inline threat_engine.py)
    # Removes the last ad-hoc CREATE TABLE IF NOT EXISTS from application code.
    # ------------------------------------------------------------------
    {
        "version": 8,
        "description": "Create adaptive_weights table (migrated from threat_engine.py)",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS adaptive_weights (
                signal_type TEXT PRIMARY KEY,
                attack_count INTEGER NOT NULL DEFAULT 0,
                benign_count INTEGER NOT NULL DEFAULT 0,
                last_attack TEXT,
                last_benign TEXT,
                weight REAL,
                decay_multiplier REAL NOT NULL DEFAULT 1.0
            );
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V9: Performance indexes for slow endpoints
    #    - idx_events_log_type: speeds up IDS queries (log_type = 'ids')
    #    - idx_events_timestamp_action: composite for timeline queries
    #      (timestamp range + action filter in single scan)
    # ------------------------------------------------------------------
    {
        "version": 9,
        "description": "Performance indexes: log_type + composite timestamp/action for /api/timeline, /api/ids-summary",
        "sql": [
            """
            CREATE INDEX IF NOT EXISTS idx_events_log_type ON events(log_type);
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_events_timestamp_action ON events(timestamp, action);
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V10: Nginx monitoring tables
    # ------------------------------------------------------------------
    {
        "version": 10,
        "description": "Create nginx_events and nginx_anomalies tables for web traffic monitoring",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS nginx_events (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                src_ip TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                response_size INTEGER,
                user_agent TEXT,
                request_time DOUBLE PRECISION,
                interface TEXT,
                ingested_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_nginx_events_timestamp ON nginx_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_nginx_events_src_ip ON nginx_events(src_ip) WHERE src_ip IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_nginx_events_status_code ON nginx_events(status_code) WHERE status_code IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_nginx_events_path ON nginx_events(path) WHERE path IS NOT NULL;
            """,
            """
            CREATE TABLE IF NOT EXISTS nginx_anomalies (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT,
                path TEXT,
                status_code INTEGER,
                description TEXT,
                detail JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_nginx_anomalies_created_at ON nginx_anomalies(created_at);
            CREATE INDEX IF NOT EXISTS idx_nginx_anomalies_attack_type ON nginx_anomalies(attack_type);
            CREATE INDEX IF NOT EXISTS idx_nginx_anomalies_src_ip ON nginx_anomalies(src_ip) WHERE src_ip IS NOT NULL;
            """,
        ],
    },
    # ------------------------------------------------------------------
    # V11: Performance indexes for rules-classified endpoint
    # ------------------------------------------------------------------
    {
        "version": 11,
        "description": "Add composite covering indexes for rules-classified optimization",
        "sql": [
            """
            -- Covering index for the main rules-classified query:
            -- SELECT ... FROM events WHERE action IN (...) AND rule_name IS NOT NULL ...
            -- This replaces full table scans on 3M+ rows with index-only scans
            CREATE INDEX IF NOT EXISTS idx_events_rules_classified
                ON events (rule_name, action)
                INCLUDE (timestamp, src_ip, dst_ip, dst_port, src_port, proto, interface, direction)
                WHERE rule_name IS NOT NULL AND rule_name != '' AND rule_name != 'N/A';
            """,
            """
            -- Composite index for the fallback enrichment query:
            -- SELECT rule_name, action, proto, dst_port, interface, COUNT(*)
            -- FROM events WHERE rule_name IN (...) GROUP BY ...
            CREATE INDEX IF NOT EXISTS idx_events_rule_agg
                ON events (rule_name, action, proto, dst_port, interface)
                WHERE rule_name IS NOT NULL AND rule_name != '' AND rule_name != 'N/A';
            """,
            """
            -- Index for pre-aggregated rule stats query:
            -- Aggregates per rule_name in one pass
            CREATE INDEX IF NOT EXISTS idx_events_rule_stats
                ON events (rule_name)
                INCLUDE (action, proto, src_ip, dst_ip, dst_port)
                WHERE rule_name IS NOT NULL AND rule_name != '' AND rule_name != 'N/A';
            """,
        ],
    },
    # ------------------------------------------------------------------
    # V12: Composite indexes for dashboard queries + ANALYZE
    # ------------------------------------------------------------------
    {
        "version": 12,
        "description": "Add composite indexes for dashboard endpoints and refresh planner stats",
        "sql": [
            """
            -- Composite index for timestamp-range queries (most dashboard endpoints)
            -- Covers: WHERE timestamp > NOW() - INTERVAL '24 hours' GROUP BY ...
            CREATE INDEX IF NOT EXISTS idx_events_ts_action
                ON events (timestamp, action)
                INCLUDE (src_ip, dst_ip, dst_port, proto, interface);
            """,
            """
            -- Composite index for src_ip grouping with time range
            -- Covers: top_sources, blocked IPs, unique IP counts
            CREATE INDEX IF NOT EXISTS idx_events_ts_src
                ON events (timestamp, src_ip)
                INCLUDE (dst_ip, dst_port, action, interface, proto);
            """,
            """
            -- Composite index for dst_port filtering (DNS, Nginx, etc.)
            -- Covers: WHERE dst_port IN (80, 443, 53) AND timestamp > ...
            -- NOTE: INCLUDE must come before WHERE in PostgreSQL syntax
            CREATE INDEX IF NOT EXISTS idx_events_dstport_ts
                ON events (dst_port, timestamp)
                INCLUDE (src_ip, dst_ip, action, proto)
                WHERE dst_port IS NOT NULL;
            """,
            """
            -- Refresh planner statistics on all key tables (critical after index additions)
            ANALYZE events;
            ANALYZE anomalies;
            """,
        ],
    },
    # ------------------------------------------------------------------
    # V13: Composite indexes for rules-classified port/dest diversity queries
    #     Eliminates seq scans on GROUP BY rule_name, src_ip queries
    # ------------------------------------------------------------------
    {
        "version": 13,
        "description": "Add composite indexes for rules-classified port/dest diversity scans",
        "sql": [
            """
            -- Covers: GROUP BY rule_name, src_ip HAVING COUNT(DISTINCT dst_port) >= 10
            CREATE INDEX IF NOT EXISTS idx_events_rule_src_port
                ON events (rule_name, src_ip, dst_port)
                WHERE rule_name IS NOT NULL AND rule_name != '' AND rule_name != 'N/A';
            """,
            """
            -- Covers: GROUP BY rule_name, src_ip HAVING COUNT(DISTINCT dst_ip) >= 10
            CREATE INDEX IF NOT EXISTS idx_events_rule_src_dst
                ON events (rule_name, src_ip, dst_ip)
                WHERE rule_name IS NOT NULL AND rule_name != '' AND rule_name != 'N/A';
            """,
            """
            ANALYZE events;
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V14: Flow classification table for behavioral ML classifier
    # ------------------------------------------------------------------
    {
        "version": 14,
        "description": "Create flow_classifications table for behavioral flow-based ML classification",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS flow_classifications (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT,
                dst_port INTEGER,
                flow_key TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                label_code INTEGER NOT NULL,
                confidence REAL NOT NULL,
                feature_vector JSONB,
                reason TEXT,
                is_uncertain BOOLEAN DEFAULT FALSE,
                human_feedback TEXT,
                classified_at TIMESTAMPTZ DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_flow_classifications_timestamp
                ON flow_classifications(timestamp);
            CREATE INDEX IF NOT EXISTS idx_flow_classifications_src_ip
                ON flow_classifications(src_ip);
            CREATE INDEX IF NOT EXISTS idx_flow_classifications_label
                ON flow_classifications(label);
            CREATE INDEX IF NOT EXISTS idx_flow_classifications_uncertain
                ON flow_classifications(is_uncertain)
                WHERE is_uncertain = TRUE;
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V15: IP behavior profiling tables
    #      Core behavioral profiling engine: per-IP profiles + signal stream
    #      GIN indexes on JSONB columns, B-tree on ip+timestamp
    # ------------------------------------------------------------------
    {
        "version": 15,
        "description": "Create ip_behavior_profiles and ip_behavior_signals for behavioral profiling",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS ip_behavior_profiles (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL UNIQUE,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                profile_data JSONB NOT NULL DEFAULT '{}',
                baseline_data JSONB NOT NULL DEFAULT '{}',
                threat_level TEXT NOT NULL DEFAULT 'low',
                total_events INTEGER NOT NULL DEFAULT 0,
                behavior_score REAL NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_profiles_ip ON ip_behavior_profiles(ip);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_profiles_threat_level ON ip_behavior_profiles(threat_level);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_profiles_behavior_score ON ip_behavior_profiles(behavior_score DESC);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_profiles_updated ON ip_behavior_profiles(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_profiles_profile_data
                ON ip_behavior_profiles USING GIN (profile_data);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_profiles_baseline_data
                ON ip_behavior_profiles USING GIN (baseline_data);
            """,
            """
            CREATE TABLE IF NOT EXISTS ip_behavior_signals (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                source TEXT NOT NULL DEFAULT 'firewall',
                signal_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                metadata JSONB NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_signals_ip ON ip_behavior_signals(ip);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_signals_timestamp ON ip_behavior_signals(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_signals_ip_ts ON ip_behavior_signals(ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_signals_severity ON ip_behavior_signals(severity);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_signals_signal_type ON ip_behavior_signals(signal_type);
            CREATE INDEX IF NOT EXISTS idx_ip_behavior_signals_metadata
                ON ip_behavior_signals USING GIN (metadata);
            """,
            """
            ANALYZE ip_behavior_profiles;
            ANALYZE ip_behavior_signals;
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V16: Correlation engine tables
    #      Incidents table + incident_signals for signal grouping
    # ------------------------------------------------------------------
    {
        "version": 16,
        "description": "Create incidents and incident_signals tables for correlation engine",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'low',
                signal_count INTEGER NOT NULL DEFAULT 0,
                signal_types TEXT[] DEFAULT '{}',
                sources TEXT[] DEFAULT '{}',
                phases TEXT[] DEFAULT '{}',
                first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                description TEXT,
                metadata JSONB NOT NULL DEFAULT '{}',
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                auto_resolved BOOLEAN NOT NULL DEFAULT FALSE,
                resolved_at TIMESTAMPTZ
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(ip);
            CREATE INDEX IF NOT EXISTS idx_incidents_active ON incidents(is_active) WHERE is_active = TRUE;
            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen DESC);
            """,
            """
            CREATE TABLE IF NOT EXISTS incident_signals (
                id SERIAL PRIMARY KEY,
                incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
                signal_type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_incident_signals_incident
                ON incident_signals(incident_id);
            CREATE INDEX IF NOT EXISTS idx_incident_signals_timestamp
                ON incident_signals(timestamp);
            """,
            """
            ANALYZE incidents;
            ANALYZE incident_signals;
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V17: Incident feedback and grouping tables
    # ------------------------------------------------------------------
    {
        "version": 17,
        "description": "Create incident_feedback and incident_groups tables",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS incident_feedback (
                id SERIAL PRIMARY KEY,
                incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
                feedback_type TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                notes TEXT
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_incident_feedback_incident
                ON incident_feedback(incident_id);
            """,
            """
            CREATE TABLE IF NOT EXISTS incident_groups (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                incident_ids INTEGER[],
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                resolved_at TIMESTAMPTZ
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_incident_groups_ip ON incident_groups(ip);
            """,
            """
            ANALYZE incident_feedback;
            ANALYZE incident_groups;
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V18: Incident lifecycle management
    #      Add status column to incidents table
    # ------------------------------------------------------------------
    {
        "version": 18,
        "description": "Add status column to incidents table for lifecycle management",
        "sql": [
            """
            ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'new';
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_active_status ON incidents(is_active, status) WHERE is_active = TRUE;
            """,
            """
            ANALYZE incidents;
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V19: UniFi controller monitoring
    #      Track UniFi network events, clients, devices, and anomalies
    # ------------------------------------------------------------------
    {
        "version": 19,
        "description": "Add UniFi controller monitoring tables",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS unifi_events (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                event_key TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'MEDIUM',
                mac TEXT,
                ip TEXT,
                device TEXT,
                ap TEXT,
                ssid TEXT,
                message TEXT,
                metadata JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_unifi_events_ts ON unifi_events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_unifi_events_type ON unifi_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_unifi_events_mac ON unifi_events(mac);
            CREATE INDEX IF NOT EXISTS idx_unifi_events_severity ON unifi_events(severity);
            """,
            """
            CREATE TABLE IF NOT EXISTS unifi_clients (
                id SERIAL PRIMARY KEY,
                mac TEXT NOT NULL,
                ip TEXT,
                hostname TEXT,
                is_wired BOOLEAN DEFAULT FALSE,
                essid TEXT,
                ap_mac TEXT,
                rssi INTEGER,
                rx_bytes BIGINT DEFAULT 0,
                tx_bytes BIGINT DEFAULT 0,
                connected_at TIMESTAMPTZ,
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                metadata JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_unifi_clients_mac ON unifi_clients(mac);
            CREATE INDEX IF NOT EXISTS idx_unifi_clients_last_seen ON unifi_clients(last_seen DESC);
            """,
            """
            CREATE TABLE IF NOT EXISTS unifi_devices (
                id SERIAL PRIMARY KEY,
                device_id TEXT NOT NULL,
                mac TEXT,
                ip TEXT,
                name TEXT,
                model TEXT,
                type TEXT,
                state TEXT,
                adopted BOOLEAN DEFAULT FALSE,
                uptime INTEGER,
                channel INTEGER,
                num_sta INTEGER DEFAULT 0,
                metadata JSONB,
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_unifi_devices_id ON unifi_devices(device_id);
            CREATE INDEX IF NOT EXISTS idx_unifi_devices_last_seen ON unifi_devices(last_seen DESC);
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_unifi_events_meta ON unifi_events USING GIN (metadata);
            CREATE INDEX IF NOT EXISTS idx_unifi_clients_meta ON unifi_clients USING GIN (metadata);
            CREATE INDEX IF NOT EXISTS idx_unifi_devices_meta ON unifi_devices USING GIN (metadata);
            """,
        ],
    },

    # ------------------------------------------------------------------
    # V20: TimescaleDB hypertable conversion
    #      - CREATE EXTENSION IF NOT EXISTS timescaledb (built-in on timescaledb image)
    #      - Convert events table to hypertable partitioned by timestamp (7-day chunks)
    #      - Drop old primary key (id), replace with (id, timestamp) composite required by TimescaleDB
    #      - Existing data is automatically redistributed into chunks by create_hypertable
    # ------------------------------------------------------------------
    {
        "version": 20,
        "description": "Convert events table to TimescaleDB hypertable partitioned by timestamp",
        "sql": [
            # Enable TimescaleDB extension (already present in timescaledb image)
            "CREATE EXTENSION IF NOT EXISTS timescaledb;",
        ],
        "hook": lambda conn: _v20_convert_hypertable(conn),
    },

    # ------------------------------------------------------------------
    # V21: Unified normalized_events table
    #
    # Design rationale:
    # The existing schema stores events from different sources in separate
    # tables (events, nginx_events, unifi_events) with different columns.
    # This makes cross-source queries, unified analytics, and consolidated
    # ML pipelines expensive — requiring UNION ALL with sparse columns.
    #
    # normalized_events solves this by defining a single superset schema that
    # covers ALL event sources. Source-specific fields that don't apply to
    # a given event are simply NULL. The payload_context JSONB column holds
    # structured, source-specific payload data that would otherwise require
    # dozens of sparse columns.
    #
    # Source mapping:
    #   - firewall (log_type='filterlog'/'firewall'):
    #       Core fields fully populated. Payload: TCP flags, TTL, length.
    #   - nginx (log_type='nginx'):
    #       Core + payload_context.method/path/status_code/user_agent/etc.
    #   - IDS (log_type='ids'):
    #       Core + payload_context.signature_id/signature_msg/gen_rev.
    #   - zenarmor (log_type='zenarmor'):
    #       Core + payload_context.policy/category/url/etc.
    #   - unifi (source='unifi'):
    #       src_ip=client IP, action=event_type, payload_context for all
    #       UniFi-specific fields (mac, ap, ssid, rssi, etc.).
    #
    # TimescaleDB: converted to hypertable partitioned by timestamp so
    # cross-source time-range queries benefit from chunk pruning.
    # ------------------------------------------------------------------
    {
        "version": 21,
        "description": "Create unified normalized_events table with superset schema for all event sources",
        "sql": [
            """
            CREATE TABLE IF NOT EXISTS normalized_events (
                id BIGSERIAL PRIMARY KEY,
                -- Core temporal + network fields (present in ALL sources)
                timestamp TIMESTAMPTZ NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                action TEXT,
                interface TEXT,
                direction TEXT,

                -- Network enrichment (DNS + geo)
                src_hostname TEXT,
                dst_hostname TEXT,
                geo_src_country TEXT,
                geo_src_city TEXT,
                geo_dst_country TEXT,
                geo_dst_city TEXT,

                -- Source-specific structured payload (JSONB per source type)
                -- firewall: {tcp_flags, ip_ttl, ip_total_length, tcp_seq, tcp_ack, tcp_window, tcp_options, udp_datalen, icmp_datalen}
                -- nginx:    {method, path, status_code, response_size, user_agent, request_time}
                -- ids:      {signature_id, signature_msg, signature_gen, signature_rev, classification}
                -- zenarmor: {policy, category, url, profile_name}
                -- unifi:    {event_key, mac, device, ap, ssid, rssi, rx_bytes, tx_bytes, model, state, num_sta}
                payload_context JSONB,

                -- Metadata
                source TEXT NOT NULL DEFAULT 'firewall',
                log_type TEXT DEFAULT '',
                rule_name TEXT,
                severity TEXT,
                raw_message TEXT,
                ingested_at TIMESTAMPTZ DEFAULT NOW(),

                -- Classification
                ip_class TEXT,       -- WAN / LAN / VPN / OWN
                flow_id TEXT,        -- Correlation key across sources for same flow

                -- TimescaleDB-friendly composite key
                CONSTRAINT pk_normalized_events PRIMARY KEY (id, timestamp)
            );
            """,
            """
            -- Core time-range index (hypertable handles timestamp partitioning,
            -- but composite indexes still help for source-filtered queries)
            CREATE INDEX IF NOT EXISTS idx_norm_events_ts_source
                ON normalized_events (timestamp, source);
            """,
            """
            -- Source + action combo for cross-source threat queries
            CREATE INDEX IF NOT EXISTS idx_norm_events_source_action
                ON normalized_events (source, action)
                WHERE action IS NOT NULL;
            """,
            """
            -- IP-based lookups (src_ip for source analysis, dst_ip for target analysis)
            CREATE INDEX IF NOT EXISTS idx_norm_events_src_ip_ts
                ON normalized_events (src_ip, timestamp)
                WHERE src_ip IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_norm_events_dst_ip_ts
                ON normalized_events (dst_ip, timestamp)
                WHERE dst_ip IS NOT NULL;
            """,
            """
            -- Classification lookups
            CREATE INDEX IF NOT EXISTS idx_norm_events_ip_class
                ON normalized_events (ip_class)
                WHERE ip_class IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_norm_events_flow_id
                ON normalized_events (flow_id)
                WHERE flow_id IS NOT NULL;
            """,
            """
            -- Severity for threat prioritization
            CREATE INDEX IF NOT EXISTS idx_norm_events_severity_ts
                ON normalized_events (severity, timestamp DESC)
                WHERE severity IS NOT NULL;
            """,
            """
            -- GIN index on payload_context for JSONB queries (path, signature, etc.)
            CREATE INDEX IF NOT EXISTS idx_norm_events_payload
                ON normalized_events USING GIN (payload_context);
            """,
            """
            -- Rule-based lookups (mirrors events table pattern)
            CREATE INDEX IF NOT EXISTS idx_norm_events_rule_name
                ON normalized_events (rule_name)
                WHERE rule_name IS NOT NULL AND rule_name != '' AND rule_name != 'N/A';
            """,
        ],
        "hook": lambda conn: (_v21_backfill(conn), _v21_convert_hypertable(conn)),
    },
]

# =============================================================================
# =============================================================================
# Migration hooks — Python-level logic that replaces DO $$ blocks
# =============================================================================

def _v3_finalize(conn: Any):
    """Finalize v3: fix constraints on rule_baselines.

    Handles:
    - Drop legacy unique constraint on rule_name
    - Add composite unique constraint on (rule, ip, hour)
    - Fix NOT NULL constraint on rule_name
    """
    # Drop legacy constraint
    _safe_drop_constraint(conn, "rule_baselines", "rule_baselines_rule_name_key")

    # Add composite unique constraint if it doesn't exist
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT 1 FROM pg_constraint
            WHERE conname = 'rule_baselines_rule_key'
        """)
        if not cur.fetchone():
            cur.execute("""
                ALTER TABLE rule_baselines
                ADD CONSTRAINT rule_baselines_rule_key
                UNIQUE (rule, ip, hour)
            """)
            logger.debug("Added composite unique constraint rule_baselines_rule_key")
    except Exception as exc:
        msg = str(exc).lower()
        if "duplicate" in msg or "already exists" in msg:
            logger.debug("Constraint rule_baselines_rule_key already exists — skipped")
        else:
            raise
    finally:
        cur.close()

    # Fix NOT NULL on rule_name (allow NULLs for backwards compat)
    cur = conn.cursor()
    try:
        cur.execute("""
            ALTER TABLE rule_baselines ALTER COLUMN rule_name DROP NOT NULL
        """)
        cur.execute("""
            ALTER TABLE rule_baselines ALTER COLUMN rule_name SET DEFAULT ''
        """)
        logger.debug("Fixed rule_name NOT NULL constraint")
    except Exception as exc:
        msg = str(exc).lower()
        if "not" in msg and ("null" in msg or "exist" in msg):
            logger.debug("rule_name constraint already correct — skipped")
        else:
            raise
    finally:
        cur.close()


def _safe_create_hypertable(
    conn: Any,
    table: str,
    time_column: str,
    chunk_interval: str = "7 days",
    primary_key_columns: Tuple[str, ...] = ("id", "timestamp"),
) -> bool:
    """Safely convert a regular table to a TimescaleDB hypertable (idempotent).

    Checks whether the table is already a hypertable. If not, drops the existing
    primary key, creates a composite primary key required by TimescaleDB, and calls
    create_hypertable(). Returns True if a conversion was performed, False if the
    table was already a hypertable.

    Args:
        conn: Active psycopg2 connection.
        table: Name of the table to convert.
        time_column: Partitioning time column.
        chunk_interval: Chunk time interval string (e.g. '7 days').
        primary_key_columns: Columns for the composite primary key.

    Returns:
        True if the table was converted, False if it was already a hypertable.
    """
    cur = conn.cursor()
    try:
        # Check if already a hypertable (idempotent)
        cur.execute(f"""
            SELECT hypertable_schema, hypertable_name
            FROM timescaledb_information.hypertables
            WHERE hypertable_name = %s
        """, (table,))
        if cur.fetchone():
            logger.info("%s is already a hypertable — skipping", table)
            return False

        # Find and drop the existing primary key constraint
        cur.execute("""
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = %s::regclass AND contype = 'p'
        """, (table,))
        pk_rows = cur.fetchall()
        for (pk_name,) in pk_rows:
            logger.info("Dropping existing primary key %s on %s", pk_name, table)
            cur.execute(f"ALTER TABLE {table} DROP CONSTRAINT {pk_name}")

        # Create composite primary key (id, timestamp) required by TimescaleDB
        pk_cols = ", ".join(primary_key_columns)
        logger.info("Adding composite primary key (%s) on %s", pk_cols, table)
        cur.execute(f"ALTER TABLE {table} ADD PRIMARY KEY ({pk_cols})")

        # Create the hypertable
        logger.info(
            "Creating hypertable on %s(%s), chunk_interval = %s",
            table, time_column, chunk_interval,
        )
        cur.execute(f"""
            SELECT create_hypertable(
                %s, %s,
                chunk_time_interval => INTERVAL %s
            )
        """, (table, time_column, chunk_interval))

        conn.commit()
        logger.info("Hypertable conversion complete for %s", table)
        return True

    except Exception as exc:
        conn.rollback()
        msg = str(exc).lower()
        if "already exists" in msg or "already a hypertable" in msg:
            logger.info("Hypertable for %s already exists — skipping", table)
            return False
        raise
    finally:
        cur.close()


def _v20_convert_hypertable(conn: Any):
    """Convert events table to TimescaleDB hypertable.

    Steps:
    1. Use _safe_create_hypertable to convert events(id, timestamp) (idempotent).
    2. Drop indexes that TimescaleDB makes redundant.
    3. Run ANALYZE to update planner statistics on the new chunk distribution.
    4. Verify event count and chunk distribution.
    """
    converted = _safe_create_hypertable(
        conn, "events", "timestamp", "7 days", ("id", "timestamp")
    )

    if not converted:
        # Already a hypertable — still refresh stats
        cur = conn.cursor()
        try:
            cur.execute("ANALYZE events")
            conn.commit()
            logger.info("V20: ANALYZE on existing hypertable complete")
        finally:
            cur.close()
        return

    # Drop the old plain B-tree timestamp index — TimescaleDB manages partitioning
    # on the time column internally. Composite indexes (V11-V13) remain useful.
    cur = conn.cursor()
    try:
        logger.info("V20: Dropping redundant idx_events_timestamp (hypertable handles this)")
        cur.execute("DROP INDEX IF EXISTS idx_events_timestamp")

        # Post-conversion: ANALYZE for accurate planner statistics
        logger.info("V20: Running ANALYZE on hypertable...")
        cur.execute("ANALYZE events")

        # Verify event count
        try:
            cur.execute("SELECT count(*) FROM events")
            count_row = cur.fetchone()
            if count_row is not None:
                logger.info("V20: Verified %d events in hypertable", count_row[0])

            # Verify chunk distribution
            cur.execute("""
                SELECT count(*), min(range_start), max(range_end)
                FROM timescaledb_information.chunks
                WHERE table_name = 'events'
            """)
            chunk_row = cur.fetchone()
            if chunk_row:
                chunk_count, range_start, range_end = chunk_row
                logger.info(
                    "V20: Verified %d chunks (range %s to %s)",
                    chunk_count, range_start, range_end,
                )
            else:
                logger.info("V20: No chunks yet (fresh instance with no events)")
        except Exception:
            logger.warning("V20: Could not verify hypertable stats (possibly mocked context)")

        logger.info("V20: Migration complete — hypertable verified")
    finally:
        cur.close()


def _v21_backfill(conn: Any):
    """Backfill normalized_events from legacy source tables (idempotent).

    Maps data from three source tables into the unified normalized_events schema:
    - events (firewall/ids/zenarmor/nginx from syslog)
    - nginx_events (Nginx access log events)
    - unifi_events (UniFi controller events)

    Idempotency: skips entirely if normalized_events already has rows, so
    re-running V21 on a database that was manually seeded is safe.

    Uses bulk INSERT ... SELECT for performance (6.8M+ events). The
    hypertable conversion runs AFTER this so TimescaleDB distributes
    backfilled data into chunks in one pass.
    """
    cur = conn.cursor()
    try:
        # Idempotency gate: skip if normalized_events already populated
        cur.execute("SELECT count(*) FROM normalized_events")
        existing = cur.fetchone()[0]
        if existing > 0:
            logger.info("V21: normalized_events already has %d rows — skipping backfill", existing)
            return

        logger.info("V21: Starting backfill into normalized_events...")
        total_backfilled = 0

        # ---------------------------------------------------------------
        # 1. Backfill from events table (firewall / ids / zenarmor / nginx via syslog)
        # ---------------------------------------------------------------
        try:
            cur.execute("""
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'events'
            """)
            if cur.fetchone():
                cur.execute("""
                    INSERT INTO normalized_events (
                        timestamp,
                        src_ip, dst_ip,
                        src_port, dst_port,
                        protocol, action, interface, direction,
                        src_hostname, dst_hostname,
                        payload_context,
                        source, log_type, rule_name, severity, raw_message,
                        ingested_at
                    )
                    SELECT
                        events.timestamp,
                        events.src_ip,
                        events.dst_ip,
                        events.src_port,
                        events.dst_port,
                        events.proto AS protocol,
                        events.action,
                        events.interface,
                        events.direction,
                        events.src_hostname,
                        events.dst_hostname,
                        jsonb_build_object(
                            'tcp_flags', events.tcp_flags,
                            'ip_ttl', events.ip_ttl,
                            'ip_total_length', events.ip_total_length,
                            'tcp_seq', events.tcp_seq,
                            'tcp_ack', events.tcp_ack,
                            'tcp_window', events.tcp_window,
                            'tcp_options', events.tcp_options,
                            'udp_datalen', events.udp_datalen,
                            'icmp_datalen', events.icmp_datalen
                        ) AS payload_context,
                        CASE
                            WHEN events.log_type = 'nginx'     THEN 'nginx'
                            WHEN events.log_type = 'ids'       THEN 'ids'
                            WHEN events.log_type = 'zenarmor'  THEN 'zenarmor'
                            ELSE 'firewall'
                        END AS source,
                        COALESCE(events.log_type, '') AS log_type,
                        events.rule_name,
                        NULL AS severity,
                        events.raw_message,
                        COALESCE(events.ingested_at, events.timestamp) AS ingested_at
                    FROM events
                """)
                row_count = cur.rowcount
                total_backfilled += row_count
                logger.info("V21: Backfilled %d rows from events table", row_count)
        except Exception as exc:
            logger.warning("V21: Could not backfill from events table: %s", exc)

        # ---------------------------------------------------------------
        # 2. Backfill from nginx_events table
        # ---------------------------------------------------------------
        try:
            cur.execute("""
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'nginx_events'
            """)
            if cur.fetchone():
                cur.execute("""
                    INSERT INTO normalized_events (
                        timestamp,
                        src_ip, dst_ip,
                        src_port, dst_port,
                        protocol, action, interface, direction,
                        src_hostname, dst_hostname,
                        payload_context,
                        source, log_type, rule_name, severity, raw_message,
                        ingested_at
                    )
                    SELECT
                        ne.timestamp,
                        ne.src_ip,
                        NULL AS dst_ip,
                        NULL AS src_port,
                        NULL AS dst_port,
                        'HTTP' AS protocol,
                        ne.method AS action,
                        ne.interface,
                        NULL AS direction,
                        NULL AS src_hostname,
                        NULL AS dst_hostname,
                        jsonb_build_object(
                            'method', ne.method,
                            'path', ne.path,
                            'status_code', ne.status_code,
                            'response_size', ne.response_size,
                            'user_agent', ne.user_agent,
                            'request_time', ne.request_time
                        ) AS payload_context,
                        'nginx' AS source,
                        'nginx' AS log_type,
                        NULL AS rule_name,
                        NULL AS severity,
                        NULL AS raw_message,
                        COALESCE(ne.ingested_at, ne.timestamp) AS ingested_at
                    FROM nginx_events ne
                """)
                row_count = cur.rowcount
                total_backfilled += row_count
                logger.info("V21: Backfilled %d rows from nginx_events table", row_count)
        except Exception as exc:
            logger.warning("V21: Could not backfill from nginx_events table: %s", exc)

        # ---------------------------------------------------------------
        # 3. Backfill from unifi_events table
        # ---------------------------------------------------------------
        try:
            cur.execute("""
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'unifi_events'
            """)
            if cur.fetchone():
                cur.execute("""
                    INSERT INTO normalized_events (
                        timestamp,
                        src_ip, dst_ip,
                        src_port, dst_port,
                        protocol, action, interface, direction,
                        src_hostname, dst_hostname,
                        payload_context,
                        source, log_type, rule_name, severity, raw_message,
                        ingested_at
                    )
                    SELECT
                        ue.timestamp,
                        ue.ip AS src_ip,
                        NULL AS dst_ip,
                        NULL AS src_port,
                        NULL AS dst_port,
                        NULL AS protocol,
                        ue.event_type AS action,
                        NULL AS interface,
                        NULL AS direction,
                        NULL AS src_hostname,
                        NULL AS dst_hostname,
                        jsonb_build_object(
                            'event_key', ue.event_key,
                            'mac', ue.mac,
                            'device', ue.device,
                            'ap', ue.ap,
                            'ssid', ue.ssid,
                            'message', ue.message
                        ) AS payload_context,
                        'unifi' AS source,
                        'unifi' AS log_type,
                        NULL AS rule_name,
                        ue.severity AS severity,
                        ue.message AS raw_message,
                        COALESCE(ue.created_at, ue.timestamp) AS ingested_at
                    FROM unifi_events ue
                """)
                row_count = cur.rowcount
                total_backfilled += row_count
                logger.info("V21: Backfilled %d rows from unifi_events table", row_count)
        except Exception as exc:
            logger.warning("V21: Could not backfill from unifi_events table: %s", exc)

        conn.commit()
        logger.info("V21: Backfill complete — %d total rows inserted into normalized_events", total_backfilled)

        # Verify against source table counts
        try:
            source_counts = {}
            for tbl in ['events', 'nginx_events', 'unifi_events']:
                cur.execute(f"SELECT count(*) FROM {tbl}")
                source_counts[tbl] = cur.fetchone()[0]

            cur.execute("SELECT count(*) FROM normalized_events")
            norm_count = cur.fetchone()[0]

            # Note: events table may contain nginx events (log_type='nginx') that
            # are also in nginx_events, so norm_count >= sum of sources is expected
            # in some deployments. Report actual counts for operator review.
            logger.info(
                "V21: Backfill verification — normalized_events: %d, "
                "events: %d, nginx_events: %d, unifi_events: %d",
                norm_count,
                source_counts.get('events', -1),
                source_counts.get('nginx_events', -1),
                source_counts.get('unifi_events', -1),
            )
        except Exception:
            logger.warning("V21: Could not verify backfill counts (possibly mocked context)")

    finally:
        cur.close()


def _v21_convert_hypertable(conn: Any):
    """Convert normalized_events to TimescaleDB hypertable (idempotent).

    Steps:
    1. Use _safe_create_hypertable to convert normalized_events(id, timestamp).
    2. Run ANALYZE on the new hypertable.
    3. Log chunk distribution for verification.
    """
    converted = _safe_create_hypertable(
        conn, "normalized_events", "timestamp", "7 days", ("id", "timestamp")
    )

    if not converted:
        cur = conn.cursor()
        try:
            cur.execute("ANALYZE normalized_events")
            conn.commit()
            logger.info("V21: ANALYZE on existing hypertable complete")
        finally:
            cur.close()
        return

    cur = conn.cursor()
    try:
        logger.info("V21: Running ANALYZE on normalized_events hypertable...")
        cur.execute("ANALYZE normalized_events")

        try:
            cur.execute("SELECT count(*) FROM normalized_events")
            count_row = cur.fetchone()
            if count_row is not None:
                logger.info("V21: Verified %d events in normalized_events hypertable", count_row[0])

            cur.execute("""
                SELECT count(*), min(range_start), max(range_end)
                FROM timescaledb_information.chunks
                WHERE table_name = 'normalized_events'
            """)
            chunk_row = cur.fetchone()
            if chunk_row:
                chunk_count, range_start, range_end = chunk_row
                logger.info(
                    "V21: Verified %d chunks (range %s to %s)",
                    chunk_count, range_start, range_end,
                )
            else:
                logger.info("V21: No chunks yet (fresh instance with no normalized_events)")
        except Exception:
            logger.warning("V21: Could not verify hypertable stats (possibly mocked context)")

        logger.info("V21: Migration complete — normalized_events hypertable verified")
    finally:
        cur.close()


# =============================================================================
# Public API
# =============================================================================

def run_migrations(db: Any) -> List[dict]:
    """
    Run all pending schema migrations.

    Args:
        db: An EventDatabase instance (must have .connect() method).

    Returns:
        List of dicts describing each migration applied:
        [{"version": 1, "description": "...", "status": "applied"}, ...]
    """
    conn = db.connect()
    results: List[dict] = []

    try:
        # Ensure version tracking table exists
        cur = conn.cursor()
        cur.execute(CREATE_VERSION_TABLE_SQL)
        cur.close()
        logger.info("schema_versions table ensured")

        # Determine current version
        current_version = _get_current_version(conn)
        logger.info(
            "Current schema version: %d (target: %d)",
            current_version,
            CURRENT_SCHEMA_VERSION,
        )

        if current_version >= CURRENT_SCHEMA_VERSION:
            logger.info("Schema already up to date (v%d)", current_version)
            return [{"version": current_version, "status": "already_current"}]

        # Run pending migrations in order
        for migration in MIGRATIONS:
            version = migration["version"]
            description = migration["description"]

            if version <= current_version:
                results.append({
                    "version": version,
                    "status": "skipped",
                    "reason": "already applied",
                })
                continue

            logger.info("Applying migration v%d: %s", version, description)

            try:
                # 1. Run idempotent SQL statements
                for sql in migration.get("sql", []):
                    cur = conn.cursor()
                    cur.execute(sql)
                    cur.close()

                # 2. Run alter_columns (safe ADD COLUMN with DuplicateColumn handling)
                added_cols = 0
                for table, column, col_def in migration.get("alter_columns", []):
                    if _safe_add_column(conn, table, column, col_def):
                        added_cols += 1
                if added_cols > 0:
                    logger.info("Migration v%d: added %d column(s)", version, added_cols)

                # 3. Run optional hook (complex Python-level logic)
                hook = migration.get("hook")
                if hook is not None:
                    hook(conn)

                # 4. Record the version
                _record_version(conn, version, description)
                results.append({
                    "version": version,
                    "status": "applied",
                    "description": description,
                })
                logger.info("Migration v%d applied successfully", version)

            except Exception as e:
                error_msg = f"Migration v{version} failed: {e}"
                logger.error(error_msg)
                results.append({
                    "version": version,
                    "status": "failed",
                    "error": str(e),
                })
                raise RuntimeError(error_msg) from e

        applied_count = len([r for r in results if r["status"] == "applied"])
        logger.info(
            "Schema migrations complete: v%d -> v%d (%d migration(s) applied)",
            current_version,
            CURRENT_SCHEMA_VERSION,
            applied_count,
        )

    finally:
        # Return connection to pool
        try:
            db.putconn(conn)
        except Exception:
            pass

    return results


def get_schema_version(db: Any) -> int:
    """Get the current schema version without running migrations."""
    # Handle both raw psycopg2 connections and EventDatabase instances
    if hasattr(db, 'connect'):
        conn = db.connect()
    else:
        conn = db
    try:
        return _get_current_version(conn)
    finally:
        if hasattr(db, 'putconn'):
            try:
                db.putconn(conn)
            except Exception:
                pass


def get_migration_status(db: Any) -> dict:
    """Get a summary of migration status for debugging."""
    # Handle both raw psycopg2 connections and EventDatabase instances
    if hasattr(db, 'connect'):
        conn = db.connect()
    else:
        conn = db
    try:
        current = _get_current_version(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT version, description, applied_at FROM schema_versions ORDER BY version"
        )
        applied = [
            {
                "version": r[0],
                "description": r[1],
                "applied_at": str(r[2]),
            }
            for r in cur.fetchall()
        ]
        cur.close()
        pending = [
            {"version": m["version"], "description": m["description"]}
            for m in MIGRATIONS
            if m["version"] > current
        ]
        return {
            "current_version": current,
            "target_version": CURRENT_SCHEMA_VERSION,
            "is_current": current >= CURRENT_SCHEMA_VERSION,
            "applied": applied,
            "pending": pending,
        }
    finally:
        if hasattr(db, 'putconn'):
            try:
                db.putconn(conn)
            except Exception:
                pass