-- OPNsense Agent Test Database Schema
-- This script initializes the PostgreSQL database with the correct schema

-- Events table (from production)
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
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
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rule_name TEXT,
    log_type TEXT,
    src_hostname TEXT,
    dst_hostname TEXT
);

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events (action);

-- Anomalies table
CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    details TEXT,
    alert_sent BOOLEAN DEFAULT FALSE,
    acknowledged BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies (timestamp);
CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies (severity);
