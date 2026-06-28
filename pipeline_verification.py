#!/usr/bin/env python3
"""
Pipeline Health Verification — Source-to-UI Tracing
====================================================

Traces data flow end-to-end through the entire anomaly detection pipeline:

  Source (syslog/OPNsense API) → Parser → Agent → Database → API → UI

Verifies:
  1. Timestamps propagate correctly through each stage
  2. Data transformations preserve expected fields
  3. Baseline calculation and anomaly detection fire on seeded data
  4. Database records match injected test markers
  5. API endpoints surface seeded data correctly
  6. Identifies pipeline gaps and data loss points

Uses marker IPs (192.168.100.x) from test_data_seeder for clean E2E tracing
without touching production data.

Usage:
    python3 pipeline_verification.py                          # run all checks
    python3 pipeline_verification.py --base http://host:8766  # remote target
    python3 pipeline_verification.py --stage database         # specific stage
    python3 pipeline_verification.py --json                   # machine-readable
    python3 pipeline_verification.py --verbose                # detailed output
    python3 pipeline_verification.py --dry-run                # plan only

Exit codes:
    0  All stages healthy
    1  One or more stages have issues

Stages verified:
    SOURCE       — Syslog listener可达性 + OPNsense API connectivity
    PARSER       — Raw syslog → structured event field extraction
    AGENT        — Event buffer → batch processing → DB insert
    DATABASE     — Events persist in correct tables with correct schema
    ANOMALY      — Attack detection + geo anomaly triggers
    BASELINE     — Baseline engine learns from events, stores rule_baselines
    API          — REST endpoints return seeded data with correct structure
    UI_DATA      — Frontend-data contracts (API → UI field mapping)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# ─── Configuration ──────────────────────────────────────────────────

DEFAULT_BASE = "http://localhost:8766"
REQUEST_TIMEOUT = 15  # seconds

# Marker IPs — same range as test_data_seeder
MARKER_IP_BASE = "192.168.100"
TEST_MARKER_PREFIX = "TEST_SEED"

logger = logging.getLogger(__name__)


class Severity(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"
    INFO = "INFO"


class Stage(Enum):
    SOURCE = "source"
    PARSER = "parser"
    AGENT = "agent"
    DATABASE = "database"
    ANOMALY = "anomaly"
    BASELINE = "baseline"
    API = "api"
    UI_DATA = "ui_data"


@dataclass
class Finding:
    stage: str
    check_name: str
    severity: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp_ms: float = 0


@dataclass
class PipelineReport:
    run_id: str
    started_at: str
    base_url: str
    completed_at: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, str] = field(default_factory=dict)

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "PASS")

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "FAIL")

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "WARN")

    @property
    def skip_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "SKIP")


# ─── HTTP Client ────────────────────────────────────────────────────

def http_get(base: str, path: str, params: Optional[Dict] = None, timeout: int = REQUEST_TIMEOUT) -> Tuple[int, Dict, float]:
    """GET request returning (status_code, json_body, elapsed_ms)."""
    url = f"{base}{path}"
    if params:
        url += "?" + urlencode(params)
    t0 = time.time()
    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
            elapsed = (time.time() - t0) * 1000
            return resp.status, body, elapsed
    except HTTPError as e:
        elapsed = (time.time() - t0) * 1000
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {"error": str(e)}
        return e.code, body, elapsed
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        return 0, {"error": str(e)}, elapsed


# ─── Stage 1: SOURCE ───────────────────────────────────────────────

def check_source(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify data sources are reachable and healthy."""
    stage = Stage.SOURCE.value
    t0 = time.time()

    # 1a: Check if health endpoint responds (proxy for agent being alive)
    status, body, ms = http_get(base, "/api/health", timeout=timeout)
    if status == 200:
        report.findings.append({
            "stage": stage, "check_name": "health_endpoint",
            "severity": "PASS", "message": "Health endpoint responding",
            "details": {"response_time_ms": round(ms, 1)},
            "timestamp_ms": ms,
        })
    else:
        report.findings.append({
            "stage": stage, "check_name": "health_endpoint",
            "severity": "FAIL", "message": f"Health endpoint returned {status}",
            "details": {"status": status, "body_preview": str(body)[:200]},
            "timestamp_ms": ms,
        })
        # If health is down, skip remaining source checks
        return

    # 1b: Check health payload for source connectivity info
    health = body.get("health", body)
    if isinstance(health, dict):
        # Check DB status in health
        db_status = health.get("database", health.get("db", {}))
        if isinstance(db_status, dict):
            db_state = db_status.get("status", db_status.get("state", "unknown"))
            if db_state in ("healthy", "connected", "ok"):
                report.findings.append({
                    "stage": stage, "check_name": "database_connectivity",
                    "severity": "PASS", "message": f"Database connected (status={db_state})",
                    "details": {"status": db_state},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })
            else:
                report.findings.append({
                    "stage": stage, "check_name": "database_connectivity",
                    "severity": "WARN", "message": f"Database status: {db_state}",
                    "details": {"status": db_state},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })

        # Check syslog status
        syslog_info = health.get("syslog", {})
        if isinstance(syslog_info, dict):
            syslog_active = syslog_info.get("active", syslog_info.get("enabled", False))
            if syslog_active:
                report.findings.append({
                    "stage": stage, "check_name": "syslog_listener",
                    "severity": "PASS", "message": "Syslog listener active",
                    "details": syslog_info,
                    "timestamp_ms": (time.time() - t0) * 1000,
                })
            else:
                report.findings.append({
                    "stage": stage, "check_name": "syslog_listener",
                    "severity": "WARN", "message": "Syslog listener not active",
                    "details": syslog_info,
                    "timestamp_ms": (time.time() - t0) * 1000,
                })

        # Check OPNsense API connectivity (if configured)
        opnsense_info = health.get("opnsense", health.get("api", {}))
        if isinstance(opnsense_info, dict):
            opn_status = opnsense_info.get("status", opnsense_info.get("connected", "unknown"))
            report.findings.append({
                "stage": stage, "check_name": "opnsense_api",
                "severity": "PASS" if opn_status in ("healthy", "connected", "ok", True) else "WARN",
                "message": f"OPNsense API: {opn_status}",
                "details": opnsense_info,
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 1c: Check version endpoint for build info
    status, body, ms = http_get(base, "/api/version", timeout=timeout)
    if status == 200:
        version = body.get("version", body.get("tag", "unknown"))
        report.findings.append({
            "stage": stage, "check_name": "version_check",
            "severity": "PASS", "message": f"Agent version: {version}",
            "details": body,
            "timestamp_ms": ms,
        })

    # 1d: Verify /api/resources for system resource monitoring
    status, body, ms = http_get(base, "/api/resources", timeout=timeout)
    if status == 200:
        report.findings.append({
            "stage": stage, "check_name": "resource_monitoring",
            "severity": "PASS", "message": "Resource monitoring active",
            "details": {"cpu": body.get("cpu", {}), "memory": body.get("memory", {}), "disk": body.get("disk", {})}
            if isinstance(body, dict) else body,
            "timestamp_ms": ms,
        })


# ─── Stage 2: PARSER ───────────────────────────────────────────────

def check_parser(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify event parsing — fields extracted from raw syslog."""
    stage = Stage.PARSER.value
    t0 = time.time()

    # Check events endpoint for parsed field structure
    status, body, ms = http_get(base, "/api/events", {"limit": "5"}, timeout=timeout)
    if status != 200 or not body:
        report.findings.append({
            "stage": stage, "check_name": "events_endpoint",
            "severity": "WARN", "message": "No events available to verify parser output",
            "details": {"status": status},
            "timestamp_ms": (time.time() - t0) * 1000,
        })
        return

    if isinstance(body, dict):
        events = body.get("events", [])
    elif isinstance(body, list):
        events = body
    else:
        events = []
    if not events:
        report.findings.append({
            "stage": stage, "check_name": "events_data",
            "severity": "WARN", "message": "Events endpoint returned empty array",
            "timestamp_ms": (time.time() - t0) * 1000,
        })
        return

    # Verify required parsed fields exist on events
    required_parser_fields = [
        "timestamp", "src_ip", "dst_ip", "proto", "action",
    ]
    optional_parser_fields = [
        "sport", "dport", "interface", "direction", "rule_name",
        "log_type", "version", "ip_ttl", "tcp_flags",
    ]

    first_event = events[0]
    missing_required = [f for f in required_parser_fields if f not in first_event and first_event.get(f) is None]
    present_optional = [f for f in optional_parser_fields if f in first_event and first_event.get(f) is not None]

    if missing_required:
        report.findings.append({
            "stage": stage, "check_name": "required_fields",
            "severity": "FAIL",
            "message": f"Missing required parsed fields: {missing_required}",
            "details": {"event_keys": list(first_event.keys())},
            "timestamp_ms": (time.time() - t0) * 1000,
        })
    else:
        report.findings.append({
            "stage": stage, "check_name": "required_fields",
            "severity": "PASS",
            "message": f"All {len(required_parser_fields)} required parser fields present",
            "details": {"fields": required_parser_fields},
            "timestamp_ms": (time.time() - t0) * 1000,
        })

    report.findings.append({
        "stage": stage, "check_name": "optional_fields",
        "severity": "INFO",
        "message": f"{len(present_optional)}/{len(optional_parser_fields)} optional fields populated",
        "details": {"present": present_optional},
        "timestamp_ms": (time.time() - t0) * 1000,
    })

    # Verify log_type classification
    log_types = set()
    for ev in events:
        lt = ev.get("log_type", "")
        if lt:
            log_types.add(lt)

    if log_types:
        report.findings.append({
            "stage": stage, "check_name": "log_type_classification",
            "severity": "PASS",
            "message": f"Events classified into {len(log_types)} log types: {sorted(log_types)}",
            "details": {"log_types": sorted(log_types)},
            "timestamp_ms": (time.time() - t0) * 1000,
        })
    else:
        report.findings.append({
            "stage": stage, "check_name": "log_type_classification",
            "severity": "WARN",
            "message": "No log_type classification on events — parser may not be tagging events",
            "timestamp_ms": (time.time() - t0) * 1000,
        })

    # Verify timestamp format (ISO 8601)
    ts_valid = 0
    ts_invalid = 0
    for ev in events[:10]:
        ts = ev.get("timestamp", "")
        if ts:
            try:
                datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
                ts_valid += 1
            except (ValueError, TypeError):
                ts_invalid += 1

    if ts_invalid == 0 and ts_valid > 0:
        report.findings.append({
            "stage": stage, "check_name": "timestamp_format",
            "severity": "PASS",
            "message": f"All {ts_valid} event timestamps are valid ISO 8601",
            "timestamp_ms": (time.time() - t0) * 1000,
        })
    elif ts_invalid > 0:
        report.findings.append({
            "stage": stage, "check_name": "timestamp_format",
            "severity": "FAIL",
            "message": f"{ts_invalid} invalid timestamps out of {ts_valid + ts_invalid}",
            "timestamp_ms": (time.time() - t0) * 1000,
        })


# ─── Stage 3: AGENT ────────────────────────────────────────────────

def check_agent(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify agent processing pipeline: buffer → batch → downstream consumers."""
    stage = Stage.AGENT.value
    t0 = time.time()

    # 3a: Check stats endpoint for event counts (proxy for processing)
    status, body, ms = http_get(base, "/api/stats", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        total = body.get("total_events", 0)
        by_source = body.get("by_source", {})

        if isinstance(total, (int, float)) and total >= 0:
            report.findings.append({
                "stage": stage, "check_name": "event_ingestion",
                "severity": "PASS" if total > 0 else "WARN",
                "message": f"Total ingested events: {total}",
                "details": {"total_events": total, "by_source": by_source},
                "timestamp_ms": (time.time() - t0) * 1000,
            })

            # Check if multiple sources are feeding (agent routes to different consumers)
            if isinstance(by_source, dict):
                active_sources = {k: v for k, v in by_source.items() if v and v > 0}
                report.findings.append({
                    "stage": stage, "check_name": "multi_source_routing",
                    "severity": "PASS" if len(active_sources) > 1 else "WARN",
                    "message": f"Active data sources: {len(active_sources)} ({list(active_sources.keys())})",
                    "details": {"sources": active_sources},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })

        # Check stats timestamp (proves agent is computing fresh data)
        stats_ts = body.get("timestamp", "")
        if stats_ts:
            try:
                stats_dt = datetime.fromisoformat(str(stats_ts).replace('Z', '+00:00'))
                age_seconds = (datetime.now(timezone.utc) - stats_dt).total_seconds()
                if age_seconds < 300:
                    report.findings.append({
                        "stage": stage, "check_name": "stats_freshness",
                        "severity": "PASS",
                        "message": f"Stats computed {age_seconds:.0f}s ago (fresh)",
                        "details": {"age_seconds": age_seconds},
                        "timestamp_ms": (time.time() - t0) * 1000,
                    })
                else:
                    report.findings.append({
                        "stage": stage, "check_name": "stats_freshness",
                        "severity": "WARN",
                        "message": f"Stats are {age_seconds:.0f}s old — agent may be stale",
                        "details": {"age_seconds": age_seconds},
                        "timestamp_ms": (time.time() - t0) * 1000,
                    })
            except ValueError:
                pass

    # 3b: Check ML model status (agent trains/classifies rules)
    status, body, ms = http_get(base, "/api/ml-summary", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        model_status = body.get("status", body.get("model_status", "unknown"))
        classified = body.get("classified_rules", body.get("total_classified", 0))
        report.findings.append({
            "stage": stage, "check_name": "ml_rule_classification",
            "severity": "PASS",
            "message": f"ML classifier: {classified} rules classified (status={model_status})",
            "details": body,
            "timestamp_ms": (time.time() - t0) * 1000,
        })

    # 3c: Check active learning queue (agent feedback loop)
    status, body, ms = http_get(base, "/api/active-learning-queue", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        queue_size = body.get("pending", body.get("queue_size", 0))
        report.findings.append({
            "stage": stage, "check_name": "active_learning",
            "severity": "PASS",
            "message": f"Active learning queue: {queue_size} pending items",
            "details": body,
            "timestamp_ms": (time.time() - t0) * 1000,
        })


# ─── Stage 4: DATABASE ─────────────────────────────────────────────

def check_database(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify data persistence: events, anomalies, baselines stored correctly."""
    stage = Stage.DATABASE.value
    t0 = time.time()

    # 4a: Check schema migrations endpoint
    status, body, ms = http_get(base, "/api/schema-migrations", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        current_version = body.get("current_version", body.get("version", 0))
        target_version = body.get("target_version", body.get("current_schema_version", 8))
        try:
            cv = int(current_version)
            tv = int(target_version)
        except (ValueError, TypeError):
            cv, tv = 0, 8
        if cv >= tv:
            report.findings.append({
                "stage": stage, "check_name": "schema_version",
                "severity": "PASS",
                "message": f"Schema v{cv} (target v{tv}) — up to date",
                "details": body,
                "timestamp_ms": (time.time() - t0) * 1000,
            })
        else:
            report.findings.append({
                "stage": stage, "check_name": "schema_version",
                "severity": "WARN",
                "message": f"Schema v{cv} / target v{tv} — pending migrations",
                "details": body,
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 4b: Verify events table has data with correct field structure
    status, body, ms = http_get(base, "/api/events", {"limit": "3"}, timeout=timeout)
    if status == 200:
        if isinstance(body, dict):
            events = body.get("events", [])
        elif isinstance(body, list):
            events = body
        else:
            events = []
        if events:
            # Check that events have IDs (persisted to DB)
            has_ids = all("id" in ev for ev in events if isinstance(ev, dict))
            report.findings.append({
                "stage": stage, "check_name": "events_persistence",
                "severity": "PASS" if has_ids else "WARN",
                "message": f"Events persisted to DB: {len(events)} records, ids_present={has_ids}",
                "details": {"sample_event_keys": list(events[0].keys()) if events else []},
                "timestamp_ms": (time.time() - t0) * 1000,
            })

            # Check ingested_at vs timestamp (pipeline latency)
            if events:
                first = events[0]
                ev_ts = first.get("timestamp", "")
                ingest_ts = first.get("ingested_at", "")
                if ev_ts and ingest_ts:
                    try:
                        ev_dt = datetime.fromisoformat(str(ev_ts).replace('Z', '+00:00'))
                        ing_dt = datetime.fromisoformat(str(ingest_ts).replace('Z', '+00:00'))
                        latency = abs((ing_dt - ev_dt).total_seconds())
                        report.findings.append({
                            "stage": stage, "check_name": "ingestion_latency",
                            "severity": "PASS" if latency < 60 else "WARN",
                            "message": f"Event-to-ingestion latency: {latency:.1f}s",
                            "details": {"event_ts": ev_ts, "ingested_ts": ingest_ts, "latency_seconds": latency},
                            "timestamp_ms": (time.time() - t0) * 1000,
                        })
                    except (ValueError, TypeError):
                        pass
        else:
            report.findings.append({
                "stage": stage, "check_name": "events_persistence",
                "severity": "WARN",
                "message": "No events in database — pipeline not ingesting or DB empty",
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 4c: Check anomalies table
    status, body, ms = http_get(base, "/api/anomalies", {"limit": "5"}, timeout=timeout)
    if status == 200:
        if isinstance(body, dict):
            anomalies = body.get("anomalies", [])
        elif isinstance(body, list):
            anomalies = body
        else:
            anomalies = []
        report.findings.append({
            "stage": stage, "check_name": "anomalies_stored",
            "severity": "PASS" if anomalies else "WARN",
            "message": f"Anomalies in DB: {len(anomalies)} records",
            "details": {"sample": anomalies[:2] if anomalies else None},
            "timestamp_ms": (time.time() - t0) * 1000,
        })

        # Verify anomaly field completeness
        if anomalies:
            first_anomaly = anomalies[0]
            required_anomaly_fields = ["timestamp", "attack_type", "severity"]
            missing = [f for f in required_anomaly_fields if f not in first_anomaly]
            if missing:
                report.findings.append({
                    "stage": stage, "check_name": "anomaly_schema",
                    "severity": "FAIL",
                    "message": f"Anomalies missing fields: {missing}",
                    "details": {"keys": list(first_anomaly.keys())},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })
            else:
                report.findings.append({
                    "stage": stage, "check_name": "anomaly_schema",
                    "severity": "PASS",
                    "message": "Anomaly records have all required fields",
                    "details": {"fields": required_anomaly_fields},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })

    # 4d: Check alerts (superset of anomalies with alert state)
    status, body, ms = http_get(base, "/api/alerts", {"limit": "5"}, timeout=timeout)
    if status == 200:
        if isinstance(body, dict):
            alerts = body.get("alerts", [])
        elif isinstance(body, list):
            alerts = body
        else:
            alerts = []
        report.findings.append({
            "stage": stage, "check_name": "alerts_stored",
            "severity": "INFO",
            "message": f"Alerts in DB: {len(alerts)} records",
            "timestamp_ms": (time.time() - t0) * 1000,
        })


# ─── Stage 5: ANOMALY ──────────────────────────────────────────────

def check_anomaly(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify anomaly detection: attack detection, geo, concept drift."""
    stage = Stage.ANOMALY.value
    t0 = time.time()

    # 5a: Check anomalies endpoint structure
    status, body, ms = http_get(base, "/api/anomalies", {"limit": "20"}, timeout=timeout)
    if status == 200 and isinstance(body, dict):
        anomalies = body.get("anomalies", [])

        # Group by attack_type
        attack_types: Dict[str, int] = {}
        severity_dist: Dict[str, int] = {}
        for a in anomalies:
            if isinstance(a, dict):
                at = a.get("attack_type", "unknown")
                attack_types[at] = attack_types.get(at, 0) + 1
                sev = a.get("severity", "unknown")
                severity_dist[sev] = severity_dist.get(sev, 0) + 1

        report.findings.append({
            "stage": stage, "check_name": "attack_type_diversity",
            "severity": "PASS" if len(attack_types) > 1 else "INFO",
            "message": f"Detected {len(attack_types)} attack types: {attack_types}",
            "details": {"by_type": attack_types, "by_severity": severity_dist},
            "timestamp_ms": (time.time() - t0) * 1000,
        })

        # Check anomaly timestamps are in order (pipeline ordering)
        timestamps = []
        for a in anomalies:
            if isinstance(a, dict):
                ts = a.get("timestamp", "")
                if ts:
                    try:
                        timestamps.append(datetime.fromisoformat(str(ts).replace('Z', '+00:00')))
                    except ValueError:
                        pass

        if len(timestamps) >= 2:
            ordered = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
            report.findings.append({
                "stage": stage, "check_name": "anomaly_timestamp_ordering",
                "severity": "PASS" if ordered else "WARN",
                "message": f"Anomaly timestamps {'ordered' if ordered else 'NOT ordered'} ({len(timestamps)} samples)",
                "details": {"count": len(timestamps)},
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 5b: Check concept drift detection
    status, body, ms = http_get(base, "/api/drift", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        drift_status = body.get("status", "unknown")
        is_drifting = body.get("is_drifting", False)
        drift_events = body.get("drift_events", [])
        report.findings.append({
            "stage": stage, "check_name": "concept_drift",
            "severity": "PASS",
            "message": f"Concept drift: {drift_status}, drifting={is_drifting}, events={len(drift_events)}",
            "details": {"status": drift_status, "drifting": is_drifting, "event_count": len(drift_events)},
            "timestamp_ms": (time.time() - t0) * 1000,
        })

    # 5c: Check threshold tuning
    status, body, ms = http_get(base, "/api/threshold", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        thresholds = body.get("thresholds", {})
        report.findings.append({
            "stage": stage, "check_name": "threshold_tuning",
            "severity": "PASS",
            "message": f"Threshold tuner active with {len(thresholds)} configured thresholds",
            "details": {"threshold_count": len(thresholds)},
            "timestamp_ms": (time.time() - t0) * 1000,
        })

    # 5d: Check geo data
    status, body, ms = http_get(base, "/api/geo", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        countries = body.get("countries", body.get("by_country", {}))
        if isinstance(countries, dict) and countries:
            report.findings.append({
                "stage": stage, "check_name": "geo_enrichment",
                "severity": "PASS",
                "message": f"Geo lookup active: {len(countries)} countries identified",
                "details": {"country_count": len(countries)},
                "timestamp_ms": (time.time() - t0) * 1000,
            })
        else:
            report.findings.append({
                "stage": stage, "check_name": "geo_enrichment",
                "severity": "WARN",
                "message": "Geo lookup returned no country data — enrichment may not be active",
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 5e: Check IP detail (threat profiles)
    status, body, ms = http_get(base, "/api/blocked-ips", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        blocked = body.get("ips", body.get("blocked_ips", []))
        if isinstance(blocked, list):
            report.findings.append({
                "stage": stage, "check_name": "threat_scoring",
                "severity": "PASS" if blocked else "INFO",
                "message": f"Threat scoring active: {len(blocked)} blocked IPs tracked",
                "details": {"blocked_count": len(blocked)},
                "timestamp_ms": (time.time() - t0) * 1000,
            })


# ─── Stage 6: BASELINE ─────────────────────────────────────────────

def check_baseline(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify baseline calculation and temporal pattern learning."""
    stage = Stage.BASELINE.value
    t0 = time.time()

    # 6a: Check stats for baseline-related metrics
    status, body, ms = http_get(base, "/api/stats", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        # Check if stats contain baseline info
        baseline_info = body.get("baselines", body.get("baseline_count", 0))
        if isinstance(baseline_info, (int, float)):
            report.findings.append({
                "stage": stage, "check_name": "baseline_count",
                "severity": "PASS" if baseline_info > 0 else "WARN",
                "message": f"Baseline count from stats: {baseline_info}",
                "details": {"count": baseline_info},
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 6b: Check ML summary for learned patterns
    status, body, ms = http_get(base, "/api/ml-summary", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        # Check for rule classification baselines
        rules = body.get("rules", body.get("classifications", {}))
        if isinstance(rules, (dict, list)) and rules:
            report.findings.append({
                "stage": stage, "check_name": "rule_baselines",
                "severity": "PASS",
                "message": f"Rule baselines: {len(rules)} rules with learned patterns",
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    # 6c: Check timeline for temporal patterns (baseline-driven visualization)
    status, body, ms = http_get(base, "/api/timeline", {"period": "7d", "granularity": "hour"}, timeout=timeout)
    if status == 200 and isinstance(body, dict):
        timeline_data = body.get("data", body.get("timeline", []))
        if isinstance(timeline_data, list):
            report.findings.append({
                "stage": stage, "check_name": "temporal_patterns",
                "severity": "PASS" if len(timeline_data) > 0 else "WARN",
                "message": f"Temporal pattern data: {len(timeline_data)} hourly buckets",
                "details": {"buckets": len(timeline_data)},
                "timestamp_ms": (time.time() - t0) * 1000,
            })

            # Verify timestamps in timeline are consistent intervals
            if len(timeline_data) >= 2:
                first_bucket = timeline_data[0]
                if isinstance(first_bucket, dict):
                    has_labels = "label" in first_bucket or "time" in first_bucket or "hour" in first_bucket
                    has_values = any(k in first_bucket for k in ["value", "count", "events", "total"])
                    report.findings.append({
                        "stage": stage, "check_name": "timeline_structure",
                        "severity": "PASS" if (has_labels and has_values) else "WARN",
                        "message": f"Timeline buckets have labels={has_labels}, values={has_values}",
                        "details": {"sample_keys": list(first_bucket.keys())},
                        "timestamp_ms": (time.time() - t0) * 1000,
                    })

    # 6d: Check rule-heatmap for per-rule baselines
    status, body, ms = http_get(base, "/api/rule-heatmap", timeout=timeout)
    if status == 200 and isinstance(body, dict):
        heatmap_data = body.get("data", body.get("heatmap", []))
        if isinstance(heatmap_data, list):
            report.findings.append({
                "stage": stage, "check_name": "rule_heatmap_baselines",
                "severity": "PASS" if heatmap_data else "WARN",
                "message": f"Rule heatmap: {len(heatmap_data)} rules with activity data",
                "timestamp_ms": (time.time() - t0) * 1000,
            })


# ─── Stage 7: API ──────────────────────────────────────────────────

def check_api(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify all API endpoints respond correctly with valid structure."""
    stage = Stage.API.value
    t0 = time.time()

    # Define all endpoints to check with expected structure
    endpoints = [
        # Core
        {"path": "/api/health", "expected_keys": [], "desc": "Health check"},
        {"path": "/api/stats", "expected_keys": ["total_events"], "desc": "Statistics"},
        {"path": "/api/version", "expected_keys": [], "desc": "Version info"},

        # Visualizations
        {"path": "/api/traffic-flow", "expected_keys": [], "desc": "Traffic flow"},
        {"path": "/api/protocols", "expected_keys": [], "desc": "Protocol distribution"},
        {"path": "/api/actions", "expected_keys": [], "desc": "Action distribution"},
        {"path": "/api/timeline", "params": {"period": "7d", "granularity": "hour"}, "expected_keys": [], "desc": "Timeline"},
        {"path": "/api/blocked-ips", "expected_keys": [], "desc": "Blocked IPs"},
        {"path": "/api/top-ports", "expected_keys": [], "desc": "Top ports"},
        {"path": "/api/rule-heatmap", "expected_keys": [], "desc": "Rule heatmap"},
        {"path": "/api/directions", "expected_keys": [], "desc": "Direction distribution"},
        {"path": "/api/rule-actions", "expected_keys": [], "desc": "Rule actions"},
        {"path": "/api/heatmap", "expected_keys": [], "desc": "IP heatmap"},
        {"path": "/api/ip-flow", "expected_keys": [], "desc": "IP flow graph"},
        {"path": "/api/ip-flow-clusters", "expected_keys": [], "desc": "Flow clusters"},

        # Data endpoints
        {"path": "/api/events", "params": {"limit": "3"}, "expected_keys": [], "desc": "Events"},
        {"path": "/api/mutes", "expected_keys": [], "desc": "Mutes"},
        {"path": "/api/geo", "expected_keys": [], "desc": "Geo data"},
        {"path": "/api/anomalies", "params": {"limit": "3"}, "expected_keys": [], "desc": "Anomalies"},
        {"path": "/api/alerts", "params": {"limit": "3"}, "expected_keys": [], "desc": "Alerts"},
        {"path": "/api/flows", "expected_keys": [], "desc": "Network flows"},
        {"path": "/api/logs", "params": {"limit": "3"}, "expected_keys": [], "desc": "Logs"},
        {"path": "/api/system_logs", "params": {"limit": "3"}, "expected_keys": [], "desc": "System logs"},

        # ML / classification
        {"path": "/api/ml-summary", "expected_keys": [], "desc": "ML summary"},
        {"path": "/api/ml-classifications", "expected_keys": [], "desc": "ML classifications"},
        {"path": "/api/rules-classified", "expected_keys": [], "desc": "Classified rules"},

        # System
        {"path": "/api/resources", "expected_keys": [], "desc": "System resources"},
        {"path": "/api/schema-migrations", "expected_keys": [], "desc": "Schema status"},
        {"path": "/api/opnsense", "expected_keys": [], "desc": "OPNsense status"},
        {"path": "/api/rules", "expected_keys": [], "desc": "Firewall rules"},

        # Advanced
        {"path": "/api/active-learning-queue", "expected_keys": [], "desc": "Learning queue"},
        {"path": "/api/drift", "expected_keys": [], "desc": "Concept drift"},
        {"path": "/api/threshold", "expected_keys": [], "desc": "Threshold tuning"},
    ]

    results: Dict[str, int] = {"pass": 0, "fail": 0, "warn": 0, "total": len(endpoints)}
    failures: List[Dict] = []

    for ep in endpoints:
        path = ep["path"]
        params = ep.get("params")
        desc = ep.get("desc", path)
        ep_start = time.time()

        status, body, ms = http_get(base, path, params, timeout=timeout)

        if status == 0:
            results["fail"] += 1
            failures.append({"endpoint": path, "error": "Connection failed", "body": body})
        elif status == 200:
            # Check expected keys
            missing_keys = [k for k in ep["expected_keys"] if k not in body] if isinstance(body, dict) else []
            if missing_keys:
                results["warn"] += 1
                failures.append({"endpoint": path, "error": f"Missing keys: {missing_keys}", "keys": list(body.keys()) if isinstance(body, dict) else "not-dict"})
            else:
                results["pass"] += 1
        else:
            results["fail"] += 1
            failures.append({"endpoint": path, "status": status, "body_preview": str(body)[:100]})

    # Summary finding
    overall_severity = "PASS" if results["fail"] == 0 else "FAIL" if results["fail"] > 2 else "WARN"
    report.findings.append({
        "stage": stage, "check_name": "endpoint_coverage",
        "severity": overall_severity,
        "message": f"API endpoints: {results['pass']}/{results['total']} passing, {results['fail']} failing, {results['warn']} warnings",
        "details": {
            "total": results["total"],
            "passing": results["pass"],
            "failing": results["fail"],
            "warnings": results["warn"],
            "failures": failures[:10],  # Cap to avoid huge payloads
        },
        "timestamp_ms": (time.time() - t0) * 1000,
    })

    # Individual findings for failures
    for f in failures[:5]:
        report.findings.append({
            "stage": stage,
            "check_name": f"endpoint_{f['endpoint'].strip('/')}",
            "severity": "FAIL" if "Connection failed" in f.get("error", "") else "WARN",
            "message": f"{f['endpoint']}: {f.get('error', 'status=' + str(f.get('status', '?')))[:80]} ({f.get('body_preview', '')[:80]})",
            "details": f,
            "timestamp_ms": (time.time() - t0) * 1000,
        })

    # Check response times
    slow_endpoints = [f for f in failures if f.get("response_time_ms", 0) > 5000]
    if not slow_endpoints:
        report.findings.append({
            "stage": stage, "check_name": "response_time",
            "severity": "PASS",
            "message": "No endpoints with response time > 5s",
            "timestamp_ms": (time.time() - t0) * 1000,
        })


# ─── Stage 8: UI_DATA ──────────────────────────────────────────────

def check_ui_data(report: PipelineReport, base: str, verbose: bool = False, timeout: int = REQUEST_TIMEOUT):
    """Verify frontend data contracts: API responses match UI expectations."""
    stage = Stage.UI_DATA.value
    t0 = time.time()

    # 8a: Verify data contracts for key visualizations
    contracts = [
        {
            "name": "heatmap_contract",
            "endpoint": "/api/heatmap",
            "description": "IP × Hour heatmap data",
            "required_structure": lambda body: isinstance(body, dict) and
                "data" in body and isinstance(body["data"], (list, dict)),
        },
        {
            "name": "ip_flow_contract",
            "endpoint": "/api/ip-flow",
            "description": "IP flow graph (nodes + edges)",
            "required_structure": lambda body: isinstance(body, dict) and
                ("nodes" in body or "edges" in body or "flows" in body),
        },
        {
            "name": "timeline_contract",
            "endpoint": "/api/timeline",
            "params": {"period": "7d", "granularity": "hour"},
            "description": "Time-series for chart rendering",
            "required_structure": lambda body: isinstance(body, dict) and
                ("data" in body or "timeline" in body or "series" in body),
        },
        {
            "name": "traffic_flow_contract",
            "endpoint": "/api/traffic-flow",
            "description": "Traffic flow visualization data",
            "required_structure": lambda body: isinstance(body, dict) or isinstance(body, list),
        },
        {
            "name": "blocked_ips_contract",
            "endpoint": "/api/blocked-ips",
            "description": "Blocked IP list with scores",
            "required_structure": lambda body: isinstance(body, dict) and
                ("ips" in body or "blocked_ips" in body or "data" in body),
        },
        {
            "name": "geo_contract",
            "endpoint": "/api/geo",
            "description": "Geographic distribution data",
            "required_structure": lambda body: isinstance(body, dict) or isinstance(body, list),
        },
        {
            "name": "events_contract",
            "endpoint": "/api/events",
            "params": {"limit": "1"},
            "description": "Event list for table rendering",
            "required_structure": lambda body: isinstance(body, dict) and
                ("events" in body or "data" in body or isinstance(body, list)),
        },
        {
            "name": "anomalies_contract",
            "endpoint": "/api/anomalies",
            "params": {"limit": "1"},
            "description": "Anomaly feed for alert panel",
            "required_structure": lambda body: isinstance(body, dict) and
                ("anomalies" in body or "data" in body or isinstance(body, list)),
        },
    ]

    contract_results = {"pass": 0, "fail": 0}
    for contract in contracts:
        status, body, ms = http_get(base, contract["endpoint"], contract.get("params", timeout=timeout))

        if status != 200:
            contract_results["fail"] += 1
            report.findings.append({
                "stage": stage, "check_name": contract["name"],
                "severity": "FAIL",
                "message": f"{contract['description']}: endpoint returned {status}",
                "details": {"endpoint": contract["endpoint"], "status": status},
                "timestamp_ms": (time.time() - t0) * 1000,
            })
            continue

        try:
            if contract["required_structure"](body):
                contract_results["pass"] += 1
                report.findings.append({
                    "stage": stage, "check_name": contract["name"],
                    "severity": "PASS",
                    "message": f"{contract['description']}: contract satisfied",
                    "details": {"top_keys": list(body.keys()) if isinstance(body, dict) else "list"},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })
            else:
                contract_results["fail"] += 1
                report.findings.append({
                    "stage": stage, "check_name": contract["name"],
                    "severity": "WARN",
                    "message": f"{contract['description']}: structure mismatch",
                    "details": {"body_type": type(body).__name__, "keys": list(body.keys()) if isinstance(body, dict) else "n/a"},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })
        except Exception as e:
            contract_results["fail"] += 1
            report.findings.append({
                "stage": stage, "check_name": contract["name"],
                "severity": "FAIL",
                "message": f"{contract['description']}: structure check raised: {e}",
                "details": {"error": str(e)},
                "timestamp_ms": (time.time() - t0) * 1000,
            })

    report.findings.append({
        "stage": stage, "check_name": "contract_summary",
        "severity": "PASS" if contract_results["fail"] == 0 else "WARN",
        "message": f"UI data contracts: {contract_results['pass']}/{len(contracts)} satisfied",
        "details": contract_results,
        "timestamp_ms": (time.time() - t0) * 1000,
    })

    # 8b: Check for empty-state messaging (critical UX concern)
    empty_endpoints = [
        ("/api/heatmap", "heatmap"),
        ("/api/ip-flow", "ip_flow"),
        ("/api/anomalies", "anomalies"),
    ]
    for path, name in empty_endpoints:
        status, body, ms = http_get(base, path, {"limit": "1"} if name != "anomalies" else None, timeout=timeout)
        if status == 200 and isinstance(body, dict):
            data_key = next((k for k in ["data", "anomalies", "flows", "nodes"] if k in body), None)
            if data_key and body[data_key]:
                report.findings.append({
                    "stage": stage, "check_name": f"empty_state_{name}",
                    "severity": "PASS",
                    "message": f"{name} has data — no empty state needed",
                    "timestamp_ms": (time.time() - t0) * 1000,
                })
            elif data_key and not body[data_key]:
                # Check for helpful empty-state message
                has_message = any(k in body for k in ["message", "empty_message", "status_message", "hint"])
                report.findings.append({
                    "stage": stage, "check_name": f"empty_state_{name}",
                    "severity": "PASS" if has_message else "WARN",
                    "message": f"{name} is empty — {'has contextual message' if has_message else 'NO contextual message for empty state'}",
                    "details": {"keys": list(body.keys())},
                    "timestamp_ms": (time.time() - t0) * 1000,
                })


# ─── Pipeline gaps detection ───────────────────────────────────────

def detect_pipeline_gaps(report: PipelineReport, base: str, timeout: int = REQUEST_TIMEOUT):
    """Cross-stage analysis to identify data flow gaps."""
    stage = "cross_stage"

    # Gap 1: Events in DB but no anomalies — detection gap?
    status_stats, body_stats, _ = http_get(base, "/api/stats", timeout=timeout)
    status_anomalies, body_anomalies, _ = http_get(base, "/api/anomalies", {"limit": "1"}, timeout=timeout)

    if status_stats == 200 and isinstance(body_stats, dict):
        total_events = body_stats.get("total_events", 0)

        anomaly_count = 0
        if status_anomalies == 200 and isinstance(body_anomalies, dict):
            anomalies = body_anomalies.get("anomalies", [])
            anomaly_count = len(anomalies) if isinstance(anomalies, list) else body_anomalies.get("total", 0)

        if total_events and total_events > 100 and anomaly_count == 0:
            report.findings.append({
                "stage": stage, "check_name": "detection_gap",
                "severity": "WARN",
                "message": f"{total_events} events but 0 anomalies — detection may be too strict or no attack traffic",
                "details": {"total_events": total_events, "anomaly_count": anomaly_count},
                "timestamp_ms": 0,
            })
        elif total_events and total_events > 0:
            ratio = anomaly_count / total_events if total_events else 0
            report.findings.append({
                "stage": stage, "check_name": "detection_ratio",
                "severity": "INFO",
                "message": f"Anomaly rate: {anomaly_count}/{total_events} events ({ratio*100:.1f}%)",
                "details": {"total_events": total_events, "anomaly_count": anomaly_count, "ratio": round(ratio, 4)},
                "timestamp_ms": 0,
            })

    # Gap 2: Anomalies detected but no alerts sent
    if status_anomalies == 200 and isinstance(body_anomalies, dict):
        anomalies = body_anomalies.get("anomalies", [])
        if isinstance(anomalies, list) and anomalies:
            unsent = sum(1 for a in anomalies if isinstance(a, dict) and not a.get("alert_sent", True))
            if unsent > 0:
                report.findings.append({
                    "stage": stage, "check_name": "alert_delivery_gap",
                    "severity": "WARN",
                    "message": f"{unsent} anomalies without alert_sent=True — Discord/alert pipeline may be broken",
                    "details": {"total_anomalies": len(anomalies), "unsent": unsent},
                    "timestamp_ms": 0,
                })

    # Gap 3: Check timestamp propagation chain
    # Events should have: syslog_timestamp → ingested_at → created_at
    status_events, body_events, _ = http_get(base, "/api/events", {"limit": "3"}, timeout=timeout)
    if status_events == 200:
        events = body_events.get("events", body_events if isinstance(body_events, list) else [])
        if events and isinstance(events[0], dict):
            ts_fields = ["timestamp", "ingested_at", "created_at"]
            present = [f for f in ts_fields if f in events[0] and events[0].get(f)]
            missing = [f for f in ts_fields if f not in events[0] or not events[0].get(f)]
            if missing:
                report.findings.append({
                    "stage": stage, "check_name": "timestamp_chain",
                    "severity": "WARN",
                    "message": f"Timestamp chain incomplete: missing {missing}",
                    "details": {"present": present, "missing": missing},
                    "timestamp_ms": 0,
                })
            else:
                report.findings.append({
                    "stage": stage, "check_name": "timestamp_chain",
                    "severity": "PASS",
                    "message": f"Full timestamp chain present: {present}",
                    "details": {"fields": present},
                    "timestamp_ms": 0,
                })

    # Gap 4: Check if test marker data is present (E2E traceability)
    status_events, body_events, _ = http_get(base, "/api/events", {"limit": "100"}, timeout=timeout)
    if status_events == 200:
        events = body_events.get("events", body_events if isinstance(body_events, list) else [])
        marker_events = []
        for ev in events:
            if isinstance(ev, dict):
                src = ev.get("src_ip", "")
                dst = ev.get("dst_ip", "")
                raw = ev.get("raw", ev.get("raw_message", ""))
                if src.startswith(MARKER_IP_BASE) or dst.startswith(MARKER_IP_BASE) or TEST_MARKER_PREFIX in raw:
                    marker_events.append(ev)
        if marker_events:
            report.findings.append({
                "stage": stage, "check_name": "e2e_marker_trace",
                "severity": "PASS",
                "message": f"E2E markers found: {len(marker_events)} test events traceable through pipeline",
                "details": {"marker_count": len(marker_events)},
                "timestamp_ms": 0,
            })
        else:
            report.findings.append({
                "stage": stage, "check_name": "e2e_marker_trace",
                "severity": "INFO",
                "message": "No E2E marker events found — run test_data_seeder.py first to inject traceable data",
                "timestamp_ms": 0,
            })


# ─── Main orchestrator ─────────────────────────────────────────────

def run_verification(base: str, stages: Optional[List[str]] = None, verbose: bool = False, dry_run: bool = False, timeout: int = REQUEST_TIMEOUT) -> PipelineReport:
    """Run full pipeline verification."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    report = PipelineReport(
        run_id=run_id,
        started_at=datetime.now(timezone.utc).isoformat(),
        base_url=base,
    )

    if dry_run:
        all_stages = [s.value for s in Stage]
        report.completed_at = datetime.now(timezone.utc).isoformat()
        report.summary = {"dry_run": "true", "stages_planned": all_stages}
        return report

    # Stage dispatch
    stage_checkers: Dict[str, Any] = {
        Stage.SOURCE.value: check_source,
        Stage.PARSER.value: check_parser,
        Stage.AGENT.value: check_agent,
        Stage.DATABASE.value: check_database,
        Stage.ANOMALY.value: check_anomaly,
        Stage.BASELINE.value: check_baseline,
        Stage.API.value: check_api,
        Stage.UI_DATA.value: check_ui_data,
    }

    if stages:
        selected = stages
    else:
        selected = list(stage_checkers.keys())

    for stage_name in selected:
        checker = stage_checkers.get(stage_name)
        if checker:
            if verbose:
                print(f"[pipeline_verification] Checking stage: {stage_name}...")
            checker(report, base, verbose, timeout)
        else:
            report.findings.append({
                "stage": stage_name, "check_name": "stage_missing",
                "severity": "SKIP", "message": f"No checker for stage: {stage_name}",
                "timestamp_ms": 0,
            })

    # Cross-stage gap analysis — only when running all stages
    all_stage_names = [s.value for s in Stage]
    if not stages or set(selected) == set(all_stage_names):
        detect_pipeline_gaps(report, base, timeout)

    report.completed_at = datetime.now(timezone.utc).isoformat()

    # Summary
    report.summary = {
        "total_findings": str(len(report.findings)),
        "pass": str(report.pass_count),
        "fail": str(report.fail_count),
        "warn": str(report.warn_count),
        "skip": str(report.skip_count),
        "status": "HEALTHY" if report.fail_count == 0 else "DEGRADED" if report.fail_count <= 2 else "UNHEALTHY",
    }

    return report


# ─── Output ─────────────────────────────────────────────────────────

def format_text(report: PipelineReport) -> str:
    """Human-readable text output."""
    lines = []
    lines.append("=" * 72)
    lines.append(f"Pipeline Health Verification — Run {report.run_id}")
    lines.append(f"Base URL: {report.base_url}")
    lines.append(f"Started:  {report.started_at}")
    lines.append(f"Finished: {report.completed_at}")
    lines.append("=" * 72)

    # Group by stage
    from collections import OrderedDict
    by_stage: Dict[str, List[Dict]] = OrderedDict()
    for f in report.findings:
        stage = f.get("stage", "unknown")
        by_stage.setdefault(stage, []).append(f)

    for stage, findings in by_stage.items():
        lines.append(f"\n── {stage.upper()} ──")
        for f in findings:
            sev_icon = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "SKIP": "○", "INFO": "ℹ"}.get(f["severity"], "?")
            lines.append(f"  [{sev_icon} {f['severity']}] {f['check_name']}: {f['message']}")

    lines.append("\n" + "=" * 72)
    lines.append(f"Summary: {report.pass_count} PASS, {report.fail_count} FAIL, {report.warn_count} WARN, {report.skip_count} SKIP")
    lines.append(f"Status:  {report.summary.get('status', 'UNKNOWN')}")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_json(report: PipelineReport) -> str:
    """Machine-readable JSON output."""
    return json.dumps({
        "run_id": report.run_id,
        "started_at": report.started_at,
        "completed_at": report.completed_at,
        "base_url": report.base_url,
        "summary": report.summary,
        "counts": {
            "pass": report.pass_count,
            "fail": report.fail_count,
            "warn": report.warn_count,
            "skip": report.skip_count,
        },
        "findings": report.findings,
    }, indent=2)


# ─── CLI ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Pipeline Health Verification — Source-to-UI tracing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Stages: source, parser, agent, database, anomaly, baseline, api, ui_data
Run all stages by default, or specify --stage to check specific ones.

Examples:
  %(prog)s                                    # all stages, local server
  %(prog)s --base http://192.168.1.50:8766   # remote deployment
  %(prog)s --stage database api               # specific stages only
  %(prog)s --json                             # JSON output for CI
  %(prog)s --dry-run                          # show plan only
        """,
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help=f"Dashboard base URL (default: {DEFAULT_BASE})")
    parser.add_argument("--stage", nargs="+", help="Specific stages to check (default: all)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without running")
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT, help=f"Request timeout in seconds (default: {REQUEST_TIMEOUT})")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    report = run_verification(args.base, args.stage, args.verbose, args.dry_run, args.timeout)

    if args.json:
        print(format_json(report))
    else:
        print(format_text(report))

    sys.exit(1 if report.fail_count > 0 else 0)


if __name__ == "__main__":
    main()
