#!/usr/bin/env python3
"""Structured detection decision logging for OPNsense Anomaly Detection Agent.

Every detection decision (alert, suppression, baseline deviation, etc.) is logged
as a structured JSON line with a canonical schema so that any "why was this
flagged?" question is answerable from the logs alone.

Schema (all fields present on every log line):
  - detection_id       unique identifier for this decision (uuid4)
  - timestamp          ISO 8601 UTC
  - event_id           ID of the triggering event (from DB or "batch:N")
  - src_ip             Source IP under investigation
  - dst_ip             Destination IP (if applicable)
  - detection_module   Which module produced the decision
                       (e.g. "attack_detector", "geo_anomaly", "baseline_anomaly")
  - decision           "ALERT", "SUPPRESSED", or "OK"
  - score              Numeric confidence / severity score (float)
  - severity           String severity: LOW / MEDIUM / HIGH / CRITICAL
  - signal_types       List of signal type names that contributed
  - threshold          Threshold value that was crossed (or null)
  - action_taken       What happened after detection
                       (e.g. "discord+apprise", "muted", "db_only")
  - explanation        Human-readable explanation string
                       e.g. "Flagged because: port_scan (15 ports in 120s)"
  - detail             Free-form dict with module-specific extra context

Usage:
    from detection_logging import get_detection_logger

    det_log = get_detection_logger(__name__)

    det_log.log_decision(
        event_id=event.get("id"),
        src_ip="1.2.3.4",
        detection_module="attack_detector",
        decision="ALERT",
        score=0.95,
        severity="HIGH",
        signal_types=["PORT_SCAN"],
        threshold=15,
        action_taken="discord+apprise",
        explanation="Flagged because: port_scan (15 distinct ports in 120s window)",
        detail={"distinct_ports": 15, "scan_subtype": "VERTICAL"},
    )
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from json_logging import get_structured_logger


# ---------------------------------------------------------------------------
# Canonical field names — used as both documentation and runtime validation
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = frozenset([
    "detection_id",
    "timestamp",
    "detection_module",
    "decision",
    "score",
    "severity",
    "signal_types",
    "explanation",
])

VALID_DECISIONS = {"ALERT", "SUPPRESSED", "OK", "ESCALATED"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class DetectionLogger:
    """Structured logger for detection decisions.

    Wraps a StructuredLogger and emits every decision as a single JSON line
    with the canonical detection schema.  An additional dedicated log file
    at DATA_DIR/detection_decisions.log captures *only* decision records for
    easy querying.
    """

    def __init__(self, module_name: str) -> None:
        self._slog = get_structured_logger(f"{module_name}.detection")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def log_decision(
        self,
        *,
        event_id: Optional[str] = None,
        src_ip: str = "",
        dst_ip: Optional[str] = None,
        detection_module: str,
        decision: str,
        score: float,
        severity: str,
        signal_types: List[str],
        threshold: Optional[float] = None,
        action_taken: str = "",
        explanation: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log a single detection decision.

        Returns the detection_id for downstream correlation.
        """
        detection_id = str(uuid.uuid4())

        # Normalise inputs
        decision = decision.upper() if decision else "OK"
        if decision not in VALID_DECISIONS:
            decision = "ALERT"
        severity = severity.upper() if severity else "MEDIUM"
        if severity not in VALID_SEVERITIES:
            severity = "MEDIUM"

        record: Dict[str, Any] = {
            "detection_id": detection_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": event_id or None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "detection_module": detection_module,
            "decision": decision,
            "score": float(score) if score is not None else 0.0,
            "severity": severity,
            "signal_types": signal_types,
            "threshold": threshold,
            "action_taken": action_taken,
            "explanation": explanation,
            "detail": detail or {},
        }

        # Validate required fields are non-empty
        _validate(record)

        # Emit via structured logger — JsonFormatter turns this into one JSON line
        self._slog.info(
            "DETECTION_DECISION",
            **record,
        )

        return detection_id

    # ------------------------------------------------------------------
    # Convenience helpers for common patterns
    # ------------------------------------------------------------------
    def log_alert(
        self,
        *,
        event_id: Optional[str] = None,
        src_ip: str,
        dst_ip: Optional[str] = None,
        detection_module: str,
        score: float,
        severity: str,
        signal_types: List[str],
        threshold: Optional[float] = None,
        explanation: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Shortcut for ALERT decisions."""
        return self.log_decision(
            event_id=event_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            detection_module=detection_module,
            decision="ALERT",
            score=score,
            severity=severity,
            signal_types=signal_types,
            threshold=threshold,
            action_taken="discord+apprise",
            explanation=explanation,
            detail=detail,
        )

    def log_suppressed(
        self,
        *,
        src_ip: str,
        detection_module: str,
        signal_types: List[str],
        explanation: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Shortcut for SUPPRESSED (muted) decisions."""
        return self.log_decision(
            src_ip=src_ip,
            detection_module=detection_module,
            decision="SUPPRESSED",
            score=0.0,
            severity="LOW",
            signal_types=signal_types,
            action_taken="muted",
            explanation=explanation,
            detail=detail,
        )

    def build_explanation(
        self,
        signal_types: List[str],
        details: Dict[str, Any],
    ) -> str:
        """Build a human-readable explanation string from signals.

        Example output:
            "Flagged because: port_scan (15 ports in 120s), http_404_spike (5 unique paths)"
        """
        if not signal_types:
            return "Flagged due to anomalous behavior"

        parts: List[str] = []
        for sig in signal_types:
            sig_lower = sig.lower().replace(" ", "_")
            # Try to extract a meaningful count from details
            detail_str = _extract_detail(sig_lower, details)
            if detail_str:
                parts.append(f"{sig_lower} ({detail_str})")
            else:
                parts.append(sig_lower)

        return "Flagged because: " + ", ".join(parts)


def _extract_detail(signal_type: str, details: Dict[str, Any]) -> str:
    """Extract a human-friendly detail string for a signal type."""
    mapping: Dict[str, List[str]] = {
        "port_scan": ["distinct_ports", "ports_count"],
        "horizontal": ["distinct_hosts", "host_list"],
        "syn_flood": ["syn_count"],
        "brute_force": ["attempt_count"],
        "probe": ["icmp_count"],
        "geo_anomaly": ["country_code"],
        "new_country": ["country_code"],
        "baseline_deviation": ["z_score"],
        "new_signature": ["trigger_count"],
        "signature_spike": ["trigger_count"],
    }

    for key in mapping.get(signal_type, []):
        val = details.get(key)
        if val is not None:
            if isinstance(val, str):
                return val
            return f"{val}"
    return ""


def _validate(record: Dict[str, Any]) -> None:
    """Lightweight validation — ensures required fields exist."""
    # Non-blocking: log warning if fields are missing
    missing = [f for f in REQUIRED_FIELDS if not record.get(f)]
    if missing:
        logging.getLogger(__name__).warning(
            "Detection log missing fields: %s", missing
        )


def get_detection_logger(module_name: str) -> DetectionLogger:
    """Factory: create a DetectionLogger for the given module."""
    return DetectionLogger(module_name)
