#!/usr/bin/env python3
"""
Incident management layer for OPNsense Anomaly Detection Agent.

Provides lifecycle control, user feedback, incident grouping, and
auto-resolution for correlated incidents produced by CorrelationEngine.

Architecture:
- IncidentManager owns state transitions (NEW -> INVESTIGATING -> CONFIRMED -> RESOLVED)
- Feedback loop: thumbs up/down on classification, stored in incident_feedback table
- Aggregation: group related incidents (same IP within configurable window)
- Auto-resolution: configurable timeout without new signals

Usage:
    from incident_manager import IncidentManager
    mgr = IncidentManager(db, correlation_engine)
    mgr.auto_create_incidents()  # Called by agent.py on new CorrelationEngine incident
    mgr.transition("inc_123", "investigating")
    mgr.record_feedback("inc_123", "thumbs_up")
"""

import json
import logging
import time
import threading
import uuid
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Incident lifecycle states ───────────────────────────────────────

INCIDENT_NEW = "new"
INCIDENT_INVESTIGATING = "investigating"
INCIDENT_CONFIRMED = "confirmed"
INCIDENT_RESOLVED = "resolved"
INCIDENT_FALSE_POSITIVE = "false_positive"

INCIDENT_STATES = [INCIDENT_NEW, INCIDENT_INVESTIGATING, INCIDENT_CONFIRMED, INCIDENT_RESOLVED, INCIDENT_FALSE_POSITIVE]
INCIDENT_TERMINAL_STATES = [INCIDENT_RESOLVED, INCIDENT_FALSE_POSITIVE]

# Valid state transitions
VALID_TRANSITIONS: Dict[str, List[str]] = {
    INCIDENT_NEW: [INCIDENT_INVESTIGATING, INCIDENT_CONFIRMED, INCIDENT_RESOLVED, INCIDENT_FALSE_POSITIVE],
    INCIDENT_INVESTIGATING: [INCIDENT_CONFIRMED, INCIDENT_RESOLVED, INCIDENT_FALSE_POSITIVE],
    INCIDENT_CONFIRMED: [INCIDENT_RESOLVED],
    INCIDENT_RESOLVED: [],  # Terminal state
    INCIDENT_FALSE_POSITIVE: [],  # Terminal state
}

# Severity rank for sorting
SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ── Feedback types ──────────────────────────────────────────────────

FEEDBACK_THUMBS_UP = "thumbs_up"
FEEDBACK_THUMBS_DOWN = "thumbs_down"
FEEDBACK_VALID_TYPES = [FEEDBACK_THUMBS_UP, FEEDBACK_THUMBS_DOWN]


# ── Incident record (in-memory representation of DB row) ─────────────

class IncidentRecord:
    """Lightweight representation of an incident with lifecycle state."""

    __slots__ = (
        "id", "db_id", "ip", "severity", "status",
        "signal_count", "signal_types", "sources", "phases",
        "first_seen", "last_seen", "description", "metadata",
        "is_active", "auto_resolved", "resolved_at", "group_id",
        "feedback_count", "feedback_score",
        "dismissal_reason",
    )

    def __init__(self, db_id: int, ip: str, severity: str = "low",
                 signal_count: int = 0, signal_types: Optional[List[str]] = None,
                 sources: Optional[List[str]] = None,
                 phases: Optional[List[str]] = None,
                 first_seen: Optional[float] = None,
                 last_seen: Optional[float] = None,
                 description: str = "", metadata: Optional[Dict] = None,
                 is_active: bool = True, auto_resolved: bool = False,
                 resolved_at: Optional[float] = None,
                 dismissal_reason: str = ""):
        self.id = f"inc_{uuid.uuid4().hex[:8]}"
        self.db_id = db_id
        self.ip = ip
        self.severity = severity
        self.status = INCIDENT_NEW
        self.signal_count = signal_count
        self.signal_types = signal_types or []
        self.sources = sources or []
        self.phases = phases or []
        self.first_seen = first_seen or time.time()
        self.last_seen = last_seen or self.first_seen
        self.description = description
        self.metadata = metadata or {}
        self.is_active = is_active
        self.auto_resolved = auto_resolved
        self.resolved_at = resolved_at
        self.group_id: Optional[int] = None
        self.feedback_count = 0
        self.feedback_score = 0.0  # avg thumbs_up ratio
        self.dismissal_reason = dismissal_reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "db_id": self.db_id,
            "ip": self.ip,
            "severity": self.severity,
            "status": self.status,
            "signal_count": self.signal_count,
            "signal_types": self.signal_types,
            "sources": self.sources,
            "phases": self.phases,
            "first_seen": datetime.fromtimestamp(self.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
            "description": self.description,
            "metadata": self.metadata,
            "is_active": self.is_active,
            "auto_resolved": self.auto_resolved,
            "resolved_at": (
                datetime.fromtimestamp(self.resolved_at, tz=timezone.utc).isoformat()
                if self.resolved_at else None
            ),
            "group_id": self.group_id,
            "feedback_count": self.feedback_count,
            "feedback_score": round(self.feedback_score, 2),
            "dismissal_reason": self.dismissal_reason,
        }


# ── Incident Group ───────────────────────────────────────────────────

class IncidentGroup:
    """Groups related incidents (same IP within a time window)."""

    def __init__(self, group_id: int, ip: str):
        self.group_id = group_id
        self.ip = ip
        self.incident_ids: List[str] = []
        self.created_at = time.time()
        self.resolved_at: Optional[float] = None
        self.severity = "low"
        self.severity_rank = 0
        self.signal_count = 0
        self.signal_types: Set[str] = set()
        self.description = ""

    def add_incident(self, record: IncidentRecord):
        self.incident_ids.append(record.id)
        self.signal_count += record.signal_count
        self.signal_types.update(record.signal_types)
        if SEVERITY_RANK.get(record.severity, 0) > self.severity_rank:
            self.severity_rank = SEVERITY_RANK[record.severity]
            self.severity = record.severity
        self.description = f"Grouped incident for {self.ip}: {len(self.incident_ids)} related incidents, {self.signal_count} total signals"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "ip": self.ip,
            "incident_ids": self.incident_ids,
            "incident_count": len(self.incident_ids),
            "created_at": datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat(),
            "resolved_at": (
                datetime.fromtimestamp(self.resolved_at, tz=timezone.utc).isoformat()
                if self.resolved_at else None
            ),
            "severity": self.severity,
            "signal_count": self.signal_count,
            "signal_types": sorted(self.signal_types),
            "description": self.description,
        }


# ── IncidentManager ──────────────────────────────────────────────────

class IncidentManager:
    """Incident lifecycle manager with feedback and grouping.

    Manages the full lifecycle of incidents from creation to resolution,
    supports user feedback for classification quality, and groups related
    incidents by IP within a configurable time window.

    Thread-safe: uses locks for concurrent access to incident registry.
    """

    def __init__(self, db: Any = None, behavioral_engine: Any = None,
                 auto_resolve_after: int = 3600,
                 grouping_window: int = 86400):
        """Initialize the incident manager.

        Args:
            db: EventDatabase instance for persistence.
            behavioral_engine: UnifiedBehavioralEngine for feedback-driven baseline adjustment.
            auto_resolve_after: Seconds without new signals before auto-resolving (default 3600s = 60min).
            grouping_window: Seconds to group related incidents from same IP (default 86400s = 24h).
        """
        self.db = db
        self.behavioral_engine = behavioral_engine
        self.auto_resolve_after = auto_resolve_after
        self.grouping_window = grouping_window

        # In-memory registry: inc_id -> IncidentRecord
        self._incidents: Dict[str, IncidentRecord] = {}
        # Group registry: group_id -> IncidentGroup
        self._groups: Dict[int, IncidentGroup] = {}
        # IP -> list of active incident IDs (for grouping)
        self._ip_incidents: Dict[str, List[str]] = defaultdict(list)

        self._lock = threading.Lock()
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = []

        # Counters
        self._total_created = 0
        self._total_resolved = 0
        self._total_feedback = 0
        self._total_confirmed = 0
        self._total_dismissed = 0

        logger.info(
            "IncidentManager initialized (auto_resolve=%ds, grouping_window=%ds)",
            auto_resolve_after, grouping_window,
        )

    # ── Lifecycle: State transitions ──────────────────────────────────

    def transition(self, inc_id: str, new_status: str,
                   reason: str = "") -> Tuple[bool, str]:
        """Transition an incident to a new state.

        Args:
            inc_id: Incident ID (inc_xxxxxxxx).
            new_status: Target state (investigating, confirmed, resolved).
            reason: Optional reason for the transition.

        Returns:
            Tuple of (success, message).
        """
        new_status = new_status.lower().strip()
        if new_status not in INCIDENT_STATES:
            return False, f"Invalid state: '{new_status}'. Valid states: {INCIDENT_STATES}"

        with self._lock:
            record = self._incidents.get(inc_id)
            if not record:
                return False, f"Incident not found: {inc_id}"

        current = record.status
        if current == new_status:
            return False, f"Incident {inc_id} is already in '{current}' state"

        allowed = VALID_TRANSITIONS.get(current, [])
        if new_status not in allowed:
            return False, (
                f"Cannot transition from '{current}' to '{new_status}'. "
                f"Allowed transitions: {allowed}"
            )

        with self._lock:
            record.status = new_status
            if new_status == INCIDENT_RESOLVED:
                record.is_active = False
                record.resolved_at = time.time()
                self._total_resolved += 1

        self._persist_status(inc_id, new_status, reason)
        logger.info(
            "Incident %s: %s -> %s%s",
            inc_id, current, new_status,
            f" (reason: {reason})" if reason else ""
        )

        # Notify callbacks
        self._notify({
            "event": "transition",
            "inc_id": inc_id,
            "from": current,
            "to": new_status,
            "reason": reason,
        })

        return True, f"Transitioned {inc_id} from '{current}' to '{new_status}'"

    def bulk_transition(self, inc_ids: List[str], new_status: str,
                        reason: str = "") -> Dict[str, Tuple[bool, str]]:
        """Transition multiple incidents to the same state.

        Args:
            inc_ids: List of incident IDs.
            new_status: Target state.
            reason: Optional reason.

        Returns:
            Dict mapping inc_id -> (success, message).
        """
        results = {}
        for inc_id in inc_ids:
            results[inc_id] = self.transition(inc_id, new_status, reason)

        success_count = sum(1 for s, _ in results.values() if s)
        logger.info(
            "Bulk transition: %d/%d succeeded to '%s'",
            success_count, len(inc_ids), new_status
        )
        return results

    # ── Feedback-integrated lifecycle: confirm / dismiss ──────────────

    def confirm_incident(self, inc_id: str, reason: str = "") -> Tuple[bool, str]:
        """Confirm an incident as a true positive (real threat).

        Transitions to CONFIRMED, records thumbs_up feedback, and notifies
        the UnifiedBehavioralEngine to reinforce signal weights.

        Args:
            inc_id: Incident ID (inc_xxxxxxxx).
            reason: Optional reason for confirmation.

        Returns:
            Tuple of (success, message).
        """
        with self._lock:
            record = self._incidents.get(inc_id)
            if not record:
                return False, f"Incident not found: {inc_id}"
            ip = record.ip
            signal_types = list(record.signal_types)

        # Transition to confirmed (or resolve first if not a valid transition)
        if record.status not in (INCIDENT_NEW, INCIDENT_INVESTIGATING):
            return False, (
                f"Cannot confirm incident {inc_id} in '{record.status}' state. "
                f"Must be '{INCIDENT_NEW}' or '{INCIDENT_INVESTIGATING}'."
            )

        success, msg = self.transition(inc_id, INCIDENT_CONFIRMED, reason or "confirmed by user")
        if not success:
            return False, msg

        with self._lock:
            self._total_confirmed += 1

        # Record thumbs_up feedback
        self.record_feedback(inc_id, FEEDBACK_THUMBS_UP, reason or "confirmed by user", "user")

        # Notify behavioral engine
        self._notify_behavioral_engine(ip, signal_types, "confirm", reason)

        logger.info(
            "Incident %s confirmed for IP %s (signal_types: %s)",
            inc_id, ip, signal_types,
        )

        self._notify({
            "event": "confirmed",
            "inc_id": inc_id,
            "ip": ip,
            "reason": reason,
        })

        return True, f"Confirmed {inc_id} as true positive for IP {ip}"

    def dismiss_incident(self, inc_id: str, reason: str = "") -> Tuple[bool, str]:
        """Dismiss an incident as a false positive.

        Transitions to FALSE_POSITIVE, records thumbs_down feedback, and notifies
        the UnifiedBehavioralEngine to adjust baselines.

        Args:
            inc_id: Incident ID (inc_xxxxxxxx).
            reason: Optional reason for dismissal.

        Returns:
            Tuple of (success, message).
        """
        with self._lock:
            record = self._incidents.get(inc_id)
            if not record:
                return False, f"Incident not found: {inc_id}"
            ip = record.ip
            signal_types = list(record.signal_types)

        # Transition to false_positive (or resolve if not a valid transition)
        if record.status not in (INCIDENT_NEW, INCIDENT_INVESTIGATING):
            return False, (
                f"Cannot dismiss incident {inc_id} in '{record.status}' state. "
                f"Must be '{INCIDENT_NEW}' or '{INCIDENT_INVESTIGATING}'."
            )

        success, msg = self.transition(inc_id, INCIDENT_FALSE_POSITIVE, reason or "dismissed by user")
        if not success:
            return False, msg

        with self._lock:
            record = self._incidents.get(inc_id)
            if record:
                record.dismissal_reason = reason or "dismissed by user"
            self._total_dismissed += 1

        # Record thumbs_down feedback
        self.record_feedback(inc_id, FEEDBACK_THUMBS_DOWN, reason or "dismissed by user", "user")

        # Notify behavioral engine
        self._notify_behavioral_engine(ip, signal_types, "dismiss", reason)

        # Persist dismissal reason to DB
        self._persist_dismissal_reason(inc_id, reason)

        logger.info(
            "Incident %s dismissed for IP %s (reason: %s)",
            inc_id, ip, reason,
        )

        self._notify({
            "event": "dismissed",
            "inc_id": inc_id,
            "ip": ip,
            "reason": reason,
        })

        return True, f"Dismissed {inc_id} as false positive for IP {ip}"

    # ── Incident creation (from CorrelationEngine) ────────────────────

    def register_incident(self, correlation_incident: Any) -> Optional[IncidentRecord]:
        """Register a new incident from the CorrelationEngine.

        Converts a CorrelationEngine Incident object to an IncidentRecord
        and registers it in the manager.

        Args:
            correlation_incident: Incident object from CorrelationEngine.

        Returns:
            The created IncidentRecord, or None if registration failed.
        """
        try:
            inc_dict = correlation_incident.to_dict() if hasattr(correlation_incident, 'to_dict') else correlation_incident
            ip = inc_dict.get("ip", "")
            if not ip:
                return None

            # Query DB for the db_id of the active incident for this IP
            db_id = self._get_db_id_for_ip(ip)

            record = IncidentRecord(
                db_id=db_id,
                ip=ip,
                severity=inc_dict.get("severity", "low"),
                signal_count=inc_dict.get("signal_count", 0),
                signal_types=inc_dict.get("signal_types", []),
                sources=inc_dict.get("sources", []),
                phases=inc_dict.get("phases", []),
                first_seen=inc_dict.get("first_seen", time.time()),
                last_seen=inc_dict.get("last_seen", time.time()),
                description=inc_dict.get("description", ""),
                metadata=inc_dict.get("metadata", {}),
                is_active=inc_dict.get("is_active", True),
                auto_resolved=inc_dict.get("auto_resolved", False),
            )

            with self._lock:
                self._incidents[record.id] = record
                self._ip_incidents[ip].append(record.id)
                self._total_created += 1

            logger.info(
                "Registered incident %s for IP %s (severity=%s, status=%s)",
                record.id, ip, record.severity, record.status
            )

            # Try to add to a group
            self._try_group_incident(record)

            # Notify callbacks
            self._notify({
                "event": "created",
                "inc_id": record.id,
                "ip": ip,
                "severity": record.severity,
            })

            return record

        except Exception as e:
            logger.error("Failed to register incident: %s", e)
            return None

    # ── Feedback ──────────────────────────────────────────────────────

    def record_feedback(self, inc_id: str, feedback_type: str,
                        notes: str = "", user_id: str = "api") -> Tuple[bool, str]:
        """Record user feedback on an incident classification.

        Args:
            inc_id: Incident ID.
            feedback_type: "thumbs_up" or "thumbs_down".
            notes: Optional notes from the user.
            user_id: Source of feedback (api, discord, dashboard).

        Returns:
            Tuple of (success, message).
        """
        if feedback_type not in FEEDBACK_VALID_TYPES:
            return False, f"Invalid feedback type: '{feedback_type}'. Must be one of {FEEDBACK_VALID_TYPES}"

        with self._lock:
            record = self._incidents.get(inc_id)
            if not record:
                return False, f"Incident not found: {inc_id}"

        # Calculate new score
        current_score = record.feedback_score
        current_count = record.feedback_count
        new_value = 1.0 if feedback_type == FEEDBACK_THUMBS_UP else 0.0
        new_count = current_count + 1
        new_score = (current_score * current_count + new_value) / new_count

        with self._lock:
            record.feedback_count = new_count
            record.feedback_score = new_score

        # Persist to DB
        self._persist_feedback(inc_id, feedback_type, notes, user_id, new_score)

        self._total_feedback += 1
        logger.info(
            "Feedback recorded for %s: %s (score=%.2f, count=%d)",
            inc_id, feedback_type, new_score, new_count
        )

        self._notify({
            "event": "feedback",
            "inc_id": inc_id,
            "feedback_type": feedback_type,
            "score": round(new_score, 2),
        })

        label = "approved" if feedback_type == FEEDBACK_THUMBS_UP else "flagged"
        return True, f"Feedback recorded: incident {inc_id} {label} (thumbs {'up' if feedback_type == FEEDBACK_THUMBS_UP else 'down'})"

    # ── Grouping ──────────────────────────────────────────────────────

    def get_groups(self, active_only: bool = True,
                   min_severity: str = "low") -> List[Dict[str, Any]]:
        """Get incident groups, optionally filtered.

        Args:
            active_only: Only return groups with active incidents.
            min_severity: Minimum severity to include.

        Returns:
            List of group dicts, sorted by severity (highest first).
        """
        min_rank = SEVERITY_RANK.get(min_severity, 0)

        with self._lock:
            groups = []
            for group in self._groups.values():
                if group.severity_rank < min_rank:
                    continue

                if active_only:
                    # Check if any incident in the group is still active
                    has_active = any(
                        (self._incidents.get(inc_id) or IncidentRecord(0, "")).is_active
                        for inc_id in group.incident_ids
                    )
                    if not has_active:
                        continue

                groups.append(group.to_dict())

        groups.sort(key=lambda g: g["severity_rank" if "severity_rank" in g else "severity"],
                     reverse=True)
        # Fallback sort by severity string
        groups.sort(key=lambda g: SEVERITY_RANK.get(g.get("severity", "low"), 0), reverse=True)
        return groups

    def get_incidents(self, status: Optional[str] = None,
                      ip: Optional[str] = None,
                      min_severity: str = "low",
                      active_only: bool = True,
                      limit: int = 50) -> List[Dict[str, Any]]:
        """Get incidents with optional filtering.

        Args:
            status: Filter by status (new, investigating, confirmed, resolved).
            ip: Filter by IP address.
            min_severity: Minimum severity to include.
            active_only: Only return active incidents.
            limit: Maximum number of incidents to return.

        Returns:
            List of incident dicts.
        """
        min_rank = SEVERITY_RANK.get(min_severity, 0)

        with self._lock:
            result = []
            for inc in self._incidents.values():
                if active_only and not inc.is_active:
                    continue
                if status and inc.status != status:
                    continue
                if ip and inc.ip != ip:
                    continue
                if SEVERITY_RANK.get(inc.severity, 0) < min_rank:
                    continue
                result.append(inc.to_dict())

        result.sort(
            key=lambda i: (SEVERITY_RANK.get(i["severity"], 0), i["last_seen"]),
            reverse=True,
        )
        return result[:limit]

    def get_incident(self, inc_id: str) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        record = self._incidents.get(inc_id)
        if record:
            return record.to_dict()

        # Fallback: query from DB if not in memory
        if self.db:
            return self._load_incident_from_db(inc_id)

        return None

    # ── Auto-resolution ──────────────────────────────────────────────

    def auto_resolve_stale(self) -> int:
        """Auto-resolve incidents without new signals for the timeout window.

        Returns:
            Number of incidents auto-resolved.
        """
        now = time.time()
        resolved_ids = []

        with self._lock:
            for record in self._incidents.values():
                if (record.is_active and
                    record.status not in INCIDENT_TERMINAL_STATES and
                    (now - record.last_seen) > self.auto_resolve_after):
                    record.is_active = False
                    record.auto_resolved = True
                    record.resolved_at = now
                    record.status = INCIDENT_RESOLVED
                    resolved_ids.append(record.id)
                    self._total_resolved += 1

        for inc_id in resolved_ids:
            self._persist_status(inc_id, INCIDENT_RESOLVED, "auto-resolved: no new signals")

        if resolved_ids:
            logger.info("Auto-resolved %d stale incidents", len(resolved_ids))

        return len(resolved_ids)

    # ── Stats ────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get incident manager statistics."""
        with self._lock:
            by_status: Dict[str, int] = defaultdict(int)
            by_severity: Dict[str, int] = defaultdict(int)

            for inc in self._incidents.values():
                by_status[inc.status] += 1
                by_severity[inc.severity] += 1

            return {
                "total_created": self._total_created,
                "total_resolved": self._total_resolved,
                "total_feedback": self._total_feedback,
                "total_confirmed": self._total_confirmed,
                "total_dismissed": self._total_dismissed,
                "active_incidents": sum(1 for i in self._incidents.values() if i.is_active),
                "by_status": dict(by_status),
                "by_severity": dict(by_severity),
                "groups_count": len(self._groups),
                "registry_size": len(self._incidents),
            }

    # ── Callbacks ────────────────────────────────────────────────────

    def on_incident_event(self, callback: Callable[[Dict[str, Any]], None]):
        """Register callback for incident events (created, transition, feedback)."""
        self._callbacks.append(callback)

    # ── Internal methods ──────────────────────────────────────────────

    def _notify_behavioral_engine(self, ip: str, signal_types: List[str],
                                   action: str, reason: str = "") -> None:
        """Forward feedback to UnifiedBehavioralEngine for baseline adjustment.

        Args:
            ip: The IP address involved.
            signal_types: Signal types associated with the incident.
            action: 'confirm' or 'dismiss'.
            reason: Optional reason.
        """
        if not self.behavioral_engine:
            logger.debug(
                "No behavioral engine configured — feedback for %s not forwarded",
                ip,
            )
            return

        try:
            if action == "confirm":
                self.behavioral_engine.record_true_positive(
                    ip, signal_types or None, notes=reason or None
                )
            elif action == "dismiss":
                self.behavioral_engine.record_false_positive(
                    ip, signal_types or None, notes=reason or None
                )
        except Exception as e:
            logger.error(
                "Failed to forward %s feedback to behavioral engine for %s: %s",
                action, ip, e,
            )

    def _persist_dismissal_reason(self, inc_id: str, reason: str) -> None:
        """Persist dismissal reason to the incidents table."""
        if not self.db:
            return

        with self._lock:
            record = self._incidents.get(inc_id)

        if not record or not record.db_id:
            return

        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    "UPDATE incidents SET dismissal_reason = %s WHERE id = %s",
                    (reason, record.db_id),
                )
                conn.commit()
            except Exception as e:
                logger.warning(
                    "Failed to persist dismissal reason for %s: %s", inc_id, e
                )
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("DB connection error persisting dismissal: %s", e)

    def _notify(self, event: Dict[str, Any]):
        """Notify all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error("Incident callback error: %s", e)

    def _get_db_id_for_ip(self, ip: str) -> int:
        """Query DB for the db_id of the active incident for this IP."""
        if not self.db:
            return 0
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT id FROM incidents WHERE ip = %s AND is_active = TRUE ORDER BY id DESC LIMIT 1",
                    (ip,),
                )
                row = cur.fetchone()
                return row[0] if row else 0
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to get DB id for incident IP %s: %s", ip, e)
            return 0

    def _persist_status(self, inc_id: str, status: str, reason: str = ""):
        """Persist status change to the incidents table."""
        if not self.db:
            return

        with self._lock:
            record = self._incidents.get(inc_id)

        if not record or not record.db_id:
            return

        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """UPDATE incidents SET
                       is_active = %s, resolved_at = CASE WHEN %s IN ('resolved', 'false_positive') THEN NOW() ELSE resolved_at END
                       WHERE id = %s""",
                    (status not in INCIDENT_TERMINAL_STATES, status, record.db_id),
                )
                conn.commit()
            except Exception as e:
                logger.warning("Failed to persist status for %s: %s", inc_id, e)
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("DB connection error persisting status: %s", e)

    def _persist_feedback(self, inc_id: str, feedback_type: str,
                          notes: str, user_id: str, score: float):
        """Persist feedback to the incident_feedback table."""
        if not self.db:
            return

        with self._lock:
            record = self._incidents.get(inc_id)

        if not record or not record.db_id:
            return

        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT INTO incident_feedback
                       (incident_id, feedback_type, confidence, notes)
                       VALUES (%s, %s, %s, %s)""",
                    (record.db_id, feedback_type, score, notes or ""),
                )
                conn.commit()
            except Exception as e:
                logger.warning("Failed to persist feedback for %s: %s", inc_id, e)
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("DB connection error persisting feedback: %s", e)

    def _try_group_incident(self, record: IncidentRecord):
        """Try to add an incident to an existing group or create a new one."""
        ip = record.ip
        now = time.time()

        with self._lock:
            # Find existing active group for this IP
            target_group = None
            for group in self._groups.values():
                if (group.ip == ip and
                    group.resolved_at is None and
                    (now - group.created_at) < self.grouping_window):
                    target_group = group
                    break

            if target_group:
                target_group.add_incident(record)
                record.group_id = target_group.group_id
                logger.debug("Added incident %s to existing group %d", record.id, target_group.group_id)
            else:
                # Create new group
                group_id = self._get_next_group_id()
                new_group = IncidentGroup(group_id, ip)
                new_group.add_incident(record)
                self._groups[group_id] = new_group
                record.group_id = group_id

                # Persist group to DB
                self._persist_group(new_group)
                logger.debug("Created new incident group %d for IP %s", group_id, ip)

    def _get_next_group_id(self) -> int:
        """Get the next group ID from the DB."""
        if not self.db:
            return int(time.time())
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM incident_groups")
                result = cur.fetchone()
                return result[0] if result else 1
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to get next group ID: %s", e)
            return int(time.time())

    def _persist_group(self, group: IncidentGroup):
        """Persist incident group to DB."""
        if not self.db:
            return
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                # Convert incident IDs to db_ids for storage
                db_ids = []
                with self._lock:
                    for inc_id in group.incident_ids:
                        rec = self._incidents.get(inc_id)
                        if rec and rec.db_id:
                            db_ids.append(rec.db_id)

                cur.execute(
                    """INSERT INTO incident_groups (ip, incident_ids)
                       VALUES (%s, %s)""",
                    (group.ip, db_ids if db_ids else '{}'),
                )
                conn.commit()
            except Exception as e:
                logger.warning("Failed to persist group %d: %s", group.group_id, e)
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("DB connection error persisting group: %s", e)

    def _load_incident_from_db(self, inc_id: str) -> Optional[Dict[str, Any]]:
        """Load incident from DB when not in memory."""
        if not self.db:
            return None
        try:
            conn = self.db.connect()
            cur = conn.cursor()
            try:
                cur.execute(
                    """SELECT id, ip, severity, signal_count, signal_types,
                              sources, phases, first_seen, last_seen, description,
                              metadata, is_active, auto_resolved, resolved_at
                       FROM incidents WHERE ip = %s ORDER BY id DESC LIMIT 1""",
                    (inc_id.replace("inc_", ""),),
                )
                row = cur.fetchone()
                if not row:
                    return None

                return {
                    "id": f"inc_{row[1]}",
                    "db_id": row[0],
                    "ip": row[1],
                    "severity": row[2],
                    "status": INCIDENT_RESOLVED if not row[11] else INCIDENT_NEW,
                    "signal_count": row[3],
                    "signal_types": row[4] or [],
                    "sources": row[5] or [],
                    "phases": row[6] or [],
                    "first_seen": row[7].timestamp() if row[7] else time.time(),
                    "last_seen": row[8].timestamp() if row[8] else time.time(),
                    "description": row[9] or "",
                    "metadata": json.loads(row[10]) if row[10] else {},
                    "is_active": row[11],
                    "auto_resolved": row[12] or False,
                }
            finally:
                cur.close()
                self.db.putconn(conn)
        except Exception as e:
            logger.warning("Failed to load incident from DB: %s", e)
            return None
