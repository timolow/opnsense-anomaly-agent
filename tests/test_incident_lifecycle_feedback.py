#!/usr/bin/env python3
"""Tests for P4-T5: Incident lifecycle with feedback integration.

Verifies that:
- FALSE_POSITIVE state exists and is a valid terminal state
- VALID_TRANSITIONS allow NEW/INVESTIGATING -> FALSE_POSITIVE
- confirm_incident() transitions to CONFIRMED, records thumbs_up, notifies behavioral engine
- dismiss_incident() transitions to FALSE_POSITIVE, records thumbs_down, notifies behavioral engine
- Behavioral engine receives record_true_positive / record_false_positive calls
- Dismissal reason is persisted to DB
- get_stats() includes total_confirmed and total_dismissed
- Auto-resolution skips incidents already in terminal states (resolved OR false_positive)
- Discord command handlers for incident-confirm and incident-dismiss
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

from incident_manager import (
    IncidentManager,
    IncidentRecord,
    INCIDENT_NEW,
    INCIDENT_INVESTIGATING,
    INCIDENT_CONFIRMED,
    INCIDENT_RESOLVED,
    INCIDENT_FALSE_POSITIVE,
    INCIDENT_STATES,
    INCIDENT_TERMINAL_STATES,
    VALID_TRANSITIONS,
    FEEDBACK_THUMBS_UP,
    FEEDBACK_THUMBS_DOWN,
)


class TestIncidentLifecycleStates:
    """Test lifecycle state constants and transitions."""

    def test_false_positive_is_in_states(self):
        """FALSE_POSITIVE is a valid incident state."""
        assert INCIDENT_FALSE_POSITIVE in INCIDENT_STATES
        assert INCIDENT_FALSE_POSITIVE == "false_positive"

    def test_terminal_states_include_false_positive(self):
        """INCIDENT_TERMINAL_STATES includes both resolved and false_positive."""
        assert INCIDENT_RESOLVED in INCIDENT_TERMINAL_STATES
        assert INCIDENT_FALSE_POSITIVE in INCIDENT_TERMINAL_STATES
        assert INCIDENT_NEW not in INCIDENT_TERMINAL_STATES
        assert INCIDENT_CONFIRMED not in INCIDENT_TERMINAL_STATES

    def test_valid_transitions_from_new(self):
        """NEW can transition to INVESTIGATING, CONFIRMED, RESOLVED, or FALSE_POSITIVE."""
        new_transitions = VALID_TRANSITIONS[INCIDENT_NEW]
        assert INCIDENT_INVESTIGATING in new_transitions
        assert INCIDENT_CONFIRMED in new_transitions
        assert INCIDENT_RESOLVED in new_transitions
        assert INCIDENT_FALSE_POSITIVE in new_transitions

    def test_valid_transitions_from_investigating(self):
        """INVESTIGATING can transition to CONFIRMED, RESOLVED, or FALSE_POSITIVE."""
        inv_transitions = VALID_TRANSITIONS[INCIDENT_INVESTIGATING]
        assert INCIDENT_CONFIRMED in inv_transitions
        assert INCIDENT_RESOLVED in inv_transitions
        assert INCIDENT_FALSE_POSITIVE in inv_transitions

    def test_false_positive_is_terminal(self):
        """FALSE_POSITIVE has no outgoing transitions."""
        assert VALID_TRANSITIONS[INCIDENT_FALSE_POSITIVE] == []

    def test_confirmed_cannot_transition_to_false_positive(self):
        """CONFIRMED can only go to RESOLVED (not FALSE_POSITIVE)."""
        confirmed_transitions = VALID_TRANSITIONS[INCIDENT_CONFIRMED]
        assert INCIDENT_RESOLVED in confirmed_transitions
        assert INCIDENT_FALSE_POSITIVE not in confirmed_transitions


class TestIncidentRecordDismissalReason:
    """Test IncidentRecord dismissal_reason field."""

    def test_default_dismissal_reason_is_empty(self):
        """New records have empty dismissal_reason."""
        record = IncidentRecord(db_id=1, ip="10.0.0.1")
        assert record.dismissal_reason == ""

    def test_dismissal_reason_can_be_set(self):
        """dismissal_reason can be set explicitly."""
        record = IncidentRecord(
            db_id=1, ip="10.0.0.1", dismissal_reason="legitimate traffic"
        )
        assert record.dismissal_reason == "legitimate traffic"

    def test_to_dict_includes_dismissal_reason(self):
        """to_dict() serializes dismissal_reason."""
        record = IncidentRecord(db_id=1, ip="10.0.0.1", dismissal_reason="whitelisted")
        d = record.to_dict()
        assert "dismissal_reason" in d
        assert d["dismissal_reason"] == "whitelisted"


class TestIncidentManagerConfirm:
    """Test confirm_incident() method."""

    def _make_manager(self, behavioral_engine=None):
        db = MagicMock()
        return IncidentManager(db, behavioral_engine=behavioral_engine)

    def _make_record(self, mgr, status=INCIDENT_NEW):
        record = IncidentRecord(
            db_id=1, ip="10.0.0.1",
            signal_types=["deviation_conn_rate", "firewall_port_scan"],
        )
        record.status = status
        with mgr._lock:
            mgr._incidents[record.id] = record
        return record

    def test_confirm_transitions_to_confirmed(self):
        """confirm_incident transitions from NEW to CONFIRMED."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_NEW)

        success, msg = mgr.confirm_incident(record.id)
        assert success
        assert record.status == INCIDENT_CONFIRMED

    def test_confirm_records_thumbs_up(self):
        """confirm_incident records thumbs_up feedback."""
        mgr = self._make_manager()
        record = self._make_record(mgr)

        success, _ = mgr.confirm_incident(record.id)
        assert success
        assert record.feedback_count == 1
        assert record.feedback_score == 1.0

    def test_confirm_notifies_behavioral_engine(self):
        """confirm_incident calls record_true_positive on behavioral engine."""
        engine = MagicMock()
        mgr = self._make_manager(engine)
        record = self._make_record(mgr)

        mgr.confirm_incident(record.id)
        engine.record_true_positive.assert_called_once()
        call_args = engine.record_true_positive.call_args
        assert call_args[0][0] == "10.0.0.1"

    def test_confirm_increments_total_confirmed(self):
        """confirm_incident increments _total_confirmed counter."""
        mgr = self._make_manager()
        record = self._make_record(mgr)

        assert mgr._total_confirmed == 0
        mgr.confirm_incident(record.id)
        assert mgr._total_confirmed == 1

    def test_confirm_from_investigating(self):
        """confirm_incident works from INVESTIGATING state."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_INVESTIGATING)

        success, msg = mgr.confirm_incident(record.id)
        assert success
        assert record.status == INCIDENT_CONFIRMED

    def test_confirm_from_confirmed_fails(self):
        """Cannot confirm an already CONFIRMED incident."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_CONFIRMED)

        success, msg = mgr.confirm_incident(record.id)
        assert not success
        assert "Cannot confirm" in msg

    def test_confirm_from_resolved_fails(self):
        """Cannot confirm a RESOLVED incident."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_RESOLVED)

        success, msg = mgr.confirm_incident(record.id)
        assert not success

    def test_confirm_not_found(self):
        """confirm_incident returns error for unknown ID."""
        mgr = self._make_manager()
        success, msg = mgr.confirm_incident("inc_nonexistent")
        assert not success
        assert "not found" in msg.lower()


class TestIncidentManagerDismiss:
    """Test dismiss_incident() method."""

    def _make_manager(self, behavioral_engine=None):
        db = MagicMock()
        return IncidentManager(db, behavioral_engine=behavioral_engine)

    def _make_record(self, mgr, status=INCIDENT_NEW):
        record = IncidentRecord(
            db_id=1, ip="10.0.0.1",
            signal_types=["deviation_conn_rate"],
        )
        record.status = status
        with mgr._lock:
            mgr._incidents[record.id] = record
        return record

    def test_dismiss_transitions_to_false_positive(self):
        """dismiss_incident transitions from NEW to FALSE_POSITIVE."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_NEW)

        success, msg = mgr.dismiss_incident(record.id, "legitimate scanner")
        assert success
        assert record.status == INCIDENT_FALSE_POSITIVE

    def test_dismiss_records_thumbs_down(self):
        """dismiss_incident records thumbs_down feedback."""
        mgr = self._make_manager()
        record = self._make_record(mgr)

        success, _ = mgr.dismiss_incident(record.id)
        assert success
        assert record.feedback_count == 1
        assert record.feedback_score == 0.0

    def test_dismiss_sets_dismissal_reason(self):
        """dismiss_incident stores the reason on the record."""
        mgr = self._make_manager()
        record = self._make_record(mgr)

        mgr.dismiss_incident(record.id, "whitelisted IP")
        assert record.dismissal_reason == "whitelisted IP"

    def test_dismiss_notifies_behavioral_engine(self):
        """dismiss_incident calls record_false_positive on behavioral engine."""
        engine = MagicMock()
        mgr = self._make_manager(engine)
        record = self._make_record(mgr)

        mgr.dismiss_incident(record.id, "test")
        engine.record_false_positive.assert_called_once()
        call_args = engine.record_false_positive.call_args
        assert call_args[0][0] == "10.0.0.1"

    def test_dismiss_increments_total_dismissed(self):
        """dismiss_incident increments _total_dismissed counter."""
        mgr = self._make_manager()
        record = self._make_record(mgr)

        assert mgr._total_dismissed == 0
        mgr.dismiss_incident(record.id)
        assert mgr._total_dismissed == 1

    def test_dismiss_from_investigating(self):
        """dismiss_incident works from INVESTIGATING state."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_INVESTIGATING)

        success, msg = mgr.dismiss_incident(record.id, "verified false positive")
        assert success
        assert record.status == INCIDENT_FALSE_POSITIVE

    def test_dismiss_from_confirmed_fails(self):
        """Cannot dismiss an already CONFIRMED incident."""
        mgr = self._make_manager()
        record = self._make_record(mgr, INCIDENT_CONFIRMED)

        success, msg = mgr.dismiss_incident(record.id)
        assert not success
        assert "Cannot dismiss" in msg

    def test_dismiss_not_found(self):
        """dismiss_incident returns error for unknown ID."""
        mgr = self._make_manager()
        success, msg = mgr.dismiss_incident("inc_nonexistent")
        assert not success
        assert "not found" in msg.lower()


class TestIncidentManagerStats:
    """Test get_stats() includes new counters."""

    def test_stats_include_confirmed_and_dismissed(self):
        """get_stats() returns total_confirmed and total_dismissed."""
        mgr = IncidentManager()
        stats = mgr.get_stats()
        assert "total_confirmed" in stats
        assert "total_dismissed" in stats
        assert stats["total_confirmed"] == 0
        assert stats["total_dismissed"] == 0


class TestAutoResolveSkipsTerminalStates:
    """Test auto_resolve_stale skips FALSE_POSITIVE incidents."""

    def test_auto_resolve_skips_false_positive(self):
        """Incidents in FALSE_POSITIVE state are not auto-resolved."""
        mgr = IncidentManager(auto_resolve_after=1)
        record = IncidentRecord(
            db_id=1, ip="10.0.0.1",
            first_seen=time.time() - 100,
            last_seen=time.time() - 100,
        )
        record.status = INCIDENT_FALSE_POSITIVE
        record.is_active = False
        with mgr._lock:
            mgr._incidents[record.id] = record

        resolved = mgr.auto_resolve_stale()
        assert resolved == 0
        # Status should remain FALSE_POSITIVE, not change to RESOLVED
        assert record.status == INCIDENT_FALSE_POSITIVE


class TestDiscordCommandHandlers:
    """Test Discord command handlers for confirm/dismiss."""

    def _make_handler(self):
        from discord_bot import CommandHandler
        handler = CommandHandler()
        handler.agent = MagicMock()
        handler.agent.incident_manager = MagicMock()
        return handler

    def test_incident_confirm_handler_success(self):
        """_cmd_incident_confirm calls confirm_incident and returns success."""
        handler = self._make_handler()
        handler.agent.incident_manager.confirm_incident.return_value = (
            True, "Confirmed inc_abc123 as true positive for IP 10.0.0.1"
        )

        result = handler._cmd_incident_confirm("inc_abc123 confirmed by analyst")
        assert "✅" in result.content
        handler.agent.incident_manager.confirm_incident.assert_called_once_with(
            "inc_abc123", "confirmed by analyst"
        )

    def test_incident_confirm_handler_failure(self):
        """_cmd_incident_confirm returns ❌ on failure."""
        handler = self._make_handler()
        handler.agent.incident_manager.confirm_incident.return_value = (
            False, "Incident not found: inc_bad"
        )

        result = handler._cmd_incident_confirm("inc_bad")
        assert "❌" in result.content

    def test_incident_dismiss_handler_success(self):
        """_cmd_incident_dismiss calls dismiss_incident and returns success."""
        handler = self._make_handler()
        handler.agent.incident_manager.dismiss_incident.return_value = (
            True, "Dismissed inc_abc123 as false positive for IP 10.0.0.1"
        )

        result = handler._cmd_incident_dismiss("inc_abc123 legitimate traffic")
        assert "✅" in result.content
        handler.agent.incident_manager.dismiss_incident.assert_called_once_with(
            "inc_abc123", "legitimate traffic"
        )

    def test_incident_dismiss_handler_no_args(self):
        """_cmd_incident_dismiss returns usage on empty args."""
        handler = self._make_handler()
        result = handler._cmd_incident_dismiss("")
        assert "Usage" in result.content

    def test_incident_confirm_handler_no_args(self):
        """_cmd_incident_confirm returns usage on empty args."""
        handler = self._make_handler()
        result = handler._cmd_incident_confirm("")
        assert "Usage" in result.content

    def test_command_registration(self):
        """COMMANDS dict includes incident-confirm and incident-dismiss."""
        from discord_bot import CommandHandler
        assert "incident-confirm" in CommandHandler.COMMANDS
        assert "incident-dismiss" in CommandHandler.COMMANDS


class TestIncidentManagerBehavioralEngineNone:
    """Test that confirm/dismiss work when behavioral_engine is None."""

    def _make_manager(self):
        return IncidentManager()  # No DB, no engine

    def test_confirm_without_engine(self):
        """confirm_incident does not crash when behavioral_engine is None."""
        mgr = self._make_manager()
        record = IncidentRecord(db_id=0, ip="10.0.0.1")
        with mgr._lock:
            mgr._incidents[record.id] = record

        success, msg = mgr.confirm_incident(record.id)
        assert success

    def test_dismiss_without_engine(self):
        """dismiss_incident does not crash when behavioral_engine is None."""
        mgr = self._make_manager()
        record = IncidentRecord(db_id=0, ip="10.0.0.1")
        with mgr._lock:
            mgr._incidents[record.id] = record

        success, msg = mgr.dismiss_incident(record.id)
        assert success


class TestIncidentManagerInitWithBehavioralEngine:
    """Test IncidentManager accepts behavioral_engine parameter."""

    def test_init_with_behavioral_engine(self):
        """IncidentManager stores behavioral_engine reference."""
        engine = MagicMock()
        mgr = IncidentManager(behavioral_engine=engine)
        assert mgr.behavioral_engine is engine

    def test_init_without_behavioral_engine(self):
        """IncidentManager works with behavioral_engine=None."""
        mgr = IncidentManager()
        assert mgr.behavioral_engine is None
