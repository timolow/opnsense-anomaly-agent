#!/usr/bin/env python3
"""
Drain mode for zero-downtime deployments.

Standalone module so it can be imported without pulling in psycopg2 / eventdb.
Server.py re-exports these symbols for backward compat.
"""

import threading
import time
import logging

logger = logging.getLogger(__name__)

_drain_mode = False
_active_requests = 0
_active_requests_lock = threading.Lock()
_drained_event = threading.Event()
_drain_initiated_at: float = 0.0
_MAX_DRAIN_WAIT = 30


def enter_drain_mode() -> None:
    """Signal the server to stop accepting new requests and drain in-flight ones."""
    global _drain_mode, _drain_initiated_at
    _drain_mode = True
    _drain_initiated_at = time.time()
    logger.info("Drain mode entered — refusing new requests, waiting for %d in-flight...", _active_requests)


def is_draining() -> bool:
    """Check if the server is in drain mode."""
    return _drain_mode


def get_active_request_count() -> int:
    """Return the current number of active requests."""
    return _active_requests


def wait_for_drain(timeout: float = _MAX_DRAIN_WAIT) -> bool:
    """Block until all in-flight requests complete or timeout.

    Returns True if drained successfully, False if timed out.
    """
    if _active_requests == 0:
        _drained_event.set()
        return True
    logger.info("Waiting up to %.0fs for %d requests to drain...", timeout, _active_requests)
    drained = _drained_event.wait(timeout=timeout)
    if not drained:
        logger.warning("Drain timeout after %.0fs — %d requests still active", timeout, _active_requests)
    return drained


def graceful_shutdown(timeout: float = _MAX_DRAIN_WAIT) -> None:
    """Enter drain mode, wait for requests to complete, then signal caller to stop server.

    Call this from a signal handler or from agent.py during shutdown.
    """
    global _drain_mode
    if _drain_mode:
        logger.info("Drain already in progress")
        return
    logger.info("Graceful shutdown initiated")
    enter_drain_mode()
    wait_for_drain(timeout=timeout)
    logger.info("Graceful shutdown complete")


def _request_enter():
    """Called at the start of request handling."""
    global _active_requests
    with _active_requests_lock:
        _active_requests += 1


def _request_exit():
    """Called at the end of request handling."""
    global _active_requests
    with _active_requests_lock:
        _active_requests -= 1
        if _drain_mode and _active_requests <= 0:
            _active_requests = max(0, _active_requests)
            _drained_event.set()


def reset_drain_state():
    """Reset all drain state. Useful for tests."""
    global _drain_mode, _active_requests, _drain_initiated_at
    _drain_mode = False
    _active_requests = 0
    _drain_initiated_at = 0.0
    _drained_event.clear()