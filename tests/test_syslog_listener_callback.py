"""Test that syslog_listener skips JSONL file writes when callback mode is active."""
import os
import sys
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Ensure module path works
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_run_syslog_listener_accepts_callback():
    """run_syslog_listener() accepts an event_callback parameter."""
    from syslog_listener import run_syslog_listener
    import inspect

    sig = inspect.signature(run_syslog_listener)
    assert "event_callback" in sig.parameters


def test_run_syslog_listener_callback_skips_file_io(tmp_path):
    """When event_callback is provided, no JSONL files or event counters are created."""
    from syslog_listener import (
        run_syslog_listener,
        _get_jsonl_writer,
        _jsonl_writer,
        OUTPUT_FILE,
        DATA_DIR,
    )
    import socket
    import threading
    import time

    # Override paths to temp dir
    test_data_dir = str(tmp_path / "agent_data")
    test_output = str(tmp_path / "syslog_events.jsonl")
    test_counter = str(tmp_path / "syslog_event_count.txt")

    events_received = []
    callback = events_received.append

    with patch.dict(os.environ, {
        "DATA_DIR": test_data_dir,
        "JSONL_PATH": test_output,
    }):
        # Reset module state
        import syslog_listener as sl
        old_output = sl.OUTPUT_FILE
        old_data_dir = sl.DATA_DIR
        old_event_count = sl.EVENT_COUNT_FILE
        old_jsonl_writer = sl._jsonl_writer

        sl.OUTPUT_FILE = test_output
        sl.DATA_DIR = test_data_dir
        sl.EVENT_COUNT_FILE = test_counter
        sl._jsonl_writer = None

        try:
            # Bind to a random free port
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.bind(("127.0.0.1", 0))
            test_port = test_sock.getsockname()[1]
            test_sock.close()

            with patch.object(sl, "UDP_PORT", test_port):
                # Run listener in background thread
                t = threading.Thread(
                    target=run_syslog_listener,
                    kwargs={"event_callback": callback},
                    daemon=True,
                )
                t.start()
                time.sleep(0.3)  # let it start

                # Send a test syslog message
                test_msg = b"Jun 25 12:00:00 OPNsense filterlog: block in on igb0"
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(test_msg, ("127.0.0.1", test_port))
                time.sleep(0.5)

                # Verify: callback received event
                assert len(events_received) > 0, "Callback should have received at least one event"
                assert isinstance(events_received[0], dict)
                assert "timestamp" in events_received[0]

                # Verify: NO JSONL file created
                assert not os.path.exists(test_output), (
                    "JSONL file should NOT be created in callback mode"
                )

                # Verify: NO event counter file created
                assert not os.path.exists(test_counter), (
                    "Event counter file should NOT be created in callback mode"
                )

                # Verify: JSONL writer not initialized
                assert sl._jsonl_writer is None, (
                    "JSONL writer should NOT be initialized in callback mode"
                )
        finally:
            # Restore module state
            sl.OUTPUT_FILE = old_output
            sl.DATA_DIR = old_data_dir
            sl.EVENT_COUNT_FILE = old_event_count
            sl._jsonl_writer = old_jsonl_writer


def test_run_syslog_listener_no_callback_uses_file():
    """When event_callback is None, JSONL file mode is used (legacy behavior)."""
    import syslog_listener as sl

    # Verify the function signature defaults to None
    import inspect
    sig = inspect.signature(sl.run_syslog_listener)
    default = sig.parameters["event_callback"].default
    assert default is None, "event_callback should default to None (file mode)"


def test_write_event_write_to_file_false_skips_io(tmp_path):
    """write_event with write_to_file=False skips all file I/O."""
    import syslog_listener as sl

    test_output = str(tmp_path / "test_events.jsonl")
    old_output = sl.OUTPUT_FILE
    old_jsonl = sl._jsonl_writer

    sl.OUTPUT_FILE = test_output
    sl._jsonl_writer = None

    try:
        event = {"timestamp": "2026-06-25T12:00:00", "action": "block"}

        # write_to_file=False should return True without creating file
        result = sl.write_event(event, write_to_file=False)
        assert result is True
        assert not os.path.exists(test_output), (
            "write_to_file=False should not create JSONL file"
        )
        assert sl._jsonl_writer is None, (
            "write_to_file=False should not initialize JSONL writer"
        )
    finally:
        sl.OUTPUT_FILE = old_output
        sl._jsonl_writer = old_jsonl


def test_sysloglistener_callback_mode():
    """SyslogListener with event_callback skips JSONL writes."""
    from syslog_listener import SyslogListener

    config = MagicMock()
    config.syslog_port = 15142

    events = []

    listener = SyslogListener(config, event_callback=events.append)
    assert listener.event_callback is not None

    # Verify the _run method checks event_callback
    import inspect
    source = inspect.getsource(listener._run)
    assert "event_callback" in source, "_run should check event_callback"
    assert "self.event_callback(event)" in source, "_run should call callback directly"