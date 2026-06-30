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


# ============================================================
# Redis Stream push tests
# ============================================================

class TestRedisStreamConfig:
    """Test REDIS_STREAM_ENABLED configuration parsing."""

    def test_redis_stream_disabled_by_default(self):
        """REDIS_STREAM_ENABLED defaults to false."""
        import syslog_listener as sl
        # Module-level value depends on env at import time.
        # In test env it should be false (no env var set).
        env_val = os.getenv("REDIS_STREAM_ENABLED", "false")
        expected = env_val.lower() in ("true", "1", "yes")
        assert sl.REDIS_STREAM_ENABLED == expected

    def test_redis_stream_name_default(self):
        """REDIS_STREAM_NAME defaults to 'event_ingest'."""
        import syslog_listener as sl
        assert sl.REDIS_STREAM_NAME == "event_ingest"

    def test_redis_url_default(self):
        """REDIS_URL defaults to redis://redis:6379/0."""
        import syslog_listener as sl
        assert sl.REDIS_URL == "redis://redis:6379/0"


class TestRedisStreamPush:
    """Test push_to_redis_stream with mocked Redis client."""

    def test_push_to_redis_stream_success(self):
        """Successful XADD pushes event JSON to stream."""
        import syslog_listener as sl
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_client.xadd.return_value = "1782793000000-0"

        # Force Redis available
        with patch.object(sl, "_get_redis_client", return_value=mock_client):
            event = {
                "timestamp": "2026-06-29T12:00:00",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "action": "block",
            }
            result = sl.push_to_redis_stream(event)
            assert result is True

            # Verify XADD was called with correct args
            mock_client.xadd.assert_called_once()
            call_args = mock_client.xadd.call_args
            assert call_args[0][0] == sl.REDIS_STREAM_NAME
            # Second arg is {"event": json_string}
            payload = call_args[0][1]
            assert "event" in payload
            imported_json = __import__("json")
            parsed = imported_json.loads(payload["event"])
            assert parsed["src_ip"] == "10.0.0.1"
            assert parsed["action"] == "block"

    def test_push_to_redis_stream_client_none(self):
        """When Redis client is None, push returns False immediately."""
        import syslog_listener as sl
        from unittest.mock import patch

        with patch.object(sl, "_get_redis_client", return_value=None):
            result = sl.push_to_redis_stream({"action": "block"})
            assert result is False

    def test_push_to_redis_stream_xadd_failure(self):
        """When XADD raises, push returns False and marks redis unavailable."""
        import syslog_listener as sl
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_client.xadd.side_effect = Exception("connection lost")

        old_available = sl._redis_available
        old_client = sl._redis_client
        try:
            sl._redis_available = True
            sl._redis_client = mock_client

            with patch.object(sl, "_get_redis_client", return_value=mock_client):
                result = sl.push_to_redis_stream({"action": "block"})
                assert result is False

                # After failure, redis is marked unavailable
                assert sl._redis_available is False
                assert sl._redis_client is None
        finally:
            sl._redis_available = old_available
            sl._redis_client = old_client


class TestRedisClientInit:
    """Test lazy Redis client initialization."""

    def test_get_redis_client_disabled(self):
        """_get_redis_client returns None when REDIS_STREAM_ENABLED is false."""
        import syslog_listener as sl
        from unittest.mock import patch

        with patch.object(sl, "REDIS_STREAM_ENABLED", False):
            result = sl._get_redis_client()
            assert result is None

    def test_get_redis_client_import_error(self):
        """_get_redis_client returns None when redis module not available."""
        import syslog_listener as sl
        from unittest.mock import patch

        with patch.object(sl, "REDIS_STREAM_ENABLED", True):
            with patch.dict(sys.modules, {"redis": None}):
                # Reset state
                old_available = sl._redis_available
                old_client = sl._redis_client
                try:
                    sl._redis_available = False
                    sl._redis_client = None

                    result = sl._get_redis_client()
                    assert result is None
                    assert sl._redis_available is False
                finally:
                    sl._redis_available = old_available
                    sl._redis_client = old_client

    def test_get_redis_client_cached(self):
        """Second call returns cached client without re-connecting."""
        import syslog_listener as sl
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_client.ping.return_value = True

        call_count = 0
        def fake_from_url(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return mock_client

        with patch.object(sl, "REDIS_STREAM_ENABLED", True):
            with patch.dict(sys.modules, {"redis": MagicMock(from_url=fake_from_url)}):
                # Reset
                old_available = sl._redis_available
                old_client = sl._redis_client
                try:
                    sl._redis_available = False
                    sl._redis_client = None

                    # First call initializes
                    result1 = sl._get_redis_client()
                    assert call_count == 1

                    # Second call returns cached
                    result2 = sl._get_redis_client()
                    assert call_count == 1  # No re-initialization
                    assert result1 is result2
                finally:
                    sl._redis_available = old_available
                    sl._redis_client = old_client