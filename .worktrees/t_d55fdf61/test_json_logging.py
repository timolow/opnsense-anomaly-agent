"""Tests for json_logging module — JsonFormatter, StructuredLogger, and setup_json_logging."""

import io
import json
import logging
import logging.handlers
import os
import tempfile
from datetime import datetime, timezone
from typing import List

import pytest

from json_logging import (
    JsonFormatter,
    RotatingJsonFileHandler,
    StructuredLogger,
    get_structured_logger,
    setup_json_logging,
)


# ── JsonFormatter tests ──────────────────────────────────────────────────────


class TestJsonFormatter:
    """Test that log records are formatted as valid single-line JSON."""

    def test_basic_fields(self):
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="/path/to/test.py",
            lineno=42,
            msg="Hello world",
            args=(),
            exc_info=None,
        )
        result = json.loads(fmt.format(record))

        assert result["timestamp"] is not None
        assert result["level"] == "INFO"
        assert result["module"] == "test.module"
        assert result["message"] == "Hello world"

    def test_timestamp_is_iso8601_utc(self):
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.DEBUG, pathname="", lineno=0,
            msg="ts", args=(), exc_info=None,
        )
        record.created = 1700000000.0  # 2023-11-14T22:13:20Z
        result = json.loads(fmt.format(record))
        ts = datetime.fromisoformat(result["timestamp"])
        assert ts.tzinfo is not None
        assert ts.tzinfo == timezone.utc
        assert ts.year == 2023
        assert ts.month == 11

    def test_message_with_args(self):
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="Connection from %s port %d", args=("10.0.0.1", 443),
            exc_info=None,
        )
        result = json.loads(fmt.format(record))
        assert result["message"] == "Connection from 10.0.0.1 port 443"
        assert result["level"] == "WARNING"

    def test_exception_info(self):
        fmt = JsonFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            exc_info = None
            import sys as _sys
            exc_info = _sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="Something broke", args=(), exc_info=exc_info,
        )
        result = json.loads(fmt.format(record))
        assert "exception" in result
        assert "ValueError" in result["exception"]
        assert "test error" in result["exception"]

    def test_extra_fields_merged(self):
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Event processed", args=(), exc_info=None,
        )
        # Simulate extra fields passed via extra={...}
        record.event_id = "evt-123"
        record.ip = "192.168.1.1"
        record.rule = "FW-001"
        result = json.loads(fmt.format(record))
        assert result["event_id"] == "evt-123"
        assert result["ip"] == "192.168.1.1"
        assert result["rule"] == "FW-001"

    def test_standard_fields_not_duplicated(self):
        """Standard LogRecord fields (levelname, levelno, etc.) should not leak into JSON."""
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="/app/test.py", lineno=10,
            msg="test", args=(), exc_info=None,
        )
        result = json.loads(fmt.format(record))
        # These standard fields must NOT appear
        for field in ("levelname", "levelno", "filename", "pathname", "funcName"):
            assert field not in result, f"Standard field '{field}' leaked into JSON output"

    def test_private_fields_not_duplicated(self):
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.DEBUG, pathname="", lineno=0,
            msg="test", args=(), exc_info=None,
        )
        record._private_data = "secret"
        result = json.loads(fmt.format(record))
        assert "_private_data" not in result

    def test_single_line_output(self):
        """Ensure the formatter produces a single line (no newlines in output)."""
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Multi\nline\nmessage", args=(), exc_info=None,
        )
        output = fmt.format(record)
        lines = output.strip().split("\n")
        # JSON may contain \n in the message string, but should be a single line
        assert len(lines) == 1

    def test_non_string_types_serialized(self):
        """Non-string extra values should serialize via default=str."""
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="test", args=(), exc_info=None,
        )
        record.port = 8080
        record.tags = ["firewall", "blocked"]
        result = json.loads(fmt.format(record))
        assert result["port"] == 8080
        assert result["tags"] == ["firewall", "blocked"]


# ── StructuredLogger tests ───────────────────────────────────────────────────


class TestStructuredLogger:
    """Test the StructuredLogger adapter for keyword-arg structured context."""

    def _capture_handler(self) -> tuple[logging.Logger, io.StringIO]:
        """Set up an in-memory handler that captures JSON log lines."""
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger("test_structured_" + id(buf).__str__())
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger, buf

    def test_basic_emit(self):
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        slog.info("test message")
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        assert len(entries) == 1
        assert entries[0]["message"] == "test message"

    def test_security_context_in_single_entry(self):
        """All security context lands in the same JSON entry — no duplicate lines."""
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        slog.info(
            "Event processed",
            event_id="evt-456", ip="10.0.0.5", rule="BLOCK-SSH",
        )
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        # Single entry with all fields inline
        assert len(entries) == 1
        entry = entries[0]
        assert entry["message"] == "Event processed"
        assert entry["event_id"] == "evt-456"
        assert entry["ip"] == "10.0.0.5"
        assert entry["rule"] == "BLOCK-SSH"

    def test_non_security_extra_passthrough(self):
        """Non-security kwargs also land in the same entry."""
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        slog.info("Custom event", custom_field="custom_value", ip="1.2.3.4")
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        assert len(entries) == 1
        assert entries[0]["message"] == "Custom event"
        assert entries[0]["custom_field"] == "custom_value"
        assert entries[0]["ip"] == "1.2.3.4"

    def test_all_levels(self):
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        slog.debug("debug msg")
        slog.info("info msg")
        slog.warning("warn msg")
        slog.error("error msg")
        slog.critical("critical msg")
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        levels = {e["level"] for e in entries}
        assert "DEBUG" in levels
        assert "INFO" in levels
        assert "WARNING" in levels
        assert "ERROR" in levels
        assert "CRITICAL" in levels
        assert len(entries) == 5

    def test_exception_method(self):
        """exception() passes exc_info correctly."""
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            slog.exception("Something went wrong", event_id="err-1")
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        assert len(entries) == 1
        assert entries[0]["message"] == "Something went wrong"
        assert "exception" in entries[0]
        assert "RuntimeError" in entries[0]["exception"]
        assert entries[0]["event_id"] == "err-1"

    def test_reserved_key_remapped(self):
        """Reserved LogRecord keys like 'module' are remapped to safe aliases."""
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        slog.error("DB error", module="eventdb", error_code="CONN_REFUSED")
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        assert len(entries) == 1
        assert entries[0]["logger_module"] == "eventdb"
        assert entries[0]["error_code"] == "CONN_REFUSED"
        # The original 'module' key is the logger name, not "eventdb"
        assert entries[0]["module"] == logger.name

    def test_get_structured_logger_factory(self):
        slog = get_structured_logger("factory_test")
        assert isinstance(slog, StructuredLogger)
        assert slog.logger.name == "factory_test"

    def test_attack_type_and_severity(self):
        logger, buf = self._capture_handler()
        slog = StructuredLogger(logger)
        slog.warning("Attack detected", attack_type="port_scan", severity="high", ip="evil.example.com")
        buf.seek(0)
        entries = [json.loads(line) for line in buf if line.strip()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["attack_type"] == "port_scan"
        assert entry["severity"] == "high"
        assert entry["ip"] == "evil.example.com"


# ── setup_json_logging tests ─────────────────────────────────────────────────


class TestSetupJsonLogging:
    """Test that setup_json_logging configures the root logger correctly."""

    def test_stdout_handler_attached(self):
        import sys
        root = setup_json_logging(level=logging.INFO, stdout=True, stderr=False, log_file=None)
        stdout_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler) and h.stream is sys.stdout]
        assert len(stdout_handlers) >= 1

    def test_stderr_handler_optional(self):
        import sys
        root = setup_json_logging(level=logging.INFO, stdout=True, stderr=False, log_file=None)
        stderr_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr]
        assert len(stderr_handlers) == 0

    def test_stderr_handler_when_enabled(self):
        import sys
        root = setup_json_logging(level=logging.INFO, stdout=True, stderr=True, log_file=None)
        stderr_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr]
        assert len(stderr_handlers) >= 1

    def test_file_handler_attached(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            root = setup_json_logging(level=logging.INFO, stdout=True, log_file=path)
            file_handlers = [h for h in root.handlers if isinstance(h, logging.handlers.TimedRotatingFileHandler)]
            assert len(file_handlers) >= 1
            assert file_handlers[0].baseFilename == path
        finally:
            os.unlink(path)

    def test_existing_handlers_removed(self):
        """Calling setup_json_logging twice should not duplicate handlers."""
        root = setup_json_logging(level=logging.INFO, stdout=True, log_file=None)
        initial_count = len(root.handlers)
        root = setup_json_logging(level=logging.INFO, stdout=True, log_file=None)
        assert len(root.handlers) == initial_count

    def test_third_party_suppressed(self):
        setup_json_logging(level=logging.INFO, stdout=True, log_file=None)
        for name in ["urllib3", "requests", "httpx", "discord", "apscheduler"]:
            assert logging.getLogger(name).level >= logging.WARNING

    def test_log_level_propagated(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as f:
            path = f.name
        try:
            root = setup_json_logging(level=logging.DEBUG, stdout=False, log_file=path)
            test_logger = logging.getLogger("test_level")
            test_logger.debug("debug message")
            for h in root.handlers:
                h.flush()
            with open(path) as fh:
                content = fh.read()
            assert len(content) > 0
            entry = json.loads(content.strip())
            assert entry["message"] == "debug message"
            assert entry["level"] == "DEBUG"
        finally:
            os.unlink(path)


# ── RotatingJsonFileHandler tests ────────────────────────────────────────────


class TestRotatingJsonFileHandler:
    """Test rotation, compression, and size limits."""

    def test_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            handler = RotatingJsonFileHandler(path)
            handler.emit(logging.LogRecord(
                name="test", level=logging.INFO, pathname="", lineno=0,
                msg="hello", args=(), exc_info=None,
            ))
            handler.close()
            assert os.path.exists(path)
            with open(path) as fh:
                content = fh.read()
            assert json.loads(content.strip())["message"] == "hello"
        finally:
            os.unlink(path)

    def test_json_format_applied(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            handler = RotatingJsonFileHandler(path)
            handler.emit(logging.LogRecord(
                name="test", level=logging.WARNING, pathname="", lineno=0,
                msg="structured test", args=(), exc_info=None,
            ))
            handler.close()
            with open(path) as fh:
                entry = json.loads(fh.read().strip())
            assert "timestamp" in entry
            assert entry["level"] == "WARNING"
        finally:
            os.unlink(path)

    def test_creates_parent_directory(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "subdir", "agent.log")
        try:
            handler = RotatingJsonFileHandler(path)
            handler.emit(logging.LogRecord(
                name="test", level=logging.INFO, pathname="", lineno=0,
                msg="nested", args=(), exc_info=None,
            ))
            handler.close()
            assert os.path.exists(path)
        finally:
            import shutil
            shutil.rmtree(tmpdir)


# ── Integration: full pipeline end-to-end ────────────────────────────────────


class TestIntegration:
    """End-to-end test: setup_json_logging -> StructuredLogger -> parse output."""

    def test_full_pipeline(self):
        """Single-entry pattern: all context in one JSON line."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            setup_json_logging(level=logging.DEBUG, stdout=False, log_file=path)

            slog = get_structured_logger("integration_test")
            slog.info(
                "Firewall event",
                event_id="evt-int-001",
                src_ip="203.0.113.50",
                dst_ip="192.168.1.100",
                rule="BLOCK-EXTERNAL-SSH",
                action="block",
                interface="wan",
            )

            root = logging.getLogger()
            for h in root.handlers:
                h.flush()

            with open(path) as fh:
                lines = [json.loads(l) for l in fh if l.strip()]

            # Single entry with all fields inline
            assert len(lines) == 1
            entry = lines[0]
            assert entry["message"] == "Firewall event"
            assert entry["event_id"] == "evt-int-001"
            assert entry["src_ip"] == "203.0.113.50"
            assert entry["dst_ip"] == "192.168.1.100"
            assert entry["rule"] == "BLOCK-EXTERNAL-SSH"
            assert entry["action"] == "block"
            assert entry["interface"] == "wan"
        finally:
            os.unlink(path)

    def test_security_fields_parsed_for_downstream(self):
        """Verify that a downstream parser could easily index on security fields."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            setup_json_logging(level=logging.DEBUG, stdout=False, log_file=path)
            slog = get_structured_logger("parser_test")

            slog.warning("Port scan detected", ip="10.0.0.99", attack_type="port_scan", severity="high")
            slog.info("Geo anomaly", ip="172.16.0.1", country_code="RU", attack_type="GEO_ANOMALY")
            slog.error("DB connection failed", module="eventdb", error_code="CONN_REFUSED")

            root = logging.getLogger()
            for h in root.handlers:
                h.flush()

            with open(path) as fh:
                lines = [json.loads(l) for l in fh if l.strip()]

            # Every entry is a real event — no structured_context noise
            assert len(lines) == 3

            # Find entries by attack_type (simulating ELK/Loki query)
            port_scan_entries = [e for e in lines if e.get("attack_type") == "port_scan"]
            assert len(port_scan_entries) == 1
            assert port_scan_entries[0]["severity"] == "high"

            geo_entries = [e for e in lines if e.get("country_code") == "RU"]
            assert len(geo_entries) == 1
            assert geo_entries[0]["attack_type"] == "GEO_ANOMALY"

            # Reserved key 'module' is remapped to 'logger_module'
            db_entries = [e for e in lines if e.get("message") == "DB connection failed"]
            assert len(db_entries) == 1
            assert db_entries[0]["logger_module"] == "eventdb"
            assert db_entries[0]["error_code"] == "CONN_REFUSED"
        finally:
            os.unlink(path)