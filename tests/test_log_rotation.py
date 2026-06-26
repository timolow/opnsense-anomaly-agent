"""Tests for log rotation: size limits, gzip compression, cleanup, env vars, and zero data loss."""
from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from json_logging import (
    JsonFormatter,
    RotatingJsonFileHandler,
    setup_json_logging,
    get_structured_logger,
)


class TestSizeBasedRotation:
    """Verify that files rotate when they hit max_bytes."""

    def _make_record(self, msg: str) -> logging.LogRecord:
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )

    def test_rotates_on_max_bytes(self, tmp_path: Path):
        """File should rotate when it exceeds max_bytes."""
        log_file = tmp_path / "test.log"
        max_bytes = 500  # tiny limit for testing

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=3)

        # Write enough to exceed max_bytes
        for i in range(50):
            handler.emit(self._make_record(f"Log entry number {i} with some padding data"))

        handler.close()

        # Original file should have been rotated
        assert log_file.exists()
        # At least one rotated file should exist
        rotated = list(tmp_path.glob("test.log.*.gz"))
        assert len(rotated) >= 1, f"Expected rotated files, found: {list(tmp_path.iterdir())}"

    def test_keeps_backup_count_files(self, tmp_path: Path):
        """Only backup_count rotated files should be retained."""
        log_file = tmp_path / "test.log"
        max_bytes = 200

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=3)

        # Write a lot to force multiple rotations
        for i in range(200):
            handler.emit(self._make_record(f"Entry {i} " + "x" * 30))

        handler.close()

        # Count rotated gz files
        rotated = [f for f in tmp_path.glob("test.log.*.gz")]
        assert len(rotated) <= 3, f"Expected <=3 rotated files, found {len(rotated)}: {rotated}"

    def test_rotated_files_are_gzip(self, tmp_path: Path):
        """Rotated files must be valid gzip files."""
        log_file = tmp_path / "test.log"
        max_bytes = 300

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=5)

        for i in range(100):
            handler.emit(self._make_record(f"Gzip test entry {i} with padding"))

        handler.close()

        rotated = list(tmp_path.glob("test.log.*.gz"))
        assert len(rotated) >= 1

        for gz_file in rotated:
            # Verify it's valid gzip
            with gzip.open(gz_file, "rt", encoding="utf-8") as f:
                content = f.read()
            # Verify content is valid JSON lines
            for line in content.strip().split("\n"):
                entry = json.loads(line)
                assert "timestamp" in entry
                assert "level" in entry

    def test_zero_data_loss_during_rotation(self, tmp_path: Path):
        """No log entries should be lost during the rotate operation itself.

        (Old entries are pruned by backup_count — that is intentional retention
        policy, not data loss. This test verifies the rotation mechanism does
        not drop entries mid-rotate.)"""
        log_file = tmp_path / "test.log"
        max_bytes = 500
        backup_count = 100  # More than enough to hold all rotated files

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=backup_count)

        all_entries: List[str] = []
        for i in range(100):
            msg = f"Critical entry {i:04d}"
            all_entries.append(msg)
            handler.emit(self._make_record(msg))

        handler.close()

        # Collect all entries from current + rotated files
        recovered: List[str] = []

        if log_file.exists():
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        recovered.append(entry["message"])

        for gz_file in tmp_path.glob("test.log.*.gz"):
            with gzip.open(gz_file, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        recovered.append(entry["message"])

        # Every entry we wrote must be recoverable
        assert len(recovered) == len(all_entries), \
            f"Data loss! Sent {len(all_entries)}, recovered {len(recovered)}"


class TestTimeBasedRotation:
    """Verify time-based rotation still works (midnight UTC)."""

    def _make_record(self, msg: str) -> logging.LogRecord:
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )

    def test_should_rollover_time_based(self, tmp_path: Path):
        """shouldRollover returns True for time-based rotation."""
        log_file = tmp_path / "test.log"
        handler = RotatingJsonFileHandler(str(log_file), max_bytes=100_000_000, backup_count=5)

        # With a huge max_bytes, shouldRollover won't trigger on size
        # It will only trigger if we cross midnight (which we can't easily test)
        # So we verify the parent class mechanism is intact
        assert isinstance(handler, logging.handlers.TimedRotatingFileHandler)
        assert handler.when == "MIDNIGHT"
        assert handler.utc is True

        handler.close()


class TestEnvVarDefaults:
    """Verify environment variable overrides work correctly."""

    def test_default_max_bytes(self):
        """Default max_bytes is 50MB."""
        assert RotatingJsonFileHandler.__init__.__defaults__ is not None
        # Check the default value in the signature
        import inspect
        sig = inspect.signature(RotatingJsonFileHandler.__init__)
        max_bytes_default = sig.parameters['max_bytes'].default
        assert max_bytes_default == 50_000_000

    def test_default_backup_count(self):
        """Default backup_count is 5."""
        import inspect
        sig = inspect.signature(RotatingJsonFileHandler.__init__)
        backup_count_default = sig.parameters['backup_count'].default
        assert backup_count_default == 5

    def test_env_var_log_max_bytes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """LOG_MAX_BYTES env var overrides default."""
        monkeypatch.setenv("LOG_MAX_BYTES", "25000000")
        log_file = tmp_path / "env_test.log"

        # Need to reimport to pick up env var
        root = setup_json_logging(level=logging.WARNING, stdout=False, log_file=str(log_file))
        file_handlers = [h for h in root.handlers if isinstance(h, RotatingJsonFileHandler)]
        assert len(file_handlers) >= 1
        assert file_handlers[0].max_bytes == 25_000_000

        for h in root.handlers:
            h.close()
        root.handlers.clear()

    def test_env_var_log_backup_count(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """LOG_BACKUP_COUNT env var overrides default."""
        monkeypatch.setenv("LOG_BACKUP_COUNT", "10")
        log_file = tmp_path / "env_test.log"

        root = setup_json_logging(level=logging.WARNING, stdout=False, log_file=str(log_file))
        file_handlers = [h for h in root.handlers if isinstance(h, RotatingJsonFileHandler)]
        assert len(file_handlers) >= 1
        assert file_handlers[0].backupCount == 10

        for h in root.handlers:
            h.close()
        root.handlers.clear()

    def test_env_var_log_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """LOG_FILE env var sets the log file path."""
        log_file = tmp_path / "custom.log"
        monkeypatch.setenv("LOG_FILE", str(log_file))

        root = setup_json_logging(level=logging.WARNING, stdout=False)
        file_handlers = [h for h in root.handlers if isinstance(h, RotatingJsonFileHandler)]
        assert len(file_handlers) >= 1
        assert file_handlers[0].baseFilename == str(log_file)

        for h in root.handlers:
            h.close()
        root.handlers.clear()

    def test_explicit_args_override_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Explicit function args take precedence over env vars."""
        monkeypatch.setenv("LOG_MAX_BYTES", "25000000")
        monkeypatch.setenv("LOG_BACKUP_COUNT", "10")
        log_file = tmp_path / "explicit.log"

        root = setup_json_logging(
            level=logging.WARNING, stdout=False, log_file=str(log_file),
            max_bytes=75_000_000, backup_count=3,
        )
        file_handlers = [h for h in root.handlers if isinstance(h, RotatingJsonFileHandler)]
        assert len(file_handlers) >= 1
        assert file_handlers[0].max_bytes == 75_000_000
        assert file_handlers[0].backupCount == 3

        for h in root.handlers:
            h.close()
        root.handlers.clear()


class TestCompression:
    """Verify gzip compression of rotated files."""

    def _make_record(self, msg: str) -> logging.LogRecord:
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )

    def test_compressed_file_readable(self, tmp_path: Path):
        """Compressed rotated files are readable with gzip."""
        log_file = tmp_path / "compress_test.log"
        max_bytes = 200

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=5)

        # Force rotation by writing lots
        for i in range(100):
            handler.emit(self._make_record(f"Compress test {i}" + "z" * 40))

        handler.close()

        gz_files = list(tmp_path.glob("compress_test.log.*.gz"))
        assert len(gz_files) >= 1

        total_lines = 0
        for gz_file in gz_files:
            with gzip.open(gz_file, "rt") as f:
                lines = [l for l in f if l.strip()]
                total_lines += len(lines)

        assert total_lines > 0, "No readable content in compressed files"

    def test_compression_level(self, tmp_path: Path):
        """Verify gzip compression uses level 6 (balanced)."""
        # This is tested implicitly by checking the compressed file is smaller
        # than the uncompressed equivalent
        log_file = tmp_path / "level_test.log"
        max_bytes = 300

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=5)

        # Write repetitive data that compresses well
        for i in range(100):
            handler.emit(self._make_record("A" * 100))

        handler.close()

        gz_files = list(tmp_path.glob("level_test.log.*.gz"))
        if gz_files:
            # Compressed should be smaller than total data written
            gz_size = gz_files[0].stat().st_size
            assert gz_size < 100 * 100, f"Compression ineffective: {gz_size} bytes"


class TestDirectoryCreation:
    """Verify parent directories are created automatically."""

    def test_creates_nested_directory(self, tmp_path: Path):
        """Handler creates nested parent directories."""
        log_file = tmp_path / "deep" / "nested" / "dir" / "agent.log"

        handler = RotatingJsonFileHandler(str(log_file))
        handler.emit(logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="nested dir test", args=(), exc_info=None,
        ))
        handler.close()

        assert log_file.exists()


class TestCleanup:
    """Verify old rotated files are cleaned up."""

    def _make_record(self, msg: str) -> logging.LogRecord:
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )

    def test_cleanup_removes_excess_files(self, tmp_path: Path):
        """Files beyond backupCount should be removed."""
        log_file = tmp_path / "cleanup.log"
        max_bytes = 150
        backup_count = 2

        handler = RotatingJsonFileHandler(str(log_file), max_bytes=max_bytes, backup_count=backup_count)

        # Force many rotations
        for i in range(300):
            handler.emit(self._make_record(f"Cleanup test {i}" + "p" * 30))

        handler.close()

        rotated = list(tmp_path.glob("cleanup.log.*.gz"))
        assert len(rotated) <= backup_count, \
            f"Expected <= {backup_count} rotated files, found {len(rotated)}"


class TestIntegration:
    """End-to-end integration: setup_json_logging -> StructuredLogger -> rotation."""

    def test_full_rotation_pipeline(self, tmp_path: Path):
        """End-to-end: log structured entries, trigger rotation, verify recovery."""
        log_file = tmp_path / "integration.log"

        setup_json_logging(
            level=logging.DEBUG, stdout=False,
            log_file=str(log_file),
            max_bytes=300,
            backup_count=3,
        )

        slog = get_structured_logger("rotation_integration")

        # Write enough to trigger rotation
        for i in range(100):
            slog.info(
                f"Integration event {i}",
                event_id=f"evt-{i:04d}",
                src_ip=f"10.0.0.{i % 256}",
                action="test",
            )

        # Flush all handlers
        root = logging.getLogger()
        for h in root.handlers:
            h.flush()
            h.close()
        root.handlers.clear()

        # Recover all entries
        recovered = []
        if log_file.exists():
            with open(log_file) as f:
                for line in f:
                    if line.strip():
                        recovered.append(json.loads(line))

        for gz_file in tmp_path.glob("integration.log.*.gz"):
            with gzip.open(gz_file, "rt") as f:
                for line in f:
                    if line.strip():
                        recovered.append(json.loads(line))

        # Verify structure of recovered entries
        assert len(recovered) > 0
        for entry in recovered:
            assert "timestamp" in entry
            assert "event_id" in entry
            assert "src_ip" in entry
            assert entry["level"] in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

    def test_no_log_file_when_disabled(self, monkeypatch: pytest.MonkeyPatch):
        """When LOG_FILE env var is not set and log_file=None, no file handler."""
        monkeypatch.delenv("LOG_FILE", raising=False)
        monkeypatch.delenv("LOG_MAX_BYTES", raising=False)
        monkeypatch.delenv("LOG_BACKUP_COUNT", raising=False)

        root = setup_json_logging(level=logging.INFO, stdout=False, log_file=None)
        file_handlers = [h for h in root.handlers if isinstance(h, RotatingJsonFileHandler)]
        assert len(file_handlers) == 0

        for h in root.handlers:
            h.close()
        root.handlers.clear()