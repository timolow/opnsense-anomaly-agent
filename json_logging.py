#!/usr/bin/env python3
"""Structured JSON logging with rotation for OPNsense Anomaly Detection Agent.

All log output is JSON-formatted with:
  - timestamp    ISO 8601 with timezone
  - level        Log level name (INFO, WARNING, ERROR, DEBUG, CRITICAL)
  - module       Logger name / module path
  - message      The log message
  - exception    Optional traceback string (present on error/critical with exc_info)
  - Plus any extra key-value fields passed via extra={...}

Rotation:
  - Daily rotation at midnight UTC
  - 7-day retention (backupCount=7)
  - Old logs compressed with gzip (.gz extension)
  - Max 100MB per log file (size-based safety rotation)

Usage:
    from json_logging import setup_json_logging

    setup_json_logging(level=logging.INFO, log_file="/path/to/agent.log")
    logger = logging.getLogger(__name__)

    logger.info("Agent started", extra={"pid": os.getpid()})
"""

from __future__ import annotations

import gzip
import json
import logging
import logging.handlers
import os
import shutil
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Cache UTC timezone
        self._utc = timezone.utc

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=self._utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }

        # Attach exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Attach stack info if present
        if record.stack_info:
            log_entry["stack"] = self.formatStack(record.stack_info)

        # Merge any extra fields the caller passed via extra={...}
        # Standard logging fields we skip to avoid duplication
        skip_keys = {
            "asctime", "args", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "module", "msecs",
            "message", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName",
        }
        for key, value in record.__dict__.items():
            if key not in skip_keys and not key.startswith("_"):
                log_entry[key] = value

        return json.dumps(log_entry, default=str, ensure_ascii=False)


class RotatingJsonFileHandler(logging.handlers.TimedRotatingFileHandler):
    """File handler with daily rotation, gzip compression, and max size limit.

    Rotation policy:
      - Rotates at midnight UTC daily (when='midnight', utc=True)
      - Keeps 7 days of rotated logs (backupCount=7)
      - Compresses rotated logs with gzip (.gz suffix)
      - Enforces maxBytes limit to prevent runaway growth
    """

    def __init__(
        self,
        filename: str,
        max_bytes: int = 100_000_000,  # 100MB max per file
        backup_count: int = 7,
        encoding: str = "utf-8",
    ) -> None:
        # Daily rotation at midnight UTC
        # Ensure parent directory exists before opening
        log_dir = os.path.dirname(os.path.abspath(filename))
        os.makedirs(log_dir, exist_ok=True)
        super().__init__(
            filename,
            when="midnight",
            interval=1,
            backupCount=backup_count,
            encoding=encoding,
            utc=True,
        )
        self.max_bytes = max_bytes
        self.setFormatter(JsonFormatter())

    def shouldRollover(self, record: logging.LogRecord) -> bool:
        """Check if rollover is needed (time OR size-based)."""
        # Size-based check
        if self.max_bytes > 0 and self.stream is not None:
            msg = self.format(record)
            self.stream.seek(0, 2)  # Seek to end
            current_size = self.stream.tell()
            if current_size + len(msg.encode("utf-8") if isinstance(msg, str) else msg) >= self.max_bytes:
                return True
        # Time-based check (parent class)
        return super().shouldRollover(record)

    def doRollover(self) -> None:
        """Perform rollover: close current, rename, compress, open new."""
        if self.stream:
            self.stream.close()

        # Determine the rotated filename using UTC midnight boundary
        # TimedRotatingFileHandler computes this in rolling_timestamp
        from datetime import datetime as dt, timezone as tz
        datetime_now = dt.now(tz.utc)
        # Use date suffix for rotated files
        rotated_name = self.baseFilename + "." + datetime_now.strftime("%Y-%m-%d")

        # If the rotated file already exists (shouldn't normally), skip
        if os.path.exists(rotated_name):
            # Already exists — compress if not already compressed
            if not rotated_name.endswith(".gz"):
                self._compress_file(rotated_name)
        else:
            # Rename current file to rotated name
            if os.path.exists(self.baseFilename):
                os.rename(self.baseFilename, rotated_name)
                # Compress the rotated file
                self._compress_file(rotated_name)

        # Clean up old rotated files beyond backupCount
        self._cleanup_old_files()

        # Reopen the new file
        self.mode = "a"
        self.stream = self._open()

    def _compress_file(self, filepath: str) -> None:
        """Compress a file with gzip, removing the original on success."""
        gz_path = filepath + ".gz"
        try:
            with open(filepath, "rb") as f_in:
                with gzip.open(gz_path, "wb", compresslevel=6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(filepath)
        except OSError:
            # If compression fails, keep the uncompressed file
            pass

    def _cleanup_old_files(self) -> None:
        """Remove rotated log files older than backupCount days."""
        import glob

        # Find all rotated log files (both compressed and uncompressed)
        pattern_gz = self.baseFilename + ".*.gz"
        pattern_plain = self.baseFilename + ".*"
        rotated_files: list[str] = []

        for f in glob.glob(pattern_gz):
            rotated_files.append(f)
        for f in glob.glob(pattern_plain):
            if not f.endswith(".gz") and f != self.baseFilename:
                rotated_files.append(f)

        # Sort by modification time, newest first
        rotated_files.sort(key=os.path.getmtime, reverse=True)

        # Remove files beyond backupCount
        for old_file in rotated_files[self.backupCount:]:
            try:
                os.remove(old_file)
            except OSError:
                pass


def setup_json_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    stdout: bool = True,
    stderr: bool = False,
    max_bytes: int = 100_000_000,
    backup_count: int = 7,
) -> logging.Logger:
    """Configure the root logger to emit structured JSON.

    Args:
        level:       Minimum log level (default: INFO).
        log_file:    Optional file path to also write JSON logs to (with rotation).
        stdout:      If True, attach a StreamHandler to stdout (default True).
        stderr:      If True, attach a StreamHandler to stderr (default False).
        max_bytes:   Max size per log file before rotation (default: 100MB).
        backup_count: Number of rotated log files to keep (default: 7 days).

    Returns:
        The root logger (for chaining if needed).
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any existing handlers to avoid duplicates on re-init
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()

    fmt = JsonFormatter()

    if stdout:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    if stderr:
        # Send WARNING+ to stderr for visibility
        err_sh = logging.StreamHandler(sys.stderr)
        err_sh.setFormatter(fmt)
        err_sh.addFilter(lambda rec: rec.levelno >= logging.WARNING)
        root.addHandler(err_sh)

    if log_file:
        # Ensure parent directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        fh = RotatingJsonFileHandler(
            log_file,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
        fh.setLevel(level)
        root.addHandler(fh)

    # Suppress noisy third-party loggers
    for noisy in ["urllib3", "requests", "httpx", "discord", "apscheduler"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return root


# Reserved LogRecord attribute names that would collide with JsonFormatter
# output. When passed as kwargs to StructuredLogger, these are remapped
# by prepending "logger_".
_RESERVED_KEYS = {
    "module",      # collides with record.name (logger module path)
}


class StructuredLogger:
    """Adapter around stdlib Logger that accepts keyword-arg structured context.

    All keyword arguments are attached to the LogRecord as extra fields so
    JsonFormatter merges them into the JSON output.  Reserved keys that
    would collide with LogRecord attributes are remapped (e.g. ``module``
    → ``logger_module``).

    Usage:
        slog = get_structured_logger(__name__)
        slog.info("Firewall event", event_id="evt-1", ip="10.0.0.1", rule="FW-001")
    """

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def _log_extra(self, level: int, msg: str, **kwargs: Any) -> None:
        """Route through the underlying logger, injecting structured kwargs."""
        remapped: Dict[str, Any] = {}
        for k, v in kwargs.items():
            remapped[k if k not in _RESERVED_KEYS else f"logger_{k}"] = v
        self.logger.log(level, msg, extra=remapped)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log_extra(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log_extra(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log_extra(logging.WARNING, msg, **kwargs)

    def warn(self, msg: str, **kwargs: Any) -> None:
        self.warning(msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log_extra(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._log_extra(logging.CRITICAL, msg, **kwargs)

    def exception(self, msg: str, **kwargs: Any) -> None:
        self.logger.exception(msg, extra=kwargs)


def get_structured_logger(name: str) -> StructuredLogger:
    """Factory: wrap a stdlib logger in StructuredLogger."""
    return StructuredLogger(logging.getLogger(name))