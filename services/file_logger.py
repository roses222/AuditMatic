"""
AuditMatic File Logger Service

Thread-safe file logging for audit operations and debugging.
"""

import threading
from datetime import datetime
from pathlib import Path
from typing import Optional
import traceback

from utils import timestamp_str


class FileLogger:
    """Thread-safe file logger for audit session logging."""

    def __init__(self, log_dir: Path, prefix: str):
        """Initialize logger with output directory and filename prefix."""
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"{prefix}_{timestamp_str()}.log"
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        """Write message to log file with timestamp."""
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def write_exception(self, exc: Exception) -> None:
        """Write exception with full traceback to log file."""
        self.write(f"ERROR: {exc}")
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(tb + "\n")

    def get_path(self) -> str:
        """Return the full path to the log file."""
        return str(self.log_file)
