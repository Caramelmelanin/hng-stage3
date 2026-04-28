"""
monitor.py
Continuously tails and parses the Nginx JSON access log line by line.
Puts parsed log entries into a shared queue for the detector to consume.
"""

import json
import time
import os
import logging
from queue import Queue
from threading import Thread

logger = logging.getLogger(__name__)


class LogEntry:
    """Represents a single parsed Nginx log line."""

    def __init__(self, source_ip, timestamp, method, path, status, response_size):
        self.source_ip    = source_ip
        self.timestamp    = timestamp
        self.method       = method
        self.path         = path
        self.status       = int(status)
        self.response_size = int(response_size)
        self.time         = time.time()  # wall clock time of parsing

    @property
    def is_error(self):
        """Returns True if the response was a 4xx or 5xx."""
        return self.status >= 400

    def __repr__(self):
        return (
            f"LogEntry(ip={self.source_ip}, method={self.method}, "
            f"path={self.path}, status={self.status})"
        )


def parse_line(line: str):
    """
    Parse a single JSON log line from Nginx.
    Returns a LogEntry on success, None if the line is malformed.
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)

        # Extract source IP — X-Forwarded-For can be a comma-separated list
        # e.g. "1.2.3.4, 10.0.0.1" — we want the first (real client) IP
        raw_ip = data.get("source_ip", "")
        source_ip = raw_ip.split(",")[0].strip() if raw_ip else "unknown"

        return LogEntry(
            source_ip    = source_ip,
            timestamp    = data.get("timestamp", ""),
            method       = data.get("method", ""),
            path         = data.get("path", ""),
            status       = data.get("status", 0),
            response_size = data.get("response_size", 0),
        )

    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.debug(f"Failed to parse log line: {e} | line: {line[:80]}")
        return None


class LogMonitor:
    """
    Tails the Nginx access log file continuously.
    Parses each line and puts LogEntry objects into the provided queue.

    Works like `tail -f`:
    - Opens the file and seeks to the end on startup
    - Reads new lines as they arrive
    - If the file is rotated (size shrinks), reopens from the start
    """

    def __init__(self, log_path: str, entry_queue: Queue):
        self.log_path    = log_path
        self.queue       = entry_queue
        self._running    = False
        self._thread     = None
        self.lines_parsed = 0
        self.lines_failed = 0

    def start(self):
        """Start the monitor in a background thread."""
        self._running = True
        self._thread  = Thread(target=self._tail_loop, daemon=True, name="log-monitor")
        self._thread.start()
        logger.info(f"LogMonitor started — watching {self.log_path}")

    def stop(self):
        """Signal the monitor to stop."""
        self._running = False
        logger.info("LogMonitor stopped")

    def _wait_for_file(self):
        """Block until the log file exists — Nginx may not have written it yet."""
        while self._running:
            if os.path.exists(self.log_path):
                return
            logger.info(f"Waiting for log file: {self.log_path}")
            time.sleep(2)

    def _tail_loop(self):
        """
        Core tail loop.
        Seeks to end of file on open, then reads new lines as they appear.
        Detects log rotation by checking if file size has shrunk.
        """
        self._wait_for_file()

        with open(self.log_path, "r") as f:
            # Seek to end — we only care about new traffic, not history
            f.seek(0, 2)
            logger.info("Log file opened — seeking to end, watching for new lines")

            while self._running:
                line = f.readline()

                if line:
                    entry = parse_line(line)
                    if entry:
                        self.queue.put(entry)
                        self.lines_parsed += 1
                    else:
                        self.lines_failed += 1
                else:
                    # No new line yet — check for log rotation
                    try:
                        current_size = os.path.getsize(self.log_path)
                        if current_size < f.tell():
                            logger.warning("Log rotation detected — reopening file")
                            f.close()
                            self._tail_loop()  # restart from new file
                            return
                    except OSError:
                        pass

                    time.sleep(0.05)  # 50ms poll interval — low CPU, fast enough
