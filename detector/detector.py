"""
detector.py
Anomaly detection logic.
Consumes LogEntry objects from the monitor queue,
maintains per-IP and global sliding windows,
and flags anomalies based on z-score and rate multiplier checks.
"""

import time
import logging
from collections import deque, defaultdict
from threading import Lock
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AnomalyEvent:
    """Represents a detected anomaly."""
    ip:            Optional[str]   # None for global anomalies
    event_type:    str             # "per_ip" or "global"
    condition:     str             # human-readable condition that fired
    current_rate:  float           # requests/sec at time of detection
    baseline_mean: float
    baseline_std:  float
    zscore:        float
    timestamp:     float = field(default_factory=time.time)


class SlidingWindow:
    """
    Tracks request timestamps in a deque over a fixed duration.

    Structure:
    ----------
    A deque of float timestamps. Every time a request arrives,
    its timestamp is appended to the right. On every rate() call,
    timestamps older than (now - duration) are evicted from the left.

    This gives an accurate count of requests in the last `duration` seconds
    without storing the full log history.

    Example (duration=60s):
        t=0s   → append 1.0
        t=1s   → append 2.0
        t=61s  → append 62.0, evict 1.0 (now 61s ago)
        rate() → len(deque) / duration
    """

    def __init__(self, duration: int = 60):
        self.duration  = duration
        self._timestamps: deque = deque()
        self._errors: deque    = deque()  # timestamps of error responses
        self._lock = Lock()

    def add(self, timestamp: float, is_error: bool = False):
        """Record a request at the given timestamp."""
        with self._lock:
            self._timestamps.append(timestamp)
            if is_error:
                self._errors.append(timestamp)

    def _evict(self, now: float):
        """Remove timestamps outside the window. Must hold lock."""
        cutoff = now - self.duration
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        while self._errors and self._errors[0] < cutoff:
            self._errors.popleft()

    def rate(self) -> float:
        """Returns requests per second over the last `duration` seconds."""
        with self._lock:
            now = time.time()
            self._evict(now)
            return len(self._timestamps) / self.duration

    def error_rate(self) -> float:
        """Returns error requests per second over the last `duration` seconds."""
        with self._lock:
            now = time.time()
            self._evict(now)
            total = len(self._timestamps)
            if total == 0:
                return 0.0
            return len(self._errors) / total

    def count(self) -> int:
        """Returns raw count of requests in the current window."""
        with self._lock:
            now = time.time()
            self._evict(now)
            return len(self._timestamps)


class AnomalyDetector:
    """
    Core detection engine.

    Maintains:
    - A global SlidingWindow for overall traffic rate
    - A per-IP SlidingWindow dict for individual IP rates
    - Detection thresholds loaded from config

    Detection logic (whichever fires first):
    1. Z-score check: (current_rate - mean) / stddev > zscore_threshold
    2. Rate multiplier: current_rate > mean * rate_multiplier

    Error surge tightening:
    If an IP's error rate is >= baseline_error_rate * error_rate_multiplier,
    thresholds are tightened to tightened_zscore and tightened_multiplier.
    """

    def __init__(self, config: dict, baseline_tracker):
        cfg = config["detection"]
        win = config["sliding_window"]["duration"]

        self.zscore_threshold      = cfg["zscore_threshold"]
        self.rate_multiplier       = cfg["rate_multiplier"]
        self.error_rate_multiplier = cfg["error_rate_multiplier"]
        self.tightened_zscore      = cfg["tightened_zscore"]
        self.tightened_multiplier  = cfg["tightened_multiplier"]
        self.window_duration       = win

        self.baseline = baseline_tracker

        # Global window — one window for all traffic combined
        self._global_window = SlidingWindow(duration=win)

        # Per-IP windows — created on first request from that IP
        self._ip_windows: dict = defaultdict(lambda: SlidingWindow(duration=win))
        self._lock = Lock()

        # Track which IPs have already been flagged to avoid duplicate alerts
        self._flagged_ips: set = set()
        self._global_flagged_until: float = 0.0

    def process(self, entry) -> Optional[AnomalyEvent]:
        """
        Process a single LogEntry.
        Returns an AnomalyEvent if an anomaly is detected, else None.
        """
        now = entry.time
        ip  = entry.source_ip

        # Feed into windows
        self._global_window.add(now, is_error=entry.is_error)
        with self._lock:
            self._ip_windows[ip].add(now, is_error=entry.is_error)

        # Don't act until baseline is ready
        if not self.baseline.is_ready():
            return None

        mean, stddev = self.baseline.get_baseline()

        # Check per-IP anomaly first
        ip_event = self._check_ip(ip, mean, stddev, now)
        if ip_event:
            return ip_event

        # Check global anomaly (throttled — one alert per 60 seconds)
        if now > self._global_flagged_until:
            global_event = self._check_global(mean, stddev, now)
            if global_event:
                self._global_flagged_until = now + 60
                return global_event

        return None

    def _check_ip(
        self,
        ip: str,
        mean: float,
        stddev: float,
        now: float
    ) -> Optional[AnomalyEvent]:
        """Check a single IP for anomalous behaviour."""

        # Skip already-flagged IPs (they're already banned)
        if ip in self._flagged_ips:
            return None

        with self._lock:
            window = self._ip_windows[ip]

        rate       = window.rate()
        error_rate = window.error_rate()

        # Determine if error surge — tighten thresholds if so
        baseline_error = self.baseline.get_error_baseline()
        error_surge    = (
            baseline_error > 0 and
            error_rate >= baseline_error * self.error_rate_multiplier
        )

        z_thresh   = self.tightened_zscore      if error_surge else self.zscore_threshold
        r_thresh   = self.tightened_multiplier  if error_surge else self.rate_multiplier

        zscore     = (rate - mean) / stddev if stddev > 0 else 0.0

        # Whichever fires first
        condition = None
        if zscore > z_thresh:
            condition = (
                f"z-score {zscore:.2f} > {z_thresh} "
                f"({'tightened — error surge' if error_surge else 'normal threshold'})"
            )
        elif rate > mean * r_thresh:
            condition = (
                f"rate {rate:.2f} req/s > {r_thresh}x baseline mean {mean:.2f} "
                f"({'tightened' if error_surge else 'normal'})"
            )

        if condition:
            self._flagged_ips.add(ip)
            logger.warning(
                f"[ANOMALY] per_ip | ip={ip} | rate={rate:.2f} | "
                f"mean={mean:.2f} | stddev={stddev:.2f} | "
                f"zscore={zscore:.2f} | condition={condition}"
            )
            return AnomalyEvent(
                ip            = ip,
                event_type    = "per_ip",
                condition     = condition,
                current_rate  = rate,
                baseline_mean = mean,
                baseline_std  = stddev,
                zscore        = zscore,
            )

        return None

    def _check_global(
        self,
        mean: float,
        stddev: float,
        now: float
    ) -> Optional[AnomalyEvent]:
        """Check global traffic rate for anomalous behaviour."""
        rate   = self._global_window.rate()
        zscore = (rate - mean) / stddev if stddev > 0 else 0.0

        condition = None
        if zscore > self.zscore_threshold:
            condition = f"global z-score {zscore:.2f} > {self.zscore_threshold}"
        elif rate > mean * self.rate_multiplier:
            condition = (
                f"global rate {rate:.2f} req/s > "
                f"{self.rate_multiplier}x mean {mean:.2f}"
            )

        if condition:
            logger.warning(
                f"[ANOMALY] global | rate={rate:.2f} | "
                f"mean={mean:.2f} | zscore={zscore:.2f} | condition={condition}"
            )
            return AnomalyEvent(
                ip            = None,
                event_type    = "global",
                condition     = condition,
                current_rate  = rate,
                baseline_mean = mean,
                baseline_std  = stddev,
                zscore        = zscore,
            )

        return None

    def unflag_ip(self, ip: str):
        """
        Remove an IP from the flagged set after it has been unbanned.
        Allows the detector to flag it again if it reoffends.
        """
        self._flagged_ips.discard(ip)
        logger.info(f"[DETECTOR] IP {ip} removed from flagged set")

    def get_top_ips(self, n: int = 10) -> list:
        """Returns top N IPs by current request rate."""
        with self._lock:
            rates = [
                {"ip": ip, "rate": round(win.rate(), 3)}
                for ip, win in self._ip_windows.items()
            ]
        return sorted(rates, key=lambda x: x["rate"], reverse=True)[:n]

    def get_global_rate(self) -> float:
        """Returns current global requests per second."""
        return round(self._global_window.rate(), 3)
