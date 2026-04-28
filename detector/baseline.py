"""
baseline.py
Maintains a rolling 30-minute baseline of per-second request counts.
Computes mean and stddev, recalculated every 60 seconds.
Maintains per-hour slots and prefers the current hour's baseline
when it has enough data.
"""

import time
import math
import logging
from collections import deque, defaultdict
from threading import Lock
from datetime import datetime

logger = logging.getLogger(__name__)


class HourlySlot:
    """
    Stores per-second request counts for a single hour.
    Used to build an hour-aware baseline.
    """

    def __init__(self, hour: int):
        self.hour     = hour        # 0-23
        self.counts   = []          # list of per-second counts observed this hour
        self.mean     = 0.0
        self.stddev   = 0.0
        self.computed = False       # has this slot been calculated at least once

    def add(self, count: float):
        self.counts.append(count)

    def compute(self):
        """Calculate mean and stddev from stored counts."""
        if len(self.counts) < 2:
            return
        n      = len(self.counts)
        mean   = sum(self.counts) / n
        variance = sum((x - mean) ** 2 for x in self.counts) / (n - 1)
        self.mean     = mean
        self.stddev   = math.sqrt(variance)
        self.computed = True

    def __repr__(self):
        return (
            f"HourlySlot(hour={self.hour}, samples={len(self.counts)}, "
            f"mean={self.mean:.2f}, stddev={self.stddev:.2f})"
        )


class BaselineTracker:
    """
    Tracks global request rates and maintains a rolling baseline.

    How it works:
    -------------
    1. Every second, the daemon calls record_tick(count) with the number
       of requests seen in that second.

    2. These per-second counts are stored in a deque capped at
       window_minutes * 60 entries (default: 1800 entries = 30 minutes).
       Old entries fall off the left side automatically.

    3. Every recalc_interval seconds (default: 60), compute() is called.
       It calculates mean and stddev from the current deque contents.

    4. Per-hour slots are also maintained. If the current hour's slot
       has >= min_hourly_samples entries, its mean/stddev are preferred
       over the global rolling window — because hour-of-day patterns
       matter (e.g. 3am is quieter than 3pm).

    5. Floor values prevent division by zero and false positives during
       low-traffic periods.
    """

    def __init__(self, config: dict):
        cfg = config

        # Config values
        self.window_size       = cfg["baseline"]["window_minutes"] * 60
        self.recalc_interval   = cfg["baseline"]["recalc_interval"]
        self.min_samples       = cfg["baseline"]["min_samples"]
        self.floor_mean        = cfg["baseline"]["floor_mean"]
        self.floor_stddev      = cfg["baseline"]["floor_stddev"]
        self.min_hourly_samples = cfg["baseline"]["min_hourly_samples"]

        # Rolling window of per-second counts (global)
        # maxlen enforces the 30-minute cap — old entries evicted automatically
        self._window: deque = deque(maxlen=self.window_size)

        # Per-hour slots: key = hour (0-23), value = HourlySlot
        self._hourly: dict = defaultdict(lambda: HourlySlot(datetime.now().hour))

        # Current effective baseline (what detector.py reads)
        self.effective_mean   = self.floor_mean
        self.effective_stddev = self.floor_stddev
        self.sample_count     = 0
        self.last_recalc      = time.time()
        self.recalc_count     = 0  # how many times baseline has been recalculated

        # Per-IP error rate baseline
        # key = ip, value = deque of 0/1 (0=ok, 1=error) over last window_size seconds
        self._ip_error_window: dict = defaultdict(lambda: deque(maxlen=self.window_size))
        self.baseline_error_rate = 0.0

        self._lock = Lock()

    def record_tick(self, count: float, error_count: float = 0):
        """
        Record one second's worth of traffic.
        Call this every second from the main loop.

        count       — total requests in this second (global)
        error_count — 4xx/5xx requests in this second
        """
        with self._lock:
            self._window.append(count)
            current_hour = datetime.now().hour

            # Ensure the hourly slot key matches the current hour
            if current_hour not in self._hourly or \
               self._hourly[current_hour].hour != current_hour:
                self._hourly[current_hour] = HourlySlot(current_hour)

            self._hourly[current_hour].add(count)
            self.sample_count += 1

            # Track global error rate
            if count > 0:
                self._ip_error_window["_global"].append(error_count / count)
            else:
                self._ip_error_window["_global"].append(0)

    def maybe_recalc(self) -> bool:
        """
        Recalculate baseline if recalc_interval has passed.
        Returns True if a recalculation was performed.
        """
        now = time.time()
        if now - self.last_recalc >= self.recalc_interval:
            self._recalculate()
            self.last_recalc = now
            return True
        return False

    def _recalculate(self):
        """
        Internal recalculation logic.
        Prefers hourly slot if it has enough samples,
        falls back to global rolling window.
        """
        with self._lock:
            current_hour = datetime.now().hour
            hourly_slot  = self._hourly.get(current_hour)

            # Prefer current hour's baseline if it has enough data
            if (hourly_slot and
                    len(hourly_slot.counts) >= self.min_hourly_samples):
                hourly_slot.compute()
                raw_mean   = hourly_slot.mean
                raw_stddev = hourly_slot.stddev
                source     = f"hourly[{current_hour:02d}h]"
            elif len(self._window) >= self.min_samples:
                # Fall back to global rolling window
                data       = list(self._window)
                n          = len(data)
                raw_mean   = sum(data) / n
                variance   = sum((x - raw_mean) ** 2 for x in data) / max(n - 1, 1)
                raw_stddev = math.sqrt(variance)
                source     = f"rolling[{n}s]"
            else:
                # Not enough data yet — keep floor values
                logger.debug("Baseline: not enough samples yet, keeping floor values")
                return

            # Apply floor values
            self.effective_mean   = max(raw_mean,   self.floor_mean)
            self.effective_stddev = max(raw_stddev, self.floor_stddev)
            self.recalc_count    += 1

            # Compute baseline error rate
            error_window = list(self._ip_error_window.get("_global", []))
            if error_window:
                self.baseline_error_rate = sum(error_window) / len(error_window)

            logger.info(
                f"[BASELINE] source={source} "
                f"mean={self.effective_mean:.3f} "
                f"stddev={self.effective_stddev:.3f} "
                f"samples={len(self._window)} "
                f"error_rate={self.baseline_error_rate:.3f}"
            )

    def get_baseline(self) -> tuple:
        """
        Returns (effective_mean, effective_stddev).
        Safe to call from any thread.
        """
        return self.effective_mean, self.effective_stddev

    def get_error_baseline(self) -> float:
        """Returns the baseline error rate (0.0 to 1.0)."""
        return self.baseline_error_rate

    def is_ready(self) -> bool:
        """Returns True if baseline has enough samples to be trusted."""
        return self.sample_count >= self.min_samples

    def get_hourly_slots(self) -> list:
        """Returns all hourly slots for dashboard display."""
        with self._lock:
            return [
                {
                    "hour":     slot.hour,
                    "samples":  len(slot.counts),
                    "mean":     round(slot.mean, 3),
                    "stddev":   round(slot.stddev, 3),
                    "computed": slot.computed,
                }
                for slot in self._hourly.values()
            ]
