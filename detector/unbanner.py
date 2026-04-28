"""
unbanner.py
Manages automatic unban scheduling with exponential backoff.

Backoff schedule (from config):
    1st offence  →  10 minutes
    2nd offence  →  30 minutes
    3rd offence  →   2 hours
    4th+         →  permanent (-1)

Each IP's offence count is tracked so repeat offenders get longer bans.
"""

import time
import logging
from threading import Lock, Thread
from collections import defaultdict

logger = logging.getLogger(__name__)


class UnbanScheduler:
    """
    Schedules automatic IP unbans based on a backoff schedule.

    Internal state per IP:
        offence_count — how many times this IP has been banned
        scheduled     — dict of ip -> (unban_time, duration)
    """

    def __init__(self, config: dict, blocker, detector, notifier):
        self.schedule  = config["ban"]["backoff_schedule"]
        self.blocker   = blocker
        self.detector  = detector
        self.notifier  = notifier

        # offence_count[ip] = number of times this IP has been banned
        self._offence_count: dict = defaultdict(int)

        # pending[ip] = unban_time (epoch float), or -1 if permanent
        self._pending: dict = {}
        self._lock    = Lock()
        self._running = False
        self._thread  = None

    def schedule_unban(self, ip: str, rate: float, baseline: float):
        """
        Schedule an unban for the given IP based on its offence history.
        Increments the offence counter for this IP.

        rate     — request rate at time of ban (for Slack notification)
        baseline — baseline mean at time of ban
        """
        with self._lock:
            count    = self._offence_count[ip]
            # Clamp index to last entry for repeat offenders beyond schedule length
            idx      = min(count, len(self.schedule) - 1)
            duration = self.schedule[idx]
            self._offence_count[ip] += 1

        if duration == -1:
            # Permanent ban — no unban scheduled
            logger.warning(f"[UNBANNER] {ip} — PERMANENT ban (offence #{count + 1})")
            with self._lock:
                self._pending[ip] = -1

            self.notifier.send_ban(
                ip        = ip,
                condition = f"Permanent ban — offence #{count + 1}",
                rate      = rate,
                baseline  = baseline,
                duration  = "permanent",
            )
        else:
            unban_at = time.time() + duration
            with self._lock:
                self._pending[ip] = unban_at

            duration_str = self._fmt_duration(duration)
            logger.info(
                f"[UNBANNER] {ip} — ban for {duration_str} "
                f"(offence #{count + 1}), unban at {unban_at:.0f}"
            )

            self.notifier.send_ban(
                ip        = ip,
                condition = f"Offence #{count + 1}",
                rate      = rate,
                baseline  = baseline,
                duration  = duration_str,
            )

    def start(self):
        """Start the unban watcher thread."""
        self._running = True
        self._thread  = Thread(
            target=self._watch_loop,
            daemon=True,
            name="unbanner"
        )
        self._thread.start()
        logger.info("[UNBANNER] Unban scheduler started")

    def stop(self):
        self._running = False

    def _watch_loop(self):
        """
        Runs every 10 seconds.
        Checks all pending unbans and fires any that have expired.
        """
        while self._running:
            now = time.time()
            to_unban = []

            with self._lock:
                for ip, unban_at in list(self._pending.items()):
                    if unban_at == -1:
                        continue  # permanent — never unban
                    if now >= unban_at:
                        to_unban.append(ip)

            for ip in to_unban:
                success = self.blocker.unban(ip, condition="backoff expired")
                if success:
                    with self._lock:
                        self._pending.pop(ip, None)

                    # Allow detector to flag this IP again if it reoffends
                    self.detector.unflag_ip(ip)

                    self.notifier.send_unban(
                        ip       = ip,
                        reason   = "Backoff period expired",
                        offences = self._offence_count.get(ip, 1),
                    )

            time.sleep(10)

    def get_pending(self) -> list:
        """Returns list of pending unbans for dashboard display."""
        now = time.time()
        with self._lock:
            result = []
            for ip, unban_at in self._pending.items():
                result.append({
                    "ip":          ip,
                    "permanent":   unban_at == -1,
                    "unban_at":    unban_at if unban_at != -1 else None,
                    "remaining_s": max(0, int(unban_at - now)) if unban_at != -1 else None,
                    "offences":    self._offence_count.get(ip, 1),
                })
        return result

    @staticmethod
    def _fmt_duration(seconds: int) -> str:
        """Human-readable duration string."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        else:
            return f"{seconds // 3600}h"
