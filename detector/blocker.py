"""
blocker.py
Manages iptables DROP rules for banned IPs.
Adds and removes rules using subprocess calls to iptables.
"""

import subprocess
import logging
import time
from threading import Lock

logger = logging.getLogger(__name__)


class Blocker:
    """
    Wraps iptables to add and remove DROP rules for specific IPs.

    Each ban is recorded in _banned dict:
        key   = ip (str)
        value = timestamp of ban (float)

    iptables command used:
        iptables -I INPUT -s <ip> -j DROP
    The -I flag inserts at the top of the chain (highest priority).
    """

    def __init__(self, config: dict, audit_logger):
        self.chain         = config["iptables"]["chain"]
        self.audit_logger  = audit_logger
        self._banned: dict = {}   # ip -> ban timestamp
        self._lock         = Lock()

    def ban(self, ip: str, duration: int, condition: str,
            rate: float, baseline: float) -> bool:
        """
        Add an iptables DROP rule for the given IP.

        ip        — IP address to block
        duration  — ban duration in seconds (-1 = permanent)
        condition — human-readable reason for ban
        rate      — current request rate at time of ban
        baseline  — current baseline mean

        Returns True on success, False on failure.
        """
        with self._lock:
            if ip in self._banned:
                logger.info(f"[BLOCKER] IP {ip} already banned — skipping")
                return False

        cmd = ["iptables", "-I", self.chain, "-s", ip, "-j", "DROP"]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            ban_time = time.time()

            with self._lock:
                self._banned[ip] = ban_time

            duration_str = "permanent" if duration == -1 else f"{duration}s"
            logger.warning(
                f"[BLOCKER] BANNED ip={ip} duration={duration_str} "
                f"condition={condition}"
            )

            # Write to audit log
            self.audit_logger.log_ban(
                ip        = ip,
                condition = condition,
                rate      = rate,
                baseline  = baseline,
                duration  = duration_str,
            )
            return True

        except subprocess.CalledProcessError as e:
            logger.error(
                f"[BLOCKER] Failed to ban {ip}: "
                f"{e.stderr.decode().strip()}"
            )
            return False

    def unban(self, ip: str, condition: str = "backoff expired") -> bool:
        """
        Remove the iptables DROP rule for the given IP.

        Returns True on success, False on failure.
        """
        cmd = ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"]

        try:
            subprocess.run(cmd, check=True, capture_output=True)

            with self._lock:
                self._banned.pop(ip, None)

            logger.info(f"[BLOCKER] UNBANNED ip={ip} reason={condition}")

            self.audit_logger.log_unban(
                ip        = ip,
                condition = condition,
            )
            return True

        except subprocess.CalledProcessError as e:
            logger.error(
                f"[BLOCKER] Failed to unban {ip}: "
                f"{e.stderr.decode().strip()}"
            )
            return False

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned."""
        with self._lock:
            return ip in self._banned

    def get_banned(self) -> dict:
        """Returns a copy of the current banned IPs dict."""
        with self._lock:
            return dict(self._banned)
