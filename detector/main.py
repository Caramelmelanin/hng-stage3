"""
main.py
Entry point for the HNG anomaly detection daemon.
Wires all modules together and runs the main event loop.
"""

import os
import sys
import time
import logging
import signal
import yaml
from queue import Queue
from datetime import datetime

from monitor   import LogMonitor
from baseline  import BaselineTracker
from detector  import AnomalyDetector
from blocker   import Blocker
from unbanner  import UnbanScheduler
from notifier  import SlackNotifier
from dashboard import Dashboard


# ── Logging setup ──────────────────────────────────────────────────────────

def setup_logging(audit_log_path: str):
    """Configure root logger and audit file logger."""
    os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)

    logging.basicConfig(
        level   = logging.INFO,
        format  = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )


class AuditLogger:
    """
    Writes structured audit log entries for every ban, unban,
    and baseline recalculation event.

    Format:
        [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._logger = logging.getLogger("audit")
        handler = logging.FileHandler(path)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

    def log_ban(self, ip: str, condition: str, rate: float,
                baseline: float, duration: str):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self._logger.info(
            f"[{ts}] BAN {ip} | {condition} | "
            f"rate={rate:.2f} | baseline={baseline:.2f} | duration={duration}"
        )

    def log_unban(self, ip: str, condition: str):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self._logger.info(
            f"[{ts}] UNBAN {ip} | {condition}"
        )

    def log_baseline(self, mean: float, stddev: float, source: str):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self._logger.info(
            f"[{ts}] BASELINE_RECALC | mean={mean:.3f} | "
            f"stddev={stddev:.3f} | source={source}"
        )


# ── Main daemon ─────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    config_path = os.environ.get("CONFIG_PATH", "/app/config.yaml")
    config      = load_config(config_path)

    setup_logging(config["audit_log_path"])
    logger = logging.getLogger("main")
    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Daemon starting...")
    logger.info("=" * 60)

    # ── Instantiate all modules ──
    audit      = AuditLogger(config["audit_log_path"])
    notifier   = SlackNotifier(config)
    baseline   = BaselineTracker(config)
    entry_queue = Queue(maxsize=10000)
    monitor    = LogMonitor(config["log_path"], entry_queue)
    blocker    = Blocker(config, audit)

    # Detector needs baseline reference
    detector   = AnomalyDetector(config, baseline)

    # Unbanner needs blocker, detector, notifier
    unbanner   = UnbanScheduler(config, blocker, detector, notifier)

    # Shared state dict passed to dashboard
    start_time = time.time()
    state = {
        "start_time": start_time,
        "baseline":   baseline,
        "detector":   detector,
        "unbanner":   unbanner,
        "total_bans": 0,
    }

    dashboard = Dashboard(config, state)

    # ── Start all background threads ──
    notifier.start()
    monitor.start()
    unbanner.start()
    dashboard.start()

    logger.info("All modules started. Entering main loop.")

    # ── Graceful shutdown handler ──
    def shutdown(signum, frame):
        logger.info("Shutdown signal received — stopping daemon...")
        monitor.stop()
        unbanner.stop()
        notifier.stop()
        dashboard.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT,  shutdown)

    # ── Per-second tick state ──
    last_tick    = time.time()
    tick_count   = 0
    tick_errors  = 0

    # ── Main event loop ──
    while True:
        # 1. Drain the log queue — process all available entries
        while not entry_queue.empty():
            try:
                entry = entry_queue.get_nowait()
                tick_count  += 1
                tick_errors += 1 if entry.is_error else 0

                # Run anomaly detection on each entry
                event = detector.process(entry)

                if event:
                    if event.event_type == "per_ip":
                        # Per-IP anomaly: ban + Slack alert
                        mean, _ = baseline.get_baseline()
                        duration_idx = 0  # unbanner will compute proper duration
                        success = blocker.ban(
                            ip        = event.ip,
                            duration  = config["ban"]["backoff_schedule"][0],
                            condition = event.condition,
                            rate      = event.current_rate,
                            baseline  = event.baseline_mean,
                        )
                        if success:
                            state["total_bans"] += 1
                            unbanner.schedule_unban(
                                ip       = event.ip,
                                rate     = event.current_rate,
                                baseline = event.baseline_mean,
                            )

                    elif event.event_type == "global":
                        # Global anomaly: Slack alert only
                        notifier.send_global_alert(
                            condition = event.condition,
                            rate      = event.current_rate,
                            baseline  = event.baseline_mean,
                        )

            except Exception as e:
                logging.getLogger("main").error(f"Error processing entry: {e}")

        # 2. Per-second baseline tick
        now = time.time()
        if now - last_tick >= 1.0:
            baseline.record_tick(
                count       = tick_count,
                error_count = tick_errors,
            )
            tick_count  = 0
            tick_errors = 0
            last_tick   = now

        # 3. Recalculate baseline if interval has passed
        recalced = baseline.maybe_recalc()
        if recalced:
            mean, stddev = baseline.get_baseline()
            audit.log_baseline(
                mean   = mean,
                stddev = stddev,
                source = "auto-recalc",
            )

        # 4. Small sleep to avoid busy-waiting
        time.sleep(0.01)


if __name__ == "__main__":
    main()
