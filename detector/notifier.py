"""
notifier.py
Sends Slack alerts for ban, unban, and global anomaly events.
All messages include: condition, current rate, baseline, timestamp, duration.
"""

import time
import logging
import requests
from datetime import datetime
from threading import Thread
from queue import Queue, Empty

logger = logging.getLogger(__name__)


class SlackNotifier:
    """
    Sends formatted Slack messages via an incoming webhook URL.

    Messages are dispatched from a background thread queue so that
    Slack API latency never blocks the detection loop.
    """

    def __init__(self, config: dict):
        self.webhook_url = config["slack"]["webhook_url"]
        self._queue      = Queue()
        self._running    = False
        self._thread     = None

    def start(self):
        """Start the background sender thread."""
        self._running = True
        self._thread  = Thread(
            target=self._send_loop,
            daemon=True,
            name="slack-notifier"
        )
        self._thread.start()
        logger.info("[NOTIFIER] Slack notifier started")

    def stop(self):
        self._running = False

    def send_ban(self, ip: str, condition: str, rate: float,
                 baseline: float, duration: str):
        """Queue a ban notification."""
        ts  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = (
            f":rotating_light: *IP BANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Condition:* {condition}\n"
            f">*Current rate:* `{rate:.2f} req/s`\n"
            f">*Baseline mean:* `{baseline:.2f} req/s`\n"
            f">*Ban duration:* `{duration}`\n"
            f">*Timestamp:* {ts}"
        )
        self._queue.put(msg)

    def send_unban(self, ip: str, reason: str, offences: int):
        """Queue an unban notification."""
        ts  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = (
            f":white_check_mark: *IP UNBANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Reason:* {reason}\n"
            f">*Total offences:* `{offences}`\n"
            f">*Timestamp:* {ts}"
        )
        self._queue.put(msg)

    def send_global_alert(self, condition: str, rate: float, baseline: float):
        """Queue a global anomaly notification."""
        ts  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f">*Condition:* {condition}\n"
            f">*Current rate:* `{rate:.2f} req/s`\n"
            f">*Baseline mean:* `{baseline:.2f} req/s`\n"
            f">*Timestamp:* {ts}"
        )
        self._queue.put(msg)

    def _send_loop(self):
        """Background thread — drains the message queue and posts to Slack."""
        while self._running:
            try:
                msg = self._queue.get(timeout=1)
                self._post(msg)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"[NOTIFIER] Unexpected error: {e}")

    def _post(self, text: str):
        """POST a message to the Slack webhook."""
        try:
            resp = requests.post(
                self.webhook_url,
                json    = {"text": text},
                timeout = 5,
            )
            if resp.status_code != 200:
                logger.error(
                    f"[NOTIFIER] Slack returned {resp.status_code}: {resp.text}"
                )
            else:
                logger.debug("[NOTIFIER] Slack message sent")
        except requests.RequestException as e:
            logger.error(f"[NOTIFIER] Failed to send Slack message: {e}")
