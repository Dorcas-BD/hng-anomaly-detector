import requests
import time
from config import config

class Notifier:
    """
    Sends Slack alerts for bans, unbans, and global anomalies.
    """
    def __init__(self):
        self.webhook_url = config["slack"]["webhook_url"]

    def _send(self, message):
        """Send a message to Slack."""
        try:
            response = requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5
            )
            if response.status_code != 200:
                print(f"[notifier] Slack error: {response.status_code} {response.text}")
        except Exception as e:
            print(f"[notifier] Failed to send Slack alert: {e}")

    def send_ban_alert(self, ip, reason, duration):
        """Send a ban notification."""
        duration_str = f"{duration} minutes" if duration != -1 else "PERMANENT"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        message = (
            f":rotating_light: *ANOMALY DETECTED — IP BANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Condition:* {reason}\n"
            f">*Ban Duration:* {duration_str}\n"
            f">*Timestamp:* {timestamp}"
        )
        self._send(message)

    def send_unban_alert(self, ip, duration):
        """Send an unban notification."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        duration_str = f"{duration} minutes" if duration != -1 else "PERMANENT"

        message = (
            f":white_check_mark: *IP UNBANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Previous Ban Duration:* {duration_str}\n"
            f">*Timestamp:* {timestamp}"
        )
        self._send(message)

    def send_global_alert(self, reason):
        """Send a global anomaly notification."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        message = (
            f":warning: *GLOBAL TRAFFIC ANOMALY DETECTED*\n"
            f">*Condition:* {reason}\n"
            f">*Timestamp:* {timestamp}\n"
            f">*Action:* Monitoring — no IP to block"
        )
        self._send(message)
