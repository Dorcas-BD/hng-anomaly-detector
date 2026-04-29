import subprocess
import time
import threading
from config import config
from audit import write_audit

class Blocker:
    """
    Manages iptables DROP rules for anomalous IPs.
    Tracks ban counts per IP to apply progressive unban schedule.
    """
    def __init__(self, notifier):
        self.notifier = notifier
        self.banned_ips = {}  # {ip: {"banned_at": t, "ban_count": n, "reason": r}}
        self.unban_schedule = config["blocking"]["unban_schedule_minutes"]
        self.lock = threading.Lock()

        # Start the unbanner thread
        self.unbanner_thread = threading.Thread(
            target=self._unban_loop,
            daemon=True
        )
        self.unbanner_thread.start()

    def ban(self, ip, reason):
        """
        Add an iptables DROP rule for the given IP.
        Sends a Slack alert within 10 seconds.
        """
        with self.lock:
            if ip in self.banned_ips:
                # Already banned — skip
                return

            # Add iptables rule
            result = subprocess.run(
                ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"[blocker] Failed to ban {ip}: {result.stderr}")
                return

            # Record the ban
            ban_count = 0
            self.banned_ips[ip] = {
                "banned_at": time.time(),
                "ban_count": ban_count,
                "reason": reason
            }

            # Determine ban duration
            duration = self._get_duration(ban_count)

            print(f"[blocker] Banned {ip} | reason: {reason} | duration: {duration}min")

            # Write to audit log
            write_audit("BAN", ip, reason, duration)

            # Send Slack alert
            self.notifier.send_ban_alert(ip, reason, duration)

    def _get_duration(self, ban_count):
        """Return ban duration in minutes based on how many times IP was banned."""
        if ban_count < len(self.unban_schedule):
            return self.unban_schedule[ban_count]
        return -1  # permanent

    def _unban_loop(self):
        """Background thread that checks for IPs ready to be unbanned."""
        while True:
            time.sleep(30)  # Check every 30 seconds
            self._process_unbans()

    def _process_unbans(self):
        """Unban IPs whose ban duration has expired."""
        with self.lock:
            now = time.time()
            to_unban = []

            for ip, info in self.banned_ips.items():
                duration = self._get_duration(info["ban_count"])

                # Permanent ban — never unban
                if duration == -1:
                    continue

                # Check if ban duration has expired
                if now - info["banned_at"] >= duration * 60:
                    to_unban.append(ip)

            for ip in to_unban:
                self._unban(ip)

    def _unban(self, ip):
        """Remove iptables rule and update ban count."""
        result = subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[blocker] Failed to unban {ip}: {result.stderr}")
            return

        info = self.banned_ips[ip]
        new_ban_count = info["ban_count"] + 1
        duration = self._get_duration(info["ban_count"])

        print(f"[blocker] Unbanned {ip} | ban_count: {new_ban_count}")

        # Write to audit log
        write_audit("UNBAN", ip, info["reason"], duration)

        # Send Slack alert
        self.notifier.send_unban_alert(ip, duration)

        # Remove from banned list
        del self.banned_ips[ip]

    def get_banned_ips(self):
        """Return current list of banned IPs."""
        with self.lock:
            return dict(self.banned_ips)
