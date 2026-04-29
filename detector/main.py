import threading
import time
import sys
from config import config
from monitor import tail_log
from baseline import SlidingWindow, BaselineEngine
from detector import Detector
from blocker import Blocker
from notifier import Notifier
from dashboard import init_dashboard, run_dashboard
from audit import write_audit

# Track per-IP error counts for error surge detection
ip_error_counts = {}
ip_total_counts = {}

def main():
    print("[main] Starting HNG Anomaly Detection Engine...")

    # Initialize all components
    notifier = Notifier()
    sliding_window = SlidingWindow()
    baseline_engine = BaselineEngine()
    detector = Detector(baseline_engine)
    blocker = Blocker(notifier)

    # Inject components into dashboard
    init_dashboard(sliding_window, baseline_engine, blocker)

    # Start dashboard in background thread
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        daemon=True
    )
    dashboard_thread.start()
    print(f"[main] Dashboard running on port {config['dashboard']['port']}")

    # Track last time we checked global anomaly
    last_global_check = time.time()

    def process_line(line):
        """
        Called for every new log line from Nginx.
        This is the heart of the daemon.
        """
        nonlocal last_global_check

        # Extract fields from parsed JSON log line
        ip = line.get("source_ip", "").strip()
        timestamp_str = line.get("timestamp", "")
        status = line.get("status", 200)

        # Skip empty or invalid IPs
        if not ip or ip == "-":
            return

        # Use current time as the timestamp for the sliding window
        now = time.time()

        # Record in sliding window and baseline
        sliding_window.add(ip, now)
        baseline_engine.record(now)

        # Track error counts per IP
        if ip not in ip_total_counts:
            ip_total_counts[ip] = 0
            ip_error_counts[ip] = 0

        ip_total_counts[ip] += 1
        if isinstance(status, int) and status >= 400:
            ip_error_counts[ip] += 1

        # Get current rates
        ip_rate = sliding_window.get_ip_rate(ip)

        # Check per-IP anomaly
        is_anomalous, reason = detector.check_ip(
            ip,
            ip_rate,
            ip_error_counts.get(ip, 0),
            ip_total_counts.get(ip, 0)
        )

        if is_anomalous:
            print(f"[main] Anomaly detected for IP {ip}: {reason}")
            blocker.ban(ip, reason)

        # Check global anomaly every 5 seconds
        if now - last_global_check >= 5:
            last_global_check = now
            global_rate = sliding_window.get_global_rate()
            is_global_anomaly, global_reason = detector.check_global(global_rate)

            if is_global_anomaly:
                print(f"[main] GLOBAL anomaly detected: {global_reason}")
                notifier.send_global_alert(global_reason)
                write_audit("GLOBAL_ANOMALY", "ALL", global_reason, None)

    # Start tailing the log — this runs forever
    print("[main] Starting log monitor...")
    try:
        tail_log(process_line)
    except KeyboardInterrupt:
        print("[main] Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()
