import time
from config import config

class Detector:
    """
    Compares current request rates against the baseline.
    Flags anomalies based on z-score or rate multiplier — whichever fires first.
    Also tracks per-IP error rates and tightens thresholds when error surges occur.
    """
    def __init__(self, baseline_engine):
        self.baseline = baseline_engine
        self.z_threshold = config["detection"]["z_score_threshold"]
        self.rate_multiplier = config["detection"]["rate_multiplier"]
        self.error_multiplier = config["detection"]["error_rate_multiplier"]

        # Track per-IP error counts: {ip: [timestamp, ...]}
        self.ip_error_counts = {}
        self.ip_total_counts = {}

    def check_ip(self, ip, ip_rate, error_count, total_count):
        """
        Check if a specific IP is behaving anomalously.
        Returns (is_anomalous, reason) tuple.
        """
        mean, stddev = self.baseline.get_baseline()

        # Check if this IP has an error surge
        # If 4xx/5xx rate is 3x the baseline error rate, tighten thresholds
        tightened = False
        if total_count > 0:
            ip_error_rate = error_count / total_count
            baseline_error_rate = 0.1  # assume 10% baseline error rate
            if ip_error_rate >= baseline_error_rate * self.error_multiplier:
                tightened = True

        # Use tightened thresholds if error surge detected
        z_threshold = self.z_threshold * 0.5 if tightened else self.z_threshold
        rate_multiplier = self.rate_multiplier * 0.5 if tightened else self.rate_multiplier

        # Rule 1 — Z-score check
        if stddev > 0:
            z_score = (ip_rate - mean) / stddev
            if z_score > z_threshold:
                return True, (f"z_score={z_score:.2f} exceeded threshold={z_threshold:.2f} "
                             f"| rate={ip_rate} mean={mean:.2f} stddev={stddev:.2f}"
                             f"{' [tightened]' if tightened else ''}")

        # Rule 2 — Rate multiplier check
        if ip_rate > mean * rate_multiplier:
            return True, (f"rate={ip_rate} exceeded {rate_multiplier}x "
                         f"mean={mean:.2f}"
                         f"{' [tightened]' if tightened else ''}")

        return False, None

    def check_global(self, global_rate):
        """
        Check if overall traffic is anomalous.
        Returns (is_anomalous, reason) tuple.
        """
        mean, stddev = self.baseline.get_baseline()

        # Rule 1 — Z-score check
        if stddev > 0:
            z_score = (global_rate - mean) / stddev
            if z_score > self.z_threshold:
                return True, (f"GLOBAL z_score={z_score:.2f} exceeded "
                             f"threshold={self.z_threshold} "
                             f"| rate={global_rate} mean={mean:.2f} "
                             f"stddev={stddev:.2f}")

        # Rule 2 — Rate multiplier check
        if global_rate > mean * self.rate_multiplier:
            return True, (f"GLOBAL rate={global_rate} exceeded "
                         f"{self.rate_multiplier}x mean={mean:.2f}")

        return False, None
