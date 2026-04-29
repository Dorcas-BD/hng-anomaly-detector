import time
import math
from collections import deque, defaultdict
from config import config

class SlidingWindow:
    def __init__(self):
        self.duration = config["sliding_window"]["duration_seconds"]
        self.global_window = deque()
        self.per_ip_window = defaultdict(deque)

    def add(self, ip, timestamp):
        self.global_window.append(timestamp)
        self.per_ip_window[ip].append(timestamp)
        self._evict()

    def _evict(self):
        cutoff = time.time() - self.duration
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()
        for ip in list(self.per_ip_window.keys()):
            while self.per_ip_window[ip] and self.per_ip_window[ip][0] < cutoff:
                self.per_ip_window[ip].popleft()
            if not self.per_ip_window[ip]:
                del self.per_ip_window[ip]

    def get_global_rate(self):
        self._evict()
        return len(self.global_window)

    def get_ip_rate(self, ip):
        self._evict()
        return len(self.per_ip_window.get(ip, []))

    def get_top_ips(self, n=10):
        self._evict()
        return sorted(
            self.per_ip_window.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:n]


class BaselineEngine:
    def __init__(self):
        self.window_minutes = config["baseline"]["window_minutes"]
        self.recalc_interval = config["baseline"]["recalculation_interval"]
        self.min_data_points = config["baseline"]["min_data_points"]
        self.floor_mean = config["baseline"]["floor_mean"]
        self.floor_stddev = config["baseline"]["floor_stddev"]

        self.per_second_counts = deque(maxlen=self.window_minutes * 60)
        self.hourly_slots = defaultdict(lambda: {
            "mean": self.floor_mean,
            "stddev": self.floor_stddev,
            "counts": deque(maxlen=3600)
        })

        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev
        self.last_recalc = time.time()
        self.current_second_count = 0
        self.current_second = int(time.time())

    def record(self, timestamp):
        second = int(timestamp)
        if second != self.current_second:
            self.per_second_counts.append(self.current_second_count)
            hour = time.gmtime(self.current_second).tm_hour
            self.hourly_slots[hour]["counts"].append(self.current_second_count)
            self.current_second_count = 0
            self.current_second = second
        self.current_second_count += 1
        if time.time() - self.last_recalc >= self.recalc_interval:
            self._recalculate()

    def _recalculate(self):
        current_hour = time.gmtime().tm_hour
        hourly = self.hourly_slots[current_hour]
        if len(hourly["counts"]) >= self.min_data_points:
            counts = list(hourly["counts"])
        elif len(self.per_second_counts) >= self.min_data_points:
            counts = list(self.per_second_counts)
        else:
            self.last_recalc = time.time()
            return
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        stddev = math.sqrt(variance)
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)
        hourly["mean"] = self.effective_mean
        hourly["stddev"] = self.effective_stddev
        self.last_recalc = time.time()
        print(f"[baseline] Recalculated — mean={self.effective_mean:.2f} "
              f"stddev={self.effective_stddev:.2f} samples={len(counts)}")

    def get_baseline(self):
        return self.effective_mean, self.effective_stddev
