import time
import os
from config import config

def write_audit(action, ip, condition, duration=None):
    """
    Write a structured audit log entry.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """
    log_path = config["logging"]["audit_log_path"]

    # Make sure the directory exists
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    duration_str = f"{duration}min" if duration and duration != -1 else "permanent"

    log_line = (
        f"[{timestamp}] {action} {ip} | "
        f"condition={condition} | "
        f"duration={duration_str}\n"
    )

    with open(log_path, "a") as f:
        f.write(log_line)

    print(f"[audit] {log_line.strip()}")
