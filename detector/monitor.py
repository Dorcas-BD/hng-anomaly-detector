import time
import json
import os
from config import config

def tail_log(callback):
    log_path = config["nginx"]["log_path"]

    while not os.path.exists(log_path):
        print(f"[monitor] Waiting for log file at {log_path}...")
        time.sleep(2)

    print(f"[monitor] Log file found. Starting to tail {log_path}")

    with open(log_path, "r") as f:
        # Move to end of file
        f.seek(0, 2)
        print(f"[monitor] Seeked to end of file. Waiting for new lines...")

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.1)
                continue

            line = line.strip()
            print(f"[monitor] Raw line received: {line[:80]}")

            if not line:
                continue

            try:
                parsed = json.loads(line)
                print(f"[monitor] Parsed line: {parsed.get('source_ip')} {parsed.get('status')}")
                callback(parsed)
            except json.JSONDecodeError as e:
                print(f"[monitor] JSON parse error: {e} on line: {line[:80]}")
                continue
