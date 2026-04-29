# HNG Anomaly Detection Engine

A real-time DDoS and anomaly detection daemon built for HNG Stage 3 DevOps task.
Monitors Nginx HTTP traffic, learns normal baselines, and automatically blocks
suspicious IPs using iptables.

## Live Details
- **Server IP (Nextcloud):** 35.168.16.250
- **Metrics Dashboard:** http://dorcasbd.duckdns.org:8080
- **GitHub:** https://github.com/Dorcas-BD/hng-anomaly-detector

## Language Choice
Python — chosen for rapid development, readable code, and strong support
for the data structures needed (deque, defaultdict). The collections module
makes sliding window implementation clean and efficient.

## How the Sliding Window Works
Two deque-based windows run continuously:
- `global_window` — every request from every IP
- `per_ip_window` — one deque per IP address

Every new request appends a Unix timestamp to the right of the deque.
An eviction function removes entries from the left that are older than
60 seconds. At any moment, `len(deque)` gives the request rate for
the last 60 seconds. This is O(1) for both insertion and eviction.

## How the Baseline Works
- Rolling 30-minute window of per-second request counts (max 1800 entries)
- Recalculated every 60 seconds using mean and standard deviation
- Per-hour slots maintained so 3am traffic is compared to 3am baseline
- Floor values (mean=1.0, stddev=0.5) prevent division by zero on startup
- Current hour's data preferred when it has enough data points (>10)

## Detection Logic
An IP or global rate is flagged anomalous if either fires first:
1. Z-score > 3.0: `(current_rate - mean) / stddev > 3.0`
2. Rate > 5x baseline mean: `current_rate > mean * 5`

If an IP's 4xx/5xx rate is 3x the baseline error rate, thresholds
are tightened by 50% automatically.

## How iptables Blocking Works
When an anomaly is detected for a specific IP:
1. `iptables -I INPUT -s <ip> -j DROP` is executed immediately
2. The kernel silently drops all packets from that IP
3. A Slack alert is sent within 10 seconds
4. Auto-unban fires on a backoff schedule: 10min → 30min → 2hrs → permanent

## Setup Instructions

### 1. Provision a Linux VPS (Ubuntu 22.04, 2 vCPU, 2GB RAM minimum)

### 2. Install Docker
```bash
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh
sudo usermod -aG docker ubuntu
newgrp docker
sudo apt install docker-compose-plugin -y
```

### 3. Clone the repo
```bash
git clone https://github.com/Dorcas-BD/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 4. Configure
```bash
cp detector/config.yaml.example detector/config.yaml
nano detector/config.yaml  # Add your Slack webhook URL
```

### 5. Start Nextcloud + Nginx
```bash
docker compose up -d
```

### 6. Set up Python environment
```bash
cd detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 7. Run the daemon
```bash
sudo /home/ubuntu/hng-anomaly-detector/detector/venv/bin/python3 \
  /home/ubuntu/hng-anomaly-detector/detector/main.py
```

### 8. View the dashboard
Open http://your-server-ip:8080 in your browser.

## Repository Structure
detector/
      main.py        — entry point, ties all components together
      monitor.py     — tails and parses Nginx access log
      baseline.py    — sliding window and rolling baseline engine
      detector.py    — anomaly detection logic (z-score + multiplier)
      blocker.py     — iptables ban/unban management
      notifier.py    — Slack alert sender
      dashboard.py   — Flask live metrics web UI
      audit.py       — structured audit log writer
      config.yaml    — all thresholds and configuration
      requirements.txt
    nginx/
      nginx.conf     — reverse proxy config with JSON logging
    docs/
      architecture.png
    screenshots/
    README.md
