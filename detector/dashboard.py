import psutil
import time
import threading
from flask import Flask, jsonify, render_template_string
from config import config

app = Flask(__name__)

# These will be injected by main.py
_sliding_window = None
_baseline_engine = None
_blocker = None
_start_time = time.time()

def init_dashboard(sliding_window, baseline_engine, blocker):
    global _sliding_window, _baseline_engine, _blocker
    _sliding_window = sliding_window
    _baseline_engine = baseline_engine
    _blocker = blocker

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector — Live Dashboard</title>
    <meta charset="utf-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0a0a;
            color: #00ff88;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        h1 {
            font-size: 1.5em;
            margin-bottom: 20px;
            border-bottom: 1px solid #00ff88;
            padding-bottom: 10px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #111;
            border: 1px solid #00ff8844;
            border-radius: 8px;
            padding: 16px;
        }
        .card h2 {
            font-size: 0.85em;
            color: #888;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .metric {
            font-size: 2em;
            font-weight: bold;
            color: #00ff88;
        }
        .sub {
            font-size: 0.75em;
            color: #555;
            margin-top: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }
        th {
            text-align: left;
            color: #555;
            padding: 4px 8px;
            border-bottom: 1px solid #222;
        }
        td {
            padding: 4px 8px;
            border-bottom: 1px solid #1a1a1a;
        }
        .banned { color: #ff4444; }
        .status {
            font-size: 0.75em;
            color: #555;
            margin-top: 20px;
            text-align: right;
        }
        .alert { color: #ff4444; }
        .ok { color: #00ff88; }
    </style>
    <script>
        async function refresh() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();

                document.getElementById('global-rate').textContent =
                    data.global_rate + ' req/60s';
                document.getElementById('cpu').textContent =
                    data.cpu_percent + '%';
                document.getElementById('memory').textContent =
                    data.memory_percent + '%';
                document.getElementById('uptime').textContent =
                    data.uptime;
                document.getElementById('mean').textContent =
                    data.effective_mean.toFixed(2);
                document.getElementById('stddev').textContent =
                    data.effective_stddev.toFixed(2);
                document.getElementById('banned-count').textContent =
                    data.banned_ips.length + ' IPs';

                // Top IPs table
                let topHtml = '';
                data.top_ips.forEach((item, i) => {
                    topHtml += `<tr>
                        <td>${i+1}</td>
                        <td>${item.ip}</td>
                        <td>${item.count}</td>
                    </tr>`;
                });
                document.getElementById('top-ips-body').innerHTML = topHtml;

                // Banned IPs table
                let bannedHtml = '';
                if (data.banned_ips.length === 0) {
                    bannedHtml = '<tr><td colspan="3" style="color:#555">No banned IPs</td></tr>';
                } else {
                    data.banned_ips.forEach(item => {
                        bannedHtml += `<tr class="banned">
                            <td>${item.ip}</td>
                            <td>${item.duration}</td>
                            <td>${item.reason.substring(0, 40)}...</td>
                        </tr>`;
                    });
                }
                document.getElementById('banned-body').innerHTML = bannedHtml;

                document.getElementById('last-update').textContent =
                    'Last updated: ' + new Date().toISOString();
            } catch(e) {
                console.error('Refresh failed:', e);
            }
        }

        // Refresh every 3 seconds
        setInterval(refresh, 3000);
        refresh();
    </script>
</head>
<body>
    <h1>NG Anomaly Detector — Live Dashboard</h1>

    <div class="grid">
        <div class="card">
            <h2>Global Request Rate</h2>
            <div class="metric" id="global-rate">—</div>
            <div class="sub">requests in last 60 seconds</div>
        </div>
        <div class="card">
            <h2>CPU Usage</h2>
            <div class="metric" id="cpu">—</div>
            <div class="sub">percent</div>
        </div>
        <div class="card">
            <h2>Memory Usage</h2>
            <div class="metric" id="memory">—</div>
            <div class="sub">percent</div>
        </div>
        <div class="card">
            <h2>Uptime</h2>
            <div class="metric" id="uptime">—</div>
            <div class="sub">since daemon started</div>
        </div>
        <div class="card">
            <h2>Baseline Mean</h2>
            <div class="metric" id="mean">—</div>
            <div class="sub">requests/second (effective)</div>
        </div>
        <div class="card">
            <h2>Baseline Stddev</h2>
            <div class="metric" id="stddev">—</div>
            <div class="sub">standard deviation</div>
        </div>
        <div class="card">
            <h2>Banned IPs</h2>
            <div class="metric banned" id="banned-count">—</div>
            <div class="sub">currently blocked</div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Top 10 Source IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Requests (60s)</th>
                    </tr>
                </thead>
                <tbody id="top-ips-body">
                    <tr><td colspan="3" style="color:#555">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div class="card">
            <h2>Banned IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Duration</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody id="banned-body">
                    <tr><td colspan="3" style="color:#555">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="status" id="last-update">Loading...</div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/metrics")
def metrics():
    uptime_seconds = int(time.time() - _start_time)
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60

    mean, stddev = _baseline_engine.get_baseline()

    top_ips = [
        {"ip": ip, "count": len(list(window))}
        for ip, window in _sliding_window.get_top_ips(10)
    ]

    banned = _blocker.get_banned_ips()
    banned_list = []
    for ip, info in banned.items():
        duration = info["ban_count"]
        schedule = config["blocking"]["unban_schedule_minutes"]
        dur_str = f"{schedule[min(duration, len(schedule)-1)]}min"
        banned_list.append({
            "ip": ip,
            "duration": dur_str,
            "reason": info["reason"]
        })

    return jsonify({
        "global_rate": _sliding_window.get_global_rate(),
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "effective_mean": mean,
        "effective_stddev": stddev,
        "banned_ips": banned_list,
        "top_ips": top_ips
    })

def run_dashboard():
    port = config["dashboard"]["port"]
    app.run(host="0.0.0.0", port=port, debug=False)
