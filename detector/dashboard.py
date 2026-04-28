"""
dashboard.py
Serves a live web dashboard showing:
- Banned IPs and remaining ban time
- Global requests/sec
- Top 10 source IPs
- CPU and memory usage
- Effective mean/stddev
- Daemon uptime
Refreshes every 3 seconds via meta-refresh and AJAX.
"""

import time
import json
import logging
import psutil
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

logger = logging.getLogger(__name__)

# HTML template — single file, no external dependencies
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detector — Live Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Courier New', monospace;
    background: #0d1117;
    color: #c9d1d9;
    padding: 20px;
  }}
  h1 {{
    color: #58a6ff;
    font-size: 1.4rem;
    margin-bottom: 4px;
  }}
  .subtitle {{
    color: #8b949e;
    font-size: 0.8rem;
    margin-bottom: 20px;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    margin-bottom: 20px;
  }}
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
  }}
  .card h2 {{
    color: #58a6ff;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 12px;
    border-bottom: 1px solid #30363d;
    padding-bottom: 8px;
  }}
  .metric {{
    display: flex;
    justify-content: space-between;
    margin-bottom: 6px;
    font-size: 0.85rem;
  }}
  .metric .label {{ color: #8b949e; }}
  .metric .value {{ color: #e6edf3; font-weight: bold; }}
  .metric .value.danger {{ color: #f85149; }}
  .metric .value.warn   {{ color: #d29922; }}
  .metric .value.ok     {{ color: #3fb950; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }}
  th {{
    color: #8b949e;
    text-align: left;
    padding: 4px 8px;
    border-bottom: 1px solid #30363d;
  }}
  td {{
    padding: 4px 8px;
    border-bottom: 1px solid #21262d;
    color: #e6edf3;
  }}
  tr:hover td {{ background: #21262d; }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: bold;
  }}
  .badge.banned    {{ background: #3d1f1f; color: #f85149; }}
  .badge.permanent {{ background: #3d1f1f; color: #ff6e6e; }}
  .badge.ok        {{ background: #1a2f1a; color: #3fb950; }}
  #status-dot {{
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #3fb950;
    margin-right: 6px;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50%       {{ opacity: 0.4; }}
  }}
  .uptime {{ color: #3fb950; }}
  footer {{
    margin-top: 20px;
    color: #8b949e;
    font-size: 0.75rem;
    text-align: center;
  }}
</style>
</head>
<body>
<h1><span id="status-dot"></span>HNG Anomaly Detection Engine</h1>
<p class="subtitle">Auto-refreshes every 3 seconds &nbsp;|&nbsp; Last update: <span id="last-update">—</span></p>

<div class="grid">
  <!-- System metrics -->
  <div class="card">
    <h2>System</h2>
    <div class="metric">
      <span class="label">Uptime</span>
      <span class="value uptime" id="uptime">—</span>
    </div>
    <div class="metric">
      <span class="label">CPU usage</span>
      <span class="value" id="cpu">—</span>
    </div>
    <div class="metric">
      <span class="label">Memory usage</span>
      <span class="value" id="memory">—</span>
    </div>
    <div class="metric">
      <span class="label">Global req/s</span>
      <span class="value" id="global-rate">—</span>
    </div>
  </div>

  <!-- Baseline -->
  <div class="card">
    <h2>Baseline</h2>
    <div class="metric">
      <span class="label">Effective mean</span>
      <span class="value" id="baseline-mean">—</span>
    </div>
    <div class="metric">
      <span class="label">Effective stddev</span>
      <span class="value" id="baseline-std">—</span>
    </div>
    <div class="metric">
      <span class="label">Baseline ready</span>
      <span class="value" id="baseline-ready">—</span>
    </div>
    <div class="metric">
      <span class="label">Recalculations</span>
      <span class="value" id="recalc-count">—</span>
    </div>
    <div class="metric">
      <span class="label">Error baseline</span>
      <span class="value" id="error-baseline">—</span>
    </div>
  </div>

  <!-- Banned IPs count -->
  <div class="card">
    <h2>Bans</h2>
    <div class="metric">
      <span class="label">Currently banned</span>
      <span class="value danger" id="banned-count">—</span>
    </div>
    <div class="metric">
      <span class="label">Total bans issued</span>
      <span class="value" id="total-bans">—</span>
    </div>
    <div class="metric">
      <span class="label">Permanent bans</span>
      <span class="value danger" id="perm-bans">—</span>
    </div>
  </div>
</div>

<!-- Banned IPs table -->
<div class="card" style="margin-bottom:16px">
  <h2>Banned IPs</h2>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Status</th>
        <th>Offences</th>
        <th>Unban In</th>
      </tr>
    </thead>
    <tbody id="banned-table">
      <tr><td colspan="4" style="color:#8b949e">No bans active</td></tr>
    </tbody>
  </table>
</div>

<!-- Top 10 IPs -->
<div class="card" style="margin-bottom:16px">
  <h2>Top 10 Source IPs (by req/s)</h2>
  <table>
    <thead>
      <tr><th>IP Address</th><th>Rate (req/s)</th></tr>
    </thead>
    <tbody id="top-ips-table">
      <tr><td colspan="2" style="color:#8b949e">No traffic yet</td></tr>
    </tbody>
  </table>
</div>

<!-- Hourly slots -->
<div class="card" style="margin-bottom:16px">
  <h2>Hourly Baseline Slots</h2>
  <table>
    <thead>
      <tr><th>Hour</th><th>Samples</th><th>Mean</th><th>Stddev</th><th>Status</th></tr>
    </thead>
    <tbody id="hourly-table">
      <tr><td colspan="5" style="color:#8b949e">Building baseline...</td></tr>
    </tbody>
  </table>
</div>

<footer>HNG Stage 3 — Anomaly Detection Engine &nbsp;|&nbsp; Built by Oluwaferanmiwhitehat</footer>

<script>
async function refresh() {{
  try {{
    const r    = await fetch('/api/metrics');
    const data = await r.json();

    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    document.getElementById('uptime').textContent      = data.uptime;
    document.getElementById('cpu').textContent         = data.cpu + '%';
    document.getElementById('memory').textContent      = data.memory + '%';
    document.getElementById('global-rate').textContent = data.global_rate + ' req/s';
    document.getElementById('baseline-mean').textContent   = data.baseline_mean + ' req/s';
    document.getElementById('baseline-std').textContent    = data.baseline_std + ' req/s';
    document.getElementById('baseline-ready').textContent  = data.baseline_ready ? 'Yes' : 'Building...';
    document.getElementById('recalc-count').textContent    = data.recalc_count;
    document.getElementById('error-baseline').textContent  = (data.error_baseline * 100).toFixed(2) + '%';
    document.getElementById('banned-count').textContent    = data.banned_count;
    document.getElementById('total-bans').textContent      = data.total_bans;
    document.getElementById('perm-bans').textContent       = data.permanent_bans;

    // Banned IPs table
    const bt = document.getElementById('banned-table');
    if (data.banned_ips.length === 0) {{
      bt.innerHTML = '<tr><td colspan="4" style="color:#8b949e">No bans active</td></tr>';
    }} else {{
      bt.innerHTML = data.banned_ips.map(b => `
        <tr>
          <td>${{b.ip}}</td>
          <td><span class="badge ${{b.permanent ? 'permanent' : 'banned'}}">${{b.permanent ? 'PERMANENT' : 'BANNED'}}</span></td>
          <td>${{b.offences}}</td>
          <td>${{b.permanent ? '∞' : b.remaining_s + 's'}}</td>
        </tr>`).join('');
    }}

    // Top IPs table
    const tt = document.getElementById('top-ips-table');
    if (data.top_ips.length === 0) {{
      tt.innerHTML = '<tr><td colspan="2" style="color:#8b949e">No traffic yet</td></tr>';
    }} else {{
      tt.innerHTML = data.top_ips.map(t => `
        <tr>
          <td>${{t.ip}}</td>
          <td>${{t.rate}}</td>
        </tr>`).join('');
    }}

    // Hourly slots
    const ht = document.getElementById('hourly-table');
    if (data.hourly_slots.length === 0) {{
      ht.innerHTML = '<tr><td colspan="5" style="color:#8b949e">Building baseline...</td></tr>';
    }} else {{
      ht.innerHTML = data.hourly_slots.map(h => `
        <tr>
          <td>${{String(h.hour).padStart(2,'0')}}:00</td>
          <td>${{h.samples}}</td>
          <td>${{h.mean}}</td>
          <td>${{h.stddev}}</td>
          <td><span class="badge ${{h.computed ? 'ok' : 'banned'}}">${{h.computed ? 'READY' : 'BUILDING'}}</span></td>
        </tr>`).join('');
    }}

  }} catch(e) {{
    console.error('Refresh failed:', e);
  }}
}}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    def __init__(self, *args, state=None, **kwargs):
        self.state = state
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        # Suppress default HTTP server logs — they're noisy
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._serve_html()
        elif self.path == "/api/metrics":
            self._serve_metrics()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_html(self):
        content = DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)

    def _serve_metrics(self):
        """Build and return JSON metrics payload."""
        s    = self.state
        now  = time.time()

        # Uptime
        elapsed = int(now - s["start_time"])
        h, rem  = divmod(elapsed, 3600)
        m, sec  = divmod(rem, 60)
        uptime  = f"{h:02d}h {m:02d}m {sec:02d}s"

        # Banned IPs
        pending     = s["unbanner"].get_pending()
        perm_count  = sum(1 for p in pending if p["permanent"])
        total_bans  = s.get("total_bans", 0)

        payload = {
            "uptime":         uptime,
            "cpu":            psutil.cpu_percent(interval=None),
            "memory":         psutil.virtual_memory().percent,
            "global_rate":    s["detector"].get_global_rate(),
            "baseline_mean":  round(s["baseline"].effective_mean, 3),
            "baseline_std":   round(s["baseline"].effective_stddev, 3),
            "baseline_ready": s["baseline"].is_ready(),
            "recalc_count":   s["baseline"].recalc_count,
            "error_baseline": round(s["baseline"].get_error_baseline(), 4),
            "banned_count":   len(pending),
            "total_bans":     total_bans,
            "permanent_bans": perm_count,
            "banned_ips":     pending,
            "top_ips":        s["detector"].get_top_ips(10),
            "hourly_slots":   s["baseline"].get_hourly_slots(),
        }

        content = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(content))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)


class Dashboard:
    """Wraps the HTTP server in a background thread."""

    def __init__(self, config: dict, state: dict):
        self.host  = config["dashboard"]["host"]
        self.port  = config["dashboard"]["port"]
        self.state = state
        self._server  = None
        self._thread  = None

    def start(self):
        def handler(*args, **kwargs):
            DashboardHandler(*args, state=self.state, **kwargs)

        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="dashboard"
        )
        self._thread.start()
        logger.info(f"[DASHBOARD] Serving on http://{self.host}:{self.port}")

    def stop(self):
        if self._server:
            self._server.shutdown()
