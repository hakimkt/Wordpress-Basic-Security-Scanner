"""
app.py — Flask web interface for the WordPress Security Scanner.

Features:
  - Input URL and trigger scan via browser
  - Real-time progress updates via Server-Sent Events (SSE)
  - Results dashboard with risk-level highlighting
  - Scan history (saved JSON reports in scans/)
  - REST endpoint: POST /api/scan, GET /api/history, GET /api/report/<id>
"""

import json
import os
import threading
import uuid
import logging
import datetime
from pathlib import Path
from typing import Dict, Any

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import (
    Flask, render_template, request, jsonify,
    Response, abort, send_from_directory,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wp_scanner.app")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "wp-scanner-dev-key")

# In-memory scan state: {scan_id: {"status": ..., "events": [...], "report": ...}}
_scans: Dict[str, Dict] = {}
_scans_lock = threading.Lock()

SCANS_DIR = Path(__file__).parent / "scans"
SCANS_DIR.mkdir(exist_ok=True)


# ─── HTML Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/history")
def history():
    """Scan history page."""
    return render_template("index.html", page="history")


# ─── API: Start a scan ────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    POST /api/scan
    Body: {"url": "https://example.com", "delay": 0.6, "active_probe": true}
    Returns: {"scan_id": "..."}
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    delay        = float(data.get("delay", 0.6))
    active_probe = bool(data.get("active_probe", True))

    # Clamp delay to safe range
    delay = max(0.2, min(delay, 5.0))

    scan_id = str(uuid.uuid4())
    with _scans_lock:
        _scans[scan_id] = {
            "status": "queued",
            "url": url,
            "started": datetime.datetime.utcnow().isoformat(),
            "events": [],
            "report": None,
        }

    # Run the scan in a background thread
    t = threading.Thread(
        target=_run_scan,
        args=(scan_id, url, delay, active_probe),
        daemon=True,
    )
    t.start()
    logger.info("Scan %s started for %s", scan_id, url)

    return jsonify({"scan_id": scan_id})


def _run_scan(scan_id: str, url: str, delay: float, active_probe: bool):
    """Background thread that drives the scanner and stores events."""
    from scanner.core import Scanner

    scanner = Scanner(
        target_url=url,
        timeout=12,
        delay=delay,
        active_probe=active_probe,
        save_reports=True,
    )

    with _scans_lock:
        _scans[scan_id]["status"] = "running"

    try:
        for event in scanner.scan_with_progress():
            with _scans_lock:
                _scans[scan_id]["events"].append(event)
                if event["type"] == "complete":
                    _scans[scan_id]["status"] = "complete"
                    _scans[scan_id]["report"]  = event["report"]
                elif event["type"] == "error":
                    pass  # keep running; errors are stored in events
    except Exception as e:
        logger.exception("Scan %s crashed", scan_id)
        with _scans_lock:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["events"].append({
                "type": "error",
                "step": "scanner",
                "message": str(e),
            })


# ─── API: Stream progress via SSE ─────────────────────────────────────────────

@app.route("/api/scan/<scan_id>/stream")
def scan_stream(scan_id: str):
    """
    GET /api/scan/<scan_id>/stream
    Server-Sent Events stream delivering scan progress in real time.
    """
    if scan_id not in _scans:
        abort(404)

    def event_generator():
        delivered = 0
        import time

        while True:
            with _scans_lock:
                scan = _scans.get(scan_id, {})
                events = scan.get("events", [])
                status = scan.get("status", "unknown")

            # Deliver any new events
            while delivered < len(events):
                evt = events[delivered]
                delivered += 1
                # Serialise as SSE
                payload = json.dumps(evt, default=str)
                yield f"data: {payload}\n\n"

            if status in ("complete", "error"):
                yield "data: {\"type\": \"done\"}\n\n"
                break

            time.sleep(0.3)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # for Nginx
        },
    )


# ─── API: Get scan result ─────────────────────────────────────────────────────

@app.route("/api/scan/<scan_id>/result")
def scan_result(scan_id: str):
    """GET /api/scan/<scan_id>/result — Return the completed scan report as JSON."""
    if scan_id not in _scans:
        abort(404)
    scan = _scans[scan_id]
    if scan["status"] != "complete":
        return jsonify({"status": scan["status"]}), 202
    return jsonify(scan["report"])


# ─── API: Scan history ────────────────────────────────────────────────────────

@app.route("/api/history")
def scan_history():
    """GET /api/history — List saved scan reports from the scans/ directory."""
    reports = []
    for p in sorted(SCANS_DIR.glob("*.json"), reverse=True)[:50]:
        try:
            with open(p, encoding="utf-8") as f:
                r = json.load(f)
            meta = r.get("meta", {})
            risk = r.get("risk_summary", {})
            reports.append({
                "file":       p.name,
                "target":     meta.get("target", "?"),
                "scan_start": meta.get("scan_start", "?"),
                "duration_s": meta.get("duration_s", 0),
                "risk_score": r.get("risk_score", 0),
                "critical":   risk.get("Critical", 0),
                "high":       risk.get("High", 0),
                "medium":     risk.get("Medium", 0),
                "low":        risk.get("Low", 0),
                "total_findings": sum(risk.values()),
            })
        except Exception as e:
            logger.warning("Could not read %s: %s", p, e)

    return jsonify(reports)


@app.route("/api/history/<filename>")
def get_historical_report(filename: str):
    """GET /api/history/<filename> — Return a specific saved report."""
    safe_name = Path(filename).name   # prevent path traversal
    p = SCANS_DIR / safe_name
    if not p.exists() or p.suffix != ".json":
        abort(404)
    with open(p, encoding="utf-8") as f:
        return jsonify(json.load(f))


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="WP Scanner Web UI")
    ap.add_argument("--host",  default="127.0.0.1", help="Bind host")
    ap.add_argument("--port",  type=int, default=5000, help="Bind port")
    ap.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = ap.parse_args()

    print(f"\n  WP Security Scanner Web UI")
    print(f"  Open http://{args.host}:{args.port} in your browser\n")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
