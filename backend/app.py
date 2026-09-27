"""
Flask Backend — REST API (Person 4 — Part 2)
===============================================
Provides REST API endpoints for the NSM dashboard:

  GET  /api/alerts         — Returns recent security alerts
  GET  /api/traffic-stats  — Returns traffic statistics
  GET  /api/summary        — Returns attack type counts
  POST /api/upload          — Upload and analyze a PCAP file
  POST /api/analyze         — Analyze the default sample.pcap
  GET  /api/status          — Check if the server is running

Usage:
    cd nsm-platform
    .\\venv\\Scripts\\python.exe backend\\app.py

    Then open http://localhost:5000 in your browser.
"""

import os
import sys
import uuid

# Add project root to path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from backend.database import Database
from capture.packet_parser import parse_pcap
from detection.detector import detect_all
from anomaly.extra_rules import detect_extra


# ──────────────────────────────────────────
# APP SETUP
# ──────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow dashboard (different port) to access the API

# Initialize database
db = Database()

# Folder to store uploaded PCAP files
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "sample_pcaps")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ──────────────────────────────────────────
# HELPER: Run the full analysis pipeline
# ──────────────────────────────────────────
def run_analysis(pcap_path, filename="unknown.pcap"):
    """
    Runs the complete pipeline: parse PCAP -> detect attacks -> store in DB.
    Returns a summary dictionary.
    """
    # Step 1: Parse the PCAP
    packets = parse_pcap(pcap_path)

    # Step 2: Run core detection rules
    alerts = detect_all(packets)

    # Step 3: Run extra/additional detection rules (Person 3)
    extra_alerts = detect_extra(packets)
    alerts.extend(extra_alerts)

    # Step 4: Generate a unique ID for this analysis run
    analysis_id = uuid.uuid4().hex[:8]

    # Step 5: Store everything in the database
    db.insert_alerts_batch(alerts)
    db.insert_traffic_stats(analysis_id, packets)
    db.insert_analysis_run(analysis_id, filename, len(packets), len(alerts))

    return {
        "analysis_id": analysis_id,
        "filename": filename,
        "total_packets": len(packets),
        "total_alerts": len(alerts),
        "status": "completed",
    }


# ──────────────────────────────────────────
# API ROUTES
# ──────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def api_status():
    """Health check — confirms the server is running."""
    return jsonify({
        "status": "active",
        "message": "NSM Platform API is running",
    })


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    GET /api/alerts
    Returns the most recent security alerts from the database.
    Optional query param: ?limit=20 (default 50)
    """
    limit = request.args.get("limit", 50, type=int)
    alerts = db.get_alerts(limit=limit)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/traffic-stats", methods=["GET"])
def api_traffic_stats():
    """
    GET /api/traffic-stats
    Returns traffic statistics (protocol breakdown, packet counts).
    """
    stats = db.get_traffic_stats()
    total_packets = db.get_total_packets()
    return jsonify({
        "stats": stats,
        "total_packets": total_packets,
    })


@app.route("/api/summary", methods=["GET"])
def api_summary():
    """
    GET /api/summary
    Returns attack counts grouped by type.
    Example: {"port_scan": 12, "brute_force": 4, "syn_flood": 1}
    """
    summary = db.get_summary()
    severity_counts = db.get_severity_counts()
    total_packets = db.get_total_packets()
    total_alerts = sum(summary.values()) if summary else 0

    return jsonify({
        "attack_counts": summary,
        "severity_counts": severity_counts,
        "total_packets": total_packets,
        "total_alerts": total_alerts,
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    POST /api/upload
    Upload a PCAP file, analyze it, and store results.
    Expects: multipart form-data with a file field named 'pcap'
    """
    if "pcap" not in request.files:
        return jsonify({"error": "No file uploaded. Send a file with field name 'pcap'."}), 400

    file = request.files["pcap"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    # Save the uploaded file
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    print(f"[+] Uploaded PCAP saved: {filepath}")

    # Run analysis
    try:
        result = run_analysis(filepath, filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    POST /api/analyze
    Analyze the default sample.pcap or a specified file.
    Optional JSON body: {"filename": "sample.pcap"}
    """
    # Get filename from request body, default to sample.pcap
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "sample.pcap")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": f"File not found: {filename}"}), 404

    try:
        result = run_analysis(filepath, filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """
    POST /api/clear
    Clears all data from the database (useful for re-running demos).
    """
    db.clear_all()
    return jsonify({"message": "All data cleared successfully."})


# ──────────────────────────────────────────
# SERVE THE DASHBOARD (so everything runs on one server)
# ──────────────────────────────────────────
DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")


@app.route("/")
def serve_dashboard():
    """Serves the main dashboard HTML page."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    """Serves static files (CSS, JS) from the dashboard folder."""
    return send_from_directory(DASHBOARD_DIR, filename)


# ──────────────────────────────────────────
# RUN THE SERVER
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  NSM Platform - Flask Server")
    print("=" * 50)
    print(f"  Dashboard:  http://localhost:5000")
    print(f"  API Base:   http://localhost:5000/api")
    print(f"  Database:   {db.db_path}")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
