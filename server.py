#!/usr/bin/env python3
"""
server.py — Web backend for the APK / C2 Threat Analysis platform.

Exposes:
  GET  /                    -> serves the dashboard (static/index.html)
  POST /api/analyze-apk     -> multipart upload of a .apk, runs apk_static_analyzer
  POST /api/analyze-pcap    -> multipart upload of a .pcap/.pcapng, runs beacon_detector
  GET  /api/health          -> simple liveness check

Combined verdict logic:
  When both an APK static report and a pcap beacon report exist for the same
  session, their scores are combined into one overall verdict band so an
  analyst gets a single answer instead of two disconnected numbers.

Run:
  pip install -r requirements.txt
  python server.py
  -> open http://localhost:5000
"""

import os
import traceback
import uuid

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

import apk_static_analyzer
import beacon_detector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_UPLOAD_MB = 200

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


def verdict_band(score):
    """Map a numeric risk score to a human verdict band. Bands are shared
    across APK-only, pcap-only, and combined scores so the UI can render
    them consistently."""
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "moderate"
    if score > 0:
        return "low"
    return "clean"


def save_upload(file_storage, allowed_exts):
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        return None, "No filename provided."
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed_exts:
        return None, f"Unsupported file type '{ext}'. Expected one of: {', '.join(allowed_exts)}"

    unique_name = f"{uuid.uuid4().hex}_{filename}"
    dest_path = os.path.join(UPLOAD_DIR, unique_name)
    file_storage.save(dest_path)
    return dest_path, None


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/analyze-apk", methods=["POST"])
def analyze_apk_route():
    if "file" not in request.files:
        return jsonify({"error": "No file field named 'file' in the request."}), 400

    dest_path, err = save_upload(request.files["file"], {".apk"})
    if err:
        return jsonify({"error": err}), 400

    try:
        report = apk_static_analyzer.build_report(dest_path)
        report["verdict"] = verdict_band(report["risk_score"])
        return jsonify({"ok": True, "report": report})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": f"Analysis failed: {e}"}), 500
    finally:
        try:
            os.remove(dest_path)
        except OSError:
            pass


@app.route("/api/analyze-pcap", methods=["POST"])
def analyze_pcap_route():
    if "file" not in request.files:
        return jsonify({"error": "No file field named 'file' in the request."}), 400

    dest_path, err = save_upload(request.files["file"], {".pcap", ".pcapng"})
    if err:
        return jsonify({"error": err}), 400

    interval_tolerance = float(request.form.get("interval_tolerance", 0.15))
    min_hits = int(request.form.get("min_hits", 3))

    try:
        findings, request_count = beacon_detector.build_report(
            dest_path, interval_tolerance=interval_tolerance, min_hits=min_hits
        )
        beacon_score = sum(f["score"] for f in findings)
        report = {
            "findings": findings,
            "request_count": request_count,
            "beacon_score": beacon_score,
            "verdict": verdict_band(beacon_score),
        }
        return jsonify({"ok": True, "report": report})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": f"Analysis failed: {e}"}), 500
    finally:
        try:
            os.remove(dest_path)
        except OSError:
            pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
