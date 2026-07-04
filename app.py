#!/usr/bin/env python3
"""
app.py — Third Eye (Flask web app)

Wires together:
  analyzer/static_analysis.py  -> analyze_apk()
  analyzer/network_analysis.py -> analyze_pcap()
  analyzer/correlate.py        -> correlate()
  analyzer/verdict.py          -> build_verdict()   (unified 0-10 score)
  analyzer/report.py           -> generate_pdf()

Run with:
    python app.py
Then open http://127.0.0.1:5000
"""

import os
import uuid
import traceback

from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename

from static_analysis import analyze_apk
from network_analysis import analyze_pcap
from correlate import correlate
from verdict import build_verdict
from report import generate_pdf

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Everything (HTML, CSS, JS, Python) lives in this same flat folder, so both
# the template loader and the static file server point at BASE_DIR directly.
app = Flask(__name__, template_folder=BASE_DIR, static_folder=BASE_DIR, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024  # 300 MB

# In-memory case store — fine for a hackathon demo; swap for a DB/session
# store if this needs to survive a server restart.
CASES = {}


def _empty_network_report():
    return {"request_count": 0, "destinations": [], "beacons": [], "timeline": [], "network_score": 0}


def _empty_correlation_report():
    return {"confirmed": [], "dormant": [], "unclaimed": [], "verdict_notes": [],
            "summary": {"confirmed_count": 0, "dormant_count": 0, "unclaimed_count": 0}}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    apk_file = request.files.get("apk")
    pcap_file = request.files.get("pcap")

    if not apk_file or apk_file.filename == "":
        return jsonify({"error": "An APK file is required."}), 400

    case_id = uuid.uuid4().hex[:12]
    case_dir = os.path.join(UPLOAD_DIR, case_id)
    os.makedirs(case_dir, exist_ok=True)

    apk_filename = secure_filename(apk_file.filename)
    apk_path = os.path.join(case_dir, apk_filename)
    apk_file.save(apk_path)

    pcap_path = None
    if pcap_file and pcap_file.filename != "":
        pcap_filename = secure_filename(pcap_file.filename)
        pcap_path = os.path.join(case_dir, pcap_filename)
        pcap_file.save(pcap_path)

    try:
        static_report = analyze_apk(apk_path)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Static analysis failed: {e}"}), 500

    if pcap_path:
        try:
            network_report = analyze_pcap(pcap_path)
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": f"Network analysis failed: {e}"}), 500
        correlation_report = correlate(static_report, network_report)
    else:
        network_report = _empty_network_report()
        correlation_report = _empty_correlation_report()

    verdict = build_verdict(static_report, network_report, correlation_report)

    result = {
        "case_id": case_id,
        "has_pcap": pcap_path is not None,
        "static": static_report,
        "network": network_report,
        "correlation": correlation_report,
        "verdict": verdict,
    }

    CASES[case_id] = result
    return jsonify(result)


@app.route("/api/report/<case_id>/pdf")
def api_report_pdf(case_id):
    case = CASES.get(case_id)
    if not case:
        return jsonify({"error": "Case not found. Please re-run the analysis."}), 404

    pdf_bytes = generate_pdf(
        case["static"], case["network"], case["correlation"], case["verdict"]
    )

    report_path = os.path.join(UPLOAD_DIR, case_id, "forensic_report.pdf")
    with open(report_path, "wb") as f:
        f.write(pdf_bytes)

    return send_file(report_path, as_attachment=True,
                      download_name=f"forensic_report_{case_id}.pdf",
                      mimetype="application/pdf")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
