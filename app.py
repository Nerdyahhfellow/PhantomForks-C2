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
import threading

from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename

from static_analysis import analyze_apk
from correlate import correlate
from verdict import build_verdict
from report import generate_pdf
from dynamic_analysis import DynamicAnalyzer

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

# Dynamic analysis runs against a real emulator and can take 1-2+ minutes,
# far too long to hold a request open, so it runs in a background thread and
# the frontend polls for status instead.
DYNAMIC_JOBS = {}


def _empty_network_report():
    return {
        "request_count": 0, "destinations": [], "beacons": [], "timeline": [], "network_score": 0,
        "behaviors": [], "evasion": {"attempted": False, "confidence": "none", "signals": []},
        "dropped_apks": [],
    }


def _empty_correlation_report():
    return {"confirmed": [], "dormant": [], "unclaimed": [], "verdict_notes": [],
            "summary": {"confirmed_count": 0, "dormant_count": 0, "unclaimed_count": 0}}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    apk_file = request.files.get("apk")

    if not apk_file or apk_file.filename == "":
        return jsonify({"error": "An APK file is required."}), 400

    case_id = uuid.uuid4().hex[:12]
    case_dir = os.path.join(UPLOAD_DIR, case_id)
    os.makedirs(case_dir, exist_ok=True)

    apk_filename = secure_filename(apk_file.filename)
    apk_path = os.path.join(case_dir, apk_filename)
    apk_file.save(apk_path)

    try:
        static_report = analyze_apk(apk_path)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Static analysis failed: {e}"}), 500

    network_report = _empty_network_report()
    correlation_report = _empty_correlation_report()
    verdict = build_verdict(static_report, network_report, correlation_report)

    result = {
        "case_id": case_id,
        "has_pcap": False,
        "apk_path": apk_path,
        "apk_filename": apk_filename,
        "static": static_report,
        "network": network_report,
        "correlation": correlation_report,
        "verdict": verdict,
    }

    CASES[case_id] = result

    # Dynamic analysis now runs automatically right alongside static
    # analysis rather than waiting for a separate button click. It's
    # emulator-driven and can take 1-2+ minutes, so it still runs in a
    # background thread and the frontend polls for status — we just kick
    # it off here instead of behind a second endpoint call.
    duration = 60
    job_id = uuid.uuid4().hex[:12]
    DYNAMIC_JOBS[job_id] = {"status": "queued", "case_id": case_id, "duration": duration}
    thread = threading.Thread(target=_run_dynamic_job, args=(job_id, case_id), daemon=True)
    thread.start()

    result["dynamic_job_id"] = job_id
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


def _run_dynamic_job(job_id, case_id):
    job = DYNAMIC_JOBS[job_id]
    case = CASES[case_id]
    try:
        job["status"] = "running"
        analyzer = DynamicAnalyzer(case["apk_path"], case["static"])
        job["analyzer"] = analyzer  # lets the status endpoint report live progress

        dynamic_result = analyzer.run_analysis(duration=job.get("duration", 60))

        if dynamic_result.get("error"):
            job["status"] = "error"
            job["error"] = dynamic_result["error"]
            return

        network_report = dynamic_result["network"]
        correlation_report = correlate(case["static"], network_report)
        verdict = build_verdict(case["static"], network_report, correlation_report)

        # Update the case in place so /api/report and the dashboard both
        # reflect the freshly-run dynamic findings.
        case["has_pcap"] = True
        case["network"] = network_report
        case["correlation"] = correlation_report
        case["verdict"] = verdict
        case["dynamic_meta"] = {
            "start_time": dynamic_result.get("start_time"),
            "end_time": dynamic_result.get("end_time"),
            "screenshots": dynamic_result.get("screenshots", []),
        }
        if dynamic_result.get("error"):
            case["dynamic_meta"]["warning"] = dynamic_result["error"]

        job["status"] = "completed"
        job["result"] = case
    except Exception as e:
        traceback.print_exc()
        job["status"] = "error"
        job["error"] = str(e)


@app.route("/api/dynamic-analyze/<case_id>", methods=["POST"])
def api_dynamic_analyze(case_id):
    """Kick off a real emulator-driven dynamic analysis run in the
    background. Requires an emulator image, adb, and (optionally) a running
    frida-server on the device — this will fail fast with a clear error if
    those aren't set up rather than hanging."""
    case = CASES.get(case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    if not case.get("apk_path") or not os.path.exists(case["apk_path"]):
        return jsonify({"error": "Original APK file is no longer available for this case."}), 400

    duration = int(request.json.get("duration", 60)) if request.is_json else 60
    duration = max(20, min(duration, 300))  # keep demo runs sane: 20s-5min

    job_id = uuid.uuid4().hex[:12]
    DYNAMIC_JOBS[job_id] = {"status": "queued", "case_id": case_id, "duration": duration}

    thread = threading.Thread(target=_run_dynamic_job, args=(job_id, case_id), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/dynamic-analyze/status/<job_id>")
def api_dynamic_analyze_status(job_id):
    job = DYNAMIC_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404

    analyzer = job.get("analyzer")
    progress = analyzer.progress if analyzer else job["status"]

    response = {"status": job["status"], "progress": progress}
    if job["status"] == "error":
        response["error"] = job.get("error", "Unknown error.")
    if job["status"] == "completed":
        response["result"] = job["result"]
    return jsonify(response)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
