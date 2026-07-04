#!/usr/bin/env python3
"""
app.py — Unified Threat Analysis Platform (APK + PCAP)
"""

import os
import re
import sys
import uuid
import json
import statistics
import traceback
import argparse
from collections import defaultdict

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

# --- ANDROGUARD SETUP ---
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="ERROR")
    from androguard.misc import AnalyzeAPK
except ImportError:
    sys.exit("androguard is required: pip install androguard")

# --- SCAPY SETUP ---
try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    sys.exit("scapy is required: pip install scapy")

# =====================================================================
# CONFIGURATION
# =====================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_UPLOAD_MB = 200

# APK Config
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Can read SMS messages (often used to steal OTPs/2FA codes)",
    "android.permission.SEND_SMS": "Can send SMS silently (premium-rate fraud, OTP interception)",
    "android.permission.RECEIVE_SMS": "Can intercept incoming SMS",
    "android.permission.READ_CONTACTS": "Can read contact list",
    "android.permission.CALL_PHONE": "Can place phone calls without user interaction",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps (overlay/phishing attacks)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Can read screen content & simulate input",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can install other APKs (dropper behavior)",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Can auto-start on device boot (persistence)",
    "android.permission.BIND_DEVICE_ADMIN": "Can request device admin rights",
    "android.permission.READ_PHONE_STATE": "Can read device identifiers",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Broad file system write access",
    "android.permission.CAMERA": "Can access camera",
    "android.permission.RECORD_AUDIO": "Can record audio",
    "android.permission.ACCESS_FINE_LOCATION": "Can access precise GPS location",
}
LOW_FUNCTIONALITY_HINTS = ["calculator", "flashlight", "wallpaper", "notes", "scanner_lite"]
URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUSPICIOUS_STRING_KEYWORDS = ["cmd=", "gate.php", "beacon", "exec(", "Runtime.getRuntime"]

# PCAP Config
SUSPICIOUS_UA_PATTERNS = [
    r"^Dalvik/\d", r"^python-requests", r"^curl/", r"^Wget/", r"^$"
]
ALLOWLIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "android.com",
    "apple.com", "microsoft.com", "cloudflare.com", "akamai.net",
}

# =====================================================================
# APK ANALYSIS LOGIC
# =====================================================================

def build_apk_report(apk_path):
    a, d_list, dx = AnalyzeAPK(apk_path)

    # 1. Permissions
    declared = a.get_permissions()
    dangerous_perms = [{"permission": p, "reason": DANGEROUS_PERMISSIONS[p]} for p in declared if p in DANGEROUS_PERMISSIONS]

    # 2. Mismatch
    app_name = (a.get_app_name() or "").lower()
    package = a.get_package().lower()
    hint_hit = any(h in app_name or h in package for h in LOW_FUNCTIONALITY_HINTS)
    mismatch = f"App name/package suggests simple utility ('{app_name or package}') but requests {len(dangerous_perms)} dangerous permission(s)." if hint_hit and dangerous_perms else None

    # 3. Exported Components
    exported_findings = []
    for tag, comp_type in [("activity", "activity"), ("service", "service"), ("receiver", "receiver"), ("provider", "provider")]:
        for node in a.get_android_manifest_xml().findall(f".//{tag}"):
            android_ns = "{http://schemas.android.com/apk/res/android}"
            name = node.get(f"{android_ns}name")
            exported = node.get(f"{android_ns}exported")
            permission = node.get(f"{android_ns}permission")
            is_exported = exported == "true" or (exported is None and node.find("intent-filter") is not None)
            if is_exported and not permission:
                exported_findings.append({"type": comp_type, "name": name, "issue": "exported with no permission guard"})

    # 4. IOC Strings
    urls, ips, suspicious_kw = set(), set(), set()
    for d in d_list:
        for s in d.get_strings():
            s = str(s)
            urls.update(URL_REGEX.findall(s))
            ips.update([m for m in IP_REGEX.findall(s) if all(0 <= int(o) <= 255 for o in m.split("."))])
            suspicious_kw.update([kw for kw in SUSPICIOUS_STRING_KEYWORDS if kw.lower() in s.lower()])
    urls = {u for u in urls if "schemas.android.com" not in u and "w3.org" not in u}

    # 5. Signing
    signing_findings = []
    try:
        certs = a.get_certificates()
        if not certs: signing_findings.append("APK does not appear to be signed.")
        for cert in certs:
            subject = getattr(cert.subject, 'human_friendly', str(cert.subject))
            if "Android Debug" in subject or "androiddebugkey" in subject.lower():
                signing_findings.append(f"Signed with DEBUG certificate: {subject}")
    except Exception as e:
        signing_findings.append(f"Could not parse cert: {e}")

    # 6. Score
    score = (len(dangerous_perms) * 2) + (len(exported_findings) * 2) + (len(ips) * 2) + len(urls) + (len(suspicious_kw) * 3) + (len(signing_findings) * 2) + (3 if mismatch else 0)

    return {
        "package": a.get_package(), "app_name": a.get_app_name(),
        "declared_permissions": declared, "dangerous_permissions": dangerous_perms,
        "category_mismatch": mismatch, "exported_components": exported_findings,
        "exported_issue_count": len(exported_findings),
        "urls": sorted(urls), "ips": sorted(ips), "suspicious_keywords": sorted(suspicious_kw),
        "signing": signing_findings, "risk_score": score,
    }

# =====================================================================
# PCAP ANALYSIS LOGIC
# =====================================================================

def build_pcap_report(pcap_path, interval_tolerance=0.15, min_hits=3):
    packets = rdpcap(pcap_path)
    requests = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)): continue
        try:
            text = bytes(pkt[Raw].load).decode(errors="ignore")
        except Exception: continue
        if not (text.startswith("GET ") or text.startswith("POST ")): continue
        
        first_line = re.match(r"(GET|POST) (\S+) HTTP/1\.\d", text)
        if not first_line: continue

        host_match = re.search(r"Host:\s*([^\r\n]+)", text)
        ua_match = re.search(r"User-Agent:\s*([^\r\n]+)", text)
        
        requests.append({
            "time": float(pkt.time), "src": pkt[IP].src, "dst": pkt[IP].dst,
            "host": host_match.group(1).strip() if host_match else pkt[IP].dst,
            "path": first_line.group(2), "ua": ua_match.group(1).strip() if ua_match else "",
        })

    groups = defaultdict(list)
    for r in requests: groups[(r["host"], r["path"])].append(r)

    findings = []
    for (host, path), reqs in groups.items():
        reqs.sort(key=lambda r: r["time"])
        if len(reqs) < min_hits: continue

        deltas = [reqs[i + 1]["time"] - reqs[i]["time"] for i in range(len(reqs) - 1)]
        if len(deltas) < 2: continue

        mean_delta = statistics.mean(deltas)
        stdev_delta = statistics.pstdev(deltas)
        jitter_ratio = (stdev_delta / mean_delta) if mean_delta > 0 else 1.0

        is_periodic = jitter_ratio <= interval_tolerance
        ua_flag = any(re.match(p, reqs[0]["ua"]) for p in SUSPICIOUS_UA_PATTERNS)
        allowlisted = any(host.endswith(d) for d in ALLOWLIST_DOMAINS)

        score, reasons = 0, []
        if is_periodic:
            score += 2; reasons.append(f"periodic beaconing (avg interval {mean_delta:.1f}s, jitter {jitter_ratio*100:.1f}%)")
        if ua_flag:
            score += 2; reasons.append(f"suspicious User-Agent: '{reqs[0]['ua']}'")
        if not allowlisted:
            score += 1; reasons.append("destination not in known-safe allowlist")

        if score >= 2:
            findings.append({
                "host": host, "path": path, "hits": len(reqs), "mean_interval": mean_delta,
                "jitter_ratio": jitter_ratio, "user_agent": reqs[0]["ua"], "score": score, "reasons": reasons,
            })

    findings.sort(key=lambda f: f["score"], reverse=True)
    return findings, len(requests)

# =====================================================================
# FLASK WEB SERVER
# =====================================================================

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

def verdict_band(score):
    """Maps a 0-10 risk score to the updated human verdict band."""
    if score > 6:
        return "High Risk"
    if score >= 4:
        return "Medium Risk"
    return "Low Risk"

def save_upload(file_storage, allowed_exts):
    filename = secure_filename(file_storage.filename or "")
    if not filename: return None, "No filename provided."
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed_exts:
        return None, f"Unsupported file type '{ext}'. Expected: {', '.join(allowed_exts)}"
    dest_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{filename}")
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
    if "file" not in request.files: return jsonify({"error": "No file field."}), 400
    dest_path, err = save_upload(request.files["file"], {".apk"})
    if err: return jsonify({"error": err}), 400

    try:
        report = build_apk_report(dest_path)
        report["verdict"] = verdict_band(report["risk_score"])
        return jsonify({"ok": True, "report": report})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if os.path.exists(dest_path): os.remove(dest_path)

@app.route("/api/analyze-pcap", methods=["POST"])
def analyze_pcap_route():
    if "file" not in request.files: return jsonify({"error": "No file field."}), 400
    dest_path, err = save_upload(request.files["file"], {".pcap", ".pcapng"})
    if err: return jsonify({"error": err}), 400

    interval_tolerance = float(request.form.get("interval_tolerance", 0.15))
    min_hits = int(request.form.get("min_hits", 3))

    try:
        findings, req_count = build_pcap_report(dest_path, interval_tolerance, min_hits)
        beacon_score = sum(f["score"] for f in findings)
        report = {
            "findings": findings, "request_count": req_count,
            "beacon_score": beacon_score, "verdict": verdict_band(beacon_score)
        }
        return jsonify({"ok": True, "report": report})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if os.path.exists(dest_path): os.remove(dest_path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)