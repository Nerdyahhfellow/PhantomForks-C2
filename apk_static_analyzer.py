#!/usr/bin/env python3
"""
apk_static_analyzer.py

Static analysis module for an APK Threat Analysis Platform.
Takes an .apk file and produces a scored risk report based on:

  1. Dangerous permissions        - flags high-risk permissions, and flags
                                     permission sets that don't match the
                                     app's apparent category (basic heuristic).
  2. Exported components          - activities/services/receivers/providers
                                     exported without a permission guard.
  3. Embedded strings             - scans all strings in the dex for raw IPs,
                                     URLs, and suspicious keywords (common
                                     hiding spot for hardcoded C2 addresses,
                                     even in apps with obfuscated class names).
  4. Signing certificate info     - self-signed / debug cert detection.

This is designed to run standalone, and its JSON output is meant to be
combined later with beacon_detector.py's network-side findings into one
unified verdict.

Usage:
    python apk_static_analyzer.py app.apk
    python apk_static_analyzer.py app.apk --json report.json

Requires: androguard  (pip install androguard)
"""

import argparse
import json
import re
import sys

# Silence androguard's very verbose debug/info logging before importing it
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="ERROR")
except ImportError:
    pass

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    sys.exit("androguard is required. Install it with: pip install androguard")


# --- Config --------------------------------------------------------------

# Permissions considered high-risk on their own.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Can read SMS messages (often used to steal OTPs/2FA codes)",
    "android.permission.SEND_SMS": "Can send SMS silently (premium-rate fraud, OTP interception)",
    "android.permission.RECEIVE_SMS": "Can intercept incoming SMS",
    "android.permission.READ_CONTACTS": "Can read contact list",
    "android.permission.CALL_PHONE": "Can place phone calls without user interaction",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps (overlay/phishing attacks)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Can read screen content & simulate input (common in banking trojans)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can install other APKs (dropper behavior)",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Can auto-start on device boot (persistence)",
    "android.permission.BIND_DEVICE_ADMIN": "Can request device admin rights (hard to uninstall, lock/wipe device)",
    "android.permission.READ_PHONE_STATE": "Can read device identifiers (IMEI, phone number)",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Broad file system write access",
    "android.permission.CAMERA": "Can access camera",
    "android.permission.RECORD_AUDIO": "Can record audio",
    "android.permission.ACCESS_FINE_LOCATION": "Can access precise GPS location",
}

# Simple category inference from app name / package — extend as needed.
LOW_FUNCTIONALITY_HINTS = ["calculator", "flashlight", "wallpaper", "notes", "scanner_lite"]

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUSPICIOUS_STRING_KEYWORDS = ["cmd=", "gate.php", "beacon", "exec(", "Runtime.getRuntime"]


def analyze_permissions(a):
    declared = a.get_permissions()
    findings = []
    for perm in declared:
        if perm in DANGEROUS_PERMISSIONS:
            findings.append({"permission": perm, "reason": DANGEROUS_PERMISSIONS[perm]})
    return declared, findings


def check_category_mismatch(a, dangerous_found):
    app_name = (a.get_app_name() or "").lower()
    package = a.get_package().lower()
    hint_hit = any(h in app_name or h in package for h in LOW_FUNCTIONALITY_HINTS)
    if hint_hit and dangerous_found:
        return (
            f"App name/package suggests simple utility ('{app_name or package}') "
            f"but requests {len(dangerous_found)} dangerous permission(s) — mismatch."
        )
    return None


def analyze_exported_components(a):
    findings = []

    def check(components, comp_type, get_perm_attr=True):
        for c in components:
            name = c.get("name") if isinstance(c, dict) else c
            # androguard's get_activities()/get_services() etc return name strings;
            # exported + permission info comes from the manifest analysis object.
            findings_entry = {"type": comp_type, "name": name}
            findings.append(findings_entry)

    # Use manifest analysis for accurate exported/permission info
    for tag, comp_type in [
        ("activity", "activity"),
        ("service", "service"),
        ("receiver", "receiver"),
        ("provider", "provider"),
    ]:
        for node in a.get_android_manifest_xml().findall(f".//{tag}"):
            android_ns = "{http://schemas.android.com/apk/res/android}"
            name = node.get(f"{android_ns}name")
            exported = node.get(f"{android_ns}exported")
            permission = node.get(f"{android_ns}permission")
            has_intent_filter = node.find("intent-filter") is not None

            is_exported = exported == "true" or (exported is None and has_intent_filter)

            if is_exported and not permission:
                findings.append({
                    "type": comp_type,
                    "name": name,
                    "issue": "exported with no permission guard",
                })

    return findings


def scan_strings_for_iocs(a, d_list):
    urls, ips, suspicious_kw = set(), set(), set()

    for d in d_list:
        for s in d.get_strings():
            s = str(s)
            for m in URL_REGEX.findall(s):
                urls.add(m)
            for m in IP_REGEX.findall(s):
                # filter out obvious version numbers / non-IP noise heuristically
                if all(0 <= int(o) <= 255 for o in m.split(".")):
                    ips.add(m)
            for kw in SUSPICIOUS_STRING_KEYWORDS:
                if kw.lower() in s.lower():
                    suspicious_kw.add(kw)

    # drop common benign schema URLs
    urls = {u for u in urls if "schemas.android.com" not in u and "w3.org" not in u}

    return sorted(urls), sorted(ips), sorted(suspicious_kw)


def analyze_signing(a):
    findings = []
    try:
        certs = a.get_certificates()
        if not certs:
            findings.append("APK does not appear to be signed (or cert not parseable).")
        for cert in certs:
            try:
                subject = cert.subject.human_friendly
            except AttributeError:
                subject = str(cert.subject)
            if "Android Debug" in subject or "androiddebugkey" in subject.lower():
                findings.append(f"Signed with the default Android DEBUG certificate: {subject}")
    except Exception as e:
        findings.append(f"Could not parse signing certificate: {e}")
    return findings


def compute_score(dangerous_perms, exported_findings, urls, ips, suspicious_kw, sign_findings, mismatch):
    score = 0
    score += len(dangerous_perms) * 2
    score += len([f for f in exported_findings if "issue" in f]) * 2
    score += len(ips) * 2          # raw hardcoded IPs are a stronger signal than URLs
    score += len(urls) * 1
    score += len(suspicious_kw) * 3
    score += len(sign_findings) * 2
    score += 3 if mismatch else 0
    return score


def print_report(report):
    print(f"\n{'='*70}\nSTATIC APK ANALYSIS REPORT\n{'='*70}")
    print(f"Package     : {report['package']}")
    print(f"App name    : {report['app_name']}")
    print(f"Risk score  : {report['risk_score']}")

    print(f"\n-- Dangerous permissions ({len(report['dangerous_permissions'])}) --")
    for p in report["dangerous_permissions"]:
        print(f"  [!] {p['permission']}")
        print(f"      {p['reason']}")

    if report["category_mismatch"]:
        print(f"\n-- Category mismatch --\n  [!] {report['category_mismatch']}")

    exported_issues = [f for f in report["exported_components"] if "issue" in f]
    print(f"\n-- Exported components without permission guard ({len(exported_issues)}) --")
    for f in exported_issues:
        print(f"  [!] {f['type']}: {f['name']}")

    print(f"\n-- Embedded URLs ({len(report['urls'])}) --")
    for u in report["urls"][:20]:
        print(f"  - {u}")

    print(f"\n-- Embedded raw IP addresses ({len(report['ips'])}) --")
    for ip in report["ips"]:
        print(f"  - {ip}")

    print(f"\n-- Suspicious string keywords found ({len(report['suspicious_keywords'])}) --")
    for kw in report["suspicious_keywords"]:
        print(f"  - {kw}")

    print(f"\n-- Signing certificate --")
    for s in report["signing"]:
        print(f"  [!] {s}")
    if not report["signing"]:
        print("  No issues found.")

    print()


def main():
    parser = argparse.ArgumentParser(description="Static risk analysis of an APK file.")
    parser.add_argument("apk", help="Path to .apk file")
    parser.add_argument("--json", help="Optional path to also write the report as JSON")
    args = parser.parse_args()

    print(f"Analyzing {args.apk} ... (this can take a little while for larger APKs)")
    a, d_list, dx = AnalyzeAPK(args.apk)

    declared_perms, dangerous_perms = analyze_permissions(a)
    mismatch = check_category_mismatch(a, dangerous_perms)
    exported_findings = analyze_exported_components(a)
    urls, ips, suspicious_kw = scan_strings_for_iocs(a, d_list)
    signing_findings = analyze_signing(a)

    score = compute_score(dangerous_perms, exported_findings, urls, ips, suspicious_kw, signing_findings, mismatch)

    report = {
        "package": a.get_package(),
        "app_name": a.get_app_name(),
        "declared_permissions": declared_perms,
        "dangerous_permissions": dangerous_perms,
        "category_mismatch": mismatch,
        "exported_components": exported_findings,
        "urls": urls,
        "ips": ips,
        "suspicious_keywords": suspicious_kw,
        "signing": signing_findings,
        "risk_score": score,
    }

    print_report(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Full JSON report written to {args.json}")


if __name__ == "__main__":
    main()
