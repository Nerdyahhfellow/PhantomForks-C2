"""
static_analysis.py

Static analysis engine for Third Eye.

Given a path to an .apk file, produces a structured, JSON-serializable
report covering:

    - file metadata (hashes, size)
    - declared permissions, with dangerous ones flagged and explained
    - category mismatch heuristic (simple app claiming dangerous perms)
    - exported components without a permission guard
    - full APK file tree (via zipfile, no androguard dependency needed here)
    - embedded IOCs pulled from dex strings: URLs, raw IPs, emails,
      phone numbers, crypto wallet addresses, and suspicious keywords
      (this is the "claimed behavior" half of the correlation engine)
    - signing certificate info (self-signed / debug cert detection)
    - an overall static risk score

This module is a refactor of the original apk_static_analyzer.py CLI tool
into an importable engine (`analyze_apk`) that the Flask app calls directly,
while keeping the CLI usable standalone for debugging.

Requires: androguard  (pip install androguard)
"""

import hashlib
import re
import sys
import zipfile

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="ERROR")
except ImportError:
    pass

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    AnalyzeAPK = None


# --- Config ---------------------------------------------------------------

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

LOW_FUNCTIONALITY_HINTS = ["calculator", "flashlight", "wallpaper", "notes", "scanner_lite"]

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_REGEX = re.compile(r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")
BTC_WALLET_REGEX = re.compile(r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_WALLET_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TOKEN_REGEX = re.compile(r"\b(?:[A-Za-z0-9_-]*(?:api[_-]?key|token|secret|bearer)[A-Za-z0-9_-]*\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{12,}['\"]?)\b", re.IGNORECASE)
SUSPICIOUS_STRING_KEYWORDS = ["cmd=", "gate.php", "beacon", "exec(", "Runtime.getRuntime", "su -c", "DexClassLoader"]

# Benign noise to filter out of URL/IP extraction
BENIGN_URL_SUBSTRINGS = ["schemas.android.com", "w3.org", "apache.org/licenses"]


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_file_metadata(apk_path):
    import os
    return {
        "filename": os.path.basename(apk_path),
        "size_bytes": os.path.getsize(apk_path),
        "sha256": _sha256(apk_path),
        "md5": _md5(apk_path),
    }


def get_file_tree(apk_path):
    """Build a nested file tree of the APK's contents via zipfile — does not
    require androguard, so this always works even on a corrupt/unusual APK."""
    tree = {"name": "/", "type": "dir", "children": {}}
    try:
        with zipfile.ZipFile(apk_path) as z:
            for info in z.infolist():
                parts = info.filename.split("/")
                node = tree
                for i, part in enumerate(parts):
                    if part == "":
                        continue
                    is_last = i == len(parts) - 1
                    if is_last and not info.is_dir():
                        node["children"].setdefault(part, {
                            "name": part, "type": "file", "size": info.file_size
                        })
                    else:
                        node = node["children"].setdefault(part, {
                            "name": part, "type": "dir", "children": {}
                        })
    except Exception as e:
        return {"name": "/", "type": "dir", "children": {}, "error": str(e)}

    def to_list(node):
        if node["type"] == "file":
            return node
        children = sorted(node["children"].values(), key=lambda c: (c["type"] != "dir", c["name"].lower()))
        return {"name": node["name"], "type": "dir", "children": [to_list(c) for c in children]}

    return to_list(tree)


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


def _resolve_component_name(name, package):
    """Manifest component names can be relative (`.Foo`), bare (`Foo`), or
    fully-qualified (`com.x.Foo`) — normalize to fully-qualified since
    that's what `am start`/`am broadcast`/`am start-service` need."""
    if not name:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def analyze_launch_components(a):
    """Find how this package can actually be *started* on a device.

    Most legitimate apps have a launcher activity (`MAIN`/`LAUNCHER` intent
    filter), which is what the dynamic-analysis spawn-gate flow assumes.
    Second-stage/dropped payloads very often don't — they're built to run
    only as a background service or a broadcast receiver once installed,
    with no UI a user is meant to tap. Trying to spawn/launch those the
    normal way silently does nothing (no crash, no process, no behavior to
    observe), which looks like "nothing happened" rather than an error.

    Returns the launcher activity if there is one, plus every exported
    service/receiver/activity as fallbacks so a dropped payload without a
    launcher can still be started deliberately for its short dynamic pass.
    """
    android_ns = "{http://schemas.android.com/apk/res/android}"
    package = a.get_package()
    manifest = a.get_android_manifest_xml()

    launcher_activity = None
    activities = []
    for node in manifest.findall(".//activity"):
        name = _resolve_component_name(node.get(f"{android_ns}name"), package)
        if not name:
            continue
        activities.append({"name": name})
        for intent in node.findall("intent-filter"):
            actions = [n.get(f"{android_ns}name") for n in intent.findall("action")]
            categories = [n.get(f"{android_ns}name") for n in intent.findall("category")]
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                if not launcher_activity:
                    launcher_activity = name

    def _exported_components(tag):
        out = []
        for node in manifest.findall(f".//{tag}"):
            name = _resolve_component_name(node.get(f"{android_ns}name"), package)
            exported = node.get(f"{android_ns}exported")
            has_filter = node.find("intent-filter") is not None
            if not name or not (exported == "true" or (exported is None and has_filter)):
                continue
            actions = []
            for intent in node.findall("intent-filter"):
                actions += [n.get(f"{android_ns}name") for n in intent.findall("action")]
            out.append({"name": name, "actions": [x for x in actions if x]})
        return out

    return {
        "launcher_activity": launcher_activity,
        "activities": activities,
        "services": _exported_components("service"),
        "receivers": _exported_components("receiver"),
    }


def analyze_exported_components(a):
    findings = []
    android_ns = "{http://schemas.android.com/apk/res/android}"
    for tag, comp_type in [
        ("activity", "activity"),
        ("service", "service"),
        ("receiver", "receiver"),
        ("provider", "provider"),
    ]:
        for node in a.get_android_manifest_xml().findall(f".//{tag}"):
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


def scan_strings_for_iocs(d_list):
    urls, ips, emails, phones, wallets, tokens, suspicious_kw = (
        set(), set(), set(), set(), set(), set(), set()
    )

    for d in d_list:
        for s in d.get_strings():
            s = str(s)
            for m in URL_REGEX.findall(s):
                urls.add(m)
            for m in IP_REGEX.findall(s):
                if all(0 <= int(o) <= 255 for o in m.split(".")):
                    ips.add(m)
            for m in EMAIL_REGEX.findall(s):
                emails.add(m)
            for m in PHONE_REGEX.findall(s):
                if len(re.sub(r"\D", "", m)) >= 10:
                    phones.add(m)
            for m in BTC_WALLET_REGEX.findall(s):
                wallets.add(m if isinstance(m, str) else m[0])
            for m in ETH_WALLET_REGEX.findall(s):
                wallets.add(m)
            for m in TOKEN_REGEX.findall(s):
                tokens.add(m[:80])
            for kw in SUSPICIOUS_STRING_KEYWORDS:
                if kw.lower() in s.lower():
                    suspicious_kw.add(kw)

    urls = {u for u in urls if not any(b in u for b in BENIGN_URL_SUBSTRINGS)}

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "emails": sorted(emails),
        "phone_numbers": sorted(phones),
        "wallet_addresses": sorted(wallets),
        "tokens_secrets": sorted(tokens),
        "suspicious_keywords": sorted(suspicious_kw),
    }


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


def analyze_apk(apk_path):
    """Main entry point used by the Flask app. Returns a JSON-serializable dict."""
    if AnalyzeAPK is None:
        raise RuntimeError("androguard is required. Install it with: pip install androguard")

    metadata = get_file_metadata(apk_path)
    file_tree = get_file_tree(apk_path)

    a, d_list, dx = AnalyzeAPK(apk_path)

    declared_perms, dangerous_perms = analyze_permissions(a)
    mismatch = check_category_mismatch(a, dangerous_perms)
    exported_findings = analyze_exported_components(a)
    iocs = scan_strings_for_iocs(d_list)
    signing_findings = analyze_signing(a)
    launch_components = analyze_launch_components(a)

    from scoring import static_score

    partial = {
        "dangerous_permissions": dangerous_perms,
        "exported_components": exported_findings,
        "iocs": iocs,
        "category_mismatch": mismatch,
        "signing": signing_findings,
    }
    score = static_score(partial)

    return {
        "metadata": metadata,
        "package": a.get_package(),
        "app_name": a.get_app_name() or metadata["filename"],
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "declared_permissions": declared_perms,
        "dangerous_permissions": dangerous_perms,
        "category_mismatch": mismatch,
        "exported_components": exported_findings,
        "file_tree": file_tree,
        "iocs": iocs,
        "signing": signing_findings,
        "launch_components": launch_components,
        "risk_score": score,
    }


# --- Standalone CLI (kept for debugging) -----------------------------------

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Static risk analysis of an APK file.")
    parser.add_argument("apk", help="Path to .apk file")
    parser.add_argument("--json", help="Optional path to also write the report as JSON")
    args = parser.parse_args()

    print(f"Analyzing {args.apk} ...")
    report = analyze_apk(args.apk)
    print(json.dumps({k: v for k, v in report.items() if k != "file_tree"}, indent=2)[:4000])

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Full JSON report written to {args.json}")


if __name__ == "__main__":
    main()
