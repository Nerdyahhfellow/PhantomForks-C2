#!/usr/bin/env python3
"""
beacon_detector.py

Static/network heuristic detector for C2-style beaconing behavior in a .pcap file.

Detection signals implemented:
  1. Periodicity   - repeated requests to the same host+path at suspiciously
                      regular time intervals (low variance / low jitter).
  2. User-Agent     - flags bare/default HTTP client fingerprints
                      (e.g. raw "Dalvik/x.x.x", "python-requests", "curl/",
                      empty UA) which legitimate branded apps rarely send as-is.
  3. Rare/unknown destination - simple allowlist check so common CDNs/analytics
                      domains don't drown out real signal (extend as needed).

Usage:
    python beacon_detector.py capture.pcap
    python beacon_detector.py capture.pcap --interval-tolerance 0.15 --min-hits 3

Requires: scapy (pip install scapy)
"""

import argparse
import re
import statistics
import sys
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    sys.exit("scapy is required. Install it with: pip install scapy")


# --- Config: known-benign User-Agent patterns / destinations -----------------
SUSPICIOUS_UA_PATTERNS = [
    r"^Dalvik/\d",          # raw Android default HTTP client, no library/branding
    r"^python-requests",
    r"^curl/",
    r"^Wget/",
    r"^$",                  # empty user-agent
]

# Extend this with your own known-safe analytics/CDN domains to reduce noise
ALLOWLIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "android.com",
    "apple.com", "microsoft.com", "cloudflare.com", "akamai.net",
}


def is_allowlisted(host: str) -> bool:
    return any(host.endswith(d) for d in ALLOWLIST_DOMAINS)


def is_suspicious_ua(ua: str) -> bool:
    return any(re.match(p, ua) for p in SUSPICIOUS_UA_PATTERNS)


def parse_http_requests(pcap_path: str):
    """Extract (timestamp, src_ip, dst_ip, host, path, user_agent) for each
    plaintext HTTP GET/POST request found in the pcap."""
    packets = rdpcap(pcap_path)
    requests = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            continue

        try:
            payload = bytes(pkt[Raw].load)
            text = payload.decode(errors="ignore")
        except Exception:
            continue

        if not (text.startswith("GET ") or text.startswith("POST ")):
            continue

        first_line_match = re.match(r"(GET|POST) (\S+) HTTP/1\.\d", text)
        if not first_line_match:
            continue

        path = first_line_match.group(2)
        host_match = re.search(r"Host:\s*([^\r\n]+)", text)
        ua_match = re.search(r"User-Agent:\s*([^\r\n]+)", text)

        host = host_match.group(1).strip() if host_match else pkt[IP].dst
        ua = ua_match.group(1).strip() if ua_match else ""

        requests.append({
            "time": float(pkt.time),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "host": host,
            "path": path,
            "ua": ua,
        })

    return requests


def analyze(requests, interval_tolerance: float, min_hits: int):
    """Group requests by (host, path) and look for periodic beaconing."""
    groups = defaultdict(list)
    for r in requests:
        groups[(r["host"], r["path"])].append(r)

    findings = []

    for (host, path), reqs in groups.items():
        reqs.sort(key=lambda r: r["time"])
        if len(reqs) < min_hits:
            continue

        deltas = [reqs[i + 1]["time"] - reqs[i]["time"] for i in range(len(reqs) - 1)]
        if len(deltas) < 2:
            continue

        mean_delta = statistics.mean(deltas)
        stdev_delta = statistics.pstdev(deltas)
        jitter_ratio = (stdev_delta / mean_delta) if mean_delta > 0 else 1.0

        is_periodic = jitter_ratio <= interval_tolerance
        ua_flag = is_suspicious_ua(reqs[0]["ua"])
        allowlisted = is_allowlisted(host)

        score = 0
        reasons = []
        if is_periodic:
            score += 2
            reasons.append(f"periodic beaconing (avg interval {mean_delta:.1f}s, jitter {jitter_ratio*100:.1f}%)")
        if ua_flag:
            score += 2
            reasons.append(f"suspicious User-Agent: '{reqs[0]['ua']}'")
        if not allowlisted:
            score += 1
            reasons.append("destination not in known-safe allowlist")

        if score >= 2:  # require at least two corroborating signals
            findings.append({
                "host": host,
                "path": path,
                "hits": len(reqs),
                "mean_interval": mean_delta,
                "jitter_ratio": jitter_ratio,
                "user_agent": reqs[0]["ua"],
                "score": score,
                "reasons": reasons,
            })

    findings.sort(key=lambda f: f["score"], reverse=True)
    return findings


def print_report(findings):
    if not findings:
        print("No beacon-like patterns detected.")
        return

    print(f"\n{'='*70}\nPOTENTIAL C2 BEACONING DETECTED\n{'='*70}")
    for f in findings:
        print(f"\n[Score: {f['score']}] {f['host']}{f['path']}")
        print(f"  Requests observed : {f['hits']}")
        print(f"  Avg interval      : {f['mean_interval']:.2f}s (jitter {f['jitter_ratio']*100:.1f}%)")
        print(f"  User-Agent        : {f['user_agent']!r}")
        print(f"  Reasons:")
        for r in f["reasons"]:
            print(f"    - {r}")
    print()


def build_report(pcap_path, interval_tolerance=0.15, min_hits=3):
    """Run the full beacon-detection pipeline on a pcap and return (findings, request_count).
    This is the function the web backend calls directly (no subprocess/CLI)."""
    requests = parse_http_requests(pcap_path)
    findings = analyze(requests, interval_tolerance, min_hits)
    return findings, len(requests)


def main():
    parser = argparse.ArgumentParser(description="Detect C2-style beaconing in a pcap file.")
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument("--interval-tolerance", type=float, default=0.15,
                         help="Max allowed jitter ratio (stdev/mean) to call traffic 'periodic'. Default 0.15")
    parser.add_argument("--min-hits", type=int, default=3,
                         help="Minimum repeated requests to same host+path before considering it. Default 3")
    args = parser.parse_args()

    print(f"Reading {args.pcap} ...")
    requests = parse_http_requests(args.pcap)
    print(f"Found {len(requests)} plaintext HTTP request(s).")

    findings = analyze(requests, args.interval_tolerance, args.min_hits)
    print_report(findings)


if __name__ == "__main__":
    main()