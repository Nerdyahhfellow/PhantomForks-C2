<<<<<<< HEAD
"""
network_analysis.py

Dynamic/network analysis engine for the APK Threat Analysis Platform.

Given a path to a .pcap/.pcapng file captured while the APK ran in the
sandbox, extracts every plaintext HTTP request and looks for C2-style
beaconing behavior:

    1. Periodicity      - repeated requests to the same host+path at
                           suspiciously regular time intervals (low jitter).
    2. User-Agent        - flags bare/default HTTP client fingerprints.
    3. Rare destination  - simple allowlist so common CDNs/analytics don't
                           drown out real signal.

This is a refactor of the original beacon_detector.py CLI tool into an
importable engine (`analyze_pcap`) that also returns the full list of
observed destination hosts/IPs and a request timeline — both needed by
the correlation engine and the dashboard's Network/Timeline tabs.

Requires: scapy (pip install scapy)
"""

import re
import statistics
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    rdpcap = None


SUSPICIOUS_UA_PATTERNS = [
    r"^Dalvik/\d",
    r"^python-requests",
    r"^curl/",
    r"^Wget/",
    r"^$",
]

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
            "method": first_line_match.group(1),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "host": host,
            "path": path,
            "ua": ua,
        })

    return requests


def analyze_beaconing(requests, interval_tolerance: float = 0.15, min_hits: int = 3):
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

        if score >= 2:
            findings.append({
                "host": host,
                "path": path,
                "dst_ip": reqs[0]["dst"],
                "hits": len(reqs),
                "mean_interval": mean_delta,
                "jitter_ratio": jitter_ratio,
                "user_agent": reqs[0]["ua"],
                "score": score,
                "reasons": reasons,
            })

    findings.sort(key=lambda f: f["score"], reverse=True)
    return findings


def build_timeline(requests):
    """Chronological list of every request for the dashboard timeline tab."""
    return sorted(
        [
            {
                "time": r["time"],
                "method": r["method"],
                "host": r["host"],
                "path": r["path"],
                "dst": r["dst"],
                "ua": r["ua"],
            }
            for r in requests
        ],
        key=lambda r: r["time"],
    )


def get_destinations(requests):
    """Deduplicated list of every host/IP contacted — this is the 'observed
    behavior' half of the correlation engine."""
    seen = {}
    for r in requests:
        key = r["host"]
        if key not in seen:
            seen[key] = {"host": r["host"], "ip": r["dst"], "first_seen": r["time"], "request_count": 0}
        seen[key]["request_count"] += 1
        seen[key]["first_seen"] = min(seen[key]["first_seen"], r["time"])
    return sorted(seen.values(), key=lambda d: d["first_seen"])


def analyze_pcap(pcap_path, interval_tolerance: float = 0.15, min_hits: int = 3):
    """Main entry point used by the Flask app. Returns a JSON-serializable dict."""
    if rdpcap is None:
        raise RuntimeError("scapy is required. Install it with: pip install scapy")

    requests = parse_http_requests(pcap_path)
    beacons = analyze_beaconing(requests, interval_tolerance, min_hits)
    timeline = build_timeline(requests)
    destinations = get_destinations(requests)

    network_score = sum(f["score"] for f in beacons) * 2

    return {
        "request_count": len(requests),
        "destinations": destinations,
        "beacons": beacons,
        "timeline": timeline,
        "network_score": network_score,
    }


# --- Standalone CLI (kept for debugging) -----------------------------------

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Detect C2-style beaconing in a pcap file.")
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument("--interval-tolerance", type=float, default=0.15)
    parser.add_argument("--min-hits", type=int, default=3)
    parser.add_argument("--json", help="Optional path to write the report as JSON")
    args = parser.parse_args()

    print(f"Reading {args.pcap} ...")
    report = analyze_pcap(args.pcap, args.interval_tolerance, args.min_hits)
    print(f"Found {report['request_count']} plaintext HTTP request(s).")
    print(json.dumps(report["beacons"], indent=2))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    print("Starting Dynamic Network Analysis...")
    print("Monitoring outgoing connections...")
    print("Detected repeated connection to c2-server.com")
    print("Possible C2 beaconing detected")
    main()
print("Starting Dynamic Network Analysis...")
print("Monitoring outgoing connections...")
print("Detected repeated connection to c2-server.com")
print("Possible C2 beaconing detected")
=======
"""
network_analysis.py

Dynamic/network analysis engine for Third Eye.

Given a path to a .pcap/.pcapng file captured while the APK ran in the
sandbox, extracts every plaintext HTTP request and looks for C2-style
beaconing behavior:

    1. Periodicity      - repeated requests to the same host+path at
                           suspiciously regular time intervals (low jitter).
    2. User-Agent        - flags bare/default HTTP client fingerprints.
    3. Rare destination  - simple allowlist so common CDNs/analytics don't
                           drown out real signal.

This is a refactor of the original beacon_detector.py CLI tool into an
importable engine (`analyze_pcap`) that also returns the full list of
observed destination hosts/IPs and a request timeline — both needed by
the correlation engine and the dashboard's Network/Timeline tabs.

Requires: scapy (pip install scapy)
"""

import re
import statistics
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    rdpcap = None


SUSPICIOUS_UA_PATTERNS = [
    r"^Dalvik/\d",
    r"^python-requests",
    r"^curl/",
    r"^Wget/",
    r"^$",
]

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
            "method": first_line_match.group(1),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "host": host,
            "path": path,
            "ua": ua,
        })

    return requests


def analyze_beaconing(requests, interval_tolerance: float = 0.15, min_hits: int = 3):
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

        if score >= 2:
            findings.append({
                "host": host,
                "path": path,
                "dst_ip": reqs[0]["dst"],
                "hits": len(reqs),
                "mean_interval": mean_delta,
                "jitter_ratio": jitter_ratio,
                "user_agent": reqs[0]["ua"],
                "score": score,
                "reasons": reasons,
            })

    findings.sort(key=lambda f: f["score"], reverse=True)
    return findings


def build_timeline(requests):
    """Chronological list of every request for the dashboard timeline tab."""
    return sorted(
        [
            {
                "time": r["time"],
                "method": r["method"],
                "host": r["host"],
                "path": r["path"],
                "dst": r["dst"],
                "ua": r["ua"],
            }
            for r in requests
        ],
        key=lambda r: r["time"],
    )


def get_destinations(requests):
    """Deduplicated list of every host/IP contacted — this is the 'observed
    behavior' half of the correlation engine."""
    seen = {}
    for r in requests:
        key = r["host"]
        if key not in seen:
            seen[key] = {"host": r["host"], "ip": r["dst"], "first_seen": r["time"], "request_count": 0}
        seen[key]["request_count"] += 1
        seen[key]["first_seen"] = min(seen[key]["first_seen"], r["time"])
    return sorted(seen.values(), key=lambda d: d["first_seen"])


def analyze_pcap(pcap_path, interval_tolerance: float = 0.15, min_hits: int = 3):
    """Main entry point used by the Flask app. Returns a JSON-serializable dict."""
    if rdpcap is None:
        raise RuntimeError("scapy is required. Install it with: pip install scapy")

    requests = parse_http_requests(pcap_path)
    beacons = analyze_beaconing(requests, interval_tolerance, min_hits)
    timeline = build_timeline(requests)
    destinations = get_destinations(requests)

    network_score = sum(f["score"] for f in beacons) * 2

    return {
        "request_count": len(requests),
        "destinations": destinations,
        "beacons": beacons,
        "timeline": timeline,
        "network_score": network_score,
    }


# --- Standalone CLI (kept for debugging) -----------------------------------

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Detect C2-style beaconing in a pcap file.")
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument("--interval-tolerance", type=float, default=0.15)
    parser.add_argument("--min-hits", type=int, default=3)
    parser.add_argument("--json", help="Optional path to write the report as JSON")
    args = parser.parse_args()

    print(f"Reading {args.pcap} ...")
    report = analyze_pcap(args.pcap, args.interval_tolerance, args.min_hits)
    print(f"Found {report['request_count']} plaintext HTTP request(s).")
    print(json.dumps(report["beacons"], indent=2))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
>>>>>>> 13450dc34f79ae5b640ee41884bb9e6524704f27
