"""
correlate.py

Correlation engine — the standout feature of this platform.

Most tools report static findings and dynamic findings as two separate
lists. This module explicitly cross-references them and surfaces the
*contradictions*, which is where the genuinely interesting forensic signal
lives:

    CONFIRMED       - a domain/IP hardcoded in the app's code was actually
                       contacted during the sandbox run. Static claim and
                       observed behavior agree.

    DORMANT         - a domain/IP is hardcoded in the app's code but was
                       NEVER contacted during the test run. This is real
                       malware behavior: time bombs, remote-activation
                       triggers, or conditions the sandbox run didn't meet.
                       Flagged as "dormant C2" for the investigator to
                       follow up on (e.g. run again with different inputs
                       or a longer capture window).

    UNCLAIMED       - the opposite mismatch: the app contacted a host at
                       runtime that has NO corresponding string anywhere in
                       the decompiled code. This points to obfuscation,
                       a domain-generation algorithm (DGA), string
                       encryption, or a second-stage payload downloading
                       its own C2 list — arguably the most suspicious
                       category of all, since it means static analysis
                       alone would have missed it completely.

Host/IP matching is done with simple containment + normalization (strip
scheme/path from URLs, compare hostnames and bare IPs) rather than exact
string equality, since a hardcoded string is often just the domain while
the observed traffic includes the full URL or an IP resolved from DNS.
"""

import re
from urllib.parse import urlparse


def _extract_host(value: str) -> str:
    """Normalize a URL/host/IP string down to a bare hostname or IP for
    comparison purposes."""
    value = value.strip()
    if "://" in value:
        try:
            parsed = urlparse(value)
            return (parsed.hostname or value).lower()
        except Exception:
            pass
    # strip any trailing path/port if it sneaked in without a scheme
    value = value.split("/")[0]
    value = value.split(":")[0]
    return value.lower()


def correlate(static_report: dict, network_report: dict) -> dict:
    static_iocs = static_report.get("iocs", {})
    static_hosts = set()
    for u in static_iocs.get("urls", []):
        static_hosts.add(_extract_host(u))
    for ip in static_iocs.get("ips", []):
        static_hosts.add(_extract_host(ip))

    observed_hosts = set()
    observed_by_host = {}
    for dest in network_report.get("destinations", []):
        h = _extract_host(dest["host"])
        observed_hosts.add(h)
        observed_by_host[h] = dest
        ip = _extract_host(dest.get("ip", ""))
        if ip:
            observed_hosts.add(ip)
            observed_by_host.setdefault(ip, dest)

    confirmed, dormant, unclaimed = [], [], []

    for h in sorted(static_hosts):
        if not h:
            continue
        if h in observed_hosts:
            dest = observed_by_host.get(h, {})
            confirmed.append({
                "host": h,
                "request_count": dest.get("request_count"),
                "note": "Hardcoded in app code and actually contacted during the sandbox run.",
            })
        else:
            dormant.append({
                "host": h,
                "note": "Hardcoded in app code but never contacted during this test run — "
                        "possible time-bomb, remote-activation trigger, or condition the "
                        "sandbox run didn't satisfy. Recommend re-running with different "
                        "inputs or a longer capture window.",
            })

    for h in sorted(observed_hosts):
        if not h:
            continue
        if h not in static_hosts:
            dest = observed_by_host.get(h, {})
            unclaimed.append({
                "host": h,
                "request_count": dest.get("request_count"),
                "note": "Contacted at runtime but no matching string found anywhere in the "
                        "decompiled code — suggests obfuscation, string encryption, a "
                        "domain-generation algorithm, or a second-stage payload.",
            })

    # Beacon findings get cross-referenced too, since a beacon to a
    # "confirmed" host is more actionable than a beacon to something we
    # can't tie back to the code at all.
    beacon_hosts = {_extract_host(b["host"]) for b in network_report.get("beacons", [])}
    verdict_notes = []
    if beacon_hosts & {c["host"] for c in confirmed}:
        verdict_notes.append("Periodic beaconing observed to a host hardcoded in the app's own code — strong C2 signal.")
    if beacon_hosts & {u["host"] for u in unclaimed}:
        verdict_notes.append("Periodic beaconing observed to a host with no trace in static code — likely obfuscated or dynamically resolved C2.")
    if dormant:
        verdict_notes.append(f"{len(dormant)} hardcoded destination(s) never triggered during this run — worth re-testing.")

    return {
        "confirmed": confirmed,
        "dormant": dormant,
        "unclaimed": unclaimed,
        "verdict_notes": verdict_notes,
        "summary": {
            "confirmed_count": len(confirmed),
            "dormant_count": len(dormant),
            "unclaimed_count": len(unclaimed),
        },
    }
