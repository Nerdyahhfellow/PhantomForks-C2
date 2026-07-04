# APK Threat Analysis Platform

A local web app for investigating Android APKs suspected of command-and-control
(C2) behavior. Combines static analysis (permissions, exported components,
embedded IOCs), dynamic analysis (beacon detection from a network capture),
and a correlation engine that catches contradictions between what an app's
code claims and what it actually does at runtime — then exports everything
as a chain-of-custody forensic PDF report.

## What's included

```
apk_platform/
├── app.py                     Flask app (routes, upload handling, PDF export)
├── requirements.txt
├── analyzer/
│   ├── static_analysis.py     Manifest, permissions, exported components,
│   │                          embedded IOCs (URLs/IPs/emails/wallets/tokens),
│   │                          file tree, signing cert checks
│   ├── network_analysis.py    Pcap parsing + beacon periodicity detection
│   ├── correlate.py           Confirmed / Dormant / Unclaimed cross-reference
│   ├── verdict.py             Combined, explainable risk score
│   └── report.py              Forensic PDF generator (reportlab)
├── templates/index.html        Single-page dashboard
├── static/css/style.css
├── static/js/app.js
└── samples/                    Bundled demo cases (C2demo.apk + capture.pcapng,
                                 calc.apk as a benign baseline) for one-click demos
```

## Setup

Requires **Python 3.9+**. `androguard` and `scapy` need real network access to
install and androguard in particular can take a minute to pull in its
dependencies — do this once, ahead of your demo, not on stage.

```bash
cd apk_platform
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python3 app.py
```

Then open **http://127.0.0.1:5000** in your browser.

- Drop an `.apk` (required) and optionally a `.pcap`/`.pcapng` capture, or
  click one of the bundled sample cases to see the full pipeline instantly.
- Without a pcap you still get the full static analysis, permissions,
  manifest, file tree, and IOC tabs — the Network/Correlation/Timeline tabs
  will note that dynamic data wasn't provided.
- Click **Generate Forensic Report** on any completed case to download the
  chain-of-custody PDF.

## Safety note

This tool is meant to run **locally against samples you already control
inside an isolated sandbox** (see your original setup notes: isolated VM,
host-only/NAT network, no shared folders). It has no authentication and
keeps analysis results in memory only — do not expose it on a shared network
or the open internet, and never point it at a live sample from your main
machine.

## Extending it

- `analyzer/static_analysis.py` — add more `DANGEROUS_PERMISSIONS` entries or
  IOC regexes (`SUSPICIOUS_STRING_KEYWORDS`, wallet formats, etc.)
- `analyzer/network_analysis.py` — tune `ALLOWLIST_DOMAINS` for your test
  network's own noise (DNS-over-HTTPS providers, telemetry, etc.), or extend
  `parse_http_requests` to also flag raw TLS ClientHello SNI values for
  encrypted C2 traffic.
- `analyzer/correlate.py` — the confirmed/dormant/unclaimed split is the
  differentiator for your demo; it's a good place to add more nuance (e.g.
  partial domain matches, DGA-pattern detection on the "unclaimed" list).
