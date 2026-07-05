# Third Eye

A local web app for investigating Android APKs suspected of command-and-control
(C2) behavior. Combines static analysis (permissions, exported components,
embedded IOCs), dynamic analysis (beacon detection from a network capture),
and a correlation engine that catches contradictions between what an app's
code claims and what it actually does at runtime — then exports everything
as a chain-of-custody forensic PDF report.

## What's included

Everything lives in one flat folder — no subfolders, so there's nothing to
misplace when you unzip it:

```
app.py                 Flask app (routes, upload handling, PDF export)
requirements.txt

static_analysis.py     Permissions, exported components,
                        embedded IOCs (URLs/IPs/emails/wallets/tokens),
                        file tree, signing cert checks
network_analysis.py    Pcap parsing + beacon periodicity detection
correlate.py           Confirmed / Dormant / Unclaimed cross-reference
verdict.py             Combined, explainable 0-10 risk score
scoring.py             Scoring weights + breakdown logic
report.py              Forensic PDF generator (reportlab)

index.html             Single-page dashboard
style.css
app.js

sample_calc.apk         Benign baseline sample
sample_C2demo.apk       Sample APK with hardcoded beacon URL
sample_capture.pcapng   Matching network capture for sample_C2demo.apk
```

An `uploads/` folder is created automatically the first time you run the
app — it doesn't need to exist in advance.

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

- Drop an `.apk` (required), or click one of the bundled sample cases to see
  the full pipeline instantly.
- Static analysis (permissions, file tree, IOCs) runs immediately.
  Dynamic analysis (emulator + Frida + network capture) kicks off
  automatically right alongside it and populates the Network/Correlation/
  Timeline tabs once it finishes — no separate button or manual pcap upload
  needed.
- After each dynamic analysis run, the virtual device is automatically wiped
  back to a clean state (`AndroidEmulatorController.reset_device()`, a
  `-wipe-data` boot cycle) so the APK that was just installed — and anything
  it wrote to the device — doesn't carry over into the next scan. You'll see
  a brief "Resetting virtual device…" step at the end of the progress bar.
- If the sample drops a second-stage APK on disk during the run (e.g. via
  `REQUEST_INSTALL_PACKAGES`-style dropper behavior), Third Eye detects it,
  pulls that file off the device before teardown, and runs a full static
  analysis plus a short follow-up dynamic pass on it — all shown in the
  **Dropped APK** tab. Detection is two-layered:
  - **Filesystem sweep (primary).** Before the sample runs, and again right
    before it's uninstalled, `AndroidEmulatorController.list_apk_files()`
    sweeps `/sdcard`, `/storage/emulated/0`, `/data/local/tmp` (plus
    `/data/data` and `/data/user/0` if `adb root` succeeds) for any file
    ending in `.apk`. Diffing those two snapshots catches a drop regardless
    of *how* it was written — buffered/byte-range writes, `java.nio`, Okio,
    native code via JNI, a download-to-temp-name-then-`renameTo()` pattern,
    or shelling out to `pm install` all show up here, none of which is
    guaranteed to trip a fixed set of hooked Java methods.
  - **Frida hooks (corroborating).** `FileOutputStream` constructors/writes,
    `DownloadManager.Request`, and `PackageInstaller.Session.commit()` are
    still hooked and timestamped, so when they do fire you get a live
    play-by-play in the Runtime Behaviors table, not just an end-of-run
    file diff.
  - **Launching the payload for its own dynamic pass.** Second-stage
    payloads very often have no launcher activity — they're built to run as
    a background service/receiver, not something a user taps, so a plain
    spawn/`monkey` launch silently does nothing. Third Eye reads the
    dropped APK's manifest and starts it the way it's actually meant to be
    started: its launcher activity if it has one, otherwise the first
    exported service (`am start-service`), exported receiver
    (`am broadcast` with its declared action), or non-launcher activity it
    can find — then attaches Frida to the resulting process. If none of
    those exist, the tab says so explicitly rather than silently showing an
    empty dynamic report.
- The same tab also reports whether the sample probed for signs it's
  running on an emulator/sandbox rather than a real phone (system property
  checks like `ro.kernel.qemu`, known emulator-only files, `getprop`/`su`
  shell probes, etc.) — a classic anti-analysis evasion technique.
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
