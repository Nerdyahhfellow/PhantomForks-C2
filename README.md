# TRIPWIRE — APK & Beacon Threat Analysis

A small web app wrapping two analyzers into one dashboard:

- `apk_static_analyzer.py` — static analysis of an `.apk` (permissions, exported
  components, embedded IOCs, signing cert).
- `beacon_detector.py` — periodicity / User-Agent / allowlist heuristics over
  HTTP traffic in a `.pcap` / `.pcapng`.

Both scripts are unmodified except for one added `build_report(...)` function
each, so the server can call them directly instead of shelling out to the CLI.
The original CLI usage (`python apk_static_analyzer.py app.apk`) still works
exactly as before.

## Setup

```bash
pip install -r requirements.txt
python server.py
```

Then open **http://localhost:5000**.

## How it works

- `server.py` is a Flask app with two upload endpoints:
  - `POST /api/analyze-apk` — multipart field `file`, must be `.apk`
  - `POST /api/analyze-pcap` — multipart field `file` (`.pcap`/`.pcapng`), plus
    optional form fields `interval_tolerance` and `min_hits` matching the
    original CLI flags
- Uploaded files are written to `uploads/` with a random filename, analyzed,
  then deleted immediately in a `finally` block — nothing persists on disk
  between scans.
- `static/index.html` is a single-file dashboard (vanilla JS, no build step)
  with drag-and-drop upload, a risk gauge, and collapsible finding sections
  for each report type.
- Risk scores are bucketed into the same verdict bands (`clean` / `low` /
  `moderate` / `high` / `critical`) for both scan types so the UI is
  consistent regardless of which analyzer produced the score.

## Notes / next steps if you want to extend this

- **Combined verdict**: right now APK and pcap scans are shown as two
  separate report cards. If you scan an APK and its matching traffic capture
  in the same session, you could sum `risk_score + beacon_score` client-side
  for one overall verdict — the hooks are already there in `verdict_band()`.
- **Persistence**: there's currently no database — every scan is stateless.
  If you want history/comparison across scans, add SQLite and store the
  JSON reports keyed by APK package name + hash.
- **Allowlist / keyword tuning**: `ALLOWLIST_DOMAINS` in `beacon_detector.py`
  and `SUSPICIOUS_STRING_KEYWORDS` / `DANGEROUS_PERMISSIONS` in
  `apk_static_analyzer.py` are intentionally small starter sets — worth
  expanding with your own threat intel feed.
- **Production**: the dev server (`app.run`) is fine locally; put it behind
  gunicorn/uwsgi + nginx before exposing it to anyone else, and consider a
  hard timeout on `AnalyzeAPK` for very large/obfuscated APKs.
