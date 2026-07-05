"""
verdict.py

Combines the static, network, and correlation reports into a single
explainable verdict for the top of the dashboard: a plain Safe/Risky
classification, a one sentence summary, and the list of specific things
that contributed to that call — as a plain bullet list, not a points
breakdown. The underlying 0-10 scoring in scoring.py is still used
internally to decide Safe vs. Risky and to order the bullets by
severity, but the numbers themselves are never surfaced to the
investigator.
"""

from scoring import build_breakdown, total_score

# Anything below this on the internal 0-10 scale is called "safe" — this
# is the same cutoff that used to separate "low" from "medium" risk.
RISKY_THRESHOLD = 2


def build_verdict(static_report: dict, network_report: dict, correlation: dict) -> dict:
    breakdown = build_breakdown(static_report, network_report, correlation)
    score = total_score(breakdown)
    is_risky = score >= RISKY_THRESHOLD

    if is_risky:
        summary = ("Risk indicators found in this app's behavior; treat it as unsafe "
                   "until an investigator reviews the flags below.")
    else:
        summary = "No significant risk indicators found; behavior appears benign."

    # Ordered worst-first internally (by the same weight that used to be
    # shown as "+N"), then the weight itself is dropped from what's
    # returned — the dashboard shows why something was flagged, not a
    # score for it.
    ordered = sorted(breakdown, key=lambda f: f["points"], reverse=True)
    flags = [{"label": f["label"], "detail": f["detail"]} for f in ordered]

    return {
        "risk_level": "risky" if is_risky else "safe",
        "summary": summary,
        "flags": flags,
    }
