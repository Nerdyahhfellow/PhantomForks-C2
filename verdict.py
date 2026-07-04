"""
verdict.py

Combines the static, network, and correlation reports into a single
explainable verdict for the top of the dashboard: a risk level, a one
sentence summary, and a breakdown of exactly what contributed to the score
("+15 for exported activity without permission" style), rather than a bare
number.
"""

from analyzer.scoring import build_breakdown, level_for_score, total_score


def build_verdict(static_report: dict, network_report: dict, correlation: dict) -> dict:
    breakdown = build_breakdown(static_report, network_report, correlation)
    score = total_score(breakdown)
    level = level_for_score(score)

    top_flags = sorted(breakdown, key=lambda x: x["points"], reverse=True)[:3]

    if level == "critical":
        summary = "Multiple strong indicators of active command-and-control behavior."
    elif level == "high":
        summary = "Significant risk indicators found; behavior is consistent with malware."
    elif level == "medium":
        summary = "Some risk indicators found; warrants closer investigator review."
    else:
        summary = "Few or no risk indicators found; behavior appears benign."

    return {
        "risk_score": score,
        "risk_level": level,
        "summary": summary,
        "breakdown": breakdown,
        "top_flags": top_flags,
    }
