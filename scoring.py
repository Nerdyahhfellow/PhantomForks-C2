"""
analyzer/scoring.py

Risk scoring engine for Third Eye.

Two layers live here:

  1. `static_score()` / `get_verdict_band()` — a quick standalone 0-10 score
     for the static-analysis-only CLI path (used by static_analysis.py).

  2. `build_breakdown()` / `total_score()` / `level_for_score()` — the
     unified scorer used by verdict.py, which combines static findings,
     dynamic (network) findings, and correlation findings into ONE
     explainable 0-10 risk score for the dashboard's verdict card.

Everything is capped to a strict 0-10 integer range — there is no 0-100
scale anywhere in this module.
"""


# ===========================================================================
# 1. Standalone static-only score (kept for static_analysis.py / CLI use)
# ===========================================================================

def static_score(partial: dict) -> int:
    """
    Calculates a balanced, capped risk score anchored from 0 to 10, based
    purely on static findings (no network/correlation data).
    """
    total_weighted_points = 0.0

    dangerous_perms = partial.get("dangerous_permissions", [])
    total_weighted_points += min(len(dangerous_perms) * 0.5, 2.5)

    exported_components = partial.get("exported_components", [])
    total_weighted_points += min(len(exported_components) * 0.5, 2.0)

    if partial.get("category_mismatch"):
        total_weighted_points += 1.5

    signing_issues = partial.get("signing", [])
    if signing_issues:
        total_weighted_points += 1.5

    iocs = partial.get("iocs", {})

    high_risk_count = (
        len(iocs.get("ips", [])) +
        len(iocs.get("tokens_secrets", [])) +
        len(iocs.get("suspicious_keywords", [])) +
        len(iocs.get("wallet_addresses", []))
    )
    total_weighted_points += min(high_risk_count * 1.0, 2.0)

    low_risk_count = (
        len(iocs.get("urls", [])) +
        len(iocs.get("emails", [])) +
        len(iocs.get("phone_numbers", []))
    )
    total_weighted_points += min(low_risk_count * 0.1, 0.5)

    return max(0, min(round(total_weighted_points), 10))


def get_verdict_band(score: int) -> str:
    """Classifies a standalone 0-10 static score into a human label."""
    if score > 6:
        return "High Risk"
    elif score >= 4:
        return "Medium Risk"
    else:
        return "Low Risk"


# ===========================================================================
# 2. Unified scorer — combines static + network + correlation for verdict.py
# ===========================================================================

def _flag(label, points, detail=""):
    return {"label": label, "points": points, "detail": detail}


def build_breakdown(static_report: dict, network_report: dict, correlation_report: dict) -> list:
    """
    Builds an itemized, explainable list of risk flags from all three
    analysis stages. Each item is capped individually so that no single
    category can dominate the score, and the grand total is hard-capped
    to 10 by total_score().
    """
    flags = []

    # --- Static: permissions -------------------------------------------
    dangerous_perms = static_report.get("dangerous_permissions", [])
    if dangerous_perms:
        names = ", ".join(p["permission"].split(".")[-1] for p in dangerous_perms[:5])
        flags.append(_flag(
            "Dangerous permissions declared",
            min(len(dangerous_perms), 3),
            names,
        ))

    if static_report.get("category_mismatch"):
        flags.append(_flag("App identity / permission mismatch", 2, static_report["category_mismatch"]))

    # --- Static: exported components ------------------------------------
    exported_issues = [f for f in static_report.get("exported_components", []) if f.get("issue")]
    if exported_issues:
        flags.append(_flag(
            "Exported components without permission guard",
            min(len(exported_issues), 2),
            ", ".join(f"{f['type']}:{f['name']}" for f in exported_issues[:3]),
        ))

    # --- Static: signing --------------------------------------------------
    signing_issues = static_report.get("signing", [])
    if signing_issues:
        flags.append(_flag("Signing certificate issue", 2, "; ".join(signing_issues[:2])))

    # --- Static: IOCs -------------------------------------------------------
    iocs = static_report.get("iocs", {})
    if iocs.get("ips"):
        flags.append(_flag("Hardcoded raw IP address(es)", min(len(iocs["ips"]), 3), ", ".join(iocs["ips"][:5])))
    if iocs.get("wallet_addresses"):
        flags.append(_flag("Cryptocurrency wallet ID(s) found", min(len(iocs["wallet_addresses"]) * 2, 4), ", ".join(iocs["wallet_addresses"][:3])))
    if iocs.get("tokens_secrets"):
        flags.append(_flag("Hardcoded token / API key pattern(s)", min(len(iocs["tokens_secrets"]), 2), ", ".join(iocs["tokens_secrets"][:3])))
    if iocs.get("suspicious_keywords"):
        flags.append(_flag("Suspicious code keyword(s)", min(len(iocs["suspicious_keywords"]) * 2, 4), ", ".join(iocs["suspicious_keywords"][:5])))

    # --- Dynamic: beaconing --------------------------------------------------
    beacons = network_report.get("beacons", [])
    for b in beacons[:3]:
        flags.append(_flag(
            f"Periodic beaconing to {b['host']}{b['path']}",
            min(b.get("score", 1), 3),
            "; ".join(b.get("reasons", [])),
        ))

    # --- Correlation: the strongest signals ------------------------------
    unclaimed = correlation_report.get("unclaimed", [])
    if unclaimed:
        flags.append(_flag(
            "Undisclosed runtime destination(s)",
            4,
            f"{len(unclaimed)} host(s) contacted at runtime with no trace in static code: "
            + ", ".join(u["host"] for u in unclaimed[:3]),
        ))

    dormant = correlation_report.get("dormant", [])
    if dormant:
        flags.append(_flag(
            "Dormant hardcoded destination(s)",
            2,
            f"{len(dormant)} hardcoded destination(s) never contacted this run: "
            + ", ".join(d["host"] for d in dormant[:3]),
        ))

    confirmed = correlation_report.get("confirmed", [])
    if confirmed:
        flags.append(_flag(
            "Hardcoded destination(s) confirmed active",
            1,
            f"{len(confirmed)} hardcoded destination(s) confirmed contacted at runtime.",
        ))

    return flags


def total_score(breakdown: list) -> int:
    """Sums all flag points and hard-caps the result to the 0-10 range."""
    raw_total = sum(f["points"] for f in breakdown)
    return max(0, min(round(raw_total), 10))


def level_for_score(score: int) -> str:
    """Maps a 0-10 score to a risk level used for CSS classes and copy."""
    if score >= 8:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 2:
        return "medium"
    return "low"
