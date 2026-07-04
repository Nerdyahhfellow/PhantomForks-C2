"""
analyzer/scoring.py

Risk scoring engine for the APK Threat Analysis Platform.
Normalizes various static threat vectors into a strict 0-10 scale.
"""

def static_score(partial: dict) -> int:
    """
    Calculates a balanced, capped risk score anchored from 0 to 10.
    
    Expected 'partial' structure:
    - dangerous_permissions (list)
    - exported_components (list)
    - category_mismatch (str or None)
    - signing (list)
    - iocs (dict containing lists: urls, ips, tokens_secrets, suspicious_keywords, etc.)
    """
    total_weighted_points = 0.0

    # 1. Dangerous Permissions Heuristic (Max Contribution: 2.5 points)
    dangerous_perms = partial.get("dangerous_permissions", [])
    total_weighted_points += min(len(dangerous_perms) * 0.5, 2.5)

    # 2. Unprotected Exported Components (Max Contribution: 2.0 points)
    exported_components = partial.get("exported_components", [])
    total_weighted_points += min(len(exported_components) * 0.5, 2.0)

    # 3. Category Mismatch (Max Contribution: 1.5 points)
    # Flagged if a low-functionality app requests high-privilege access
    if partial.get("category_mismatch"):
        total_weighted_points += 1.5

    # 4. Certificate Validation / Debug Signing (Max Contribution: 1.5 points)
    signing_issues = partial.get("signing", [])
    if signing_issues:
        total_weighted_points += 1.5

    # 5. String Extraction & Embedded IOCs (Max Contribution: 2.5 points total)
    iocs = partial.get("iocs", {})
    
    # High-Risk Network Signals (Raw IPs, Leaked Cryptographic Tokens, Suspicious Keywords)
    high_risk_count = (
        len(iocs.get("ips", [])) +
        len(iocs.get("tokens_secrets", [])) +
        len(iocs.get("suspicious_keywords", [])) +
        len(iocs.get("wallet_addresses", []))
    )
    total_weighted_points += min(high_risk_count * 1.0, 2.0)

    # Low-Risk Metadata Noise (Generic URLs, Emails, Phone Numbers)
    low_risk_count = (
        len(iocs.get("urls", [])) +
        len(iocs.get("emails", [])) +
        len(iocs.get("phone_numbers", []))
    )
    total_weighted_points += min(low_risk_count * 0.1, 0.5)

    # Normalize, round, and hard-cap between a 0 to 10 integer range
    final_score = max(0, min(round(total_weighted_points), 10))
    return final_score


def get_verdict_band(score: int) -> str:
    """
    Classifies the standardized 0-10 score into threat levels.
    
    Thresholds:
    - 0 to 3: Low Risk
    - 4 to 6: Medium Risk
    - Above 6: High Level Risk
    """
    if score > 6:
        return "High Risk"
    elif score >= 4:
        return "Medium Risk"
    else:
        return "Low Risk"