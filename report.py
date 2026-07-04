"""
report.py

Generates the "Forensic Report" PDF — the explicit deliverable called out
in the problem statement. Opens with a chain-of-custody style header
(file hash, filename, analysis timestamp, tool version) since that's a
real forensic requirement and instantly reads as more legitimate than a
typical hackathon demo screenshot.
"""

import datetime
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

TOOL_VERSION = "APK Threat Analysis Platform v1.0"

NAVY = colors.HexColor("#0b1220")
AMBER = colors.HexColor("#d9a441")
RED = colors.HexColor("#c0392b")
TEAL = colors.HexColor("#2e8b8b")
MUTED = colors.HexColor("#5a6472")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="CaseTitle", fontSize=20, leading=24, fontName="Helvetica-Bold", textColor=NAVY, spaceAfter=4))
    ss.add(ParagraphStyle(name="SectionHeading", fontSize=13, leading=16, fontName="Helvetica-Bold", textColor=NAVY, spaceBefore=16, spaceAfter=6))
    ss.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8.5, leading=11, textColor=colors.black))
    ss.add(ParagraphStyle(name="MonoSmall", fontName="Courier", fontSize=8, leading=10, textColor=MUTED))
    ss.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9.5, leading=13))
    ss.add(ParagraphStyle(name="Verdict", fontName="Helvetica-Bold", fontSize=14, leading=18))
    return ss


def _level_color(level):
    return {"critical": RED, "high": RED, "medium": AMBER, "low": TEAL}.get(level, MUTED)


def _custody_table(static_report, generated_at):
    meta = static_report.get("metadata", {})
    data = [
        ["Filename", meta.get("filename", "-")],
        ["SHA-256", meta.get("sha256", "-")],
        ["MD5", meta.get("md5", "-")],
        ["File size", f"{meta.get('size_bytes', 0):,} bytes"],
        ["Package", static_report.get("package", "-")],
        ["Report generated", generated_at],
        ["Tool / version", TOOL_VERSION],
    ]
    t = Table(data, colWidths=[1.6 * inch, 4.9 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f2f2")),
    ]))
    return t


def _bullet_list(items, styles, empty_text="None found."):
    if not items:
        return Paragraph(f"<i>{empty_text}</i>", styles["Body"])
    html = "<br/>".join(f"&bull; {i}" for i in items)
    return Paragraph(html, styles["Body"])


def generate_pdf(static_report: dict, network_report: dict, correlation: dict, verdict: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        title="APK Forensic Analysis Report",
    )
    styles = _styles()
    story = []

    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    story.append(Paragraph("APK FORENSIC ANALYSIS REPORT", styles["CaseTitle"]))
    story.append(Paragraph("Case File — Chain of Custody", styles["MonoSmall"]))
    story.append(Spacer(1, 10))
    story.append(_custody_table(static_report, generated_at))
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc")))

    # Verdict
    story.append(Paragraph("VERDICT", styles["SectionHeading"]))
    level = verdict.get("risk_level", "low").upper()
    score = verdict.get("risk_score", 0)
    verdict_style = ParagraphStyle(name="VerdictColored", parent=styles["Verdict"], textColor=_level_color(verdict.get("risk_level", "low")))
    story.append(Paragraph(f"Risk level: {level}  (score: {score})", verdict_style))
    story.append(Paragraph(verdict.get("summary", ""), styles["Body"]))
    story.append(Spacer(1, 6))
    for flag in verdict.get("top_flags", []):
        story.append(Paragraph(f"&bull; <b>+{flag['points']}</b> — {flag['label']}: {flag.get('detail','')}", styles["Body"]))

    # App info
    story.append(Paragraph("APPLICATION DETAILS", styles["SectionHeading"]))
    app_info = [
        f"App name: {static_report.get('app_name', '-')}",
        f"Package: {static_report.get('package', '-')}",
        f"Version: {static_report.get('version_name', '-')} (code {static_report.get('version_code', '-')})",
        f"Min SDK / Target SDK: {static_report.get('min_sdk', '-')} / {static_report.get('target_sdk', '-')}",
    ]
    story.append(_bullet_list(app_info, styles))

    # Permissions
    story.append(Paragraph("DANGEROUS PERMISSIONS", styles["SectionHeading"]))
    perm_items = [f"<b>{p['permission']}</b> — {p['reason']}" for p in static_report.get("dangerous_permissions", [])]
    story.append(_bullet_list(perm_items, styles))

    # Exported components
    story.append(Paragraph("EXPORTED COMPONENTS WITHOUT PERMISSION GUARD", styles["SectionHeading"]))
    exp_items = [f"{f['type']}: {f['name']}" for f in static_report.get("exported_components", []) if "issue" in f]
    story.append(_bullet_list(exp_items, styles))

    # IOCs
    story.append(Paragraph("EMBEDDED INDICATORS OF COMPROMISE (STATIC)", styles["SectionHeading"]))
    iocs = static_report.get("iocs", {})
    for label, key in [("URLs", "urls"), ("Raw IP addresses", "ips"), ("Suspicious keywords", "suspicious_keywords"),
                        ("Emails", "emails"), ("Wallet addresses", "wallet_addresses"), ("Tokens/secrets", "tokens_secrets")]:
        vals = iocs.get(key, [])
        if vals:
            story.append(Paragraph(f"<b>{label}</b> ({len(vals)})", styles["Body"]))
            story.append(Paragraph("<br/>".join(vals[:30]), styles["Mono"]))
            story.append(Spacer(1, 4))

    # Network
    story.append(Paragraph("NETWORK BEHAVIOR (DYNAMIC)", styles["SectionHeading"]))
    story.append(Paragraph(f"Total HTTP requests captured: {network_report.get('request_count', 0)}", styles["Body"]))
    beacon_items = [
        f"{b['host']}{b['path']} — {b['hits']} requests, avg interval {b['mean_interval']:.1f}s, score {b['score']} ({'; '.join(b['reasons'])})"
        for b in network_report.get("beacons", [])
    ]
    story.append(Paragraph("<b>Beaconing patterns detected:</b>", styles["Body"]))
    story.append(_bullet_list(beacon_items, styles, empty_text="No beacon-like patterns detected."))

    # Correlation
    story.append(Paragraph("CORRELATION: CLAIMED VS. OBSERVED BEHAVIOR", styles["SectionHeading"]))
    story.append(Paragraph(f"<b>Confirmed</b> — hardcoded in code AND contacted at runtime ({len(correlation.get('confirmed', []))})", styles["Body"]))
    story.append(_bullet_list([c["host"] for c in correlation.get("confirmed", [])], styles))
    story.append(Paragraph(f"<b>Dormant</b> — hardcoded but never contacted this run ({len(correlation.get('dormant', []))})", styles["Body"]))
    story.append(_bullet_list([d["host"] for d in correlation.get("dormant", [])], styles))
    story.append(Paragraph(f"<b>Unclaimed</b> — contacted at runtime with no trace in static code ({len(correlation.get('unclaimed', []))})", styles["Body"]))
    story.append(_bullet_list([u["host"] for u in correlation.get("unclaimed", [])], styles))

    if correlation.get("verdict_notes"):
        story.append(Spacer(1, 4))
        story.append(_bullet_list(correlation["verdict_notes"], styles))

    # Signing
    story.append(Paragraph("SIGNING CERTIFICATE", styles["SectionHeading"]))
    story.append(_bullet_list(static_report.get("signing", []), styles, empty_text="No issues found."))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        "This report was generated automatically for investigative triage purposes. "
        "Findings should be validated by a qualified analyst before use in legal proceedings.",
        styles["MonoSmall"]
    ))

    doc.build(story)
    return buf.getvalue()
