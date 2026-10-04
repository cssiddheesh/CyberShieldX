"""PDF report export (PRD section 14). Requires the optional reportlab package.

Renders the unified report layout to a single PDF: header, target, risk,
AI summary, findings, evidence, score contributions, recommendations,
limitations and sources. All text is sanitised plain text - never HTML.
"""
from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from reportlab.lib import colors


def _text(value: Any, limit: int = 1200) -> str:
    text = "" if value is None else str(value)
    return text[:limit].replace("\x00", "")


def render_pdf(report: dict[str, Any], scan: dict[str, Any] | None = None) -> bytes:
    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, spaceAfter=2 * mm)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceBefore=5 * mm,
                        spaceAfter=2 * mm, textColor=colors.HexColor("#1e3a5f"))
    body = ParagraphStyle("Body2", parent=styles["BodyText"], fontSize=10, leading=14)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, leading=12,
                           textColor=colors.HexColor("#444444"))

    story: list = []
    story.append(Paragraph("CyberShield X - Security Report", title))
    story.append(Paragraph("AI-powered 360-degree security intelligence. Defensive and educational.", small))
    story.append(Spacer(1, 3 * mm))

    meta = [
        ["Target", _text(report.get("target"), 300)],
        ["Module", _text(report.get("module_label"))],
        ["Analyzed", _text(report.get("analysis_time"))],
        ["Scan ID", _text(report.get("scan_id"))],
        ["Data", _text(report.get("data_label"))],
        ["Risk", f"{_text(report.get('overall_risk'))} ({report.get('risk_score')}/100)"],
        ["Confidence", f"{_text(report.get('confidence_label'))} ({report.get('confidence')})"],
        ["Verdict", _text(report.get("verdict_label"))],
    ]
    table = Table(meta, colWidths=[32 * mm, 150 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2fb")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9db1d8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)

    ai = report.get("ai_analysis") or {}
    if ai.get("executive_summary"):
        story.append(Paragraph("AI Security Analyst", h2))
        story.append(Paragraph(_text(ai["executive_summary"]), body))
        for line in (ai.get("observed") or [])[:6]:
            story.append(Paragraph("OBSERVED: " + _text(line, 600), small))
        if ai.get("assessment"):
            story.append(Paragraph("ASSESSMENT: " + _text(ai["assessment"], 800), small))

    story.append(Paragraph("Key findings", h2))
    findings = report.get("findings") or []
    if not findings:
        story.append(Paragraph("No suspicious findings. This does not prove safety.", body))
    for item in findings[:20]:
        story.append(Paragraph(
            f"[{_text(item.get('severity'))}] {_text(item.get('title'), 300)} "
            f"({_text(item.get('source'))})", body))

    story.append(Paragraph("Evidence", h2))
    story.append(Paragraph(_text(report.get("correlation_explanation"), 800), small))
    for row in (report.get("evidence") or [])[:25]:
        story.append(Paragraph(
            f"[{_text(row.get('severity'))}] {_text(row.get('source'))}: "
            f"{_text(row.get('finding'), 300)} - {_text(row.get('evidence'), 600)}", small))

    story.append(Paragraph("Why this score", h2))
    for contrib in (report.get("score_contributions") or [])[:20]:
        story.append(Paragraph(
            f"{_text(contrib.get('source'))} ({contrib.get('points')}): "
            f"{_text(contrib.get('detail'), 500)}", small))

    story.append(Paragraph("Recommended actions", h2))
    for rec in (report.get("recommendations") or [])[:10]:
        story.append(Paragraph("- " + _text(rec, 500), body))

    story.append(Paragraph("Limitations", h2))
    for lim in (report.get("limitations") or [])[:10]:
        story.append(Paragraph("- " + _text(lim, 500), small))

    story.append(Paragraph("Sources consulted", h2))
    for src in (report.get("sources_consulted") or [])[:15]:
        story.append(Paragraph(
            f"{_text(src.get('name'))}: {_text(src.get('state'))} - {_text(src.get('message'), 300)}",
            small))

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "CyberShield X is educational and is not a replacement for professional security products. "
        "Risk scores are internal assessments.", small))

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="CyberShield X Security Report",
                            author="CyberShield X")
    doc.build(story)
    return buffer.getvalue()
