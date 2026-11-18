"""
SCAM KILLER — PDF Report Generation Service
Generates formal, branded Cybersecurity Threat Intelligence Assessment Reports in PDF format.
Powered by Google Gemini AI assessment data.
"""

import io
from datetime import datetime
from typing import Dict, Any, List

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    class _DummyColors:
        @staticmethod
        def HexColor(c): return c
    colors = _DummyColors()


class ReportService:
    """Generates downloadable PDF assessment reports."""

    DARK_GREEN = colors.HexColor("#092318")
    FOREST_GREEN = colors.HexColor("#0e3323")
    EMERALD_GREEN = colors.HexColor("#059669")
    ROSE_RED = colors.HexColor("#e11d48")
    AMBER_ORANGE = colors.HexColor("#d97706")
    SLATE_DARK = colors.HexColor("#0f172a")
    SLATE_MUTED = colors.HexColor("#64748b")
    SLATE_LIGHT = colors.HexColor("#f8fafc")
    BORDER_COLOR = colors.HexColor("#e2e8f0")

    @classmethod
    def is_available(cls) -> bool:
        """Returns True if reportlab is installed."""
        return REPORTLAB_AVAILABLE

    @classmethod
    def generate_pdf_report(cls, report_data: Dict[str, Any]) -> bytes:
        """
        Builds a comprehensive PDF report from assessment data.
        Returns bytes of the compiled PDF.
        """
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("ReportLab library is not installed in the environment.")

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Typography Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.white
        )

        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#86efac")
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=cls.DARK_GREEN,
            spaceBefore=10,
            spaceAfter=4
        )

        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=cls.SLATE_DARK
        )

        badge_style = ParagraphStyle(
            "BadgeStyle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.white,
            alignment=1
        )

        meta_label_style = ParagraphStyle(
            "MetaLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=cls.SLATE_MUTED
        )

        meta_val_style = ParagraphStyle(
            "MetaVal",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=cls.SLATE_DARK
        )

        story = []

        # 1. Header Banner Table
        header_text = [
            Paragraph("SCAM KILLER", title_style),
            Paragraph("AI-Powered Cybersecurity Threat Intelligence & Scam Detector", subtitle_style)
        ]
        header_table = Table([[header_text]], colWidths=[532])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), cls.DARK_GREEN),
            ("PADDING", (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 14))

        # 2. Assessment Summary & Classification Badge
        classification = str(report_data.get("risk_level", "caution")).lower()
        if "suspicious" in classification:
            badge_bg = cls.ROSE_RED
            badge_text = "▲ SUSPICIOUS — HIGH THREAT CONFIDENCE"
        elif "no clear" in classification or "safe" in classification or "no_clear" in classification:
            badge_bg = cls.EMERALD_GREEN
            badge_text = "✓ NO CLEAR WARNING SIGNS"
        else:
            badge_bg = cls.AMBER_ORANGE
            badge_text = "● CAUTION — VERIFY INDEPENDENTLY"

        scan_id = report_data.get("scan_id", f"SK-{datetime.now().strftime('%y%m%d%H%M')}")
        scan_date = report_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M UTC"))
        target_item = report_data.get("submitted_item", report_data.get("input_snippet", "User submitted input"))
        engine_status = report_data.get("engine_status", "Google Gemini AI Intelligence")

        meta_data = [
            [
                Paragraph("Assessment ID", meta_label_style),
                Paragraph(str(scan_id), meta_val_style),
                Paragraph("Evaluation Engine", meta_label_style),
                Paragraph(str(engine_status), meta_val_style)
            ],
            [
                Paragraph("Generated Timestamp", meta_label_style),
                Paragraph(str(scan_date), meta_val_style),
                Paragraph("Verification Policy", meta_label_style),
                Paragraph("Strict Zero-Log Privacy", meta_val_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[110, 156, 110, 156])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), cls.SLATE_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, cls.BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, cls.BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # Verdict Banner
        verdict_cell = Paragraph(badge_text, badge_style)
        verdict_table = Table([[verdict_cell]], colWidths=[532])
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), badge_bg),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 12))

        # 3. Analyzed Input Excerpt
        story.append(Paragraph("Analyzed Content Excerpt", h2_style))
        excerpt_cell = Paragraph(f"<i>\"{target_item}\"</i>", body_style)
        excerpt_table = Table([[excerpt_cell]], colWidths=[532])
        excerpt_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, cls.BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(excerpt_table)
        story.append(Spacer(1, 10))

        # 4. Plain-Language Explanation
        story.append(Paragraph("Executive Summary & Plain-Language Assessment", h2_style))
        explanation_text = report_data.get("explanation") or report_data.get("summary") or "The submitted content was analyzed using our multi-vector threat signature pipeline."
        story.append(Paragraph(explanation_text, body_style))
        story.append(Spacer(1, 10))

        # 5. Detected Threat Indicators
        indicators = report_data.get("detected_indicators", [])
        if indicators:
            story.append(Paragraph("Detected Warning Indicators", h2_style))
            ind_rows = []
            for ind in indicators:
                ind_text = ind.get("title", str(ind)) if isinstance(ind, dict) else str(ind)
                ind_exp = ind.get("explanation", "") if isinstance(ind, dict) else ""
                full_text = f"<b>{ind_text}</b>: {ind_exp}" if ind_exp else ind_text
                ind_rows.append([
                    Paragraph("•", ParagraphStyle("Bullet", parent=styles["Normal"], fontName="Helvetica-Bold", textColor=cls.ROSE_RED)),
                    Paragraph(full_text, body_style)
                ])
            ind_table = Table(ind_rows, colWidths=[20, 512])
            ind_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(ind_table)
            story.append(Spacer(1, 10))

        # 6. Why It Matters
        why_matters = report_data.get("why_it_matters", (
            "Cybercriminals use manufactured urgency, fake brand authority, and deceptive links to manipulate victims "
            "into authorizing fraudulent transactions, installing malicious packages, or surrendering sensitive credentials."
        ))
        story.append(Paragraph("Why This Assessment Matters", h2_style))
        story.append(Paragraph(why_matters, body_style))
        story.append(Spacer(1, 10))

        # 7. Independent Verification Guidance
        verification_advice = report_data.get("verification_advice")
        if verification_advice:
            story.append(Paragraph("Independent Verification Guidance", h2_style))
            story.append(Paragraph(verification_advice, body_style))
            story.append(Spacer(1, 10))

        # 8. Recommended Safe Next Steps
        steps = report_data.get("recommended_actions") or report_data.get("recommended_steps", [
            "Do not click any embedded links or dial unverified numbers found in the message.",
            "Verify the communication independently through the organization's verified official portal or app.",
            "Never share One-Time Passwords (OTP), UPI PINs, or banking passwords under any circumstance.",
            "Report fraudulent messages to your national cybercrime reporting portal or official telecom spam authority."
        ])
        story.append(Paragraph("Recommended Safe Next Steps", h2_style))
        step_rows = []
        for i, step in enumerate(steps, 1):
            step_rows.append([
                Paragraph(f"{i}.", ParagraphStyle("StepNum", parent=styles["Normal"], fontName="Helvetica-Bold", textColor=cls.EMERALD_GREEN)),
                Paragraph(step, body_style)
            ])
        step_table = Table(step_rows, colWidths=[20, 512])
        step_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(step_table)
        story.append(Spacer(1, 10))

        # 9. Important Uncertainties & Limitations
        uncertainties = report_data.get("important_uncertainties") or report_data.get("limitations", [])
        if uncertainties:
            story.append(Paragraph("Scope & Important Uncertainties", h2_style))
            unc_rows = []
            for u in uncertainties:
                unc_rows.append([
                    Paragraph("–", ParagraphStyle("Dash", parent=styles["Normal"], fontName="Helvetica", textColor=cls.SLATE_MUTED)),
                    Paragraph(u, ParagraphStyle("UncertaintyText", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=9, leading=13, textColor=cls.SLATE_MUTED))
                ])
            unc_table = Table(unc_rows, colWidths=[20, 512])
            unc_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 2),
            ]))
            story.append(unc_table)
            story.append(Spacer(1, 12))

        # 10. Footer & Privacy Assurance
        story.append(HRFlowable(width="100%", thickness=0.5, color=cls.BORDER_COLOR, spaceBefore=4, spaceAfter=8))
        disclaimer = (
            "<b>Privacy Notice:</b> SCAM KILLER operates under strict client-privacy safeguards. All personal credentials, "
            "card numbers, and secret tokens are sanitized prior to telemetry recording. This assessment represents AI-powered "
            "risk analysis and does not constitute formal legal counsel."
        )
        story.append(Paragraph(disclaimer, ParagraphStyle("FooterText", parent=styles["Normal"], fontName="Helvetica", fontSize=7.5, leading=10, textColor=cls.SLATE_MUTED)))

        # Build document
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
