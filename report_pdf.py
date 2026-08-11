# -*- coding: utf-8 -*-
"""
report_pdf.py
Generates a PDF report from an AnalysisResult (see analyzer.py).
Uses fpdf2 (pip install fpdf2), a lightweight pure-Python library that
packages cleanly with PyInstaller.

Part of E-MailX-Ray.
"""

import datetime
from fpdf import FPDF

RISK_COLORS_RGB = {
    "High": (192, 57, 43),
    "Medium": (230, 126, 34),
    "Low": (39, 174, 96),
}

SEVERITY_COLORS_RGB = {
    "high": (192, 57, 43),
    "medium": (230, 126, 34),
    "low": (154, 124, 12),
    "info": (44, 62, 80),
    "ai": (142, 68, 173),
}

SEVERITY_LABELS = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "ai": "AI",
}

PAGE_WIDTH_USABLE = 178  # mm, with 16mm margins on A4


def _safe(text: str) -> str:
    """
    Core PDF fonts (Helvetica) only support Latin-1. Replace any character
    outside that set (emoji, unusual symbols) instead of breaking PDF
    generation.
    """
    if text is None:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class _ReportPDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def generate_pdf_report(result, output_path: str, app_name: str = "E-MailX-Ray"):
    """
    result: instance of analyzer.AnalysisResult
    output_path: path to save the .pdf to
    """
    pdf = _ReportPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()

    # --- Title ------------------------------------------------------------
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 9, _safe("Email Header Analysis Report"), ln=1)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(120, 120, 120)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 6, _safe(f"Generated with {app_name} on {now}"), ln=1)
    pdf.ln(4)

    # --- Risk banner --------------------------------------------------------
    color = RISK_COLORS_RGB.get(result.risk_level, (127, 127, 127))
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(
        0, 12,
        _safe(f"   Risk: {result.risk_level}    |    Score: {result.score}    |    "
              f"{len(result.findings)} finding(s)"),
        ln=1, fill=True,
    )
    pdf.ln(6)

    # --- Extracted fields ---------------------------------------------------
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Extracted fields", ln=1)
    pdf.set_draw_color(210, 210, 210)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + PAGE_WIDTH_USABLE, pdf.get_y())
    pdf.ln(3)

    for k, v in result.fields.items():
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(PAGE_WIDTH_USABLE, 5.2, _safe(f"{k}:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(70, 70, 70)
        pdf.set_x(pdf.l_margin + 4)
        pdf.multi_cell(PAGE_WIDTH_USABLE - 4, 5.2, _safe(v))
        pdf.ln(1)

    pdf.ln(3)

    # --- Findings -------------------------------------------------------------
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 8, "Risk findings", ln=1)
    pdf.set_draw_color(210, 210, 210)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + PAGE_WIDTH_USABLE, pdf.get_y())
    pdf.ln(3)

    for f in result.findings:
        sev_color = SEVERITY_COLORS_RGB.get(f.severity, (80, 80, 80))
        label = SEVERITY_LABELS.get(f.severity, "")

        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_text_color(*sev_color)
        pdf.multi_cell(0, 6, _safe(f"[{label}] {f.rule}   (+{f.weight} pts)"))

        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(70, 70, 70)
        pdf.set_x(pdf.l_margin + 4)
        pdf.multi_cell(PAGE_WIDTH_USABLE - 4, 5.2, _safe(f.detail))
        pdf.ln(3)

    pdf.output(output_path)
