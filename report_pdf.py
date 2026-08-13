# -*- coding: utf-8 -*-
"""
report_pdf.py
Generates PDF reports from an AnalysisResult (see analyzer.py).
Uses fpdf2 (pip install fpdf2), a lightweight pure-Python library that
packages cleanly with PyInstaller.

Two report types are available:
  - "technical": full detail — every extracted field and every finding
    with its weight/severity. For security analysts / IT.
  - "executive": a one-to-two page, jargon-free summary — verdict,
    recommendation, and the handful of findings that matter. For managers
    and non-technical stakeholders.

Part of E-MailX-Ray.
"""

from fpdf import FPDF

from report_common import build_summary, SEVERITY_LABELS

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

PAGE_WIDTH_USABLE = 178  # mm, with 16mm margins on A4


def _safe(text) -> str:
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


def _header_block(pdf, title, summary):
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 9, _safe(title), ln=1)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, _safe(f"Generated with {summary['app_name']} on {summary['generated_at']}"), ln=1)
    pdf.ln(4)

    color = RISK_COLORS_RGB.get(summary["risk_level"], (127, 127, 127))
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(
        0, 12,
        _safe(f"   Risk: {summary['risk_level']}    |    Score: {summary['score']}    |    "
              f"{summary['total_findings']} finding(s)"),
        ln=1, fill=True,
    )
    pdf.ln(6)


def _section_title(pdf, text):
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 8, _safe(text), ln=1)
    pdf.set_draw_color(210, 210, 210)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + PAGE_WIDTH_USABLE, pdf.get_y())
    pdf.ln(3)


def _callout_box(pdf, label, body, rgb):
    pdf.set_draw_color(*rgb)
    pdf.set_line_width(0.6)
    x, y = pdf.get_x(), pdf.get_y()
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*rgb)
    pdf.set_x(x + 4)
    pdf.multi_cell(PAGE_WIDTH_USABLE - 8, 6, _safe(label))
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    pdf.set_x(x + 4)
    pdf.multi_cell(PAGE_WIDTH_USABLE - 8, 5.6, _safe(body))
    y_end = pdf.get_y() + 2
    pdf.rect(x, y - 2, PAGE_WIDTH_USABLE, y_end - (y - 2))
    pdf.set_line_width(0.2)  # restore default so later rules aren't affected
    pdf.set_xy(x, y_end + 4)


# ----------------------------------------------------------------------
# Executive report
# ----------------------------------------------------------------------

def _build_executive_pdf(pdf, result, summary):
    _header_block(pdf, "Email Phishing Risk \u2014 Executive Summary", summary)

    pdf.set_font("Helvetica", "", 11.5)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(PAGE_WIDTH_USABLE, 6.5, _safe(summary["verdict"]))
    pdf.ln(4)

    rec_color = RISK_COLORS_RGB.get(summary["risk_level"], (80, 80, 80))
    _callout_box(pdf, "Recommended action", summary["recommendation"], rec_color)
    pdf.ln(2)

    _section_title(pdf, "Why")
    if summary["top_findings"]:
        for f in summary["top_findings"]:
            sev_color = SEVERITY_COLORS_RGB.get(f.severity, (80, 80, 80))
            pdf.set_font("Helvetica", "B", 10.5)
            pdf.set_text_color(*sev_color)
            pdf.multi_cell(0, 6, _safe(f"\u2022 [{SEVERITY_LABELS.get(f.severity, '')}] {f.rule}"))
            pdf.set_font("Helvetica", "", 9.8)
            pdf.set_text_color(70, 70, 70)
            pdf.set_x(pdf.l_margin + 6)
            pdf.multi_cell(PAGE_WIDTH_USABLE - 6, 5.4, _safe(f.detail))
            pdf.ln(2)
    else:
        pdf.set_font("Helvetica", "", 10.5)
        pdf.set_text_color(70, 70, 70)
        pdf.multi_cell(PAGE_WIDTH_USABLE, 6, _safe("No findings were raised by the analysis."))

    pdf.ln(2)
    c = summary["counts"]
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(
        PAGE_WIDTH_USABLE, 5.5,
        _safe(f"Full breakdown: {c['high']} high, {c['medium']} medium, {c['low']} low, "
              f"{c['ai']} AI-flagged, {c['info']} informational finding(s). "
              "See the technical report for complete details."),
    )


# ----------------------------------------------------------------------
# Technical report
# ----------------------------------------------------------------------

def _build_technical_pdf(pdf, result, summary, raw_header=None):
    _header_block(pdf, "Email Header Analysis Report \u2014 Technical Detail", summary)

    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(PAGE_WIDTH_USABLE, 5.6, _safe(summary["verdict"]))
    pdf.ln(4)

    # --- Extracted fields ---------------------------------------------
    _section_title(pdf, "Extracted fields")
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

    # --- Findings ---------------------------------------------------------
    _section_title(pdf, "Risk findings")
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

    # --- Optional appendix: raw header analyzed ----------------------------
    if raw_header:
        pdf.add_page()
        _section_title(pdf, "Appendix: raw header analyzed")
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(PAGE_WIDTH_USABLE, 4.2, _safe(raw_header))


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------

def generate_pdf_report(result, output_path: str, app_name: str = "E-MailX-Ray",
                         report_type: str = "technical", raw_header: str = None):
    """
    result: instance of analyzer.AnalysisResult
    output_path: path to save the .pdf to
    report_type: "technical" (full detail) or "executive" (short summary)
    raw_header: optional raw header text, included as an appendix in the
                technical report only
    """
    summary = build_summary(result, app_name=app_name)

    pdf = _ReportPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()

    if report_type == "executive":
        _build_executive_pdf(pdf, result, summary)
    else:
        _build_technical_pdf(pdf, result, summary, raw_header=raw_header)

    pdf.output(output_path)
