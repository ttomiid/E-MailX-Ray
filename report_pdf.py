# -*- coding: utf-8 -*-
"""
report_pdf.py
Genera un informe en PDF a partir de un AnalysisResult (ver analyzer.py).
Usa fpdf2 (pip install fpdf2), una librería pura Python liviana y fácil
de empaquetar con PyInstaller.
"""

import datetime
from fpdf import FPDF

RISK_COLORS_RGB = {
    "Alto": (192, 57, 43),
    "Medio": (230, 126, 34),
    "Bajo": (39, 174, 96),
}

SEVERITY_COLORS_RGB = {
    "high": (192, 57, 43),
    "medium": (230, 126, 34),
    "low": (154, 124, 12),
    "info": (44, 62, 80),
}

SEVERITY_LABELS = {
    "high": "ALTO",
    "medium": "MEDIO",
    "low": "BAJO",
    "info": "INFO",
}

PAGE_WIDTH_USABLE = 178  # mm, con márgenes de 16mm en A4


def _safe(text: str) -> str:
    """
    Las fuentes 'core' de PDF (Helvetica) solo soportan Latin-1. Reemplaza
    cualquier carácter fuera de ese set (emojis, símbolos raros) en vez de
    romper la generación del PDF.
    """
    if text is None:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class _ReportPDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Página {self.page_no()}", align="C")


def generate_pdf_report(result, output_path: str, app_name: str = "E-MailX-Ray"):
    """
    result: instancia de analyzer.AnalysisResult
    output_path: ruta donde guardar el .pdf
    """
    pdf = _ReportPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()

    # --- Título ---------------------------------------------------------
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 9, _safe("Informe de Analisis de Cabecera de Correo"), ln=1)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(120, 120, 120)
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 6, _safe(f"Generado con {app_name} el {fecha}"), ln=1)
    pdf.ln(4)

    # --- Banda de riesgo --------------------------------------------------
    color = RISK_COLORS_RGB.get(result.risk_level, (127, 127, 127))
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(
        0, 12,
        _safe(f"   Riesgo: {result.risk_level}    |    Puntaje: {result.score}    |    "
              f"{len(result.findings)} hallazgo(s)"),
        ln=1, fill=True,
    )
    pdf.ln(6)

    # --- Campos extraídos ---------------------------------------------------
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Campos extraidos", ln=1)
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

    # --- Hallazgos ------------------------------------------------------------
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 8, "Hallazgos de riesgo", ln=1)
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
