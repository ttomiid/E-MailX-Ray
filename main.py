# -*- coding: utf-8 -*-
"""
main.py
Interfaz gráfica (Tkinter) del Analizador de Cabeceras de Phishing.
Ejecutar con:  python main.py
Empaquetar a .exe con:  pyinstaller --onefile --windowed --name AnalizadorPhishing main.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import datetime

from analyzer import analyze_headers
from report_pdf import generate_pdf_report

APP_TITLE = "E-MailX-Ray"

RISK_COLORS = {
    "Alto": "#c0392b",
    "Medio": "#e67e22",
    "Bajo": "#27ae60",
}

SEVERITY_TAGS = {
    "high": ("🔴", "#c0392b"),
    "medium": ("🟠", "#e67e22"),
    "low": ("🟡", "#b7950b"),
    "info": ("ℹ️", "#2c3e50"),
}

EXAMPLE_HEADER = """From: "PayPal Support" <support@paypa1-secure.com>
Reply-To: recovery@paypa1-secure.com
Return-Path: <bounce@mailblaster.ru>
To: undisclosed-recipients:;
Subject: =?UTF-8?B?VXJnZW50ZTogdmVyaWZpY2EgdHUgY3VlbnRh?=
Date: Thu, 06 Aug 2026 10:15:00 -0300
Message-ID: <abc123@mailblaster.ru>
X-Mailer: PHPMailer 6.1
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=mailblaster.ru; dkim=none; dmarc=fail
Received: from [192.168.1.5] by mx.example.com; Thu, 06 Aug 2026 10:14:58 -0300
"""


class PhishingAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1050x720")
        self.minsize(900, 600)
        self.configure(bg="#f4f6f8")

        self._build_style()
        self._build_layout()

    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TButton", padding=6, font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), background="#f4f6f8")
        style.configure("Sub.TLabel", font=("Segoe UI", 9), background="#f4f6f8", foreground="#555")
        style.configure("Field.TLabel", font=("Segoe UI", 9, "bold"), background="#ffffff")
        style.configure("Value.TLabel", font=("Segoe UI", 9), background="#ffffff")
        style.configure("TNotebook", background="#f4f6f8")

    # ------------------------------------------------------------------
    def _build_layout(self):
        # --- Encabezado ---
        top = tk.Frame(self, bg="#f4f6f8")
        top.pack(fill="x", padx=16, pady=(14, 6))
        ttk.Label(top, text="🛡️  " + APP_TITLE, style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            top,
            text="Pegá la cabecera de un correo (o cargá un archivo .eml / .txt) y analizá señales de phishing.",
            style="Sub.TLabel",
        ).pack(anchor="w")

        # --- Panel principal dividido ---
        main_pane = tk.PanedWindow(self, orient="horizontal", sashwidth=6, bg="#f4f6f8")
        main_pane.pack(fill="both", expand=True, padx=16, pady=10)

        # ---- Izquierda: entrada de texto ----
        left = tk.Frame(main_pane, bg="#f4f6f8")
        main_pane.add(left, minsize=380, width=430)

        btn_row = tk.Frame(left, bg="#f4f6f8")
        btn_row.pack(fill="x", pady=(0, 6))
        ttk.Button(btn_row, text="📂 Cargar archivo", command=self.load_eml).pack(side="left")
        ttk.Button(btn_row, text="🧪 Ejemplo", command=self.load_example).pack(side="left", padx=6)
        ttk.Button(btn_row, text="🗑️ Limpiar", command=self.clear_input).pack(side="left")

        self.input_text = scrolledtext.ScrolledText(
            left, wrap="word", font=("Consolas", 9), height=25, undo=True
        )
        self.input_text.pack(fill="both", expand=True)

        analyze_row = tk.Frame(left, bg="#f4f6f8")
        analyze_row.pack(fill="x", pady=8)
        analyze_btn = tk.Button(
            analyze_row, text="🔎 Analizar cabecera", command=self.run_analysis,
            bg="#2c3e50", fg="white", font=("Segoe UI", 10, "bold"),
            relief="flat", padx=14, pady=8, cursor="hand2",
        )
        analyze_btn.pack(fill="x")

        # ---- Derecha: resultados ----
        right = tk.Frame(main_pane, bg="#f4f6f8")
        main_pane.add(right, minsize=420)

        # Tarjeta de score
        self.score_frame = tk.Frame(right, bg="#ffffff", bd=1, relief="solid")
        self.score_frame.pack(fill="x", pady=(0, 10))
        self.score_label = tk.Label(
            self.score_frame, text="Sin analizar todavía", font=("Segoe UI", 16, "bold"),
            bg="#ffffff", fg="#7f8c8d", pady=14,
        )
        self.score_label.pack(fill="x")

        # Notebook con pestañas: Campos / Hallazgos
        notebook = ttk.Notebook(right)
        notebook.pack(fill="both", expand=True)

        # Pestaña Campos extraídos
        fields_tab = tk.Frame(notebook, bg="#ffffff")
        notebook.add(fields_tab, text="Campos extraídos")
        self.fields_container = tk.Frame(fields_tab, bg="#ffffff")
        self.fields_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Pestaña Hallazgos
        findings_tab = tk.Frame(notebook, bg="#ffffff")
        notebook.add(findings_tab, text="Hallazgos de riesgo")
        self.findings_text = scrolledtext.ScrolledText(
            findings_tab, wrap="word", font=("Segoe UI", 10), bd=0, state="disabled"
        )
        self.findings_text.pack(fill="both", expand=True, padx=6, pady=6)

        export_row = tk.Frame(right, bg="#f4f6f8")
        export_row.pack(fill="x", pady=(8, 0))
        ttk.Button(export_row, text="📄 Exportar .pdf", command=self.export_report_pdf).pack(side="right", padx=(6, 0))
        ttk.Button(export_row, text="💾 Exportar .txt", command=self.export_report_txt).pack(side="right")

        self.last_result = None

    # ------------------------------------------------------------------
    def load_eml(self):
        path = filedialog.askopenfilename(
            title="Seleccionar archivo de cabecera (.eml, .txt, ...)",
            filetypes=[
                ("Cabeceras / correos", "*.eml *.txt *.msg *.header"),
                ("Archivo .eml", "*.eml"),
                ("Archivo de texto", "*.txt"),
                ("Todos los archivos", "*.*"),
            ],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", content)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo:\n{e}")

    def load_example(self):
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", EXAMPLE_HEADER)

    def clear_input(self):
        self.input_text.delete("1.0", "end")

    # ------------------------------------------------------------------
    def run_analysis(self):
        raw = self.input_text.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("Atención", "Pegá o cargá una cabecera de correo primero.")
            return
        try:
            result = analyze_headers(raw)
        except Exception as e:
            messagebox.showerror("Error de análisis", f"No se pudo analizar la cabecera:\n{e}")
            return

        self.last_result = result
        self._render_score(result)
        self._render_fields(result)
        self._render_findings(result)

    # ------------------------------------------------------------------
    def _render_score(self, result):
        color = RISK_COLORS.get(result.risk_level, "#7f8c8d")
        self.score_frame.configure(bg=color)
        self.score_label.configure(
            bg=color, fg="white",
            text=f"Riesgo: {result.risk_level}   |   Puntaje: {result.score}   |   "
                 f"{len(result.findings)} hallazgo(s)",
        )

    def _render_fields(self, result):
        for w in self.fields_container.winfo_children():
            w.destroy()
        for i, (k, v) in enumerate(result.fields.items()):
            row = tk.Frame(self.fields_container, bg="#ffffff")
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=k + ":", style="Field.TLabel", width=24, anchor="w").pack(side="left")
            val = (v[:120] + "…") if len(v) > 120 else v
            ttk.Label(row, text=val, style="Value.TLabel", anchor="w", wraplength=380, justify="left").pack(
                side="left", fill="x", expand=True
            )

    def _render_findings(self, result):
        self.findings_text.configure(state="normal")
        self.findings_text.delete("1.0", "end")
        for f in result.findings:
            icon, color = SEVERITY_TAGS.get(f.severity, ("•", "#333"))
            tag = f"tag_{id(f)}"
            self.findings_text.insert("end", f"{icon} {f.rule}", tag)
            self.findings_text.tag_config(tag, foreground=color, font=("Segoe UI", 10, "bold"))
            self.findings_text.insert("end", f"   (+{f.weight} pts)\n")
            self.findings_text.insert("end", f"    {f.detail}\n\n")
        self.findings_text.configure(state="disabled")

    # ------------------------------------------------------------------
    def export_report_txt(self):
        if not self.last_result:
            messagebox.showwarning("Atención", "Primero analizá una cabecera.")
            return
        path = filedialog.asksaveasfilename(
            title="Guardar informe",
            defaultextension=".txt",
            filetypes=[("Archivo de texto", "*.txt")],
            initialfile=f"informe_phishing_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.txt",
        )
        if not path:
            return
        result = self.last_result
        lines = [
            "=" * 60,
            "INFORME DE ANÁLISIS DE CABECERA DE CORREO",
            "=" * 60,
            f"Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Riesgo: {result.risk_level}   |   Puntaje total: {result.score}",
            "",
            "-- Campos extraídos --",
        ]
        for k, v in result.fields.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("-- Hallazgos --")
        for f in result.findings:
            lines.append(f"[{f.severity.upper()}] {f.rule} (+{f.weight} pts)")
            lines.append(f"  {f.detail}")
            lines.append("")

        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            messagebox.showinfo("Listo", f"Informe guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el informe:\n{e}")

    def export_report_pdf(self):
        if not self.last_result:
            messagebox.showwarning("Atención", "Primero analizá una cabecera.")
            return
        path = filedialog.asksaveasfilename(
            title="Guardar informe en PDF",
            defaultextension=".pdf",
            filetypes=[("Documento PDF", "*.pdf")],
            initialfile=f"informe_phishing_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
        )
        if not path:
            return
        try:
            generate_pdf_report(self.last_result, path)
            messagebox.showinfo("Listo", f"Informe PDF guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el PDF:\n{e}")


if __name__ == "__main__":
    app = PhishingAnalyzerApp()
    app.mainloop()
