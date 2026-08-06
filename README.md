# Analizador de Cabeceras de Phishing

Aplicación de escritorio (Tkinter) para analizar cabeceras de email y detectar
señales de phishing mediante reglas heurísticas, 100% offline (no consulta
APIs externas).

## Requisitos

- Python 3.9 o superior (Tkinter viene incluido en la instalación estándar de
  Python para Windows, no hace falta instalar nada extra).
- La librería `fpdf2` para exportar informes en PDF:

```bash
pip install -r requirements.txt
```

## Cómo ejecutarlo

```bash
python main.py
```

Se abre la ventana de la app. Podés:

- **Pegar** la cabecera cruda de un correo (Gmail: "Mostrar original" /
  Outlook: "Ver origen del mensaje") en el panel izquierdo.
- **Cargar un archivo** (`.eml`, `.txt`, etc.) con el botón correspondiente.
  Soporta exports tipo `.txt` de clientes como ProtonMail, incluso si vienen
  envueltos en un bloque de firma PGP (`-----BEGIN PGP SIGNED MESSAGE-----`):
  la app recorta automáticamente el envoltorio y usa solo las cabeceras.
- Probar el botón **"Ejemplo"** para ver un caso de phishing simulado ya cargado.
- Apretar **"Analizar cabecera"** para ver:
  - El **puntaje de riesgo** y clasificación (Bajo / Medio / Alto).
  - Los **campos extraídos** (From, Reply-To, Return-Path, SPF/DKIM/DMARC, etc.)
  - El **detalle de cada hallazgo** con su peso y explicación.
- **Exportar el informe** a un archivo `.txt` o `.pdf` (con formato,
  colores según nivel de riesgo, y todos los hallazgos detallados).

## Cómo empaquetarlo como .exe para Windows

Con la app terminada, en una máquina Windows (o vía cross-compile) corré:

```bash
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --onefile --windowed --name AnalizadorPhishing main.py
```

El ejecutable queda en `dist/AnalizadorPhishing.exe`, listo para repartir sin
necesitar Python instalado en la máquina destino.

## Reglas heurísticas incluidas

1. Ausencia o fallo de SPF / DKIM / DMARC (`Authentication-Results`)
2. Mismatch entre `From` y `Return-Path`
3. Mismatch entre `From` y `Reply-To` (desvío de respuestas)
4. `Message-ID` de dominio distinto al del remitente
5. Suplantación de marcas conocidas en el nombre mostrado
6. Typosquatting de dominio (ej. `paypa1.com` en vez de `paypal.com`)
7. TLDs de alto riesgo (`.tk`, `.xyz`, `.top`, etc.)
8. Codificación MIME excesiva/ofuscada en cabeceras
9. Ausencia de cabeceras `Received` o IP de origen privada
10. `X-Mailer` asociado a herramientas de envío masivo
11. Lenguaje de urgencia/presión en el asunto
12. Destinatarios genéricos u ocultos (`undisclosed-recipients`)
13. El propio proveedor de correo (Gmail, ProtonMail, Outlook) ya lo marcó
    como spam en cabeceras internas (`X-Spam`, `X-Pm-Spam-Action`, etc.)
14. SPF/DKIM en estado "pass" pero para un dominio distinto al que se
    muestra en `From` (spoofing con infraestructura propia del atacante)
15. Subdominios con apariencia aleatoria (generados automáticamente),
    típicos de infraestructura de spam
16. Nombre del remitente con marca conocida ofuscada con puntos/espacios
    (ej. `P.A.Y.P.A.L`) para evadir filtros de texto
17. Asunto con codificación corrupta / mojibake (`??????...`)

Cada regla suma puntos a un score total:

- **0–19** → Riesgo Bajo
- **20–49** → Riesgo Medio
- **50+** → Riesgo Alto

## Estructura del proyecto

```
phishing_analyzer/
├── analyzer.py       # Motor de análisis y heurísticas (sin dependencias de UI)
├── report_pdf.py     # Generación del informe en PDF
├── main.py           # Interfaz gráfica Tkinter
├── requirements.txt  # Dependencias (fpdf2)
└── README.md
```

## Posibles mejoras a futuro

- Consultar reputación de IP/dominio contra listas negras públicas (VirusTotal,
  AbuseIPDB) — requeriría API key y conexión a internet.
- Resolución DNS en vivo para validar SPF/DKIM en dominios sin
  `Authentication-Results`.
- Analizar también el cuerpo del correo (URLs, adjuntos) además de las cabeceras.
- Guardar un historial de análisis en una base de datos local (SQLite).
