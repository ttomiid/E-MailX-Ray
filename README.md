# E-MailX-Ray

A desktop application (Tkinter) for analyzing email headers and detecting
phishing signals through heuristic rules — 100% offline (no external APIs
are queried).

## Requirements

- Python 3.9 or later (Tkinter ships with the standard Python installation
  for Windows, so nothing extra is needed there).
- The `fpdf2` library, for exporting reports as PDF:

```bash
pip install -r requirements.txt
```

## How to run it

```bash
python main.py
```

The app window opens. You can:

- **Paste** the raw header of an email (Gmail: "Show original" / Outlook:
  "View message source") into the left-hand panel.
- **Load a file** (`.eml`, `.txt`, etc.) with the corresponding button.
  Supports `.txt` exports from clients like ProtonMail, even when wrapped
  in a PGP signature block (`-----BEGIN PGP SIGNED MESSAGE-----`): the app
  automatically strips the wrapper and uses only the headers.
- Try the **"Example"** button to load a simulated phishing case.
- Click **"Analyze header"** to see:
  - The **risk score** and classification (Low / Medium / High).
  - The **extracted fields** (From, Reply-To, Return-Path, SPF/DKIM/DMARC, etc.)
  - The **details of each finding**, with its weight and explanation.
- **Export the report** as a `.txt` or `.pdf` file (with formatting, colors
  by risk level, and all findings spelled out).

## How to package it as a Windows .exe

Once the app is ready, on a Windows machine (or via cross-compilation) run:

```bash
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --onefile --windowed --name EMailXRay main.py
```

The executable will be at `dist/EMailXRay.exe`, ready to distribute without
needing Python installed on the target machine.

## Included heuristic rules

1. Missing or failed SPF / DKIM / DMARC (`Authentication-Results`)
2. Mismatch between `From` and `Return-Path`
3. Mismatch between `From` and `Reply-To` (reply hijacking)
4. `Message-ID` from a domain unrelated to the sender
5. Known-brand impersonation in the display name
6. Domain typosquatting (e.g. `paypa1.com` instead of `paypal.com`)
7. High-risk TLDs (`.tk`, `.xyz`, `.top`, etc.)
8. Excessive/obfuscated MIME encoding in headers
9. Missing `Received` headers, or a private-range origin IP
10. `X-Mailer` associated with bulk-sending tools
11. Urgency/pressure language in the subject
12. Generic or hidden recipients (`undisclosed-recipients`)
13. The mail provider itself (Gmail, ProtonMail, Outlook) already flagged
    the message as spam in internal headers (`X-Spam`, `X-Pm-Spam-Action`, etc.)
14. SPF/DKIM in a "pass" state, but for a domain different from the one
    shown in `From` (spoofing using the attacker's own infrastructure)
15. Randomly-generated-looking subdomains, typical of spam infrastructure
16. Sender name with a known brand obfuscated via dots/spaces
    (e.g. `P.A.Y.P.A.L`) to evade text filters
17. Subject with corrupted encoding / mojibake (`??????...`)

Each rule adds points to a total score:

- **0–19** → Low risk
- **20–49** → Medium risk
- **50+** → High risk

## Project structure

```
emailxray/
├── analyzer.py       # Analysis engine and heuristics (no UI dependencies)
├── report_pdf.py     # PDF report generation
├── main.py            # Tkinter graphical interface
├── requirements.txt  # Dependencies (fpdf2)
└── README.md
```

## Possible future improvements

- Query IP/domain reputation against public blocklists (VirusTotal,
  AbuseIPDB) — would require an API key and an internet connection.
- Live DNS resolution to validate SPF/DKIM for domains missing
  `Authentication-Results`.
- Also analyze the email body (URLs, attachments), not just the headers.
- Keep an analysis history in a local database (SQLite).
