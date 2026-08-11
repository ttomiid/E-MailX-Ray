# 🛡️ E-MailX-Ray

<img width="1536" height="1024" alt="email_xray_eng" src="https://github.com/user-attachments/assets/a34cbbbf-0b45-473d-bc99-9c62e11d3e18" />


**E-MailX-Ray** is a desktop tool (Tkinter GUI) that analyzes raw email headers and body content to detect phishing, spoofing, and social-engineering signals — entirely offline, no external services required. An optional module can additionally use an LLM (local via Ollama, or Claude via API) to analyze the email body for contextual red flags.

> ⚠️ **Defensive tool.** E-MailX-Ray does not send, receive, or modify emails. It only reads the raw text you paste or load (`.eml` / `.txt`) and reports risk indicators. It's meant to help you decide whether a suspicious email deserves further scrutiny — it does **not** guarantee an email is safe or malicious.

---

## ✨ Features

- **Paste or load** raw email source (`.eml`, `.txt`, or plain header block).
- **31 built-in heuristic rules** covering authentication, domain spoofing, link analysis, attachment risk, and social-engineering patterns (see full list below).
- **Risk score & level** (Low / Medium / High) computed from weighted findings.
- **Optional AI body analysis** via [LangChain](https://python.langchain.com/), pluggable between:
  - **Ollama** (free, local, runs entirely on your machine)
  - **Anthropic Claude** (paid, requires an API key)
- **Export reports** as `.txt` or a formatted `.pdf`.
- 100% offline for the heuristic engine — no data leaves your machine unless you explicitly enable the AI body analysis.

---

## 📸 How it works

1. Paste the raw headers (and, optionally, the full body) of a suspicious email, or load a `.eml`/`.txt` file.
2. Click **Analyze header**. The heuristic engine parses the message and runs all detection rules.
3. Review the **risk score**, the **extracted fields** tab, and the **risk findings** tab (each finding shows its severity, point weight, and a plain-language explanation).
4. *(Optional)* Enable **AI body analysis** to also have an LLM inspect the email body for phishing language, credential requests, or brand impersonation that the offline heuristics might miss.
5. Export the result as a `.txt` or `.pdf` report if you need to share or archive it.

---

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/E-MailX-Ray.git
cd E-MailX-Ray
pip install -r requirements.txt   # see "Dependencies" below
python main.py
```

### Packaging as a standalone executable

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name EMailXRay main.py
```

### Dependencies

| Package               | Required for                                  |
|------------------------|------------------------------------------------|
| `fpdf2`                 | PDF report export (`report_pdf.py`)             |
| `langchain-core`         | AI body analysis (message formatting)           |
| `pydantic`               | AI body analysis (structured output validation) |
| `langchain-ollama`       | AI body analysis with a local Ollama model      |
| `langchain-anthropic`    | AI body analysis with Claude via API            |

The GUI and the full heuristic engine (`analyzer.py`) work with **zero external dependencies** beyond the Python standard library — `langchain-*` packages are only imported lazily, the moment you actually enable AI body analysis.

---

## 🔍 Detection engine

All heuristics live in `analyzer.py` and run completely offline. Each rule adds a **weighted score** and a **severity** (`info` / `low` / `medium` / `high`) to the result. The final verdict is:

| Score | Risk level |
|-------|------------|
| ≥ 50  | 🔴 High    |
| ≥ 20  | 🟠 Medium  |
| < 20  | 🟡 Low     |

### Authentication & domain-alignment rules
1. **SPF / DKIM / DMARC status** — flags `fail`, `softfail`, or missing records.
2. **From vs. Return-Path mismatch** — unrelated bounce domain.
3. **From vs. Reply-To mismatch** — replies silently redirected elsewhere.
4. **Message-ID from an unrelated domain**.
5. **SPF/DKIM "pass" for a domain different from the visible sender** — a valid authentication result does *not* mean the visible sender is legitimate; the attacker's own domain can pass its own checks.

### Impersonation & typosquatting
6. **Known brand mentioned in the display name but sent from an unrelated domain.**
7. **Brand name sent from free webmail** (Gmail, Outlook, etc.).
8. **Domain typosquatting** — text-similarity match against a curated list of commonly-impersonated brands, *now also catching character-substitution tricks* (`0`/`o`, `1`/`l`, `rn`/`m`).
9. **High-risk TLD** (`.tk`, `.xyz`, `.click`, `.top`, etc.).
10. **Internationalized domain names (punycode)** — detects `xn--` domains and decodes them, since IDN/homograph spoofing only becomes visible after decoding.
11. **Homoglyph brand impersonation** — normalizes Cyrillic/Greek look-alike characters (e.g. Cyrillic "а" vs Latin "a") before comparing against known brand domains.

### Header structure & anomalies
12. **Suspicious MIME encoding** (excessive `=?...?=` blocks used to evade filters).
13. **Empty or suspicious `Received` chain**, including private/internal-IP first hops.
14. **Suspicious `X-Mailer`** (bulk/automated sending tools).
15. **Generic or hidden recipient** (`undisclosed-recipients`, `user@`, etc.).
16. **Provider already flagged it as spam** (`X-Spam-*` headers).
17. **Randomly-generated-looking subdomains** in From / Return-Path / Message-ID — typical of auto-provisioned spam infrastructure.
18. **Corrupted subject encoding (mojibake)**.
19. **Duplicate critical headers** (`From`, `Reply-To`, `Return-Path`) — a technique to smuggle a different address past filters than the one shown to the user.
20. **Conflicting `Authentication-Results`** — multiple headers with different SPF/DKIM/DMARC verdicts (only the one added by your own organization's final server should be trusted).
21. **`Date` header anomaly** — timestamps implausibly in the future or the distant past.
22. **Randomly-generated-looking sender mailbox** (the local-part before the `@`, not just the domain).
23. **Unusually high number of recipients** in `To`/`Cc`.
24. **Marketing tone from a "known brand" domain with no `List-Unsubscribe` header** (real companies almost always include it for CAN-SPAM/GDPR compliance).

### Social engineering
25. **Urgency/pressure language in the subject** (`urgent`, `account locked`, `verify your account`, etc.).
26. **Business Email Compromise (BEC) pattern** — combines executive-sounding display names or free-webmail senders with wire-transfer/gift-card/confidentiality language in the subject or body.

### Link analysis (body)
27. **Anchor text vs. real destination mismatch** — a link that visually displays one domain but points to another.
28. **Raw IP address as the link host**, instead of a domain name.
29. **URL-shortening services** (bit.ly, tinyurl, t.co, etc.) that hide the real destination.
30. **`@` obfuscation trick** in URLs (`http://real-brand.com@evil.ru/`), which browsers resolve using only the host *after* the `@`.
31. **Link domain impersonating a known brand** — the same typosquat/homoglyph checks applied to From are also applied to every link found in the body.

### Attachment analysis
32. **Dangerous attachment extensions** (`.exe`, `.js`, `.vbs`, `.hta`, `.iso`, `.lnk`, etc.).
33. **Disguised double-extension attachments** (e.g. `invoice.pdf.exe`), a classic trick that relies on hidden file extensions in the OS file explorer.

> Some rules are conditioned on others (e.g. link/attachment analysis only runs when the body/attachments are present), so the exact count of findings varies by input.

---

## 🤖 Optional AI body analysis

The heuristic engine only sees **headers and structural body signals** (links, attachments, MIME structure). The optional AI module (`llm_body_analyzer.py`) reads the actual **text of the email body** and asks an LLM to flag concrete phishing indicators the rules above can't reason about — tone, context, and language nuance.

- Configure the **provider** (`ollama` or `anthropic`), **model**, and (for Anthropic) your **API key** directly in the GUI.
- The AI step is **isolated**: if it fails (Ollama not running, invalid API key, network error) the header-only heuristic results are still shown — nothing blocks on it.
- The AI's contribution is capped at **0–40 points** and merged into the same score/finding system as the heuristic rules, so it never dominates the verdict.

<img width="1044" height="748" alt="image" src="https://github.com/user-attachments/assets/a518c9ba-7a0f-406d-aa4d-9cf08dc83393" />


---

## 🗂️ Project structure

```
E-MailX-Ray/
├── main.py                # Tkinter GUI, wires everything together
├── analyzer.py             # Offline heuristic detection engine (header parsing + 30+ rules)
├── llm_body_analyzer.py     # Optional LLM-based body analysis (LangChain, Ollama/Claude)
├── report_pdf.py            # PDF report generation (fpdf2)
└── README.md
```


---

## ⚠️ Limitations & disclaimer

- This tool performs **heuristic** analysis. A low score does **not** guarantee an email is safe, and a high score does not guarantee malicious intent — always apply human judgment for anything involving credentials, payments, or sensitive actions.
- The heuristic rules rely on curated lists (`KNOWN_BRANDS`, `SUSPICIOUS_TLDS`, `URL_SHORTENERS`, etc.) that need periodic updates to stay effective against new campaigns.
- The AI body analysis sends the email body text to the selected provider (locally with Ollama, or to Anthropic's API if you choose Claude) — review your organization's data-handling policies before enabling it on sensitive mail.
- Encrypted (PGP) bodies cannot be analyzed without the corresponding private key; the tool detects and skips them gracefully instead of failing.

---

## 🤝 Contributing

Pull requests are welcome — especially for:
- Additional/updated brand and TLD reference lists.
- New heuristic rules (open an issue describing the phishing pattern and a sample header/body first).
- Internationalization of the GUI and findings text.

## 📄 License

GPL-3.0 License
