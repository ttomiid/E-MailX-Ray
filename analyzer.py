# -*- coding: utf-8 -*-
"""
analyzer.py
Motor de análisis heurístico de cabeceras de email para detección de phishing.
No depende de servicios externos: todo el análisis es offline, basado en las
cabeceras que el usuario provee (texto crudo o archivo .eml).
"""

import re
import email
from email import policy
from email.utils import parseaddr, getaddresses
from difflib import SequenceMatcher
from dataclasses import dataclass, field


# ----------------------------------------------------------------------
# Datos de referencia para heurísticas
# ----------------------------------------------------------------------

FREE_MAIL_DOMAINS = {
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "yandex.com",
    "gmx.com", "zoho.com",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".icu", ".click", ".link", ".buzz", ".rest", ".fit", ".loan", ".men",
    ".party", ".review", ".science", ".stream", ".download", ".racing",
}

# Marcas comunmente suplantadas + su dominio "oficial" típico
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "banco": None,
    "santander": "santander.com",
    "bbva": "bbva.com",
    "mercadolibre": "mercadolibre.com",
    "mercado pago": "mercadopago.com",
    "afip": "afip.gob.ar",
    "dropbox": "dropbox.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "office365": "office.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
}

URGENCY_KEYWORDS = [
    "urgente", "verifica tu cuenta", "suspendida", "suspendido", "bloqueada",
    "bloqueado", "clic aqui", "haz clic", "confirma tus datos", "actualiza tu información",
    "premio", "ganaste", "factura adjunta", "pago pendiente", "acción requerida",
    "urgent", "verify your account", "suspended", "click here", "confirm your",
    "invoice attached", "payment overdue", "action required", "account locked",
]


@dataclass
class Finding:
    rule: str
    detail: str
    weight: int
    severity: str  # "info" | "low" | "medium" | "high"


@dataclass
class AnalysisResult:
    fields: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    score: int = 0
    risk_level: str = "Bajo"

    def add(self, rule, detail, weight, severity):
        self.findings.append(Finding(rule, detail, weight, severity))
        self.score += weight


# ----------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------

def _domain_of(address: str) -> str:
    if not address:
        return ""
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _looks_like_typosquat(domain: str, brand_domain: str) -> bool:
    if not domain or not brand_domain:
        return False
    if domain == brand_domain:
        return False
    # Similaridad alta pero no idéntico => sospechoso (ej: paypa1.com vs paypal.com)
    ratio = _similarity(domain, brand_domain)
    return 0.75 <= ratio < 1.0


def _decode_header_value(raw: str) -> str:
    try:
        from email.header import decode_header
        parts = decode_header(raw)
        decoded = ""
        for text, enc in parts:
            if isinstance(text, bytes):
                decoded += text.decode(enc or "utf-8", errors="replace")
            else:
                decoded += text
        return decoded
    except Exception:
        return raw


def _has_random_looking_label(domain: str, min_len: int = 10, max_vowel_ratio: float = 0.15):
    """
    Detecta si algún 'label' del dominio (parte entre puntos) es una cadena
    de apariencia aleatoria: larga y con muy pocas vocales, típico de
    subdominios generados automáticamente por infraestructura de spam
    (ej. 'rjttznyzjjzydnillquh.designclub.uk.com'). Devuelve el label
    sospechoso, o None si no encuentra ninguno.
    """
    if not domain:
        return None
    for label in domain.split("."):
        letters = [c for c in label if c.isalpha()]
        if len(letters) >= min_len:
            vowels = sum(1 for c in letters if c.lower() in "aeiou")
            if (vowels / len(letters)) <= max_vowel_ratio:
                return label
    return None


# ----------------------------------------------------------------------
# Analizador principal
# ----------------------------------------------------------------------

_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")
_PGP_MARKERS = (
    "-----BEGIN PGP SIGNED MESSAGE-----",
    "-----BEGIN PGP MESSAGE-----",
)


def _strip_pgp_and_noise(raw_text: str) -> str:
    """
    Algunos clientes (ej. ProtonMail al exportar como .txt) envuelven las
    cabeceras en un bloque de firma PGP, o el cuerpo del mensaje (cifrado)
    aparece después de las cabeceras como '-----BEGIN PGP MESSAGE-----'.
    Esta función:
      1) Si el texto EMPIEZA con un envoltorio PGP (firma), salta esas
         líneas de armor para llegar a las cabeceras reales.
      2) Corta todo lo que venga después del bloque de cabeceras (la
         primera línea en blanco), para no confundir el parser con el
         cuerpo cifrado/firmado.
    """
    text = raw_text.replace("\r\n", "\n").strip("\n")
    lines = text.split("\n")

    # --- Paso 1: si el TEXTO ARRANCA con un envoltorio PGP, saltarlo ---
    start_idx = 0
    if lines and any(lines[0].strip().startswith(m) for m in _PGP_MARKERS):
        for i, line in enumerate(lines):
            if any(line.strip().startswith(m) for m in _PGP_MARKERS):
                start_idx = i + 1
                continue
            if line.strip().lower().startswith("hash:"):
                start_idx = i + 1
                continue
            if _HEADER_LINE_RE.match(line):
                start_idx = i
                break

    # --- Paso 2: encontrar dónde termina el bloque de cabeceras --------
    # Las cabeceras terminan en la primera línea en blanco (separador
    # estándar entre headers y body) o, si aparece antes, en la línea
    # donde arranca un bloque PGP (firma o mensaje cifrado como body).
    end_idx = len(lines)
    for i in range(start_idx, len(lines)):
        line = lines[i]
        if line.strip() == "":
            end_idx = i
            break
        if any(line.strip().startswith(m) for m in _PGP_MARKERS) or \
           line.strip().startswith("-----BEGIN PGP SIGNATURE-----"):
            end_idx = i
            break

    cleaned = "\n".join(lines[start_idx:end_idx]).strip("\n")
    return cleaned


def analyze_headers(raw_text: str) -> AnalysisResult:
    result = AnalysisResult()

    # Limpieza previa: quita envoltorios PGP y ruido antes de las cabeceras
    # (frecuente en exports .txt de clientes como ProtonMail).
    text = _strip_pgp_and_noise(raw_text)

    # El módulo email puede parsear tanto un mensaje completo (.eml) como
    # un bloque de solo-cabeceras si termina en doble salto de línea.
    text = text.strip()
    if not text.endswith("\n\n"):
        text += "\n\n"
    msg = email.message_from_string(text, policy=policy.default)

    # --- Extracción de campos base -------------------------------------
    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")
    to_raw = msg.get("To", "")
    subject_raw = _decode_header_value(msg.get("Subject", ""))
    message_id = msg.get("Message-ID", "")
    x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    auth_results_all = msg.get_all("Authentication-Results", []) or []
    auth_results = " ; ".join(auth_results_all)
    received_all = msg.get_all("Received", []) or []

    from_name, from_addr = parseaddr(from_raw)
    from_name = _decode_header_value(from_name)
    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to_raw)
    return_path_domain = _domain_of(return_path_raw)
    msgid_domain = message_id.split("@")[-1].rstrip(">").lower() if "@" in message_id else ""

    result.fields = {
        "De (From)": from_raw or "(no presente)",
        "Nombre mostrado": from_name or "(sin nombre)",
        "Dominio del From": from_domain or "(desconocido)",
        "Reply-To": reply_to_raw or "(no presente)",
        "Return-Path": return_path_raw or "(no presente)",
        "Para (To)": to_raw or "(no presente)",
        "Asunto": subject_raw or "(sin asunto)",
        "Message-ID": message_id or "(no presente)",
        "X-Mailer / User-Agent": x_mailer or "(no presente)",
        "Authentication-Results": auth_results or "(no presente)",
        "Saltos Received": str(len(received_all)),
    }

    # --- Regla 1: SPF / DKIM / DMARC ------------------------------------
    ar_lower = auth_results.lower()
    if not auth_results:
        result.add(
            "Sin Authentication-Results",
            "El mensaje no trae cabecera Authentication-Results: no se puede "
            "verificar SPF/DKIM/DMARC. Los servidores modernos casi siempre la agregan; "
            "su ausencia es sospechosa.",
            15, "medium",
        )
    else:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mech}=(\w+)", ar_lower)
            if m:
                verdict = m.group(1)
                if verdict in ("fail", "softfail", "permerror", "temperror"):
                    result.add(
                        f"{mech.upper()} en estado '{verdict}'",
                        f"La autenticación {mech.upper()} no pasó correctamente.",
                        25, "high",
                    )
                elif verdict == "none":
                    result.add(
                        f"{mech.upper()} no configurado",
                        f"El dominio remitente no publica registro {mech.upper()}.",
                        10, "low",
                    )

    # --- Regla 2: From vs Return-Path mismatch --------------------------
    if return_path_domain and from_domain and return_path_domain != from_domain:
        if _similarity(return_path_domain, from_domain) < 0.5:
            result.add(
                "Return-Path no coincide con From",
                f"From usa '{from_domain}' pero Return-Path usa '{return_path_domain}'. "
                "Es común en spoofing/spam.",
                20, "high",
            )
        else:
            result.add(
                "Return-Path distinto de From (subdominio o similar)",
                f"'{from_domain}' vs '{return_path_domain}'.",
                8, "low",
            )

    # --- Regla 3: From vs Reply-To mismatch -----------------------------
    if reply_domain and from_domain and reply_domain != from_domain:
        result.add(
            "Reply-To apunta a otro dominio",
            f"Las respuestas se redirigen de '{from_domain}' a '{reply_domain}'. "
            "Técnica clásica para desviar respuestas a un buzón del atacante.",
            20, "high",
        )

    # --- Regla 4: Message-ID no coincide con el dominio del From -------
    if msgid_domain and from_domain and msgid_domain != from_domain:
        if _similarity(msgid_domain, from_domain) < 0.4:
            result.add(
                "Message-ID de dominio ajeno",
                f"El Message-ID fue generado por '{msgid_domain}', no por '{from_domain}'.",
                10, "medium",
            )

    # --- Regla 1b: SPF/DKIM "pasan" pero para un dominio distinto al From --
    # Un SPF/DKIM en estado 'pass' NO significa que el correo sea legítimo:
    # solo confirma que el dominio autenticado tiene permiso para enviar.
    # Si ese dominio no es el que se muestra en 'From', es spoofing con
    # infraestructura propia del atacante (muy común y fácil de pasar por alto).
    spf_domain_match = re.search(r"smtp\.mailfrom=([^\s;)]+)", auth_results, re.IGNORECASE)
    spf_auth_domain = spf_domain_match.group(1).split("@")[-1].lower() if spf_domain_match else None
    dkim_domain_match = re.search(r"header\.d=([^\s;)]+)", auth_results, re.IGNORECASE)
    dkim_auth_domain = dkim_domain_match.group(1).lower().rstrip(",;") if dkim_domain_match else None

    def _aligned(d1, d2):
        if not d1 or not d2:
            return True  # sin datos suficientes, no penalizar
        return d1 == d2 or d1.endswith("." + d2) or d2.endswith("." + d1)

    if "spf=pass" in ar_lower and spf_auth_domain and from_domain and not _aligned(spf_auth_domain, from_domain):
        result.add(
            "SPF válido, pero para un dominio distinto al remitente visible",
            f"SPF pasa para '{spf_auth_domain}', no para '{from_domain}' (el dominio que "
            "aparece en 'From'). Esto significa que el servidor de origen tiene permiso "
            "para enviar en nombre de SU PROPIO dominio, no que el remitente mostrado sea "
            "auténtico. Es una técnica muy común de phishing: infraestructura propia del "
            "atacante, con SPF/DKIM en regla, pero con un 'From' falsificado.",
            30, "high",
        )
    elif dkim_auth_domain and from_domain and not _aligned(dkim_auth_domain, from_domain):
        result.add(
            "DKIM válido, pero para un dominio distinto al remitente visible",
            f"La firma DKIM corresponde a '{dkim_auth_domain}', no a '{from_domain}'.",
            25, "high",
        )

    # --- Regla 5: Suplantación de marca conocida ------------------------
    name_lower = from_name.lower()
    # Normalizamos quitando todo lo que no sea letra/número para detectar
    # ofuscación con puntos, espacios o guiones (ej. "P.A.Y.P.A.L", "P a y pal").
    name_normalized = re.sub(r"[^a-z0-9]", "", name_lower)
    for brand, brand_domain in KNOWN_BRANDS.items():
        brand_key = brand.replace(" ", "")
        if brand_key in name_normalized:
            if brand_domain and from_domain and brand_domain not in from_domain:
                result.add(
                    "Posible suplantación de marca",
                    f"El nombre mostrado menciona '{brand}' pero el correo viene de "
                    f"'{from_domain}', que no pertenece a {brand_domain}.",
                    30, "high",
                )
            if from_domain in FREE_MAIL_DOMAINS:
                result.add(
                    "Marca + webmail gratuito",
                    f"Se usa el nombre '{brand}' desde un dominio de correo gratuito "
                    f"('{from_domain}'). Las empresas no suelen escribir desde webmail.",
                    25, "high",
                )

    # --- Regla 6: Typosquatting de dominio -------------------------------
    for brand, brand_domain in KNOWN_BRANDS.items():
        if not brand_domain or not from_domain:
            continue
        if _looks_like_typosquat(from_domain, brand_domain):
            result.add(
                "Dominio parecido a uno legítimo (typosquatting)",
                f"'{from_domain}' se parece sospechosamente a '{brand_domain}'.",
                30, "high",
            )

    # --- Regla 7: TLD sospechoso -----------------------------------------
    if from_domain:
        for tld in SUSPICIOUS_TLDS:
            if from_domain.endswith(tld):
                result.add(
                    "TLD de riesgo",
                    f"El dominio '{from_domain}' usa la extensión '{tld}', "
                    "frecuentemente asociada a campañas de phishing (registro barato/anónimo).",
                    12, "medium",
                )
                break

    # --- Regla 8: Codificación sospechosa en cabeceras --------------------
    for hname in ("Subject", "From"):
        raw_val = msg.get(hname, "")
        if raw_val and "=?" in raw_val and "?=" in raw_val:
            encoded_blocks = len(re.findall(r"=\?[^?]+\?[BbQq]\?[^?]*\?=", raw_val))
            if encoded_blocks >= 3:
                result.add(
                    "Codificación MIME excesiva",
                    f"La cabecera '{hname}' usa múltiples bloques de codificación, "
                    "una táctica para ofuscar el contenido y evadir filtros.",
                    10, "low",
                )

    # --- Regla 9: Cadena de Received ---------------------------------------
    if len(received_all) == 0:
        result.add(
            "Sin cabeceras Received",
            "No hay rastro de la ruta del correo por servidores SMTP. Puede indicar "
            "inyección directa o que se pegó un fragmento incompleto.",
            10, "low",
        )
    else:
        ips = re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", " ".join(received_all))
        private_ip_pattern = re.compile(
            r"^(10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|127\.)"
        )
        if ips and private_ip_pattern.match(ips[-1]):
            result.add(
                "IP de origen privada/interna",
                f"El primer salto reporta una IP interna ({ips[-1]}), inusual para "
                "correo entrante de Internet; puede indicar cabeceras falsificadas.",
                8, "low",
            )

    # --- Regla 10: X-Mailer sospechoso ---------------------------------------
    if x_mailer:
        suspicious_mailers = ["php", "mass mailer", "bulk", "quick send", "mailer daemon"]
        if any(s in x_mailer.lower() for s in suspicious_mailers):
            result.add(
                "Herramienta de envío sospechosa",
                f"X-Mailer/User-Agent indica '{x_mailer}', asociado a menudo a "
                "herramientas de envío masivo automatizado.",
                10, "medium",
            )

    # --- Regla 11: Palabras de urgencia en el asunto -----------------------
    subj_lower = subject_raw.lower()
    hits = [kw for kw in URGENCY_KEYWORDS if kw in subj_lower]
    if hits:
        result.add(
            "Lenguaje de urgencia/presión en el asunto",
            f"El asunto contiene frases típicas de ingeniería social: {', '.join(hits[:4])}.",
            10, "low",
        )

    # --- Regla 12: Destinatario oculto / genérico ---------------------------
    if to_raw:
        to_addrs = getaddresses([to_raw])
        if len(to_addrs) == 1 and to_addrs[0][1]:
            local_part = to_addrs[0][1].split("@")[0].lower()
            if local_part in ("undisclosed-recipients", "recipient", "user", "customer"):
                result.add(
                    "Destinatario genérico/oculto",
                    "El campo 'To' no identifica a un destinatario real, típico de "
                    "envíos masivos de phishing.",
                    8, "low",
                )

    # --- Regla 13: el proveedor de correo ya lo marcó como spam ------------
    spam_marker_headers = {
        "X-Spam": msg.get("X-Spam", ""),
        "X-Spam-Flag": msg.get("X-Spam-Flag", ""),
        "X-Spam-Status": msg.get("X-Spam-Status", ""),
        "X-Pm-Spam-Action": msg.get("X-Pm-Spam-Action", ""),
    }
    for hname, hval in spam_marker_headers.items():
        if not hval:
            continue
        hval_lower = hval.lower()
        if hval_lower.startswith("yes") or "spam" == hval_lower.strip() or \
           hval_lower.startswith("spam"):
            result.add(
                "El proveedor de correo ya lo marcó como spam",
                f"La cabecera '{hname}' indica '{hval.strip()}': el propio servidor "
                "receptor (Gmail, ProtonMail, Outlook, etc.) ya clasificó este mensaje "
                "como spam/phishing antes de que llegara a la bandeja. Es una señal "
                "de alta confianza, incluso si SPF/DKIM/DMARC pasan (puede tratarse de "
                "un dominio legítimo comprometido y usado para enviar spam).",
                35, "high",
            )
            break  # un solo hallazgo alcanza, no sumar por cada cabecera repetida

    # --- Regla 13: Dominios con apariencia aleatoria (spam automatizado) ---
    for label_name, domain_val in (
        ("From", from_domain),
        ("Return-Path", return_path_domain),
        ("Message-ID", msgid_domain),
    ):
        random_label = _has_random_looking_label(domain_val)
        if random_label:
            result.add(
                f"Subdominio con apariencia aleatoria en {label_name}",
                f"'{random_label}' (dentro de '{domain_val}') parece una cadena generada "
                "automáticamente, sin relación con un nombre real. Es típico de "
                "infraestructura de envío masivo/spam creada dinámicamente.",
                15, "medium",
            )

    # --- Regla 14: Asunto con codificación corrupta (mojibake) -------------
    if subject_raw.count("?") >= 5:
        result.add(
            "Asunto con caracteres corruptos (mojibake)",
            "El asunto contiene numerosos símbolos '?' seguidos, señal de una "
            "codificación de caracteres rota o de texto ofuscado para evadir "
            "filtros de contenido.",
            10, "low",
        )

    # --- Clasificación final -------------------------------------------------
    if result.score >= 50:
        result.risk_level = "Alto"
    elif result.score >= 20:
        result.risk_level = "Medio"
    else:
        result.risk_level = "Bajo"

    if not result.findings:
        result.add(
            "Sin indicadores relevantes",
            "No se detectaron patrones sospechosos con las reglas actuales. "
            "Esto no garantiza que el correo sea legítimo.",
            0, "info",
        )

    return result
