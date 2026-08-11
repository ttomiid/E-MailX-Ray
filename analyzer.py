# -*- coding: utf-8 -*-
"""
analyzer.py
Heuristic email header analysis engine for phishing detection.
No external services required: everything runs offline, based purely on
the headers the user provides (raw text or a .eml file).

Part of E-MailX-Ray.
"""

import re
import email
import datetime
from email import policy
from email.utils import parseaddr, getaddresses, parsedate_to_datetime
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ----------------------------------------------------------------------
# Reference data used by the heuristics
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

# Commonly-impersonated brands + their legitimate domain(s).
# A brand can map to MORE than one legitimate domain: sister companies under
# the same corporate group (e.g. Mercado Libre / Mercado Pago are both run
# by the same company and legitimately email from either domain) commonly
# cross-reference each other, and that isn't impersonation.
KNOWN_BRANDS = {
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com",),
    "microsoft": ("microsoft.com",),
    "google": ("google.com",),
    "apple": ("apple.com",),
    "netflix": ("netflix.com",),
    "bank": (),
    "santander": ("santander.com",),
    "bbva": ("bbva.com",),
    "mercadolibre": ("mercadolibre.com", "mercadopago.com"),
    "mercado libre": ("mercadolibre.com", "mercadopago.com"),
    "mercado pago": ("mercadopago.com", "mercadolibre.com"),
    "irs": ("irs.gov",),
    "dropbox": ("dropbox.com",),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "linkedin": ("linkedin.com",),
    "office365": ("office.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
}

URGENCY_KEYWORDS = [
    "urgent", "verify your account", "suspended", "click here", "confirm your",
    "invoice attached", "payment overdue", "action required", "account locked",
    "limited time", "unusual activity", "confirm your identity", "update your information",
    "you have won", "claim your prize", "final notice",
]

# Business Email Compromise (CEO fraud / wire-transfer scam) language.
# Distinct from generic phishing: it targets a specific employee and pushes
# for a financial action rather than credential theft.
BEC_KEYWORDS = [
    "wire transfer", "bank transfer", "gift card", "gift cards", "itunes card",
    "purchase order", "invoice payment", "change of bank details", "new account details",
    "keep this confidential", "don't tell anyone", "handle discreetly", "are you available",
    "are you at your desk", "can you do me a favor", "urgent payment", "process a payment",
]

# Titles that, combined with a mismatch (free webmail, spoofed domain), are
# typical of BEC impersonation of an executive.
EXEC_TITLE_KEYWORDS = [
    "ceo", "cfo", "coo", "president", "director general", "gerente general",
    "chief executive", "chief financial", "founder", "owner",
]

# Extensions that can execute code and are almost never legitimate as a
# direct email attachment.
DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".jar", ".bat", ".cmd", ".com",
    ".pif", ".hta", ".wsf", ".msi", ".ps1", ".jse", ".cpl", ".lnk", ".iso", ".img",
}

# "Innocent-looking" extensions commonly abused in double-extension bait
# (e.g. "invoice.pdf.exe").
DOCUMENT_LIKE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "bl.ink",
}

# Look-alike character normalization: maps Unicode homoglyphs (Cyrillic,
# Greek, etc.) and common leetspeak digit substitutions to their closest
# Latin letter, so brand-impersonation and typosquat checks aren't fooled
# by characters that render as nearly identical to the human eye
# (e.g. Cyrillic 'а' vs Latin 'a', or 'paypa1.com' vs 'paypal.com').
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "һ": "h", "ԁ": "d", "ѡ": "w", "ⅼ": "l", "ⅽ": "c",
    "0": "o", "1": "l", "3": "e", "5": "s", "8": "b",
}


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
    risk_level: str = "Low"

    def add(self, rule, detail, weight, severity):
        self.findings.append(Finding(rule, detail, weight, severity))
        self.score += weight


# ----------------------------------------------------------------------
# Utilities
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


def _aligned(d1: str, d2: str) -> bool:
    """
    True if d1 and d2 are the same domain, or one is a genuine subdomain of
    the other (e.g. 'bounces.google.com' under 'google.com'). This is a much
    more reliable check than text similarity for telling apart "legitimate
    infrastructure subdomain" from "actually a different, unrelated domain".
    """
    if not d1 or not d2:
        return True  # not enough data, don't penalize
    return d1 == d2 or d1.endswith("." + d2) or d2.endswith("." + d1)


def _normalize_confusables(text: str) -> str:
    """Maps look-alike characters (Cyrillic/Greek homoglyphs, leetspeak
    digits) to their closest Latin letter — see HOMOGLYPH_MAP."""
    if not text:
        return text
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in text.lower())


def _looks_like_typosquat(domain: str, brand_domain: str) -> bool:
    if not domain or not brand_domain:
        return False
    if domain == brand_domain:
        return False
    # High similarity but not identical => suspicious (e.g. paypa1.com vs paypal.com)
    ratio = _similarity(domain, brand_domain)
    if 0.75 <= ratio < 1.0:
        return True
    # Catch character-substitution tricks (0/o, 1/l, rn/m, etc.) that plain
    # text similarity can miss on short domains (e.g. "paypaI.com").
    normalized = _normalize_confusables(domain).replace("rn", "m")
    if normalized != domain.lower() and normalized == brand_domain.lower():
        return True
    return False


def _has_idn_label(domain: str) -> bool:
    """True if any label of the domain is ACE/punycode-encoded (xn--...)."""
    return any(label.lower().startswith("xn--") for label in domain.split("."))


def _decode_idn_label(label: str) -> str:
    """Best-effort punycode -> Unicode decoding of a single domain label."""
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except Exception:
        return label


def _decode_idn_domain(domain: str) -> str:
    return ".".join(_decode_idn_label(lbl) for lbl in domain.split("."))


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


def _domain_matches_brand(domain: str, brand_domains) -> bool:
    """
    True if `domain` IS one of a brand's legitimate domains, a subdomain of
    one, or a regional ccTLD variant of one (e.g. 'mercadopago.com.mx' is a
    legitimate regional site of 'mercadopago.com', not a typosquat).
    `brand_domains` may be a single domain string or an iterable of them,
    since some brands legitimately send from more than one domain (sister
    companies, regional sites).
    """
    if not domain:
        return False
    if isinstance(brand_domains, str):
        brand_domains = (brand_domains,)
    d = domain[4:] if domain.startswith("www.") else domain
    for bd in brand_domains:
        if not bd:
            continue
        if d == bd or _aligned(d, bd) or d.startswith(bd + "."):
            return True
    return False


def _same_corporate_family(d1: str, d2: str) -> bool:
    """
    True if d1 and d2 are both listed as legitimate domains of the SAME
    KNOWN_BRANDS entry (e.g. mercadolibre.com and mercadopago.com) — i.e.
    sister companies under one corporate group, not a case of one domain
    impersonating or hijacking the other.
    """
    if not d1 or not d2 or d1 == d2:
        return False
    for brand_domains in KNOWN_BRANDS.values():
        if len(brand_domains) < 2:
            continue
        if _domain_matches_brand(d1, brand_domains) and _domain_matches_brand(d2, brand_domains):
            return True
    return False


def _has_random_looking_label(domain: str, min_len: int = 10, max_vowel_ratio: float = 0.15):
    """
    Detects whether any label of the domain (the part between dots) looks
    randomly generated: long and with very few vowels, typical of
    subdomains auto-generated by spam infrastructure
    (e.g. 'rjttznyzjjzydnillquh.designclub.uk.com'). Returns the suspicious
    label, or None if none is found.
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
# Main analyzer
# ----------------------------------------------------------------------

_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")
_PGP_MARKERS = (
    "-----BEGIN PGP SIGNED MESSAGE-----",
    "-----BEGIN PGP MESSAGE-----",
)


def _strip_pgp_and_noise(raw_text: str) -> str:
    """
    Some clients (e.g. ProtonMail exporting as .txt) wrap the headers in a
    PGP signature block, or the (encrypted) message body appears right
    after the headers as '-----BEGIN PGP MESSAGE-----'. This function:
      1) If the text STARTS with a PGP wrapper (signature), skips those
         armor lines to reach the real headers.
      2) Cuts off everything that comes after the header block (the first
         blank line), so the parser isn't confused by the
         encrypted/signed body.
    """
    text = raw_text.replace("\r\n", "\n").strip("\n")
    lines = text.split("\n")

    # --- Step 1: if the TEXT STARTS with a PGP wrapper, skip it ---------
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

    # --- Step 2: find where the header block ends -----------------------
    # Headers end at the first blank line (standard separator between
    # headers and body) or, if it appears earlier, at the line where a PGP
    # block starts (signature or encrypted message used as the body).
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


def _html_to_text(html: str) -> str:
    """
    Minimal, dependency-free HTML -> plain text conversion, good enough to
    feed an LLM (we don't need pixel-perfect rendering, just readable text).
    """
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def extract_body_text(raw_text: str) -> str:
    """
    Extracts the readable body of the message from the ORIGINAL raw text
    (unlike analyze_headers, which intentionally discards the body to keep
    the header parser safe).

    Walks ALL parts of the message and collects both text/plain and
    text/html content, instead of picking a single "preferred" part. This
    matters because some phishing emails put meaningless filler text in
    text/plain (to dodge plain-text spam filters) while the actual
    malicious content — fake branding, links, urgency language — lives
    only in the text/html alternative. Picking just one part can hide the
    real payload from the analysis.

    Returns "" if there's no usable body, or if the only content is a
    PGP-encrypted block we have no key to decrypt.
    """
    text = raw_text.replace("\r\n", "\n").strip("\n")
    lines = text.split("\n")

    # Skip a leading PGP-signature wrapper, same logic as in _strip_pgp_and_noise,
    # but WITHOUT truncating the body afterwards.
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

    cleaned = "\n".join(lines[start_idx:])
    if not cleaned.strip():
        return ""

    try:
        msg = email.message_from_string(cleaned, policy=policy.default)
    except Exception:
        return ""

    collected = []
    seen = set()
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue

        stripped = content.strip()
        if not stripped:
            continue
        if stripped.startswith("-----BEGIN PGP MESSAGE-----"):
            continue  # encrypted, no key to decrypt

        if ctype == "text/html":
            content = _html_to_text(content)
        content = content.strip()

        if content and content not in seen:
            seen.add(content)
            label = "[HTML part]" if ctype == "text/html" else "[Plain text part]"
            collected.append(f"{label}\n{content}")

    return "\n\n---\n\n".join(collected).strip()


# ----------------------------------------------------------------------
# Link & attachment extraction (used by the link/attachment heuristics)
# ----------------------------------------------------------------------

_URL_RE = re.compile(r"""(?xi) \b (?:https?://|www\.) [^\s<>"'\)\]]+ """)
_HTML_LINK_RE = re.compile(
    r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _strip_html_tags(fragment: str) -> str:
    return re.sub(r"<[^>]+>", " ", fragment).strip()


def _domain_from_url(url: str) -> str:
    """Extracts just the host (no scheme, no userinfo, no port) from a URL,
    tolerating URLs without a scheme (e.g. 'www.example.com/path')."""
    try:
        candidate = url if "://" in url else "//" + url
        netloc = urlparse(candidate).netloc
        netloc = netloc.split("@")[-1]  # drop userinfo ("user:pass@")
        netloc = netloc.split(":")[0]   # drop port
        return netloc.lower().strip()
    except Exception:
        return ""


def extract_links(raw_text: str) -> list:
    """
    Extracts (anchor_text, href) pairs from the email body: real <a href>
    tags from HTML parts (so we keep the visible text separate from the
    real destination — needed to detect anchor/destination mismatches),
    and bare URLs from plain-text parts (anchor_text == href there).
    Returns [] if there's no parseable body.
    """
    text = raw_text.replace("\r\n", "\n").strip("\n")
    try:
        msg = email.message_from_string(text, policy=policy.default)
    except Exception:
        return []

    links = []
    seen = set()
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue

        if ctype == "text/html":
            for href, anchor_html in _HTML_LINK_RE.findall(content):
                anchor_text = _strip_html_tags(anchor_html)
                key = (anchor_text, href)
                if key not in seen:
                    seen.add(key)
                    links.append((anchor_text, href))
        else:
            for url in _URL_RE.findall(content):
                key = (url, url)
                if key not in seen:
                    seen.add(key)
                    links.append((url, url))

    return links


def extract_attachments(raw_text: str) -> list:
    """Returns the filenames of every part declared with a filename
    (Content-Disposition: attachment, or any inline part with 'name')."""
    text = raw_text.replace("\r\n", "\n").strip("\n")
    try:
        msg = email.message_from_string(text, policy=policy.default)
    except Exception:
        return []

    names = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            names.append(_decode_header_value(filename))
    return names


def analyze_headers(raw_text: str) -> AnalysisResult:
    result = AnalysisResult()

    # Pre-cleanup: strip PGP wrappers and noise before the headers
    # (common in .txt exports from clients like ProtonMail).
    text = _strip_pgp_and_noise(raw_text)

    # The email module can parse both a full message (.eml) and a
    # headers-only block if it ends with a double line break.
    text = text.strip()
    if not text.endswith("\n\n"):
        text += "\n\n"
    msg = email.message_from_string(text, policy=policy.default)

    # --- Base field extraction -------------------------------------------
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
        "From": from_raw or "(not present)",
        "Display name": from_name or "(no name)",
        "From domain": from_domain or "(unknown)",
        "Reply-To": reply_to_raw or "(not present)",
        "Return-Path": return_path_raw or "(not present)",
        "To": to_raw or "(not present)",
        "Subject": subject_raw or "(no subject)",
        "Message-ID": message_id or "(not present)",
        "X-Mailer / User-Agent": x_mailer or "(not present)",
        "Authentication-Results": auth_results or "(not present)",
        "Received hops": str(len(received_all)),
    }

    # --- Rule 1: SPF / DKIM / DMARC ---------------------------------------
    ar_lower = auth_results.lower()
    if not auth_results:
        result.add(
            "No Authentication-Results header",
            "The message has no Authentication-Results header: SPF/DKIM/DMARC "
            "cannot be verified. Modern mail servers almost always add this "
            "header, so its absence is suspicious.",
            15, "medium",
        )
    else:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mech}=(\w+)", ar_lower)
            if m:
                verdict = m.group(1)
                if verdict in ("fail", "softfail", "permerror", "temperror"):
                    result.add(
                        f"{mech.upper()} status '{verdict}'",
                        f"{mech.upper()} authentication did not pass.",
                        25, "high",
                    )
                elif verdict == "none":
                    result.add(
                        f"{mech.upper()} not configured",
                        f"The sending domain does not publish a {mech.upper()} record.",
                        10, "low",
                    )

    # --- DMARC/DKIM alignment check (used by several rules below) ---------------
    # DMARC authenticates the visible 'From' domain if EITHER SPF OR DKIM
    # aligns with it — that's the actual spec, not "SPF must align". A
    # receiving server (Gmail, Outlook, etc.) already computes this and
    # publishes the verdict as 'dmarc=pass ... header.from=<domain>'; if
    # that's present and aligned, it's the single most authoritative signal
    # we have, and should override weaker heuristics like a mismatched
    # Return-Path (very common with legitimate third-party ESPs: survey
    # tools, marketing platforms, transactional mailers, etc., which sign
    # with their own DKIM key but pass through the brand's alignment).
    dmarc_match = re.search(r"dmarc=pass[^;]*header\.from=([^\s;)]+)", ar_lower)
    dmarc_aligned_domain = dmarc_match.group(1).rstrip(",;") if dmarc_match else None
    dmarc_authenticated = bool(
        dmarc_aligned_domain and from_domain and _aligned(dmarc_aligned_domain, from_domain)
    )

    # Fallback for inputs without an explicit dmarc= verdict: check every
    # DKIM signature that passed (a message can carry more than one, e.g.
    # the brand's own signature plus an ESP's) and see if any of them is
    # signed for a domain aligned with 'From'. Supports both the 'header.d='
    # and identity 'header.i=user@domain' forms used in the wild.
    dkim_pass_domains = []
    for seg in re.findall(r"dkim=pass[^;]*", ar_lower):
        d_match = re.search(r"header\.d=([^\s;)]+)", seg)
        i_match = re.search(r"header\.i=([^\s;)]+)", seg)
        dom = None
        if d_match:
            dom = d_match.group(1).rstrip(",;")
        elif i_match:
            ident = i_match.group(1).rstrip(",;")
            dom = ident.split("@")[-1] if "@" in ident else ident
        if dom:
            dkim_pass_domains.append(dom)
    dkim_aligned = bool(from_domain) and any(_aligned(d, from_domain) for d in dkim_pass_domains)

    sender_domain_authenticated = dmarc_authenticated or dkim_aligned

    # --- Rule 2: From vs Return-Path mismatch -----------------------------
    if return_path_domain and from_domain and return_path_domain != from_domain:
        if _aligned(return_path_domain, from_domain):
            # Genuine parent/subdomain relationship (e.g. bounces.google.com
            # under google.com) — common for bulk/notification senders and
            # NOT a red flag on its own.
            pass
        elif sender_domain_authenticated:
            # Return-Path pointing to unrelated infrastructure (a survey
            # tool, mailer, or bulk-email platform) is normal when DMARC/DKIM
            # still authenticate the visible From domain — this is exactly
            # how DMARC alignment is designed to work, so it isn't penalized.
            pass
        elif _similarity(return_path_domain, from_domain) < 0.5:
            result.add(
                "Return-Path does not match From",
                f"From uses '{from_domain}' but Return-Path uses '{return_path_domain}'. "
                "Common in spoofing/spam.",
                20, "high",
            )
        else:
            result.add(
                "Return-Path differs from From (subdomain or similar)",
                f"'{from_domain}' vs '{return_path_domain}'.",
                8, "low",
            )

    # --- Rule 3: From vs Reply-To mismatch --------------------------------
    if (
        reply_domain and from_domain and reply_domain != from_domain
        and not _aligned(reply_domain, from_domain)
        and not _same_corporate_family(reply_domain, from_domain)
    ):
        result.add(
            "Reply-To points to a different domain",
            f"Replies get redirected from '{from_domain}' to '{reply_domain}'. "
            "A classic technique for diverting replies to an attacker's mailbox.",
            20, "high",
        )

    # --- Rule 4: Message-ID doesn't match the From domain ------------------
    # Skipped when DMARC/DKIM already authenticate the visible From domain:
    # third-party ESPs (survey tools, marketing platforms, transactional
    # mailers) very commonly generate Message-IDs using their own internal
    # server hostname rather than the brand's domain — normal infrastructure
    # behavior, not a spoofing signal, once the stronger DMARC/DKIM check
    # already vouches for the sender.
    if (
        msgid_domain and from_domain and msgid_domain != from_domain
        and not sender_domain_authenticated
    ):
        if _similarity(msgid_domain, from_domain) < 0.4:
            result.add(
                "Message-ID from an unrelated domain",
                f"The Message-ID was generated by '{msgid_domain}', not by '{from_domain}'.",
                10, "medium",
            )

    # --- Rule 1b: SPF/DKIM "pass" but for a different domain than From -----
    # An SPF/DKIM 'pass' does NOT mean the email is legitimate on its own: it
    # only confirms that the authenticated domain is allowed to send. If
    # that domain isn't the one shown in 'From' AND nothing else aligns
    # (see sender_domain_authenticated above), it's spoofing using the
    # attacker's own infrastructure — very common and easy to overlook.
    spf_domain_match = re.search(r"smtp\.mailfrom=([^\s;)]+)", auth_results, re.IGNORECASE)
    spf_auth_domain = spf_domain_match.group(1).split("@")[-1].lower() if spf_domain_match else None
    dkim_domain_match = re.search(r"header\.d=([^\s;)]+)", auth_results, re.IGNORECASE)
    dkim_auth_domain = dkim_domain_match.group(1).lower().rstrip(",;") if dkim_domain_match else (
        dkim_pass_domains[0] if dkim_pass_domains else None
    )

    if sender_domain_authenticated:
        pass  # DMARC/DKIM already authenticate the visible From domain
    elif "spf=pass" in ar_lower and spf_auth_domain and from_domain and not _aligned(spf_auth_domain, from_domain):
        result.add(
            "SPF passes, but for a domain different from the visible sender",
            f"SPF passes for '{spf_auth_domain}', not for '{from_domain}' (the domain "
            "shown in 'From'), and no DKIM/DMARC alignment covers it either. This "
            "means the sending server is allowed to send on behalf of ITS OWN "
            "domain, not that the displayed sender is authentic — a very common "
            "phishing technique: the attacker's own infrastructure, with valid "
            "SPF/DKIM for itself, paired with a spoofed 'From'.",
            30, "high",
        )
    elif dkim_auth_domain and from_domain and not _aligned(dkim_auth_domain, from_domain):
        result.add(
            "DKIM valid, but for a domain different from the visible sender",
            f"The DKIM signature belongs to '{dkim_auth_domain}', not to '{from_domain}'.",
            25, "high",
        )

    # --- Rule 5: Known brand impersonation ----------------------------------
    name_lower = from_name.lower()
    # Normalize by removing anything that isn't a letter/digit, to catch
    # obfuscation with dots, spaces or dashes (e.g. "P.A.Y.P.A.L", "P a y pal").
    name_normalized = re.sub(r"[^a-z0-9]", "", name_lower)
    for brand, brand_domains in KNOWN_BRANDS.items():
        brand_key = brand.replace(" ", "")
        if brand_key in name_normalized:
            if brand_domains and from_domain and not _domain_matches_brand(from_domain, brand_domains):
                result.add(
                    "Possible brand impersonation",
                    f"The display name mentions '{brand}' but the email comes from "
                    f"'{from_domain}', which does not belong to {' / '.join(brand_domains)}.",
                    30, "high",
                )
            if from_domain in FREE_MAIL_DOMAINS:
                result.add(
                    "Brand name + free webmail",
                    f"The name '{brand}' is used from a free email domain "
                    f"('{from_domain}'). Companies rarely email from webmail providers.",
                    25, "high",
                )

    # --- Rule 6: Domain typosquatting ---------------------------------------
    for brand, brand_domains in KNOWN_BRANDS.items():
        if not brand_domains or not from_domain:
            continue
        if _domain_matches_brand(from_domain, brand_domains):
            continue  # legitimate domain (or regional/sister variant) for this brand
        for bd in brand_domains:
            if _looks_like_typosquat(from_domain, bd):
                result.add(
                    "Domain resembling a legitimate one (typosquatting)",
                    f"'{from_domain}' suspiciously resembles '{bd}'.",
                    30, "high",
                )
                break

    # --- Rule 7: Suspicious TLD -----------------------------------------------
    if from_domain:
        for tld in SUSPICIOUS_TLDS:
            if from_domain.endswith(tld):
                result.add(
                    "High-risk TLD",
                    f"The domain '{from_domain}' uses the '{tld}' extension, "
                    "frequently associated with phishing campaigns (cheap/anonymous registration).",
                    12, "medium",
                )
                break

    # --- Rule 8: Suspicious header encoding -----------------------------------
    for hname in ("Subject", "From"):
        raw_val = msg.get(hname, "")
        if raw_val and "=?" in raw_val and "?=" in raw_val:
            encoded_blocks = len(re.findall(r"=\?[^?]+\?[BbQq]\?[^?]*\?=", raw_val))
            if encoded_blocks >= 3:
                result.add(
                    "Excessive MIME encoding",
                    f"The '{hname}' header uses multiple encoded blocks, "
                    "a tactic used to obfuscate content and evade filters.",
                    10, "low",
                )

    # --- Rule 9: Received chain ------------------------------------------------
    if len(received_all) == 0:
        result.add(
            "No Received headers",
            "There's no trace of the email's path through SMTP servers. May "
            "indicate direct injection, or that an incomplete fragment was pasted.",
            10, "low",
        )
    else:
        ips = re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", " ".join(received_all))
        private_ip_pattern = re.compile(
            r"^(10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|127\.)"
        )
        if ips and private_ip_pattern.match(ips[-1]):
            result.add(
                "Private/internal origin IP",
                f"The first hop reports an internal IP ({ips[-1]}), unusual for "
                "email arriving from the Internet; may indicate forged headers.",
                8, "low",
            )

    # --- Rule 10: Suspicious X-Mailer ------------------------------------------
    if x_mailer:
        suspicious_mailers = ["php", "mass mailer", "bulk", "quick send", "mailer daemon"]
        if any(s in x_mailer.lower() for s in suspicious_mailers):
            result.add(
                "Suspicious sending tool",
                f"X-Mailer/User-Agent indicates '{x_mailer}', often associated with "
                "automated bulk-sending tools.",
                10, "medium",
            )

    # --- Rule 11: Urgency/pressure language in the subject ---------------------
    subj_lower = subject_raw.lower()
    hits = [kw for kw in URGENCY_KEYWORDS if kw in subj_lower]
    if hits:
        result.add(
            "Urgency/pressure language in the subject",
            f"The subject contains phrases typical of social engineering: {', '.join(hits[:4])}.",
            10, "low",
        )

    # --- Rule 12: Generic/hidden recipient ---------------------------------------
    if to_raw:
        to_addrs = getaddresses([to_raw])
        if len(to_addrs) == 1 and to_addrs[0][1]:
            local_part = to_addrs[0][1].split("@")[0].lower()
            if local_part in ("undisclosed-recipients", "recipient", "user", "customer"):
                result.add(
                    "Generic/hidden recipient",
                    "The 'To' field does not identify a real recipient, typical of "
                    "bulk phishing sends.",
                    8, "low",
                )

    # --- Rule 13: The mail provider already flagged it as spam ------------------
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
                "The mail provider already flagged this as spam",
                f"The '{hname}' header shows '{hval.strip()}': the receiving server "
                "itself (Gmail, ProtonMail, Outlook, etc.) already classified this "
                "message as spam/phishing before it reached the inbox. This is a "
                "high-confidence signal, even if SPF/DKIM/DMARC pass (the sending "
                "domain may be legitimate but compromised and abused to send spam).",
                35, "high",
            )
            break  # one finding is enough, don't add per repeated header

    # --- Rule 14: Domains with a randomly-generated look (spam automation) -----
    for label_name, domain_val in (
        ("From", from_domain),
        ("Return-Path", return_path_domain),
        ("Message-ID", msgid_domain),
    ):
        random_label = _has_random_looking_label(domain_val)
        if random_label:
            result.add(
                f"Randomly-generated-looking subdomain in {label_name}",
                f"'{random_label}' (inside '{domain_val}') looks like an "
                "auto-generated string with no relation to a real name. Typical of "
                "dynamically-created bulk-mail/spam infrastructure.",
                15, "medium",
            )

    # --- Rule 15: Subject with corrupted encoding (mojibake) --------------------
    if subject_raw.count("?") >= 5:
        result.add(
            "Subject with corrupted characters (mojibake)",
            "The subject contains numerous consecutive '?' symbols, a sign of "
            "broken character encoding or text obfuscated to evade content filters.",
            10, "low",
        )

    # --- Rule 16: Internationalized domain name (punycode) in From --------------
    if from_domain and _has_idn_label(from_domain):
        decoded = _decode_idn_domain(from_domain)
        result.add(
            "Internationalized domain name (punycode)",
            f"'{from_domain}' decodes to '{decoded}'. Attackers register punycode "
            "domains that render as characters nearly identical to a trusted brand "
            "(homograph/IDN spoofing) to fool the eye.",
            20, "high",
        )
        for brand, brand_domains in KNOWN_BRANDS.items():
            if brand_domains and brand in decoded.lower() and not _domain_matches_brand(decoded.lower(), brand_domains):
                result.add(
                    "Punycode domain resembling a known brand",
                    f"Decoded, '{from_domain}' reads as '{decoded}', which imitates "
                    f"'{' / '.join(brand_domains)}'.",
                    25, "high",
                )
                break

    # --- Rule 17: Homoglyph brand impersonation in the domain --------------------
    if from_domain:
        normalized_domain = _normalize_confusables(from_domain)
        if normalized_domain != from_domain.lower():
            for brand, brand_domains in KNOWN_BRANDS.items():
                if not brand_domains:
                    continue
                if _domain_matches_brand(from_domain, brand_domains):
                    continue  # legitimate domain for this brand
                for bd in brand_domains:
                    if bd in normalized_domain:
                        result.add(
                            "Domain uses look-alike characters to mimic a brand",
                            f"'{from_domain}' contains characters that visually resemble "
                            f"'{bd}' once normalized ('{normalized_domain}'), but is "
                            "a different domain.",
                            30, "high",
                        )
                        break

    # --- Rule 18: Duplicate critical headers --------------------------------------
    for hname in ("From", "Reply-To", "Return-Path"):
        values = msg.get_all(hname, [])
        if len(values) > 1:
            result.add(
                f"Duplicate '{hname}' header",
                f"The message declares {len(values)} '{hname}' headers. Mail clients "
                "usually only display one, so extra copies can be used to smuggle a "
                "different address past filters than the one the user sees.",
                20, "high",
            )

    # --- Rule 19: Conflicting Authentication-Results ------------------------------
    if len(auth_results_all) > 1:
        verdict_sets = []
        for ar in auth_results_all:
            verdicts = tuple(sorted(re.findall(r"(spf|dkim|dmarc)=(\w+)", ar.lower())))
            if verdicts:
                verdict_sets.append(verdicts)
        if len(set(verdict_sets)) > 1:
            result.add(
                "Multiple Authentication-Results with conflicting verdicts",
                f"The message carries {len(auth_results_all)} separate "
                "'Authentication-Results' headers with different SPF/DKIM/DMARC "
                "verdicts. Only the header added by your own organization's final "
                "mail server should be trusted; earlier ones may have been forged by "
                "the sender to fake a 'pass'.",
                20, "medium",
            )

    # --- Rule 20: Date header anomaly ----------------------------------------------
    date_raw = msg.get("Date", "")
    if date_raw:
        try:
            parsed_date = parsedate_to_datetime(date_raw)
            if parsed_date is not None:
                now = (
                    datetime.datetime.now(parsed_date.tzinfo)
                    if parsed_date.tzinfo is not None
                    else datetime.datetime.now()
                )
                delta_days = (parsed_date - now).total_seconds() / 86400
                if delta_days > 1:
                    result.add(
                        "Date header is in the future",
                        f"The 'Date' header ({date_raw.strip()}) is {delta_days:.1f} "
                        "day(s) ahead of now, inconsistent with a normal SMTP send.",
                        8, "low",
                    )
                elif delta_days < -3650:
                    result.add(
                        "Date header is implausibly old",
                        f"The 'Date' header ({date_raw.strip()}) is more than 10 years "
                        "in the past.",
                        8, "low",
                    )
        except Exception:
            pass

    # --- Rule 21: Random-looking sender mailbox (local-part) ----------------------
    from_local = from_addr.split("@")[0] if "@" in from_addr else ""
    if from_local:
        letters = [c for c in from_local if c.isalpha()]
        if len(letters) >= 10:
            vowels = sum(1 for c in letters if c.lower() in "aeiou")
            if (vowels / len(letters)) <= 0.15:
                result.add(
                    "Randomly-generated-looking sender mailbox",
                    f"The mailbox name '{from_local}' looks auto-generated rather "
                    "than a real username, typical of throwaway spam accounts.",
                    12, "medium",
                )

    # --- Rule 22: Business Email Compromise (BEC) pattern --------------------------
    body_for_bec = extract_body_text(raw_text)
    combined_text = f"{subject_raw}\n{body_for_bec}".lower()
    bec_hits = [kw for kw in BEC_KEYWORDS if kw in combined_text]
    exec_title_hit = any(t in name_lower for t in EXEC_TITLE_KEYWORDS)
    if bec_hits and (exec_title_hit or from_domain in FREE_MAIL_DOMAINS):
        reason = (
            f"the display name suggests an executive ('{from_name}') "
            if exec_title_hit
            else f"it's sent from a free webmail domain ('{from_domain}') "
        )
        result.add(
            "Possible Business Email Compromise (BEC) pattern",
            "Combination typical of CEO/executive-impersonation fraud: " + reason +
            f"together with payment-related pressure language: {', '.join(bec_hits[:4])}.",
            25, "high",
        )

    # --- Rule 23: Unusually high number of recipients ------------------------------
    cc_raw = msg.get("Cc", "")
    all_recipients = getaddresses([to_raw, cc_raw]) if (to_raw or cc_raw) else []
    if len(all_recipients) > 30:
        result.add(
            "Unusually high number of recipients",
            f"{len(all_recipients)} addresses appear in To/Cc, typical of a mass "
            "phishing blast rather than legitimate individual correspondence.",
            8, "low",
        )

    # --- Rule 24: Marketing tone from a known brand, no List-Unsubscribe -----------
    if not msg.get("List-Unsubscribe"):
        for brand, brand_domains in KNOWN_BRANDS.items():
            if brand_domains and _domain_matches_brand(from_domain, brand_domains) and any(
                kw in subj_lower for kw in ("% off", "sale", "newsletter", "offer", "discount")
            ):
                result.add(
                    "Marketing-style email without List-Unsubscribe",
                    f"Claims to be from '{from_domain}' with promotional language, "
                    "but lacks the 'List-Unsubscribe' header real companies include "
                    "for legal compliance (CAN-SPAM/GDPR).",
                    8, "low",
                )
                break

    # --- Rules 25-29: Link analysis in the body -------------------------------------
    links = extract_links(raw_text)
    flagged_mismatch = flagged_ip = flagged_shortener = False
    flagged_at_trick = flagged_link_typosquat = False

    for anchor_text, href in links:
        href_domain = _domain_from_url(href)
        if not href_domain:
            continue

        # Rule 25: anchor text displays one domain, href points elsewhere
        if not flagged_mismatch:
            anchor_match = re.search(
                r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})", anchor_text.lower()
            )
            if anchor_match:
                anchor_domain = anchor_match.group(1)
                if not _aligned(anchor_domain, href_domain) and _similarity(anchor_domain, href_domain) < 0.6:
                    result.add(
                        "Link text does not match its real destination",
                        f"A link displays '{anchor_domain}' but actually points to "
                        f"'{href_domain}'.",
                        30, "high",
                    )
                    flagged_mismatch = True

        # Rule 26: raw IP address as the link host
        if not flagged_ip and _IP_HOST_RE.match(href_domain):
            result.add(
                "Link points to a raw IP address",
                f"A link in the body points directly to an IP address ({href_domain}) "
                "instead of a domain name, a common evasion technique.",
                20, "medium",
            )
            flagged_ip = True

        # Rule 27: URL-shortening service
        if not flagged_shortener and href_domain in URL_SHORTENERS:
            result.add(
                "Link uses a URL-shortening service",
                f"A link uses '{href_domain}', which hides the real destination "
                "until clicked.",
                10, "low",
            )
            flagged_shortener = True

        # Rule 28: userinfo ("@") obfuscation trick
        host_part = href.split("//", 1)[-1].split("/", 1)[0]
        if not flagged_at_trick and "@" in host_part:
            result.add(
                "Link uses the '@' obfuscation trick",
                f"The URL '{href}' contains an '@' before the real host, a technique "
                "to make a malicious domain look like it belongs to a trusted one.",
                25, "high",
            )
            flagged_at_trick = True

        # Rule 29: link domain impersonates a known brand
        if not flagged_link_typosquat:
            normalized_href = _normalize_confusables(href_domain)
            for brand, brand_domains in KNOWN_BRANDS.items():
                if not brand_domains:
                    continue
                if _domain_matches_brand(href_domain, brand_domains):
                    continue  # legitimate domain (or regional/sister variant) for this brand
                for bd in brand_domains:
                    if _looks_like_typosquat(href_domain, bd) or (bd in normalized_href and href_domain != bd):
                        result.add(
                            "Link domain resembles a known brand",
                            f"A link points to '{href_domain}', which resembles "
                            f"'{bd}' but is not the same domain.",
                            25, "high",
                        )
                        flagged_link_typosquat = True
                        break
                if flagged_link_typosquat:
                    break

    # --- Rules 30-31: Attachment analysis --------------------------------------------
    for filename in extract_attachments(raw_text):
        lower_name = filename.lower().strip()
        ext = "." + lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""

        if ext in DANGEROUS_ATTACHMENT_EXTENSIONS:
            result.add(
                "Dangerous attachment type",
                f"The attachment '{filename}' has the extension '{ext}', which can "
                "execute code and is rarely legitimate as an email attachment.",
                30, "high",
            )

        parts_ext = re.findall(r"\.[a-z0-9]{2,5}", lower_name)
        if len(parts_ext) >= 2:
            second_last, last = parts_ext[-2], parts_ext[-1]
            if second_last in DOCUMENT_LIKE_EXTENSIONS and last in DANGEROUS_ATTACHMENT_EXTENSIONS:
                result.add(
                    "Attachment with a disguised double extension",
                    f"'{filename}' looks like a document ('{second_last}') but the "
                    f"real extension is '{last}', a classic trick to make an "
                    "executable look harmless when file extensions are hidden.",
                    35, "high",
                )

    # --- Final classification ---------------------------------------------------
    if result.score >= 50:
        result.risk_level = "High"
    elif result.score >= 20:
        result.risk_level = "Medium"
    else:
        result.risk_level = "Low"

    if not result.findings:
        result.add(
            "No relevant indicators found",
            "No suspicious patterns were detected with the current rules. "
            "This does not guarantee the email is legitimate.",
            0, "info",
        )

    return result