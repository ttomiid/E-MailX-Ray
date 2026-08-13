# -*- coding: utf-8 -*-
"""
report_common.py
Shared content-building logic for the report exporters (report_pdf.py and
report_docx.py). Both the "technical" and "executive" report, in both PDF
and DOCX format, are built from the same summary dict produced here — so
the four output combinations never drift apart in wording or numbers.

Part of E-MailX-Ray.
"""

import datetime

VERDICT_TEXT = {
    "High": "This email shows strong indicators of phishing and should be treated as malicious.",
    "Medium": "This email shows some suspicious indicators and warrants caution before acting on it.",
    "Low": "No significant phishing indicators were detected in this email.",
}

RECOMMENDATION_TEXT = {
    "High": "Do not click any links, open attachments, or reply. Report it to your "
            "security/IT team and delete the message.",
    "Medium": "Do not act on this email yet. Verify the sender through a separate, "
               "trusted channel (e.g. a phone call) before clicking links, opening "
               "attachments, or replying.",
    "Low": "No action required beyond standard email hygiene. Stay cautious with "
           "unexpected links and attachments as usual.",
}

# Sort order for "most important first" — used to pick the handful of
# findings shown in the executive summary.
SEVERITY_ORDER = {"high": 0, "medium": 1, "ai": 2, "low": 3, "info": 4}

SEVERITY_LABELS = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "ai": "AI",
}


def top_findings(result, limit=5):
    """
    The most relevant findings for a business-friendly summary: sorted by
    severity (high > medium > ai > low > info) and then by weight
    descending, capped at `limit`. Zero-weight informational noise is
    excluded unless there's genuinely nothing else to show.
    """
    findings = list(result.findings)
    significant = [f for f in findings if not (f.severity == "info" and f.weight == 0)]
    pool = significant or findings
    pool.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.weight))
    return pool[:limit]


def severity_counts(result):
    counts = {"high": 0, "medium": 0, "low": 0, "ai": 0, "info": 0}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def build_summary(result, app_name="E-MailX-Ray"):
    """
    Returns a plain dict with everything the report backends need for the
    executive summary section (and the short verdict line the technical
    report also shows). `result` is an analyzer.AnalysisResult.
    """
    return {
        "app_name": app_name,
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_level": result.risk_level,
        "score": result.score,
        "verdict": VERDICT_TEXT.get(result.risk_level, ""),
        "recommendation": RECOMMENDATION_TEXT.get(result.risk_level, ""),
        "counts": severity_counts(result),
        "top_findings": top_findings(result),
        "total_findings": len(result.findings),
    }
