# -*- coding: utf-8 -*-
"""
llm_body_analyzer.py
Uses an LLM (via LangChain) to analyze the BODY of an email for phishing
signals — something the header-only heuristic engine in analyzer.py can't
see at all.

Provider is pluggable so you can start free/local (Ollama) and later switch
to a paid API (Anthropic/Claude) without touching any other code:

    EMAILXRAY_LLM_PROVIDER = "ollama" (default) | "anthropic"
    EMAILXRAY_OLLAMA_MODEL = "llama3.2" (default)
    EMAILXRAY_ANTHROPIC_MODEL = "claude-sonnet-5" (default)
    ANTHROPIC_API_KEY = "..." (required only if provider = "anthropic")

These are read from environment variables so the GUI (main.py) can just set
os.environ[...] right before calling analyze_email_body(), with no need to
change this module.

Part of E-MailX-Ray.
"""

import os
import re
import json
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage

MAX_BODY_CHARS = 3500  # keep prompts small & cheap; also leaves more room for the reply

SYSTEM_PROMPT = """You are a cybersecurity assistant specialized in phishing detection.
You will be shown the body of an email, plus the sender's domain and whether
its authentication (SPF/DKIM) already passed.

Decide whether the BODY shows CONCRETE signs of phishing or social engineering.
Only count something as a red flag if it is specific and well-founded, e.g.:
  - A link whose visible text or destination domain does NOT match the
    sender's actual domain.
  - An explicit request for a password, PIN, credit card number, or similar
    credentials.
  - Threats, fake deadlines, or high-pressure urgency tied to an action.
  - Impersonation of a brand/authority that doesn't match the sender's domain.

Do NOT flag an email just because it has a generic greeting, a marketing
tone, a call-to-action button, or a link — these are completely normal in
legitimate transactional and notification emails from real companies
(shipping updates, event registrations, newsletters, etc.). If the sender's
domain is a well-known, authenticated company domain and you don't have a
concrete reason from the list above, keep risk_contribution low (0-10) even
if the email is promotional or impersonal in tone.

Keep your answer SHORT: at most 3 red flags, and a summary of no more than 2
sentences. Only list a red flag if you can point to the specific text or
element in the body that justifies it — do not invent details that aren't
actually present in the body you were given.

Respond with ONLY a JSON object, no extra text, no markdown fences, matching
exactly this shape:
{
  "is_suspicious": true or false,
  "risk_contribution": integer from 0 to 40 (0 = no concerns, 40 = extremely suspicious),
  "red_flags": ["short phrase", "short phrase"],
  "summary": "1-2 sentence explanation of your verdict, in the same language as the email body"
}

(In English, please)
"""


class BodyAnalysis(BaseModel):
    is_suspicious: bool = Field(default=False)
    risk_contribution: int = Field(default=0, ge=0, le=40)
    red_flags: list = Field(default_factory=list)
    summary: str = Field(default="")


class LLMNotConfigured(RuntimeError):
    """Raised when the selected provider is missing required configuration
    (e.g. no ANTHROPIC_API_KEY) or is unreachable (e.g. Ollama not running)."""
    pass


def get_llm():
    """
    Provider factory. Returns a LangChain chat model instance based on
    environment variables. Keeping this as a single function means adding
    a third provider later (OpenAI, Groq, etc.) only touches this file.
    """
    provider = os.environ.get("EMAILXRAY_LLM_PROVIDER", "ollama").lower().strip()

    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise LLMNotConfigured(
                "Anthropic provider selected, but ANTHROPIC_API_KEY is not set."
            )
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as e:
            raise LLMNotConfigured(
                "The 'langchain-anthropic' package is not installed. "
                "Run: pip install langchain-anthropic"
            ) from e
        model = os.environ.get("EMAILXRAY_ANTHROPIC_MODEL", "claude-sonnet-5")
        return ChatAnthropic(model=model, api_key=api_key, temperature=0, max_tokens=1024)

    # Default: local, free, offline-friendly Ollama
    try:
        from langchain_ollama import ChatOllama
    except ImportError as e:
        raise LLMNotConfigured(
            "The 'langchain-ollama' package is not installed. "
            "Run: pip install langchain-ollama"
        ) from e
    model = os.environ.get("EMAILXRAY_OLLAMA_MODEL", "llama3.2")
    try:
        return ChatOllama(
            model=model,
            temperature=0,
            num_ctx=8192,      # default (2048) is too small: prompt + JSON reply gets truncated
            num_predict=700,   # generous cap so the JSON response always has room to finish
        )
    except Exception as e:
        raise LLMNotConfigured(
            f"Could not initialize the local Ollama model '{model}'. "
            "Make sure Ollama is installed and running (https://ollama.com), "
            f"and that you've pulled the model: 'ollama pull {model}'."
        ) from e


def _extract_json(raw_text: str) -> dict:
    """
    Models sometimes wrap JSON in ```json fences or add stray text around
    it. Grab the first {...} block and parse that. If the response got cut
    off mid-generation (common with small Ollama context windows), try to
    salvage the fields we can find instead of failing outright.
    """
    match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass  # fall through to partial recovery below

    partial = {}
    m = re.search(r'"is_suspicious"\s*:\s*(true|false)', raw_text)
    if m:
        partial["is_suspicious"] = m.group(1) == "true"
    m = re.search(r'"risk_contribution"\s*:\s*(\d+)', raw_text)
    if m:
        partial["risk_contribution"] = int(m.group(1))
    m = re.search(r'"summary"\s*:\s*"([^"]*)', raw_text)
    if m:
        partial["summary"] = m.group(1).strip() + " (note: AI response was cut off before finishing)"
    if '"red_flags"' in raw_text:
        tail = raw_text.split('"red_flags"', 1)[1]
        tail = tail.split('"summary"', 1)[0]
        flags = re.findall(r'"([^"]{3,80})"', tail)
        if flags:
            partial["red_flags"] = flags[:5]

    if partial:
        return partial

    raise ValueError(f"No JSON object found in the LLM response: {raw_text[:200]!r}")


def analyze_email_body(
    subject: str,
    body_text: str,
    sender_display: str,
    sender_domain: str = "",
    auth_results: str = "",
    llm=None,
) -> BodyAnalysis:
    """
    Runs the LLM-based body analysis. Raises LLMNotConfigured or any
    provider-specific connection error if the call fails — the caller
    (the GUI) is expected to catch that and degrade gracefully to the
    heuristic-only result.
    """
    if not body_text or not body_text.strip():
        return BodyAnalysis(
            is_suspicious=False, risk_contribution=0, red_flags=[],
            summary="No email body was found to analyze (headers-only input, or an encrypted/empty body).",
        )

    if llm is None:
        llm = get_llm()

    truncated_body = body_text.strip()[:MAX_BODY_CHARS]

    user_prompt = (
        f"Sender display name: {sender_display or '(unknown)'}\n"
        f"Sender domain: {sender_domain or '(unknown)'}\n"
        f"Authentication-Results (SPF/DKIM/DMARC): {auth_results or '(not present)'}\n"
        f"Subject: {subject or '(no subject)'}\n\n"
        f"Email body:\n---\n{truncated_body}\n---\n"
    )

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=user_prompt)]
    response = llm.invoke(messages)
    raw = response.content if hasattr(response, "content") else str(response)

    data = _extract_json(raw)
    return BodyAnalysis(
        is_suspicious=bool(data.get("is_suspicious", False)),
        risk_contribution=max(0, min(40, int(data.get("risk_contribution", 0)))),
        red_flags=list(data.get("red_flags", []))[:10],
        summary=str(data.get("summary", "")).strip(),
    )
