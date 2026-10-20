"""Find secrets in arbitrary text and replace them with handles.

Detection is deliberately conservative: a false positive costs the user a
redaction they can undo; a false negative leaks a key. Every pattern
carries a human name so the handle is obvious ({{stripe}}, {{github}}).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (kind, pattern, priority) — higher priority wins on overlap.
_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), 100),
    ("openai", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), 90),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), 95),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), 90),
    ("groq", re.compile(r"gsk_[A-Za-z0-9]{20,}"), 90),
    ("stripe", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"), 90),
    ("slack", re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}"), 90),
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}"), 85),
    ("google", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), 85),
    ("sendgrid", re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), 85),
    ("resend", re.compile(r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{8,}\b"), 85),
    ("discord", re.compile(r"[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}"), 85),
    ("twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 80),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 70),
    ("pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{32,}?-----END [A-Z ]*PRIVATE KEY-----"), 100),
]

# Assign a stable handle per kind so repeated keys of the same provider
# collapse into one handle (stripe, stripe-2, ...).
_BASE_NAME = {
    "anthropic": "anthropic",
    "openai": "openai",
    "github_pat": "github",
    "github": "github",
    "groq": "groq",
    "stripe": "stripe",
    "slack": "slack",
    "aws": "aws",
    "google": "google",
    "sendgrid": "sendgrid",
    "resend": "resend",
    "discord": "discord",
    "twilio": "twilio",
    "jwt": "jwt",
    "pem": "privatekey",
}

# Words that, when near a candidate, raise confidence. Used only for the
# generic high-entropy rule.
_CONTEXT = re.compile(r"(?:api[_\- ]?key|token|secret|passwd|password|bearer)", re.I)
_GENERIC = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    start: int
    end: int
    suggested: str


def find(text: str) -> list[Finding]:
    hits: list[Finding] = []

    for kind, rx, _prio in _PATTERNS:
        for m in rx.finditer(text):
            hits.append(
                Finding(kind, m.group(0), m.start(), m.end(), _BASE_NAME.get(kind, kind))
            )

    # Generic fallback: only with nearby context words, to avoid redacting
    # every long identifier the user pastes.
    for m in _GENERIC.finditer(text):
        window = text[max(0, m.start() - 60) : m.start()]
        if _CONTEXT.search(window):
            hits.append(Finding("generic", m.group(0), m.start(), m.end(), "secret"))

    # Drop overlaps, keeping the highest-priority (longest) match.
    hits.sort(key=lambda f: (f.start, -(f.end - f.start)))
    out: list[Finding] = []
    for f in hits:
        if out and f.start < out[-1].end:
            continue
        out.append(f)
    return out


def unique_handles(findings: list[Finding]) -> dict[str, Finding]:
    """Map handle name -> first finding of that kind."""
    used: dict[str, int] = {}
    mapping: dict[str, Finding] = {}
    for f in findings:
        if f.suggested in mapping:
            continue
        count = used.get(f.suggested, 0) + 1
        used[f.suggested] = count
        handle = f.suggested if count == 1 else f"{f.suggested}-{count}"
        mapping[handle] = f
    return mapping


def redact(text: str) -> tuple[str, dict[str, str]]:
    """Replace every detected secret with {{handle}}.

    Returns (clean_text, {handle: raw_value}). The raw values are meant to
    be written straight into the vault and never returned to the caller.
    """
    findings = find(text)
    if not findings:
        return text, {}

    handles = unique_handles(findings)
    # Rebuild the string so each kind collapses to one handle.
    pieces: list[str] = []
    cursor = 0
    ordered = sorted(findings, key=lambda f: f.start)
    handle_by_kind: dict[str, str] = {}
    for handle, f in handles.items():
        handle_by_kind.setdefault(f.kind, handle)

    for f in ordered:
        handle = handle_by_kind.get(f.kind, f.suggested)
        pieces.append(text[cursor : f.start])
        pieces.append("{{" + handle + "}}")
        cursor = f.end
    pieces.append(text[cursor:])

    return "".join(pieces), {h: f.value for h, f in handles.items()}
