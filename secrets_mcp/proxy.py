"""Inject handles server-side so the agent never handles raw keys."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from . import detect, store

HANDLE_RE = re.compile(r"\{\{\s*([a-z0-9][a-z0-9_-]{0,31})\s*\}\}")
_MAX_BODY = 8000


def substitute(text: str) -> str:
    """Replace every {{handle}} with its secret. Raises on unknown handles."""
    if not text:
        return text

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        store.touch(name)
        return store.get(name)

    return HANDLE_RE.sub(repl, text)


def substitute_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {k: substitute(str(v)) for k, v in headers.items()}


def request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 30,
) -> dict:
    """Perform an HTTP request with handles resolved at the last moment.

    The response is scrubbed before it is returned: a few APIs echo the
    key back in errors, and we never want that in the transcript.
    """
    method = (method or "GET").upper()
    data = None
    if body:
        data = substitute(body).encode("utf-8")

    req = urllib.request.Request(
        substitute(url),
        data=data,
        headers=substitute_headers(headers),
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(_MAX_BODY * 2).decode("utf-8", "replace")
            status = resp.status
            resp_headers = dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read(_MAX_BODY * 2).decode("utf-8", "replace")
        status = exc.code
        resp_headers = dict(exc.headers or {})
    except urllib.error.URLError as exc:
        return {"ok": False, "error": f"request failed: {exc.reason}"}

    clean, leaked = detect.redact(raw)
    if leaked:
        # The API echoed a secret. Store nothing, just strip it.
        pass

    out = {
        "ok": 200 <= status < 400,
        "status": status,
        "content_type": resp_headers.get("Content-Type", ""),
        "body": clean[:_MAX_BODY],
        "truncated": len(clean) > _MAX_BODY,
    }
    if leaked:
        out["note"] = "response contained a secret; it was redacted before return"
    return out


def to_json(value) -> str:
    return json.dumps(value, indent=2, default=str)
