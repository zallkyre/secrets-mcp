"""secrets-mcp — give the agent a handle, not the key.

Design rule: no tool in this server ever returns a raw secret. If a tool
did, the agent would echo it and the whole point would be lost.
"""

from __future__ import annotations

import json
import sys

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from . import detect, proxy, store

__version__ = "0.1.0"

# mcp 2.x reports serverInfo.version from the client-visible server object;
# without this it shows "" because the package is not installed as a distribution
_extra = {}
try:
    import inspect as _inspect

    if "version" in _inspect.signature(_Server.__init__).parameters:
        _extra["version"] = __version__
except Exception:
    pass

mcp = _Server(
    "secrets-mcp",
    **_extra,
    instructions=(
        "Secret handoff for AI agents. When the user pastes an API key or "
        "token, call stage_secret with the pasted text. It returns the same "
        "text with the key replaced by a {{handle}}. From then on, never ask "
        "for the key again and never type it: reference the handle and use "
        "request_with_secret, which fills it in outside the conversation."
    ),
)


def _err(exc: Exception) -> str:
    return json.dumps({"ok": False, "error": str(exc)}, indent=2)


@mcp.tool()
def stage_secret(text: str, name: str | None = None) -> str:
    """Store any secrets in `text` and return it with handles substituted.

    Use this the moment a user pastes an API key, token, or private key.
    The returned text is safe to repeat; the original was written to an
    encrypted local vault and is not returned.

    Args:
        text: the raw text containing the secret(s).
        name: optional handle to force, e.g. "stripe" -> {{stripe}}.
    """
    try:
        cleaned, found = detect.redact(text)
        if not found:
            return json.dumps(
                {
                    "ok": True,
                    "found": 0,
                    "text": text,
                    "note": "no secrets detected; nothing stored",
                },
                indent=2,
            )

        stored = []
        if name:
            # Single explicit name: collapse every detection into one handle.
            handle = store.normalize_name(name)
            first = next(iter(found.values()))
            stored.append(store.put(handle, first))
            cleaned = proxy.HANDLE_RE.sub("{{" + handle + "}}", cleaned)
        else:
            for handle, value in found.items():
                stored.append(store.put(handle, value))

        return json.dumps(
            {
                "ok": True,
                "found": len(stored),
                "handles": [s["name"] for s in stored],
                "text": cleaned,
                "next": "Reference these handles, e.g. {{"
                + stored[0]["name"]
                + "}}. Never ask for the raw value again.",
            },
            indent=2,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the agent
        return _err(exc)


@mcp.tool()
def list_secrets() -> str:
    """List stored handles with fingerprints. Never returns secret values."""
    try:
        items = store.listing()
        return json.dumps({"ok": True, "count": len(items), "secrets": items}, indent=2)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def request_with_secret(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> str:
    """Call an API, substituting {{handle}} with the real secret server-side.

    Use this instead of writing the key into a shell command or curl. The
    key is injected here, outside the conversation, and the response is
    scrubbed before it comes back.

    Args:
        method: GET, POST, PUT, PATCH, DELETE.
        url: full URL; {{handle}} is allowed in the path or query.
        headers: e.g. {"Authorization": "Bearer {{stripe}}"}.
        body: request body; {{handle}} is substituted.
    """
    try:
        return json.dumps(proxy.request(method, url, headers, body), indent=2)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def revoke_secret(name: str) -> str:
    """Delete a stored handle. The real secret is destroyed locally."""
    try:
        removed = store.delete(name)
        return json.dumps(
            {
                "ok": removed,
                "name": name,
                "note": "removed" if removed else "no such handle",
            },
            indent=2,
        )
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def vault_info() -> str:
    """Where the vault lives and how many handles it holds. No values."""
    try:
        return json.dumps(
            {
                "ok": True,
                "version": __version__,
                "vault": str(store.vault_path()),
                "backend": "windows-dpapi" if sys.platform == "win32" else "aes-gcm",
                "count": len(store.listing()),
            },
            indent=2,
        )
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
