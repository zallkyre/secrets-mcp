"""Encrypted local vault.

Windows uses DPAPI (CryptProtectData) — the same protection Chrome and
Windows Credential Manager use. No master password, no key management,
and the blob is bound to the current Windows user.

On other platforms the vault requires `cryptography` (AES-GCM) and a key
file at ~/.secrets-mcp/key with 0600 permissions.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
from pathlib import Path

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_VAULT_VERSION = 1


class VaultError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Windows DPAPI
# --------------------------------------------------------------------------

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes as wt

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    def _to_blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _protect(data: bytes) -> bytes:
        blob_in, _keep = _to_blob(data)
        blob_out = _BLOB()
        ok = _crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            raise VaultError("CryptProtectData failed")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(blob_out.pbData)

    def _unprotect(data: bytes) -> bytes:
        blob_in, _keep = _to_blob(data)
        blob_out = _BLOB()
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            raise VaultError("CryptUnprotectData failed (wrong user or corrupted vault)")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(blob_out.pbData)

else:  # pragma: no cover - non-Windows path
    def _key_path() -> Path:
        return Path.home() / ".secrets-mcp" / "key"

    def _load_key() -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except ImportError as exc:
            raise VaultError(
                "non-Windows vaults need the 'cryptography' package: pip install cryptography"
            ) from exc
        kp = _key_path()
        if not kp.exists():
            kp.parent.mkdir(parents=True, exist_ok=True)
            kp.write_bytes(os.urandom(32))
            os.chmod(kp, 0o600)
        return kp.read_bytes()

    def _protect(data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        return nonce + AESGCM(_load_key()).encrypt(nonce, data, None)

    def _unprotect(data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(_load_key()).decrypt(data[:12], data[12:], None)


# --------------------------------------------------------------------------
# Vault file
# --------------------------------------------------------------------------


def vault_path() -> Path:
    override = os.environ.get("SECRETS_MCP_VAULT")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("APPDATA") if sys.platform == "win32" else None
    root = Path(base) if base else Path.home() / ".config"
    return root / "secrets-mcp" / "vault.json"


def _read() -> dict:
    p = vault_path()
    if not p.exists():
        return {"version": _VAULT_VERSION, "secrets": {}}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError(f"vault is corrupted: {p}") from exc


def _write(data: dict) -> None:
    p = vault_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, p)


def normalize_name(name: str) -> str:
    """Validate a handle name. Strict on purpose: silent rewriting of a
    name like "../etc/passwd" would hide a mistake instead of surfacing it."""
    n = (name or "").strip().lower()
    if not _NAME_RE.match(n):
        suggestion = re.sub(r"[^a-z0-9_-]+", "-", n).strip("-") or "secret"
        raise VaultError(
            f"invalid name {name!r}: use lowercase letters, numbers, - and _, "
            f"max 32 chars (try {suggestion!r})"
        )
    return n


def _hint(value: str) -> str:
    tail = value[-4:] if len(value) >= 8 else "*" * len(value)
    return f"…{tail}"


def put(name: str, value: str) -> dict:
    n = normalize_name(name)
    if not value:
        raise VaultError("empty secret")
    data = _read()
    data["secrets"][n] = {
        "blob": base64.b64encode(_protect(value.encode("utf-8"))).decode("ascii"),
        "hint": _hint(value),
        "length": len(value),
        "created": int(time.time()),
        "uses": 0,
    }
    _write(data)
    return {"name": n, "hint": _hint(value)}


def get(name: str) -> str:
    n = normalize_name(name)
    entry = _read()["secrets"].get(n)
    if not entry:
        raise VaultError(f"no secret named {n!r}")
    return _unprotect(base64.b64decode(entry["blob"])).decode("utf-8")


def touch(name: str) -> None:
    """Bump the use counter. Never returns the value."""
    n = normalize_name(name)
    data = _read()
    entry = data["secrets"].get(n)
    if entry:
        entry["uses"] = int(entry.get("uses", 0)) + 1
        _write(data)


def listing() -> list[dict]:
    data = _read()
    out = []
    for name, entry in sorted(data["secrets"].items()):
        out.append(
            {
                "name": name,
                "hint": entry.get("hint", "…"),
                "length": entry.get("length", 0),
                "created": entry.get("created", 0),
                "uses": entry.get("uses", 0),
            }
        )
    return out


def names() -> set[str]:
    return set(_read()["secrets"].keys())


def delete(name: str) -> bool:
    n = normalize_name(name)
    data = _read()
    if n not in data["secrets"]:
        return False
    del data["secrets"][n]
    _write(data)
    return True
