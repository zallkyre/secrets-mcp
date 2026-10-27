# secrets-mcp

**Give the agent a handle, not the key.**

An MCP server that takes an API key out of the conversation the moment it appears. The agent keeps `{{stripe}}` and calls your APIs through the server, which fills in the real key outside the transcript.

## Install

```powershell
irm https://raw.githubusercontent.com/zallkyre/secrets-mcp/main/install.ps1 | iex
```

It finds the agents on your PC, lists them, and wires up the one you pick:

```
  Detected agents:
    [1] OpenCode
    [2] OpenWork
    [3] Claude Desktop
    [4] Cursor
    [5] VS Code

  Connect secrets-mcp to which agent(s)?
  Enter numbers separated by commas, 'a' for all, or Ctrl+C to abort.
  >
```

Every config it touches is backed up first. Re-running is safe — it replaces its own entry instead of duplicating it.

`MIT` · `Python 3.10+` · `Windows first` · [`11 agents`](#supported-agents)

---

## What it looks like

```
you:    here's my stripe key sk_live_4eC39Hq…
agent:  stored as {{stripe}} — I won't repeat it.
agent:  calling the API with {{stripe}}
        ↑ filled in locally, after the model stops writing

agent:  200 OK  balance: $1,204.00
```

One tool call at the paste. After that the key is out of the model's reach.

## Why

Every time you paste a key into chat, that key lives in:

- the model provider's request logs
- your local transcript
- every later tool call the agent writes (curl, shell, files)
- any screenshot or code block it prints

`secrets-mcp` closes everything after the paste. It cannot close the paste itself — see [Threat model](#threat-model).

## Tools

| tool | what it does |
|---|---|
| `stage_secret` | finds keys in text, stores them, returns the text with `{{handles}}` |
| `list_secrets` | handles + last-4 fingerprint + use count. **Never values.** |
| `request_with_secret` | HTTP call with `{{handle}}` resolved server-side |
| `revoke_secret` | deletes a handle |
| `vault_info` | vault path, backend, count |

No tool returns a raw secret. That is the entire design constraint — a single `get` would make the whole thing pointless, so it does not exist.

**Detected formats:** Anthropic · OpenAI · GitHub PAT · AWS access key · Stripe · Slack · Google API · SendGrid · Resend · Discord bot · Twilio · Groq · JWTs · PEM private keys · high-entropy strings with nearby `api_key`/`token` context.

## Storage

| platform | backend |
|---|---|
| Windows | **DPAPI** (`CryptProtectData`) — bound to your Windows user, no password |
| Linux / macOS | AES-GCM, key at `~/.secrets-mcp/key` (`0600`), requires `cryptography` |

Vault: `%APPDATA%\secrets-mcp\vault.json`. Override with `SECRETS_MCP_VAULT`.

## Threat model

**Protects against**

- the key being written into shell commands, curl, files, or later prompts
- the key leaking through agent logs of tool arguments
- API error responses that echo your key back (the proxy scrubs responses too)
- plaintext secrets sitting on disk

**Does not protect against**

- **the paste itself.** Once you send a key, it reached the model provider on that request. No tool can undo that. Revoke and rotate if it was live.
- a compromised local account — DPAPI decrypts for your user by design
- a malicious MCP server you installed alongside this one
- prompt injection that persuades the agent to call `request_with_secret` against an attacker's URL — review the tool calls, and use scoped keys

**Honest framing:** this reduces blast radius. It is not a vault you can safely paste anything into.

---

## Supported agents

| agent | config |
|---|---|
| OpenCode | `~/.config/opencode/opencode.jsonc` |
| OpenWork | `%APPDATA%\openwork\runtime-opencode-config.json` |
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `~/.claude.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| VS Code | `%APPDATA%\Code\User\mcp.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Codex CLI | `~/.codex/config.toml` |
| Zed | `%APPDATA%\Zed\settings.json` |
| OpenClaw | `~/.openclaw/config.json` |

Only the ones actually installed are offered.

### Manual install

OpenCode / OpenWork:

```json
{
  "mcp": {
    "secrets": {
      "type": "local",
      "command": ["python", "-m", "secrets_mcp"],
      "enabled": true
    }
  }
}
```

Everything else:

```json
{
  "mcpServers": {
    "secrets": { "command": "python", "args": ["-m", "secrets_mcp"] }
  }
}
```

## Development

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
```

## License

MIT

---

**LLM guide** — Give the agent a handle, not the key. MCP server that keeps API keys out of AI agent conversations. · Stack: Python · Run: `pip install .` · License: MIT
