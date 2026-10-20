<#
.SYNOPSIS
  Install secrets-mcp and connect it to the AI agents on this PC.

.DESCRIPTION
  Detects installed agent apps, shows a numbered list, installs the MCP
  server for the ones you pick, and backs up every config it touches.

  One-liner:
    irm https://raw.githubusercontent.com/zallkyre/secrets-mcp/main/install.ps1 | iex

.PARAMETER List
  Only show what is installed. Change nothing.

.PARAMETER All
  Connect every detected agent without prompting.

.PARAMETER Menu
  Force the interactive picker even when the script was piped.

.EXAMPLE
  .\install.ps1 -List
#>
[CmdletBinding()]
param(
    [switch]$List,
    [switch]$All,
    [switch]$Menu,
    [switch]$NoDeps
)

$ErrorActionPreference = 'Stop'
$Repo = 'https://github.com/zallkyre/secrets-mcp'
$ServerName = 'secrets'
$pkgSpec = "git+$Repo.git@main"

function Info($m) { Write-Host "  $m" -ForegroundColor Gray }
function Ok($m)   { Write-Host "  [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "  [x]  $m" -ForegroundColor Red }

function Get-JsoncText([string]$Path) {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return '{}' }
    # strip // and /* */ comments, respecting strings
    $sb = New-Object System.Text.StringBuilder
    $inStr = $false; $esc = $false; $i = 0
    while ($i -lt $raw.Length) {
        $c = $raw[$i]
        if ($inStr) {
            [void]$sb.Append($c)
            if ($esc) { $esc = $false }
            elseif ($c -eq '\') { $esc = $true }
            elseif ($c -eq '"') { $inStr = $false }
            $i++
            continue
        }
        if ($c -eq '"') { $inStr = $true; [void]$sb.Append($c); $i++; continue }
        if ($c -eq '/' -and $i + 1 -lt $raw.Length -and $raw[$i + 1] -eq '/') {
            while ($i -lt $raw.Length -and $raw[$i] -ne "`n") { $i++ }
            continue
        }
        if ($c -eq '/' -and $i + 1 -lt $raw.Length -and $raw[$i + 1] -eq '*') {
            $i += 2
            while ($i + 1 -lt $raw.Length -and -not ($raw[$i] -eq '*' -and $raw[$i + 1] -eq '/')) { $i++ }
            $i += 2
            continue
        }
        [void]$sb.Append($c); $i++
    }
    $txt = $sb.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($txt)) { return '{}' }
    return $txt
}

function Read-JsonObject([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $txt = Get-JsoncText $Path
        return $txt | ConvertFrom-Json
    } catch {
        throw "could not parse $Path : $($_.Exception.Message)"
    }
}

function Backup-Config([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    Copy-Item -LiteralPath $Path -Destination "$Path.$stamp.bak" -Force
}

function Write-JsonObject([string]$Path, $Obj) {
    Backup-Config $Path
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Obj | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------- agents ---
# kind: opencode | mcpServers | vscode | zed | codex
function Get-Agents {
    $h = $env:USERPROFILE
    $app = $env:APPDATA
    $loc = $env:LOCALAPPDATA

    @(
        @{ Id='opencode'; Name='OpenCode'; Kind='opencode'
           Probe = @("$h\.config\opencode")
           Config = @("$h\.config\opencode\opencode.jsonc", "$h\.config\opencode\opencode.json") }

        @{ Id='openwork'; Name='OpenWork'; Kind='opencode'
           Probe = @("$app\openwork")
           Config = @("$app\openwork\runtime-opencode-config.json") }

        @{ Id='claude-desktop'; Name='Claude Desktop'; Kind='mcpServers'
           Probe = @("$app\Claude")
           Config = @("$app\Claude\claude_desktop_config.json") }

        @{ Id='claude-code'; Name='Claude Code'; Kind='mcpServers'
           Probe = @("$h\.claude", "$h\.claude.json")
           Config = @("$h\.claude.json") }

        @{ Id='cursor'; Name='Cursor'; Kind='mcpServers'
           Probe = @("$h\.cursor")
           Config = @("$h\.cursor\mcp.json") }

        @{ Id='windsurf'; Name='Windsurf'; Kind='mcpServers'
           Probe = @("$h\.codeium\windsurf")
           Config = @("$h\.codeium\windsurf\mcp_config.json") }

        @{ Id='vscode'; Name='VS Code'; Kind='vscode'
           Probe = @("$app\Code")
           Config = @("$app\Code\User\mcp.json") }

        @{ Id='gemini'; Name='Gemini CLI'; Kind='mcpServers'
           Probe = @("$h\.gemini")
           Config = @("$h\.gemini\settings.json") }

        @{ Id='codex'; Name='Codex CLI'; Kind='codex'
           Probe = @("$h\.codex")
           Config = @("$h\.codex\config.toml") }

        @{ Id='zed'; Name='Zed'; Kind='zed'
           Probe = @("$app\Zed", "$h\.config\zed")
           Config = @("$app\Zed\settings.json", "$h\.config\zed\settings.json") }

        @{ Id='openclaw'; Name='OpenClaw'; Kind='mcpServers'
           Probe = @("$h\.openclaw", "$app\openclaw")
           Config = @("$h\.openclaw\config.json") }
    )
}

function Resolve-Config($agent) {
    foreach ($p in $agent.Config) { if (Test-Path -LiteralPath $p) { return $p } }
    return $agent.Config[0]
}

function Test-Agent($agent) {
    foreach ($p in $agent.Probe) { if (Test-Path -LiteralPath $p) { return $true } }
    foreach ($p in $agent.Config) { if (Test-Path -LiteralPath $p) { return $true } }
    return $false
}

function Install-ForAgent($agent, [string]$Python) {
    $cfg = Resolve-Config $agent
    switch ($agent.Kind) {

        'opencode' {
            $obj = Read-JsonObject $cfg
            if ($null -eq $obj) { $obj = [pscustomobject]@{} }
            if (-not $obj.PSObject.Properties['mcp']) {
                $obj | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $entry = [pscustomobject]@{
                type    = 'local'
                command = @($Python, '-m', 'secrets_mcp')
                enabled = $true
            }
            $obj.mcp | Add-Member -NotePropertyName $ServerName -NotePropertyValue $entry -Force
            Write-JsonObject $cfg $obj
        }

        'mcpServers' {
            $obj = Read-JsonObject $cfg
            if ($null -eq $obj) { $obj = [pscustomobject]@{} }
            if (-not $obj.PSObject.Properties['mcpServers']) {
                $obj | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $entry = [pscustomobject]@{ command = $Python; args = @('-m', 'secrets_mcp') }
            $obj.mcpServers | Add-Member -NotePropertyName $ServerName -NotePropertyValue $entry -Force
            Write-JsonObject $cfg $obj
        }

        'vscode' {
            $obj = Read-JsonObject $cfg
            if ($null -eq $obj) { $obj = [pscustomobject]@{} }
            if (-not $obj.PSObject.Properties['servers']) {
                $obj | Add-Member -NotePropertyName servers -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $entry = [pscustomobject]@{ type = 'stdio'; command = $Python; args = @('-m', 'secrets_mcp') }
            $obj.servers | Add-Member -NotePropertyName $ServerName -NotePropertyValue $entry -Force
            Write-JsonObject $cfg $obj
        }

        'zed' {
            $obj = Read-JsonObject $cfg
            if ($null -eq $obj) { $obj = [pscustomobject]@{} }
            if (-not $obj.PSObject.Properties['context_servers']) {
                $obj | Add-Member -NotePropertyName context_servers -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $entry = [pscustomobject]@{ command = [pscustomobject]@{ path = $Python; args = @('-m', 'secrets_mcp') } }
            $obj.context_servers | Add-Member -NotePropertyName $ServerName -NotePropertyValue $entry -Force
            Write-JsonObject $cfg $obj
        }

        'codex' {
            $dir = Split-Path -Parent $cfg
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $existing = if (Test-Path -LiteralPath $cfg) { Get-Content -LiteralPath $cfg -Raw } else { '' }
            if ($existing -match "(?m)^\[mcp_servers\.$ServerName\]") {
                Ok "already present in $cfg"
                return
            }
            Backup-Config $cfg
            $safePy = $Python -replace '\\', '\\'
            $block = "`n[mcp_servers.$ServerName]`ncommand = `"$safePy`"`nargs = [""-m"", ""secrets_mcp""]`n"
            [System.IO.File]::AppendAllText($cfg, $block, (New-Object System.Text.UTF8Encoding($false)))
        }

        default { throw "unknown config kind: $($agent.Kind)" }
    }
    Ok "$($agent.Name)  ->  $cfg"
}

# ------------------------------------------------------------------ main ---
Write-Host ""
Write-Host "  secrets-mcp setup" -ForegroundColor White
Write-Host "  give the agent a handle, not the key" -ForegroundColor DarkGray
Write-Host ("  " + ('-' * 46)) -ForegroundColor DarkGray
Write-Host ""

$agents = Get-Agents
$found = @()
foreach ($a in $agents) { if (Test-Agent $a) { $found += $a } }

if ($found.Count -eq 0) {
    Warn "No supported agent found on this machine."
    Info "Supported: OpenCode, OpenWork, Claude Desktop, Claude Code, Cursor,"
    Info "           Windsurf, VS Code, Gemini CLI, Codex, Zed, OpenClaw"
    exit 1
}

Write-Host "  Detected agents:" -ForegroundColor White
for ($i = 0; $i -lt $found.Count; $i++) {
    $n = $i + 1
    Write-Host ("    [{0}] {1}" -f $n, $found[$i].Name)
}
Write-Host ""

if ($List) { exit 0 }

$pick = @()
if ($All) {
    $pick = 1..$found.Count
} else {
    Write-Host "  Connect secrets-mcp to which agent(s)?" -ForegroundColor White
    Write-Host "  Enter numbers separated by commas, 'a' for all, or Ctrl+C to abort." -ForegroundColor Gray
    $answer = Read-Host "  >"
    if ($answer -match '^\s*a\s*$') { $pick = 1..$found.Count }
    else {
        foreach ($t in ($answer -split '[,\s]+' | Where-Object { $_ })) {
            $n = 0
            if ([int]::TryParse($t, [ref]$n) -and $n -ge 1 -and $n -le $found.Count) { $pick += $n }
            else { Warn "ignoring '$t'" }
        }
    }
}
if ($pick.Count -eq 0) { Warn "nothing selected"; exit 0 }

# --- dependencies -----------------------------------------------------------
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { Fail "Python 3.10+ is required. Install it from python.org and re-run."; exit 1 }
Ok "python: $python"

if (-not $NoDeps) {
    Info "installing secrets-mcp (this pulls the 'mcp' package, ~10s)..."
    & $python -m pip install --quiet --upgrade $pkgSpec
    if ($LASTEXITCODE -ne 0) { Fail "pip install failed"; exit 1 }
    Ok "secrets-mcp installed"
}

# --- write configs ----------------------------------------------------------
Write-Host ""
foreach ($n in $pick) {
    $a = $found[$n - 1]
    try { Install-ForAgent $a $python }
    catch { Fail "$($a.Name): $($_.Exception.Message)" }
}

Write-Host ""
Write-Host "  Done. Restart the agent(s) to load the server." -ForegroundColor Green
Write-Host ""
Info "Try this in chat:  'store this key: sk-ant-...'"
Info "The agent calls stage_secret and keeps only {{anthropic}}."
Write-Host ""
Info "Vault: $env:APPDATA\secrets-mcp\vault.json  (DPAPI-encrypted)"
Info "Docs:  $Repo"
