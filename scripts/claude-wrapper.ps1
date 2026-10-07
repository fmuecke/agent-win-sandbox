# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox
<#
.SYNOPSIS
    Installs, updates, and launches Claude Code on Windows.

.DESCRIPTION
    Use this script instead of calling `claude` directly. It sets environment
    variables for the Claude process, checks for the native Claude executable,
    offers to install it when absent, and updates it before launch.

.EXAMPLE
    .\claude-wrapper.ps1
    .\claude-wrapper.ps1 --resume
    .\claude-wrapper.ps1 -SkipUpdate --help
#>
[CmdletBinding()]
param(
    [switch]$SkipUpdate,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ClaudeArguments
)

$ErrorActionPreference = 'Stop'

function Get-ClaudeExecutable {
    # Current native installer location; retain this fallback in case the PATH
    # was not refreshed after installation. Prefer it over any machine-wide
    # copy that may also be on PATH.
    $fallback = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
    if (Test-Path -LiteralPath $fallback -PathType Leaf) {
        return $fallback
    }

    $command = Get-Command claude -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
    if ($null -ne $command) {
        return $command.Source
    }
    return $null
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Agent Sandbox requires PowerShell 7 or later.'
}
if ($env:USERNAME -ne 'AgentSandbox') {
    throw "Refusing to run: expected user 'AgentSandbox' but running as '$env:USERNAME'."
}

$claude = Get-ClaudeExecutable
if ($null -eq $claude) {
    $answer = Read-Host 'Claude Code is not installed. Download and install it now? [y/N]'
    if ($answer -notmatch '^[Yy](es)?$') {
        Write-Host 'Aborted.'
        exit 0
    }

    Write-Host 'Installing Claude Code...'
    # Official Anthropic Windows installer. Run it in this process so the
    # installer can update PATH before we resolve Claude again.
    Invoke-RestMethod 'https://claude.ai/install.ps1' | Invoke-Expression
    $claude = Get-ClaudeExecutable

    if ($null -eq $claude) {
        throw 'Claude Code installation finished, but claude.exe was not found. Open a new PowerShell window and run this wrapper again.'
    }
}

if (-not $SkipUpdate) {
    Write-Host 'Checking Claude Code for updates...'
    try {
        & $claude update
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Claude Code update failed (exit code $LASTEXITCODE). Launching the installed version."
        }
    }
    catch {
        Write-Warning "Claude Code update failed: $($_.Exception.Message). Launching the installed version."
    }

    # An update can replace the executable; resolve it once more before launch.
    $updatedClaude = Get-ClaudeExecutable
    if ($null -ne $updatedClaude) {
        $claude = $updatedClaude
    }
}

$previousPowerShellTool = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_USE_POWERSHELL_TOOL', 'Process')
$previousNonessentialTraffic = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'Process')
try {
    # Settings apply only to Claude and programs it starts.
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = '1'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    & $claude @ClaudeArguments
    $claudeExitCode = $LASTEXITCODE
}
finally {
    if ($null -eq $previousPowerShellTool) {
        Remove-Item Env:CLAUDE_CODE_USE_POWERSHELL_TOOL -ErrorAction SilentlyContinue
    }
    else {
        $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = $previousPowerShellTool
    }
    if ($null -eq $previousNonessentialTraffic) {
        Remove-Item Env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC -ErrorAction SilentlyContinue
    }
    else {
        $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = $previousNonessentialTraffic
    }
}

exit $claudeExitCode
