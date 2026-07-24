#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the local ClaudeSandbox account and claude-win-sandbox ProgramData
    state.

.DESCRIPTION
    This is the teardown counterpart to Setup-ClaudeSandbox.ps1. It removes the
    fixed ClaudeSandbox local user, that user's Windows profile, account-scoped
    firewall rules, the hidden-login-screen registry value, generated
    ProgramData files under the claude-win-sandbox ProgramData directory, and the optional
    Public Desktop shortcut.

    It deliberately does NOT delete or modify the shared sandbox workspace
    directory. Delete the workspace manually if it is no longer needed.

.PARAMETER Force
    Skip the interactive confirmation prompt.

.EXAMPLE
    .\Remove-ClaudeSandbox.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$UserName = 'ClaudeSandbox'   # baked in; not configurable
$ProgramDataRoot = Join-Path $env:ProgramData 'claude-win-sandbox'    # baked in; not configurable
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$ShortcutPath = Join-Path (Join-Path $env:PUBLIC 'Desktop') 'Claude (sandboxed).lnk'
$FirewallRuleGroup = 'claude-win-sandbox'

function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Removed { param($m) Write-Host "  removed $m" -ForegroundColor Green }
function Write-Skipped { param($m) Write-Host "  skipped $m" -ForegroundColor Yellow }

function Get-ConfiguredSandboxPath {
    if (-not (Test-Path $ConfigFile)) {
        return $null
    }

    try {
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        if (-not [string]::IsNullOrWhiteSpace($config.sandboxPath)) {
            return [string]$config.sandboxPath
        }
    }
    catch {
        Write-Warning "Could not read sandbox path from ${ConfigFile}: $($_.Exception.Message)"
    }

    return $null
}

function Remove-SandboxFirewallRules {
    $rules = @(Get-NetFirewallRule -Group $FirewallRuleGroup -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        Write-Skipped "firewall rules (none found)"
        return
    }

    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess("firewall rule '$($rule.Name)'", 'Remove')) {
            Remove-NetFirewallRule -InputObject $rule
            Write-Removed "firewall rule: $($rule.DisplayName)"
        }
    }
}

function Remove-SandboxLoginScreenEntry {
    $ualPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if (-not (Test-Path $ualPath)) {
        Write-Skipped "hidden-login-screen registry cleanup (key not found)"
        return
    }

    $value = Get-ItemProperty -Path $ualPath -Name $UserName -ErrorAction SilentlyContinue
    if (-not $value) {
        Write-Skipped "hidden-login-screen registry cleanup (value not found)"
        return
    }

    if ($PSCmdlet.ShouldProcess("$ualPath\$UserName", 'Remove registry value')) {
        Remove-ItemProperty -Path $ualPath -Name $UserName
        Write-Removed "hidden-login-screen registry value"
    }
}

function Remove-SandboxShortcut {
    if (-not (Test-Path $ShortcutPath)) {
        Write-Skipped "desktop shortcut ($ShortcutPath not found)"
        return
    }

    if ($PSCmdlet.ShouldProcess($ShortcutPath, 'Remove desktop shortcut')) {
        Remove-Item -LiteralPath $ShortcutPath -Force
        Write-Removed "desktop shortcut: $ShortcutPath"
    }
}

# --- 0. Resolve current state -------------------------------------------------
$ResolvedSandboxPath = Get-ConfiguredSandboxPath
$user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
$sid = if ($user) { $user.SID.Value } else { $null }
$profile = if ($sid) {
    Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
}
else {
    $null
}

Write-Step "Removal target summary"
Write-Host "  user: $UserName"
if ($profile) {
    Write-Host "  profile: $($profile.LocalPath)"
}
else {
    Write-Host "  profile: not found" -ForegroundColor Yellow
}
Write-Host "  ProgramData: $ProgramDataRoot"
Write-Host "  shortcut: $ShortcutPath"
if ([string]::IsNullOrWhiteSpace($ResolvedSandboxPath)) {
    Write-Host "  workspace: unknown (not modified by this script)" -ForegroundColor Yellow
}
else {
    Write-Host "  workspace: $ResolvedSandboxPath (not modified by this script)" -ForegroundColor Yellow
}

if (-not $Force -and -not $WhatIfPreference) {
    Write-Host ''
    Write-Host 'This removes the sandbox user, its Windows profile, per-user Claude install/settings, ProgramData state, and shortcut.' -ForegroundColor Yellow
    Write-Host 'The shared workspace directory and its ACLs are left intact for manual review.' -ForegroundColor Yellow
    Write-Host ''
    $answer = Read-Host "Type REMOVE to continue"
    if ($answer -ne 'REMOVE') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 1
    }
}

# --- 1. Remove account-scoped hardening artifacts ----------------------------
Write-Step "Removing account-scoped firewall rules"
Remove-SandboxFirewallRules

Write-Step "Removing login-screen hiding entry"
Remove-SandboxLoginScreenEntry

# --- 2. Remove optional launcher shortcut ------------------------------------
Write-Step "Removing optional desktop shortcut"
Remove-SandboxShortcut

# --- 3. Remove sandbox user profile ------------------------------------------
Write-Step "Removing user profile for '$UserName'"
if (-not $profile) {
    Write-Skipped "user profile (not found)"
}
elseif ($profile.Loaded) {
    Write-Warning "Skipping user profile removal because it is currently loaded: $($profile.LocalPath)"
}
elseif ($PSCmdlet.ShouldProcess("user profile '$($profile.LocalPath)'", 'Remove')) {
    $profile | Remove-CimInstance
    Write-Removed "user profile: $($profile.LocalPath)"
}

# --- 4. Remove the local sandbox user ----------------------------------------
Write-Step "Removing local user '$UserName'"
if ($user) {
    if ($PSCmdlet.ShouldProcess("local user '$UserName'", 'Remove')) {
        Remove-LocalUser -Name $UserName
        Write-Removed "local user '$UserName'"
    }
}
else {
    Write-Skipped "local user '$UserName' (not found)"
}

# --- 5. Remove generated ProgramData files -----------------------------------
Write-Step "Removing ProgramData sandbox files"
if (Test-Path $ProgramDataRoot) {
    if ($PSCmdlet.ShouldProcess($ProgramDataRoot, 'Remove generated ProgramData files recursively')) {
        Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force
        Write-Removed $ProgramDataRoot
    }
}
else {
    Write-Skipped "$ProgramDataRoot (not found)"
}

# --- 6. Done ------------------------------------------------------------------
Write-Step "Removal complete"
$workspaceMessage = if ([string]::IsNullOrWhiteSpace($ResolvedSandboxPath)) {
    '  (unknown - config was missing or unreadable before ProgramData cleanup)'
}
else {
    "  $ResolvedSandboxPath"
}
Write-Host @"
The shared sandbox workspace was not deleted or modified:

$workspaceMessage

Delete that directory manually if it is no longer needed. It is a shared working
area, so this script leaves its contents and ACLs for human review.

"@ -ForegroundColor Cyan
