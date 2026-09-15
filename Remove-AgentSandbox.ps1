# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the local AgentSandbox account and agent-win-sandbox ProgramData
    state.

.DESCRIPTION
    This is the teardown counterpart to Setup-AgentSandbox.ps1. It removes the
    fixed AgentSandbox local user, that user's Windows profile, account-scoped
    firewall rules, the hidden-login-screen registry value, generated
    ProgramData files under the agent-win-sandbox ProgramData directory, and the
    Public Desktop shortcut.

    It deliberately does NOT delete or modify the shared sandbox workspace
    directory. Delete the workspace manually if it is no longer needed.

.PARAMETER Force
    Skip the interactive confirmation prompt.

.EXAMPLE
    .\Remove-AgentSandbox.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$UserName = 'AgentSandbox'   # baked in; not configurable
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'    # baked in; not configurable
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$LaunchAsAdminExe = Join-Path (Join-Path $env:ProgramFiles 'launch-as') 'launch-as-admin.exe'
$LegacyLaunchAsAdminExe = Join-Path $ProgramDataRoot 'launch-as-admin.exe'
$LegacyLaunchAsExe = Join-Path $ProgramDataRoot 'launch-as.exe'
$LaunchAsVersion = 'v1.2.0-preview'
$SupportedLaunchAsVersions = @('v1.0.0-preview', 'v1.1.0-preview', 'v1.1.0', 'v1.2.0-preview')
$ShortcutPaths = @(
    (Join-Path (Join-Path $env:PUBLIC 'Desktop') 'Agent Sandbox.lnk')
)
$FirewallRuleGroup = 'agent-win-sandbox'

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

function Stop-IfLegacyInstallationPresent {
    $hasConfig = Test-Path -LiteralPath $ConfigFile -PathType Leaf
    $hasInstalledClient = Test-Path -LiteralPath (Join-Path (Join-Path $env:ProgramFiles 'launch-as') 'launch-as.exe') -PathType Leaf
    $hasLegacyClient = Test-Path -LiteralPath $LegacyLaunchAsExe -PathType Leaf
    $hasUser = $null -ne (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)

    if (-not $hasConfig -and -not $hasLegacyClient -and -not $hasUser) {
        return
    }
    if (-not $hasConfig -or (-not $hasInstalledClient -and -not $hasLegacyClient)) {
        throw "A legacy or incomplete Agent Sandbox installation was found. This removal script supports only launch-as $LaunchAsVersion and will not alter the account or files. Uninstall the matching earlier Agent Sandbox version first."
    }

    try {
        $installedConfig = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
        $installedVersion = [string]$installedConfig.setup.launchAsVersion
    }
    catch {
        throw "An unreadable Agent Sandbox installation was found. This removal script will not alter it. Uninstall the matching earlier Agent Sandbox version first."
    }

    if ($installedVersion -notin $SupportedLaunchAsVersions) {
        throw "Agent Sandbox uses launch-as '$installedVersion'. This removal script supports only launch-as $LaunchAsVersion and will not alter it. Uninstall the matching earlier Agent Sandbox version first."
    }
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
    foreach ($shortcutPath in $ShortcutPaths) {
        if (-not (Test-Path $shortcutPath)) {
            Write-Skipped "desktop shortcut ($shortcutPath not found)"
            continue
        }

        if ($PSCmdlet.ShouldProcess($shortcutPath, 'Remove desktop shortcut')) {
            Remove-Item -LiteralPath $shortcutPath -Force
            Write-Removed "desktop shortcut: $shortcutPath"
        }
    }
}

# --- 0. Resolve current state -------------------------------------------------
Stop-IfLegacyInstallationPresent
$ResolvedSandboxPath = Get-ConfiguredSandboxPath
$user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
$sid = if ($user) { $user.SID.Value } else { $null }
$profile = if ($sid) {
    Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
}
else {
    $null
}

function Test-BrokerManagedSandbox {
    if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
        return $false
    }

    try {
        $config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
        return [string]$config.setup.launchAsVersion -in $SupportedLaunchAsVersions
    }
    catch {
        Write-Warning "Could not read launch-as version from ${ConfigFile}: $($_.Exception.Message)"
        return $false
    }
}

function Get-ConfiguredLaunchAsVersion {
    $config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
    return [string]$config.setup.launchAsVersion
}

function Get-LaunchAsAdminExecutable {
    if (Test-Path -LiteralPath $LaunchAsAdminExe -PathType Leaf) {
        return $LaunchAsAdminExe
    }
    if (Test-Path -LiteralPath $LegacyLaunchAsAdminExe -PathType Leaf) {
        return $LegacyLaunchAsAdminExe
    }

    throw "launch-as broker administration tool is missing: $LaunchAsAdminExe. Refusing to delete broker-managed '$UserName' without unenrolling it."
}

function Unenroll-SandboxBrokerAccount {
    if (-not (Test-BrokerManagedSandbox)) {
        return
    }
    $launchAsAdmin = Get-LaunchAsAdminExecutable
    $installedVersion = Get-ConfiguredLaunchAsVersion

    if ($PSCmdlet.ShouldProcess("broker-managed account '$UserName'", 'Unenroll')) {
        if ($installedVersion -eq 'v1.0.0-preview') {
            & $launchAsAdmin unenroll $UserName --force
        }
        else {
            & $launchAsAdmin forget $UserName
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Could not unenroll broker-managed '$UserName' (exit code $LASTEXITCODE)."
        }
        Write-Removed "launch-as broker enrollment for '$UserName'"
    }
}

if ($profile -and $profile.Loaded) {
    Write-Host "Cannot remove '$UserName' while its profile is loaded: $($profile.LocalPath)" -ForegroundColor Red
    Write-Host 'Close all Agent Sandbox terminals and retry.' -ForegroundColor Yellow
    exit 1
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
Write-Host "  shortcuts: $($ShortcutPaths -join ', ')"
if ([string]::IsNullOrWhiteSpace($ResolvedSandboxPath)) {
    Write-Host "  workspace: unknown (not modified by this script)" -ForegroundColor Yellow
}
else {
    Write-Host "  workspace: $ResolvedSandboxPath (not modified by this script)" -ForegroundColor Yellow
}

if (-not $Force -and -not $WhatIfPreference) {
    Write-Host ''
    Write-Host 'This removes the sandbox user, its Windows profile, per-user agent installs/settings, ProgramData state, and shortcuts.' -ForegroundColor Yellow
    Write-Host 'The shared workspace directory and its ACLs are left intact for manual review.' -ForegroundColor Yellow
    Write-Host ''
    $answer = Read-Host "Type REMOVE to continue"
    if ($answer -ne 'REMOVE') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 1
    }
}

# --- 1. Unenroll the broker-managed account ----------------------------------
Write-Step "Unenrolling broker-managed account '$UserName'"
Unenroll-SandboxBrokerAccount

# --- 2. Remove account-scoped hardening artifacts ----------------------------
Write-Step "Removing account-scoped firewall rules"
Remove-SandboxFirewallRules

Write-Step "Removing login-screen hiding entry"
Remove-SandboxLoginScreenEntry

# --- 3. Remove launcher shortcut ---------------------------------------------
Write-Step "Removing desktop shortcut"
Remove-SandboxShortcut

# --- 4. Remove sandbox user profile ------------------------------------------
Write-Step "Removing user profile for '$UserName'"
if (-not $profile) {
    Write-Skipped "user profile (not found)"
}
elseif ($PSCmdlet.ShouldProcess("user profile '$($profile.LocalPath)'", 'Remove')) {
    $profile | Remove-CimInstance
    Write-Removed "user profile: $($profile.LocalPath)"
}

# --- 5. Remove the local sandbox user ----------------------------------------
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

# --- 6. Remove generated ProgramData files -----------------------------------
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

# --- 7. Done ------------------------------------------------------------------
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
