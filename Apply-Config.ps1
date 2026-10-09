# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -RunAsAdministrator
#Requires -Version 7.0
<#
.SYNOPSIS
    Applies the installed Agent Sandbox configuration to the network proxy
    policy and the AgentSandbox network lock.

.DESCRIPTION
    Part of agent-win-sandbox. Reads
    C:\ProgramData\agent-win-sandbox\config.json, validates it, regenerates
    the proxy policy, stops the running proxy, and replaces the wfp-lock policy
    with the proxy endpoint plus the configured directEndpoints. The launcher
    restarts the proxy as the launcher account on the next start.

    Setup calls this script. Run it yourself, elevated, after editing
    config.json; the launcher refuses to start until settings are applied.
    Close all AgentSandbox sessions first.

    Workspace changes are not applied here; run Setup-AgentSandbox.ps1.

.EXAMPLE
    & "$env:ProgramData\agent-win-sandbox\Apply-Config.ps1"
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$UserName = 'AgentSandbox'
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$WfpLockExe = Join-Path $ProgramDataRoot 'wfp-lock.exe'
$NetworkSandboxExe = Join-Path $ProgramDataRoot 'network-sandbox.exe'
$NetworkSandboxStateRoot = Join-Path $ProgramDataRoot 'network-sandbox'
$NetworkSandboxConfig = Join-Path $NetworkSandboxStateRoot 'network-sandbox.json'
$AdminFullAce = '*S-1-5-32-544:F'
$SystemFullAce = '*S-1-5-18:F'
$UsersReadExecuteAce = '*S-1-5-32-545:RX'

. (Join-Path (Join-Path $PSScriptRoot 'bootstrap') 'AgentSandboxConfig.ps1')

function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }

function Protect-AdminFile {
    param([string]$Path)

    icacls $Path /inheritance:r /grant:r $AdminFullAce $SystemFullAce $UsersReadExecuteAce | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not protect $Path." }
    icacls $Path /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set Administrators as owner of $Path." }
}

function Assert-NotLinked {
    param([string]$Path)

    if ((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path -Force).LinkType) {
        throw "Refusing to write linked file: $Path"
    }
}

# --- Pre-flight ---------------------------------------------------------------
foreach ($required in $ConfigFile, $WfpLockExe, $NetworkSandboxExe) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Missing $required. Run Setup-AgentSandbox.ps1 first."
    }
}
$sandboxUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $sandboxUser) { throw "User '$UserName' does not exist. Run Setup-AgentSandbox.ps1 first." }
$sandboxProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($sandboxUser.SID.Value)'"
if ($sandboxProfile -and $sandboxProfile.Loaded) {
    throw "Close all '$UserName' sessions before applying the configuration."
}

$config = Read-AgentSandboxConfig -Path $ConfigFile
$settings = Get-AgentSandboxSettings -Config $config
$warnings = Test-AgentSandboxSettings -Settings $settings
foreach ($warning in $warnings) { Write-Warning $warning }
$setup = $config['setup']
if ($setup -isnot [Collections.IDictionary]) {
    throw "Config has no setup section. Run Setup-AgentSandbox.ps1."
}
if ($settings.workspace -ne $setup['provisionedWorkspace']) {
    throw "workspace changed from '$($setup['provisionedWorkspace'])' to '$($settings.workspace)'. Run Setup-AgentSandbox.ps1 to provision a new workspace."
}
$proxyPort = [int]$settings.proxy.port
$lockEndpoints = Get-AgentSandboxLockEndpoints -Settings $settings

# --- Proxy policy -------------------------------------------------------------
# The launcher starts the proxy as the launcher account; a proxy started here
# would run with this elevated token.
Write-Step "Stopping the network proxy"
if (Test-Path -LiteralPath $NetworkSandboxConfig -PathType Leaf) {
    & $NetworkSandboxExe stop -config $NetworkSandboxConfig
    if ($LASTEXITCODE -ne 0) { throw 'Could not stop the network proxy.' }
}
$listeners = @(Get-NetTCPConnection -State Listen -LocalPort $proxyPort -ErrorAction SilentlyContinue)
if ($listeners.Count -gt 0) {
    throw "TCP port $proxyPort is in use (PID: $(($listeners.OwningProcess | Sort-Object -Unique) -join ', ')). Choose another proxy.port in $ConfigFile."
}

Write-Step "Writing proxy policy"
$policy = [ordered]@{
    port             = $proxyPort
    logfile          = Join-Path $NetworkSandboxStateRoot 'network-sandbox.log'
    loglevel         = 'info'
    privateaddresses = 'deny'
    allowed          = @($settings.proxy.allowedHosts)
}
Assert-NotLinked -Path $NetworkSandboxConfig
Set-Content -LiteralPath $NetworkSandboxConfig -Value ($policy | ConvertTo-Json -Depth 4) -Encoding utf8NoBOM -NoNewline
Protect-AdminFile -Path $NetworkSandboxConfig
foreach ($allowedHost in $settings.proxy.allowedHosts) {
    Write-Host "  proxy allows $allowedHost" -ForegroundColor Green
}

# --- Network lock -------------------------------------------------------------
Write-Step "Applying the network lock for '$UserName'"
& $WfpLockExe apply --user $UserName --allow $lockEndpoints
if ($LASTEXITCODE -ne 0) { throw "Could not apply wfp-lock for '$UserName'." }
& $WfpLockExe verify --user $UserName --allow $lockEndpoints
if ($LASTEXITCODE -ne 0) { throw "Could not verify wfp-lock for '$UserName'." }
Write-Host "  allowed 127.0.0.1:$proxyPort (proxy)" -ForegroundColor Green
foreach ($entry in $settings.directEndpoints) {
    Write-Host "  allowed $(ConvertTo-AgentSandboxEndpoint -Endpoint $entry.endpoint) ($($entry.label))" -ForegroundColor Green
}

# --- Record the applied settings ---------------------------------------------
$setup['appliedSettingsHash'] = Get-AgentSandboxSettingsHash -Config $config
$setup['appliedAtUtc'] = (Get-Date).ToUniversalTime().ToString('o')
Assert-NotLinked -Path $ConfigFile
Set-Content -LiteralPath $ConfigFile -Value ($config | ConvertTo-Json -Depth 10) -Encoding utf8NoBOM
Protect-AdminFile -Path $ConfigFile

Write-Step "Configuration applied"
Write-Host 'The launcher starts the proxy on the next Agent Sandbox start.'
