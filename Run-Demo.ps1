# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0
<#
.SYNOPSIS
    Opens a disposable Windows Sandbox with this Agent Sandbox version installed.
.DESCRIPTION
    Packages the files beside this script, maps the package and the current
    PowerShell 7 runtime read-only, and provisions AgentSandbox inside the guest.
    Leaves the guest open for exploration. No host account or policy is changed.
.PARAMETER PrepareOnly
    Creates the package and .wsb configuration without opening Windows Sandbox.
.EXAMPLE
    .\Run-Demo.ps1
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 65535)][int]$ProxyPort = 8080,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist\demo-runs'),
    [switch]$PrepareOnly
)

$ErrorActionPreference = 'Stop'

# --- Host prerequisites -------------------------------------------------------
$pwshRoot = $PSHOME
if (-not (Test-Path -LiteralPath (Join-Path $pwshRoot 'pwsh.exe') -PathType Leaf)) {
    throw 'Run the demo from Windows PowerShell 7 (pwsh.exe).'
}
if (-not $PrepareOnly) {
    $sandboxCommand = Get-Command WindowsSandbox.exe -ErrorAction Stop
    $wsbCommand = Get-Command wsb.exe -ErrorAction SilentlyContinue
    if ($wsbCommand) {
        $running = & $wsbCommand.Source --raw list | Out-String | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or $null -eq $running.WindowsSandboxEnvironments) {
            throw 'Could not determine whether Windows Sandbox is occupied.'
        }
        if (@($running.WindowsSandboxEnvironments).Count -gt 0) {
            throw 'A Windows Sandbox is already running. Close it before starting the demo.'
        }
    }
    elseif (Get-Process -Name WindowsSandbox, WindowsSandboxClient -ErrorAction SilentlyContinue) {
        throw 'A Windows Sandbox is already running. Close it before starting the demo.'
    }
}

# --- Read-only demo inputs ----------------------------------------------------
$runDirectory = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
& (Join-Path $PSScriptRoot 'Package-Release.ps1') -OutputDirectory $runDirectory
$archive = @(Get-ChildItem -LiteralPath $runDirectory -Filter 'agent-win-sandbox-v*.zip' -File)
if ($archive.Count -ne 1) { throw 'Expected exactly one Agent Sandbox demo package.' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'bootstrap\Initialize-AgentSandboxDemo.ps1') -Destination $runDirectory

$guestCommand = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\AgentSandboxDemoSource\Initialize-AgentSandboxDemo.ps1" -ArchiveName "{0}" -ProxyPort {1}' -f $archive[0].Name, $ProxyPort
$hostSourceXml = [Security.SecurityElement]::Escape($runDirectory)
$hostPowerShellXml = [Security.SecurityElement]::Escape($pwshRoot)
$guestCommandXml = [Security.SecurityElement]::Escape($guestCommand)
$configurationPath = Join-Path $runDirectory 'AgentSandbox-Demo.wsb'
@"
<Configuration>
    <vGPU>Disable</vGPU>
    <Networking>Enable</Networking>
    <AudioInput>Disable</AudioInput>
    <VideoInput>Disable</VideoInput>
    <PrinterRedirection>Disable</PrinterRedirection>
    <ClipboardRedirection>Disable</ClipboardRedirection>
    <MemoryInMB>4096</MemoryInMB>
    <MappedFolders>
        <MappedFolder>
            <HostFolder>$hostSourceXml</HostFolder>
            <SandboxFolder>C:\AgentSandboxDemoSource</SandboxFolder>
            <ReadOnly>true</ReadOnly>
        </MappedFolder>
        <MappedFolder>
            <HostFolder>$hostPowerShellXml</HostFolder>
            <SandboxFolder>C:\AgentSandboxDemoPowerShell</SandboxFolder>
            <ReadOnly>true</ReadOnly>
        </MappedFolder>
    </MappedFolders>
    <LogonCommand><Command>$guestCommandXml</Command></LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath $configurationPath -Encoding utf8NoBOM

Write-Host "Demo configuration: $configurationPath" -ForegroundColor Cyan
if (-not $PrepareOnly) {
    # Open the interactive demo window.
    Start-Process -FilePath $sandboxCommand.Source -ArgumentList "`"$configurationPath`"" | Out-Null
    Write-Host 'Setup runs inside the guest. Be patient - full startup may take some time. Close Windows Sandbox when you finish exploring. ' -ForegroundColor Cyan
}
