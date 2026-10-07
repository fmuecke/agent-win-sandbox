# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 5.1
#Requires -RunAsAdministrator
# Guest-only Windows Sandbox logon command. Uses 5.1 to bootstrap PowerShell 7.
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^agent-win-sandbox-v\d+\.\d+\.\d+\.zip$')]
    [string]$ArchiveName,
    [ValidateRange(1, 65535)][int]$ProxyPort = 8080
)

$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount') {
    throw 'This bootstrap is only for the interactive Windows Sandbox demo account.'
}

Start-Transcript -Path 'C:\AgentSandboxDemo.log' -Force | Out-Null
try {
    # Copy the read-only mapped runtime into the guest's protected tool location.
    $pwshRoot = Join-Path $env:ProgramFiles 'PowerShell\7'
    New-Item -ItemType Directory -Path $pwshRoot -Force | Out-Null
    Copy-Item -Path 'C:\AgentSandboxDemoPowerShell\*' -Destination $pwshRoot -Recurse -Force
    $pwsh = Join-Path $pwshRoot 'pwsh.exe'
    $setupRoot = Join-Path $env:ProgramFiles 'AgentSandboxDemo'
    Expand-Archive -LiteralPath (Join-Path $PSScriptRoot $ArchiveName) -DestinationPath $setupRoot

    # A fresh guest has no existing policy: accept the optional managed settings.
    $setupInput = Join-Path $env:TEMP 'AgentSandboxDemo-input.txt'
    Set-Content -LiteralPath $setupInput -Value 'y' -Encoding ascii
    $setup = Join-Path $setupRoot 'Setup-AgentSandbox.ps1'
    try {
        Write-Host 'Installing Agent Sandbox inside the guest; downloads may take a minute...' -ForegroundColor Cyan
        $setupProcess = Start-Process -FilePath $pwsh -NoNewWindow -PassThru `
            -ArgumentList "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$setup`" -SandboxPath C:\AgentSandbox -ProxyPort $ProxyPort" `
            -RedirectStandardInput $setupInput -RedirectStandardOutput 'C:\AgentSandboxDemo-setup.log' `
            -RedirectStandardError 'C:\AgentSandboxDemo-setup-error.log'
        # The proxy intentionally outlives setup. Wait for the installer itself;
        # Start-Process -Wait also waits for its background descendants.
        $null = $setupProcess.Handle
        if (-not $setupProcess.WaitForExit(600000)) {
            Stop-Process -Id $setupProcess.Id -Force -ErrorAction SilentlyContinue
            throw 'Guest setup did not finish within ten minutes.'
        }
        Get-Content -LiteralPath 'C:\AgentSandboxDemo-setup.log' | ForEach-Object { Write-Host $_ }
        Get-Content -LiteralPath 'C:\AgentSandboxDemo-setup-error.log' | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        if ($setupProcess.ExitCode -ne 0) { throw "Guest setup failed with exit code $($setupProcess.ExitCode)." }
    }
    finally {
        Remove-Item -LiteralPath $setupInput -Force
    }

    Write-Host 'Demo configured. Try sandbox-exposure, claude, or copilot in the AgentSandbox console.' -ForegroundColor Cyan
    Write-Host 'Git and Visual Studio are not preinstalled in this fresh guest.' -ForegroundColor Yellow
    $launcher = Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'Start-AgentSandbox.ps1'
    # The Sandbox logon command has a hidden console. Open a separate visible
    # console so the initial broker session is available on the guest desktop.
    Start-Process -FilePath $pwsh -WindowStyle Normal `
        -ArgumentList "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$launcher`"" | Out-Null
    Set-Content -LiteralPath 'C:\AgentSandboxDemo.ready' -Value 'Configured' -Encoding ascii
}
catch {
    Write-Host "Demo failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Diagnostics: C:\AgentSandboxDemo.log' -ForegroundColor Yellow
    Read-Host 'Press Enter to close this console'
    exit 1
}
finally {
    Stop-Transcript | Out-Null
}
