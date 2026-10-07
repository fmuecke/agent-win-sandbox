# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

# Initializes a plain PowerShell session as AgentSandbox. It deliberately does
# not enter the Visual Studio Developer Shell or start an agent.
#Requires -Version 7.0
$Version = '0.9.0'
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$BootstrapRoot = Join-Path $ProgramDataRoot 'bootstrap'
$DevShellScript = Join-Path $BootstrapRoot 'Enter-DevShell.ps1'
$ClaudeWrapper = Join-Path $BootstrapRoot 'claude-wrapper.ps1'
$CopilotWrapper = Join-Path $BootstrapRoot 'copilot-wrapper.ps1'
$CheckScript = Join-Path $ProgramDataRoot 'Check-AgentSandbox.ps1'
$ExposureCheckScript = Join-Path $ProgramDataRoot 'Test-AgentSandboxExposure.ps1'
$WfpLockExe = Join-Path $ProgramDataRoot 'wfp-lock.exe'

function Stop-ShellInitialization {
    param([string]$Message)

    Write-Host $Message -ForegroundColor Red
    Write-Host 'Run Setup-AgentSandbox.ps1 again.' -ForegroundColor Yellow
    exit 1
}

function Set-AgentSandboxWindowTitle {
    try {
        $Host.UI.RawUI.WindowTitle = 'Agent Sandbox'
    }
    catch {
        # Some non-console hosts do not expose a mutable window title.
    }
}

function Add-UserLocalBinToPath {
    $localBin = Join-Path $env:USERPROFILE '.local\bin'
    $localBinFull = [System.IO.Path]::GetFullPath($localBin).TrimEnd('\')
    $localBinOnPath = @($env:PATH -split ';') | Where-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            $false
        }
        else {
            try {
                [System.IO.Path]::GetFullPath($_).TrimEnd('\') -ieq $localBinFull
            }
            catch {
                $_.TrimEnd('\') -ieq $localBinFull
            }
        }
    }

    if (-not $localBinOnPath) {
        $env:PATH = if ([string]::IsNullOrWhiteSpace($env:PATH)) {
            $localBin
        }
        else {
            "$localBin;$env:PATH"
        }
    }
}

function Write-SandboxNetworkExposureWarning {
    $mappedDrives = @()
    try {
        $mappedDrives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop |
            Where-Object { $_.DisplayRoot -like '\\*' })
    }
    catch {
        $mappedDrives = @()
    }

    $persistentMappings = @()
    try {
        if (Test-Path 'HKCU:\Network') {
            $persistentMappings = @(Get-ChildItem -Path 'HKCU:\Network' -ErrorAction Stop | ForEach-Object {
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                    [pscustomobject]@{
                        Drive      = "$($_.PSChildName):"
                        RemotePath = [string]$props.RemotePath
                        UserName   = [string]$props.UserName
                    }
                })
        }
    }
    catch {
        $persistentMappings = @()
    }

    $networkShortcuts = @()
    $shortcutDir = Join-Path $env:APPDATA 'Microsoft\Windows\Network Shortcuts'
    try {
        if (Test-Path $shortcutDir) {
            $networkShortcuts = @(Get-ChildItem -Path $shortcutDir -Force -ErrorAction Stop)
        }
    }
    catch {
        $networkShortcuts = @()
    }

    if ((-not $mappedDrives) -and (-not $persistentMappings) -and (-not $networkShortcuts)) {
        return
    }

    Write-Host 'Warning: this sandbox profile has network access hints.' -ForegroundColor Yellow
    Write-Host 'Review these before starting an agent if this machine is domain joined.' -ForegroundColor Yellow

    foreach ($drive in $mappedDrives) {
        Write-Host "  mapped drive $($drive.Name): -> $($drive.DisplayRoot)" -ForegroundColor Yellow
    }
    foreach ($mapping in $persistentMappings) {
        $asUser = if ([string]::IsNullOrWhiteSpace($mapping.UserName)) {
            'default credentials'
        }
        else {
            $mapping.UserName
        }
        Write-Host "  persistent drive $($mapping.Drive) -> $($mapping.RemotePath) ($asUser)" -ForegroundColor Yellow
    }
    foreach ($shortcut in $networkShortcuts) {
        Write-Host "  network shortcut $($shortcut.Name)" -ForegroundColor Yellow
    }
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Stop-ShellInitialization 'Agent Sandbox requires PowerShell 7 or later.'
}
if ($env:USERNAME -ne 'AgentSandbox') {
    Stop-ShellInitialization "Refusing to run: expected user 'AgentSandbox' but running as '$env:USERNAME'."
}
if (-not (Test-Path $ConfigFile)) {
    Stop-ShellInitialization "Sandbox config missing: $ConfigFile"
}

try {
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $SandboxPath = $config.sandboxPath
    $ProxyPort = [int]$config.setup.proxyPort
}
catch {
    Stop-ShellInitialization "Sandbox config is invalid: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($SandboxPath) -or -not (Test-Path $SandboxPath)) {
    Stop-ShellInitialization "Sandbox path is missing or does not exist: $SandboxPath"
}
if ($ProxyPort -lt 1 -or $ProxyPort -gt 65535) {
    Stop-ShellInitialization 'Sandbox proxy port is missing or invalid.'
}
if (-not (Test-Path $WfpLockExe -PathType Leaf)) {
    Stop-ShellInitialization "Network lock is missing: $WfpLockExe"
}
& $WfpLockExe verify --user AgentSandbox --port $ProxyPort
if ($LASTEXITCODE -ne 0) {
    Stop-ShellInitialization 'Network lock verification failed.'
}

foreach ($commandScript in @($DevShellScript, $ClaudeWrapper, $CopilotWrapper, $CheckScript, $ExposureCheckScript)) {
    if (-not (Test-Path $commandScript -PathType Leaf)) {
        Stop-ShellInitialization "Sandbox command missing: $commandScript"
    }
}

Set-AgentSandboxWindowTitle
Set-Location $SandboxPath
Add-UserLocalBinToPath
$proxyUri = "http://127.0.0.1:$ProxyPort"
$env:HTTP_PROXY = $proxyUri
$env:HTTPS_PROXY = $proxyUri
Write-SandboxNetworkExposureWarning

Set-Alias -Name devshell -Value $DevShellScript -Scope Global
Set-Alias -Name claude -Value $ClaudeWrapper -Scope Global
Set-Alias -Name copilot -Value $CopilotWrapper -Scope Global
Set-Alias -Name sandbox-check -Value $CheckScript -Scope Global

function global:Invoke-SandboxExposure {
    $installedRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
    $installedConfig = Get-Content (Join-Path $installedRoot 'config.json') -Raw | ConvertFrom-Json
    & (Join-Path $installedRoot 'Test-AgentSandboxExposure.ps1') -SandboxPath $installedConfig.sandboxPath @args
}
Set-Alias -Name sandbox-exposure -Value Invoke-SandboxExposure -Scope Global

function global:sandbox-help {
    Write-Host @'
Agent Sandbox commands:
  sandbox-check  Check the sandbox configuration
  sandbox-exposure  Assess this session's exposure with the workspace path
  sandbox-help   Show this help
  devshell       Enter the Visual Studio Developer Shell in this terminal
  claude         Install, update, or launch Claude Code
  copilot        Install, update, or launch GitHub Copilot CLI
'@ -ForegroundColor Cyan
}

Write-Host "Agent Sandbox $Version" -ForegroundColor Cyan
Write-Host "Running as: $env:USERNAME" -ForegroundColor Green
Write-Host "Workspace: $SandboxPath" -ForegroundColor Green
Write-Host ''
sandbox-help
Write-Host ''
