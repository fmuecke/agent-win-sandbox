# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

# Initializes a plain PowerShell session as AgentSandbox. It deliberately does
# not enter the Visual Studio Developer Shell or start an agent.
#Requires -Version 7.0
$Version = '0.9.1'
# Not %ProgramData%: AgentSandbox can redirect its own environment variables.
$ProgramDataRoot = Join-Path ([IO.Path]::GetPathRoot([Environment]::SystemDirectory)) 'ProgramData\agent-win-sandbox'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$BootstrapRoot = Join-Path $ProgramDataRoot 'bootstrap'
$DevShellScript = Join-Path $BootstrapRoot 'Enter-DevShell.ps1'
$ClaudeWrapper = Join-Path $BootstrapRoot 'claude-wrapper.ps1'
$CopilotWrapper = Join-Path $BootstrapRoot 'copilot-wrapper.ps1'
$CheckScript = Join-Path $ProgramDataRoot 'Check-AgentSandbox.ps1'
$ExposureCheckScript = Join-Path $ProgramDataRoot 'Test-AgentSandboxExposure.ps1'
$WfpLockExe = Join-Path $ProgramDataRoot 'wfp-lock.exe'
$ConfigFunctionsScript = Join-Path $BootstrapRoot 'AgentSandboxConfig.ps1'

function Stop-ShellInitialization {
    param([string]$Message)

    Write-Host $Message -ForegroundColor Red
    Write-Host 'An administrator must run Apply-Config.ps1 or Setup-AgentSandbox.ps1 again.' -ForegroundColor Yellow
    Read-Host 'Press Enter to close'
    # The shell runs with -NoExit; 'exit' would leave an interactive prompt open.
    [Environment]::Exit(1)
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
foreach ($required in $ConfigFile, $ConfigFunctionsScript) {
    if (-not (Test-Path $required -PathType Leaf)) {
        Stop-ShellInitialization "Sandbox config missing: $required"
    }
}

try {
    . $ConfigFunctionsScript
    $settings = Get-AgentSandboxSettings -Config (Read-AgentSandboxConfig -Path $ConfigFile)
    $null = Test-AgentSandboxSettings -Settings $settings
    $SandboxPath = $settings.workspace
    $ProxyPort = [int]$settings.proxy.port
    $lockEndpoints = Get-AgentSandboxLockEndpoints -Settings $settings
}
catch {
    Stop-ShellInitialization "Sandbox config is invalid: $($_.Exception.Message)"
}

# Verify the network lock before anything else uses the session.
if (-not (Test-Path $WfpLockExe -PathType Leaf)) {
    Stop-ShellInitialization "Network lock is missing: $WfpLockExe"
}
& $WfpLockExe verify --user AgentSandbox --allow $lockEndpoints
if ($LASTEXITCODE -ne 0) {
    Stop-ShellInitialization 'Network lock verification failed.'
}

if ([string]::IsNullOrWhiteSpace($SandboxPath) -or -not (Test-Path $SandboxPath)) {
    Stop-ShellInitialization "Sandbox path is missing or does not exist: $SandboxPath"
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
    $installedRoot = Join-Path ([IO.Path]::GetPathRoot([Environment]::SystemDirectory)) 'ProgramData\agent-win-sandbox'
    $installedConfig = Get-Content (Join-Path $installedRoot 'config.json') -Raw | ConvertFrom-Json
    & (Join-Path $installedRoot 'Test-AgentSandboxExposure.ps1') -SandboxPath $installedConfig.workspace @args
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
