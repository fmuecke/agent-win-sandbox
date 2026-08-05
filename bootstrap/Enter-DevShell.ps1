# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

# Enters the Visual Studio Developer Shell in the current Agent Sandbox terminal.
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Agent Sandbox requires PowerShell 7 or later.'
}
if ($env:USERNAME -ne 'AgentSandbox') {
    throw "Refusing to run: expected user 'AgentSandbox' but running as '$env:USERNAME'."
}
if (-not (Test-Path $ConfigFile)) {
    throw "Sandbox config missing: $ConfigFile"
}

$config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
$SandboxPath = $config.sandboxPath
if ([string]::IsNullOrWhiteSpace($SandboxPath) -or -not (Test-Path $SandboxPath)) {
    throw "Sandbox path is missing or does not exist: $SandboxPath"
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere -PathType Leaf)) {
    throw "Visual Studio locator not found: $vswhere"
}

$vs = & $vswhere -latest -format json | ConvertFrom-Json
if ($null -eq $vs -or [string]::IsNullOrWhiteSpace($vs.installationPath)) {
    throw 'No Visual Studio installation was found.'
}

$devShellModule = Join-Path $vs.installationPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
Import-Module $devShellModule -ErrorAction Stop
Enter-VsDevShell -VsInstanceId $vs.instanceId -SkipAutomaticLocation -DevCmdArguments '-arch=x64'
Set-Location $SandboxPath

try {
    $Host.UI.RawUI.WindowTitle = 'Agent Sandbox - Developer Shell'
}
catch {
    # Some non-console hosts do not expose a mutable window title.
}

Write-Host 'Visual Studio Developer Shell active.' -ForegroundColor Cyan
