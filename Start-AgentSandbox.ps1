# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

<#
.SYNOPSIS
    Launches a PowerShell 7 terminal as the low-privilege AgentSandbox user,
    scoped to the workspace stored in ProgramData config.

.DESCRIPTION
    Part of agent-win-sandbox. Assumes Setup-AgentSandbox.ps1 has provisioned
    the low-priv user, sandbox ACLs, config, and shell initializer.

    Launch uses the bundled launch-as.exe helper. It starts an interactive
    console with the target user's token and uses Windows Credential UI to
    obtain or update the target account credential when required. The shell
    exposes commands for the Developer Shell, Claude Code, Copilot CLI, and the
    sandbox checker.

.EXAMPLE
    & "$env:ProgramData\agent-win-sandbox\Start-AgentSandbox.ps1"
    Launches an Agent Sandbox PowerShell terminal.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$UserName = 'AgentSandbox'
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
$ShellInitScript = Join-Path (Join-Path $ProgramDataRoot 'bootstrap') 'Initialize-AgentSandboxShell.ps1'
$LaunchAsExe = Join-Path $ProgramDataRoot 'launch-as.exe'
$CheckerScript = Join-Path $ProgramDataRoot 'Check-AgentSandbox.ps1'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$PwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'

function Stop-LauncherError {
    param([string]$Message)

    Write-Host $Message -ForegroundColor Red
    if (Test-Path $CheckerScript) {
        Write-Host "Verify setup with: & '$CheckerScript'" -ForegroundColor Yellow
    }
    Write-Host ""
    Read-Host 'Press Enter to close'
    exit 1
}

function Enable-CtrlBreakGuard {
    if (-not ('AgentSandboxCtrlBreakGuard' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AgentSandboxCtrlBreakGuard
{
    private const uint CtrlBreakEvent = 1;
    private const int StandardInput = -10;
    private const int StandardOutput = -11;
    private delegate bool HandlerRoutine(uint controlType);
    private static readonly HandlerRoutine Handler = Handle;
    private static uint originalInputMode;
    private static uint originalOutputMode;
    private static bool hasOriginalModes;
    private static bool installed;

    [DllImport("Kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("Kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("Kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleMode(IntPtr handle, uint mode);

    public static void Install()
    {
        IntPtr input = GetStdHandle(StandardInput);
        IntPtr output = GetStdHandle(StandardOutput);
        if (!GetConsoleMode(input, out originalInputMode) ||
            !GetConsoleMode(output, out originalOutputMode))
        {
            return;
        }
        hasOriginalModes = true;

        if (!SetConsoleCtrlHandler(Handler, true))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        installed = true;
    }

    public static void Remove()
    {
        if (installed)
        {
            SetConsoleCtrlHandler(Handler, false);
            installed = false;
        }
        if (hasOriginalModes)
        {
            SetConsoleMode(GetStdHandle(StandardInput), originalInputMode);
            SetConsoleMode(GetStdHandle(StandardOutput), originalOutputMode);
            hasOriginalModes = false;
        }
    }

    private static bool Handle(uint controlType)
    {
        return controlType == CtrlBreakEvent;
    }
}
'@
    }

    [AgentSandboxCtrlBreakGuard]::Install()
}

trap {
    Stop-LauncherError "Unexpected launcher error: $($_.Exception.Message)"
}

# --- Pre-flight checks --------------------------------------------------------
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    Stop-LauncherError "User '$UserName' does not exist. Run Setup-AgentSandbox.ps1 first."
}
if (-not (Test-Path $ShellInitScript)) {
    Stop-LauncherError "Shell initializer not found at $ShellInitScript. Run Setup-AgentSandbox.ps1 first."
}
if (-not (Test-Path $LaunchAsExe)) {
    Stop-LauncherError "launch-as not found at $LaunchAsExe. Run Setup-AgentSandbox.ps1 first."
}
if (-not (Test-Path $PwshExe -PathType Leaf)) {
    Stop-LauncherError "PowerShell 7 not found at $PwshExe. Install it machine-wide, then run setup again."
}
if (-not (Test-Path $ConfigFile)) {
    Stop-LauncherError "Config not found at $ConfigFile. Run Setup-AgentSandbox.ps1 first."
}
try {
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $sandboxPath = $config.sandboxPath
}
catch {
    Stop-LauncherError "Config at $ConfigFile is invalid: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($sandboxPath)) {
    Stop-LauncherError "Config at $ConfigFile does not define sandboxPath. Run Setup-AgentSandbox.ps1 again."
}
if (-not (Test-Path $sandboxPath)) {
    Stop-LauncherError "Sandbox path $sandboxPath does not exist. Run Setup-AgentSandbox.ps1 again."
}
Write-Host "Configured sandbox path: $sandboxPath" -ForegroundColor Cyan

# --- Launch -------------------------------------------------------------------
Write-Host "Launching Agent Sandbox as '$UserName' in $sandboxPath ..." -ForegroundColor Green
Write-Host '(Windows Credential UI appears if launch-as needs a credential.)' -ForegroundColor DarkGray

Enable-CtrlBreakGuard
try {
    & $LaunchAsExe `
        --user $UserName `
        --working-directory $sandboxPath `
        --terminal `
        -- $PwshExe -NoLogo -NoExit -NoProfile -ExecutionPolicy Bypass -File $ShellInitScript
    $launchAsExitCode = $LASTEXITCODE
}
finally {
    [AgentSandboxCtrlBreakGuard]::Remove()
}

if ($launchAsExitCode -ne 0) {
    Write-Warning "The interactive shell launcher returned exit code $launchAsExitCode."
    if (Test-Path $CheckerScript) {
        Write-Host "Verify setup with: & '$CheckerScript'" -ForegroundColor Yellow
    }
    Write-Host ""
    Read-Host 'Press Enter to close'
    exit 1
}
else {
    Write-Host 'Agent Sandbox session ended.' -ForegroundColor Cyan
}
