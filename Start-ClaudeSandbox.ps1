# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

<#
.SYNOPSIS
    Launches Claude Code as a low-privilege user inside a Visual Studio Developer
    Shell, scoped to the ClaudeSandbox workspace stored in ProgramData config.
    Prompts for the password each launch.

.DESCRIPTION
    Part of claude-win-sandbox. Assumes Setup-ClaudeSandbox.ps1 has provisioned
    the low-priv user, sandbox ACLs, config, and the Dev Shell bootstrap.

    Launch uses the bundled launch-as.exe helper. It starts an interactive
    console with the target user's token and uses Windows Credential UI to
    obtain or update the target account credential when required.

.EXAMPLE
    & "$env:ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1"
    Prompts for the password, launches a sandboxed Dev Shell in the workspace
    stored in the ProgramData config by setup.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$UserName = 'ClaudeSandbox'
$ProgramDataRoot = Join-Path $env:ProgramData 'claude-win-sandbox'
$BootstrapScript = Join-Path (Join-Path $ProgramDataRoot 'bootstrap') 'Enter-ClaudeDevShell.ps1'
$LaunchAsExe = Join-Path $ProgramDataRoot 'launch-as.exe'
$CheckerScript = Join-Path $ProgramDataRoot 'Check-ClaudeSandbox.ps1'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'

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
    if (-not ('ClaudeSandboxCtrlBreakGuard' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ClaudeSandboxCtrlBreakGuard
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

    [ClaudeSandboxCtrlBreakGuard]::Install()
}

trap {
    Stop-LauncherError "Unexpected launcher error: $($_.Exception.Message)"
}

# --- Pre-flight checks --------------------------------------------------------
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    Stop-LauncherError "User '$UserName' does not exist. Run Setup-ClaudeSandbox.ps1 first."
}
if (-not (Test-Path $BootstrapScript)) {
    Stop-LauncherError "Bootstrap not found at $BootstrapScript. Run Setup-ClaudeSandbox.ps1 first."
}
if (-not (Test-Path $LaunchAsExe)) {
    Stop-LauncherError "launch-as not found at $LaunchAsExe. Run Setup-ClaudeSandbox.ps1 first."
}
if (-not (Test-Path $ConfigFile)) {
    Stop-LauncherError "Config not found at $ConfigFile. Run Setup-ClaudeSandbox.ps1 first."
}
try {
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $sandboxPath = $config.sandboxPath
}
catch {
    Stop-LauncherError "Config at $ConfigFile is invalid: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($sandboxPath)) {
    Stop-LauncherError "Config at $ConfigFile does not define sandboxPath. Run Setup-ClaudeSandbox.ps1 again."
}
if (-not (Test-Path $sandboxPath)) {
    Stop-LauncherError "Sandbox path $sandboxPath does not exist. Run Setup-ClaudeSandbox.ps1 again."
}
Write-Host "Configured sandbox path: $sandboxPath" -ForegroundColor Cyan

# --- Launch -------------------------------------------------------------------
$powershellExe = (Get-Command powershell.exe -ErrorAction Stop).Source
Write-Host "Launching as '$UserName' in $sandboxPath ..." -ForegroundColor Green
Write-Host '(Windows Credential UI appears if launch-as needs a credential.)' -ForegroundColor DarkGray

Enable-CtrlBreakGuard
try {
    & $LaunchAsExe `
        --user $UserName `
        --working-directory $sandboxPath `
        --terminal `
        -- $powershellExe -NoExit -ExecutionPolicy Bypass -File $BootstrapScript
    $launchAsExitCode = $LASTEXITCODE
}
finally {
    [ClaudeSandboxCtrlBreakGuard]::Remove()
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
    Write-Host 'Sandbox session ended.' -ForegroundColor Cyan
}
