# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0

<#
.SYNOPSIS
    Launches a PowerShell 7 terminal as the low-privilege AgentSandbox user,
    scoped to the workspace stored in ProgramData config.

.DESCRIPTION
    Part of agent-win-sandbox. Assumes Setup-AgentSandbox.ps1 has provisioned
    the low-priv user, sandbox ACLs, config, and shell initializer.

    Launch uses the installed launch-as.exe client and the installed launch-as
    broker service. The broker owns a short-lived account password and starts a
    console in an independent logon session without exposing that credential to
    this script or its caller. The shell exposes commands for the Developer
    Shell, Claude Code, Copilot CLI, and the sandbox checker.

.EXAMPLE
    & "$env:ProgramData\agent-win-sandbox\Start-AgentSandbox.ps1"
    Launches an Agent Sandbox PowerShell terminal.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$UserName = 'AgentSandbox'
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
$BootstrapRoot = Join-Path $ProgramDataRoot 'bootstrap'
$ShellInitScript = Join-Path $BootstrapRoot 'Initialize-AgentSandboxShell.ps1'
$ConfigFunctionsScript = Join-Path $BootstrapRoot 'AgentSandboxConfig.ps1'
$LaunchAsExe = Join-Path (Join-Path $env:ProgramFiles 'launch-as') 'launch-as.exe'
$CheckerScript = Join-Path $ProgramDataRoot 'Check-AgentSandbox.ps1'
$ApplyConfigScript = Join-Path $ProgramDataRoot 'Apply-Config.ps1'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$PwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
$NetworkSandboxExe = Join-Path $ProgramDataRoot 'network-sandbox.exe'
$NetworkSandboxConfig = Join-Path (Join-Path $ProgramDataRoot 'network-sandbox') 'network-sandbox.json'

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

# Returns why a non-admin principal could change Path, or nothing when only
# Administrators, SYSTEM, and TrustedInstaller can.
function Get-WriteAccessIssue {
    param([string]$Path)

    $trustedSids = @(
        'S-1-5-32-544',
        'S-1-5-18',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    $writeMask = [int](
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership) -bor
    0x10000000 -bor 0x40000000    # GENERIC_ALL, GENERIC_WRITE

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        return "$Path is a link."
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trustedSids) {
        return "$Path is owned by $owner."
    }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and
            $ace.IdentityReference.Value -notin $trustedSids -and
            ([int]$ace.FileSystemRights -band $writeMask)) {
            return "$Path is writable by $($ace.IdentityReference.Value)."
        }
    }
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
foreach ($required in $ConfigFile, $ConfigFunctionsScript) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Stop-LauncherError "$required not found. Run Setup-AgentSandbox.ps1 first."
    }
}
# Only administrators may change the config or what the session runs.
foreach ($protectedPath in $ProgramDataRoot, $BootstrapRoot, $ConfigFile, $ConfigFunctionsScript, $ShellInitScript) {
    $issue = Get-WriteAccessIssue -Path $protectedPath
    if ($issue) {
        Stop-LauncherError "Refusing to launch: $issue Only administrators may modify it. Run Setup-AgentSandbox.ps1 again."
    }
}
. $ConfigFunctionsScript
$applyHint = "Close all '$UserName' sessions, then run elevated: & '$ApplyConfigScript'"
try {
    $config = Read-AgentSandboxConfig -Path $ConfigFile
    $settings = Get-AgentSandboxSettings -Config $config
    $null = Test-AgentSandboxSettings -Settings $settings
}
catch {
    Stop-LauncherError "Config at $ConfigFile is invalid: $($_.Exception.Message)"
}
if ([string]$config['setup']['appliedSettingsHash'] -ne (Get-AgentSandboxSettingsHash -Config $config)) {
    Stop-LauncherError "Settings in $ConfigFile changed since they were last applied. $applyHint"
}
$sandboxPath = $settings.workspace
$proxyPort = [int]$settings.proxy.port
$proxyOwnerSid = [string]$config['setup']['proxyOwnerSid']
if (-not (Test-Path $sandboxPath)) {
    Stop-LauncherError "Sandbox path $sandboxPath does not exist. Run Setup-AgentSandbox.ps1 again."
}
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $proxyOwnerSid) {
    Stop-LauncherError 'This launcher must run as the account that installed the proxy. Run setup again from the intended launcher account.'
}
if (-not (Test-Path $NetworkSandboxExe -PathType Leaf) -or
    -not (Test-Path $NetworkSandboxConfig -PathType Leaf)) {
    Stop-LauncherError 'Network proxy is not installed. Run Setup-AgentSandbox.ps1 again.'
}
$proxyStatus = @(& $NetworkSandboxExe status -config $NetworkSandboxConfig 2>&1)
if ($LASTEXITCODE -ne 0 -or ($proxyStatus -join ' ') -notmatch "127\.0\.0\.1:$proxyPort(?!\d)") {
    & $NetworkSandboxExe start -config $NetworkSandboxConfig
    $proxyStatus = @(& $NetworkSandboxExe status -config $NetworkSandboxConfig 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($proxyStatus -join ' ') -notmatch "127\.0\.0\.1:$proxyPort(?!\d)") {
        Stop-LauncherError "Network proxy could not start on 127.0.0.1:$proxyPort. Run Setup-AgentSandbox.ps1 again."
    }
}
Write-Host "Configured sandbox path: $sandboxPath" -ForegroundColor Cyan

# --- Launch -------------------------------------------------------------------
Write-Host "Launching Agent Sandbox as '$UserName' in $sandboxPath ..." -ForegroundColor Green
# launch-as uses the installed broker; no password prompt is expected.

Enable-CtrlBreakGuard
try {
    & $LaunchAsExe `
        --user $UserName `
        --working-directory $sandboxPath `
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
