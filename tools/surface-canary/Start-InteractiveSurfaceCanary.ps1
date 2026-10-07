# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

<#
.SYNOPSIS
    Starts a harmless interactive-user process and window for sandbox-boundary tests.

.DESCRIPTION
    Run this as the interactive user, not as AgentSandbox. It launches a separate
    PowerShell process containing a random 32-byte canary only in its own
    allocated memory and displays a window with a random title. Closing that
    window stops the process and removes the state file.

    The state file contains only a process ID, a fixed 32-byte buffer address,
    the canary's SHA-256 hash, and the expected window title. It never contains a
    real secret or the canary plaintext.

.PARAMETER StatePath
    Public state file read by the verifier running as AgentSandbox.

.PARAMETER Worker
    Internal switch used only by the child process.

.PARAMETER ValidateOnly
    Compiles the worker code without creating a window or state file.
#>

[CmdletBinding()]
param(
    [string]$StatePath = (Join-Path (Join-Path $env:PUBLIC 'Documents') 'AgentSandboxSurfaceCanary\state.json'),
    [switch]$Worker,
    [string]$CanaryId,
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Initialize-InteractiveSurfaceCanaryType {
    if ('InteractiveSurfaceCanary' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class InteractiveSurfaceCanary
{
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_READWRITE = 0x04;
    private const int CanaryLength = 32;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr owner, string text, string caption, uint type);

    private static string JsonString(string value)
    {
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static void WriteState(string statePath, string canaryId, IntPtr buffer, string canaryHash, string windowTitle)
    {
        string json = "{\n" +
            "  \"schema\": \"agent-sandbox-surface-canary-v1\",\n" +
            "  \"canaryId\": " + JsonString(canaryId) + ",\n" +
            "  \"processId\": " + GetCurrentProcessId() + ",\n" +
            "  \"bufferAddress\": " + JsonString("0x" + buffer.ToInt64().ToString("X")) + ",\n" +
            "  \"bufferLength\": " + CanaryLength + ",\n" +
            "  \"canarySha256\": " + JsonString(canaryHash) + ",\n" +
            "  \"windowTitle\": " + JsonString(windowTitle) + "\n" +
            "}\n";

        using (var stream = new FileStream(statePath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(json);
        }
    }

    public static void Run(string statePath, string canaryId)
    {
        byte[] canary = new byte[CanaryLength];
        using (var random = RandomNumberGenerator.Create())
        {
            random.GetBytes(canary);
        }
        string canaryHash;
        using (var sha256 = SHA256.Create())
        {
            canaryHash = BitConverter.ToString(sha256.ComputeHash(canary)).Replace("-", String.Empty);
        }

        IntPtr buffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)CanaryLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buffer == IntPtr.Zero)
        {
            throw new InvalidOperationException("VirtualAlloc failed: " + Marshal.GetLastWin32Error());
        }

        bool stateCreated = false;
        try
        {
            Marshal.Copy(canary, 0, buffer, CanaryLength);
            string windowTitle = "AgentSandbox UI Canary " + canaryId;
            WriteState(statePath, canaryId, buffer, canaryHash, windowTitle);
            stateCreated = true;

            MessageBoxW(
                IntPtr.Zero,
                "Interactive surface canary is running.\r\n\r\n" +
                    "It contains random test data only. Keep this dialog open while running the verifier as AgentSandbox.",
                windowTitle,
                0x00000040);
        }
        finally
        {
            if (stateCreated)
            {
                try { File.Delete(statePath); } catch { }
            }
            VirtualFree(buffer, UIntPtr.Zero, MEM_RELEASE);
        }
    }
}
'@
}

if ($ValidateOnly) {
    Initialize-InteractiveSurfaceCanaryType
    Write-Host 'Interactive surface canary code compiled successfully.' -ForegroundColor Green
    return
}

if ($Worker) {
    if ([string]::IsNullOrWhiteSpace($CanaryId)) {
        throw 'The worker requires a canary ID.'
    }
    Initialize-InteractiveSurfaceCanaryType
    [InteractiveSurfaceCanary]::Run($StatePath, $CanaryId)
    return
}

if ($env:USERNAME -eq 'AgentSandbox') {
    throw 'Run this canary as the interactive user, not as AgentSandbox.'
}

$stateDirectory = Split-Path -Parent $StatePath
if (-not (Test-Path -LiteralPath $stateDirectory)) {
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
}
if (Test-Path -LiteralPath $StatePath) {
    throw "State file already exists: $StatePath. Close the existing canary window or remove a stale state file after confirming no canary is running."
}

$canaryId = [guid]::NewGuid().ToString('N')
$enginePath = (Get-Process -Id $PID).Path
$quotedScript = '"' + $PSCommandPath.Replace('"', '""') + '"'
$quotedState = '"' + $StatePath.Replace('"', '""') + '"'
$arguments = "-NoProfile -File $quotedScript -Worker -CanaryId $canaryId -StatePath $quotedState"
$workerProcess = Start-Process -FilePath $enginePath -ArgumentList $arguments -WindowStyle Hidden -PassThru

$deadline = [DateTime]::UtcNow.AddSeconds(10)
while ((-not (Test-Path -LiteralPath $StatePath)) -and ([DateTime]::UtcNow -lt $deadline)) {
    Start-Sleep -Milliseconds 100
}
if (-not (Test-Path -LiteralPath $StatePath)) {
    if (-not $workerProcess.HasExited) {
        Stop-Process -Id $workerProcess.Id -Force
    }
    throw 'The canary worker did not create its state file within 10 seconds.'
}

Write-Host 'Interactive canary is ready.' -ForegroundColor Green
Write-Host "State file: $StatePath"
Write-Host "Worker PID: $($workerProcess.Id)"
Write-Host 'From an AgentSandbox terminal, run:' -ForegroundColor Cyan
Write-Host "  & '$PSScriptRoot\Test-SurfaceCanary.ps1' -StatePath '$StatePath'"
Write-Host 'Close the canary window when finished.' -ForegroundColor DarkGray
