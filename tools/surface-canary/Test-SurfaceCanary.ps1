# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

<#
.SYNOPSIS
    Verifies a controlled cross-user process-memory and desktop-access canary.

.DESCRIPTION
    This verifier deliberately has no PID, address, length, process-name, window
    title, or dump-file parameters. It accepts only a state file created by
    Start-InteractiveSurfaceCanary.ps1, checks that the referenced process was
    started as that script's worker using a direct native process command-line
    query, then reads exactly its fixed 32-byte canary buffer and compares its
    SHA-256 hash. It never scans memory or saves bytes.

    It also opens the active input desktop for read/enumeration only and reports
    whether that desktop contains the canary's exact window title. It never
    captures pixels, sends input, or changes any UI object.
#>

[CmdletBinding()]
param(
    [string]$StatePath = (Join-Path (Join-Path $env:PUBLIC 'Documents') 'AgentSandboxSurfaceCanary\state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Initialize-SurfaceCanaryVerifierType {
    if ('AgentSandbox.SurfaceCanaryV2.SurfaceCanaryVerifier' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace AgentSandbox.SurfaceCanaryV2
{
public sealed class TokenSnapshot
{
    public string UserSid { get; set; }
    public string[] LogonSids { get; set; }
}

public sealed class MemoryProof
{
    public bool Opened { get; set; }
    public bool ReadSucceeded { get; set; }
    public string Sha256 { get; set; }
    public int Error { get; set; }
}

public sealed class ProcessCommandLineProof
{
    public bool Opened { get; set; }
    public string CommandLine { get; set; }
    public int NtStatus { get; set; }
}

public sealed class DesktopProof
{
    public bool OpenedForRead { get; set; }
    public bool CanaryWindowFound { get; set; }
    public bool OpenedForWriteObjects { get; set; }
    public string Name { get; set; }
    public int ReadError { get; set; }
    public int WriteError { get; set; }
}

public static class SurfaceCanaryVerifier
{
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int ProcessCommandLineInformation = 60;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;
    private const int TokenGroups = 2;
    private const uint SE_GROUP_LOGON_ID = 0xC0000000;
    private const uint DESKTOP_READOBJECTS = 0x0001;
    private const uint DESKTOP_ENUMERATE = 0x0040;
    private const uint DESKTOP_WRITEOBJECTS = 0x0080;
    private const int UOI_NAME = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenGroupsHeader { public uint GroupCount; public SidAndAttributes FirstGroup; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUserInfo { public SidAndAttributes User; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    private delegate bool EnumDesktopProc(IntPtr window, IntPtr parameter);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int informationClass, IntPtr tokenInformation, int informationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, int size, out IntPtr bytesRead);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint desiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetUserObjectInformation(IntPtr handle, int index, StringBuilder information, int length, out int requiredLength);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EnumDesktopWindows(IntPtr desktop, EnumDesktopProc callback, IntPtr parameter);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLengthW(IntPtr window);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(IntPtr window, StringBuilder text, int maxCount);

    private static IntPtr GetTokenInformationBuffer(IntPtr token, int informationClass)
    {
        int size;
        GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out size);
        if (size <= 0) { throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation size query failed"); }
        IntPtr buffer = Marshal.AllocHGlobal(size);
        if (!GetTokenInformation(token, informationClass, buffer, size, out size))
        {
            int error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(error, "GetTokenInformation failed");
        }
        return buffer;
    }

    private static TokenSnapshot ReadToken(IntPtr token)
    {
        IntPtr userBuffer = IntPtr.Zero;
        IntPtr groupsBuffer = IntPtr.Zero;
        try
        {
            userBuffer = GetTokenInformationBuffer(token, TokenUser);
            TokenUserInfo user = Marshal.PtrToStructure<TokenUserInfo>(userBuffer);
            groupsBuffer = GetTokenInformationBuffer(token, TokenGroups);
            uint count = unchecked((uint)Marshal.ReadInt32(groupsBuffer));
            int offset = Marshal.OffsetOf<TokenGroupsHeader>("FirstGroup").ToInt32();
            int size = Marshal.SizeOf<SidAndAttributes>();
            var logonSids = new List<string>();
            for (uint index = 0; index < count; index++)
            {
                IntPtr entryAddress = IntPtr.Add(groupsBuffer, offset + checked((int)index * size));
                SidAndAttributes entry = Marshal.PtrToStructure<SidAndAttributes>(entryAddress);
                if ((entry.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                {
                    logonSids.Add(new SecurityIdentifier(entry.Sid).Value);
                }
            }
            return new TokenSnapshot { UserSid = new SecurityIdentifier(user.User.Sid).Value, LogonSids = logonSids.ToArray() };
        }
        finally
        {
            if (groupsBuffer != IntPtr.Zero) { Marshal.FreeHGlobal(groupsBuffer); }
            if (userBuffer != IntPtr.Zero) { Marshal.FreeHGlobal(userBuffer); }
        }
    }

    private static TokenSnapshot GetTokenSnapshot(IntPtr process)
    {
        IntPtr token;
        if (!OpenProcessToken(process, TOKEN_QUERY, out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        }
        try { return ReadToken(token); }
        finally { CloseHandle(token); }
    }

    public static TokenSnapshot GetCurrentTokenSnapshot() { return GetTokenSnapshot(GetCurrentProcess()); }

    public static TokenSnapshot GetProcessTokenSnapshot(int processId)
    {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess token query failed"); }
        try { return GetTokenSnapshot(process); }
        finally { CloseHandle(process); }
    }

    public static ProcessCommandLineProof GetProcessCommandLine(int processId)
    {
        var result = new ProcessCommandLineProof();
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process == IntPtr.Zero)
        {
            result.NtStatus = Marshal.GetLastWin32Error();
            return result;
        }
        result.Opened = true;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int requiredLength;
            int status = NtQueryInformationProcess(process, ProcessCommandLineInformation, IntPtr.Zero, 0, out requiredLength);
            if (status != STATUS_INFO_LENGTH_MISMATCH || requiredLength <= 0)
            {
                result.NtStatus = status;
                return result;
            }

            buffer = Marshal.AllocHGlobal(requiredLength);
            status = NtQueryInformationProcess(process, ProcessCommandLineInformation, buffer, requiredLength, out requiredLength);
            if (status != 0)
            {
                result.NtStatus = status;
                return result;
            }

            UnicodeString commandLine = Marshal.PtrToStructure<UnicodeString>(buffer);
            long bufferStart = buffer.ToInt64();
            long bufferEnd = checked(bufferStart + requiredLength);
            long textStart = commandLine.Buffer.ToInt64();
            long textEnd = checked(textStart + commandLine.Length);
            if ((commandLine.Length & 1) != 0 || textStart < bufferStart || textEnd > bufferEnd)
            {
                result.NtStatus = STATUS_INFO_LENGTH_MISMATCH;
                return result;
            }
            result.CommandLine = Marshal.PtrToStringUni(commandLine.Buffer, commandLine.Length / sizeof(char));
            return result;
        }
        finally
        {
            if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
            CloseHandle(process);
        }
    }

    public static MemoryProof ReadFixedCanary(int processId, long address, int length)
    {
        var result = new MemoryProof();
        IntPtr process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
        if (process == IntPtr.Zero)
        {
            result.Error = Marshal.GetLastWin32Error();
            return result;
        }
        result.Opened = true;
        try
        {
            byte[] bytes = new byte[length];
            IntPtr bytesRead;
            if (!ReadProcessMemory(process, new IntPtr(address), bytes, length, out bytesRead) || bytesRead.ToInt64() != length)
            {
                result.Error = Marshal.GetLastWin32Error();
                return result;
            }
            using (var sha256 = SHA256.Create())
            {
                result.Sha256 = BitConverter.ToString(sha256.ComputeHash(bytes)).Replace("-", String.Empty);
            }
            result.ReadSucceeded = true;
            return result;
        }
        finally { CloseHandle(process); }
    }

    private static string DesktopName(IntPtr desktop)
    {
        int requiredLength;
        GetUserObjectInformation(desktop, UOI_NAME, null, 0, out requiredLength);
        if (requiredLength <= 0) { return String.Empty; }
        var name = new StringBuilder(requiredLength / sizeof(char));
        return GetUserObjectInformation(desktop, UOI_NAME, name, requiredLength, out requiredLength) ? name.ToString() : String.Empty;
    }

    public static DesktopProof FindCanaryWindow(string expectedTitle)
    {
        var proof = new DesktopProof();
        IntPtr desktop = OpenInputDesktop(0, false, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
        if (desktop == IntPtr.Zero)
        {
            proof.ReadError = Marshal.GetLastWin32Error();
        }
        else
        {
            proof.OpenedForRead = true;
            proof.Name = DesktopName(desktop);
            EnumDesktopProc callback = delegate(IntPtr window, IntPtr parameter) {
                int length = GetWindowTextLengthW(window);
                if (length <= 0) { return true; }
                var title = new StringBuilder(length + 1);
                GetWindowTextW(window, title, title.Capacity);
                if (String.Equals(title.ToString(), expectedTitle, StringComparison.Ordinal))
                {
                    proof.CanaryWindowFound = true;
                    return false;
                }
                return true;
            };
            EnumDesktopWindows(desktop, callback, IntPtr.Zero);
            CloseDesktop(desktop);
        }

        IntPtr writeDesktop = OpenInputDesktop(0, false, DESKTOP_WRITEOBJECTS);
        if (writeDesktop == IntPtr.Zero)
        {
            proof.WriteError = Marshal.GetLastWin32Error();
        }
        else
        {
            proof.OpenedForWriteObjects = true;
            CloseDesktop(writeDesktop);
        }
        return proof;
    }
}
}
'@
}

function Get-ValidatedCanaryState {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Canary state file not found: $Path"
    }
    $state = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($state.schema -ne 'agent-sandbox-surface-canary-v1') {
        throw 'The state file is not an agent-sandbox surface-canary v1 state file.'
    }
    if ([string]$state.canaryId -notmatch '^[0-9a-f]{32}$' -or
        [int]$state.processId -le 0 -or
        [string]$state.bufferAddress -notmatch '^0x[0-9A-F]+$' -or
        [int]$state.bufferLength -ne 32 -or
        [string]$state.canarySha256 -notmatch '^[0-9A-F]{64}$' -or
        [string]$state.windowTitle -ne "AgentSandbox UI Canary $($state.canaryId)") {
        throw 'The canary state file has an invalid or unsafe shape.'
    }
    return $state
}

function Test-CanaryWorkerIdentity {
    param(
        [pscustomobject]$State,
        [string]$ExpectedWorkerScript
    )

    $worker = [AgentSandbox.SurfaceCanaryV2.SurfaceCanaryVerifier]::GetProcessCommandLine([int]$State.processId)
    if (-not $worker.CommandLine) {
        throw ('Refusing to inspect PID {0}: its native command line could not be queried (status 0x{1:X8}).' -f $State.processId, [uint32]$worker.NtStatus)
    }
    foreach ($argument in @($ExpectedWorkerScript, '-Worker', '-CanaryId', [string]$State.canaryId)) {
        if ($worker.CommandLine -notlike "*$argument*") {
            throw "Refusing to inspect PID $($State.processId): it is not the expected canary worker."
        }
    }
}

Initialize-SurfaceCanaryVerifierType
$state = Get-ValidatedCanaryState -Path $StatePath
$expectedWorkerScript = Join-Path $PSScriptRoot 'Start-InteractiveSurfaceCanary.ps1'
Test-CanaryWorkerIdentity -State $state -ExpectedWorkerScript $expectedWorkerScript

$currentToken = [AgentSandbox.SurfaceCanaryV2.SurfaceCanaryVerifier]::GetCurrentTokenSnapshot()
$targetToken = [AgentSandbox.SurfaceCanaryV2.SurfaceCanaryVerifier]::GetProcessTokenSnapshot([int]$state.processId)
$sharedLogonSid = @($targetToken.LogonSids | Where-Object { $_ -in $currentToken.LogonSids })
$address = [Convert]::ToInt64(([string]$state.bufferAddress).Substring(2), 16)
$memory = [AgentSandbox.SurfaceCanaryV2.SurfaceCanaryVerifier]::ReadFixedCanary([int]$state.processId, $address, [int]$state.bufferLength)
$desktop = [AgentSandbox.SurfaceCanaryV2.SurfaceCanaryVerifier]::FindCanaryWindow([string]$state.windowTitle)

$memoryProven = $memory.ReadSucceeded -and ($memory.Sha256 -eq $state.canarySha256)
$processProven = ($currentToken.UserSid -ne $targetToken.UserSid) -and ($sharedLogonSid.Count -gt 0) -and $memoryProven
$desktopProven = $desktop.OpenedForRead -and $desktop.CanaryWindowFound

Write-Host 'Controlled surface-canary result' -ForegroundColor Cyan
[pscustomobject]@{
    VerifierUserSid      = $currentToken.UserSid
    CanaryUserSid        = $targetToken.UserSid
    CrossUserTest        = $currentToken.UserSid -ne $targetToken.UserSid
    SharedLogonSid       = if ($sharedLogonSid) { $sharedLogonSid -join ', ' } else { '<none>' }
    CanaryMemoryRead     = $memoryProven
    InputDesktopName     = if ($desktop.Name) { $desktop.Name } else { '<unavailable>' }
    CanaryWindowFound    = $desktop.CanaryWindowFound
    DesktopWriteObjects  = $desktop.OpenedForWriteObjects
} | Format-List

if ($processProven) {
    Write-Host '[PROVEN] A different user process sharing the verifier logon SID disclosed the exact 32-byte test canary.' -ForegroundColor Red
}
elseif ($memoryProven -and ($currentToken.UserSid -eq $targetToken.UserSid)) {
    Write-Host '[BASELINE] The exact 32-byte test canary was read successfully. Verifier and canary use the same TokenUser, so this run does not test cross-user process exposure.' -ForegroundColor Yellow
}
elseif ($memoryProven) {
    Write-Host '[NOT PROVEN] The exact 32-byte test canary was read, but the verifier did not establish the required shared logon SID for cross-user process exposure.' -ForegroundColor Green
}
else {
    Write-Host "[NOT PROVEN] The controlled memory canary was not read (Open/Read error $($memory.Error))." -ForegroundColor Green
}
if ($desktopProven) {
    Write-Host '[PROVEN] The active input desktop exposed the interactive canary window title.' -ForegroundColor Red
}
else {
    Write-Host "[NOT PROVEN] The active input desktop did not expose the canary window (read error $($desktop.ReadError))." -ForegroundColor Green
}
if ($desktop.OpenedForWriteObjects) {
    Write-Host '[EXPOSED] The token also opened the active input desktop with DESKTOP_WRITEOBJECTS; this verifier did not write any object.' -ForegroundColor Red
}

Write-Host 'Safety: this verifier read exactly 32 bytes from its verified canary worker. It did not scan memory, save bytes, capture the screen, send input, or modify a process or desktop.' -ForegroundColor DarkGray

if (-not ($processProven -and $desktopProven)) {
    exit 1
}
