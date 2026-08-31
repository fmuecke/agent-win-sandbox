# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

<#
.SYNOPSIS
    Read-only diagnostic for interactive-session process and desktop exposure.

.DESCRIPTION
    Run this inside an AgentSandbox session. The diagnostic checks whether another
    user in the same Windows session shares the current logon SID and whether the
    current token can obtain PROCESS_VM_READ or PROCESS_TERMINATE handles to that
    process. It also reports the current desktop and probes non-mutating access to
    the input desktop. A desktop name alone is not enough to identify an
    interactive desktop: noninteractive window stations can also contain a
    desktop named Default.

    It never reads target-process memory, terminates a process, captures the
    screen, sends input, or changes a desktop ACL. A successful handle request is
    evidence that the corresponding operation would be permitted, not execution of
    that operation.

.NOTES
    Risk interpretation:

    Surface 1 is UI/desktop reach. Access to the active input desktop can let
    hostile code observe UI objects and potentially act through applications
    already running as the interactive user. UIPI and the UAC secure desktop can
    restrict selected cross-integrity paths; this diagnostic does not test them.

    Surface 2 is process/kernel-object reach. PROCESS_VM_READ can disclose
    plaintext held in another process, such as source, terminal output, or web
    session material. PROCESS_TERMINATE can cause data loss or disrupt tools.
    Neither result alone proves code injection, elevation, a screen capture, or
    input injection. Those require additional rights or successful API calls.

    A positive result means this launcher is blast-radius reduction, not a hard
    isolation boundary. Use a VM or separate Windows session for hostile code.

.PARAMETER ProcessId
    Optional process IDs to inspect. By default, inspect processes in the current
    Windows session whose token user differs from the current token user.

.EXAMPLE
    sandbox-surfaces
    Reports observable process and desktop exposure from the current sandbox
    session without performing an attack.
#>

[CmdletBinding()]
param(
    [int[]]$ProcessId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Initialize-SurfaceProbe {
    if ('AgentSandboxSurfaceProbe' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public sealed class ProcessTokenSnapshot
{
    public string UserSid { get; set; }
    public string[] LogonSids { get; set; }
}

public sealed class HandleProbe
{
    public bool Allowed { get; set; }
    public int Error { get; set; }
}

public sealed class DesktopSnapshot
{
    public string CurrentWindowStationName { get; set; }
    public string CurrentDesktopName { get; set; }
    public HandleProbe InputDesktopRead { get; set; }
    public HandleProbe InputDesktopWriteObjects { get; set; }
}

public static class AgentSandboxSurfaceProbe
{
    private const uint PROCESS_TERMINATE = 0x0001;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;
    private const int TokenGroups = 2;
    private const uint SE_GROUP_LOGON_ID = 0xC0000000;
    private const uint DESKTOP_READOBJECTS = 0x0001;
    private const uint DESKTOP_ENUMERATE = 0x0040;
    private const uint DESKTOP_WRITEOBJECTS = 0x0080;
    private const int UOI_NAME = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenGroupsHeader
    {
        public uint GroupCount;
        public SidAndAttributes FirstGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUserInfo
    {
        public SidAndAttributes User;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetThreadDesktop(uint threadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetUserObjectInformation(
        IntPtr handle,
        int index,
        StringBuilder information,
        int length,
        out int requiredLength);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint desiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr desktop);

    private static IntPtr GetTokenInformationBuffer(IntPtr tokenHandle, int informationClass)
    {
        int size;
        GetTokenInformation(tokenHandle, informationClass, IntPtr.Zero, 0, out size);
        if (size <= 0)
        {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error, "GetTokenInformation size query failed");
        }

        IntPtr buffer = Marshal.AllocHGlobal(size);
        if (!GetTokenInformation(tokenHandle, informationClass, buffer, size, out size))
        {
            int error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(error, "GetTokenInformation failed");
        }
        return buffer;
    }

    private static ProcessTokenSnapshot ReadTokenSnapshot(IntPtr tokenHandle)
    {
        IntPtr userBuffer = IntPtr.Zero;
        IntPtr groupsBuffer = IntPtr.Zero;
        try
        {
            userBuffer = GetTokenInformationBuffer(tokenHandle, TokenUser);
            TokenUserInfo user = Marshal.PtrToStructure<TokenUserInfo>(userBuffer);
            string userSid = new SecurityIdentifier(user.User.Sid).Value;

            groupsBuffer = GetTokenInformationBuffer(tokenHandle, TokenGroups);
            uint groupCount = unchecked((uint)Marshal.ReadInt32(groupsBuffer));
            int groupsOffset = Marshal.OffsetOf<TokenGroupsHeader>("FirstGroup").ToInt32();
            int groupSize = Marshal.SizeOf<SidAndAttributes>();
            var logonSids = new List<string>();
            for (uint index = 0; index < groupCount; index++)
            {
                IntPtr groupAddress = IntPtr.Add(groupsBuffer, groupsOffset + checked((int)index * groupSize));
                SidAndAttributes group = Marshal.PtrToStructure<SidAndAttributes>(groupAddress);
                if ((group.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                {
                    logonSids.Add(new SecurityIdentifier(group.Sid).Value);
                }
            }

            return new ProcessTokenSnapshot { UserSid = userSid, LogonSids = logonSids.ToArray() };
        }
        finally
        {
            if (groupsBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(groupsBuffer);
            }
            if (userBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(userBuffer);
            }
        }
    }

    public static ProcessTokenSnapshot GetProcessTokenSnapshot(int processId)
    {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess token query failed");
        }

        try
        {
            IntPtr token;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
            }
            try
            {
                return ReadTokenSnapshot(token);
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    public static HandleProbe ProbeProcessVmRead(int processId)
    {
        return ProbeProcess(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    }

    public static HandleProbe ProbeProcessTerminate(int processId)
    {
        return ProbeProcess(processId, PROCESS_TERMINATE);
    }

    private static HandleProbe ProbeProcess(int processId, uint desiredAccess)
    {
        IntPtr process = OpenProcess(desiredAccess, false, processId);
        if (process == IntPtr.Zero)
        {
            return new HandleProbe { Allowed = false, Error = Marshal.GetLastWin32Error() };
        }
        CloseHandle(process);
        return new HandleProbe { Allowed = true, Error = 0 };
    }

    private static HandleProbe ProbeInputDesktop(uint desiredAccess)
    {
        IntPtr desktop = OpenInputDesktop(0, false, desiredAccess);
        if (desktop == IntPtr.Zero)
        {
            return new HandleProbe { Allowed = false, Error = Marshal.GetLastWin32Error() };
        }
        CloseDesktop(desktop);
        return new HandleProbe { Allowed = true, Error = 0 };
    }

    private static string GetUserObjectName(IntPtr userObject, string objectType)
    {
        if (userObject == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), objectType + " query failed");
        }

        int requiredLength;
        GetUserObjectInformation(userObject, UOI_NAME, null, 0, out requiredLength);
        if (requiredLength <= 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(), objectType + " name size query failed");
        }
        var name = new StringBuilder(requiredLength / sizeof(char));
        if (!GetUserObjectInformation(userObject, UOI_NAME, name, requiredLength, out requiredLength))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), objectType + " name query failed");
        }
        return name.ToString();
    }

    public static DesktopSnapshot GetDesktopSnapshot()
    {
        return new DesktopSnapshot
        {
            CurrentWindowStationName = GetUserObjectName(
                GetProcessWindowStation(), "GetProcessWindowStation"),
            CurrentDesktopName = GetUserObjectName(
                GetThreadDesktop(GetCurrentThreadId()), "GetThreadDesktop"),
            InputDesktopRead = ProbeInputDesktop(DESKTOP_READOBJECTS | DESKTOP_ENUMERATE),
            InputDesktopWriteObjects = ProbeInputDesktop(DESKTOP_WRITEOBJECTS)
        };
    }
}
'@
}

function Write-Section {
    param([string]$Title)

    Write-Host "`n== $Title ==" -ForegroundColor Cyan
}

function Get-TargetProcessIds {
    param([int[]]$RequestedProcessId)

    if ($RequestedProcessId) {
        return @($RequestedProcessId | Where-Object { $_ -ne $PID } | Sort-Object -Unique)
    }

    $currentSessionId = (Get-Process -Id $PID).SessionId
    return @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -ne $PID -and $_.SessionId -eq $currentSessionId } |
        Select-Object -ExpandProperty Id |
        Sort-Object -Unique)
}

Initialize-SurfaceProbe

Write-Host 'Read-only diagnostic: no memory is read, no process is terminated, and no input is sent.' -ForegroundColor DarkGray

$currentToken = [AgentSandboxSurfaceProbe]::GetProcessTokenSnapshot($PID)
$currentLogonSids = @($currentToken.LogonSids)

Write-Section 'Current token'
Write-Host "Token user: $($currentToken.UserSid)"
if ($currentLogonSids.Count -eq 0) {
    Write-Host '[INDETERMINATE] The token has no logon SID group; process-session comparison cannot run.' -ForegroundColor Yellow
}
else {
    Write-Host "Logon SID(s): $($currentLogonSids -join ', ')"
}

Write-Section 'Surface 1: desktop reach'
$desktop = [AgentSandboxSurfaceProbe]::GetDesktopSnapshot()
$startedOnInteractiveDesktop = ($desktop.CurrentWindowStationName -ieq 'WinSta0') -and
($desktop.CurrentDesktopName -ieq 'Default')
$desktopExposed = $startedOnInteractiveDesktop -or
$desktop.InputDesktopRead.Allowed -or $desktop.InputDesktopWriteObjects.Allowed
Write-Host "Current window station: $($desktop.CurrentWindowStationName)"
Write-Host "Current desktop: $($desktop.CurrentDesktopName)"
if ($startedOnInteractiveDesktop) {
    Write-Host '[EXPOSED] The command started on Winsta0\Default.' -ForegroundColor Red
}
else {
    Write-Host '[INFO] The command did not start on Winsta0\Default.' -ForegroundColor DarkGray
}
if ($desktop.InputDesktopRead.Allowed) {
    Write-Host '[EXPOSED] The token can open the active input desktop for object enumeration.' -ForegroundColor Red
}
else {
    Write-Host "[OK] Cannot open the input desktop for enumeration (Win32 error $($desktop.InputDesktopRead.Error))." -ForegroundColor Green
}
if ($desktop.InputDesktopWriteObjects.Allowed) {
    Write-Host '[EXPOSED] The token can open the active input desktop with DESKTOP_WRITEOBJECTS.' -ForegroundColor Red
}
else {
    Write-Host "[OK] Cannot open the input desktop with DESKTOP_WRITEOBJECTS (Win32 error $($desktop.InputDesktopWriteObjects.Error))." -ForegroundColor Green
}

Write-Section 'Surface 2: other-user process reach'
$observations = @()
$confirmed = @()
foreach ($targetProcessId in Get-TargetProcessIds -RequestedProcessId $ProcessId) {
    try {
        $targetToken = [AgentSandboxSurfaceProbe]::GetProcessTokenSnapshot($targetProcessId)
    }
    catch {
        continue
    }

    if ($targetToken.UserSid -eq $currentToken.UserSid) {
        continue
    }

    $sharedLogonSids = @($targetToken.LogonSids | Where-Object { $_ -in $currentLogonSids })
    $vmRead = [AgentSandboxSurfaceProbe]::ProbeProcessVmRead($targetProcessId)
    $terminate = [AgentSandboxSurfaceProbe]::ProbeProcessTerminate($targetProcessId)
    if (($sharedLogonSids.Count -eq 0) -and -not $vmRead.Allowed -and -not $terminate.Allowed) {
        continue
    }

    $name = '<exited>'
    try {
        $name = (Get-Process -Id $targetProcessId -ErrorAction Stop).ProcessName
    }
    catch {
        # The process can exit after its token was inspected.
    }
    $observations += [pscustomobject]@{
        Target         = "$name ($targetProcessId)"
        SharedLogonSid = if ($sharedLogonSids) { 'yes' } else { 'no' }
        AllowedAccess  = @(
            if ($vmRead.Allowed) { 'VM_READ' }
            if ($terminate.Allowed) { 'TERMINATE' }
        ) -join ', '
    }
}

if (-not $observations) {
    Write-Host '[OK] No inspectable other-user process in this session exposed a shared logon SID or either requested handle.' -ForegroundColor Green
}
else {
    $observations | Format-Table -AutoSize
    $confirmed = @($observations | Where-Object {
            $_.SharedLogonSid -eq 'yes' -and -not [string]::IsNullOrWhiteSpace($_.AllowedAccess)
        })
    if ($confirmed) {
        Write-Host '[EXPOSED] A different user in this session shares the logon SID and accepted a VM-read and/or terminate-capable handle.' -ForegroundColor Red
    }
    else {
        Write-Host '[INDETERMINATE] Handle access or a shared logon SID was observed, but not both for the same target.' -ForegroundColor Yellow
    }
}

Write-Section 'Risk interpretation'
if ($desktopExposed) {
    Write-Host '[RISK] Desktop reach can expose on-screen/UI information and may enable actions through interactive-user applications.' -ForegroundColor Yellow
    Write-Host '       It does not prove a successful screen capture or input injection; UIPI and the UAC secure desktop can restrict some paths.' -ForegroundColor DarkGray
}
else {
    Write-Host '[OK] The requested desktop access was not granted.' -ForegroundColor Green
}
if ($confirmed) {
    Write-Host '[RISK] VM_READ can disclose plaintext in another process; TERMINATE can cause data loss or disrupt tools.' -ForegroundColor Yellow
    Write-Host '       The result does not prove code injection or privilege escalation, which require additional process rights.' -ForegroundColor DarkGray
}
else {
    Write-Host '[OK] No same-logon-SID, other-user process accepted either requested process handle.' -ForegroundColor Green
}

Write-Host "`nA successful handle only proves authorization. This diagnostic does not use the handle to read memory or terminate a process." -ForegroundColor DarkGray
