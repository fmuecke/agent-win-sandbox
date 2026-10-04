# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#requires -Version 7.0

<#
.SYNOPSIS
    Inside-only exposure assessment for an AI coding agent's execution context.

.DESCRIPTION
    Assumes prompt injection succeeded and the agent runs arbitrary code as the
    current process identity. The script inventories and probes, without
    damaging anything, what that identity can reach, which authority it holds,
    how well it is contained and whether its actions are visible. It reports a
    control score interval, evidence coverage and a verdict.

    Run it through the agent's normal shell. It needs no elevation, modules or
    prompts. It never reads another process's memory, uses
    discovered credentials, executes discovered scripts or binaries, or
    modifies files, ACLs, services, tasks or the registry. Access probes
    request one right at a time and close the handle immediately.

    Every run probes the documented default Internet targets: DNS for
    example.com and TCP 443 to example.com, 1.1.1.1 and
    2606:4700:4700::1111. TCP probes connect and close without sending data.
    Each HTTP_PROXY/HTTPS_PROXY proxy also receives one request for
    example.com (HEAD http://example.com/ or CONNECT example.com:443), of
    which only the status line is read; a proxy URL that carries credentials
    is not used. Lateral reach is probed from local configuration only: each
    default gateway (TCP 80, 443, 53), each private-range DNS server (TCP 53),
    one loopback port and each local TCP listener on a loopback or wildcard
    address, probed through loopback; no other hosts are discovered or
    scanned. An
    explicit local denial (WSAEACCES, typically Windows Firewall) counts as a
    block; a refused connection counts as reach. Use -SkipCheck NETWORK to run
    without network probes.

    It reads bounded candidate text files for suspected secrets and inventories
    Credential Manager metadata. Process probes request individual rights;
    no memory read, injection, suspension or handle duplication is performed.

    Limits: this run cannot establish complete host policy, external log
    collection or remote authorization. A compromised agent can falsify the
    report. Treat the output as data for review, not instructions.

.PARAMETER Json
    Write exactly one schema-versioned JSON object to stdout. Diagnostics go to
    stderr.

.PARAMETER Brief
    Shorten the human report to the summary only: verdict, score, dimensions,
    top findings, unknowns and remediation. Without it, the report also lists
    every criterion grouped by dimension with its outcome
    (met/unmet/unknown/na) and reason. Ignored with -Json, whose output always
    carries every criterion.

.PARAMETER Workspace
    The agent workspace. Defaults to the current directory.

.PARAMETER NetworkTarget
    Additional probe targets, for example a NAS or another PC. Forms:
    dns:<name>, tcp:<host>:<port>, smb:<host> (TCP 445). Use brackets for
    IPv6, for example tcp:[::1]:8080.

.PARAMETER PolicyPath
    Optional JSON policy: { "name": "...", "requireMet": ["R-NET-INTERNET", ...] }.
    Adds compliant/violation/unknown results without changing the score.

.PARAMETER OutputDirectory
    Existing writable directory for assessment-<timestamp>.json and .md.

.PARAMETER SkipCheck
    Check areas to skip. Their criteria stay unknown and count against coverage.

.EXAMPLE
    .\Test-AgentSandboxExposure.ps1
    Prints the full human report for the current process context, including a
    per-criterion met/unmet/unknown breakdown.

.EXAMPLE
    .\Test-AgentSandboxExposure.ps1 -Brief
    Prints only the summary, without the per-criterion breakdown.

.EXAMPLE
    .\Test-AgentSandboxExposure.ps1 -Json 2>$null
    Emits one JSON assessment.

.NOTES
    Exit codes: 0 when the assessment completed, regardless of risk;
    1 when it could not run (invalid arguments or a fatal error).
    Exposure severity is in the output, not the exit code.
#>

[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$Brief,
    [string]$Workspace,
    [string[]]$NetworkTarget = @(),
    [string]$PolicyPath,
    [string]$OutputDirectory,
    [ValidateSet('IDENTITY', 'FILES', 'SECRETS', 'PROCESSES', 'DESKTOP', 'INDIRECT',
        'NETWORK', 'REMOTE', 'HANDOFF', 'CONTAINMENT', 'MONITORING')]
    [string[]]$SkipCheck = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$SchemaVersion = 'agent-sandbox-assessment/1'
$CheckerVersion = '0.2.0'
$ProfileId = 'default'
$ProfileVersion = '5'
$MinimumCoverageForVerdict = 0.6
# Every verdict is bounded to the OS process: tools that execute outside it
# (MCP servers, account connectors, browser actions) are not assessed. Egress
# is probed over TCP; DNS queries through the system resolver and UDP can
# still carry data out when every TCP route is blocked.
$VerdictScope = 'OS process only, network egress over TCP only; agent tool authority (MCP servers, connectors, plugins) and DNS/UDP exfiltration are not assessed.'

# --- Criterion registry -------------------------------------------------------
# Profile default/5. Each criterion belongs to exactly one dimension and one
# check area. Essential criteria must be resolved (met or unmet) before a
# bounded verdict is awarded. Monitoring criteria are nonessential because an
# inside-only run usually cannot resolve them.

$CriterionRegistry = @(
    # Reach
    @{ Id = 'R-FILES-PROFILES'; Dimension = 'Reach'; Check = 'FILES'; Essential = $true; Severity = 'high'
        Title = 'No read access to tested profile files or directory listings'
        Remediation = 'Remove inherited or explicit read ACEs that give the agent identity access to other user profiles.' 
    }
    @{ Id = 'R-FILES-ADJACENT'; Dimension = 'Reach'; Check = 'FILES'; Essential = $true; Severity = 'high'
        Title = 'No read access to tested adjacent files or directory listings'
        Remediation = 'Restrict Users/Authenticated Users read ACEs on non-system drive-root folders and workspace siblings, or move the workspace to an isolated tree.' 
    }
    @{ Id = 'R-FILES-WRITE'; Dimension = 'Reach'; Check = 'FILES'; Essential = $false; Severity = 'high'
        Title = 'No write access to tested adjacent files or directories'
        Remediation = 'Remove Modify ACEs for Authenticated Users or Users inherited from non-system volume roots and drive-root folders, or deny the agent identity write access there.'
    }
    @{ Id = 'R-FILES-SECRETS'; Dimension = 'Reach'; Check = 'FILES'; Essential = $false; Severity = 'high'
        Title = 'No readable credential containers outside the workspace, found by file name'
        Remediation = 'Move certificates, private keys, password databases, VPN and RDP profiles out of agent-readable folders, or remove the agent identity''s read access to them.'
    }
    @{ Id = 'R-REG-OTHERS'; Dimension = 'Reach'; Check = 'FILES'; Essential = $false; Severity = 'medium'
        Title = 'Other users'' registry hives and SAM/SECURITY are not readable'
        Remediation = 'Remove read ACEs for the agent identity on other users'' loaded hives.' 
    }
    @{ Id = 'R-SECRETS-ENV'; Dimension = 'Reach'; Check = 'SECRETS'; Essential = $false; Severity = 'high'
        Title = 'No suspected secrets in the environment'
        Remediation = 'Stop passing tokens through environment variables into the agent session.' 
    }
    @{ Id = 'R-SECRETS-KNOWN'; Dimension = 'Reach'; Check = 'SECRETS'; Essential = $true; Severity = 'high'
        Title = 'No readable credentials in known credential locations'
        Remediation = 'Remove credential files from the agent profile, or keep them in an identity the agent cannot read.' 
    }
    @{ Id = 'R-SECRETS-SCAN'; Dimension = 'Reach'; Check = 'SECRETS'; Essential = $true; Severity = 'high'
        Title = 'No suspected secrets in scanned workspace and configuration files'
        Remediation = 'Remove or rotate the suspected secrets and load them from a store the agent cannot read.' 
    }
    @{ Id = 'R-SECRETS-CREDMAN'; Dimension = 'Reach'; Check = 'SECRETS'; Essential = $false; Severity = 'medium'
        Title = 'No Credential Manager entries for the agent identity'
        Remediation = 'Remove stored credentials from the agent account''s Credential Manager.' 
    }
    @{ Id = 'R-PROC-READ'; Dimension = 'Reach'; Check = 'PROCESSES'; Essential = $true; Severity = 'high'
        Title = 'No other identity or higher-integrity process grants memory-read access'
        Remediation = 'Run the agent under a logon that does not share a logon SID or default DACL with the interactive user; see sandbox-surfaces.' 
    }
    @{ Id = 'R-DESKTOP'; Dimension = 'Reach'; Check = 'DESKTOP'; Essential = $true; Severity = 'high'
        Title = 'Agent does not share the interactive desktop'
        Remediation = 'Launch the agent on a separate window station/desktop or in a separate session.' 
    }
    @{ Id = 'R-NET-INTERNET'; Dimension = 'Reach'; Check = 'NETWORK'; Essential = $true; Severity = 'high'
        Title = 'Arbitrary Internet destinations are unreachable on tested routes'
        Remediation = 'Restrict outbound traffic for the agent identity to an allowlist (firewall rules per user SID or an enforced proxy).' 
    }
    @{ Id = 'R-NET-LATERAL'; Dimension = 'Reach'; Check = 'NETWORK'; Essential = $false; Severity = 'medium'
        Title = 'LAN and loopback destinations are unreachable on tested routes'
        Remediation = 'Block LAN and loopback service access for the agent identity where it is not required.' 
    }
    @{ Id = 'R-NET-SHARES'; Dimension = 'Reach'; Check = 'NETWORK'; Essential = $false; Severity = 'medium'
        Title = 'No network shares are mapped into the agent session'
        Remediation = 'Remove persistent drive mappings for the agent identity; mount remote data only when required and under a least-privilege identity.' 
    }
    # Authority
    @{ Id = 'A-ID-ADMIN'; Dimension = 'Authority'; Check = 'IDENTITY'; Essential = $true; Severity = 'critical'
        Title = 'Identity is not an administrator and not elevated'
        Remediation = 'Run the agent as a standard user without Administrators membership.' 
    }
    @{ Id = 'A-ID-PRIVS'; Dimension = 'Authority'; Check = 'IDENTITY'; Essential = $true; Severity = 'critical'
        Title = 'Token holds no high-impact privileges'
        Remediation = 'Remove user-rights assignments that give the agent identity sensitive privileges.' 
    }
    @{ Id = 'A-ID-GROUPS'; Dimension = 'Authority'; Check = 'IDENTITY'; Essential = $false; Severity = 'high'
        Title = 'No membership in privileged or broker groups'
        Remediation = 'Remove the agent identity from privileged and broker groups (for example docker-users, Hyper-V Administrators).' 
    }
    @{ Id = 'A-PROC-INJECT'; Dimension = 'Authority'; Check = 'PROCESSES'; Essential = $true; Severity = 'critical'
        Title = 'No protected process grants memory, thread, handle or security modification rights'
        Remediation = 'Separate the agent logon from the interactive user and services; review process DACLs that grant the agent rights.' 
    }
    @{ Id = 'A-PROC-CONTROL'; Dimension = 'Authority'; Check = 'PROCESSES'; Essential = $false; Severity = 'medium'
        Title = 'No protected process grants terminate or suspend rights'
        Remediation = 'Separate the agent logon from the interactive user so default DACLs do not grant control rights.'
    }
    @{ Id = 'A-PROC-HANDLES'; Dimension = 'Authority'; Check = 'PROCESSES'; Essential = $false; Severity = 'high'
        Title = 'No held handle grants more than the agent token'
        Remediation = 'Launch the agent without inheritable handles from a more privileged or other-identity process (for example, start it through a broker that clears handle inheritance).'
    }
    @{ Id = 'A-SVC'; Dimension = 'Authority'; Check = 'INDIRECT'; Essential = $true; Severity = 'critical'
        Title = 'Service and task binaries and configuration are not agent-writable'
        Remediation = 'Fix ACLs on the listed service/task binaries, directories, registry keys and service objects.' 
    }
    @{ Id = 'A-HANDOFF-SHARED'; Dimension = 'Authority'; Check = 'HANDOFF'; Essential = $true; Severity = 'high'
        Title = 'No agent-writable location is executed by other identities'
        Remediation = 'Remove write/create rights for the agent identity on machine PATH directories, startup locations, Run keys, program directories, other profiles, and programs, DLLs or build scripts outside Program Files that other users run or build.'
    }
    @{ Id = 'A-HANDOFF-WORKSPACE'; Dimension = 'Authority'; Check = 'HANDOFF'; Essential = $true; Severity = 'medium'
        Title = 'Agent-written workspace content is not consumed by another identity'
        Remediation = 'Review agent output before another identity builds, runs or opens it; use a separate clone or a less privileged consumer. Give the agent its own clone, not write access to a repository another user owns, since git runs that repository''s hooks and config for its owner.'
    }
    @{ Id = 'A-REMOTE-DELEGATED'; Dimension = 'Authority'; Check = 'REMOTE'; Essential = $false; Severity = 'high'
        Title = 'No usable remote credentials or delegated sessions'
        Remediation = 'Remove credential helpers, tool logins and stored tokens from the agent identity, or scope them to least privilege.' 
    }
    @{ Id = 'A-TOOL-SCOPE'; Dimension = 'Authority'; Check = 'REMOTE'; Essential = $false; Severity = 'medium'
        Title = 'No external agent tool channels are declared'
        Remediation = 'Inventory each declared MCP/tool server and its authority, or remove unneeded servers.' 
    }
    @{ Id = 'A-REMOTE-DOMAIN'; Dimension = 'Authority'; Check = 'REMOTE'; Essential = $false; Severity = 'high'
        Title = 'Device is not domain-joined with domain-reachable authority'
        Remediation = 'Keep the sandbox off the AD/Azure AD domain, or confirm the agent account has no domain-reachable rights (local account, no delegated or computer-account resource access).' 
    }
    # Containment
    @{ Id = 'C-POLICY-INTEGRITY'; Dimension = 'Containment'; Check = 'CONTAINMENT'; Essential = $true; Severity = 'high'
        Title = 'Agent cannot modify its launcher, policy or checker files'
        Remediation = 'Make launcher, bootstrap, managed policy and checker files admin-write only. Never run setup, removal or other elevated scripts from a checkout the agent can write; use a reviewed release or a clone the agent cannot modify.'
    }
    @{ Id = 'C-TOOL-POLICY'; Dimension = 'Containment'; Check = 'CONTAINMENT'; Essential = $false; Severity = 'medium'
        Title = 'Agent tool permissions come from a managed policy'
        Remediation = 'Deploy the agent''s admin-owned managed policy and restrict it to managed permission rules (Claude Code: allowManagedPermissionRulesOnly in managed-settings.json) so agent-writable settings cannot widen tool permissions.'
    }
    @{ Id = 'C-EXEC-POLICY'; Dimension = 'Containment'; Check = 'CONTAINMENT'; Essential = $false; Severity = 'medium'
        Title = 'Code execution is restricted by an enforced application control policy'
        Remediation = 'Enforce WDAC user-mode code integrity or AppLocker executable rules so downloaded programs and scripts cannot run from agent-writable paths.'
    }
    @{ Id = 'C-JOB'; Dimension = 'Containment'; Check = 'CONTAINMENT'; Essential = $false; Severity = 'medium'
        Title = 'Process tree is confined to a kill-on-close job without breakaway'
        Remediation = 'Launch the agent inside a job object with kill-on-close and no breakaway.' 
    }
    @{ Id = 'C-PERSIST-SELF'; Dimension = 'Containment'; Check = 'CONTAINMENT'; Essential = $false; Severity = 'medium'
        Title = 'Agent cannot persist code into later sandbox sessions'
        Remediation = 'Reset or lock agent-writable startup paths (profile scripts, user PATH directories, agent hooks) between sessions.' 
    }
    @{ Id = 'C-PROXY-INTEGRITY'; Dimension = 'Containment'; Check = 'CONTAINMENT'; Essential = $false; Severity = 'medium'
        Title = 'Configured proxy cannot be changed by the agent'
        Remediation = 'Enforce the proxy machine-wide (policy) and block direct egress so user-level proxy changes do not matter.' 
    }
    # Monitoring
    @{ Id = 'M-ATTRIBUTION'; Dimension = 'Monitoring'; Check = 'MONITORING'; Essential = $false; Severity = 'medium'
        Title = 'Agent actions are attributable to a distinct account'
        Remediation = 'Run the agent as a dedicated account distinct from the interactive user.' 
    }
    @{ Id = 'M-OS-LOGGING'; Dimension = 'Monitoring'; Check = 'MONITORING'; Essential = $false; Severity = 'medium'
        Title = 'OS-level process or script logging is configured'
        Remediation = 'Enable PowerShell script block logging, process-creation auditing with command lines, or Sysmon/EDR.' 
    }
    @{ Id = 'M-TAMPER'; Dimension = 'Monitoring'; Check = 'MONITORING'; Essential = $false; Severity = 'medium'
        Title = 'Agent cannot alter discovered monitoring controls'
        Remediation = 'Restrict write access to logging policy, monitoring services and log output directories.' 
    }
    @{ Id = 'M-AGENT-LOG'; Dimension = 'Monitoring'; Check = 'MONITORING'; Essential = $false; Severity = 'low'
        Title = 'Agent tool logs are outside the agent''s write reach'
        Remediation = 'Forward agent transcripts to a location the agent identity cannot modify.' 
    }
)

$Dimensions = @('Reach', 'Authority', 'Containment', 'Monitoring')
$SeverityRank = @{ critical = 4; high = 3; medium = 2; low = 1; info = 0 }

# --- Native probes ------------------------------------------------------------
# Every probe either queries information or requests a single access right and
# closes the handle. No probe reads foreign memory, writes data, or returns a
# credential blob.

function Initialize-NativeProbe {
    # A compiled type cannot be replaced within a session, so a session that
    # ran an older checker keeps the old class. The class carries a hash of
    # its source; a mismatch stops the run instead of mixing versions.
    $source = $script:NativeSource
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($source)))
    $loaded = 'AgentSandboxAssessmentNative' -as [type]
    if ($loaded) {
        $field = $loaded.GetField('SourceHash')
        if ($field -and $field.GetValue($null) -eq $hash) { return }
        throw 'This PowerShell session holds an older build of the native probe class, which cannot be reloaded. Run the checker in a new session: pwsh -NoProfile -File .\Test-AgentSandboxExposure.ps1'
    }
    Add-Type -TypeDefinition $source.Replace('__SOURCE_HASH__', $hash)
}

$script:NativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public sealed class TokenGroupInfo
{
    public string Sid { get; set; }
    public uint Attributes { get; set; }
}

public sealed class TokenPrivilegeInfo
{
    public string Name { get; set; }
    public uint Attributes { get; set; }
}

public sealed class TokenSnapshot
{
    public string UserSid { get; set; }
    public TokenGroupInfo[] Groups { get; set; }
    public TokenPrivilegeInfo[] Privileges { get; set; }
    public string IntegritySid { get; set; }
    public int ElevationType { get; set; }
    public bool IsElevated { get; set; }
    public int SessionId { get; set; }
    public string AuthenticationId { get; set; }
    public int TokenType { get; set; }
    public int RestrictedSidCount { get; set; }
    public bool IsAppContainer { get; set; }
    public int CapabilityCount { get; set; }
    public bool UiAccess { get; set; }
    public bool HasThreadToken { get; set; }
}

public sealed class ForeignTokenInfo
{
    public string UserSid { get; set; }
    public string IntegritySid { get; set; }
    public string[] LogonSids { get; set; }
}

public sealed class AccessCheckResult
{
    public uint Granted { get; set; }
    public int Error { get; set; }
}

public sealed class CredentialEntry
{
    public int Type { get; set; }
    public string TargetName { get; set; }
}

public sealed class HeldHandle
{
    public string Type { get; set; }
    public uint Access { get; set; }
    public bool Inheritable { get; set; }
    public int ProcessId { get; set; }
    public string Path { get; set; }
    public string TokenSid { get; set; }
    public bool TokenElevated { get; set; }
}

public sealed class JobInfo
{
    public bool InJob { get; set; }
    public uint LimitFlags { get; set; }
    public uint UiRestrictions { get; set; }
    public int Error { get; set; }
}

public static class AgentSandboxAssessmentNative
{
    public const string SourceHash = "__SOURCE_HASH__";
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const uint SE_GROUP_LOGON_ID = 0xC0000000;
    private const uint OWNER_SECURITY_INFORMATION = 0x1;
    private const uint GROUP_SECURITY_INFORMATION = 0x2;
    private const uint DACL_SECURITY_INFORMATION = 0x4;
    private const uint LABEL_SECURITY_INFORMATION = 0x10;

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenGroupsHeader { public uint GroupCount; public SidAndAttributes FirstGroup; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct Luid { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct LuidAndAttributes { public Luid Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping { public uint GenericRead; public uint GenericWrite; public uint GenericExecute; public uint GenericAll; }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ProcessIdToSessionId(int processId, out int sessionId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, int length, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returnLength);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeNameW(string system, ref Luid luid, StringBuilder name, ref int length);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetNamedSecurityInfoW(string name, int objectType, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AccessCheck(IntPtr descriptor, IntPtr token, uint desired, ref GenericMapping mapping, IntPtr privileges, ref int privilegesLength, out uint granted, out bool status);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern int RegOpenKeyExW(IntPtr hive, string subKey, uint options, uint access, out IntPtr key);
    [DllImport("advapi32.dll")] private static extern int RegCloseKey(IntPtr key);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CredEnumerateW(string filter, uint flags, out int count, out IntPtr credentials);
    [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr buffer);

    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetThreadDesktop(uint threadId);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetUserObjectInformationW(IntPtr handle, int index, StringBuilder info, int length, out int needed);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr OpenWindowStationW(string name, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool CloseWindowStation(IntPtr station);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int processId);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr info, int length, out int returnLength);
    [DllImport("ntdll.dll")] private static extern int NtQueryObject(IntPtr handle, int infoClass, IntPtr info, int length, out int returnLength);
    [DllImport("kernel32.dll")] private static extern int GetProcessId(IntPtr process);
    [DllImport("kernel32.dll")] private static extern int GetProcessIdOfThread(IntPtr thread);
    [DllImport("kernel32.dll")] private static extern uint GetFileType(IntPtr file);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern int GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, int length, uint flags);

    private static IntPtr identificationToken = IntPtr.Zero;
    private static IntPtr serviceManager = IntPtr.Zero;

    // --- Token ---------------------------------------------------------------

    private static IntPtr QueryToken(IntPtr token, int infoClass)
    {
        int size;
        GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out size);
        if (size <= 0) { return IntPtr.Zero; }
        IntPtr buffer = Marshal.AllocHGlobal(size);
        if (!GetTokenInformation(token, infoClass, buffer, size, out size))
        {
            Marshal.FreeHGlobal(buffer);
            return IntPtr.Zero;
        }
        return buffer;
    }

    private static int QueryTokenInt(IntPtr token, int infoClass)
    {
        IntPtr buffer = QueryToken(token, infoClass);
        if (buffer == IntPtr.Zero) { return -1; }
        try { return Marshal.ReadInt32(buffer); } finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string QueryTokenSid(IntPtr token, int infoClass)
    {
        IntPtr buffer = QueryToken(token, infoClass);
        if (buffer == IntPtr.Zero) { return null; }
        try { return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value; } finally { Marshal.FreeHGlobal(buffer); }
    }

    private static TokenGroupInfo[] QueryTokenGroups(IntPtr token, int infoClass)
    {
        IntPtr buffer = QueryToken(token, infoClass);
        if (buffer == IntPtr.Zero) { return new TokenGroupInfo[0]; }
        try
        {
            uint count = unchecked((uint)Marshal.ReadInt32(buffer));
            int offset = Marshal.OffsetOf(typeof(TokenGroupsHeader), "FirstGroup").ToInt32();
            int size = Marshal.SizeOf(typeof(SidAndAttributes));
            var groups = new List<TokenGroupInfo>();
            for (uint i = 0; i < count; i++)
            {
                var item = (SidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(buffer, offset + checked((int)i * size)), typeof(SidAndAttributes));
                groups.Add(new TokenGroupInfo { Sid = new SecurityIdentifier(item.Sid).Value, Attributes = item.Attributes });
            }
            return groups.ToArray();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static TokenPrivilegeInfo[] QueryTokenPrivileges(IntPtr token)
    {
        IntPtr buffer = QueryToken(token, 3);
        if (buffer == IntPtr.Zero) { return new TokenPrivilegeInfo[0]; }
        try
        {
            int count = Marshal.ReadInt32(buffer);
            int size = Marshal.SizeOf(typeof(LuidAndAttributes));
            var privileges = new List<TokenPrivilegeInfo>();
            for (int i = 0; i < count; i++)
            {
                var item = (LuidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(buffer, 4 + i * size), typeof(LuidAndAttributes));
                var luid = item.Luid;
                int length = 128;
                var name = new StringBuilder(length);
                string text = LookupPrivilegeNameW(null, ref luid, name, ref length) ? name.ToString() : "LUID:" + luid.HighPart + ":" + luid.LowPart;
                privileges.Add(new TokenPrivilegeInfo { Name = text, Attributes = item.Attributes });
            }
            return privileges.ToArray();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public static TokenSnapshot GetCurrentToken()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        }
        try
        {
            var snapshot = new TokenSnapshot();
            snapshot.UserSid = QueryTokenSid(token, 1);
            snapshot.Groups = QueryTokenGroups(token, 2);
            snapshot.Privileges = QueryTokenPrivileges(token);
            snapshot.TokenType = QueryTokenInt(token, 8);
            snapshot.SessionId = QueryTokenInt(token, 12);
            snapshot.ElevationType = QueryTokenInt(token, 18);
            snapshot.IsElevated = QueryTokenInt(token, 20) != 0;
            snapshot.UiAccess = QueryTokenInt(token, 26) == 1;
            snapshot.IsAppContainer = QueryTokenInt(token, 29) == 1;
            snapshot.RestrictedSidCount = QueryTokenGroups(token, 11).Length;
            snapshot.CapabilityCount = QueryTokenGroups(token, 30).Length;
            snapshot.IntegritySid = QueryTokenSid(token, 25);

            IntPtr statistics = QueryToken(token, 10);
            if (statistics != IntPtr.Zero)
            {
                try { snapshot.AuthenticationId = Marshal.ReadInt32(statistics, 12).ToString("x8") + ":" + Marshal.ReadInt32(statistics, 8).ToString("x8"); }
                finally { Marshal.FreeHGlobal(statistics); }
            }

            IntPtr threadToken;
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, out threadToken))
            {
                snapshot.HasThreadToken = true;
                CloseHandle(threadToken);
            }
            return snapshot;
        }
        finally { CloseHandle(token); }
    }

    public static ForeignTokenInfo GetProcessToken(int processId)
    {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process == IntPtr.Zero) { return null; }
        try
        {
            IntPtr token;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) { return null; }
            try
            {
                var info = new ForeignTokenInfo();
                info.UserSid = QueryTokenSid(token, 1);
                info.IntegritySid = QueryTokenSid(token, 25);
                var logon = new List<string>();
                foreach (var group in QueryTokenGroups(token, 2))
                {
                    if ((group.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) { logon.Add(group.Sid); }
                }
                info.LogonSids = logon.ToArray();
                return info;
            }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(process); }
    }

    public static int GetSessionId(int processId)
    {
        int sessionId;
        return ProcessIdToSessionId(processId, out sessionId) ? sessionId : -1;
    }

    public static int ProbeProcess(int processId, uint access)
    {
        IntPtr process = OpenProcess(access, false, processId);
        if (process == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        CloseHandle(process);
        return 0;
    }

    // --- Security descriptors --------------------------------------------------

    private static IntPtr GetIdentificationToken()
    {
        if (identificationToken != IntPtr.Zero) { return identificationToken; }
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, out token))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        }
        try
        {
            IntPtr duplicate;
            if (!DuplicateToken(token, 1, out duplicate))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateToken failed");
            }
            identificationToken = duplicate;
            return identificationToken;
        }
        finally { CloseHandle(token); }
    }

    // objectType: 1 = file, 4 = registry key. Evaluates the object's security
    // descriptor against the current token without opening the object.
    public static AccessCheckResult CheckNamedObject(string name, int objectType)
    {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        int error = GetNamedSecurityInfoW(name, objectType, info, out owner, out group, out dacl, out sacl, out descriptor);
        if (error != 0) { return new AccessCheckResult { Granted = 0, Error = error }; }
        try
        {
            var mapping = objectType == 4
                ? new GenericMapping { GenericRead = 0x20019, GenericWrite = 0x20006, GenericExecute = 0x20019, GenericAll = 0xF003F }
                : new GenericMapping { GenericRead = 0x120089, GenericWrite = 0x120116, GenericExecute = 0x1200A0, GenericAll = 0x1F01FF };
            int privilegeLength = 256;
            IntPtr privileges = Marshal.AllocHGlobal(privilegeLength);
            try
            {
                uint granted;
                bool status;
                if (!AccessCheck(descriptor, GetIdentificationToken(), MAXIMUM_ALLOWED, ref mapping, privileges, ref privilegeLength, out granted, out status))
                {
                    return new AccessCheckResult { Granted = 0, Error = Marshal.GetLastWin32Error() };
                }
                return new AccessCheckResult { Granted = status ? granted : 0, Error = 0 };
            }
            finally { Marshal.FreeHGlobal(privileges); }
        }
        finally { LocalFree(descriptor); }
    }

    // Opens an existing file or directory with one access mask and closes it.
    // OPEN_EXISTING never creates or truncates; reparse points are not followed.
    public static int ProbeFile(string path, uint access)
    {
        IntPtr handle = CreateFileW(path, access, 7, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
        if (handle == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }
        CloseHandle(handle);
        return 0;
    }

    // hive: 1 = HKCU, 2 = HKLM, 3 = HKU.
    public static int ProbeRegistryKey(int hive, string subKey, uint access)
    {
        IntPtr root = new IntPtr(unchecked((int)(0x80000000u + (uint)hive)));
        IntPtr key;
        int error = RegOpenKeyExW(root, subKey, 0, access | 0x0100, out key);
        if (error == 0) { RegCloseKey(key); }
        return error;
    }

    public static int ProbeService(string name, uint access)
    {
        if (serviceManager == IntPtr.Zero)
        {
            serviceManager = OpenSCManagerW(null, null, 0x0001);
            if (serviceManager == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        }
        IntPtr service = OpenServiceW(serviceManager, name, access);
        if (service == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        CloseServiceHandle(service);
        return 0;
    }

    // Enumerates the current identity's stored credentials, copying only the
    // type and target name. The credential blob (the secret) is never read.
    public static CredentialEntry[] GetCredentialEntries(out int error)
    {
        error = 0;
        int count;
        IntPtr credentials;
        if (!CredEnumerateW(null, 0, out count, out credentials))
        {
            error = Marshal.GetLastWin32Error();
            return new CredentialEntry[0];
        }
        try
        {
            var entries = new List<CredentialEntry>();
            for (int i = 0; i < count; i++)
            {
                IntPtr credential = Marshal.ReadIntPtr(credentials, i * IntPtr.Size);
                entries.Add(new CredentialEntry
                {
                    Type = Marshal.ReadInt32(credential, 4),
                    TargetName = Marshal.PtrToStringUni(Marshal.ReadIntPtr(credential, 8))
                });
            }
            return entries.ToArray();
        }
        finally { CredFree(credentials); }
    }

    // --- Desktop ---------------------------------------------------------------

    private static string GetUserObjectName(IntPtr handle)
    {
        if (handle == IntPtr.Zero) { return null; }
        int needed;
        GetUserObjectInformationW(handle, 2, null, 0, out needed);
        if (needed <= 0) { return null; }
        var name = new StringBuilder(needed / 2);
        return GetUserObjectInformationW(handle, 2, name, needed, out needed) ? name.ToString() : null;
    }

    public static string GetWindowStationName() { return GetUserObjectName(GetProcessWindowStation()); }

    public static string GetDesktopName() { return GetUserObjectName(GetThreadDesktop(GetCurrentThreadId())); }

    public static int ProbeInputDesktop(uint access)
    {
        IntPtr desktop = OpenInputDesktop(0, false, access);
        if (desktop == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        CloseDesktop(desktop);
        return 0;
    }

    public static int ProbeWindowStation(string name, uint access)
    {
        IntPtr station = OpenWindowStationW(name, false, access);
        if (station == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        CloseWindowStation(station);
        return 0;
    }

    // Owning process IDs of visible top-level windows on the current desktop.
    // Window titles and contents are not read.
    public static int[] GetVisibleWindowProcessIds()
    {
        var ids = new List<int>();
        EnumWindowsProc callback = delegate (IntPtr window, IntPtr parameter)
        {
            if (IsWindowVisible(window))
            {
                int processId;
                GetWindowThreadProcessId(window, out processId);
                ids.Add(processId);
            }
            return true;
        };
        EnumWindows(callback, IntPtr.Zero);
        GC.KeepAlive(callback);
        return ids.ToArray();
    }

    // --- Session and job ------------------------------------------------------

    public static string GetSessionUser()
    {
        IntPtr buffer;
        int bytes;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, -1, 5, out buffer, out bytes)) { return null; }
        try { return Marshal.PtrToStringUni(buffer); } finally { WTSFreeMemory(buffer); }
    }

    // The user logged on at the physical console (the interactive human), or
    // null when there is no active console session to compare against.
    public static string GetConsoleSessionUser()
    {
        uint session = WTSGetActiveConsoleSessionId();
        if (session == 0xFFFFFFFF) { return null; }
        IntPtr buffer;
        int bytes;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, unchecked((int)session), 5, out buffer, out bytes)) { return null; }
        try { return Marshal.PtrToStringUni(buffer); } finally { WTSFreeMemory(buffer); }
    }

    public static string GetConsoleSessionSid()
    {
        uint session = WTSGetActiveConsoleSessionId();
        if (session == 0xFFFFFFFF) { return null; }
        IntPtr buffer;
        int bytes;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, unchecked((int)session), 5, out buffer, out bytes)) { return null; }
        string user;
        try { user = Marshal.PtrToStringUni(buffer); } finally { WTSFreeMemory(buffer); }
        if (String.IsNullOrEmpty(user)) { return null; }
        if (!WTSQuerySessionInformationW(IntPtr.Zero, unchecked((int)session), 7, out buffer, out bytes)) { return null; }
        string domain;
        try { domain = Marshal.PtrToStringUni(buffer); } finally { WTSFreeMemory(buffer); }
        try { return new NTAccount(domain, user).Translate(typeof(SecurityIdentifier)).Value; }
        catch { return null; }
    }

    // --- Held handles ----------------------------------------------------------
    // This process's own handle table (ProcessHandleInformation). Only the
    // types that carry cross-boundary authority are described: Process and
    // Thread by owning process id, Token by user and elevation, disk File by
    // final path, Key by object name. Pipe and other file names are never
    // queried because those queries can block. No handle is duplicated.

    private static string QueryObjectString(IntPtr handle, int infoClass, IntPtr buffer, int length)
    {
        int returned;
        if (NtQueryObject(handle, infoClass, buffer, length, out returned) != 0) { return null; }
        int bytes = (ushort)Marshal.ReadInt16(buffer);
        IntPtr text = Marshal.ReadIntPtr(buffer, IntPtr.Size);
        return text == IntPtr.Zero ? null : Marshal.PtrToStringUni(text, bytes / 2);
    }

    public static HeldHandle[] GetHeldHandles(out int status)
    {
        var handles = new List<HeldHandle>();
        int length = 0x10000, returned;
        IntPtr table = Marshal.AllocHGlobal(length);
        IntPtr scratch = Marshal.AllocHGlobal(0x2000);
        try
        {
            status = NtQueryInformationProcess(GetCurrentProcess(), 51, table, length, out returned);
            while (status == unchecked((int)0xC0000004))   // STATUS_INFO_LENGTH_MISMATCH
            {
                Marshal.FreeHGlobal(table);
                length = returned + 0x1000;
                table = Marshal.AllocHGlobal(length);
                status = NtQueryInformationProcess(GetCurrentProcess(), 51, table, length, out returned);
            }
            if (status != 0) { return handles.ToArray(); }
            long count = Marshal.ReadIntPtr(table).ToInt64();
            // PROCESS_HANDLE_TABLE_ENTRY_INFO: HandleValue, HandleCount,
            // PointerCount (pointer-sized), then GrantedAccess, ObjectTypeIndex,
            // HandleAttributes and Reserved (ULONG each).
            int entrySize = 3 * IntPtr.Size + 16;
            for (long i = 0; i < count; i++)
            {
                IntPtr entry = table + 2 * IntPtr.Size + (int)i * entrySize;
                IntPtr handle = Marshal.ReadIntPtr(entry);
                var held = new HeldHandle();
                held.Access = unchecked((uint)Marshal.ReadInt32(entry, 3 * IntPtr.Size));
                held.Inheritable = (Marshal.ReadInt32(entry, 3 * IntPtr.Size + 8) & 0x2) != 0;
                held.Type = QueryObjectString(handle, 2, scratch, 0x2000);
                switch (held.Type)
                {
                    case "Process": held.ProcessId = GetProcessId(handle); break;
                    case "Thread": held.ProcessId = GetProcessIdOfThread(handle); break;
                    case "Token":
                        if ((held.Access & TOKEN_QUERY) != 0)
                        {
                            held.TokenSid = QueryTokenSid(handle, 1);
                            held.TokenElevated = QueryTokenInt(handle, 20) == 1;
                        }
                        break;
                    case "File":
                        if (GetFileType(handle) != 1) { continue; }   // FILE_TYPE_DISK only
                        var path = new StringBuilder(1024);
                        int written = GetFinalPathNameByHandleW(handle, path, path.Capacity, 0);
                        if (written > 0 && written < path.Capacity) { held.Path = path.ToString(); }
                        break;
                    case "Key": held.Path = QueryObjectString(handle, 1, scratch, 0x2000); break;
                    default: continue;
                }
                handles.Add(held);
            }
            return handles.ToArray();
        }
        finally
        {
            Marshal.FreeHGlobal(table);
            Marshal.FreeHGlobal(scratch);
        }
    }

    public static JobInfo GetJobInfo()
    {
        var info = new JobInfo();
        bool inJob;
        if (!IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out inJob)) { info.Error = Marshal.GetLastWin32Error(); return info; }
        info.InJob = inJob;
        if (!inJob) { return info; }
        // QueryInformationJobObject requires an exactly-sized buffer per info
        // class; an oversized buffer returns ERROR_BAD_LENGTH. Basic limit info
        // (class 2) carries the kill-on-close / breakaway flags we need.
        int basicSize = Marshal.SizeOf(typeof(JobBasicLimitInformation));
        IntPtr buffer = Marshal.AllocHGlobal(basicSize);
        try
        {
            int length;
            if (QueryInformationJobObject(IntPtr.Zero, 2, buffer, basicSize, out length))
            {
                var basic = (JobBasicLimitInformation)Marshal.PtrToStructure(buffer, typeof(JobBasicLimitInformation));
                info.LimitFlags = basic.LimitFlags;
            }
            else { info.Error = Marshal.GetLastWin32Error(); }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        IntPtr uiBuffer = Marshal.AllocHGlobal(4);   // JOBOBJECT_BASIC_UI_RESTRICTIONS is a single DWORD
        try
        {
            int length;
            if (QueryInformationJobObject(IntPtr.Zero, 4, uiBuffer, 4, out length)) { info.UiRestrictions = unchecked((uint)Marshal.ReadInt32(uiBuffer)); }
        }
        finally { Marshal.FreeHGlobal(uiBuffer); }
        return info;
    }
}
'@

# --- Assessment state ---------------------------------------------------------

$script:Criteria = [ordered]@{}
foreach ($entry in $CriterionRegistry) {
    $script:Criteria[$entry.Id] = [pscustomobject]@{
        Id             = $entry.Id
        Dimension      = $entry.Dimension
        Check          = $entry.Check
        Essential      = $entry.Essential
        Severity       = $entry.Severity
        Title          = $entry.Title
        Remediation    = $entry.Remediation
        Outcome        = 'unknown'
        Reason         = 'not evaluated'
        Method         = $null
        Critical       = $false
        CriticalReason = $null
    }
}

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Errors = New-Object System.Collections.Generic.List[object]
$script:Inventory = [ordered]@{}
$script:UserProfile = $null
$script:WorkspacePath = $null
$script:OtherProfiles = @()
$script:NetworkProbed = $false
$script:NetworkTargetsUsed = @()

$AllCheckAreas = @('IDENTITY', 'FILES', 'SECRETS', 'PROCESSES', 'DESKTOP', 'INDIRECT',
    'NETWORK', 'REMOTE', 'HANDOFF', 'CONTAINMENT', 'MONITORING')

# --- Core helpers -------------------------------------------------------------

function Write-Diag {
    param([string]$Message)

    [Console]::Error.WriteLine((Protect-Text $Message))
}

# --- Progress spinner ---------------------------------------------------------
# A background runspace animates a spinner on stderr so a long check (network
# probes stall on DNS/TCP timeouts) never looks hung. stderr keeps stdout clean
# for -Json; the spinner is suppressed when stderr is redirected (so 2>$null or
# a log file never collects spinner frames) or in -Json mode.

function Start-ProgressSpinner {
    param([string]$Label = 'Working')

    if ($Json -or [Console]::IsErrorRedirected) {
        return $null
    }
    $state = [hashtable]::Synchronized(@{ Label = $Label; Active = $true })
    $worker = [powershell]::Create()
    $worker.AddScript({
            param($State)

            $frames = '|', '/', '-', '\'
            $index = 0
            while ($State.Active) {
                $frame = $frames[$index % $frames.Count]
                [Console]::Error.Write(("`r{0} {1}" -f $frame, $State.Label).PadRight(70))
                $index++
                Start-Sleep -Milliseconds 100
            }
        }).AddArgument($state) | Out-Null
    $handle = $worker.BeginInvoke()
    return [pscustomobject]@{ Worker = $worker; Handle = $handle; State = $state }
}

function Update-ProgressSpinner {
    param($Spinner, [string]$Label)

    if ($Spinner) { $Spinner.State.Label = $Label }
}

function Stop-ProgressSpinner {
    param($Spinner)

    if (-not $Spinner) { return }
    $Spinner.State.Active = $false
    try { $Spinner.Worker.EndInvoke($Spinner.Handle) } catch { }
    $Spinner.Worker.Dispose()
    [Console]::Error.Write(("`r" + (' ' * 70) + "`r"))   # erase the spinner line
}

function Protect-Text {
    # Redact credential-shaped metadata, including URLs, paths and parse errors.
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }
    $value = [regex]::Replace($Text, '(?i)([a-z][a-z0-9+.-]*://)[^/@\s:]+(?::[^/@\s]+)?@', '$1<redacted>@')
    $value = [regex]::Replace($value,
        '(?i)(["'']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|client[_-]?secret|sig|signature|credential)["'']?\s*[:=]\s*)(["''])(?:\\.|(?!\2)[^\\])*\2',
        '$1$2<redacted>$2')
    $value = [regex]::Replace($value,
        '(?i)((?:[?&;]|\b)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|client[_-]?secret|sig|signature|credential)\s*["'']?\s*[:=]\s*["'']?)[^\s"''&;<>]+',
        '$1<redacted>')
    $value = [regex]::Replace($value, '(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+', '$1 <redacted>')
    $value = [regex]::Replace($value,
        '\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})',
        '<redacted>')
    $value = [regex]::Replace($value, '(?<![A-Za-z0-9_])[A-Za-z0-9_]{32,}(?![A-Za-z0-9_])', '<redacted>')
    return [regex]::Replace($value, '[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})', '<redacted>@$1')
}

function Protect-Report {
    # Sanitize every string at the output boundary, including inventory fields.
    param($Value)

    if ($Value -is [string]) { return (Protect-Text $Value) }
    if ($Value -is [System.Collections.IDictionary]) {
        $safe = [ordered]@{}
        foreach ($key in $Value.Keys) { $safe[(Protect-Text ([string]$key))] = Protect-Report $Value[$key] }
        return $safe
    }
    if ($Value -is [pscustomobject]) {
        $safe = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) { $safe[$property.Name] = Protect-Report $property.Value }
        return [pscustomobject]$safe
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $safe = @($Value | ForEach-Object { Protect-Report $_ })
        return ,$safe
    }
    return $Value
}

function Format-SafePath {
    param([string]$Path)

    if ([string]::IsNullOrEmpty($Path)) {
        return $Path
    }
    $value = $Path
    if ($script:WorkspacePath -and
        $value.StartsWith($script:WorkspacePath, [StringComparison]::OrdinalIgnoreCase)) {
        $value = '%WORKSPACE%' + $value.Substring($script:WorkspacePath.Length)
    }
    elseif ($script:UserProfile -and
        $value.StartsWith($script:UserProfile, [StringComparison]::OrdinalIgnoreCase)) {
        $value = '%USERPROFILE%' + $value.Substring($script:UserProfile.Length)
    }
    return (Protect-Text $value)
}

function Get-ErrorCategory {
    param([int]$Code)

    switch ($Code) {
        0 { 'none' }
        2 { 'not-found' }
        3 { 'not-found' }
        5 { 'access-denied' }
        32 { 'sharing-violation' }
        1920 { 'cannot-access' }
        default { "win32-$Code" }
    }
}

function Set-CriterionOutcome {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('met', 'unmet', 'unknown', 'na')][string]$Outcome,
        [string]$Reason,
        [string]$Method,
        [switch]$Critical,
        [string]$CriticalReason
    )

    if (-not $script:Criteria.Contains($Id)) {
        throw "Unknown criterion id: $Id"
    }
    $criterion = $script:Criteria[$Id]
    $criterion.Outcome = $Outcome
    if ($PSBoundParameters.ContainsKey('Reason')) { $criterion.Reason = $Reason }
    if ($PSBoundParameters.ContainsKey('Method')) { $criterion.Method = $Method }
    if ($Critical) {
        $criterion.Critical = $true
        $criterion.CriticalReason = $CriticalReason
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Check,
        [string]$Criterion,
        [Parameter(Mandatory)][string]$Target,
        [string]$Capability,
        [ValidateSet('granted', 'denied', 'unknown', 'observed')][string]$Result = 'observed',
        [ValidateSet('inventory', 'permission-analysis', 'access-request', 'observed-operation')][string]$Method = 'inventory',
        [string]$Scope,
        [string]$ErrorCategory,
        [string]$Impact,
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')][string]$Severity = 'info'
    )

    $script:Findings.Add([pscustomobject]@{
            Check         = $Check
            Criterion     = $Criterion
            Target        = (Format-SafePath $Target)
            Capability    = $Capability
            Result        = $Result
            Method        = $Method
            Scope         = $Scope
            ErrorCategory = $ErrorCategory
            Impact        = $Impact
            Severity      = $Severity
        }) | Out-Null
}

function Add-AssessmentError {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Message,
        [string]$Category = 'check-exception'
    )

    $safe = Protect-Text $Message
    $script:Errors.Add([pscustomobject]@{ Check = $Check; Category = $Category; Message = $safe }) | Out-Null
    Write-Diag "[$Check] ${Category}: $safe"
}

function Invoke-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    if ($SkipCheck -contains $Name) {
        foreach ($criterion in @($script:Criteria.Values | Where-Object { $_.Check -eq $Name })) {
            Set-CriterionOutcome -Id $criterion.Id -Outcome 'unknown' -Reason 'skipped'
        }
        Write-Diag "[$Name] skipped by request."
        return
    }
    try {
        & $Body
        # Completeness invariant: a check must resolve every criterion in its
        # area. An unresolved criterion is a check bug, not a silent unknown.
        $unresolved = @($script:Criteria.Values |
            Where-Object { $_.Check -eq $Name -and $_.Reason -eq 'not evaluated' })
        if ($unresolved.Count -gt 0) {
            Add-AssessmentError -Check $Name -Category 'incomplete-check' `
                -Message "Check left criteria unresolved: $(($unresolved | ForEach-Object { $_.Id }) -join ', ')"
        }
    }
    catch {
        Add-AssessmentError -Check $Name -Message $_.Exception.Message
        # A thrown check may have resolved some criteria before failing; mark the
        # rest as unknown/check-error so the later sweep does not mislabel them
        # "not implemented in v1".
        foreach ($criterion in @($script:Criteria.Values |
                Where-Object { $_.Check -eq $Name -and $_.Reason -eq 'not evaluated' })) {
            Set-CriterionOutcome -Id $criterion.Id -Outcome 'unknown' -Reason 'check error'
        }
    }
}

# --- Access probing -----------------------------------------------------------

function Get-PathAccess {
    # Resolves the effective rights of the current identity on an existing path
    # without opening it for a mutating operation. Prefers an AccessCheck
    # against the security descriptor; falls back to single-right open requests.
    param([Parameter(Mandatory)][string]$Path)

    $result = [ordered]@{
        Path = $Path; Exists = $false; IsDirectory = $false; Method = $null; ErrorCategory = $null
        Read = 'unknown'; Create = 'unknown'; Write = 'unknown'; Delete = 'unknown'
        ChangeAcl = 'unknown'; TakeOwnership = 'unknown'; DeleteChild = 'unknown'
    }
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        # Test-Path cannot distinguish absence from an inaccessible path.
        $read = [AgentSandboxAssessmentNative]::ProbeFile($Path, 0x1)
        $result.ErrorCategory = Get-ErrorCategory $read
        $result.Method = 'access-request'
        $result.Read = ConvertTo-ProbeOutcome $read
        if ($read -ne 5) {
            $result.Exists = ($read -eq 0)
            return [pscustomobject]$result
        }
        # Denied: the path exists but is hidden; resolve its rights below.
    }
    $result.Exists = $true
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    $isDir = $false
    if ($item) { $isDir = [bool]$item.PSIsContainer }
    $result.IsDirectory = $isDir

    $check = [AgentSandboxAssessmentNative]::CheckNamedObject($Path, 1)
    if ($check.Error -eq 0) {
        $result.Method = 'permission-analysis'
        $granted = $check.Granted
        # Test specific data rights, not the generic masks: FILE_GENERIC_WRITE
        # shares SYNCHRONIZE and READ_CONTROL with FILE_GENERIC_READ, so a
        # whole-mask -band test reports write on read-only objects.
        $fileReadData = 0x1     # FILE_READ_DATA / FILE_LIST_DIRECTORY
        $fileWriteData = 0x2    # FILE_WRITE_DATA / FILE_ADD_FILE
        $fileAppend = 0x4       # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        $result.Read = if ($granted -band $fileReadData) { 'granted' } else { 'denied' }
        $writeMask = if ($isDir) { $fileWriteData } else { $fileWriteData -bor $fileAppend }
        $result.Write = if ($granted -band $writeMask) { 'granted' } else { 'denied' }
        $result.Create = if ($granted -band ($fileWriteData -bor $fileAppend)) { 'granted' } else { 'denied' }
        $result.Delete = if ($granted -band 0x10000) { 'granted' } else { 'denied' }
        $result.ChangeAcl = if ($granted -band 0x40000) { 'granted' } else { 'denied' }
        $result.TakeOwnership = if ($granted -band 0x80000) { 'granted' } else { 'denied' }
        $result.DeleteChild = if ($isDir -and ($granted -band 0x40)) { 'granted' } else { 'denied' }
    }
    else {
        # Security descriptor unreadable: request each right on its own
        # OPEN_EXISTING handle and close it. Nothing is created or changed.
        $result.ErrorCategory = Get-ErrorCategory $check.Error
        $result.Method = 'access-request'
        $read = [AgentSandboxAssessmentNative]::ProbeFile($Path, 0x1)
        $result.Read = ConvertTo-ProbeOutcome $read
        if ($read -ne 0) { $result.ErrorCategory = Get-ErrorCategory $read }
        $writeData = [AgentSandboxAssessmentNative]::ProbeFile($Path, 0x2)
        $append = [AgentSandboxAssessmentNative]::ProbeFile($Path, 0x4)
        $result.Write = if ($isDir) { ConvertTo-ProbeOutcome $writeData } else { ConvertTo-ProbeOutcome $writeData, $append }
        $result.Create = ConvertTo-ProbeOutcome $writeData, $append
        $result.Delete = ConvertTo-ProbeOutcome ([AgentSandboxAssessmentNative]::ProbeFile($Path, 0x10000))
        $result.ChangeAcl = ConvertTo-ProbeOutcome ([AgentSandboxAssessmentNative]::ProbeFile($Path, 0x40000))
        $result.TakeOwnership = ConvertTo-ProbeOutcome ([AgentSandboxAssessmentNative]::ProbeFile($Path, 0x80000))
        $result.DeleteChild = if ($isDir -or -not $item) { ConvertTo-ProbeOutcome ([AgentSandboxAssessmentNative]::ProbeFile($Path, 0x40)) } else { 'denied' }
        # The read-only attribute denies data writes and deletion on files
        # regardless of the DACL, so those denials are conclusive only when the
        # attribute cannot be cleared. Directories ignore the attribute.
        if (-not $isDir -and [AgentSandboxAssessmentNative]::ProbeFile($Path, 0x100) -ne 5) {
            foreach ($right in @('Write', 'Create', 'Delete')) {
                if ($result[$right] -eq 'denied') { $result[$right] = 'unknown' }
            }
        }
    }
    # DELETE on the object and FILE_DELETE_CHILD on its parent are independent
    # ways to authorize deletion. This is permission analysis, never a delete.
    $parent = Split-Path -Parent $Path
    if ($parent -and $result.Delete -ne 'granted') {
        $parentCheck = [AgentSandboxAssessmentNative]::CheckNamedObject($parent, 1)
        if ($parentCheck.Error -eq 0 -and ($parentCheck.Granted -band 0x40)) { $result.Delete = 'granted' }
        elseif ($parentCheck.Error -ne 0) {
            switch (ConvertTo-ProbeOutcome ([AgentSandboxAssessmentNative]::ProbeFile($parent, 0x40))) {
                'granted' { $result.Delete = 'granted' }
                'unknown' { $result.Delete = 'unknown' }
            }
        }
    }
    return [pscustomobject]$result
}

function ConvertTo-ProbeOutcome {
    # Combines single-right request results: any grant wins; only explicit
    # ERROR_ACCESS_DENIED on every request counts as denied.
    param([int[]]$Code)

    if ($Code -contains 0) { return 'granted' }
    if (@($Code | Where-Object { $_ -ne 5 }).Count -eq 0) { return 'denied' }
    return 'unknown'
}

function Test-AnyWrite {
    param([Parameter(Mandatory)][psobject]$Access)

    return @('Create', 'Write', 'Delete', 'ChangeAcl', 'TakeOwnership', 'DeleteChild') |
    Where-Object { $Access.PSObject.Properties.Name -contains $_ } |
    Where-Object { $Access.$_ -eq 'granted' } |
    Select-Object -First 1
}

function Test-UnknownWrite {
    param([Parameter(Mandatory)][psobject]$Access)

    return [bool](@('Create', 'Write', 'Delete', 'ChangeAcl', 'TakeOwnership', 'DeleteChild') |
        Where-Object { $Access.PSObject.Properties.Name -contains $_ } |
        Where-Object { $Access.$_ -eq 'unknown' } | Select-Object -First 1)
}

function Get-MatchingTargets {
    # Probes a path list for the requested right, emits one finding per match,
    # and returns { Existing; Matched; Unknown } without deciding a criterion. Used
    # directly by checks that combine several target sources into one criterion.
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Criterion,
        [Parameter(Mandatory)][ValidateSet('Read', 'Write')][string]$Right,
        [string[]]$Path = @(),
        [Parameter(Mandatory)][string]$Capability,
        [switch]$IncludeHowInCapability,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Impact,
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')][string]$Severity = 'medium'
    )

    $existing = @()
    $matched = @()
    $unknown = @()
    foreach ($target in @($Path | Where-Object { $_ } | Select-Object -Unique)) {
        $access = Get-PathAccess -Path $target
        if (-not $access.Exists -and $access.ErrorCategory -eq 'not-found') { continue }
        $existing += $target
        $how = if ($Right -eq 'Write') { Test-AnyWrite -Access $access }
        elseif ($access.Read -eq 'granted') { 'Read' } else { $null }
        if ($how) {
            $matched += $target
            $findingCapability = if ($IncludeHowInCapability) { "$Capability ($how)" } else { $Capability }
            $findingImpact = $Impact
            if ($Right -eq 'Read' -and $access.IsDirectory) {
                $findingCapability = 'directory listing'
                $findingImpact = 'Directory names are visible; child file readability is evaluated separately.'
            }
            Add-Finding -Check $Check -Criterion $Criterion -Target $target -Capability $findingCapability `
                -Result granted -Method $access.Method -Scope $Scope -Impact $findingImpact -Severity $Severity
        }
        elseif (($Right -eq 'Write' -and (Test-UnknownWrite $access)) -or
            ($Right -eq 'Read' -and $access.Read -eq 'unknown')) {
            $unknown += $target
            Add-Finding -Check $Check -Criterion $Criterion -Target $target -Capability $Capability `
                -Result unknown -Method $access.Method -Scope $Scope -ErrorCategory $access.ErrorCategory `
                -Impact 'Access could not be fully evaluated.'
        }
    }
    return [pscustomobject]@{ Existing = @($existing); Matched = @($matched); Unknown = @($unknown) }
}

function Resolve-AccessTargets {
    # Shared discover -> probe -> decide -> emit pattern for a single-source
    # path-set criterion. Sets the criterion to unknown (none exist), unmet
    # (any match) or met (none match). Returns the matching paths. -Right Write
    # matches any mutating right; -Right Read matches read.
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Criterion,
        [Parameter(Mandatory)][ValidateSet('Read', 'Write')][string]$Right,
        [string[]]$Path = @(),
        [Parameter(Mandatory)][string]$Capability,
        [switch]$IncludeHowInCapability,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Impact,
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')][string]$Severity = 'medium',
        [Parameter(Mandatory)][string]$NoneReason,
        [Parameter(Mandatory)][string]$MetReason,
        [Parameter(Mandatory)][string]$UnmetReasonFormat
    )

    $result = Get-MatchingTargets -Check $Check -Criterion $Criterion -Right $Right -Path $Path `
        -Capability $Capability -IncludeHowInCapability:$IncludeHowInCapability -Scope $Scope `
        -Impact $Impact -Severity $Severity
    if ($result.Existing.Count -eq 0) {
        Set-CriterionOutcome -Id $Criterion -Outcome 'unknown' -Method 'permission-analysis' -Reason $NoneReason
        return @()
    }
    if ($result.Matched.Count -gt 0) {
        Set-CriterionOutcome -Id $Criterion -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason ($UnmetReasonFormat -f $result.Matched.Count, $result.Existing.Count)
    }
    elseif ($result.Unknown.Count -gt 0) {
        Set-CriterionOutcome -Id $Criterion -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason "Access could not be fully evaluated on $($result.Unknown.Count) of $($result.Existing.Count) targets."
    }
    else {
        Set-CriterionOutcome -Id $Criterion -Outcome 'met' -Method 'permission-analysis' -Reason $MetReason
    }
    return $result.Matched
}

function Get-WritableRegistryKeys {
    # Probes registry keys for KEY_SET_VALUE, emits one finding per writable key,
    # and returns matched and unresolved keys. Does not decide a criterion.
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Criterion,
        [hashtable[]]$Key = @(),
        [Parameter(Mandatory)][string]$Capability,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Impact,
        [ValidateSet('critical', 'high', 'medium', 'low', 'info')][string]$Severity = 'medium'
    )

    $writable = @()
    $unknown = @()
    foreach ($entry in $Key) {
        $probe = [AgentSandboxAssessmentNative]::ProbeRegistryKey($entry.Hive, $entry.Sub, 0x2)
        if ($probe -eq 0) {
            $writable += $entry.Display
            Add-Finding -Check $Check -Criterion $Criterion -Target $entry.Display -Capability $Capability `
                -Result granted -Method access-request -Scope $Scope -Impact $Impact -Severity $Severity
        }
        elseif ($probe -notin 2, 3, 5) { $unknown += $entry.Display }
    }
    return [pscustomobject]@{ Matched = @($writable); Unknown = @($unknown) }
}

function Get-IntegrityLabel {
    param([string]$IntegritySid)

    if ([string]::IsNullOrEmpty($IntegritySid)) { return 'unknown' }
    $rid = ($IntegritySid -split '-')[-1]
    switch ($rid) {
        '0' { 'untrusted' }
        '4096' { 'low' }
        '8192' { 'medium' }
        '8448' { 'medium-plus' }
        '12288' { 'high' }
        '16384' { 'system' }
        default { "level-$rid" }
    }
}

function Resolve-SidName {
    param([string]$Sid)

    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate(
            [System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $null
    }
}

# --- IDENTITY -----------------------------------------------------------------

function Invoke-IdentityCheck {
    $token = [AgentSandboxAssessmentNative]::GetCurrentToken()
    $enabled = 0x4
    $denyOnly = 0x10

    $groupView = foreach ($group in $token.Groups) {
        [pscustomobject]@{
            Sid      = $group.Sid
            Name     = (Resolve-SidName $group.Sid)
            Enabled  = [bool]($group.Attributes -band $enabled)
            DenyOnly = [bool]($group.Attributes -band $denyOnly)
        }
    }
    $privilegeNames = @($token.Privileges | ForEach-Object { $_.Name })
    $integrityLabel = Get-IntegrityLabel $token.IntegritySid

    $script:Inventory['identity'] = [ordered]@{
        userSid            = $token.UserSid
        userName           = (Protect-Text (Resolve-SidName $token.UserSid))
        integrityLevel     = $integrityLabel
        isElevated         = $token.IsElevated
        elevationType      = $token.ElevationType
        sessionId          = $token.SessionId
        authenticationId   = $token.AuthenticationId
        tokenType          = $token.TokenType
        restrictedSidCount = $token.RestrictedSidCount
        isAppContainer     = $token.IsAppContainer
        capabilityCount    = $token.CapabilityCount
        hasThreadToken     = $token.HasThreadToken
        privileges         = $privilegeNames
        groups             = @($groupView | ForEach-Object { @{ sid = $_.Sid; name = (Protect-Text $_.Name); enabled = $_.Enabled; denyOnly = $_.DenyOnly } })
    }

    # A-ID-ADMIN
    $adminGroup = $groupView | Where-Object { $_.Sid -eq 'S-1-5-32-544' } | Select-Object -First 1
    $adminActive = $adminGroup -and -not $adminGroup.DenyOnly
    $highIntegrity = @('high', 'system') -contains $integrityLabel
    if ($token.IsElevated -or $adminActive -or $highIntegrity) {
        Set-CriterionOutcome -Id 'A-ID-ADMIN' -Outcome 'unmet' -Method 'inventory' `
            -Reason "Identity holds active administrative authority (integrity=$integrityLabel, elevated=$($token.IsElevated))." `
            -Critical -CriticalReason 'Administrative control over the host from the agent context.'
        Add-Finding -Check IDENTITY -Criterion 'A-ID-ADMIN' -Target $token.UserSid -Capability 'administrator' `
            -Result observed -Method inventory -Scope 'current-token' -Impact 'Full administrative control of the host.' -Severity critical
    }
    elseif ($adminGroup) {
        Set-CriterionOutcome -Id 'A-ID-ADMIN' -Outcome 'unmet' -Method 'inventory' `
            -Reason 'Identity is a member of Administrators as a deny-only (UAC split-token) group and can elevate without credentials.'
        Add-Finding -Check IDENTITY -Criterion 'A-ID-ADMIN' -Target $token.UserSid -Capability 'administrator (split token)' `
            -Result observed -Method inventory -Scope 'current-token' -Impact 'Elevation to administrator without credentials via UAC.' -Severity high
    }
    else {
        Set-CriterionOutcome -Id 'A-ID-ADMIN' -Outcome 'met' -Method 'inventory' `
            -Reason "Standard user, integrity=$integrityLabel, not elevated."
    }

    # A-ID-PRIVS
    $highImpactPrivileges = @(
        'SeDebugPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeLoadDriverPrivilege',
        'SeRestorePrivilege', 'SeBackupPrivilege', 'SeTakeOwnershipPrivilege',
        'SeAssignPrimaryTokenPrivilege', 'SeImpersonatePrivilege'
    )
    $dangerous = @($privilegeNames | Where-Object { $highImpactPrivileges -contains $_ })
    if ($dangerous.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-ID-PRIVS' -Outcome 'unmet' -Method 'inventory' `
            -Reason "Token holds high-impact privileges: $($dangerous -join ', ')." `
            -Critical -CriticalReason 'Privileges permit host-wide escalation regardless of enabled state.'
        Add-Finding -Check IDENTITY -Criterion 'A-ID-PRIVS' -Target ($dangerous -join ', ') -Capability 'high-impact privilege' `
            -Result observed -Method inventory -Scope 'current-token' -Impact 'Escalation or kernel/credential access.' -Severity critical
    }
    else {
        Set-CriterionOutcome -Id 'A-ID-PRIVS' -Outcome 'met' -Method 'inventory' `
            -Reason 'No high-impact privileges present in the token.'
    }

    # A-ID-GROUPS
    $privilegedGroupSids = @{
        'S-1-5-32-551' = 'Backup Operators'; 'S-1-5-32-549' = 'Server Operators'
        'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-578' = 'Hyper-V Administrators'
        'S-1-5-32-580' = 'Remote Management Users'; 'S-1-5-32-556' = 'Network Configuration Operators'
    }
    $brokerGroupNames = @('docker-users', 'Hyper-V Administrators')
    $privilegedMemberships = @($groupView | Where-Object {
            -not $_.DenyOnly -and (
                $privilegedGroupSids.ContainsKey($_.Sid) -or
                ($null -ne $_.Name -and ($brokerGroupNames -contains ($_.Name -replace '.*\\', '')))
            )
        })
    if ($privilegedMemberships.Count -gt 0) {
        $names = @($privilegedMemberships | ForEach-Object { if ($_.Name) { $_.Name } else { $_.Sid } })
        Set-CriterionOutcome -Id 'A-ID-GROUPS' -Outcome 'unmet' -Method 'inventory' `
            -Reason "Member of privileged or broker groups: $($names -join ', ')."
        Add-Finding -Check IDENTITY -Criterion 'A-ID-GROUPS' -Target ($names -join ', ') -Capability 'privileged group membership' `
            -Result observed -Method inventory -Scope 'current-token' -Impact 'Delegated administrative or broker authority.' -Severity high
    }
    else {
        Set-CriterionOutcome -Id 'A-ID-GROUPS' -Outcome 'met' -Method 'inventory' `
            -Reason 'No privileged or broker group memberships are active.'
    }
}

# --- CONTAINMENT --------------------------------------------------------------

function Test-ManagedSettingsPresent {
    return (Test-Path -LiteralPath 'C:\Program Files\ClaudeCode\managed-settings.json' -PathType Leaf)
}

function Get-OwnerSid {
    param([Parameter(Mandatory)][string]$Path)

    return (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
}

function Get-ControlTargets {
    # Bounded walk of an installed control tree; never execute its contents.
    param([string[]]$Root, [int]$MaxTargets = 200)

    $paths = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $incomplete = $false
    foreach ($directory in $Root) { $pending.Push($directory) }
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        if ($paths.Count -ge $MaxTargets) { $incomplete = $true; break }
        if (Get-ScanPathExclusion $directory) { $incomplete = $true; continue }
        $paths.Add($directory)
        $enumErrors = @()
        $children = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue -ErrorVariable enumErrors |
            Select-Object -First ($MaxTargets - $paths.Count + 1))
        if ($enumErrors.Count) { $incomplete = $true }
        foreach ($child in $children) {
            if ($paths.Count + $pending.Count -ge $MaxTargets) { $incomplete = $true; break }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
            elseif (Get-ScanPathExclusion $child.FullName) { $incomplete = $true }
            else { $paths.Add($child.FullName) }
        }
    }
    return [pscustomobject]@{ Paths = @($paths.ToArray()); Incomplete = $incomplete; MaxTargets = $MaxTargets }
}

function Invoke-ExecutionPolicyCheck {
    # C-EXEC-POLICY: enforced WDAC user-mode code integrity, or enforced
    # AppLocker executable rules with the Application Identity service running.
    $umci = $null
    $appLocker = $null
    $failures = @()
    try {
        $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
        $umci = [int]$deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus
    }
    catch { $failures += "WDAC status: $($_.Exception.Message)" }
    # Editions without AppLocker have no cmdlet; a cmdlet that fails to load or
    # run leaves AppLocker unresolved.
    if (-not (Get-Command -Name Get-AppLockerPolicy -ErrorAction SilentlyContinue)) { $appLocker = $false }
    else {
        try {
            $exeRules = @((Get-AppLockerPolicy -Effective -ErrorAction Stop).RuleCollections |
                Where-Object { $_.RuleCollectionType -eq 'Exe' -and $_.EnforcementMode -eq 'Enabled' -and $_.Count -gt 0 })
            $appLocker = $exeRules.Count -gt 0 -and (Get-Service -Name AppIDSvc -ErrorAction Stop).Status -eq 'Running'
        }
        catch { $failures += "AppLocker policy: $($_.Exception.Message)" }
    }
    $script:Inventory['executionPolicy'] = [ordered]@{ umciStatus = $umci; appLockerExeEnforced = $appLocker }

    if ($umci -eq 2) {
        Set-CriterionOutcome -Id 'C-EXEC-POLICY' -Outcome met -Method inventory -Reason 'WDAC enforces user-mode code integrity.'
    }
    elseif ($appLocker -eq $true) {
        Set-CriterionOutcome -Id 'C-EXEC-POLICY' -Outcome met -Method inventory -Reason 'AppLocker enforces executable rules and the Application Identity service is running.'
    }
    elseif ($failures.Count -gt 0) {
        Set-CriterionOutcome -Id 'C-EXEC-POLICY' -Outcome unknown -Method inventory `
            -Reason "Application control could not be fully evaluated: $($failures -join '; ')."
    }
    else {
        Set-CriterionOutcome -Id 'C-EXEC-POLICY' -Outcome unmet -Method inventory `
            -Reason "No enforced application control: WDAC user-mode code integrity status $umci, no enforced AppLocker executable rules. Any program or script the agent writes can run."
    }
}

function Invoke-ContainmentCheck {
    # C-POLICY-INTEGRITY: launcher/policy/checker files must not be agent-writable.
    $programDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'
    $scriptDir = if ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { $null }
    $policyTargets = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @(
            $programDataRoot,
            'C:\Program Files\ClaudeCode',
            'C:\Program Files\ClaudeCode\managed-settings.json',
            $PSCommandPath,
            $scriptDir)) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { $policyTargets.Add($candidate) | Out-Null }
    }
    $controlRoots = @($programDataRoot | Where-Object { Test-Path -LiteralPath $_ })
    # Check shipped nested wrappers/bootstrap independently of their directory ACL.
    if ($scriptDir) {
        foreach ($name in @('bootstrap', 'scripts')) {
            $directory = Join-Path $scriptDir $name
            if (Test-Path -LiteralPath $directory) { $controlRoots += $directory }
        }
        foreach ($name in @('Start-AgentSandbox.ps1', 'Check-AgentSandbox.ps1', 'managed-settings.json')) {
            $file = Join-Path $scriptDir $name
            if (Test-Path -LiteralPath $file) { $policyTargets.Add($file) }
        }
    }
    $controls = Get-ControlTargets -Root $controlRoots
    foreach ($path in $controls.Paths) { $policyTargets.Add($path) }
    $script:Inventory['controlTargets'] = $controls
    $policyTargets = @($policyTargets | Select-Object -Unique)
    Resolve-AccessTargets -Check CONTAINMENT -Criterion 'C-POLICY-INTEGRITY' -Right Write -Path $policyTargets `
        -Capability 'writable control file' -IncludeHowInCapability -Scope 'control-integrity' `
        -Impact 'Agent can alter its own launcher, policy or checker.' -Severity high `
        -NoneReason 'No installed launcher, policy or checker targets were found to evaluate.' `
        -MetReason "No write, create, delete or ACL rights on $($policyTargets.Count) control targets." `
        -UnmetReasonFormat '{0} of {1} control targets are agent-writable.' | Out-Null
    if ($controls.Incomplete -and $script:Criteria['C-POLICY-INTEGRITY'].Outcome -ne 'unmet') {
        Set-CriterionOutcome -Id 'C-POLICY-INTEGRITY' -Outcome unknown -Method inventory `
            -Reason 'Control-tree discovery was incomplete or reached its target limit.'
    }

    # C-TOOL-POLICY: managed policy differs per agent (Claude Code, Codex,
    # Copilot CLI), so only the agent running this check is assessed, and only
    # Claude Code (CLAUDECODE=1) is implemented. Results carry that scope.
    $claudeHome = Join-Path $env:USERPROFILE '.claude'
    $managedPath = 'C:\Program Files\ClaudeCode\managed-settings.json'
    # C-PERSIST-SELF below also uses these, whichever agent is running.
    $managedPresent = Test-ManagedSettingsPresent
    $managedAccess = if ($managedPresent) { Get-PathAccess $managedPath } else { $null }
    if ($env:CLAUDECODE -ne '1') {
        Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'Tool policy is assessed only for Claude Code; this run is not under Claude Code, and other agents use different policy mechanisms.'
    }
    elseif ($managedPresent) {
        $owner = $null
        try { $owner = Get-OwnerSid -Path $managedPath } catch { }
        $settings = $null
        try { $settings = Get-Content -LiteralPath $managedPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { }
        $trustedOwners = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        if (Test-AnyWrite $managedAccess) {
            Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome unmet -Method permission-analysis `
                -Reason 'Claude Code managed settings are present but agent-writable.'
        }
        elseif ((Test-UnknownWrite $managedAccess) -or $owner -notin $trustedOwners -or $settings -isnot [System.Collections.IDictionary]) {
            Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome unknown -Method permission-analysis `
                -Reason 'Claude Code managed settings are present, but their write access, administrative ownership or content could not be verified.'
        }
        elseif ($settings['allowManagedPermissionRulesOnly'] -eq $true) {
            Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome met -Method permission-analysis `
                -Reason 'Claude Code managed settings are admin-owned, not agent-writable and allow only managed permission rules. Scope: Claude Code only; application by the tool is not observed.'
        }
        else {
            Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome unmet -Method permission-analysis `
                -Reason 'Claude Code managed settings do not set allowManagedPermissionRulesOnly, so user or project settings the agent can write may add allow rules; managed deny rules still apply. Scope: Claude Code only.'
        }
    }
    elseif (Test-Path -LiteralPath $claudeHome) {
        Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome 'unmet' -Method 'inventory' `
            -Reason 'Claude Code settings exist without a managed policy to constrain tool permissions.'
    }
    else {
        Set-CriterionOutcome -Id 'C-TOOL-POLICY' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'No Claude Code managed policy and no agent settings directory were found.'
    }

    Invoke-ExecutionPolicyCheck

    # C-JOB
    $job = [AgentSandboxAssessmentNative]::GetJobInfo()
    $script:Inventory['job'] = [ordered]@{
        inJob = $job.InJob; limitFlags = ('0x{0:x}' -f $job.LimitFlags)
        uiRestrictions = ('0x{0:x}' -f $job.UiRestrictions); error = $job.Error
    }
    $killOnClose = [bool]($job.LimitFlags -band 0x2000)
    $breakaway = [bool]($job.LimitFlags -band (0x800 -bor 0x1000))
    if ($job.InJob -and $job.Error -ne 0) {
        Set-CriterionOutcome -Id 'C-JOB' -Outcome 'unknown' -Method 'inventory' `
            -Reason "Process is in a job but its limits could not be queried (win32-$($job.Error))."
    }
    elseif ($job.InJob -and $killOnClose -and -not $breakaway) {
        Set-CriterionOutcome -Id 'C-JOB' -Outcome 'met' -Method 'inventory' `
            -Reason 'Confined to a kill-on-close job without breakaway.'
    }
    elseif ($job.InJob) {
        Set-CriterionOutcome -Id 'C-JOB' -Outcome 'unmet' -Method 'inventory' `
            -Reason "In a job without reliable kill-on-close/no-breakaway (killOnClose=$killOnClose, breakaway=$breakaway)."
    }
    else {
        Set-CriterionOutcome -Id 'C-JOB' -Outcome 'unmet' -Method 'inventory' `
            -Reason 'Process is not confined to a job object.'
    }

    # C-PERSIST-SELF
    $persistTargets = New-Object System.Collections.Generic.List[string]
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath) {
        foreach ($dir in ($userPath -split ';' | Where-Object { $_ -and $_.Trim() })) {
            $persistTargets.Add($dir.Trim()) | Out-Null
        }
    }
    $persistTargets.Add((Join-Path $env:USERPROFILE '.local\bin')) | Out-Null
    # GetFolderPath returns an empty string when Documents cannot be resolved.
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ($documents) {
        foreach ($name in @('PowerShell', 'WindowsPowerShell')) { $persistTargets.Add((Join-Path $documents $name)) | Out-Null }
    }
    $managedBlocksHooks = $false
    if ($managedPresent -and -not (Test-AnyWrite $managedAccess) -and -not (Test-UnknownWrite $managedAccess)) {
        try {
            $managed = Get-Content -LiteralPath 'C:\Program Files\ClaudeCode\managed-settings.json' -Raw | ConvertFrom-Json
            if ($managed.PSObject.Properties.Name -contains 'allowManagedHooksOnly') {
                $managedBlocksHooks = [bool]$managed.allowManagedHooksOnly
            }
        }
        catch {
            Add-AssessmentError -Check CONTAINMENT -Message "Could not parse managed-settings.json: $($_.Exception.Message)" -Category 'parse'
        }
    }
    if (-not $managedBlocksHooks) {
        $persistTargets.Add((Join-Path $claudeHome 'settings.json')) | Out-Null
    }
    Resolve-AccessTargets -Check CONTAINMENT -Criterion 'C-PERSIST-SELF' -Right Write -Path @($persistTargets) `
        -Capability 'writable startup path' -Scope 'persistence' `
        -Impact 'Code placed here runs in later agent sessions.' -Severity medium `
        -NoneReason 'No persistence targets (user PATH, profile, agent hooks) exist to evaluate.' `
        -MetReason 'No evaluated startup/persistence paths are agent-writable.' `
        -UnmetReasonFormat '{0} startup/persistence paths are agent-writable.' | Out-Null

    # C-PROXY-INTEGRITY: the agent can always change its own environment and
    # HKCU proxy settings, and can ignore any proxy setting. A change only
    # matters if it opens a route, so this is decided by the NETWORK evidence
    # (which runs first): no direct Internet route reached its host.
    $envProxy = $env:HTTPS_PROXY -or $env:HTTP_PROXY -or $env:ALL_PROXY
    $userProxy = $false
    try {
        $wininet = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if (($wininet.PSObject.Properties.Name -contains 'ProxyEnable') -and $wininet.ProxyEnable -eq 1) { $userProxy = $true }
    }
    catch {
        # No per-user WinINET configuration present.
    }
    # The policy key also holds unrelated defaults such as CallLegacyWCMPolicies;
    # only proxy values make it a machine proxy policy.
    $machinePolicy = $false
    try {
        $policy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $machinePolicy = @($policy.PSObject.Properties.Name |
            Where-Object { $_ -in 'ProxySettingsPerUser', 'ProxyEnable', 'ProxyServer', 'AutoConfigURL' }).Count -gt 0
    }
    catch {
        # No machine proxy policy present.
    }
    $directReached = @()
    if ($script:Inventory.Contains('networkProbes')) {
        $directReached = @($script:Inventory['networkProbes'] |
            Where-Object { $_.Kind -eq 'tcp' -and $_.Class -eq 'internet' -and $_.Outcome -in 'connected', 'refused' })
    }
    $policyWritable = $machinePolicy -and [AgentSandboxAssessmentNative]::ProbeRegistryKey(
        2, 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings', 0x2) -eq 0
    if (-not $envProxy -and -not $userProxy -and -not $machinePolicy) {
        Set-CriterionOutcome -Id 'C-PROXY-INTEGRITY' -Outcome 'na' -Method 'inventory' `
            -Reason 'No proxy is configured for this identity.'
    }
    elseif ($policyWritable) {
        Set-CriterionOutcome -Id 'C-PROXY-INTEGRITY' -Outcome 'unmet' -Method 'access-request' `
            -Reason 'Machine proxy policy key is agent-writable.'
    }
    elseif ($directReached.Count -gt 0) {
        Set-CriterionOutcome -Id 'C-PROXY-INTEGRITY' -Outcome 'unmet' -Method 'observed-operation' `
            -Reason 'A direct Internet route reached its host, so the agent can bypass the configured proxy.'
    }
    elseif ($script:Criteria['R-NET-INTERNET'].Outcome -eq 'met') {
        Set-CriterionOutcome -Id 'C-PROXY-INTEGRITY' -Outcome 'met' -Method 'observed-operation' `
            -Reason 'The agent can change its own proxy settings, but no direct Internet route reached its host, so a change cannot widen egress on tested routes.'
    }
    else {
        Set-CriterionOutcome -Id 'C-PROXY-INTEGRITY' -Outcome 'unknown' -Method 'observed-operation' `
            -Reason 'The agent can change its own proxy settings; whether that widens egress is unresolved because direct Internet routes were not established as restricted.'
    }
}

# --- MONITORING ---------------------------------------------------------------

function Invoke-MonitoringCheck {
    # Session placement alone says nothing about distinct account attribution.
    $agentSession = [AgentSandboxAssessmentNative]::GetSessionId($PID)
    $consoleUser = [AgentSandboxAssessmentNative]::GetConsoleSessionUser()
    $consoleSid = [AgentSandboxAssessmentNative]::GetConsoleSessionSid()
    $ownSid = [AgentSandboxAssessmentNative]::GetCurrentToken().UserSid
    $script:Inventory['sessionUser'] = [AgentSandboxAssessmentNative]::GetSessionUser()
    $script:Inventory['agentSessionId'] = $agentSession
    $script:Inventory['consoleUser'] = (Protect-Text $consoleUser)
    if ($consoleSid -and $ownSid -and $consoleSid -ne $ownSid) {
        Set-CriterionOutcome -Id 'M-ATTRIBUTION' -Outcome 'met' -Method 'inventory' `
            -Reason 'Agent token SID differs from the interactive console account SID; log collection is assessed separately.'
    }
    elseif ($consoleSid -and $consoleSid -eq $ownSid) {
        Set-CriterionOutcome -Id 'M-ATTRIBUTION' -Outcome 'unmet' -Method 'inventory' `
            -Reason 'Agent runs as the interactive console user, so its actions are not separately attributable.'
    }
    else {
        Set-CriterionOutcome -Id 'M-ATTRIBUTION' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'Console account SID could not be determined; session placement alone does not establish distinct attribution.'
    }

    # M-OS-LOGGING and discovery for M-TAMPER
    $loggingSignals = @()
    $scriptLoggingEnabled = $false
    $processMonitorRunning = @()
    $monitoringServices = @()
    # An installed but stopped sensor records nothing; only a running one counts.
    foreach ($serviceName in @('Sysmon', 'Sysmon64', 'Sense')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) { continue }
        $monitoringServices += $serviceName
        $running = ($service.PSObject.Properties.Name -contains 'Status') -and "$($service.Status)" -eq 'Running'
        $loggingSignals += "service:$serviceName ($(if ($running) { 'running' } else { 'not running' }))"
        if ($running) { $processMonitorRunning += $serviceName }
    }
    # Windows PowerShell and PowerShell 7 read separate policy keys.
    $loggingPolicyKeys = @()
    foreach ($policyRoot in @('Windows\PowerShell', 'PowerShellCore')) {
        $scriptBlockKey = "SOFTWARE\Policies\Microsoft\$policyRoot\ScriptBlockLogging"
        try {
            $sbl = Get-ItemProperty -Path "HKLM:\$scriptBlockKey" -ErrorAction Stop
            if (($sbl.PSObject.Properties.Name -contains 'EnableScriptBlockLogging') -and $sbl.EnableScriptBlockLogging -eq 1) {
                $loggingSignals += "policy:ScriptBlockLogging ($policyRoot)"
                $scriptLoggingEnabled = $true
                $loggingPolicyKeys += $scriptBlockKey
            }
        }
        catch {
            # Policy not configured.
        }
    }
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    try {
        $audit = Get-ItemProperty -Path $auditKey -ErrorAction Stop
        if (($audit.PSObject.Properties.Name -contains 'ProcessCreationIncludeCmdLine_Enabled') -and
            $audit.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
            $loggingSignals += 'policy:ProcessCreationCmdLine'
            $loggingPolicyKeys += 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        }
    }
    catch {
        # Policy not configured.
    }
    $script:Inventory['loggingSignals'] = $loggingSignals

    if ($scriptLoggingEnabled -or $processMonitorRunning.Count -gt 0) {
        $what = @(
            if ($scriptLoggingEnabled) { 'PowerShell script-block logging policy is enabled' }
            if ($processMonitorRunning.Count -gt 0) { "process monitoring is running ($($processMonitorRunning -join ', '))" }
        ) -join '; '
        Set-CriterionOutcome -Id 'M-OS-LOGGING' -Outcome 'met' -Method 'inventory' `
            -Reason "$what. Event delivery and external collection are unverified."
    }
    else {
        $hints = if ($loggingSignals.Count -gt 0) { $loggingSignals -join ', ' } else { 'none' }
        Set-CriterionOutcome -Id 'M-OS-LOGGING' -Outcome 'unknown' -Method 'inventory' `
            -Reason "Active process/script logging is unverified. Visible hints: $hints. A stopped sensor, command-line inclusion or audit policy this identity cannot read does not establish logging."
    }

    # M-TAMPER
    $tamperable = @()
    $tamperUnknown = @()
    foreach ($key in $loggingPolicyKeys) {
        $probe = [AgentSandboxAssessmentNative]::ProbeRegistryKey(2, $key, 0x2)
        if ($probe -eq 0) {
            $tamperable += "regkey:$key"
            Add-Finding -Check MONITORING -Criterion 'M-TAMPER' -Target $key -Capability 'writable logging policy key' `
                -Result granted -Method access-request -Scope 'monitoring-integrity' `
                -Impact 'Agent can disable logging policy.' -Severity medium
        }
        elseif ($probe -ne 5) { $tamperUnknown += "regkey:$key" }
    }
    foreach ($serviceName in $monitoringServices) {
        foreach ($right in @(@{ Name = 'change-config'; Mask = 0x2 }, @{ Name = 'stop'; Mask = 0x20 })) {
            $probe = [AgentSandboxAssessmentNative]::ProbeService($serviceName, [uint32]$right.Mask)
            if ($probe -eq 0) {
                $tamperable += "service:${serviceName}:$($right.Name)"
                Add-Finding -Check MONITORING -Criterion 'M-TAMPER' -Target $serviceName -Capability "$($right.Name) on monitoring service" `
                    -Result granted -Method access-request -Scope 'monitoring-integrity' `
                    -Impact 'Agent can stop or reconfigure monitoring.' -Severity medium
            }
            elseif ($probe -ne 5) { $tamperUnknown += "service:${serviceName}:$($right.Name)" }
        }
    }
    if ($loggingSignals.Count -eq 0 -and $loggingPolicyKeys.Count -eq 0) {
        Set-CriterionOutcome -Id 'M-TAMPER' -Outcome 'unknown' -Method 'access-request' `
            -Reason 'No monitoring controls were discovered to test for tamper resistance.'
    }
    elseif ($tamperable.Count -gt 0) {
        Set-CriterionOutcome -Id 'M-TAMPER' -Outcome 'unmet' -Method 'access-request' `
            -Reason "Agent can alter discovered monitoring controls: $($tamperable -join ', ')."
    }
    elseif ($tamperUnknown.Count -gt 0) {
        Set-CriterionOutcome -Id 'M-TAMPER' -Outcome 'unknown' -Method 'access-request' `
            -Reason 'Some monitoring-control access probes could not be resolved.'
    }
    else {
        Set-CriterionOutcome -Id 'M-TAMPER' -Outcome 'met' -Method 'access-request' `
            -Reason 'Discovered monitoring controls did not grant write/change-config/stop rights.'
    }

    # M-AGENT-LOG
    $logDirs = @(
        (Join-Path $env:USERPROFILE '.claude\projects'),
        (Join-Path $env:USERPROFILE '.copilot'))
    $existingLogDirs = @($logDirs | Where-Object { Test-Path -LiteralPath $_ })
    if ($existingLogDirs.Count -eq 0) {
        Set-CriterionOutcome -Id 'M-AGENT-LOG' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason 'No agent transcript directories were found.'
    }
    else {
        $writableLogs = @()
        $unknownLogs = @()
        foreach ($dir in $existingLogDirs) {
            $access = Get-PathAccess -Path $dir
            if (Test-AnyWrite -Access $access) { $writableLogs += $dir }
            elseif (Test-UnknownWrite $access) { $unknownLogs += $dir }
        }
        if ($writableLogs.Count -gt 0) {
            Set-CriterionOutcome -Id 'M-AGENT-LOG' -Outcome 'unmet' -Method 'permission-analysis' `
                -Reason 'Agent transcript directories are writable by the agent identity.'
            Add-Finding -Check MONITORING -Criterion 'M-AGENT-LOG' -Target ($writableLogs[0]) -Capability 'writable agent log directory' `
                -Result granted -Method permission-analysis -Scope 'monitoring-integrity' `
                -Impact 'Agent can alter its own transcripts.' -Severity low
        }
        elseif ($unknownLogs.Count -gt 0) {
            Set-CriterionOutcome -Id 'M-AGENT-LOG' -Outcome 'unknown' -Method 'permission-analysis' `
                -Reason 'Write permissions on some agent transcript directories could not be resolved.'
        }
        else {
            Set-CriterionOutcome -Id 'M-AGENT-LOG' -Outcome 'met' -Method 'permission-analysis' `
                -Reason 'Agent transcript directories are not agent-writable.'
        }
    }
}

# --- FILES --------------------------------------------------------------------

function Get-AdjacentDirectories {
    param([string[]]$DriveRoot, [int]$MaxTargets = 200)

    if (-not $PSBoundParameters.ContainsKey('DriveRoot')) {
        $DriveRoot = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
            ForEach-Object { $_.RootDirectory.FullName })
    }
    $systemRoots = @($env:SystemRoot, (Join-Path $env:SystemDrive 'Program Files'),
        (Join-Path $env:SystemDrive 'Program Files (x86)'), (Join-Path $env:SystemDrive 'Users'),
        (Join-Path $env:SystemDrive 'ProgramData')) | ForEach-Object { $_.TrimEnd('\') }
    $workspace = $script:WorkspacePath.TrimEnd('\')
    $ancestors = @()
    $cursor = $workspace
    while ($cursor) {
        $ancestors += $cursor.TrimEnd('\')
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    # Root siblings alone miss C:\dev\workspace-neighbor beside C:\dev\workspace.
    $roots = @($DriveRoot) + @(Split-Path -Parent $workspace)
    $paths = [Collections.Generic.List[string]]::new()
    $incomplete = $false
    foreach ($root in @($roots | Where-Object { $_ } | Select-Object -Unique)) {
        if (Get-ScanPathExclusion $root) { $incomplete = $true; continue }
        $enumErrors = @()
        $children = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable enumErrors |
            Select-Object -First ($MaxTargets + 1))
        if ($enumErrors.Count -or $children.Count -gt $MaxTargets) { $incomplete = $true }
        foreach ($directory in $children) {
            $full = $directory.FullName.TrimEnd('\')
            if ($systemRoots -contains $full -or $ancestors -contains $full -or
                $full.StartsWith($workspace + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($paths.Contains($directory.FullName)) { continue }
            if ($paths.Count -ge $MaxTargets) { $incomplete = $true; break }
            $paths.Add($directory.FullName)
        }
    }
    return [pscustomobject]@{ Paths = @($paths.ToArray()); Incomplete = $incomplete; MaxTargets = $MaxTargets }
}

function Get-ReadSamples {
    # Sample direct child files without reading content or traversing links.
    param([string[]]$Directory, [int]$MaxFilesPerDirectory = 20)

    $paths = [Collections.Generic.List[string]]::new()
    $incomplete = $false
    foreach ($root in $Directory) {
        $exclusion = Get-ScanPathExclusion $root
        # An absent root has nothing to sample. A root behind a denied ancestor
        # cannot be enumerated or classified; its own read right is still
        # requested without following links.
        if ($exclusion -eq 'not-found') { continue }
        if ($exclusion -eq 'metadata-denied') { $paths.Add($root); continue }
        if ($exclusion) { $incomplete = $true; continue }
        $paths.Add($root)
        $enumErrors = @()
        $files = @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue -ErrorVariable enumErrors |
            Select-Object -First ($MaxFilesPerDirectory + 1))
        # A denied listing leaves nothing to sample; the root's read probe
        # records the denial. Other enumeration errors stay incomplete.
        $unexpectedErrors = @($enumErrors | Where-Object { $_.Exception -isnot [UnauthorizedAccessException] })
        if ($unexpectedErrors.Count -or $files.Count -gt $MaxFilesPerDirectory) { $incomplete = $true }
        foreach ($file in @($files | Select-Object -First $MaxFilesPerDirectory)) {
            if (Get-ScanPathExclusion $file.FullName) { $incomplete = $true; continue }
            $paths.Add($file.FullName)
        }
    }
    return [pscustomobject]@{ Paths = @($paths.ToArray()); Incomplete = $incomplete; MaxFilesPerDirectory = $MaxFilesPerDirectory }
}

function Find-AdjacentItems {
    # Bounded name-only walk of adjacent trees for items that -Match accepts
    # ($_ is the file or directory). Never opens or executes them; directory
    # links are not followed. The limit applies per root so one large tree
    # cannot hide the others.
    param([string[]]$Root, [Parameter(Mandatory)][scriptblock]$Match, [int]$MaxDepth = 3, [int]$MaxPerRoot = 20)

    $paths = [Collections.Generic.List[string]]::new()
    $incomplete = $false
    foreach ($directory in $Root) {
        $exclusion = Get-ScanPathExclusion $directory
        if ($exclusion) {
            if ($exclusion -ne 'not-found') { $incomplete = $true }
            continue
        }
        $enumErrors = @()
        $found = @(Get-ChildItem -LiteralPath $directory -Recurse -Depth $MaxDepth -Force -ErrorAction SilentlyContinue -ErrorVariable enumErrors |
            Where-Object $Match | Select-Object -First ($MaxPerRoot + 1))
        # A denied subdirectory listing hides nothing the agent could use
        # through that listing; other enumeration errors leave the walk incomplete.
        if (@($enumErrors | Where-Object { $_.Exception -isnot [UnauthorizedAccessException] }).Count) { $incomplete = $true }
        if ($found.Count -gt $MaxPerRoot) { $incomplete = $true }
        foreach ($item in @($found | Select-Object -First $MaxPerRoot)) { $paths.Add($item.FullName) }
    }
    return [pscustomobject]@{ Paths = @($paths.ToArray()); Incomplete = $incomplete; MaxPerRoot = $MaxPerRoot }
}

function Invoke-FilesCheck {
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    $ownProfile = $env:USERPROFILE.TrimEnd('\')
    $excluded = @('Public', 'Default', 'Default User', 'All Users')

    # R-FILES-PROFILES
    $otherProfiles = @()
    $profileErrors = @()
    if (Test-Path -LiteralPath $usersRoot) {
        $otherProfiles = @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable profileErrors |
            Where-Object { $_.FullName.TrimEnd('\') -ne $ownProfile -and $excluded -notcontains $_.Name } |
            ForEach-Object { $_.FullName })
    }
    $script:OtherProfiles = $otherProfiles   # cached for HANDOFF (step 4)
    $profileRoots = @($otherProfiles)
    foreach ($root in $otherProfiles) {
        foreach ($name in @('Documents', 'Desktop', 'AppData')) {
            $profileRoots += Join-Path $root $name
        }
    }
    $profileSamples = Get-ReadSamples -Directory $profileRoots
    $script:Inventory['profileReadSamples'] = $profileSamples
    Resolve-AccessTargets -Check FILES -Criterion 'R-FILES-PROFILES' -Right Read -Path $profileSamples.Paths `
        -Capability 'readable sampled profile file' -Scope 'cross-user-files-sample' `
        -Impact 'A sampled file in another user profile is readable.' -Severity high `
        -NoneReason 'No other user profiles are present to evaluate.' `
        -MetReason 'No tested profile file or directory listing grants read access; descendants outside the sample are untested.' `
        -UnmetReasonFormat '{0} of {1} tested profile files or directory listings grant read access.' | Out-Null
    if (($profileErrors.Count -or $profileSamples.Incomplete) -and $script:Criteria['R-FILES-PROFILES'].Outcome -ne 'unmet') {
        Set-CriterionOutcome -Id 'R-FILES-PROFILES' -Outcome unknown -Method inventory -Reason 'Profile discovery or file sampling was incomplete.'
    }

    # R-FILES-ADJACENT: non-system top-level dirs on fixed drives, excluding the
    # workspace tree and its ancestors. Capped at 200 directories.
    $adjacent = Get-AdjacentDirectories
    $adjacentSamples = Get-ReadSamples -Directory $adjacent.Paths
    $script:Inventory['adjacentDiscovery'] = $adjacent
    $script:Inventory['adjacentReadSamples'] = $adjacentSamples
    Resolve-AccessTargets -Check FILES -Criterion 'R-FILES-ADJACENT' -Right Read -Path $adjacentSamples.Paths `
        -Capability 'readable sampled file outside workspace' -Scope 'host-files-sample' `
        -Impact 'A sampled file outside the workspace is readable.' -Severity medium `
        -NoneReason 'No non-system directories outside the workspace were found to evaluate.' `
        -MetReason 'No tested adjacent file or directory listing grants read access; descendants outside the sample are untested.' `
        -UnmetReasonFormat '{0} of {1} tested adjacent files or directory listings grant read access.' | Out-Null
    if (($adjacent.Incomplete -or $adjacentSamples.Incomplete) -and $script:Criteria['R-FILES-ADJACENT'].Outcome -ne 'unmet') {
        Set-CriterionOutcome -Id 'R-FILES-ADJACENT' -Outcome unknown -Method inventory -Reason 'Adjacent-directory discovery or file sampling was incomplete.'
    }

    # R-FILES-WRITE: the same adjacent sample, probed for any mutating right.
    Resolve-AccessTargets -Check FILES -Criterion 'R-FILES-WRITE' -Right Write -Path $adjacentSamples.Paths `
        -Capability 'writable file or directory outside workspace' -IncludeHowInCapability -Scope 'host-files-sample' `
        -Impact 'The agent can modify, delete or plant files outside the workspace.' -Severity high `
        -NoneReason 'No non-system directories outside the workspace were found to evaluate.' `
        -MetReason 'No tested adjacent file or directory grants write, create, delete or ACL rights; descendants outside the sample are untested.' `
        -UnmetReasonFormat '{0} of {1} tested adjacent files or directories are agent-writable.' | Out-Null
    if (($adjacent.Incomplete -or $adjacentSamples.Incomplete) -and $script:Criteria['R-FILES-WRITE'].Outcome -ne 'unmet') {
        Set-CriterionOutcome -Id 'R-FILES-WRITE' -Outcome unknown -Method inventory -Reason 'Adjacent-directory discovery or file sampling was incomplete.'
    }

    # R-FILES-SECRETS: credential containers found by name only; their
    # contents are never read.
    $containers = Find-AdjacentItems -Root $adjacent.Paths -Match {
        -not $_.PSIsContainer -and (
            $_.Extension -in '.pfx', '.p12', '.kdbx', '.pem', '.ppk', '.ovpn', '.rdp' -or
            $_.Name -in '.env', 'wallet.dat' -or
            ($_.Name -like 'id_*' -and $_.Extension -ne '.pub'))
    }
    $script:Inventory['credentialContainers'] = $containers
    if ($containers.Paths.Count -eq 0) {
        $outcome = if ($containers.Incomplete -or $adjacent.Incomplete) { 'unknown' } else { 'met' }
        Set-CriterionOutcome -Id 'R-FILES-SECRETS' -Outcome $outcome -Method inventory `
            -Reason $(if ($outcome -eq 'met') { 'No credential containers were found by name in the searched adjacent trees.' } else { 'The name search of adjacent trees was incomplete and found no credential containers.' })
    }
    else {
        Resolve-AccessTargets -Check FILES -Criterion 'R-FILES-SECRETS' -Right Read -Path $containers.Paths `
            -Capability 'readable credential container outside workspace' -Scope 'host-files' `
            -Impact 'A certificate, private key, password database or connection profile outside the workspace is readable.' -Severity high `
            -NoneReason 'No credential containers outside the workspace could be evaluated.' `
            -MetReason "None of $($containers.Paths.Count) credential containers found by name is readable." `
            -UnmetReasonFormat '{0} of {1} credential containers found by name are readable.' | Out-Null
        if (($containers.Incomplete -or $adjacent.Incomplete) -and $script:Criteria['R-FILES-SECRETS'].Outcome -ne 'unmet') {
            Set-CriterionOutcome -Id 'R-FILES-SECRETS' -Outcome unknown -Method inventory -Reason 'The name search of adjacent trees was incomplete.'
        }
    }

    Invoke-RegistryOthersCheck
}

function Get-LoadedUserHives {
    # Names only: Get-ChildItem opens each subkey and silently drops the
    # ones this identity cannot open, which are exactly the other users.
    return @([Microsoft.Win32.Registry]::Users.GetSubKeyNames())
}

function Invoke-RegistryOthersCheck {
    # R-REG-OTHERS. A denial (5) is protection; any other probe error and a
    # failed hive enumeration leave the criterion unknown.
    $ownSid = $null
    try { $ownSid = [AgentSandboxAssessmentNative]::GetCurrentToken().UserSid } catch { }
    $targets = @()
    $enumerationFailed = $false
    try {
        foreach ($sid in @(Get-LoadedUserHives | Where-Object { $_ -match '^S-1-5-21-' -and $_ -notlike '*_Classes' -and $_ -ne $ownSid })) {
            $targets += @{ Hive = 3; Sub = "$sid\Software"; Display = "HKU\$sid\Software"; Capability = 'readable other-user hive'
                Scope = 'cross-user-registry'; Impact = 'Another user''s registry data is readable.'; Severity = 'medium' }
        }
    }
    catch { $enumerationFailed = $true }
    foreach ($sensitive in @('SAM\SAM', 'SECURITY')) {
        $targets += @{ Hive = 2; Sub = $sensitive; Display = "HKLM\$sensitive"; Capability = 'readable sensitive registry hive'
            Scope = 'registry'; Impact = 'A sensitive security hive is readable.'; Severity = 'high' }
    }
    $readable = @()
    $failed = @()
    foreach ($target in $targets) {
        $result = [AgentSandboxAssessmentNative]::ProbeRegistryKey($target.Hive, $target.Sub, 0x20019)
        if ($result -eq 0) {
            $readable += $target.Display
            Add-Finding -Check FILES -Criterion 'R-REG-OTHERS' -Target $target.Display `
                -Capability $target.Capability -Result granted -Method access-request `
                -Scope $target.Scope -Impact $target.Impact -Severity $target.Severity
        }
        elseif ($result -ne 5) { $failed += "$($target.Display) (win32-$result)" }
    }
    if ($readable.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-REG-OTHERS' -Outcome 'unmet' -Method 'access-request' `
            -Reason "$($readable.Count) other-user or sensitive registry location(s) are readable."
    }
    elseif ($enumerationFailed) {
        Set-CriterionOutcome -Id 'R-REG-OTHERS' -Outcome 'unknown' -Method 'access-request' `
            -Reason 'Loaded user hives could not be enumerated.'
    }
    elseif ($failed.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-REG-OTHERS' -Outcome 'unknown' -Method 'access-request' `
            -Reason "Registry probes failed without a denial: $($failed -join '; ')."
    }
    else {
        Set-CriterionOutcome -Id 'R-REG-OTHERS' -Outcome 'met' -Method 'access-request' `
            -Reason "Every probed other-user or sensitive registry location denied read ($($targets.Count) probed)."
    }
}

# --- DESKTOP ------------------------------------------------------------------

function Invoke-DesktopCheck {
    $winsta = [AgentSandboxAssessmentNative]::GetWindowStationName()
    $desk = [AgentSandboxAssessmentNative]::GetDesktopName()
    $onInteractive = ($winsta -ieq 'WinSta0') -and ($desk -ieq 'Default')
    $inputOpenable = ([AgentSandboxAssessmentNative]::ProbeInputDesktop(0x41) -eq 0)  # READOBJECTS|ENUMERATE

    $ownSid = $null
    try { $ownSid = [AgentSandboxAssessmentNative]::GetCurrentToken().UserSid } catch { }
    $foreignOwned = @()
    foreach ($wpid in @([AgentSandboxAssessmentNative]::GetVisibleWindowProcessIds() | Sort-Object -Unique)) {
        if ($wpid -le 0 -or $wpid -eq $PID) { continue }
        $info = [AgentSandboxAssessmentNative]::GetProcessToken($wpid)
        if ($info -and $info.UserSid -and $info.UserSid -ne $ownSid) { $foreignOwned += $wpid }
    }
    $script:Inventory['desktop'] = [ordered]@{
        windowStation = $winsta; desktop = $desk; onInteractiveDesktop = $onInteractive
        inputDesktopOpenable = $inputOpenable; foreignOwnedWindowCount = $foreignOwned.Count
    }

    # Broker named pipes: inventory presence of known names only; never connect.
    $knownPipes = @('docker_engine', 'openssh-ssh-agent')
    $presentPipes = @()
    try {
        $pipeNames = @(Get-ChildItem -Path '\\.\pipe\' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        $presentPipes = @($knownPipes | Where-Object { $pipeNames -contains $_ })
    }
    catch { }
    $script:Inventory['brokerPipes'] = @($presentPipes)

    if ($onInteractive -and ($inputOpenable -or $foreignOwned.Count -gt 0)) {
        $why = if ($inputOpenable) { 'the input desktop is openable' }
        else { "visible windows are owned by another identity ($($foreignOwned.Count))" }
        Set-CriterionOutcome -Id 'R-DESKTOP' -Outcome 'unmet' -Method 'access-request' `
            -Reason "Shares the interactive desktop ($winsta\$desk): $why."
        Add-Finding -Check DESKTOP -Criterion 'R-DESKTOP' -Target "$winsta\$desk" `
            -Capability 'interactive desktop access' -Result granted -Method access-request -Scope 'desktop' `
            -Impact 'Can observe or drive the interactive user''s UI session.' -Severity high
    }
    elseif (-not $onInteractive -and -not $inputOpenable) {
        Set-CriterionOutcome -Id 'R-DESKTOP' -Outcome 'met' -Method 'access-request' `
            -Reason "Not on WinSta0\Default ($winsta\$desk) and the input desktop is not openable."
    }
    else {
        Set-CriterionOutcome -Id 'R-DESKTOP' -Outcome 'unknown' -Method 'access-request' `
            -Reason "Indeterminate desktop exposure ($winsta\$desk, inputDesktopOpenable=$inputOpenable)."
    }
}

# --- NETWORK ------------------------------------------------------------------

function ConvertTo-NetworkTarget {
    param([Parameter(Mandatory)][string]$Spec)

    $split = $Spec.IndexOf(':')
    if ($split -lt 1) { return $null }
    $kind = $Spec.Substring(0, $split).ToLowerInvariant()
    $rest = $Spec.Substring($split + 1)
    switch ($kind) {
        'dns' { if ($rest) { return [pscustomobject]@{ Raw = $Spec; Kind = 'dns'; HostName = $rest; Port = 0 } } }
        'smb' { if ($rest) { return [pscustomobject]@{ Raw = $Spec; Kind = 'tcp'; HostName = $rest; Port = 445 } } }
        'tcp' {
            if ($rest.StartsWith('[')) {
                $close = $rest.IndexOf(']')
                if ($close -lt 2) { return $null }
                $hostName = $rest.Substring(1, $close - 1)
                $portText = $rest.Substring($close + 1).TrimStart(':')
            }
            else {
                $lastColon = $rest.LastIndexOf(':')
                if ($lastColon -lt 1) { return $null }
                $hostName = $rest.Substring(0, $lastColon)
                $portText = $rest.Substring($lastColon + 1)
            }
            $port = 0
            if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { return $null }
            return [pscustomobject]@{ Raw = $Spec; Kind = 'tcp'; HostName = $hostName; Port = $port }
        }
    }
    return $null
}

function Get-AddressClass {
    param([Parameter(Mandatory)][string]$HostOrIp)

    $ip = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($HostOrIp, [ref]$ip)) {
        try { $ip = @([System.Net.Dns]::GetHostAddresses($HostOrIp))[0] } catch { return 'unknown' }
    }
    if (-not $ip) { return 'unknown' }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return 'loopback' }
    $bytes = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -eq 10) { return 'lan' }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return 'lan' }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return 'lan' }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return 'lan' }
        return 'internet'
    }
    if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { return 'lan' }
    if (($bytes[0] -band 0xFE) -eq 0xFC) { return 'lan' }  # fc00::/7 unique-local
    return 'internet'
}

function ConvertTo-ConnectOutcome {
    # Classifies a failed connect. WSAEACCES (10013) is a local policy denial,
    # typically Windows Firewall; WSAECONNREFUSED (10061) means the packet
    # reached the host. Other errors do not show where the attempt stopped.
    param([int]$SocketError)

    switch ($SocketError) {
        10013 { 'blocked' }
        10061 { 'refused' }
        10060 { 'timeout' }
        default { 'error' }
    }
}

function Invoke-TcpProbe {
    # Connects and closes without sending any application data. Returns
    # connected, refused, blocked, timeout or error.
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 3000)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { return 'timeout' }
        $client.EndConnect($async)
        return 'connected'
    }
    catch {
        $exception = $_.Exception
        while ($exception -and $exception -isnot [System.Net.Sockets.SocketException]) { $exception = $exception.InnerException }
        if ($exception) { return ConvertTo-ConnectOutcome $exception.ErrorCode }
        return 'error'
    }
    finally { $client.Close() }
}

function Get-LateralTargets {
    # Lateral targets from local configuration only: each default gateway
    # (TCP 80, 443, 53), each private-range DNS server (TCP 53) and one
    # loopback port that is not a configured proxy. A blocked or refused
    # connect is decisive without a listener, so other hosts need not be
    # discovered. IPv6 link-local addresses need a scope and are skipped, as
    # are deprecated site-local ones (Windows lists fec0:0:0:ffff::1-3 as
    # placeholder DNS servers when none is configured).
    param([string[]]$Gateway = @(), [string[]]$DnsServer = @(), [int[]]$ExcludeLoopbackPort = @())

    $specs = [Collections.Generic.List[string]]::new()
    $hosts = @(@($Gateway | ForEach-Object { @{ Address = $_; Ports = @(80, 443, 53) } }) +
        @($DnsServer | ForEach-Object { @{ Address = $_; Ports = @(53) } }))
    foreach ($entry in $hosts) {
        $ip = [System.Net.IPAddress]::None
        if (-not [System.Net.IPAddress]::TryParse([string]$entry.Address, [ref]$ip)) { continue }
        if ($ip.Equals([System.Net.IPAddress]::Any) -or $ip.Equals([System.Net.IPAddress]::IPv6Any) -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { continue }
        if ((Get-AddressClass -HostOrIp $ip.ToString()) -ne 'lan') { continue }
        $hostText = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "[$ip]" } else { "$ip" }
        foreach ($port in $entry.Ports) { $specs.Add("tcp:${hostText}:$port") }
    }
    $loopbackPort = @(49151, 49150 | Where-Object { $_ -notin $ExcludeLoopbackPort })[0]
    $specs.Add("tcp:127.0.0.1:$loopbackPort")
    return @($specs | Select-Object -Unique)
}

function Get-LoopbackListenerTargets {
    # TCP listeners reachable through loopback: loopback and wildcard local
    # addresses, as tcp:<loopback>:<port> specs. Allowed proxy ports are left
    # out. Throws when the listener table cannot be read.
    param([int[]]$ExcludePort = @(), [int]$MaxTargets = 64)

    $specs = [Collections.Generic.List[string]]::new()
    foreach ($listener in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
        if ([int]$listener.LocalPort -in $ExcludePort) { continue }
        $address = [string]$listener.LocalAddress
        $loopback = if ($address -in '0.0.0.0', '127.0.0.1') { '127.0.0.1' } elseif ($address -in '::', '::1') { '[::1]' } else { $null }
        if ($loopback) { $specs.Add("tcp:${loopback}:$($listener.LocalPort)") }
    }
    return @($specs | Select-Object -Unique | Select-Object -First $MaxTargets)
}

function Format-OutcomeCount {
    param([object[]]$Result)

    return (@($Result | Group-Object -Property Outcome | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')
}

function Get-EnvironmentProxy {
    # HTTP_PROXY and HTTPS_PROXY as curl reads them; a value without a scheme
    # is an http:// proxy. Uri is $null when the value does not parse.
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not $value) { continue }
        $text = if ($value -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $value } else { "http://$value" }
        $uri = $null
        if (-not [Uri]::TryCreate($text, [UriKind]::Absolute, [ref]$uri)) { $uri = $null }
        [pscustomobject]@{ Variable = $name; Value = $value; Uri = $uri }
    }
}

function Invoke-ProxyProbe {
    # Sends one request for the default Internet destination through an HTTP
    # proxy and reads only the status line: CONNECT for HTTPS_PROXY, HEAD for
    # HTTP_PROXY. Returns the status code, or 0 when no HTTP response arrived.
    param(
        [Parameter(Mandatory)][Uri]$Proxy,
        [Parameter(Mandatory)][string]$Variable,
        [string]$HostName = 'example.com',
        [int]$TimeoutMs = 5000
    )

    $request = if ($Variable -eq 'HTTPS_PROXY') { "CONNECT ${HostName}:443 HTTP/1.1`r`nHost: ${HostName}:443`r`n`r`n" }
    else { "HEAD http://$HostName/ HTTP/1.1`r`nHost: $HostName`r`nConnection: close`r`n`r`n" }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($Proxy.DnsSafeHost, $Proxy.Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { return 0 }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $bytes = [Text.Encoding]::ASCII.GetBytes($request)
        $stream.Write($bytes, 0, $bytes.Length)
        $statusLine = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII).ReadLine()
        if ($statusLine -match '^HTTP/\d(?:\.\d)?\s+(\d{3})\b') { return [int]$Matches[1] }
        return 0
    }
    catch { return 0 }
    finally { $client.Close() }
}

function Invoke-NetworkCheck {
    # Inventory (always): interfaces, gateways, DNS, proxy.
    $interfaces = @()
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            $props = $nic.GetIPProperties()
            $interfaces += [ordered]@{
                name      = $nic.Name
                type      = $nic.NetworkInterfaceType.ToString()
                addresses = @($props.UnicastAddresses | ForEach-Object { $_.Address.IPAddressToString })
                gateways  = @($props.GatewayAddresses | ForEach-Object { $_.Address.IPAddressToString })
                dns       = @($props.DnsAddresses | ForEach-Object { $_.IPAddressToString })
            }
        }
    }
    catch { }
    $userProxy = $null
    try {
        $wininet = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if (($wininet.PSObject.Properties.Name -contains 'ProxyEnable') -and $wininet.ProxyEnable -eq 1 -and
            ($wininet.PSObject.Properties.Name -contains 'ProxyServer')) {
            $userProxy = (Protect-Text ([string]$wininet.ProxyServer))
        }
    }
    catch { }
    $proxyConfigured = [bool]($env:HTTPS_PROXY -or $env:HTTP_PROXY -or $userProxy)

    # Mapped network shares (configured reach to remote file servers). Inventory
    # of presence only; shares are never contacted or authenticated to here.
    $mappedShares = @()
    $sharesError = $null
    try {
        foreach ($connection in @(Get-CimInstance -ClassName Win32_NetworkConnection -ErrorAction Stop)) {
            $mappedShares += [ordered]@{ local = $connection.LocalName; remote = (Protect-Text $connection.RemoteName) }
        }
    }
    catch { $sharesError = $_.Exception.Message }

    $script:Inventory['network'] = [ordered]@{
        interfaces   = @($interfaces)
        proxy        = [ordered]@{ envHttps = (Protect-Text $env:HTTPS_PROXY); envHttp = (Protect-Text $env:HTTP_PROXY); user = $userProxy }
        mappedShares = @($mappedShares)
    }

    # R-NET-SHARES
    if ($mappedShares.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-NET-SHARES' -Outcome 'unmet' -Method 'inventory' `
            -Reason "$($mappedShares.Count) network share(s) are mapped into the agent session; remote file-server data is reachable."
        foreach ($share in $mappedShares) {
            Add-Finding -Check NETWORK -Criterion 'R-NET-SHARES' -Target ([string]$share.remote) `
                -Capability 'mapped network share' -Result observed -Method inventory -Scope 'lateral' `
                -Impact 'Data on a remote file server is reachable from the agent context.' -Severity medium
        }
    }
    elseif ($sharesError) {
        Set-CriterionOutcome -Id 'R-NET-SHARES' -Outcome 'unknown' -Method 'inventory' `
            -Reason "Mapped network shares could not be enumerated: $sharesError"
    }
    else {
        Set-CriterionOutcome -Id 'R-NET-SHARES' -Outcome 'met' -Method 'inventory' `
            -Reason 'No network shares are mapped into the agent session.'
    }

    # Targets: the documented Internet defaults, the lateral targets from local
    # configuration, plus any -NetworkTarget.
    $loopbackProxyPorts = @(Get-EnvironmentProxy | Where-Object { $_.Uri -and $_.Uri.IsLoopback } | ForEach-Object { $_.Uri.Port })
    $lateralSpecs = @(Get-LateralTargets -Gateway @($interfaces | ForEach-Object { $_.gateways }) `
            -DnsServer @($interfaces | ForEach-Object { $_.dns }) -ExcludeLoopbackPort $loopbackProxyPorts)
    try { $lateralSpecs += @(Get-LoopbackListenerTargets -ExcludePort $loopbackProxyPorts) }
    catch {
        Add-AssessmentError -Check NETWORK -Category 'inventory' -Message "Could not list local TCP listeners: $($_.Exception.Message)"
    }
    $specs = @('dns:example.com', 'tcp:example.com:443', 'tcp:1.1.1.1:443', 'tcp:[2606:4700:4700::1111]:443')
    $specs += $lateralSpecs
    $specs += @($NetworkTarget)
    $specs = @($specs | Select-Object -Unique)
    $script:NetworkProbed = ($specs.Count -gt 0)
    $script:NetworkTargetsUsed = @($specs)

    $probeResults = @()
    foreach ($spec in $specs) {
        $target = ConvertTo-NetworkTarget -Spec $spec
        if (-not $target) {
            Add-AssessmentError -Check NETWORK -Category 'bad-target' -Message "Ignored malformed network target: $spec"
            continue
        }
        if ($target.Kind -eq 'dns') {
            $outcome = 'error'
            try { if (@([System.Net.Dns]::GetHostAddresses($target.HostName)).Count -gt 0) { $outcome = 'resolved' } } catch { }
            $probeResults += [pscustomobject]@{ Spec = $spec; Kind = 'dns'; Class = 'n/a'; Outcome = $outcome }
            continue
        }
        $class = Get-AddressClass -HostOrIp $target.HostName
        $outcome = Invoke-TcpProbe -HostName $target.HostName -Port $target.Port
        $probeResults += [pscustomobject]@{ Spec = $spec; Kind = 'tcp'; Class = $class; Outcome = $outcome }
        # A refused connect also proves the packet reached the host.
        if ($outcome -in 'connected', 'refused') {
            $criterion = if ($class -eq 'internet') { 'R-NET-INTERNET' } else { 'R-NET-LATERAL' }
            $severity = if ($class -eq 'internet') { 'high' } else { 'medium' }
            Add-Finding -Check NETWORK -Criterion $criterion -Target $spec -Capability "tcp $outcome ($class)" `
                -Result granted -Method observed-operation -Scope 'egress' `
                -Impact 'A network destination is reachable from the agent context.' -Severity $severity
        }
    }
    $script:Inventory['networkProbes'] = @($probeResults)

    # Proxy route: ask each environment proxy for the default Internet
    # destination. A proxy URL carrying credentials is not used, because this
    # assessment never uses discovered credentials.
    $proxyResults = @()
    foreach ($proxy in @(Get-EnvironmentProxy)) {
        $status = 0
        $result = if (-not $proxy.Uri -or $proxy.Uri.Scheme -ne 'http') { 'unsupported proxy URL' }
        elseif ($proxy.Uri.UserInfo) { 'not probed: URL carries credentials' }
        else {
            $status = Invoke-ProxyProbe -Proxy $proxy.Uri -Variable $proxy.Variable
            if ($status -ge 200 -and $status -lt 300) { 'reached' } elseif ($status) { "returned $status" } else { 'no HTTP response' }
        }
        $proxyResults += [pscustomobject]@{ Variable = $proxy.Variable; Proxy = (Protect-Text $proxy.Value); Status = $status; Result = $result }
        if ($result -eq 'reached') {
            Add-Finding -Check NETWORK -Criterion 'R-NET-INTERNET' -Target "$($proxy.Variable) -> example.com" `
                -Capability "Internet request via proxy (HTTP $status)" -Result granted -Method observed-operation -Scope 'egress' `
                -Impact 'An arbitrary Internet destination is reachable through the configured proxy.' -Severity high
        }
    }
    $script:Inventory['proxyProbes'] = @($proxyResults)
    $proxyReached = @($proxyResults | Where-Object { $_.Result -eq 'reached' })
    # 403/451 are a proxy's explicit policy refusal; 407 only asks for
    # credentials. Every configured proxy must have been probed.
    $proxyRefused = @($proxyResults | Where-Object { $_.Status -in 403, 451 })
    $proxyUntested = @($proxyResults | Where-Object { $_.Status -eq 0 -and $_.Result -ne 'no HTTP response' })
    $proxyNote = if ($proxyResults.Count -gt 0) {
        ' Proxy route: ' + (($proxyResults | ForEach-Object { "$($_.Variable) $($_.Result)" }) -join '; ') + '.'
    }
    else { '' }

    # R-NET-INTERNET: a DNS resolution alone never decides this. Connected or
    # refused proves reach; only an explicit local denial (blocked) or an
    # explicit proxy refusal is enforcement evidence.
    $internetTcp = @($probeResults | Where-Object { $_.Kind -eq 'tcp' -and $_.Class -eq 'internet' })
    $internetReached = @($internetTcp | Where-Object { $_.Outcome -in 'connected', 'refused' })
    $internetBlocked = @($internetTcp | Where-Object { $_.Outcome -eq 'blocked' })
    $proxiesClosed = @($proxyResults | Where-Object { $_.Status -notin 403, 451 }).Count -eq 0
    $directNote = " Direct probes: $(Format-OutcomeCount $internetTcp)."
    if ($internetReached.Count -gt 0) {
        $reason = 'A direct TCP connection reached an Internet destination.'
        if ($proxyConfigured) { $reason += ' A proxy is configured, so this is a bypass on the tested route.' }
        Set-CriterionOutcome -Id 'R-NET-INTERNET' -Outcome 'unmet' -Method 'observed-operation' -Reason ($reason + $directNote + $proxyNote)
    }
    elseif ($proxyReached.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-NET-INTERNET' -Outcome 'unmet' -Method 'observed-operation' `
            -Reason "An arbitrary Internet destination (example.com) is reachable through the configured proxy.$directNote$proxyNote"
    }
    elseif ($internetTcp.Count -gt 0 -and $internetBlocked.Count -eq $internetTcp.Count -and $proxiesClosed) {
        Set-CriterionOutcome -Id 'R-NET-INTERNET' -Outcome 'met' -Method 'observed-operation' `
            -Reason "All $($internetTcp.Count) direct Internet TCP probes were blocked by local policy.$proxyNote DNS and UDP egress were not assessed."
    }
    elseif ($internetTcp.Count -gt 0 -and $proxyRefused.Count -gt 0 -and $proxyUntested.Count -eq 0) {
        Set-CriterionOutcome -Id 'R-NET-INTERNET' -Outcome 'met' -Method 'observed-operation' `
            -Reason "No direct Internet TCP probe reached its host and the configured proxy explicitly refused an arbitrary destination.$directNote$proxyNote DNS and UDP egress were not assessed."
    }
    elseif ($internetTcp.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-NET-INTERNET' -Outcome 'unknown' -Method 'observed-operation' `
            -Reason "No Internet TCP probe reached its host, but timeouts and other errors do not establish enforced restriction.$directNote$proxyNote"
    }
    else {
        Set-CriterionOutcome -Id 'R-NET-INTERNET' -Outcome 'unknown' -Method 'observed-operation' `
            -Reason 'No Internet TCP target could be probed.'
    }

    # R-NET-LATERAL: same evidence rules for gateway, DNS, loopback and
    # supplied LAN targets.
    $lateralTcp = @($probeResults | Where-Object { $_.Kind -eq 'tcp' -and ($_.Class -eq 'lan' -or $_.Class -eq 'loopback') })
    $lateralReached = @($lateralTcp | Where-Object { $_.Outcome -in 'connected', 'refused' })
    $lateralBlocked = @($lateralTcp | Where-Object { $_.Outcome -eq 'blocked' })
    if ($lateralTcp.Count -eq 0) {
        Set-CriterionOutcome -Id 'R-NET-LATERAL' -Outcome 'unknown' -Method 'observed-operation' `
            -Reason 'No LAN or loopback target was available to probe.'
    }
    elseif ($lateralReached.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-NET-LATERAL' -Outcome 'unmet' -Method 'observed-operation' `
            -Reason "$($lateralReached.Count) of $($lateralTcp.Count) LAN/loopback probes reached their host (connected or refused)."
    }
    elseif ($lateralBlocked.Count -eq $lateralTcp.Count) {
        Set-CriterionOutcome -Id 'R-NET-LATERAL' -Outcome 'met' -Method 'observed-operation' `
            -Reason "All $($lateralTcp.Count) LAN/loopback probes (gateway, DNS server, loopback, supplied targets) were blocked by local policy."
    }
    else {
        Set-CriterionOutcome -Id 'R-NET-LATERAL' -Outcome 'unknown' -Method 'observed-operation' `
            -Reason "No LAN/loopback probe reached its host, but timeouts and other errors do not establish enforced restriction. Probes: $(Format-OutcomeCount $lateralTcp)."
    }
}

# --- HANDOFF ------------------------------------------------------------------

function Get-HandoffArtifacts {
    # Programs and build entry points another identity may run or build.
    param([string[]]$Root, [int]$MaxPerRoot = 20)

    return Find-AdjacentItems -Root $Root -MaxPerRoot $MaxPerRoot -Match {
        if ($_.PSIsContainer) { $_.Name -eq 'hooks' -and $_.Parent.Name -eq '.git' }
        else { $_.Extension -in '.exe', '.dll' -or $_.Name -in 'build.ps1', 'CMakeLists.txt' }
    }
}

function Invoke-HandoffCheck {
    # A-HANDOFF-SHARED: locations an agent can write that another identity runs.
    $sharedPaths = New-Object System.Collections.Generic.List[string]
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath) {
        foreach ($dir in ($machinePath -split ';' | Where-Object { $_ -and $_.Trim() })) {
            $sharedPaths.Add($dir.Trim()) | Out-Null
        }
    }
    $sharedPaths.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')) | Out-Null
    foreach ($programFiles in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($programFiles -and (Test-Path -LiteralPath $programFiles)) {
            foreach ($dir in @(Get-ChildItem -LiteralPath $programFiles -Directory -Force -ErrorAction SilentlyContinue)) {
                $sharedPaths.Add($dir.FullName) | Out-Null
            }
        }
    }
    foreach ($profile in $script:OtherProfiles) { $sharedPaths.Add($profile) | Out-Null }

    $pathResult = Get-MatchingTargets -Check HANDOFF -Criterion 'A-HANDOFF-SHARED' -Right Write -Path @($sharedPaths) `
        -Capability 'agent-writable shared execution location' -Scope 'handoff' `
        -Impact 'Code written here executes under another identity.' -Severity high
    $runKeys = @(
        @{ Hive = 2; Sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Display = 'HKLM\Software\...\CurrentVersion\Run' }
        @{ Hive = 2; Sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Display = 'HKLM\Software\...\CurrentVersion\RunOnce' }
        @{ Hive = 2; Sub = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'; Display = 'HKLM\Software\Wow6432Node\...\Run' }
    )
    $runResult = Get-WritableRegistryKeys -Check HANDOFF -Criterion 'A-HANDOFF-SHARED' -Key $runKeys `
            -Capability 'agent-writable Run key' -Scope 'handoff' `
            -Impact 'Code written here executes under another identity at logon.' -Severity high

    # Programs, DLLs and build entry points outside Program Files that the
    # interactive user may launch or build, for example portable tools.
    $artifacts = Get-HandoffArtifacts -Root (Get-AdjacentDirectories).Paths
    $script:Inventory['handoffAdjacentArtifacts'] = $artifacts
    $artifactResult = Get-MatchingTargets -Check HANDOFF -Criterion 'A-HANDOFF-SHARED' -Right Write -Path $artifacts.Paths `
        -Capability 'agent-writable program or build entry point outside Program Files' -Scope 'handoff' `
        -Impact 'Another identity that runs or builds this executes agent-written code.' -Severity high

    $matchedCount = @($pathResult.Matched).Count + $runResult.Matched.Count + @($artifactResult.Matched).Count
    $probedCount = @($pathResult.Existing).Count + $runKeys.Count + @($artifactResult.Existing).Count
    if ($probedCount -eq 0) {
        Set-CriterionOutcome -Id 'A-HANDOFF-SHARED' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason 'No shared execution locations were available to evaluate.'
    }
    elseif ($matchedCount -gt 0) {
        Set-CriterionOutcome -Id 'A-HANDOFF-SHARED' -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason "$matchedCount shared execution location(s) (PATH, Program Files, startup, Run keys, other profiles, programs and build entry points outside Program Files) are agent-writable."
    }
    elseif ($pathResult.Unknown.Count -gt 0 -or $runResult.Unknown.Count -gt 0 -or $artifactResult.Unknown.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-HANDOFF-SHARED' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason 'Some shared execution locations could not be evaluated for write access.'
    }
    elseif ($artifacts.Incomplete) {
        Set-CriterionOutcome -Id 'A-HANDOFF-SHARED' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'The search for programs and build entry points outside Program Files was incomplete or reached its limit.'
    }
    else {
        Set-CriterionOutcome -Id 'A-HANDOFF-SHARED' -Outcome 'met' -Method 'permission-analysis' `
            -Reason "No shared execution location is agent-writable ($probedCount probed)."
    }

    # A-HANDOFF-WORKSPACE: agent output consumed by another identity.
    $ws = $script:WorkspacePath
    $wsAccess = Get-PathAccess -Path $ws
    $wsWritable = [bool](Test-AnyWrite -Access $wsAccess)
    $ownSid = $null
    try { $ownSid = [AgentSandboxAssessmentNative]::GetCurrentToken().UserSid } catch { }
    $benignSids = @($ownSid, 'S-1-5-18', 'S-1-3-0',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') | Where-Object { $_ }
    $otherReaders = @()
    $aclUnknown = $false
    try {
        $acl = Get-Acl -LiteralPath $ws -ErrorAction Stop
        foreach ($rule in @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' })) {
            if ($rule.FileSystemRights.ToString() -notmatch 'Read|Modify|FullControl|ListDirectory|ExecuteFile') { continue }
            $sid = $null
            try {
                $sid = if ($rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $rule.IdentityReference.Value
                }
                else { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            }
            catch { $sid = $rule.IdentityReference.ToString() }
            if ($benignSids -notcontains $sid) { $otherReaders += $sid }
        }
    }
    catch {
        $aclUnknown = $true
        Add-AssessmentError -Check HANDOFF -Category 'acl-read' -Message "Could not read workspace ACL: $($_.Exception.Message)"
    }
    $otherReaders = @($otherReaders | Select-Object -Unique)

    # Inventory of executable handoff artifacts (counts only; never executed).
    $artifact = [ordered]@{
        gitHooks    = @(Get-ChildItem -LiteralPath (Join-Path $ws '.git\hooks') -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ne '.sample' }).Count
        vscodeTasks = [bool](Test-Path -LiteralPath (Join-Path $ws '.vscode\tasks.json'))
        workflows   = @(Get-ChildItem -LiteralPath (Join-Path $ws '.github\workflows') -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.yml', '.yaml' }).Count
    }
    $script:Inventory['handoffArtifacts'] = $artifact

    # Git runs hooks and config-defined commands (core.fsmonitor,
    # core.hooksPath) for the repository owner without a safe.directory
    # exception, so agent-writable git control files in a repository owned by
    # another identity hand code to that identity.
    $gitMatched = @()
    $gitDir = Join-Path $ws '.git'
    if (Test-Path -LiteralPath $gitDir -PathType Container) {
        $gitOwner = $null
        try { $gitOwner = Get-OwnerSid -Path $gitDir } catch { }
        if ($gitOwner -and $gitOwner -ne $ownSid) {
            $gitMatched = @((Get-MatchingTargets -Check HANDOFF -Criterion 'A-HANDOFF-WORKSPACE' -Right Write `
                        -Path @((Join-Path $gitDir 'hooks'), (Join-Path $gitDir 'config')) `
                        -Capability 'agent-writable git hooks or config in a repository owned by another identity' -Scope 'handoff' `
                        -Impact 'Git runs hooks and config-defined commands as the repository owner.' -Severity high).Matched)
        }
    }

    if ($gitMatched.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-HANDOFF-WORKSPACE' -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason 'The workspace repository is owned by another identity and the agent can write its git hooks or config; git runs them as the owner.'
    }
    elseif ($wsWritable -and $otherReaders.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-HANDOFF-WORKSPACE' -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason "Workspace is agent-writable and its ACL grants read to $($otherReaders.Count) other principal(s); consumer privileges unknown."
        Add-Finding -Check HANDOFF -Criterion 'A-HANDOFF-WORKSPACE' -Target $ws `
            -Capability 'agent-writable workspace read by other identities' -Result observed -Method permission-analysis `
            -Scope 'handoff' -Impact 'Agent-written source/config may be built, run or opened by another identity.' -Severity medium
    }
    elseif ((-not $wsWritable -and (Test-UnknownWrite $wsAccess)) -or ($wsWritable -and $aclUnknown)) {
        Set-CriterionOutcome -Id 'A-HANDOFF-WORKSPACE' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason 'Workspace write permissions or consumer access could not be evaluated.'
    }
    else {
        Set-CriterionOutcome -Id 'A-HANDOFF-WORKSPACE' -Outcome 'met' -Method 'permission-analysis' `
            -Reason $(if (-not $wsWritable) { 'Workspace is not agent-writable.' } else { 'No other principal has read access to the workspace.' })
    }
}

# --- INDIRECT -----------------------------------------------------------------

function Get-ServiceImagePath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        $end = $trimmed.IndexOf('"', 1)
        if ($end -gt 1) { return $trimmed.Substring(1, $end - 1) }
    }
    $match = [regex]::Match($trimmed, '^(?<p>.*?\.exe)(\s|$)', 'IgnoreCase')
    if ($match.Success) { return $match.Groups['p'].Value }
    return ($trimmed -split '\s')[0]
}

function Get-ExecutionIdentitySid {
    param([string]$Account)

    if (-not $Account) { return $null }
    if ($Account -match '^S-1-\d+(-\d+)+$') { return $Account }
    if ($Account -in @('LocalSystem', 'SYSTEM', 'NT AUTHORITY\SYSTEM')) { return 'S-1-5-18' }
    try {
        return ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch { return $null }
}

function Expand-MachinePath {
    # Expands only variables that resolve identically for every identity.
    # Per-user variables such as %LOCALAPPDATA% depend on the task principal
    # and stay unexpanded, so callers keep treating them as unresolved.
    param([string]$Path)

    $machine = @('windir', 'SystemRoot', 'SystemDrive', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
        'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432', 'ProgramData', 'ALLUSERSPROFILE')
    return [regex]::Replace($Path, '%([^%]+)%', {
            param($match)
            $name = $match.Groups[1].Value
            $value = if ($machine -contains $name) { [Environment]::GetEnvironmentVariable($name, 'Process') }
            if ($value) { $value } else { $match.Value }
        })
}

function Read-RegistryValue {
    # Reads a key's default or named value without expanding variables.
    # State is present, absent or denied; it describes the key, so a key
    # without the requested value is present with a $null Value.
    param([Parameter(Mandatory)][string]$Path, [string]$Name = '')

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return [pscustomobject]@{ State = 'present'; Value = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') }
    }
    catch [Management.Automation.ItemNotFoundException] { return [pscustomobject]@{ State = 'absent'; Value = $null } }
    catch { return [pscustomobject]@{ State = 'denied'; Value = $null } }
}

function Get-ArgumentPathTokens {
    # Absolute paths an argument string hands to a program, after expanding
    # machine-wide variables. Flags and other words are data. A bare DLL name,
    # optionally after a -name: or -name= prefix, resolves in -BaseDirectory
    # when present there, because LoadLibrary searches the program directory
    # first. A rundll32-style ",EntryPoint" suffix is not part of a path. Any
    # other token that looks like a file reference but is not an absolute
    # local path (per-user variable, UNC, relative or bare name) is incomplete.
    param([string]$Arguments, [string]$BaseDirectory)

    $paths = [Collections.Generic.List[string]]::new()
    $incomplete = $false
    foreach ($match in [regex]::Matches((Expand-MachinePath $Arguments), '"([^"]*)"|(\S+)')) {
        $token = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
        $path = [regex]::Match($token, '(?<![A-Za-z0-9])[A-Za-z]:[\\/].*')
        if ($path.Success -and $token -notmatch '%') {
            $paths.Add(($path.Value -replace '(\.[A-Za-z0-9]{1,5}),[^\\/]*$', '$1'))
            continue
        }
        $bareDll = [regex]::Match($token, '(?i)^(?:[-/][\w-]*[:=])?([\w.-]+\.dll)$')
        if ($bareDll.Success -and $BaseDirectory) {
            $candidate = Join-Path $BaseDirectory $bareDll.Groups[1].Value
            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
                $paths.Add($candidate)
                continue
            }
        }
        if ($token -match '%|\\' -or $token -match '(?i)\.(?:ps1|psm1|bat|cmd|exe|dll|js|vbs|py|xml|json|config|ini|txt)$') {
            $incomplete = $true
        }
    }
    return [pscustomobject]@{ Paths = @($paths.ToArray()); Incomplete = $incomplete }
}

function Resolve-BareExecutable {
    # Resolves a bare program name the way CreateProcess searches: the
    # working directory, the system directories, then the machine PATH.
    # Agent-writable PATH directories are assessed by A-HANDOFF-SHARED.
    param([string]$Name, [string]$WorkingDirectory)

    if ($Name -notmatch '^[\w.-]+$') { return $null }
    $file = if ([IO.Path]::GetExtension($Name)) { $Name } else { "$Name.exe" }
    $directories = @($WorkingDirectory, [Environment]::SystemDirectory, (Join-Path $env:windir 'System'), $env:windir) +
        @(([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') | ForEach-Object { Expand-MachinePath $_.Trim() })
    foreach ($directory in $directories) {
        if ($directory -notmatch '^[A-Za-z]:[\\/]' -or $directory -match '%') { continue }
        $candidate = Join-Path $directory $file
        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) { return $candidate }
    }
    return $null
}

function Resolve-ComHandler {
    # Resolves a COM task handler to the server file it loads, plus the
    # registry keys whose change would redirect it. A principal's per-user
    # registration overrides the machine one; a per-user hive this identity
    # cannot read is accepted as having no override (see the spec). A class
    # hosted by a service (AppID LocalService) is assessed through the
    # services check; an unregistered class through whether it can be added.
    param([string]$ClassId, [string]$PrincipalSid)

    $result = [pscustomobject]@{ Paths = @(); ArgumentPaths = @(); Keys = @(); Incomplete = $true }
    if ($ClassId -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { return $result }
    $registrations = @()
    if ($PrincipalSid) {
        foreach ($sub in @("${PrincipalSid}_Classes\CLSID", "$PrincipalSid\Software\Classes\CLSID")) {
            $registrations += @{ Hive = 3; Root = 'Registry::HKEY_USERS\'; Sub = "$sub\$ClassId" }
            # Creating this key would plant an override for the principal.
            $result.Keys += @{ Hive = 3; Sub = $sub; Access = 0x4; Display = "HKU\$sub (create override)" }
        }
    }
    $registrations += @{ Hive = 2; Root = 'Registry::HKEY_LOCAL_MACHINE\'; Sub = "SOFTWARE\Classes\CLSID\$ClassId" }
    foreach ($registration in $registrations) {
        $base = $registration.Root + $registration.Sub
        $state = (Read-RegistryValue $base).State
        if ($state -eq 'denied' -and $registration.Hive -eq 2) { return $result }
        if ($state -ne 'present') { continue }
        if ((Read-RegistryValue "$base\TreatAs").State -ne 'absent') { return $result }
        $display = $(if ($registration.Hive -eq 2) { 'HKLM\' } else { 'HKU\' }) + $registration.Sub
        $result.Keys += @{ Hive = $registration.Hive; Sub = $registration.Sub; Access = 0x2 -bor 0x4; Display = $display }
        $inproc = Read-RegistryValue "$base\InprocServer32"
        $local = Read-RegistryValue "$base\LocalServer32"
        if ($inproc.State -eq 'present' -and $inproc.Value) {
            $server = Expand-MachinePath ([string]$inproc.Value).Trim().Trim('"')
            $result.Keys += @{ Hive = $registration.Hive; Sub = "$($registration.Sub)\InprocServer32"; Access = 0x2; Display = "$display\InprocServer32" }
            if ($server -match '^[A-Za-z]:[\\/]' -and $server -notmatch '%') {
                $result.Paths = @($server)
                $result.Incomplete = $false
            }
        }
        elseif ($local.State -eq 'present' -and $local.Value) {
            $tokens = Get-ArgumentPathTokens ([string]$local.Value)
            $result.Keys += @{ Hive = $registration.Hive; Sub = "$($registration.Sub)\LocalServer32"; Access = 0x2; Display = "$display\LocalServer32" }
            $result.Paths = @($tokens.Paths | Select-Object -First 1)
            $result.ArgumentPaths = @($tokens.Paths | Select-Object -Skip 1)
            $result.Incomplete = $tokens.Incomplete -or $result.Paths.Count -eq 0
        }
        else {
            $appId = [string](Read-RegistryValue $base -Name 'AppID').Value
            if ($appId -match '^\{[0-9A-Fa-f-]{36}\}$') {
                $appSub = "SOFTWARE\Classes\AppID\$appId"
                $service = Read-RegistryValue "Registry::HKEY_LOCAL_MACHINE\$appSub" -Name 'LocalService'
                if ($service.State -eq 'present' -and $service.Value) {
                    $result.Keys += @{ Hive = 2; Sub = $appSub; Access = 0x2; Display = "HKLM\$appSub" }
                    $result.Incomplete = $false
                }
            }
        }
        return $result
    }
    # Registered nowhere readable: the task loads nothing unless the class
    # can be registered.
    $result.Keys += @{ Hive = 2; Sub = 'SOFTWARE\Classes\CLSID'; Access = 0x4; Display = 'HKLM\SOFTWARE\Classes\CLSID (register handler)' }
    $result.Incomplete = $false
    return $result
}

function Get-TaskActionTargets {
    # Recognize common script-launch forms and COM handlers as data.
    # Ambiguous command strings, per-user environment paths and unresolvable
    # handlers remain incomplete.
    param([Parameter(Mandatory)]$Action, [string]$PrincipalSid)

    if ($Action.PSObject.Properties.Name -contains 'ClassId') {
        return Resolve-ComHandler -ClassId ([string]$Action.ClassId) -PrincipalSid $PrincipalSid
    }
    $paths = [Collections.Generic.List[string]]::new()
    $argumentPaths = @()
    $incomplete = $false
    $execute = if ($Action.PSObject.Properties.Name -contains 'Execute') { [string]$Action.Execute } else { '' }
    $arguments = if ($Action.PSObject.Properties.Name -contains 'Arguments') { [string]$Action.Arguments } else { '' }
    $working = if ($Action.PSObject.Properties.Name -contains 'WorkingDirectory') { Expand-MachinePath ([string]$Action.WorkingDirectory) } else { '' }
    $execute = Expand-MachinePath $execute.Trim('"')
    if ($execute -notmatch '^[A-Za-z]:[\\/]') {
        $resolved = Resolve-BareExecutable -Name $execute -WorkingDirectory $working
        if ($resolved) { $execute = $resolved }
    }
    if ($execute -match '^[A-Za-z]:[\\/]' -and $execute -notmatch '%') { $paths.Add($execute) }
    else { $incomplete = $true }
    # conhost --headless only hosts the command that follows; assess that.
    if ($paths.Count -gt 0 -and [IO.Path]::GetFileNameWithoutExtension($execute) -eq 'conhost' -and
        $arguments -match '^\s*--headless\s+(?:"(?<exe>[^"]+)"|(?<exe>\S+))\s*(?<rest>.*)$') {
        $hosted = [pscustomobject]@{ Execute = $Matches['exe']; Arguments = $Matches['rest']; WorkingDirectory = $working }
        $inner = Get-TaskActionTargets $hosted -PrincipalSid $PrincipalSid
        $inner.Paths = @($execute) + @($inner.Paths)
        return $inner
    }
    $interpreter = [IO.Path]::GetFileNameWithoutExtension($execute)
    $scriptArgument = $null
    if ($interpreter -in @('powershell', 'pwsh', 'cmd', 'python', 'python3', 'node', 'cscript', 'wscript', 'bash', 'sh')) {
        $pattern = switch ($interpreter) {
            { $_ -in @('powershell', 'pwsh') } { '(?i)^\s*(?:(?:-(?:NoProfile|NonInteractive|NoLogo|NoExit|Sta|Mta)\s+)|(?:-(?:ExecutionPolicy|WindowStyle)\s+\w+\s+))*-File\s+(?:"(?<path>[^"\r\n]+)"|(?<path>\S+))' }
            'cmd' { '(?i)^\s*(?:/d\s+)?/[ck]\s+(?:call\s+)?(?:"(?<path>[^"\r\n]+\.(?:cmd|bat))"|(?<path>[^\s"&|<>]+\.(?:cmd|bat)))(?:\s|$)' }
            default { '^\s*(?:"(?<path>[^"\r\n]+)"|(?<path>[^\s-][^\s]*))' }
        }
        $match = [regex]::Match($arguments, $pattern)
        if ($match.Success -and $arguments -notmatch '[&|<>]') {
            $scriptArgument = Expand-MachinePath $match.Groups['path'].Value
            if ($scriptArgument.StartsWith('-') -or
                ($interpreter -in @('powershell', 'pwsh') -and [IO.Path]::GetExtension($scriptArgument) -ne '.ps1')) {
                $scriptArgument = $null
                $incomplete = $true
            }
        }
        else { $incomplete = $true }
    }
    elseif ($arguments) {
        # Other executables can load scripts/plugins/configuration from args;
        # each absolute path among them is assessed like an execution file.
        $programDirectory = if ($paths.Count -gt 0) { Split-Path -Parent $paths[0] } else { '' }
        $tokens = Get-ArgumentPathTokens $arguments -BaseDirectory $programDirectory
        $argumentPaths = $tokens.Paths
        if ($tokens.Incomplete) { $incomplete = $true }
    }
    if ($scriptArgument) {
        if ($scriptArgument -match '%' -or $scriptArgument -match '^\\\\') { $incomplete = $true }
        elseif ($scriptArgument -match '^[A-Za-z]:[\\/]') { $paths.Add($scriptArgument) }
        elseif ($working -match '^[A-Za-z]:[\\/]' -and $working -notmatch '%') {
            $paths.Add([IO.Path]::GetFullPath((Join-Path $working $scriptArgument)))
        }
        else { $incomplete = $true }
    }
    return [pscustomobject]@{ Paths = @($paths.ToArray()); ArgumentPaths = @($argumentPaths); Keys = @(); Incomplete = $incomplete }
}

function Get-MissingFileCreateAccess {
    # Creating a missing execution file plants it. An existing parent needs
    # FILE_ADD_FILE (directory Write); a deeper existing ancestor needs a new
    # folder (Create), which its creator then owns. Returns $null when the
    # path exists but is hidden from this identity, so callers assess it as
    # present.
    param([Parameter(Mandatory)][string]$Path)

    if ((Get-PathAccess -Path $Path).ErrorCategory -ne 'not-found') { return $null }
    $parent = Split-Path -Parent $Path
    $cursor = $parent
    while ($cursor) {
        $access = Get-PathAccess -Path $cursor
        if ($access.ErrorCategory -ne 'not-found') { return $(if ($cursor -eq $parent) { $access.Write } else { $access.Create }) }
        $cursor = Split-Path -Parent $cursor
    }
    return 'unknown'
}

function Get-ExecutionFileExposure {
    # Rights that change what an execution file runs: writing the file or its
    # security, creating it while missing, deleting or replacing it, and
    # adding files beside it. Unknown rights make the result incomplete.
    param([Parameter(Mandatory)][string]$Path)

    $result = [pscustomobject]@{ Missing = $false; Writable = $null; ParentAdd = $false; Deletable = $false; Replacement = $false; Incomplete = $false }
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $create = Get-MissingFileCreateAccess -Path $Path
        if ($create) {
            $result.Missing = $true
            if ($create -eq 'granted') { $result.Writable = 'creatable while missing' }
            elseif ($create -ne 'denied') { $result.Incomplete = $true }
            return $result
        }
    }
    $fileAccess = Get-PathAccess -Path $Path
    $parentAccess = Get-PathAccess -Path (Split-Path -Parent $Path)
    $result.Writable = @('Write', 'ChangeAcl', 'TakeOwnership') | Where-Object { $fileAccess.$_ -eq 'granted' } | Select-Object -First 1
    $result.ParentAdd = ($parentAccess.Create -eq 'granted')
    $hasDelete = $fileAccess.PSObject.Properties.Name -contains 'Delete'
    $result.Deletable = $hasDelete -and $fileAccess.Delete -eq 'granted'
    # Directory Write is FILE_ADD_FILE; Create also allows folders.
    $result.Replacement = $result.Deletable -and ($parentAccess.Write -eq 'granted')
    $result.Incomplete = ($hasDelete -and $fileAccess.Delete -eq 'unknown') -or
        [bool](@('Write', 'ChangeAcl', 'TakeOwnership') | Where-Object { $fileAccess.$_ -eq 'unknown' }) -or
        $parentAccess.Create -eq 'unknown'
    return $result
}

function Get-UnquotedPathCandidates {
    # CreateProcess splits an unquoted command line at each space and tries
    # every prefix before the full image, appending .exe when the prefix has
    # no extension: C:\Program Files\A B\x.exe tries C:\Program.exe and
    # C:\Program Files\A.exe first.
    param([string]$PathName, [string]$Image)

    $trimmed = "$PathName".Trim()
    if (-not $Image -or $trimmed.StartsWith('"') -or -not $trimmed.StartsWith($Image, [StringComparison]::OrdinalIgnoreCase)) { return @() }
    $candidates = @()
    for ($i = $Image.IndexOf(' '); $i -ge 0; $i = $Image.IndexOf(' ', $i + 1)) {
        $prefix = $Image.Substring(0, $i)
        if (-not [IO.Path]::GetExtension($prefix)) { $prefix += '.exe' }
        $candidates += $prefix
    }
    return $candidates
}

function Get-ServiceDll {
    # svchost runs the DLL named by ServiceDll in the service's Parameters key
    # or its root key. A per-user service instance (name_<hex>) is configured
    # by its template service. Key is the subkey holding (or hiding) the value.
    # When Windows hides that key from this identity, the DLL named by the
    # service's own DisplayName/Description resource (@<dll>,-<id>) stands in,
    # marked Inferred: a ServiceDll differing from it is not seen.
    param([Parameter(Mandatory)][string]$Name)

    $names = @($Name)
    if ($Name -match '^(.+)_[0-9a-f]+$') { $names += $Matches[1] }
    $hiddenKey = $null
    foreach ($serviceName in $names) {
        foreach ($sub in @("SYSTEM\CurrentControlSet\Services\$serviceName\Parameters", "SYSTEM\CurrentControlSet\Services\$serviceName")) {
            $value = Read-RegistryValue "Registry::HKEY_LOCAL_MACHINE\$sub" -Name 'ServiceDll'
            if ($value.Value) {
                $path = Expand-MachinePath ([string]$value.Value)
                if ($path -match '^[A-Za-z]:[\\/]') { return [pscustomobject]@{ Path = $path; Key = $sub; Inferred = $false; Unresolved = $null } }
                return [pscustomobject]@{ Path = $null; Key = $sub; Inferred = $false; Unresolved = 'ServiceDll is not an absolute path' }
            }
            if ($value.State -eq 'denied' -and -not $hiddenKey) { $hiddenKey = $sub }
        }
    }
    if (-not $hiddenKey) { return [pscustomobject]@{ Path = $null; Key = $null; Inferred = $false; Unresolved = 'no ServiceDll found' } }
    foreach ($serviceName in $names) {
        foreach ($valueName in 'DisplayName', 'Description') {
            $resource = [string](Read-RegistryValue "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$serviceName" -Name $valueName).Value
            if ($resource -match '^@(?<dll>[^,]+\.dll),-\d+$') {
                $path = Expand-MachinePath $Matches['dll']
                if ($path -match '^[A-Za-z]:[\\/]') { return [pscustomobject]@{ Path = $path; Key = $hiddenKey; Inferred = $true; Unresolved = $null } }
            }
        }
    }
    return [pscustomobject]@{ Path = $null; Key = $hiddenKey; Inferred = $false; Unresolved = 'ServiceDll key unreadable' }
}

function Invoke-IndirectCheck {
    $ownSid = $null
    try { $ownSid = [AgentSandboxAssessmentNative]::GetCurrentToken().UserSid } catch { }

    $probed = 0
    $unmet = @()
    $criticalHit = $false
    $incomplete = $false
    $unresolvedServices = @()
    $inferredServices = @()

    # Services
    try {
        foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            $pathName = $service.PathName
            $startName = $service.StartName
            if (-not $pathName -or -not $startName) {
                # CIM omits configuration this identity cannot query; the
                # service's registry key is often still readable.
                $serviceKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                if (-not $pathName) { $pathName = Expand-MachinePath ([string](Read-RegistryValue $serviceKey -Name 'ImagePath').Value) }
                if (-not $startName) { $startName = [string](Read-RegistryValue $serviceKey -Name 'ObjectName').Value }
            }
            $exe = Get-ServiceImagePath -PathName $pathName
            if (-not $exe) { $incomplete = $true; continue }
            $probed++
            # The consumer identity only grades severity; an unresolved one
            # does not make denied write access unknown.
            $consumerSid = Get-ExecutionIdentitySid $startName
            # Every file Windows may execute for the service: the prefixes an
            # unquoted path tries first, the image, and a svchost ServiceDll.
            # Only the image's directory is assessed for planted neighbors.
            $files = @(Get-UnquotedPathCandidates -PathName $pathName -Image $exe | ForEach-Object { @{ Path = $_; Label = 'unquoted-path candidate'; Neighbors = $false } })
            $files += @{ Path = $exe; Label = 'binary'; Neighbors = $true }
            $registryKeys = @("SYSTEM\CurrentControlSet\Services\$($service.Name)")
            if ((Split-Path -Leaf $exe) -ieq 'svchost.exe') {
                $serviceDll = Get-ServiceDll -Name $service.Name
                if ($serviceDll.Key -and $serviceDll.Key -notin $registryKeys) { $registryKeys += $serviceDll.Key }
                if ($serviceDll.Path) {
                    $files += @{ Path = $serviceDll.Path; Label = $(if ($serviceDll.Inferred) { 'ServiceDll (inferred)' } else { 'ServiceDll' }); Neighbors = $false }
                    if ($serviceDll.Inferred) { $inferredServices += $service.Name }
                }
                else { $incomplete = $true; $unresolvedServices += "$($service.Name) ($($serviceDll.Unresolved))" }
            }
            $fileChanges = @()
            $binaryWritable = $false
            $parentAdd = $false
            $deletable = $false
            foreach ($file in $files) {
                $exposure = Get-ExecutionFileExposure -Path $file.Path
                if ($exposure.Incomplete) { $incomplete = $true }
                if ($exposure.Writable) { $binaryWritable = $true; $fileChanges += "$($file.Label) ($($exposure.Writable)) [$($file.Path)]" }
                if ($exposure.Replacement) { $binaryWritable = $true; $fileChanges += "$($file.Label) replacement via delete and parent file-create rights [$($file.Path)]" }
                elseif ($exposure.Deletable) { $deletable = $true; $fileChanges += "$($file.Label) deletion [$($file.Path)]" }
                if ($file.Neighbors -and $exposure.ParentAdd) { $parentAdd = $true; $fileChanges += "$($file.Label) parent directory" }
            }
            $svcRights = @()
            foreach ($right in @(
                    @{ Name = 'change-config'; Mask = 0x2 },
                    @{ Name = 'change-DACL'; Mask = 0x40000 },
                    @{ Name = 'change-owner'; Mask = 0x80000 })) {
                $probe = [AgentSandboxAssessmentNative]::ProbeService($service.Name, [uint32]$right.Mask)
                if ($probe -eq 0) { $svcRights += $right.Name }
                elseif ($probe -ne 5) { $incomplete = $true }
            }
            $svcConfig = ($svcRights.Count -gt 0)
            $writableKeys = @()
            foreach ($registryKey in $registryKeys) {
                $regProbe = [AgentSandboxAssessmentNative]::ProbeRegistryKey(2, $registryKey, 0x2)
                if ($regProbe -eq 0) { $writableKeys += "HKLM\$registryKey" }
                elseif ($regProbe -notin 2, 3, 5) { $incomplete = $true }
            }
            $regSet = ($writableKeys.Count -gt 0)

            $configWritable = $binaryWritable -or $svcConfig -or $regSet
            if ($configWritable -or $parentAdd -or $deletable) {
                $unmet += $service.Name
                $severity = if ($configWritable -and $consumerSid -eq 'S-1-5-18' -and $ownSid -ne $consumerSid) { 'critical' } else { 'high' }
                if ($severity -eq 'critical') { $criticalHit = $true }
                $how = @(
                    $fileChanges
                    if ($svcConfig) { "service object ($($svcRights -join ', '))" }
                    if ($regSet) { "service registry key ($($writableKeys -join ', '))" }
                ) -join ', '
                Add-Finding -Check INDIRECT -Criterion 'A-SVC' -Target "service:$($service.Name) [$startName]" `
                    -Capability "agent-writable service target: $how" -Result granted -Method permission-analysis `
                    -Scope 'broker' -Impact 'Granted rights permit changes to a service execution file, configuration or parent directory; execution was not exercised.' -Severity $severity
            }
        }
    }
    catch {
        $incomplete = $true
        Add-AssessmentError -Check INDIRECT -Category 'service-enum' -Message "Service enumeration failed: $($_.Exception.Message)"
    }

    # Scheduled tasks
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            $principal = $null
            if ($task.Principal) { $principal = $task.Principal.UserId }
            $consumerSid = Get-ExecutionIdentitySid $principal
            foreach ($action in @($task.Actions)) {
                $targets = Get-TaskActionTargets $action -PrincipalSid $consumerSid
                if ($targets.Incomplete) { $incomplete = $true }
                foreach ($key in $targets.Keys) {
                    $keyProbe = [AgentSandboxAssessmentNative]::ProbeRegistryKey($key.Hive, $key.Sub, [uint32]$key.Access)
                    if ($keyProbe -eq 0) {
                        $unmet += "task:$($task.TaskName)"
                        $severity = if ($consumerSid -eq 'S-1-5-18' -and $ownSid -ne $consumerSid) { 'critical' } else { 'high' }
                        if ($severity -eq 'critical') { $criticalHit = $true }
                        Add-Finding -Check INDIRECT -Criterion 'A-SVC' -Target "task:$($task.TaskName) [$principal]" `
                            -Capability "agent-writable task COM registration [$($key.Display)]" -Result granted -Method access-request `
                            -Scope 'broker' -Impact 'Agent can redirect the COM handler a task loads; execution was not exercised.' -Severity $severity
                    }
                    elseif ($keyProbe -notin 2, 3, 5) { $incomplete = $true }
                }
                foreach ($argumentPath in $targets.ArgumentPaths) {
                    # A missing argument may be an output the program creates, so it
                    # is not treated as plantable; it stays unresolved.
                    if (-not (Test-Path -LiteralPath $argumentPath -ErrorAction SilentlyContinue) -and
                        (Get-PathAccess -Path $argumentPath).ErrorCategory -eq 'not-found') { $incomplete = $true; continue }
                    $probed++
                    $argumentAccess = Get-PathAccess -Path $argumentPath
                    $how = Test-AnyWrite -Access $argumentAccess
                    if ($how) {
                        $unmet += "task:$($task.TaskName)"
                        Add-Finding -Check INDIRECT -Criterion 'A-SVC' -Target "task:$($task.TaskName) [$principal]" `
                            -Capability "agent-writable task argument path ($how) [$argumentPath]" -Result granted -Method permission-analysis `
                            -Scope 'broker' -Impact 'A path passed to a task program is agent-writable; whether the program loads code from it is unverified.' -Severity high
                    }
                    elseif (Test-UnknownWrite $argumentAccess) { $incomplete = $true }
                }
                $executionResolved = -not $targets.Incomplete -and $targets.Paths.Count -gt 0 -and
                    (Test-Path -LiteralPath $targets.Paths[0] -ErrorAction SilentlyContinue)
                foreach ($exe in $targets.Paths) {
                    $probed++
                    $exposure = Get-ExecutionFileExposure -Path $exe
                    if ($exposure.Incomplete) { $incomplete = $true }
                    if ($exposure.Missing) {
                        if ($exposure.Writable) {
                            $unmet += "task:$($task.TaskName)"
                            Add-Finding -Check INDIRECT -Criterion 'A-SVC' -Target "task:$($task.TaskName) [$principal]" `
                                -Capability "agent-writable task target: missing execution file is creatable [$exe]" -Result granted -Method permission-analysis `
                                -Scope 'broker' -Impact 'Agent can plant a missing task executable or script; execution was not exercised.' -Severity high
                        }
                        continue
                    }
                    if ($exposure.Writable -or $exposure.ParentAdd -or $exposure.Deletable) {
                        $unmet += "task:$($task.TaskName)"
                        $severity = if (($exposure.Writable -or $exposure.Replacement) -and $executionResolved -and $consumerSid -eq 'S-1-5-18' -and $ownSid -ne $consumerSid) { 'critical' } else { 'high' }
                        if ($severity -eq 'critical') { $criticalHit = $true }
                        $how = if ($exposure.Writable) { "execution file ($($exposure.Writable))" } elseif ($exposure.Replacement) { 'execution file replacement' } elseif ($exposure.Deletable) { 'execution file deletion' } else { 'execution file parent directory' }
                        Add-Finding -Check INDIRECT -Criterion 'A-SVC' -Target "task:$($task.TaskName) [$principal]" `
                            -Capability "agent-writable task target: $how [$exe]" -Result granted -Method permission-analysis `
                            -Scope 'broker' -Impact 'Agent can alter a task executable, script or its parent directory; ambiguous arguments remain unverified.' -Severity $severity
                    }
                }
            }
        }
    }
    catch {
        $incomplete = $true
        Add-AssessmentError -Check INDIRECT -Category 'task-enum' -Message "Scheduled-task enumeration failed: $($_.Exception.Message)"
    }

    if ($probed -eq 0) {
        Set-CriterionOutcome -Id 'A-SVC' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason 'No service or task binaries were available to evaluate.'
    }
    elseif ($criticalHit) {
        Set-CriterionOutcome -Id 'A-SVC' -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason "$($unmet.Count) of $probed service/task targets are agent-writable, including an execution file or config for SYSTEM." `
            -Critical -CriticalReason 'Agent-writable execution file or config with a resolved SYSTEM consumer identity.'
    }
    elseif ($unmet.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-SVC' -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason "$($unmet.Count) of $probed service/task targets expose writable execution files, configuration or parent directories; privileged execution is unverified."
    }
    elseif ($incomplete) {
        Set-CriterionOutcome -Id 'A-SVC' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason ('Some service/task targets or access permissions could not be evaluated.' +
                $(if ($unresolvedServices.Count -gt 0) { " Unresolved service DLLs: $($unresolvedServices -join ', ')." } else { '' }))
    }
    else {
        Set-CriterionOutcome -Id 'A-SVC' -Outcome 'met' -Method 'permission-analysis' `
            -Reason ("No service or task binary, config or parent directory is agent-writable ($probed probed)." +
                $(if ($inferredServices.Count -gt 0) { " ServiceDll hidden from this identity and inferred from the service's name resource: $($inferredServices -join ', ')." } else { '' }))
    }
}

# --- REMOTE -------------------------------------------------------------------

function Get-DomainIdentity {
    $info = [ordered]@{
        partOfDomain = $false; domain = $null; workgroup = $null; azureAdJoined = $false
        logonServer = $env:LOGONSERVER; userDomain = $env:USERDOMAIN
        computerName = $env:COMPUTERNAME; agentAccountScope = 'local'; unresolved = @()
    }
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info.partOfDomain = [bool]$computerSystem.PartOfDomain
        $info.domain = $computerSystem.Domain
        $info.workgroup = $computerSystem.Workgroup
    }
    catch { $info.unresolved += 'AD membership' }
    # Azure AD / Entra join leaves a GUID subkey under CloudDomainJoin\JoinInfo;
    # a missing key means not joined, any other failure is unresolved.
    try {
        $joinInfo = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
        $info.azureAdJoined = @(Get-ChildItem -LiteralPath $joinInfo -ErrorAction Stop).Count -gt 0
    }
    catch [Management.Automation.ItemNotFoundException] { }
    catch { $info.unresolved += 'Entra join' }
    if ($info.userDomain -and $info.computerName -and ($info.userDomain -ne $info.computerName)) {
        $info.agentAccountScope = 'domain'
    }
    return $info
}

function Get-GitConfigPaths {
    # Git's read order on Windows: ProgramData, system, XDG, global.
    return @(
        (Join-Path $env:ProgramData 'Git\config'),
        (Join-Path $env:ProgramFiles 'Git\etc\gitconfig'),
        (Join-Path $env:USERPROFILE '.config\git\config'),
        (Join-Path $env:USERPROFILE '.gitconfig'))
}

function Get-StoredCredentialTargets {
    # Credential Manager target names for the current identity; secrets are
    # never read. ERROR_NOT_FOUND (1168) means nothing is stored.
    $credentialError = 0
    $entries = [AgentSandboxAssessmentNative]::GetCredentialEntries([ref]$credentialError)
    if ($credentialError -notin 0, 1168) { throw "CredEnumerate failed: $credentialError" }
    return @($entries | ForEach-Object { $_.TargetName })
}

function Get-GitCredentialConfig {
    # Effective credential helpers and credentialStore, parsed from git config
    # files as data (git is never executed). An empty helper value clears the
    # helpers configured before it in the same section. Includes are not
    # followed; their presence is reported so the result stays unresolved.
    param([string[]]$Path)

    $helpers = [ordered]@{}
    $store = $null
    $includes = $false
    foreach ($file in $Path) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
        $section = ''
        foreach ($line in [IO.File]::ReadAllLines($file)) {
            $text = $line.Trim()
            if ($text -match '^[#;]') { continue }
            if ($text -match '^\[\s*([^\]]+?)\s*\]') {
                $section = $Matches[1]
                if ($section -match '^(?i)include(if)?\b') { $includes = $true }
                continue
            }
            if ($section -notmatch '^(?i)credential(\s|\.|$)') { continue }
            if ($text -match '^(?i)(helper|credentialStore)\s*(?:=\s*(.*))?$') {
                $value = "$($Matches[2])".Trim()
                if ($Matches[1] -ieq 'credentialStore') { $store = $value.Trim('"'); continue }
                $key = $section.ToLowerInvariant()
                if (-not $helpers.Contains($key)) { $helpers[$key] = [Collections.Generic.List[string]]::new() }
                if ($value -eq '' -or $value -eq '""') { $helpers[$key].Clear() } else { $helpers[$key].Add($value) }
            }
        }
    }
    return [pscustomobject]@{
        Helpers = @($helpers.Values | ForEach-Object { $_ } | Where-Object { $_ })
        CredentialStore = $store
        Includes = $includes
    }
}

function Invoke-RemoteCheck {
    # A-REMOTE-DELEGATED: presence only; credentials are never read or used.
    # A credential helper is usable only if it has something stored: a
    # helper with nothing stored can only obtain credentials interactively.
    $signals = @()
    $unresolved = @()
    $git = Get-GitCredentialConfig -Path (Get-GitConfigPaths)
    if ($git.Includes) { $unresolved += 'git config include not followed' }
    $script:Inventory['gitCredentialHelpers'] = @($git.Helpers | ForEach-Object { ($_ -split '\s+')[0] })
    foreach ($helper in $git.Helpers) {
        $name = ($helper -split '\s+')[0]
        if ($name -in 'manager', 'manager-core', 'wincred') {
            if ($name -ne 'wincred' -and $git.CredentialStore -and $git.CredentialStore -ne 'wincred') {
                $unresolved += "git-credential-helper:$name (credentialStore $($git.CredentialStore))"
                continue
            }
            try {
                $stored = @(Get-StoredCredentialTargets | Where-Object { $_ -like 'git:*' })
                if ($stored.Count -gt 0) { $signals += "git-credential-helper:$name ($($stored.Count) stored)" }
            }
            catch { $unresolved += "git-credential-helper:$name (Credential Manager not readable)" }
        }
        elseif ($name -eq 'store') {
            $storeFiles = if ($helper -match '--file[=\s]+(?:"([^"]+)"|(\S+))') { @("$($Matches[1])$($Matches[2])" -replace '^~', $env:USERPROFILE) }
            else { @((Join-Path $env:USERPROFILE '.git-credentials'), (Join-Path $env:USERPROFILE '.config\git\credentials')) }
            if (@($storeFiles | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0) { $signals += 'git-credential-helper:store' }
        }
        else { $unresolved += "git-credential-helper:$name" }
    }
    $credentialFiles = @(
        (Join-Path $env:USERPROFILE '.git-credentials'),
        (Join-Path $env:APPDATA 'GitHub CLI\hosts.yml'),
        (Join-Path $env:USERPROFILE '.aws\credentials'),
        (Join-Path $env:USERPROFILE '.kube\config'),
        (Join-Path $env:USERPROFILE '.docker\config.json'))
    foreach ($credentialFile in $credentialFiles) {
        if (Test-Path -LiteralPath $credentialFile) { $signals += (Format-SafePath $credentialFile) }
    }
    foreach ($credentialDir in @((Join-Path $env:USERPROFILE '.azure'))) {
        if (Test-Path -LiteralPath $credentialDir -PathType Container) { $signals += (Format-SafePath $credentialDir) }
    }

    # Workspace git remotes -> inventory, userinfo stripped.
    $remotes = @()
    $wsGitConfig = Join-Path $script:WorkspacePath '.git\config'
    if (Test-Path -LiteralPath $wsGitConfig) {
        foreach ($line in @(Select-String -LiteralPath $wsGitConfig -Pattern '^\s*url\s*=\s*(.+)$' -ErrorAction SilentlyContinue)) {
            $remotes += (Protect-Text $line.Matches[0].Groups[1].Value.Trim())
        }
    }
    $script:Inventory['gitRemotes'] = @($remotes | Select-Object -Unique)

    if ($signals.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-REMOTE-DELEGATED' -Outcome 'unmet' -Method 'inventory' `
            -Reason "$($signals.Count) remote credential source(s) present for the agent identity; effective scopes unknown."
        Add-Finding -Check REMOTE -Criterion 'A-REMOTE-DELEGATED' -Target ($signals -join '; ') `
            -Capability 'usable remote credential source' -Result observed -Method inventory -Scope 'remote' `
            -Impact 'Agent may act against remote services; granted scope unknown.' -Severity high
    }
    elseif ($unresolved.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-REMOTE-DELEGATED' -Outcome 'unknown' -Method 'inventory' `
            -Reason "Git credential configuration could not be fully assessed: $($unresolved -join '; ')."
    }
    else {
        $helperNote = if ($git.Helpers.Count -gt 0) { ' Configured git credential helpers have nothing stored.' } else { '' }
        Set-CriterionOutcome -Id 'A-REMOTE-DELEGATED' -Outcome 'met' -Method 'inventory' `
            -Reason "No stored git credential or known tool login material was found for the agent identity.$helperNote"
    }

    # A-TOOL-SCOPE: declared MCP/tool servers. Local declarations only. Parsed
    # as a hashtable (PowerShell 7) so a .claude.json with keys differing only
    # by case (real-world project paths) still parses.
    $mcpCount = 0
    $parseFailed = $false
    $claudeJson = Join-Path $env:USERPROFILE '.claude.json'
    if (Test-Path -LiteralPath $claudeJson -ErrorAction SilentlyContinue) {
        try {
            $config = Get-Content -LiteralPath $claudeJson -Raw | ConvertFrom-Json -AsHashtable
            if ($config.ContainsKey('mcpServers') -and $config['mcpServers'] -is [System.Collections.IDictionary]) {
                $mcpCount += $config['mcpServers'].Keys.Count
            }
            if ($config.ContainsKey('projects') -and $config['projects'] -is [System.Collections.IDictionary]) {
                foreach ($project in $config['projects'].Values) {
                    if ($project -is [System.Collections.IDictionary] -and $project.ContainsKey('mcpServers') -and
                        $project['mcpServers'] -is [System.Collections.IDictionary]) {
                        $mcpCount += $project['mcpServers'].Keys.Count
                    }
                }
            }
        }
        catch {
            $parseFailed = $true
            Add-AssessmentError -Check REMOTE -Category 'parse' -Message "Could not parse .claude.json: $($_.Exception.Message)"
        }
    }
    $wsMcp = Join-Path $script:WorkspacePath '.mcp.json'
    if (Test-Path -LiteralPath $wsMcp -ErrorAction SilentlyContinue) {
        try {
            $config = Get-Content -LiteralPath $wsMcp -Raw | ConvertFrom-Json -AsHashtable
            if ($config.ContainsKey('mcpServers') -and $config['mcpServers'] -is [System.Collections.IDictionary]) {
                $mcpCount += $config['mcpServers'].Keys.Count
            }
        }
        catch {
            $parseFailed = $true
            Add-AssessmentError -Check REMOTE -Category 'parse' -Message "Could not parse .mcp.json: $($_.Exception.Message)"
        }
    }
    $script:Inventory['toolScope'] = 'partial (local declarations only)'
    $script:Inventory['mcpServerCount'] = $mcpCount
    if ($mcpCount -gt 0) {
        Set-CriterionOutcome -Id 'A-TOOL-SCOPE' -Outcome 'unknown' -Method 'inventory' `
            -Reason "$mcpCount MCP/tool server(s) declared locally; their authority is not assessed by this OS-process scope."
    }
    elseif ($parseFailed) {
        Set-CriterionOutcome -Id 'A-TOOL-SCOPE' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'Local MCP/tool declarations could not be parsed; tool scope is undetermined.'
    }
    else {
        # Absence here is not evidence: plugins, account-attached connectors
        # and other agents' configurations declare tools this check cannot see.
        Set-CriterionOutcome -Id 'A-TOOL-SCOPE' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'No MCP/tool servers are declared in .claude.json or the workspace .mcp.json; plugins, account connectors and other agents'' tool configurations are not assessed.'
    }

    # A-REMOTE-DOMAIN: domain / Entra membership widens reachable identities.
    $domain = Get-DomainIdentity
    $script:Inventory['domainIdentity'] = $domain
    if ($domain.partOfDomain -or $domain.azureAdJoined) {
        $kinds = @(
            if ($domain.partOfDomain) { "AD domain-joined ($($domain.domain))" }
            if ($domain.azureAdJoined) { 'Entra/Azure AD-joined' }
        ) -join ', '
        $scopeNote = if ($domain.agentAccountScope -eq 'domain') {
            ' The agent runs as a domain account, which widens reachable identities and resources.'
        }
        else { ' The agent runs as a local account, so domain reach is limited but not necessarily zero.' }
        Set-CriterionOutcome -Id 'A-REMOTE-DOMAIN' -Outcome 'unmet' -Method 'inventory' `
            -Reason "Device is $kinds.$scopeNote Effective domain authority is unknown without further evidence."
        Add-Finding -Check REMOTE -Criterion 'A-REMOTE-DOMAIN' -Target $kinds -Capability 'domain-joined device' `
            -Result observed -Method inventory -Scope 'remote' `
            -Impact 'Domain membership can expand reachable identities and resources; effective scope unknown.' -Severity high
    }
    elseif ($domain.unresolved.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-REMOTE-DOMAIN' -Outcome 'unknown' -Method 'inventory' `
            -Reason "Device membership could not be determined: $($domain.unresolved -join ', ')."
    }
    else {
        Set-CriterionOutcome -Id 'A-REMOTE-DOMAIN' -Outcome 'met' -Method 'inventory' `
            -Reason "Standalone or workgroup device (workgroup $($domain.workgroup)); no domain-reachable authority."
    }
}

# --- PROCESSES ----------------------------------------------------------------

function Invoke-ProcessesCheck {
    $token = [AgentSandboxAssessmentNative]::GetCurrentToken()
    $ownSid = $token.UserSid
    $ownIntegrity = 0
    if ($token.IntegritySid -match '^S-1-16-(\d+)$') { $ownIntegrity = [int]$Matches[1] }
    $consoleSid = [AgentSandboxAssessmentNative]::GetConsoleSessionSid()
    $selfGrantPrivileges = @($token.Privileges | Where-Object {
            $_.Name -in @('SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeRestorePrivilege') } |
        ForEach-Object { $_.Name })
    # Rights are requested individually. A grant records that permission;
    # it does not prove successful code injection or usable stolen handles.
    $rights = @(
        @{ Name = 'PROCESS_VM_READ'; Mask = 0x10; Criterion = 'R-PROC-READ' }
        @{ Name = 'PROCESS_TERMINATE'; Mask = 0x1; Criterion = 'A-PROC-CONTROL' }
        @{ Name = 'PROCESS_SUSPEND_RESUME'; Mask = 0x800; Criterion = 'A-PROC-CONTROL' }
        @{ Name = 'PROCESS_VM_WRITE'; Mask = 0x20; Criterion = 'A-PROC-INJECT' }
        @{ Name = 'PROCESS_VM_OPERATION'; Mask = 0x8; Criterion = 'A-PROC-INJECT' }
        @{ Name = 'PROCESS_CREATE_THREAD'; Mask = 0x2; Criterion = 'A-PROC-INJECT' }
        @{ Name = 'PROCESS_DUP_HANDLE'; Mask = 0x40; Criterion = 'A-PROC-INJECT' }
        @{ Name = 'WRITE_DAC'; Mask = 0x40000; Criterion = 'A-PROC-INJECT' }
        @{ Name = 'WRITE_OWNER'; Mask = 0x80000; Criterion = 'A-PROC-INJECT' }
    )
    $hits = @{}
    $unresolved = @{}
    foreach ($id in @('R-PROC-READ', 'A-PROC-CONTROL', 'A-PROC-INJECT')) {
        $hits[$id] = 0
        $unresolved[$id] = 0
    }
    $enumErrors = @()
    $processes = @(Get-Process -ErrorAction SilentlyContinue -ErrorVariable enumErrors)
    $examined = 0
    $ownerUnknown = 0
    $readCritical = $false
    foreach ($proc in $processes) {
        if ($proc.Id -le 4 -or $proc.Id -eq $PID) { continue }
        $info = [AgentSandboxAssessmentNative]::GetProcessToken($proc.Id)
        $integrity = 0
        if ($info -and $info.IntegritySid -match '^S-1-16-(\d+)$') { $integrity = [int]$Matches[1] }
        # Same SID is insufficient: an elevated process of this account is
        # still a target. Only a known same-account, same/lower-integrity
        # process is outside this cross-boundary criterion.
        if ($info -and $ownSid -and $info.UserSid -eq $ownSid -and
            $integrity -gt 0 -and $ownIntegrity -gt 0 -and $integrity -le $ownIntegrity) { continue }
        if (-not $info -or -not $info.UserSid -or -not $integrity) { $ownerUnknown++ }
        $examined++
        $session = [AgentSandboxAssessmentNative]::GetSessionId($proc.Id)
        $owner = if ($info -and $info.UserSid) { $info.UserSid } else { 'owner-unknown' }
        $label = "$($proc.ProcessName) ($($proc.Id)) [session $session, $owner]"
        $sensitiveReadTarget = ($ownIntegrity -gt 0 -and $integrity -gt $ownIntegrity) -or
            ($consoleSid -and $info -and $info.UserSid -eq $consoleSid -and $consoleSid -ne $ownSid)
        foreach ($right in $rights) {
            $probe = [AgentSandboxAssessmentNative]::ProbeProcess($proc.Id, [uint32]$right.Mask)
            if ($probe -eq 0) {
                $hits[$right.Criterion]++
                $critical = $right.Criterion -eq 'R-PROC-READ' -and $sensitiveReadTarget
                if ($critical) { $readCritical = $true }
                Add-Finding -Check PROCESSES -Criterion $right.Criterion -Target $label `
                    -Capability "$($right.Name) on a protected or unattributed process" -Result granted -Method access-request `
                    -Scope 'cross-process' -Impact 'Requested process permission was granted; its operation and downstream consequences were not exercised.' `
                    -Severity $(if ($critical) { 'critical' } elseif ($right.Criterion -eq 'A-PROC-CONTROL') { 'medium' } else { 'high' })
            }
            elseif ($probe -ne 5) {
                $unresolved[$right.Criterion]++
                Add-Finding -Check PROCESSES -Criterion $right.Criterion -Target $label `
                    -Capability $right.Name -Result unknown -Method access-request -Scope cross-process `
                    -ErrorCategory (Get-ErrorCategory $probe) -Impact 'Process access could not be resolved.'
            }
        }
    }
    $script:Inventory['processes'] = [ordered]@{
        protectedProcessesProbed = $examined; ownerUnattributed = $ownerUnknown
        enumerationErrors = $enumErrors.Count; grantedRights = $hits; unresolvedRights = $unresolved
        rightsRequested = @($rights | ForEach-Object { $_.Name })
    }
    # Owner attribution only selects targets and grades severity. Unattributed
    # processes stay targets, so an explicit denial on each counts regardless
    # of owner; an isolated identity typically cannot attribute any of them.
    $ownerNote = if ($ownerUnknown -gt 0) { " ($ownerUnknown with unattributed owners)" } else { '' }
    $privilegeNote = if ($selfGrantPrivileges.Count -gt 0) { "; held security privileges: $($selfGrantPrivileges -join ', '). Privilege-enabled access was not tested" } else { '' }
    foreach ($id in @('R-PROC-READ', 'A-PROC-CONTROL', 'A-PROC-INJECT')) {
        if ($hits[$id] -gt 0) {
            Set-CriterionOutcome -Id $id -Outcome unmet -Method access-request `
                -Reason "$($hits[$id]) individually requested process right(s) granted across a protected or unattributed boundary; operations were not exercised." `
                -Critical:($id -eq 'R-PROC-READ' -and $readCritical) `
                -CriticalReason $(if ($id -eq 'R-PROC-READ' -and $readCritical) { 'Memory-read permission on a verified higher-integrity or distinct console-account process.' } else { $null })
        }
        elseif ($examined -eq 0 -or $enumErrors.Count -gt 0 -or $unresolved[$id] -gt 0 -or $selfGrantPrivileges.Count -gt 0) {
            Set-CriterionOutcome -Id $id -Outcome unknown -Method access-request `
                -Reason "Boundary incomplete: $examined targets$ownerNote, $($enumErrors.Count) enumeration errors, $($unresolved[$id]) unresolved rights$privilegeNote."
        }
        else {
            Set-CriterionOutcome -Id $id -Outcome met -Method access-request `
                -Reason "All requested rights for this criterion were denied on $examined protected processes$ownerNote; no token security-bypass privilege was found."
        }
    }
    Invoke-HeldHandleCheck -OwnSid $ownSid -OwnElevated ([bool]$token.IsElevated)
}

function ConvertFrom-HeldHandlePath {
    # Maps a held handle's object name to a probe target: a local file path
    # or an HKLM/HKU key. Anything else (network files, private hives) is
    # unresolved rather than probed.
    param([string]$Type, [string]$Path)

    if ($Type -eq 'File' -and $Path -match '^\\\\\?\\([A-Za-z]:\\.*)$') { return @{ Path = $Matches[1]; Display = (Format-SafePath $Matches[1]) } }
    if ($Type -eq 'Key' -and $Path -match '^\\REGISTRY\\(MACHINE|USER)(?:\\(.*))?$') {
        $hive = if ($Matches[1] -eq 'MACHINE') { 2 } else { 3 }
        $sub = [string]$Matches[2]
        return @{ Hive = $hive; Sub = $sub; Display = "$(if ($hive -eq 2) { 'HKLM' } else { 'HKU' })\$sub" }
    }
    return $null
}

function Invoke-HeldHandleCheck {
    # A-PROC-HANDLES: compare each handle this process holds with what the
    # agent token is granted when it asks itself. A handle granting more was
    # inherited or opened under another identity; either way it is authority
    # beyond the token. Covers this checker process, which inherits what the
    # agent passes down; non-inheritable handles of the agent itself are not
    # visible. No foreign handle is duplicated or used.
    param([string]$OwnSid, [bool]$OwnElevated)

    $status = 0
    $handles = @([AgentSandboxAssessmentNative]::GetHeldHandles([ref]$status))
    if ($status -ne 0) {
        Set-CriterionOutcome -Id 'A-PROC-HANDLES' -Outcome 'unknown' -Method 'access-request' `
            -Reason ('The handle table of this process could not be read (ntstatus 0x{0:X8}).' -f $status)
        return
    }
    $rights = @{
        Process = @(0x1, 0x2, 0x8, 0x10, 0x20, 0x40, 0x200, 0x800, 0x40000, 0x80000)
        File    = @(0x1, 0x2, 0x4, 0x10000, 0x40000, 0x80000)
        Key     = @(0x1, 0x2, 0x4, 0x8, 0x20, 0x10000, 0x40000, 0x80000)
    }
    $threadControl = 0x1 -bor 0x2 -bor 0x10 -bor 0x20 -bor 0x100 -bor 0x200 -bor 0x40000 -bor 0x80000
    $excess = @()
    $unresolved = @()
    $compared = 0
    foreach ($handle in $handles) {
        # 'continue' inside switch leaves only the switch; a $null $codes
        # skips the comparison below.
        $codes = $null
        $held = @($rights[$handle.Type] | Where-Object { ($handle.Access -band $_) -eq $_ })
        switch ($handle.Type) {
            'Token' {
                $compared++
                if (-not $handle.TokenSid) {
                    if ($handle.Access -band 0x7) { $unresolved += 'Token (not queryable)' }
                }
                elseif ($handle.TokenSid -ne $OwnSid) { $excess += @{ Target = "token of $($handle.TokenSid)"; Rights = 'impersonation or assignment' } }
                elseif ($handle.TokenElevated -and -not $OwnElevated) { $excess += @{ Target = 'elevated token of this account'; Rights = 'impersonation or assignment' } }
            }
            'Thread' {
                if ($handle.ProcessId -eq $PID) { continue }
                $compared++
                if ($handle.Access -band $threadControl) { $unresolved += "Thread of process $($handle.ProcessId)" }
            }
            'Process' {
                if ($handle.ProcessId -eq $PID -or $held.Count -eq 0) { continue }
                $compared++
                if ($handle.ProcessId -le 0) { $unresolved += 'Process (id not readable)'; continue }
                $display = "process $($handle.ProcessId)"
                $codes = @{}
                foreach ($right in $held) { $codes[$right] = [AgentSandboxAssessmentNative]::ProbeProcess($handle.ProcessId, [uint32]$right) }
            }
            default {
                if ($held.Count -eq 0) { continue }
                $compared++
                $target = ConvertFrom-HeldHandlePath -Type $handle.Type -Path $handle.Path
                if (-not $target) { $unresolved += "$($handle.Type) (unmapped name)"; continue }
                $display = "$($handle.Type) $($target.Display)"
                $codes = @{}
                if ($handle.Type -eq 'File') {
                    # Path analysis, not a second open: the holder's share mode
                    # would turn an open into a sharing violation.
                    $access = Get-PathAccess -Path $target.Path
                    $field = @{ 0x1 = 'Read'; 0x2 = 'Write'; 0x4 = 'Write'; 0x10000 = 'Delete'; 0x40000 = 'ChangeAcl'; 0x80000 = 'TakeOwnership' }
                    foreach ($right in $held) { $codes[$right] = @{ granted = 0; denied = 5 }[[string]$access.($field[$right])] }
                }
                else {
                    foreach ($right in $held) { $codes[$right] = [AgentSandboxAssessmentNative]::ProbeRegistryKey($target.Hive, $target.Sub, [uint32]$right) }
                }
            }
        }
        if (-not $codes) { continue }
        # A right the token is explicitly denied is excess; any other failure
        # to obtain it leaves the comparison unresolved.
        $denied = @($held | Where-Object { $codes[$_] -eq 5 })
        if ($denied.Count -gt 0) { $excess += @{ Target = $display; Rights = (($denied | ForEach-Object { '0x{0:X}' -f $_ }) -join ', ') } }
        elseif (@($held | Where-Object { $codes[$_] -ne 0 }).Count -gt 0) { $unresolved += $display }
    }
    $script:Inventory['heldHandles'] = [ordered]@{
        compared = $compared; inheritable = @($handles | Where-Object { $_.Inheritable }).Count
        excess = $excess.Count; unresolved = @($unresolved | Select-Object -First 10)
    }
    foreach ($item in $excess) {
        Add-Finding -Check PROCESSES -Criterion 'A-PROC-HANDLES' -Target $item.Target `
            -Capability "held handle grants rights the agent token is denied ($($item.Rights))" -Result granted -Method access-request `
            -Scope 'inherited-handle' -Impact 'A handle in the agent''s process tree grants access beyond its token; it was inherited or opened under another identity.' -Severity high
    }
    if ($excess.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-PROC-HANDLES' -Outcome 'unmet' -Method 'access-request' `
            -Reason "$($excess.Count) held handle(s) grant rights the agent token is denied."
    }
    elseif ($unresolved.Count -gt 0) {
        Set-CriterionOutcome -Id 'A-PROC-HANDLES' -Outcome 'unknown' -Method 'access-request' `
            -Reason "$($unresolved.Count) held handle(s) could not be compared with the token: $(@($unresolved | Select-Object -First 5) -join '; ')."
    }
    else {
        Set-CriterionOutcome -Id 'A-PROC-HANDLES' -Outcome 'met' -Method 'access-request' `
            -Reason "No held handle grants more than the agent token ($compared compared). Covers this checker process and what it inherited; the agent's non-inheritable handles are not visible."
    }
}

# --- SECRETS ------------------------------------------------------------------

function Invoke-SecretsCheck {
    # R-SECRETS-ENV: report only names, never values.
    $pattern = '(?i)(token|secret|passwd|password|api[_-]?key|apikey|credential|client[_-]?secret|\bpat\b|access[_-]?key|\bpwd\b)'
    $envHits = @()
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        if (($entry.Key -match $pattern) -and -not [string]::IsNullOrEmpty([string]$entry.Value)) {
            $envHits += [string]$entry.Key
        }
    }
    $envHits = @($envHits | Sort-Object -Unique)
    if ($envHits.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-SECRETS-ENV' -Outcome 'unmet' -Method 'inventory' `
            -Reason "$($envHits.Count) environment variable name(s) look secret-bearing: $($envHits -join ', ')."
        Add-Finding -Check SECRETS -Criterion 'R-SECRETS-ENV' -Target ($envHits -join ', ') `
            -Capability 'secret-bearing environment variable (name only)' -Result observed -Method inventory `
            -Scope 'secrets' -Impact 'A token or credential may be exposed to the agent via the environment.' -Severity high
    }
    else {
        Set-CriterionOutcome -Id 'R-SECRETS-ENV' -Outcome 'met' -Method 'inventory' `
            -Reason 'No secret-bearing environment variable names were found.'
    }

    # R-SECRETS-KNOWN: existence + readability only; no file contents are read.
    $expectedCredential = Join-Path $env:USERPROFILE '.claude\.credentials.json'
    $candidates = @('.git-credentials', '.netrc', '_netrc', '.npmrc', '.pypirc',
        '.aws\credentials', '.kube\config', '.docker\config.json') |
    ForEach-Object { Join-Path $env:USERPROFILE $_ }
    $candidates += Join-Path $env:APPDATA 'GitHub CLI\hosts.yml'
    $credentialDirectories = @((Join-Path $env:USERPROFILE '.azure'), (Join-Path $env:USERPROFILE '.config\gcloud'),
        (Join-Path $env:APPDATA 'gcloud')) | Where-Object { Test-Path -LiteralPath $_ }
    $credentialSamples = Get-ReadSamples -Directory @($credentialDirectories)
    $candidates += $credentialSamples.Paths
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (Test-Path -LiteralPath $sshDir) {
        $candidates += @(Get-ChildItem -LiteralPath $sshDir -File -Force -ErrorAction SilentlyContinue |
            Where-Object { @('.pub', '.cer', '.crt') -notcontains $_.Extension -and @('known_hosts', 'config') -notcontains $_.Name } |
            ForEach-Object { $_.FullName })
    }

    $present = 0
    $readable = @()
    $readUnknown = if ($credentialSamples.Incomplete) { 1 } else { 0 }
    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $present++
        $access = Get-PathAccess -Path $candidate
        if ($access.Read -eq 'granted' -and $access.IsDirectory) {
            Add-Finding -Check SECRETS -Criterion 'R-SECRETS-KNOWN' -Target (Format-SafePath $candidate) `
                -Capability 'directory listing at a credential location' -Result granted -Method permission-analysis `
                -Scope secrets -Impact 'Names are visible; credential file readability requires a separate file probe.' -Severity info
        }
        elseif ($access.Read -eq 'granted') {
            $readable += $candidate
            Add-Finding -Check SECRETS -Criterion 'R-SECRETS-KNOWN' -Target (Format-SafePath $candidate) `
                -Capability 'readable credential location' -Result granted -Method permission-analysis `
                -Scope 'secrets' -Impact 'A stored credential file is readable by the agent identity.' -Severity high
        }
        elseif ($access.Read -eq 'unknown') { $readUnknown++ }
    }
    $agentCredentialPresent = Test-Path -LiteralPath $expectedCredential
    if ($agentCredentialPresent) {
        Add-Finding -Check SECRETS -Criterion 'R-SECRETS-KNOWN' -Target (Format-SafePath $expectedCredential) `
            -Capability 'agent operating credential (expected)' -Result observed -Method inventory `
            -Scope 'secrets' -Impact 'Expected: the agent''s own credential; not counted against this criterion.' -Severity info
    }
    $script:Inventory['secrets'] = [ordered]@{
        envNameHits = $envHits.Count; credentialFilesPresent = $present
        credentialFilesReadable = $readable.Count; agentCredentialPresent = [bool]$agentCredentialPresent
        directorySamples = $credentialSamples
    }
    if ($readable.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-SECRETS-KNOWN' -Outcome 'unmet' -Method 'permission-analysis' `
            -Reason "$($readable.Count) of $present known credential location(s) are readable (agent's own credential excluded)."
    }
    elseif ($readUnknown -gt 0) {
        Set-CriterionOutcome -Id 'R-SECRETS-KNOWN' -Outcome 'unknown' -Method 'permission-analysis' `
            -Reason "Read access on $readUnknown known credential location(s) could not be resolved."
    }
    elseif ($present -eq 0) {
        Set-CriterionOutcome -Id 'R-SECRETS-KNOWN' -Outcome 'met' -Method 'permission-analysis' `
            -Reason 'No known third-party credential locations are present.'
    }
    else {
        Set-CriterionOutcome -Id 'R-SECRETS-KNOWN' -Outcome 'met' -Method 'permission-analysis' `
            -Reason "$present known credential location(s) present but none readable by the agent identity."
    }

    # R-SECRETS-CREDMAN: enumerate stored credentials by type and target name
    # only; the credential blobs are never read. Guarded so an unavailable
    # method (e.g. a stale Add-Type class cached in a reused session) degrades
    # to unknown instead of aborting the whole SECRETS check.
    $credError = 0
    $credentials = $null
    try { $credentials = [AgentSandboxAssessmentNative]::GetCredentialEntries([ref]$credError) }
    catch { $credentials = $null }
    if ($null -eq $credentials) {
        Set-CriterionOutcome -Id 'R-SECRETS-CREDMAN' -Outcome 'unknown' -Method 'inventory' `
            -Reason 'Credential Manager enumeration is unavailable in this session; if the script was edited mid-session, re-run it in a fresh shell.'
    }
    elseif ($credentials.Count -gt 0) {
        # Report provider prefix + type only; drop the user-identifying tail of
        # each target name (account ids, emails) so no PII is emitted.
        $typeNames = @{ 1 = 'generic'; 2 = 'domain-password'; 3 = 'domain-certificate'
            4 = 'domain-visible-password'; 5 = 'generic-certificate'; 6 = 'domain-extended'
        }
        $byType = @{}
        $providers = @()
        foreach ($credential in $credentials) {
            $key = if ($typeNames.ContainsKey([int]$credential.Type)) { $typeNames[[int]$credential.Type] } else { "type-$($credential.Type)" }
            $byType[$key] = 1 + [int]$byType[$key]
            $prefix = (([string]$credential.TargetName) -split '[:/|\\]', 2)[0]
            if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = 'unnamed' }
            $prefix = [regex]::Replace((Protect-Text $prefix), '\S+@\S+', '<redacted>')
            $providers += $prefix
        }
        $typeSummary = @($byType.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
        $providerList = @($providers | Select-Object -Unique)
        Set-CriterionOutcome -Id 'R-SECRETS-CREDMAN' -Outcome 'unmet' -Method 'inventory' `
            -Reason "$($credentials.Count) Credential Manager entr$(if ($credentials.Count -eq 1) { 'y is' } else { 'ies are' }) available to the agent identity ($typeSummary)."
        Add-Finding -Check SECRETS -Criterion 'R-SECRETS-CREDMAN' -Target (($providerList | Select-Object -First 15) -join '; ') `
            -Capability 'Credential Manager entries (providers, metadata only)' -Result observed -Method inventory -Scope 'secrets' `
            -Impact 'Stored credentials usable by the agent via the credential APIs; secret values not read.' -Severity medium
    }
    elseif ($credError -eq 0 -or $credError -eq 1168) {
        # 1168 = ERROR_NOT_FOUND: the store holds no credentials.
        Set-CriterionOutcome -Id 'R-SECRETS-CREDMAN' -Outcome 'met' -Method 'inventory' `
            -Reason 'No Credential Manager entries are present for the agent identity.'
    }
    else {
        Set-CriterionOutcome -Id 'R-SECRETS-CREDMAN' -Outcome 'unknown' -Method 'inventory' `
            -Reason "Credential Manager enumeration failed (win32-$credError)."
    }

    # R-SECRETS-SCAN is resolved by Invoke-SecretContentScan below.
    Invoke-SecretContentScan
}

function Get-ScanPathExclusion {
    # Inspect metadata only. Exclude links and detectable cloud/offline content,
    # including ancestors, before enumerating a directory or opening a file.
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -notmatch '^[A-Za-z]:[\\/]') { return 'network-path' }
    try {
        $cursor = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($cursor)
        if ([IO.DriveInfo]::new($root).DriveType -eq [IO.DriveType]::Network) { return 'network-path' }
        $ancestors = [Collections.Generic.Stack[string]]::new()
        while ($cursor) {
            $ancestors.Push($cursor)
            $cursor = [IO.Path]::GetDirectoryName($cursor)
        }
        while ($ancestors.Count -gt 0) {
            $cursor = $ancestors.Pop()
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            $attributes = [int]$item.Attributes
            if ($attributes -band (0x1000 -bor 0x40000 -bor 0x400000)) { return 'offline-placeholder' }
            if ($attributes -band 0x400) { return 'reparse-point' }
        }
    }
    catch {
        if ($_.Exception -is [UnauthorizedAccessException]) { return 'metadata-denied' }
        if ($_.Exception -is [Management.Automation.ItemNotFoundException]) {
            # PowerShell also reports hidden items as missing; confirm natively.
            switch ([AgentSandboxAssessmentNative]::ProbeFile($Path, 0x1)) {
                { $_ -in 2, 3 } { return 'not-found' }
                5 { return 'metadata-denied' }
            }
        }
        return 'metadata-error'
    }
    return $null
}

function ConvertFrom-ScanBytes {
    # Decode by byte-order mark; Windows PowerShell 5.1 redirection writes
    # UTF-16LE. Without a mark, UTF-8 (which also covers ASCII).
    param([byte[]]$Buffer, [int]$Count)

    if ($Count -ge 2 -and $Buffer[0] -eq 0xFF -and $Buffer[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Buffer, 2, $Count - 2) }
    if ($Count -ge 2 -and $Buffer[0] -eq 0xFE -and $Buffer[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($Buffer, 2, $Count - 2) }
    return [Text.Encoding]::UTF8.GetString($Buffer, 0, $Count)
}

function Invoke-SecretContentScan {
    # Bounded content scan for likely secrets in the workspace and a short list
    # of plain-text profile config files. Reports only the sanitized location,
    # the suspected category and a match count -- never the matched value, a
    # snippet or surrounding text. Honors file/byte/time limits and records them.
    $maxFiles = 5000
    $maxFileBytes = 1MB
    $maxTotalBytes = 32MB
    $budgetSeconds = 30
    $maxDiscoveryEntries = 50000

    $patterns = @(
        @{ Category = 'private-key'; Confidence = 'high'; Regex = '-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----' }
        @{ Category = 'aws-access-key-id'; Confidence = 'high'; Regex = '\bAKIA[0-9A-Z]{16}\b' }
        @{ Category = 'github-token'; Confidence = 'high'; Regex = '\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b' }
        @{ Category = 'google-api-key'; Confidence = 'high'; Regex = '\bAIza[0-9A-Za-z_\-]{35}\b' }
        @{ Category = 'slack-token'; Confidence = 'high'; Regex = '\bxox[baprs]-[A-Za-z0-9-]{10,}' }
        @{ Category = 'jwt'; Confidence = 'medium'; Regex = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' }
        # Generic assignments are evidence only when the value is not an
        # obvious placeholder; known token formats above are never excused.
        @{ Category = 'assigned-secret'; Confidence = 'medium'; Regex = '(?i)(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?key|connection[_ ]?string)["'']?\s*[:=]\s*["'']?(?<value>[A-Za-z0-9._/+\-]{16,})'
            Placeholder = '(?i)example|sample|synthetic|dummy|placeholder|changeme|redacted|fake|your[_-]?(?:api|key|token|secret|password)|x{6,}'
        }
    )
    $placeholderMatches = 0
    $textExtensions = @('.env', '.json', '.yaml', '.yml', '.xml', '.config', '.ini', '.txt', '.ps1', '.psm1',
        '.psd1', '.cmd', '.bat', '.sh', '.cfg', '.conf', '.properties', '.toml', '.pem', '.key', '.md', '.tf', '.tfvars')
    $configNames = @('.npmrc', '.netrc', '_netrc', '.pypirc', '.gitconfig', '.env')
    $skipDirectories = @('.git', 'node_modules', 'obj', 'bin', '.vs', 'dist', 'build', 'packages', '.venv', 'venv', '__pycache__')

    # Walk one directory at a time so unsafe directories are never descended.
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $candidates = New-Object System.Collections.Generic.List[string]
    $exclusions = New-Object System.Collections.Generic.List[object]
    $enumerationErrors = 0
    $entriesVisited = 0
    $limitHit = $null
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($script:WorkspacePath)
    while ($pending.Count -gt 0 -and -not $limitHit) {
        if ($stopwatch.Elapsed.TotalSeconds -ge $budgetSeconds) { $limitHit = 'time-budget'; break }
        $directory = $pending.Pop()
        $exclusion = Get-ScanPathExclusion $directory
        if ($exclusion) {
            $exclusions.Add([ordered]@{ path = (Format-SafePath $directory); reason = $exclusion })
            continue
        }
        $directoryErrors = @()
        $items = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue -ErrorVariable directoryErrors |
            Select-Object -First ($maxDiscoveryEntries - $entriesVisited + 1))
        $enumerationErrors += $directoryErrors.Count
        foreach ($item in $items) {
            if ($entriesVisited -ge $maxDiscoveryEntries) { $limitHit = 'max-discovery-entries'; break }
            $entriesVisited++
            if ($stopwatch.Elapsed.TotalSeconds -ge $budgetSeconds) { $limitHit = 'time-budget'; break }
            if ($item.PSIsContainer -and $skipDirectories -contains $item.Name) { continue }
            $isCandidate = ($textExtensions -contains $item.Extension) -or ($configNames -contains $item.Name)
            if (-not $item.PSIsContainer -and -not $isCandidate) { continue }
            $exclusion = Get-ScanPathExclusion $item.FullName
            if ($exclusion) {
                $exclusions.Add([ordered]@{ path = (Format-SafePath $item.FullName); reason = $exclusion })
                continue
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            else {
                if ($candidates.Count -ge $maxFiles) { $limitHit = 'max-files'; break }
                $candidates.Add($item.FullName) | Out-Null
            }
        }
    }
    foreach ($name in $configNames) {
        $profileFile = Join-Path $env:USERPROFILE $name
        if ((Test-Path -LiteralPath $profileFile -ErrorAction SilentlyContinue) -and ($candidates -notcontains $profileFile)) {
            $exclusion = Get-ScanPathExclusion $profileFile
            if ($exclusion) {
                $exclusions.Add([ordered]@{ path = (Format-SafePath $profileFile); reason = $exclusion })
                continue
            }
            if ($candidates.Count -ge $maxFiles) { $limitHit = 'max-files'; break }
            $candidates.Add($profileFile) | Out-Null
        }
    }

    $totalBytes = 0L
    $scanned = 0
    $readErrors = 0
    $partialFiles = 0
    $hitsByCategory = @{}
    $hitFiles = @()

    foreach ($path in $candidates) {
        if ($stopwatch.Elapsed.TotalSeconds -ge $budgetSeconds) { $limitHit = 'time-budget'; break }
        if ($totalBytes -ge $maxTotalBytes) { $limitHit = 'max-total-bytes'; break }
        $exclusion = Get-ScanPathExclusion $path
        if ($exclusion) {
            $exclusions.Add([ordered]@{ path = (Format-SafePath $path); reason = $exclusion })
            continue
        }
        $text = $null
        try {
            $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $toRead = [int][Math]::Min([long]$maxFileBytes, [Math]::Min($stream.Length, $maxTotalBytes - $totalBytes))
                $read = 0
                if ($toRead -gt 0) {
                    $buffer = New-Object byte[] $toRead
                    while ($read -lt $toRead) {
                        $count = $stream.Read($buffer, $read, $toRead - $read)
                        if ($count -eq 0) { break }
                        $read += $count
                    }
                    $totalBytes += $read
                    $text = ConvertFrom-ScanBytes -Buffer $buffer -Count $read
                }
                if ($read -lt $stream.Length) { $partialFiles++ }
            }
            finally { $stream.Dispose() }
        }
        catch {
            $readErrors++
            $exclusions.Add([ordered]@{ path = (Format-SafePath $path); reason = 'read-error' })
            continue
        }
        if ([string]::IsNullOrEmpty($text)) { $scanned++; continue }
        $scanned++
        $fileCategories = @()
        foreach ($pattern in $patterns) {
            if (-not $pattern.ContainsKey('Placeholder')) {
                if ([regex]::IsMatch($text, $pattern.Regex)) { $fileCategories += $pattern.Category }
                continue
            }
            $matched = @([regex]::Matches($text, $pattern.Regex))
            $real = @($matched | Where-Object { $_.Groups['value'].Value -notmatch $pattern.Placeholder })
            $placeholderMatches += $matched.Count - $real.Count
            if ($real.Count -gt 0) { $fileCategories += $pattern.Category }
        }
        if ($fileCategories.Count -gt 0) {
            foreach ($category in $fileCategories) { $hitsByCategory[$category] = 1 + ([int]$hitsByCategory[$category]) }
            $hitFiles += $path
            Add-Finding -Check SECRETS -Criterion 'R-SECRETS-SCAN' -Target (Format-SafePath $path) `
                -Capability "suspected secret ($($fileCategories -join ', '))" -Result observed -Method 'observed-operation' `
                -Scope 'secrets' -Impact 'A file readable by the agent contains a token-like string (value not shown).' -Severity high
        }
    }
    $stopwatch.Stop()

    $script:Inventory['secretScan'] = [ordered]@{
        candidateFiles = $candidates.Count; filesScanned = $scanned
        discoveryEntries = $entriesVisited
        bytesScanned = $totalBytes; limitReached = $limitHit
        readErrors = $readErrors; enumerationErrors = $enumerationErrors; partialFiles = $partialFiles
        placeholderMatches = $placeholderMatches
        exclusions = @($exclusions.ToArray())
        limits = [ordered]@{ maxFiles = $maxFiles; maxFileBytes = $maxFileBytes; maxTotalBytes = $maxTotalBytes; budgetSeconds = $budgetSeconds; maxDiscoveryEntries = $maxDiscoveryEntries }
        excludedDirectories = $skipDirectories
        categories = @($hitsByCategory.Keys | Sort-Object)
    }

    if ($hitFiles.Count -gt 0) {
        Set-CriterionOutcome -Id 'R-SECRETS-SCAN' -Outcome 'unmet' -Method 'observed-operation' `
            -Reason "$($hitFiles.Count) file(s) contain suspected secrets ($(@($hitsByCategory.Keys | Sort-Object) -join ', ')); values not shown."
    }
    elseif ($limitHit -or $partialFiles -gt 0 -or $exclusions.Count -gt 0 -or $enumerationErrors -gt 0) {
        Set-CriterionOutcome -Id 'R-SECRETS-SCAN' -Outcome 'unknown' -Method 'observed-operation' `
            -Reason "Scan incomplete: $scanned files scanned, $partialFiles partial, $readErrors read errors, $enumerationErrors enumeration errors, $($exclusions.Count) exclusions; limit=$limitHit. No secret found in the scanned subset."
    }
    else {
        Set-CriterionOutcome -Id 'R-SECRETS-SCAN' -Outcome 'met' -Method 'observed-operation' `
            -Reason ("Scanned $scanned candidate file(s); no suspected secrets detected." +
                $(if ($placeholderMatches -gt 0) { " $placeholderMatches generic assignment(s) with placeholder values were ignored." } else { '' }))
    }
}

# --- Scoring and verdict ------------------------------------------------------

function Measure-Assessment {
    $dimensionResults = @()
    $sumLower = 0.0
    $sumUpper = 0.0
    $sumCoverage = 0.0
    foreach ($dim in $Dimensions) {
        $items = @($script:Criteria.Values | Where-Object { $_.Dimension -eq $dim })
        $applicable = @($items | Where-Object { $_.Outcome -ne 'na' })
        $met = @($applicable | Where-Object { $_.Outcome -eq 'met' }).Count
        $unmet = @($applicable | Where-Object { $_.Outcome -eq 'unmet' }).Count
        $unknown = @($applicable | Where-Object { $_.Outcome -eq 'unknown' }).Count
        if ($applicable.Count -eq 0) {
            $lowerFrac = 0.0
            $upperFrac = 1.0
        }
        else {
            $lowerFrac = $met / $applicable.Count
            $upperFrac = ($met + $unknown) / $applicable.Count
        }
        $sumLower += $lowerFrac * 25
        $sumUpper += $upperFrac * 25
        $dimensionCoverage = if ($applicable.Count -eq 0) { 0.0 } else { ($met + $unmet) / $applicable.Count }
        $sumCoverage += $dimensionCoverage
        $dimensionResults += [pscustomobject]@{
            Dimension   = $dim
            Applicable  = $applicable.Count
            Met         = $met
            Unmet       = $unmet
            Unknown     = $unknown
            Coverage    = [math]::Round($dimensionCoverage, 3)
            LowerPoints = [int][math]::Floor($lowerFrac * 25)
            UpperPoints = [int][math]::Ceiling($upperFrac * 25)
        }
    }
    $scoreLower = [int][math]::Max(0, [math]::Min(100, [math]::Floor($sumLower)))
    $scoreUpper = [int][math]::Max(0, [math]::Min(100, [math]::Ceiling($sumUpper)))
    $criticalCriteria = @($script:Criteria.Values | Where-Object { $_.Critical })
    $criticalApplied = $criticalCriteria.Count -gt 0
    if ($criticalApplied) {
        $scoreLower = [math]::Min($scoreLower, 39)
        $scoreUpper = [math]::Min($scoreUpper, 39)
    }
    $coverage = [math]::Round(($sumCoverage / $Dimensions.Count), 3)
    $essentialUnknowns = @($script:Criteria.Values | Where-Object { $_.Essential -and $_.Outcome -eq 'unknown' })

    if ($criticalApplied) { $verdict = 'Critical' }
    elseif ($essentialUnknowns.Count -gt 0 -or $coverage -lt $MinimumCoverageForVerdict) { $verdict = 'Incomplete' }
    elseif ($scoreLower -lt 40) { $verdict = 'Weak' }
    elseif ($scoreLower -lt 70) { $verdict = 'Partial' }
    else { $verdict = 'Strong' } # Bounded within tested scope

    return [pscustomobject]@{
        Dimensions         = $dimensionResults
        ScoreLower         = $scoreLower
        ScoreUpper         = $scoreUpper
        CriticalCapApplied = $criticalApplied
        Coverage           = $coverage
        Verdict            = $verdict
        EssentialUnknowns  = $essentialUnknowns
    }
}

function Test-Policy {
    param([Parameter(Mandatory)][string]$Path)

    $policy = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $requireMet = @()
    if ($policy.PSObject.Properties.Name -contains 'requireMet') { $requireMet = @($policy.requireMet) }
    $results = foreach ($id in $requireMet) {
        if (-not $script:Criteria.Contains($id)) { throw "Policy references unknown criterion id: $id" }
        $criterion = $script:Criteria[$id]
        $compliance = switch ($criterion.Outcome) {
            'met' { 'compliant' }
            'na' { 'compliant' }
            'unmet' { 'violation' }
            default { 'unknown' }
        }
        [pscustomobject]@{ Criterion = $id; Required = 'met'; Outcome = $criterion.Outcome; Compliance = $compliance }
    }
    return [pscustomobject]@{
        Name    = if ($policy.PSObject.Properties.Name -contains 'name') { $policy.name } else { 'unnamed' }
        Results = @($results)
    }
}

# --- Reporting ----------------------------------------------------------------

function Get-TopFindings {
    # One representative (the most severe) per criterion, ranked by severity, so
    # every category with a finding appears once and a single noisy criterion
    # cannot crowd out the rest. GroupCount reports how many findings that
    # criterion produced. With $Count > 0 the list is capped; 0 shows all.
    param([int]$Count = 0)

    $representatives = foreach ($group in ($script:Findings | Group-Object -Property Criterion)) {
        $top = @($group.Group |
            Sort-Object -Property @{ Expression = { $SeverityRank[$_.Severity] }; Descending = $true })[0]
        [pscustomobject]@{
            Severity   = $top.Severity
            Capability = $top.Capability
            Target     = $top.Target
            Impact     = $top.Impact
            Criterion  = $top.Criterion
            GroupCount = $group.Count
        }
    }
    $ranked = @($representatives |
        Sort-Object -Property @{ Expression = { $SeverityRank[$_.Severity] }; Descending = $true }, Criterion)
    if ($Count -gt 0) { return @($ranked | Select-Object -First $Count) }
    return $ranked
}

function Get-OutcomeColor {
    param([Parameter(Mandatory)][string]$Outcome)

    switch ($Outcome) {
        'met' { 'Green' }
        'unmet' { 'Red' }
        'na' { 'DarkGray' }
        default { 'Yellow' }
    }
}

function Write-HumanReport {
    param(
        [Parameter(Mandatory)][psobject]$Measure,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Context,
        [switch]$Brief
    )

    $verdictColor = switch ($Measure.Verdict) {
        'Critical' { 'Red' }
        'Incomplete' { 'Yellow' }
        'Weak' { 'Red' }
        'Partial' { 'Yellow' }
        default { 'Green' }
    }
    Write-Host ''
    Write-Host '== Agent sandbox exposure assessment ==' -ForegroundColor Cyan
    Write-Host ("Identity: {0} (SID {1}), integrity {2}, elevated {3}, session {4}" -f `
            $Context.userName, $Context.userSid, $Context.integrityLevel, $Context.isElevated, $Context.sessionId)
    Write-Host ("Profile {0}/{1}  checker {2}  {3}" -f $ProfileId, $ProfileVersion, $CheckerVersion, $Context.timestampUtc) -ForegroundColor DarkGray
    if ($Brief) {
        Write-Host ''
        Write-Host 'Dimensions:' -ForegroundColor Cyan
        foreach ($dim in $Measure.Dimensions) {
            Write-Host ("  {0,-12} {1,2}-{2,-2} pts   met {3}  unmet {4}  unknown {5}  (applicable {6})" -f `
                    $dim.Dimension, $dim.LowerPoints, $dim.UpperPoints, $dim.Met, $dim.Unmet, $dim.Unknown, $dim.Applicable)
        }
    }
    else {
        Write-Host ''
        Write-Host 'Results (each criterion):' -ForegroundColor Cyan
        foreach ($dim in $Measure.Dimensions) {
            $items = @($script:Criteria.Values | Where-Object { $_.Dimension -eq $dim.Dimension })
            if ($items.Count -eq 0) { continue }
            $summary = "$($dim.Met)/$($dim.Applicable) met"
            if ($dim.Unknown -gt 0) { $summary += ", $($dim.Unknown) unknown" }
            Write-Host ("  {0} ({1})" -f $dim.Dimension, $summary) -ForegroundColor White
            foreach ($criterion in $items) {
                $tag = "[$($criterion.Outcome.ToUpper())]".PadRight(9)
                $essential = if ($criterion.Essential) { '*' } else { ' ' }
                Write-Host ("    {0} {1}{2,-20} {3}" -f $tag, $essential, $criterion.Id, $criterion.Title) `
                    -ForegroundColor (Get-OutcomeColor $criterion.Outcome)
                Write-Host ("            why: {0}" -f (Protect-Text $criterion.Reason)) -ForegroundColor DarkGray
            }
        }
        Write-Host ''
        Write-Host '  * essential criterion (must be met or unmet for a bounded verdict)' -ForegroundColor DarkGray
    }
    $top = @(Get-TopFindings)
    if ($top.Count -gt 0) {
        Write-Host ''
        Write-Host 'Top findings (one per category):' -ForegroundColor Cyan
        foreach ($finding in $top) {
            $more = if ($finding.GroupCount -gt 1) { " (+$($finding.GroupCount - 1) more)" } else { '' }
            Write-Host ("  [{0}] {1}: {2}{3}" -f $finding.Severity.ToUpper(), $finding.Capability, $finding.Target, $more) -ForegroundColor Yellow
            if ($finding.Impact) { Write-Host ("        {0}" -f $finding.Impact) -ForegroundColor DarkGray }
        }
    }
    $notEvaluated = @($script:Criteria.Values | Where-Object { $_.Outcome -eq 'unknown' } |
        Sort-Object -Property @{ Expression = { -not $_.Essential } }, Id)
    if ($notEvaluated.Count -gt 0) {
        Write-Host ''
        Write-Host "Not evaluated / unknown ($($notEvaluated.Count)):" -ForegroundColor Yellow
        foreach ($criterion in $notEvaluated) {
            $tag = if ($criterion.Essential) { 'essential, blocks bounded verdict' } else { 'non-essential' }
            Write-Host ("  {0} [{1}]  {2}" -f $criterion.Id, $tag, $criterion.Title)
            Write-Host ("        why: {0}" -f (Protect-Text $criterion.Reason)) -ForegroundColor DarkGray
        }
    }
    # The verdict concludes the evidence above and leads into remediation.
    # Show the whole verdict scale; the current verdict is raised and colored.
    Write-Host ''
    Write-Host 'Verdict: ' -NoNewline
    $scale = @('Critical', 'Incomplete', 'Weak', 'Partial', 'Strong')
    for ($i = 0; $i -lt $scale.Count; $i++) {
        if ($i -gt 0) { Write-Host ' | ' -NoNewline -ForegroundColor DarkGray }
        if ($scale[$i] -eq $Measure.Verdict) { Write-Host $scale[$i].ToUpperInvariant() -NoNewline -ForegroundColor $verdictColor }
        else { Write-Host $scale[$i] -NoNewline -ForegroundColor DarkGray }
    }
    Write-Host ''
    Write-Host "Verdict scope: $VerdictScope" -ForegroundColor DarkGray
    Write-Host ("Control score: {0}-{1} / 100{2}" -f $Measure.ScoreLower, $Measure.ScoreUpper,
        $(if ($Measure.CriticalCapApplied) { '  (critical cap applied)' } else { '' }))
    Write-Host ("Evidence coverage: {0}%" -f [int]($Measure.Coverage * 100))
    $remediable = @($script:Criteria.Values | Where-Object { $_.Outcome -eq 'unmet' })
    if ($remediable.Count -gt 0) {
        Write-Host ''
        Write-Host 'Remediation:' -ForegroundColor Cyan
        foreach ($criterion in $remediable) {
            Write-Host ("  {0}: {1}" -f $criterion.Id, $criterion.Remediation) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    Write-Host 'Inside-only diagnostic. Granted handles prove authorization only; a compromised agent can falsify this report.' -ForegroundColor DarkGray
}

function Get-MarkdownReport {
    param([Parameter(Mandatory)][psobject]$Measure, [Parameter(Mandatory)][System.Collections.IDictionary]$Context)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Agent sandbox exposure assessment')
    $lines.Add('')
    $lines.Add("- Verdict: **$($Measure.Verdict)**")
    $lines.Add("- Verdict scope: $VerdictScope")
    $lines.Add("- Control score: $($Measure.ScoreLower)-$($Measure.ScoreUpper) / 100" +
        $(if ($Measure.CriticalCapApplied) { ' (critical cap applied)' } else { '' }))
    $lines.Add("- Evidence coverage: $([int]($Measure.Coverage * 100))%")
    $lines.Add("- Identity: $($Context.userName) (integrity $($Context.integrityLevel), elevated $($Context.isElevated))")
    $lines.Add("- Profile $ProfileId/$ProfileVersion, checker $CheckerVersion, $($Context.timestampUtc)")
    $lines.Add('')
    $lines.Add('## Dimensions')
    $lines.Add('')
    $lines.Add('| Dimension | Points | Met | Unmet | Unknown | Applicable |')
    $lines.Add('| --- | --- | --- | --- | --- | --- |')
    foreach ($dim in $Measure.Dimensions) {
        $lines.Add("| $($dim.Dimension) | $($dim.LowerPoints)-$($dim.UpperPoints) | $($dim.Met) | $($dim.Unmet) | $($dim.Unknown) | $($dim.Applicable) |")
    }
    $lines.Add('')
    $lines.Add('## Criteria')
    $lines.Add('')
    $lines.Add('| ID | Outcome | Essential | Reason |')
    $lines.Add('| --- | --- | --- | --- |')
    foreach ($criterion in $script:Criteria.Values) {
        $lines.Add("| $($criterion.Id) | $($criterion.Outcome) | $($criterion.Essential) | $(Protect-Text $criterion.Reason) |")
    }
    return ($lines -join [Environment]::NewLine)
}

# --- Main ---------------------------------------------------------------------

$script:StartTime = [DateTime]::UtcNow

$script:UserProfile = $env:USERPROFILE
if ($Workspace) {
    try { $script:WorkspacePath = (Resolve-Path -LiteralPath $Workspace -ErrorAction Stop).Path }
    catch { Write-Diag "Workspace not found, using as-is: $Workspace"; $script:WorkspacePath = $Workspace }
}
else {
    $script:WorkspacePath = (Get-Location).Path
}

if ($PolicyPath -and -not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
    Write-Diag "Policy file not found: $PolicyPath"
    exit 1
}
if ($OutputDirectory -and -not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    Write-Diag "Output directory does not exist: $OutputDirectory"
    exit 1
}
# Run order is explicit. Adding a check is one line here plus its criteria in
# the registry and one Invoke-<Area>Check function; areas with no entry remain
# "not implemented in v1". Invoke-Check enforces that each listed check resolves
# every criterion in its area.
$CheckPlan = @(
    @{ Area = 'IDENTITY'; Body = { Invoke-IdentityCheck } }
    @{ Area = 'FILES'; Body = { Invoke-FilesCheck } }
    @{ Area = 'SECRETS'; Body = { Invoke-SecretsCheck } }
    @{ Area = 'PROCESSES'; Body = { Invoke-ProcessesCheck } }
    @{ Area = 'DESKTOP'; Body = { Invoke-DesktopCheck } }
    @{ Area = 'NETWORK'; Body = { Invoke-NetworkCheck } }
    @{ Area = 'HANDOFF'; Body = { Invoke-HandoffCheck } }
    @{ Area = 'INDIRECT'; Body = { Invoke-IndirectCheck } }
    @{ Area = 'REMOTE'; Body = { Invoke-RemoteCheck } }
    @{ Area = 'CONTAINMENT'; Body = { Invoke-ContainmentCheck } }
    @{ Area = 'MONITORING'; Body = { Invoke-MonitoringCheck } }
)

# Native init (Add-Type compile) and the checks are the slow part; a spinner
# runs across both. The finally guarantees the spinner stops and its line is
# erased on any exit, including the init-failure exit below.
$spinner = Start-ProgressSpinner -Label 'Initializing'
try {
    try {
        Initialize-NativeProbe
    }
    catch {
        # The outer finally stops the spinner before the process exits.
        Write-Diag "Fatal: native probe initialization failed: $($_.Exception.Message)"
        exit 1
    }
    $checkCount = $CheckPlan.Count
    $checkIndex = 0
    foreach ($plan in $CheckPlan) {
        $checkIndex++
        Update-ProgressSpinner -Spinner $spinner -Label ("[{0}/{1}] checking {2}" -f $checkIndex, $checkCount, $plan.Area)
        Invoke-Check -Name $plan.Area -Body $plan.Body
    }
}
finally {
    Stop-ProgressSpinner -Spinner $spinner
}
$implementedAreas = @($CheckPlan | ForEach-Object { $_.Area })
$notImplementedAreas = @($AllCheckAreas | Where-Object { $implementedAreas -notcontains $_ })

# Checks not implemented in v1 keep their criteria as honest unknowns.
foreach ($criterion in $script:Criteria.Values) {
    if ($criterion.Reason -eq 'not evaluated') {
        Set-CriterionOutcome -Id $criterion.Id -Outcome 'unknown' -Reason 'not implemented in v1'
    }
}

$policyResult = $null
if ($PolicyPath) {
    try { $policyResult = Test-Policy -Path $PolicyPath }
    catch { Write-Diag $_.Exception.Message; exit 1 }
}

$scopeLimitations = 'Process grants are individual permissions, not verified injection paths. Filesystem checks sample declared targets and direct child files, not all descendants.'
if ($notImplementedAreas.Count -gt 0) {
    $scopeLimitations += " These checks are not implemented: $($notImplementedAreas -join ', '); related criteria are unknown."
}

$measure = Measure-Assessment

$contextToken = [AgentSandboxAssessmentNative]::GetCurrentToken()
$parentProcess = $null
try {
    $parentId = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop).ParentProcessId
    $parentProcess = (Get-Process -Id $parentId -ErrorAction Stop).ProcessName
}
catch {
    # Parent process is not always inspectable; launch context stays partial.
}

$context = [ordered]@{
    userSid        = $contextToken.UserSid
    userName       = (Protect-Text (Resolve-SidName $contextToken.UserSid))
    integrityLevel = (Get-IntegrityLabel $contextToken.IntegritySid)
    isElevated     = $contextToken.IsElevated
    sessionId      = $contextToken.SessionId
    processId      = $PID
    parentProcess  = $parentProcess
    psVersion      = $PSVersionTable.PSVersion.ToString()
    osVersion      = [System.Environment]::OSVersion.Version.ToString()
    timestampUtc   = $script:StartTime.ToString('o')
}

$report = [ordered]@{
    schemaVersion     = $SchemaVersion
    checkerVersion    = $CheckerVersion
    profile           = [ordered]@{ id = $ProfileId; version = $ProfileVersion }
    status            = if ($script:Errors.Count -gt 0) { 'completed-with-errors' } else { 'completed' }
    durationSeconds   = [math]::Round(([DateTime]::UtcNow - $script:StartTime).TotalSeconds, 2)
    executionContext  = $context
    scope             = [ordered]@{
        workspace            = (Format-SafePath $script:WorkspacePath)
        checksEvaluated      = @($implementedAreas | Where-Object { $SkipCheck -notcontains $_ })
        checksSkipped        = @($SkipCheck)
        checksNotImplemented = @($notImplementedAreas)
        networkProbed        = $script:NetworkProbed
        networkTargets       = @($script:NetworkTargetsUsed)
    }
    verdict           = $measure.Verdict
    verdictScope      = $VerdictScope
    score             = [ordered]@{ lower = $measure.ScoreLower; upper = $measure.ScoreUpper; criticalCapApplied = $measure.CriticalCapApplied }
    coverage          = $measure.Coverage
    dimensions        = @($measure.Dimensions | ForEach-Object {
            [ordered]@{ dimension = $_.Dimension; applicable = $_.Applicable; met = $_.Met; unmet = $_.Unmet; unknown = $_.Unknown; coverage = $_.Coverage; lowerPoints = $_.LowerPoints; upperPoints = $_.UpperPoints }
        })
    criteria          = @($script:Criteria.Values | ForEach-Object {
            [ordered]@{ id = $_.Id; dimension = $_.Dimension; check = $_.Check; essential = $_.Essential; severity = $_.Severity; title = $_.Title; outcome = $_.Outcome; reason = (Protect-Text $_.Reason); method = $_.Method; critical = $_.Critical; criticalReason = $_.CriticalReason; remediation = $_.Remediation }
        })
    findings          = $script:Findings.ToArray()
    essentialUnknowns = @($measure.EssentialUnknowns | ForEach-Object { $_.Id })
    notEvaluated      = @($script:Criteria.Values | Where-Object { $_.Outcome -eq 'unknown' } | ForEach-Object {
            [ordered]@{ id = $_.Id; title = $_.Title; dimension = $_.Dimension; essential = $_.Essential; reason = (Protect-Text $_.Reason) }
        })
    policy            = $policyResult
    inventory         = $script:Inventory
    limitations       = @(
        'Inside-only run: host policy, external log collection and remote authorization cannot be fully established.',
        'A compromised agent could falsify this report; provenance is recorded but not independently attested.',
        $scopeLimitations,
        'Discovery and scans have entry, file and byte caps plus a cooperative time budget; a blocked filesystem/API call can exceed that budget.',
        'Ambiguous task arguments, effective proxy routing, managed-tool policy application and active external logging remain unverified.',
        'A granted handle proves authorization only; no destructive operation was performed.'
    )
    errors            = $script:Errors.ToArray()
}

$report = Protect-Report $report
$jsonText = $report | ConvertTo-Json -Depth 12

if ($Json) {
    [Console]::Out.WriteLine($jsonText)
}
else {
    Write-HumanReport -Measure $measure -Context $context -Brief:$Brief
}

if ($OutputDirectory) {
    $stamp = $script:StartTime.ToString('yyyyMMdd-HHmmss')
    $jsonPath = Join-Path $OutputDirectory "assessment-$stamp.json"
    $mdPath = Join-Path $OutputDirectory "assessment-$stamp.md"
    Set-Content -LiteralPath $jsonPath -Value $jsonText -Encoding utf8
    Set-Content -LiteralPath $mdPath -Value (Get-MarkdownReport -Measure $measure -Context $context) -Encoding utf8
    Write-Diag "Wrote $jsonPath and $mdPath"
}

exit 0
