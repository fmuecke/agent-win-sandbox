# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox
#Requires -Version 5.1
<#
.SYNOPSIS
    General Windows host hardening for a machine that may run untrusted workloads
    (including AI agents under separate standard-user accounts).

.DESCRIPTION
    This v1 intentionally stops at general Windows host hardening. Agent-specific
    containment (broker/session isolation, localhost services, named pipes, WSL
    bridges, egress policy, etc.) belongs in the agent sandbox setup.

    The script defaults to AUDIT MODE. No changes are made unless -Apply is used.

    Intended hardening steps agreed for v1
    =======================================

    1.  Selected personal/data roots:
        In audit mode, discover likely personal/data top-level directories on fixed
        drives and list them as candidate private roots. Known Windows-, service-,
        and application-managed roots are excluded. Candidates are suggestions
        only and are never assumed to be private automatically.
        For explicitly selected roots, disable inheritance on the root, remove
        broad access throughout the selected tree, and grant Full Control on the
        root only to the current user, SYSTEM, and BUILTIN\Administrators.
        No explicit Deny ACEs are added.

    2.  System-drive root:
        Remove broad standard-user create/write rights on the drive root itself
        (for example C:\), while preserving read/execute and existing child
        permissions. No special write ACE is added for the current administrator;
        creating at the drive root should require elevation.

    3.  Other local fixed-drive roots:
        Apply the same root-only policy to all local fixed drives. Do not touch
        removable or network drives.

    4.  Public profile:
        Remove broad Users / Authenticated Users / Everyone write/modify rights
        from C:\Users\Public and descendants. Preserve read/execute.

    5.  User-profile privacy:
        Verify real user-profile roots do not grant broad access to Users,
        Authenticated Users, or Everyone. Remediate deviations only. Exclude
        Public, Default/system profiles, and the configured agent profile.

    6.  Machine PATH:
        Ensure directories in the machine-wide PATH, plus executable/script files
        directly inside them, are not writable by broad standard-user principals.
        Skip explicitly configured agent-writable roots.

    7.  Privileged services and scheduled tasks:
        Inspect executable/script paths used by Windows services and elevated/
        privileged scheduled tasks. Detect broad-user-writable executables or
        parent directories and remediate clearly unsafe ACLs. Report ambiguous
        command lines such as unquoted service paths for manual review.

    8.  Current-user PATH:
        Remove broad-group write/modify access from directories in the current
        user's PATH while preserving the current user's own ability to modify
        those directories where needed. Flag/skip paths shared with the agent.

    9.  Shared auto-execution locations:
        Protect common Startup / Start Menu execution locations from broad
        standard-user writes while preserving read/execute.

    10. Machine-wide registry execution/configuration points:
        Verify and remediate broad-user write access on HKLM Run/RunOnce,
        App Paths, Image File Execution Options, Winlogon, and service
        configuration keys.

    11. UAC:
        Verify security-critical UAC settings and remediate only weakened values:
        EnableLUA must be enabled, elevation prompts must use the secure desktop,
        silent administrator elevation is not accepted, and UIAccess elevation
        remains limited to secure locations. Do NOT force "Always notify".

    12. Dangerous elevation shortcuts:
        Disable AlwaysInstallElevated if configured, and detect/remove stored
        AutoAdminLogon credentials when -Apply is used.

    13. Microsoft Defender:
        Verify real-time, behavior, and script scanning. In -Apply mode, attempt
        to re-enable these protections if disabled. Report all exclusions and
        highlight broad development-root exclusions and exclusions overlapping
        agent-writable paths. Exclusions are REPORT-ONLY and are never removed.

    14. Credential-protection status:
        Report LSA protection configuration and Credential Guard/VBS runtime
        status. REPORT-ONLY; this script does not force-enable Credential Guard.

    Safety model
    ============
    - Audit is the default. Use -Apply explicitly to modify the system.
    - Broad principals are identified by SID, not localized account names:
        Everyone            S-1-1-0
        Authenticated Users S-1-5-11
        BUILTIN\Users       S-1-5-32-545
    - No explicit Deny ACEs are created.
    - System-managed trees such as Windows, Program Files, and ProgramData are
      never recursively re-ACL'd.
    - Defender exclusions and Credential Guard are never changed automatically.
    - Restart may be required for some security-policy changes to take effect.

.PARAMETER Apply
    Actually apply approved remediations. Without this switch the script only
    audits and reports.

.PARAMETER PrivateRoot
    One or more personal/data roots to make private, e.g. C:\dev-private,D:\data.
    Do not specify Windows-managed locations.

.PARAMETER AgentWritableRoot
    One or more locations intentionally writable by the agent. These are used to
    skip PATH hardening conflicts and to flag Defender exclusion overlap.

.PARAMETER AgentUser
    Agent account name whose profile should be excluded from step 5.
    Default: AgentSandbox

.EXAMPLE
    .\Harden-WindowsHost.ps1 -PrivateRoot C:\private,D:\personal `
        -AgentWritableRoot C:\agent-work

.EXAMPLE
    .\Harden-WindowsHost.ps1 -Apply `
        -PrivateRoot C:\private,D:\personal `
        -AgentWritableRoot C:\agent-work
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [string[]]$PrivateRoot = @(),
    [string[]]$AgentWritableRoot = @(),
    [string]$AgentUser = 'AgentSandbox'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- constants ----------------------------------------------------------------

$script:BroadSids = @(
    'S-1-1-0',       # Everyone
    'S-1-5-11',      # Authenticated Users
    'S-1-5-32-545'   # BUILTIN\Users
)

$script:SystemSid = 'S-1-5-18'
$script:AdministratorsSid = 'S-1-5-32-544'
$script:CurrentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

$script:FsWriteMask = [int][System.Security.AccessControl.FileSystemRights]::WriteData `
    -bor [int][System.Security.AccessControl.FileSystemRights]::AppendData `
    -bor [int][System.Security.AccessControl.FileSystemRights]::WriteAttributes `
    -bor [int][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
    -bor [int][System.Security.AccessControl.FileSystemRights]::Delete `
    -bor [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
    -bor [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions `
    -bor [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership

$script:RegistryWriteMask = [int][System.Security.AccessControl.RegistryRights]::SetValue `
    -bor [int][System.Security.AccessControl.RegistryRights]::CreateSubKey `
    -bor [int][System.Security.AccessControl.RegistryRights]::Delete `
    -bor [int][System.Security.AccessControl.RegistryRights]::ChangePermissions `
    -bor [int][System.Security.AccessControl.RegistryRights]::TakeOwnership

$script:Findings = [System.Collections.Generic.List[object]]::new()

# --- reporting ----------------------------------------------------------------

function Add-Finding {
    param(
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][ValidateSet('INFO','OK','WARN','HIGH','ERROR','CHANGED','SKIPPED')][string]$Level,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Message
    )

    $item = [pscustomobject]@{
        Step    = $Step
        Level   = $Level
        Target  = $Target
        Message = $Message
    }
    $script:Findings.Add($item)

    if ($Level -ne 'OK' -or $VerbosePreference -eq 'Continue') {
        $prefix = "[{0,2}] {1,-7}" -f $Step, $Level
        Write-Host "$prefix $Target - $Message"
    }
}

function Invoke-ApprovedChange {
    param(
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    if (-not $Apply) {
        Add-Finding -Step $Step -Level WARN -Target $Target -Message "$Description [audit only]"
        return $false
    }

    try {
        & $Action
        Add-Finding -Step $Step -Level CHANGED -Target $Target -Message $Description
        return $true
    }
    catch {
        Add-Finding -Step $Step -Level ERROR -Target $Target -Message "$Description FAILED: $($_.Exception.Message)"
        return $false
    }
}

# --- generic helpers ----------------------------------------------------------

function Test-IsAdministrator {
    $principal = [System.Security.Principal.WindowsPrincipal]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Normalize-Path {
    param([Parameter(Mandatory)][string]$Path)
    try {
        return [System.IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Path)
        ).TrimEnd('\')
    }
    catch {
        return $Path.TrimEnd('\')
    }
}

function Test-PathOverlap {
    param(
        [Parameter(Mandatory)][string]$A,
        [Parameter(Mandatory)][string]$B
    )

    $a1 = (Normalize-Path $A)
    $b1 = (Normalize-Path $B)

    return $a1.Equals($b1, [System.StringComparison]::OrdinalIgnoreCase) -or
           $a1.StartsWith($b1 + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
           $b1.StartsWith($a1 + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-AgentWritableOverlap {
    param([Parameter(Mandatory)][string]$Path)

    foreach ($root in $AgentWritableRoot) {
        if ($root -and (Test-PathOverlap -A $Path -B $root)) {
            return $true
        }
    }
    return $false
}

function Test-IsBroadSid {
    param([Parameter(Mandatory)][string]$Sid)
    return $script:BroadSids -contains $Sid
}

function Get-FileSystemRulesBySid {
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemSecurity]$Acl)

    return $Acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )
}

function Test-FsRuleHasWrite {
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemAccessRule]$Rule)

    if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
        return $false
    }
    return (([int]$Rule.FileSystemRights -band $script:FsWriteMask) -ne 0)
}

function Get-BroadFsRules {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$WriteOnly
    )

    $acl = Get-Acl -LiteralPath $Path
    $rules = Get-FileSystemRulesBySid -Acl $acl

    return @($rules | Where-Object {
        (Test-IsBroadSid $_.IdentityReference.Value) -and
        (-not $WriteOnly -or (Test-FsRuleHasWrite $_))
    })
}

function Remove-BroadWriteFromFsItem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step,
        [switch]$BreakInheritance
    )

    $rules = @(Get-BroadFsRules -Path $Path -WriteOnly)
    if ($rules.Count -eq 0) {
        Add-Finding -Step $Step -Level OK -Target $Path -Message 'No broad standard-user write ACL found.'
        return
    }

    $desc = "Remove broad standard-user write/modify ACLs"
    Invoke-ApprovedChange -Step $Step -Target $Path -Description $desc -Action {
        $acl = Get-Acl -LiteralPath $Path

        if ($BreakInheritance -and -not $acl.AreAccessRulesProtected) {
            # Copy inherited ACEs as explicit ACEs, then edit locally.
            $acl.SetAccessRuleProtection($true, $true)
        }

        $editRules = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ))

        foreach ($rule in $editRules) {
            $sid = $rule.IdentityReference.Value
            if (-not (Test-IsBroadSid $sid)) { continue }
            if (-not (Test-FsRuleHasWrite $rule)) { continue }

            # If an inherited rule remains inherited, it cannot be removed here.
            if ($rule.IsInherited) {
                throw "Unsafe write ACE for $sid is inherited; use a parent-specific remediation."
            }

            $old = [int]$rule.FileSystemRights
            $safe = $old -band (-bnot $script:FsWriteMask)

            [void]$acl.RemoveAccessRuleSpecific($rule)

            if ($safe -ne 0) {
                $newRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $rule.IdentityReference,
                    [System.Security.AccessControl.FileSystemRights]$safe,
                    $rule.InheritanceFlags,
                    $rule.PropagationFlags,
                    $rule.AccessControlType
                )
                $acl.AddAccessRule($newRule)
            }
        }

        Set-Acl -LiteralPath $Path -AclObject $acl
    } | Out-Null
}

function Remove-WriteFromDriveRootPreserveChildren {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step
    )

    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [System.Security.Principal.SecurityIdentifier]
    ))

    $unsafe = @($rules | Where-Object {
        (Test-IsBroadSid $_.IdentityReference.Value) -and
        (Test-FsRuleHasWrite $_) -and
        (($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)
    })

    if ($unsafe.Count -eq 0) {
        Add-Finding -Step $Step -Level OK -Target $Path -Message 'No broad write/create right applies to the drive root.'
        return
    }

    Invoke-ApprovedChange -Step $Step -Target $Path `
        -Description 'Remove broad write/create rights from this drive root while preserving child inheritance' `
        -Action {
            $acl2 = Get-Acl -LiteralPath $Path
            $rules2 = @($acl2.GetAccessRules(
                $true,
                $false,
                [System.Security.Principal.SecurityIdentifier]
            ))

            foreach ($rule in $rules2) {
                $sid = $rule.IdentityReference.Value
                if (-not (Test-IsBroadSid $sid)) { continue }
                if (-not (Test-FsRuleHasWrite $rule)) { continue }
                if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
                    continue
                }

                $old = [int]$rule.FileSystemRights
                $removed = $old -band $script:FsWriteMask
                $safe = $old -band (-bnot $script:FsWriteMask)

                [void]$acl2.RemoveAccessRuleSpecific($rule)

                if ($safe -ne 0) {
                    $safeRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                        $rule.IdentityReference,
                        [System.Security.AccessControl.FileSystemRights]$safe,
                        $rule.InheritanceFlags,
                        $rule.PropagationFlags,
                        $rule.AccessControlType
                    )
                    $acl2.AddAccessRule($safeRule)
                }

                # Preserve the previous write inheritance for children, but make
                # those write bits inherit-only so they no longer apply to root.
                if ($removed -ne 0 -and
                    $rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None) {

                    $childPropagation = $rule.PropagationFlags -bor `
                        [System.Security.AccessControl.PropagationFlags]::InheritOnly

                    $childRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                        $rule.IdentityReference,
                        [System.Security.AccessControl.FileSystemRights]$removed,
                        $rule.InheritanceFlags,
                        $childPropagation,
                        $rule.AccessControlType
                    )
                    $acl2.AddAccessRule($childRule)
                }
            }

            Set-Acl -LiteralPath $Path -AclObject $acl2
        } | Out-Null
}

function Set-StrictPrivateRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Add-Finding -Step $Step -Level ERROR -Target $Path -Message 'Private root does not exist.'
        return
    }

    $full = Normalize-Path $Path
    $protectedRoots = @(
        (Normalize-Path $env:windir),
        (Normalize-Path $env:ProgramFiles),
        $(if (${env:ProgramFiles(x86)}) { Normalize-Path ${env:ProgramFiles(x86)} }),
        (Normalize-Path $env:ProgramData),
        (Normalize-Path "$env:SystemDrive\Users")
    ) | Where-Object { $_ }

    foreach ($protected in $protectedRoots) {
        if (Test-PathOverlap -A $full -B $protected) {
            Add-Finding -Step $Step -Level ERROR -Target $Path `
                -Message "Refusing strict-private ACL on Windows-managed tree: $protected"
            return
        }
    }

    if ([System.IO.Path]::GetPathRoot($full).TrimEnd('\') -eq $full.TrimEnd('\')) {
        Add-Finding -Step $Step -Level ERROR -Target $Path -Message 'Refusing strict-private ACL on a drive root.'
        return
    }

    Invoke-ApprovedChange -Step $Step -Target $Path `
        -Description 'Set strict private ACL: current user + SYSTEM + Administrators only' `
        -Action {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false) # disable inheritance, discard inherited ACEs

            foreach ($rule in @($acl.GetAccessRules(
                $true,
                $false,
                [System.Security.Principal.SecurityIdentifier]
            ))) {
                [void]$acl.RemoveAccessRuleSpecific($rule)
            }

            $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $prop = [System.Security.AccessControl.PropagationFlags]::None
            $fc = [System.Security.AccessControl.FileSystemRights]::FullControl
            $allow = [System.Security.AccessControl.AccessControlType]::Allow

            foreach ($sidText in @(
                $script:CurrentUserSid,
                $script:SystemSid,
                $script:AdministratorsSid
            )) {
                $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid, $fc, $inherit, $prop, $allow
                )
                $acl.AddAccessRule($rule)
            }

            Set-Acl -LiteralPath $Path -AclObject $acl

            # Root inheritance is now clean. Remove any explicit broad ACEs that
            # descendants may carry independently of the root.
            foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue)) {
                try {
                    $childAcl = Get-Acl -LiteralPath $child.FullName
                    $explicitRules = @($childAcl.GetAccessRules(
                        $true,
                        $false,
                        [System.Security.Principal.SecurityIdentifier]
                    ))

                    $changed = $false
                    foreach ($childRule in $explicitRules) {
                        if (Test-IsBroadSid $childRule.IdentityReference.Value) {
                            [void]$childAcl.RemoveAccessRuleSpecific($childRule)
                            $changed = $true
                        }
                    }

                    if ($changed) {
                        Set-Acl -LiteralPath $child.FullName -AclObject $childAcl
                    }
                }
                catch {
                    Add-Finding -Step $Step -Level ERROR -Target $child.FullName `
                        -Message "Could not remove descendant broad ACL: $($_.Exception.Message)"
                }
            }
        } | Out-Null

    # In audit mode, identify explicit descendant broad ACEs that would survive
    # a root-only ACL change unless removed.
    if (-not $Apply) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue)) {
            try {
                $childAcl = Get-Acl -LiteralPath $child.FullName
                $explicitBroad = @($childAcl.GetAccessRules(
                    $true,
                    $false,
                    [System.Security.Principal.SecurityIdentifier]
                ) | Where-Object { Test-IsBroadSid $_.IdentityReference.Value })

                if ($explicitBroad.Count -gt 0) {
                    Add-Finding -Step $Step -Level WARN -Target $child.FullName `
                        -Message 'Explicit broad descendant ACL would be removed in apply mode.'
                }
            }
            catch {
                Add-Finding -Step $Step -Level ERROR -Target $child.FullName -Message $_.Exception.Message
            }
        }
    }
}

function Protect-TreeFromBroadWrite {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][int]$Step
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        Add-Finding -Step $Step -Level SKIPPED -Target $Root -Message 'Path not present.'
        return
    }

    $items = @((Get-Item -LiteralPath $Root -Force))
    try {
        $items += @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction SilentlyContinue)
    }
    catch {
        Add-Finding -Step $Step -Level WARN -Target $Root -Message "Could not enumerate complete tree: $($_.Exception.Message)"
    }

    foreach ($item in $items) {
        try {
            $unsafe = @(Get-BroadFsRules -Path $item.FullName -WriteOnly)
            if ($unsafe.Count -gt 0) {
                Remove-BroadWriteFromFsItem -Path $item.FullName -Step $Step -BreakInheritance
            }
        }
        catch {
            Add-Finding -Step $Step -Level ERROR -Target $item.FullName -Message $_.Exception.Message
        }
    }
}

function Ensure-CurrentUserModify {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))

    $hasModify = $false
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -eq $script:CurrentUserSid -and
            $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            (([int]$rule.FileSystemRights -band [int][System.Security.AccessControl.FileSystemRights]::Modify) -ne 0)) {
            $hasModify = $true
            break
        }
    }

    if ($hasModify) { return }

    Invoke-ApprovedChange -Step $Step -Target $Path `
        -Description 'Grant current user Modify on user-PATH directory' `
        -Action {
            $acl2 = Get-Acl -LiteralPath $Path
            $sid = [System.Security.Principal.SecurityIdentifier]::new($script:CurrentUserSid)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl2.AddAccessRule($rule)
            Set-Acl -LiteralPath $Path -AclObject $acl2
        } | Out-Null
}

function Get-PathEntries {
    param([Parameter(Mandatory)][ValidateSet('Machine','User')][string]$Scope)

    $raw = [Environment]::GetEnvironmentVariable('Path', $Scope)
    if (-not $raw) { return @() }

    return @($raw.Split(';') |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ } |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } |
        Select-Object -Unique)
}

function Protect-PathDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step,
        [switch]$PreserveCurrentUserModify
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Add-Finding -Step $Step -Level WARN -Target $Path -Message 'PATH entry does not exist.'
        return
    }

    if (Test-AgentWritableOverlap -Path $Path) {
        Add-Finding -Step $Step -Level SKIPPED -Target $Path `
            -Message 'Overlaps an explicitly agent-writable root; review manually.'
        return
    }

    $hadBroadWrite = @(Get-BroadFsRules -Path $Path -WriteOnly).Count -gt 0
    if ($hadBroadWrite) {
        Remove-BroadWriteFromFsItem -Path $Path -Step $Step -BreakInheritance
        if ($PreserveCurrentUserModify) {
            Ensure-CurrentUserModify -Path $Path -Step $Step
        }
    }
    else {
        Add-Finding -Step $Step -Level OK -Target $Path -Message 'PATH directory is not broadly writable.'
    }

    # PATH command lookup is top-level. Check executable/script files directly in it.
    $patterns = @('*.exe','*.com','*.bat','*.cmd','*.ps1')
    foreach ($pattern in $patterns) {
        foreach ($file in @(Get-ChildItem -LiteralPath $Path -Filter $pattern -File -Force -ErrorAction SilentlyContinue)) {
            try {
                if (@(Get-BroadFsRules -Path $file.FullName -WriteOnly).Count -gt 0) {
                    Remove-BroadWriteFromFsItem -Path $file.FullName -Step $Step -BreakInheritance
                }
            }
            catch {
                Add-Finding -Step $Step -Level ERROR -Target $file.FullName -Message $_.Exception.Message
            }
        }
    }
}

function Get-ReferencedPathsFromCommandLine {
    param([string]$CommandLine)

    if (-not $CommandLine) { return @() }

    $line = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $result = [System.Collections.Generic.List[string]]::new()

    # Leading executable, quoted or unquoted (unquoted form may include spaces up to .exe).
    if ($line -match '^\s*"(?<p>[^"]+\.(?:exe|com|bat|cmd))"') {
        $result.Add($Matches.p)
    }
    elseif ($line -match '^\s*(?<p>[A-Za-z]:\\.*?\.(?:exe|com|bat|cmd))(?=\s|$)') {
        $result.Add($Matches.p)
    }

    # Absolute referenced executable/script/library paths elsewhere in arguments.
    $regex = '(?i)(?:"(?<q>(?:[A-Z]:\\|\\\\)[^"]+\.(?:exe|com|bat|cmd|ps1|vbs|js|dll))"|(?<u>(?:[A-Z]:\\|\\\\)[^\s"]+\.(?:exe|com|bat|cmd|ps1|vbs|js|dll)))'
    foreach ($m in [regex]::Matches($line, $regex)) {
        $p = if ($m.Groups['q'].Success) { $m.Groups['q'].Value } else { $m.Groups['u'].Value }
        if ($p -and -not $result.Contains($p)) {
            $result.Add($p)
        }
    }

    return @($result)
}

function Test-UnquotedServicePath {
    param([string]$CommandLine)

    if (-not $CommandLine) { return $false }
    $line = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($line.StartsWith('"')) { return $false }

    if ($line -match '^(?<p>[A-Za-z]:\\.*?\.exe)(?=\s|$)') {
        return $Matches.p.Contains(' ')
    }
    return $false
}

function Protect-ExecutionPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][string]$Source
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)

    if (-not [System.IO.Path]::IsPathRooted($expanded)) {
        try {
            $cmd = Get-Command $expanded -ErrorAction Stop
            $expanded = $cmd.Source
        }
        catch {
            Add-Finding -Step $Step -Level WARN -Target "$Source :: $Path" -Message 'Could not resolve execution path.'
            return
        }
    }

    if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
        Add-Finding -Step $Step -Level WARN -Target "$Source :: $expanded" -Message 'Referenced execution file not found.'
        return
    }

    try {
        if (@(Get-BroadFsRules -Path $expanded -WriteOnly).Count -gt 0) {
            Add-Finding -Step $Step -Level HIGH -Target "$Source :: $expanded" -Message 'Privileged execution file is broadly writable.'
            Remove-BroadWriteFromFsItem -Path $expanded -Step $Step -BreakInheritance
        }

        $parent = Split-Path -Parent $expanded
        if ($parent -and @(Get-BroadFsRules -Path $parent -WriteOnly).Count -gt 0) {
            Add-Finding -Step $Step -Level HIGH -Target "$Source :: $parent" -Message 'Parent directory of privileged execution file is broadly writable.'
            Remove-BroadWriteFromFsItem -Path $parent -Step $Step -BreakInheritance
        }
    }
    catch {
        Add-Finding -Step $Step -Level ERROR -Target "$Source :: $expanded" -Message $_.Exception.Message
    }
}

# --- registry ACL helpers -----------------------------------------------------

function Get-RegistryRulesBySid {
    param([Parameter(Mandatory)][System.Security.AccessControl.RegistrySecurity]$Acl)

    return $Acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )
}

function Test-RegistryRuleHasWrite {
    param([Parameter(Mandatory)][System.Security.AccessControl.RegistryAccessRule]$Rule)

    if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
        return $false
    }
    return (([int]$Rule.RegistryRights -band $script:RegistryWriteMask) -ne 0)
}

function Protect-RegistryKey {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Step
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Finding -Step $Step -Level SKIPPED -Target $Path -Message 'Registry key not present.'
        return
    }

    $acl = Get-Acl -LiteralPath $Path
    $unsafe = @(Get-RegistryRulesBySid -Acl $acl | Where-Object {
        (Test-IsBroadSid $_.IdentityReference.Value) -and
        (Test-RegistryRuleHasWrite $_)
    })

    if ($unsafe.Count -eq 0) {
        Add-Finding -Step $Step -Level OK -Target $Path -Message 'No broad standard-user registry write ACL found.'
        return
    }

    Add-Finding -Step $Step -Level HIGH -Target $Path -Message 'Machine execution/configuration registry key is broadly writable.'

    Invoke-ApprovedChange -Step $Step -Target $Path `
        -Description 'Remove broad standard-user registry write permissions' `
        -Action {
            $acl2 = Get-Acl -LiteralPath $Path
            if (-not $acl2.AreAccessRulesProtected) {
                $acl2.SetAccessRuleProtection($true, $true)
            }

            foreach ($rule in @($acl2.GetAccessRules(
                $true,
                $true,
                [System.Security.Principal.SecurityIdentifier]
            ))) {
                if (-not (Test-IsBroadSid $rule.IdentityReference.Value)) { continue }
                if (-not (Test-RegistryRuleHasWrite $rule)) { continue }
                if ($rule.IsInherited) {
                    throw "Broad registry write ACE is still inherited after inheritance protection."
                }

                $old = [int]$rule.RegistryRights
                $safe = $old -band (-bnot $script:RegistryWriteMask)
                [void]$acl2.RemoveAccessRuleSpecific($rule)

                if ($safe -ne 0) {
                    $newRule = [System.Security.AccessControl.RegistryAccessRule]::new(
                        $rule.IdentityReference,
                        [System.Security.AccessControl.RegistryRights]$safe,
                        $rule.InheritanceFlags,
                        $rule.PropagationFlags,
                        $rule.AccessControlType
                    )
                    $acl2.AddAccessRule($newRule)
                }
            }

            Set-Acl -LiteralPath $Path -AclObject $acl2
        } | Out-Null
}

function Get-RegDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $v = Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
        return [int]$v
    }
    catch {
        return $null
    }
}

function Set-RegDwordApproved {
    param(
        [Parameter(Mandatory)][int]$Step,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)][string]$Why
    )

    Invoke-ApprovedChange -Step $Step -Target "$Path\$Name" -Description $Why -Action {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    } | Out-Null
}

# --- prerequisite -------------------------------------------------------------

if ($Apply -and -not (Test-IsAdministrator)) {
    throw 'Apply mode requires an elevated PowerShell session.'
}

Write-Host ''
Write-Host ('Mode: ' + $(if ($Apply) { 'APPLY' } else { 'AUDIT ONLY' }))
Write-Host ''
if (-not $Apply -and $PrivateRoot.Count -eq 0) {
    Add-Finding -Step 1 -Level INFO -Target '<none>' `
        -Message 'No -PrivateRoot specified; audit mode only lists candidates.'
}


function Get-PrivateRootCandidates {
    $excludedLeafNames = @(
        # Windows-managed / system
        'Windows',
        'Program Files',
        'Program Files (x86)',
        'ProgramData',
        'Users',
        'Recovery',
        '$Recycle.Bin',
        'System Volume Information',
        'Documents and Settings',
        'PerfLogs',

        # Common application/service-managed top-level roots.
        # These should not be suggested as personal/private data roots.
        'inetpub',
        'OneDriveTemp',
        'Config.Msi',
        'MSOCache',
        'ESD',
        'Intel',
        'NVIDIA',
        'NVIDIA Corporation'
    )

    foreach ($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        $root = "$($drive.DeviceID)\"

        foreach ($item in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
            if ($excludedLeafNames -contains $item.Name) { continue }

            # Skip reparse points/junctions at the root to avoid suggesting aliases
            # into system-managed trees.
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                continue
            }

            # Skip well-known Windows installation directories even if renamed
            # or located on another fixed drive.
            $normalized = Normalize-Path $item.FullName
            $knownManaged = @(
                $(if ($env:windir) { Normalize-Path $env:windir }),
                $(if ($env:ProgramFiles) { Normalize-Path $env:ProgramFiles }),
                $(if (${env:ProgramFiles(x86)}) { Normalize-Path ${env:ProgramFiles(x86)} }),
                $(if ($env:ProgramData) { Normalize-Path $env:ProgramData }),
                $(if ($env:SystemDrive) { Normalize-Path "$env:SystemDrive\Users" })
            ) | Where-Object { $_ }

            $isManaged = $false
            foreach ($managed in $knownManaged) {
                if ($normalized.Equals($managed, [StringComparison]::OrdinalIgnoreCase)) {
                    $isManaged = $true
                    break
                }
            }
            if ($isManaged) { continue }

            [pscustomobject]@{
                Path = $item.FullName
                Drive = $drive.DeviceID
            }
        }
    }
}

# ==============================================================================
# STEP 1 - selected private roots
# ==============================================================================

foreach ($root in $PrivateRoot) {
    if ($root) {
        Set-StrictPrivateRoot -Path $root -Step 1
    }
}

if (-not $Apply) {
    $candidates = @(Get-PrivateRootCandidates)

    if ($candidates.Count -eq 0) {
        Add-Finding -Step 1 -Level INFO -Target '<none>' `
            -Message 'No obvious non-system top-level private-root candidates found.'
    }
    else {
        foreach ($candidate in $candidates) {
            $alreadySelected = $false
            foreach ($selected in $PrivateRoot) {
                if ($selected -and (Test-PathOverlap -A $candidate.Path -B $selected)) {
                    $alreadySelected = $true
                    break
                }
            }

            if (-not $alreadySelected) {
                Add-Finding -Step 1 -Level INFO -Target $candidate.Path `
                    -Message 'Candidate private root discovered. Suggestion only; review before passing via -PrivateRoot.'
            }
        }
    }
}

# ==============================================================================
# STEPS 2 + 3 - fixed-drive roots
# ==============================================================================

$fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
foreach ($drive in $fixedDrives) {
    $root = "$($drive.DeviceID)\"
    $step = if ($drive.DeviceID -ieq $env:SystemDrive) { 2 } else { 3 }
    try {
        Remove-WriteFromDriveRootPreserveChildren -Path $root -Step $step
    }
    catch {
        Add-Finding -Step $step -Level ERROR -Target $root -Message $_.Exception.Message
    }
}

# ==============================================================================
# STEP 4 - Public profile
# ==============================================================================

if ($env:PUBLIC -and (Test-Path -LiteralPath $env:PUBLIC)) {
    Protect-TreeFromBroadWrite -Root $env:PUBLIC -Step 4
}
else {
    Add-Finding -Step 4 -Level SKIPPED -Target 'C:\Users\Public' -Message 'Public profile path not found.'
}

# ==============================================================================
# STEP 5 - user profile privacy
# ==============================================================================

$profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
    -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath)
})

foreach ($profile in $profiles) {
    $leaf = Split-Path -Leaf $profile.LocalPath
    if ($leaf -ieq $AgentUser) {
        Add-Finding -Step 5 -Level SKIPPED -Target $profile.LocalPath -Message 'Configured agent profile; managed separately.'
        continue
    }

    try {
        $acl = Get-Acl -LiteralPath $profile.LocalPath
        $broad = @(Get-FileSystemRulesBySid -Acl $acl | Where-Object {
            (Test-IsBroadSid $_.IdentityReference.Value) -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            ([int]$_.FileSystemRights -ne 0)
        })
    }
    catch {
        Add-Finding -Step 5 -Level ERROR -Target $profile.LocalPath `
            -Message "Could not inspect user-profile ACL: $($_.Exception.Message)"
        continue
    }

    if ($broad.Count -eq 0) {
        Add-Finding -Step 5 -Level OK -Target $profile.LocalPath -Message 'No broad user-profile access found.'
        continue
    }

    Add-Finding -Step 5 -Level HIGH -Target $profile.LocalPath -Message 'Broad principal can access this user profile.'

    Invoke-ApprovedChange -Step 5 -Target $profile.LocalPath `
        -Description 'Remove broad access from user-profile root and preserve profile owner/SYSTEM/Administrators' `
        -Action {
            $acl2 = Get-Acl -LiteralPath $profile.LocalPath
            if (-not $acl2.AreAccessRulesProtected) {
                $acl2.SetAccessRuleProtection($true, $true)
            }

            foreach ($rule in @($acl2.GetAccessRules(
                $true,
                $true,
                [System.Security.Principal.SecurityIdentifier]
            ))) {
                if ((Test-IsBroadSid $rule.IdentityReference.Value) -and -not $rule.IsInherited) {
                    [void]$acl2.RemoveAccessRuleSpecific($rule)
                }
            }

            $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $prop = [System.Security.AccessControl.PropagationFlags]::None
            $fc = [System.Security.AccessControl.FileSystemRights]::FullControl
            $allow = [System.Security.AccessControl.AccessControlType]::Allow

            foreach ($sidText in @($profile.SID, $script:SystemSid, $script:AdministratorsSid)) {
                if (-not $sidText) { continue }
                $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid, $fc, $inherit, $prop, $allow
                )
                $acl2.AddAccessRule($rule)
            }

            Set-Acl -LiteralPath $profile.LocalPath -AclObject $acl2
        } | Out-Null
}

# ==============================================================================
# STEP 6 - machine PATH
# ==============================================================================

foreach ($entry in (Get-PathEntries -Scope Machine)) {
    try {
        Protect-PathDirectory -Path $entry -Step 6
    }
    catch {
        Add-Finding -Step 6 -Level ERROR -Target $entry -Message $_.Exception.Message
    }
}

# ==============================================================================
# STEP 7 - privileged services + scheduled tasks
# ==============================================================================

$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
foreach ($service in $services) {
    $source = "Service:$($service.Name)"

    if (Test-UnquotedServicePath -CommandLine $service.PathName) {
        Add-Finding -Step 7 -Level HIGH -Target $source `
            -Message "Unquoted service executable path contains spaces: $($service.PathName)"
    }

    foreach ($path in (Get-ReferencedPathsFromCommandLine -CommandLine $service.PathName)) {
        Protect-ExecutionPath -Path $path -Step 7 -Source $source
    }
}

try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($task in $tasks) {
        $isPrivileged = $false
        if ($task.Principal.RunLevel -eq 'Highest') { $isPrivileged = $true }

        $uid = [string]$task.Principal.UserId
        if ($uid -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|NT AUTHORITY\\SYSTEM)$') {
            $isPrivileged = $true
        }

        if (-not $isPrivileged) { continue }

        foreach ($action in @($task.Actions)) {
            if (-not $action.Execute) { continue }
            $source = "Task:$($task.TaskPath)$($task.TaskName)"
            $command = ('"{0}" {1}' -f $action.Execute, $action.Arguments)
            foreach ($path in (Get-ReferencedPathsFromCommandLine -CommandLine $command)) {
                Protect-ExecutionPath -Path $path -Step 7 -Source $source
            }
        }
    }
}
catch {
    Add-Finding -Step 7 -Level WARN -Target 'Scheduled Tasks' -Message "Could not enumerate tasks: $($_.Exception.Message)"
}

# ==============================================================================
# STEP 8 - current-user PATH
# ==============================================================================

foreach ($entry in (Get-PathEntries -Scope User)) {
    try {
        Protect-PathDirectory -Path $entry -Step 8 -PreserveCurrentUserModify
    }
    catch {
        Add-Finding -Step 8 -Level ERROR -Target $entry -Message $_.Exception.Message
    }
}

# ==============================================================================
# STEP 9 - common auto-execution locations
# ==============================================================================

$commonExecutionRoots = @(
    [Environment]::GetFolderPath('CommonStartup'),
    [Environment]::GetFolderPath('CommonPrograms')
) | Where-Object { $_ } | Select-Object -Unique

foreach ($root in $commonExecutionRoots) {
    try {
        Protect-TreeFromBroadWrite -Root $root -Step 9
    }
    catch {
        Add-Finding -Step 9 -Level ERROR -Target $root -Message $_.Exception.Message
    }
}

# ==============================================================================
# STEP 10 - HKLM execution/configuration ACLs
# ==============================================================================

$registryRoots = @(
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
)

foreach ($key in $registryRoots) {
    try {
        Protect-RegistryKey -Path $key -Step 10

        # For these container keys, inspect direct children too. This catches
        # service/app-specific ACL deviations without recursively rewriting HKLM.
        if ($key -match '(App Paths|Image File Execution Options|CurrentControlSet\\Services)$' -and
            (Test-Path -LiteralPath $key)) {
            foreach ($child in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
                Protect-RegistryKey -Path $child.PSPath -Step 10
            }
        }
    }
    catch {
        Add-Finding -Step 10 -Level ERROR -Target $key -Message $_.Exception.Message
    }
}

# ==============================================================================
# STEP 11 - UAC security-critical settings
# ==============================================================================

$uacKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

$enableLUA = Get-RegDword -Path $uacKey -Name 'EnableLUA'
if ($enableLUA -ne 1) {
    Add-Finding -Step 11 -Level HIGH -Target 'EnableLUA' -Message "Expected 1; found '$enableLUA'."
    Set-RegDwordApproved -Step 11 -Path $uacKey -Name 'EnableLUA' -Value 1 -Why 'Enable UAC / Admin Approval Mode'
}
else {
    Add-Finding -Step 11 -Level OK -Target 'EnableLUA' -Message 'UAC is enabled.'
}

$secureDesktop = Get-RegDword -Path $uacKey -Name 'PromptOnSecureDesktop'
if ($secureDesktop -ne 1) {
    Add-Finding -Step 11 -Level WARN -Target 'PromptOnSecureDesktop' -Message "Expected 1; found '$secureDesktop'."
    Set-RegDwordApproved -Step 11 -Path $uacKey -Name 'PromptOnSecureDesktop' -Value 1 -Why 'Use secure desktop for UAC prompts'
}
else {
    Add-Finding -Step 11 -Level OK -Target 'PromptOnSecureDesktop' -Message 'Secure desktop is enabled for UAC prompts.'
}

$adminPrompt = Get-RegDword -Path $uacKey -Name 'ConsentPromptBehaviorAdmin'
if ($adminPrompt -eq 0) {
    Add-Finding -Step 11 -Level HIGH -Target 'ConsentPromptBehaviorAdmin' -Message 'Administrators are elevated without prompting.'
    Set-RegDwordApproved -Step 11 -Path $uacKey -Name 'ConsentPromptBehaviorAdmin' -Value 5 `
        -Why 'Restore default prompt-for-consent behavior for non-Windows binaries'
}
else {
    Add-Finding -Step 11 -Level OK -Target 'ConsentPromptBehaviorAdmin' `
        -Message "No silent admin elevation detected (value=$adminPrompt)."
}

$secureUIA = Get-RegDword -Path $uacKey -Name 'EnableSecureUIAPaths'
if ($secureUIA -eq 0) {
    Add-Finding -Step 11 -Level WARN -Target 'EnableSecureUIAPaths' -Message 'UIAccess apps may elevate from insecure locations.'
    Set-RegDwordApproved -Step 11 -Path $uacKey -Name 'EnableSecureUIAPaths' -Value 1 `
        -Why 'Restrict UIAccess elevation to secure locations'
}
else {
    Add-Finding -Step 11 -Level OK -Target 'EnableSecureUIAPaths' -Message 'UIAccess secure-location restriction is enabled/default.'
}

# ==============================================================================
# STEP 12 - dangerous elevation shortcuts
# ==============================================================================

$aieLocations = @(
    @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'; Scope='Machine' },
    @{ Path='Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer'; Scope='Current user' }
)

foreach ($loc in $aieLocations) {
    $value = Get-RegDword -Path $loc.Path -Name 'AlwaysInstallElevated'
    if ($value -eq 1) {
        Add-Finding -Step 12 -Level HIGH -Target "$($loc.Scope) AlwaysInstallElevated" -Message 'Enabled.'
        Set-RegDwordApproved -Step 12 -Path $loc.Path -Name 'AlwaysInstallElevated' -Value 0 `
            -Why 'Disable AlwaysInstallElevated'
    }
    else {
        Add-Finding -Step 12 -Level OK -Target "$($loc.Scope) AlwaysInstallElevated" `
            -Message 'Disabled or not configured.'
    }
}

$winlogon = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$autoAdmin = $null
$defaultPassword = $null
try { $autoAdmin = Get-ItemPropertyValue -LiteralPath $winlogon -Name 'AutoAdminLogon' -ErrorAction Stop } catch {}
try { $defaultPassword = Get-ItemPropertyValue -LiteralPath $winlogon -Name 'DefaultPassword' -ErrorAction Stop } catch {}

if ($autoAdmin -eq '1' -or $defaultPassword) {
    Add-Finding -Step 12 -Level HIGH -Target 'AutoAdminLogon' -Message 'Automatic logon and/or stored DefaultPassword detected.'

    Invoke-ApprovedChange -Step 12 -Target 'AutoAdminLogon' `
        -Description 'Disable AutoAdminLogon and remove stored DefaultPassword' `
        -Action {
            New-ItemProperty -LiteralPath $winlogon -Name 'AutoAdminLogon' -PropertyType String -Value '0' -Force | Out-Null
            Remove-ItemProperty -LiteralPath $winlogon -Name 'DefaultPassword' -ErrorAction SilentlyContinue
        } | Out-Null
}
else {
    Add-Finding -Step 12 -Level OK -Target 'AutoAdminLogon' -Message 'No stored automatic-logon password detected.'
}

# ==============================================================================
# STEP 13 - Microsoft Defender
# ==============================================================================

try {
    $mp = Get-MpPreference -ErrorAction Stop

    $defenderChecks = @(
        @{ Name='Real-time monitoring'; Property='DisableRealtimeMonitoring'; Setter={ Set-MpPreference -DisableRealtimeMonitoring $false } },
        @{ Name='Behavior monitoring';  Property='DisableBehaviorMonitoring'; Setter={ Set-MpPreference -DisableBehaviorMonitoring $false } },
        @{ Name='Script scanning';       Property='DisableScriptScanning'; Setter={ Set-MpPreference -DisableScriptScanning $false } }
    )

    foreach ($check in $defenderChecks) {
        $disabled = [bool]$mp.($check.Property)
        if ($disabled) {
            Add-Finding -Step 13 -Level HIGH -Target $check.Name -Message 'Disabled.'
            Invoke-ApprovedChange -Step 13 -Target $check.Name -Description 'Re-enable Microsoft Defender protection' -Action $check.Setter | Out-Null
        }
        else {
            Add-Finding -Step 13 -Level OK -Target $check.Name -Message 'Enabled.'
        }
    }

    foreach ($exclusion in @($mp.ExclusionPath)) {
        if (-not $exclusion) { continue }

        $level = 'WARN'
        $reason = 'Defender path exclusion configured.'

        $expanded = [Environment]::ExpandEnvironmentVariables([string]$exclusion)
        if ($expanded -match '^[A-Za-z]:\\?$') {
            $level = 'HIGH'
            $reason = 'Entire drive is excluded from Defender.'
        }
        elseif ($expanded -match '(?i)\\(dev|src|source|repos?|workspace|workspaces)\\?$') {
            $level = 'HIGH'
            $reason = 'Broad development root is excluded from Defender.'
        }

        foreach ($agentRoot in $AgentWritableRoot) {
            if ($agentRoot -and (Test-PathOverlap -A $expanded -B $agentRoot)) {
                $level = 'HIGH'
                $reason = "Defender exclusion overlaps agent-writable root '$agentRoot'."
                break
            }
        }

        Add-Finding -Step 13 -Level $level -Target $exclusion -Message "$reason REPORT-ONLY."
    }

    foreach ($exclusion in @($mp.ExclusionProcess)) {
        if ($exclusion) {
            Add-Finding -Step 13 -Level WARN -Target $exclusion -Message 'Defender process exclusion configured. REPORT-ONLY.'
        }
    }

    foreach ($exclusion in @($mp.ExclusionExtension)) {
        if ($exclusion) {
            Add-Finding -Step 13 -Level WARN -Target "*.$exclusion" -Message 'Defender extension exclusion configured. REPORT-ONLY.'
        }
    }
}
catch {
    Add-Finding -Step 13 -Level WARN -Target 'Microsoft Defender' `
        -Message "Defender PowerShell interface unavailable or blocked: $($_.Exception.Message)"
}

# ==============================================================================
# STEP 14 - LSA protection + Credential Guard/VBS status (REPORT ONLY)
# ==============================================================================

$lsaKey = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
$runAsPpl = Get-RegDword -Path $lsaKey -Name 'RunAsPPL'

switch ($runAsPpl) {
    1 { Add-Finding -Step 14 -Level OK -Target 'LSA protection' -Message 'RunAsPPL=1 (explicitly configured with UEFI lock semantics where supported).' }
    2 { Add-Finding -Step 14 -Level OK -Target 'LSA protection' -Message 'RunAsPPL=2 (explicitly configured without UEFI lock).' }
    default {
        Add-Finding -Step 14 -Level INFO -Target 'LSA protection' `
            -Message "RunAsPPL is not explicitly configured (value='$runAsPpl'). Windows may still enable LSA protection automatically. REPORT-ONLY."
    }
}

try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName 'Win32_DeviceGuard' -ErrorAction Stop

    $vbsText = switch ([int]$dg.VirtualizationBasedSecurityStatus) {
        0 { 'disabled' }
        1 { 'enabled but not running' }
        2 { 'enabled and running' }
        default { "unknown ($($dg.VirtualizationBasedSecurityStatus))" }
    }

    $cgRunning = @($dg.SecurityServicesRunning) -contains 1
    Add-Finding -Step 14 -Level $(if ($cgRunning) { 'OK' } else { 'INFO' }) `
        -Target 'Credential Guard' `
        -Message "Credential Guard running=$cgRunning; VBS=$vbsText. REPORT-ONLY."
}
catch {
    Add-Finding -Step 14 -Level INFO -Target 'Credential Guard' `
        -Message "Could not query Win32_DeviceGuard: $($_.Exception.Message). REPORT-ONLY."
}

# --- summary ------------------------------------------------------------------

Write-Host ''
Write-Host 'Summary'
Write-Host '-------'

$summary = $script:Findings |
    Group-Object Level |
    Sort-Object Name |
    ForEach-Object {
        [pscustomobject]@{ Level = $_.Name; Count = $_.Count }
    }

$summary | Format-Table -AutoSize

$high = @($script:Findings | Where-Object { $_.Level -eq 'HIGH' }).Count
$errors = @($script:Findings | Where-Object { $_.Level -eq 'ERROR' }).Count

if (-not $Apply) {
    Write-Host ''
    Write-Host 'Audit only: rerun with -Apply to perform the approved remediations.'
}

Write-Host ''
Write-Host "High-risk findings: $high"
Write-Host "Errors:            $errors"

# Return displayed findings to the pipeline for optional export/filtering.
$script:Findings | Where-Object { $_.Level -ne 'OK' -or $VerbosePreference -eq 'Continue' }
