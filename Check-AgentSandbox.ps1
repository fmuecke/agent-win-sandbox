# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

<#
.SYNOPSIS
    Verifies an agent-win-sandbox installation: user, hardening, ACLs, policy,
    toolchain, and the assumptions the boundary depends on. Read-only - makes no
    changes. Safe to run anytime, including as a post-launch diagnostic.

.PARAMETER UserName
    Low-privilege sandbox user. Default: AgentSandbox.

.PARAMETER ShellInitScript
    Shell initializer written by Setup-AgentSandbox.ps1.

.PARAMETER DevShellScript
    Developer Shell command written by Setup-AgentSandbox.ps1.

.PARAMETER ClaudeWrapperScript
    Claude Code command wrapper written by Setup-AgentSandbox.ps1.

.PARAMETER CopilotWrapperScript
    GitHub Copilot CLI command wrapper written by Setup-AgentSandbox.ps1.

.PARAMETER LauncherScript
    Installed launcher written by Setup-AgentSandbox.ps1.

.PARAMETER LaunchAsExe
    launch-as executable downloaded by Setup-AgentSandbox.ps1.

.PARAMETER InstalledCheckScript
    Installed checker written by Setup-AgentSandbox.ps1.

.PARAMETER ManagedSettings
    Claude Code enterprise policy file.

.PARAMETER ManagedSettingsRegistryPath
    Machine-wide Claude Code policy registry key.

.PARAMETER ConfigFile
    agent-win-sandbox ProgramData config file.

.EXAMPLE
    & "$env:ProgramData\agent-win-sandbox\Check-AgentSandbox.ps1"
    Runs all checks and prints a PASS/WARN/FAIL summary.

.NOTES
    Exit code 0 if no FAILs, 1 if any FAIL. WARN does not fail the run.
    Some checks need elevation to read fully (e.g. user-rights, HKLM, other
    users' profiles); run elevated for complete results - the script notes where
    it's degraded.
#>

[CmdletBinding()]
param(
    [string]$UserName = 'AgentSandbox',
    [string]$ShellInitScript = (Join-Path (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'bootstrap') 'Initialize-AgentSandboxShell.ps1'),
    [string]$DevShellScript = (Join-Path (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'bootstrap') 'Enter-DevShell.ps1'),
    [string]$ClaudeWrapperScript = (Join-Path (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'bootstrap') 'claude-wrapper.ps1'),
    [string]$CopilotWrapperScript = (Join-Path (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'bootstrap') 'copilot-wrapper.ps1'),
    [string]$LauncherScript = (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'Start-AgentSandbox.ps1'),
    [string]$LaunchAsExe = (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'launch-as.exe'),
    [string]$InstalledCheckScript = (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'Check-AgentSandbox.ps1'),
    [string]$ManagedSettings = (Join-Path (Join-Path $env:ProgramFiles 'ClaudeCode') 'managed-settings.json'),
    [string]$ManagedSettingsRegistryPath = 'HKLM:\SOFTWARE\Policies\ClaudeCode',
    [string]$ManagedSettingsRegistryValue = 'Settings',
    [string]$ConfigFile = (Join-Path (Join-Path $env:ProgramData 'agent-win-sandbox') 'config.json')
)

$Version = '0.6.0'
$FirewallMode = 'BlockWindowsLanProtocols'
$BuiltinAdministratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$BuiltinUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$LocalSystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$TrustedInstallerSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$EveryoneSid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$AuthenticatedUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
$RemoteDesktopUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-555')
$BackupOperatorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-551')
$PowerUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-547')
$AdminWriteSidValues = @($BuiltinAdministratorsSid.Value, $LocalSystemSid.Value, $TrustedInstallerSid.Value)
$BroadReadSidValues = @($BuiltinUsersSid.Value, $EveryoneSid.Value, $AuthenticatedUsersSid.Value)
$RiskyGroupChecks = @(
    [pscustomobject]@{ Description = 'Remote Desktop Users'; Sid = $RemoteDesktopUsersSid },
    [pscustomobject]@{ Description = 'Backup Operators'; Sid = $BackupOperatorsSid },
    [pscustomobject]@{ Description = 'Power Users'; Sid = $PowerUsersSid }
)
$FirewallRules = @(
    [pscustomobject]@{
        Name        = 'agent_win_sandbox_block_smb_netbios_tcp'
        DisplayName = 'Agent Sandbox - Block SMB and NetBIOS TCP'
        Protocol    = 'TCP'
        RemotePort  = @('139', '445')
    },
    [pscustomobject]@{
        Name        = 'agent_win_sandbox_block_netbios_udp'
        DisplayName = 'Agent Sandbox - Block NetBIOS UDP'
        Protocol    = 'UDP'
        RemotePort  = @('137', '138')
    },
    [pscustomobject]@{
        Name        = 'agent_win_sandbox_block_remote_admin_tcp'
        DisplayName = 'Agent Sandbox - Block remote admin TCP'
        Protocol    = 'TCP'
        RemotePort  = @('135', '3389', '5985', '5986')
    }
)

$script:fails = 0
$script:warns = 0

function Pass { param($m) Write-Host "  [PASS] $m" -ForegroundColor Green }
function Info { param($m) Write-Host "  [INFO] $m" -ForegroundColor DarkGray }
function Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:warns++ }
function Fail { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:fails++ }
function Section { param($m) Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Get-IdentitySidValue {
    param([Security.Principal.IdentityReference]$Identity)

    try {
        if ($Identity -is [Security.Principal.SecurityIdentifier]) {
            return $Identity.Value
        }
        return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $null
    }
}
function Test-IdentitySidIn {
    param(
        [Security.Principal.IdentityReference]$Identity,
        [string[]]$SidValues
    )

    $sidValue = Get-IdentitySidValue -Identity $Identity
    return $sidValue -and ($sidValue -in $SidValues)
}
function Get-NonAdminWritableAce {
    param(
        [System.Security.AccessControl.FileSystemSecurity]$Acl,
        [string]$UserName
    )
    $Acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.PropagationFlags -notmatch 'InheritOnly' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl|Delete|ChangePermissions|TakeOwnership' -and
        -not (Test-IdentitySidIn -Identity $_.IdentityReference -SidValues $AdminWriteSidValues)
    }
}
function Test-AdminWriteOnlyPath {
    param(
        [string]$Path,
        [string]$Description,
        [string]$UserName
    )
    if (-not (Test-Path $Path)) {
        Fail "$Description missing: $Path"
        return
    }

    $acl = Get-Acl $Path
    $writable = Get-NonAdminWritableAce -Acl $acl -UserName $UserName
    if ($writable) {
        $principals = ($writable.IdentityReference | Sort-Object -Unique) -join ', '
        Fail "$Description is writable by non-admin principals: $principals"
    }
    else {
        Pass "$Description is admin-write-only."
    }
}
function Test-ManagedPolicyContent {
    param(
        [string]$Description,
        [string]$JsonText
    )

    try {
        $json = $JsonText | ConvertFrom-Json
        if ($json.permissions.disableBypassPermissionsMode -eq 'disable') {
            Pass "$Description disables bypass-permissions mode."
        }
        else {
            Warn "$Description does NOT disable bypass-permissions mode."
        }
        if ($json.permissions.deny) {
            Pass "$Description has deny rules ($($json.permissions.deny.Count) entries)."
        }
        else {
            Warn "$Description has no deny rules."
        }
        if ($json.allowedMcpServers -is [array] -and $json.allowedMcpServers.Count -eq 0 -and
            $json.allowManagedMcpServersOnly -eq $true) {
            Pass "$Description locks MCP servers to an empty managed allowlist."
        }
        else {
            Warn "$Description does not lock MCP servers to an empty managed allowlist."
        }
    }
    catch {
        Fail "$Description is not valid JSON: $($_.Exception.Message)"
    }
}
function Test-ConfigSetupField {
    param(
        [object]$Setup,
        [string]$Field,
        [string]$Expected,
        [string]$Description
    )
    $property = $Setup.PSObject.Properties[$Field]
    if (-not $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        Fail "$Description missing in config setup section."
        return
    }
    if ([string]$property.Value -ine $Expected) {
        Fail "$Description drift: config '$($property.Value)', expected '$Expected'."
    }
    else {
        Pass "$Description matches config setup section."
    }
}
function Test-ConfigSetupRequiredField {
    param(
        [object]$Setup,
        [string]$Field,
        [string]$Description
    )
    $property = $Setup.PSObject.Properties[$Field]
    if (-not $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        Fail "$Description missing in config setup section."
    }
    else {
        Pass "$Description is present in config setup section."
    }
}
function Test-ConfigSetupStringList {
    param(
        [object]$Setup,
        [string]$Field,
        [string[]]$Expected,
        [string]$Description
    )
    $property = $Setup.PSObject.Properties[$Field]
    if (-not $property) {
        Fail "$Description missing in config setup section."
        return
    }

    $actual = @($property.Value) | ForEach-Object { [string]$_ } | Sort-Object
    $expectedSorted = @($Expected) | ForEach-Object { [string]$_ } | Sort-Object
    $delta = Compare-Object -ReferenceObject $expectedSorted -DifferenceObject $actual
    if ($delta) {
        Fail "$Description drift: config '$($actual -join ', ')', expected '$($expectedSorted -join ', ')'."
    }
    else {
        Pass "$Description matches config setup section."
    }
}
function Expand-FirewallValues {
    param([object[]]$Values)
    $expanded = @()
    foreach ($value in @($Values)) {
        if ($null -eq $value) { continue }
        $expanded += ([string]$value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    return $expanded
}
function Test-StringSetEquals {
    param(
        [string[]]$Actual,
        [string[]]$Expected
    )
    $actualSorted = @($Actual) | ForEach-Object { [string]$_ } | Sort-Object
    $expectedSorted = @($Expected) | ForEach-Object { [string]$_ } | Sort-Object
    return -not (Compare-Object -ReferenceObject $expectedSorted -DifferenceObject $actualSorted)
}
function Test-LocalFirewallPolicyApplies {
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        if ($policy.LocalPolicyModifyState -eq 0) {
            Pass "Local firewall policy changes apply on active profiles."
        }
        else {
            Fail "Local firewall policy changes may not apply: LocalPolicyModifyState=$($policy.LocalPolicyModifyState)."
        }
    }
    catch {
        Fail "Could not verify local firewall policy state: $($_.Exception.Message)"
    }
}
function Test-SandboxFirewallRule {
    param(
        [pscustomobject]$RuleSpec,
        [string]$SandboxSid
    )

    $ok = $true
    $rule = Get-NetFirewallRule -Name $RuleSpec.Name -ErrorAction SilentlyContinue
    if (-not $rule) {
        Fail "Firewall rule missing: $($RuleSpec.Name). Run setup."
        return
    }

    if ($rule.Enabled -ine 'True') {
        Fail "Firewall rule '$($RuleSpec.Name)' is not enabled."
        $ok = $false
    }
    if ($rule.Direction -ine 'Outbound') {
        Fail "Firewall rule '$($RuleSpec.Name)' is not outbound."
        $ok = $false
    }
    if ($rule.Action -ine 'Block') {
        Fail "Firewall rule '$($RuleSpec.Name)' is not a block rule."
        $ok = $false
    }

    try {
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
        if ($portFilter.Protocol -ine $RuleSpec.Protocol) {
            Fail "Firewall rule '$($RuleSpec.Name)' protocol drift: '$($portFilter.Protocol)', expected '$($RuleSpec.Protocol)'."
            $ok = $false
        }

        $actualPorts = Expand-FirewallValues -Values $portFilter.RemotePort
        if (-not (Test-StringSetEquals -Actual $actualPorts -Expected $RuleSpec.RemotePort)) {
            Fail "Firewall rule '$($RuleSpec.Name)' remote ports drift: '$($actualPorts -join ', ')', expected '$($RuleSpec.RemotePort -join ', ')'."
            $ok = $false
        }
    }
    catch {
        Fail "Could not read port filter for firewall rule '$($RuleSpec.Name)': $($_.Exception.Message)"
        $ok = $false
    }

    try {
        $securityFilter = Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule
        $localUser = [string]$securityFilter.LocalUser
        if ([string]::IsNullOrWhiteSpace($localUser) -or ($localUser -notlike "*$SandboxSid*")) {
            Fail "Firewall rule '$($RuleSpec.Name)' is not scoped to $SandboxSid."
            $ok = $false
        }
    }
    catch {
        Fail "Could not read security filter for firewall rule '$($RuleSpec.Name)': $($_.Exception.Message)"
        $ok = $false
    }

    if ($ok) {
        Pass "Firewall rule '$($RuleSpec.Name)' blocks $($RuleSpec.Protocol) ports $($RuleSpec.RemotePort -join ', ') for '$UserName'."
    }
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Note: not elevated - some checks (user-rights, HKLM, other profiles) may be limited." -ForegroundColor DarkYellow
}

# --- 0. ProgramData config ----------------------------------------------------
Section "Sandbox configuration"
$SandboxPath = $null
if (-not (Test-Path $ConfigFile)) {
    Fail "Config missing: $ConfigFile - run setup."
    Section "Summary"
    Write-Host "  $script:fails FAIL, $script:warns WARN." -ForegroundColor Red
    exit 1
}
else {
    Pass "Config present: $ConfigFile"
    try {
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        $SandboxPath = $config.sandboxPath
        if ([string]::IsNullOrWhiteSpace($SandboxPath)) {
            Fail "Config does not define sandboxPath."
        }
        elseif ((Split-Path $SandboxPath -Leaf) -ne 'AgentSandbox') {
            Fail "sandboxPath must end in the fixed directory name 'AgentSandbox': $SandboxPath"
        }
        else {
            Pass "Configured sandbox path: $SandboxPath"
        }

        $setupProperty = $config.PSObject.Properties['setup']
        $setup = if ($setupProperty) { $setupProperty.Value } else { $null }
        if (-not $setup) {
            Fail 'Config does not define setup metadata. Run setup with the current script.'
        }
        else {
            $versionProperty = $setup.PSObject.Properties['version']
            if ($versionProperty -and -not [string]::IsNullOrWhiteSpace([string]$versionProperty.Value)) {
                Info "Installed version: $($versionProperty.Value). Current checker version: $Version."
            }
            else {
                Info "Installed version metadata is not present. Current checker version: $Version."
            }
            Test-ConfigSetupRequiredField -Setup $setup -Field 'createdAtUtc' -Description 'Setup timestamp'
            Test-ConfigSetupField -Setup $setup -Field 'userName' -Expected $UserName -Description 'Sandbox user'
            Test-ConfigSetupRequiredField -Setup $setup -Field 'installedByUser' -Description 'Installing user'
            Test-ConfigSetupField -Setup $setup -Field 'firewallMode' -Expected $FirewallMode -Description 'Firewall mode'
            Test-ConfigSetupStringList -Setup $setup -Field 'firewallRuleNames' -Expected @($FirewallRules | ForEach-Object { $_.Name }) -Description 'Firewall rule names'
            Test-ConfigSetupField -Setup $setup -Field 'launchAsVersion' -Expected 'v0.3.2' -Description 'launch-as version'
        }
    }
    catch {
        Fail "Config file is not valid JSON: $($_.Exception.Message)"
    }

    $programDataRoot = Split-Path $ConfigFile -Parent
    Test-AdminWriteOnlyPath -Path $programDataRoot -Description 'ProgramData sandbox directory' -UserName $UserName
    Test-AdminWriteOnlyPath -Path $ConfigFile -Description 'Sandbox config file' -UserName $UserName

    if ([string]::IsNullOrWhiteSpace($SandboxPath) -or ((Split-Path $SandboxPath -Leaf) -ne 'AgentSandbox')) {
        Section "Summary"
        Write-Host "  $script:fails FAIL, $script:warns WARN." -ForegroundColor Red
        exit 1
    }

}

# --- 1. User exists and is not admin -----------------------------------------
Section "User account"
$u = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $u) {
    Fail "User '$UserName' does not exist. Run Setup-AgentSandbox.ps1."
    # Nothing else is meaningful without the user; print summary and exit.
    Write-Host "`nAborting remaining checks." -ForegroundColor Red
    exit 1
}
Pass "User '$UserName' exists."

if (-not $u.Enabled) { Warn "Account is disabled - launcher won't work until enabled." }
else { Pass "Account is enabled." }

$adminMembers = Get-LocalGroupMember -SID $BuiltinAdministratorsSid -ErrorAction SilentlyContinue
if ($adminMembers | Where-Object { $_.SID -and ($_.SID.Value -eq $u.SID.Value) }) { Fail "'$UserName' is in Administrators - should be Standard only." }
else { Pass "Not a member of Administrators." }

$riskyGroups = foreach ($groupCheck in $RiskyGroupChecks) {
    $members = Get-LocalGroupMember -SID $groupCheck.Sid -ErrorAction SilentlyContinue
    if ($members | Where-Object { $_.SID -and ($_.SID.Value -eq $u.SID.Value) }) {
        $groupCheck.Description
    }
}
if ($riskyGroups) { Warn "Member of elevated/remote groups: $($riskyGroups -join ', ')" }
else { Pass "No risky group memberships." }

# --- 2. Account hardening -----------------------------------------------------
Section "Account hardening"
if ($u.PasswordExpires) { Warn "Password is set to expire - may break launcher unexpectedly." }
else { Pass "Password never expires." }

if ($u.UserMayChangePassword) { Warn "User may change own password (no self-service needed)." }
else { Pass "User cannot change own password." }

# Deny network + RDP logon rights (read via secedit export; needs elevation).
if ($isAdmin) {
    try {
        $sid = $u.SID.Value
        $tmp = Join-Path $env:TEMP "agent_win_sandbox_check_secpol.inf"
        secedit /export /cfg $tmp /areas USER_RIGHTS /quiet | Out-Null
        $pol = Get-Content $tmp
        Remove-Item $tmp -ErrorAction SilentlyContinue

        # secedit may record the account as *SID or by bare name - match either.
        $sidForm = [regex]::Escape("*$sid")
        $nameForm = "(^|[=,\s])$([regex]::Escape($UserName))([,\s]|$)"
        function Test-RightIncludesAccount {
            param([string]$Line, [string]$SidPattern, [string]$NamePattern)
            if (-not $Line) { return $false }
            $val = ($Line -split '=', 2)[1]
            return ($val -match $SidPattern) -or ($val -match $NamePattern)
        }

        foreach ($right in 'SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
            $line = $pol | Where-Object { $_ -match "^$right\s*=" }
            if (Test-RightIncludesAccount -Line $line -SidPattern $sidForm -NamePattern $nameForm) {
                Pass "$right includes the account."
            }
            else {
                Warn "$right does NOT include the account (run setup to apply)."
            }
        }
        # Sanity: interactive must NOT be denied, or the launcher breaks.
        $denyInteractive = $pol | Where-Object { $_ -match '^SeDenyInteractiveLogonRight\s*=' }
        if (Test-RightIncludesAccount -Line $denyInteractive -SidPattern $sidForm -NamePattern $nameForm) {
            Fail "Interactive logon is DENIED for the account - the launcher will not work."
        }
        else {
            Pass "Interactive logon is allowed (required by the launcher)."
        }
    }
    catch {
        Warn "Could not read user-rights policy: $($_.Exception.Message)"
    }
}
else {
    Warn "Skipped logon-rights checks (need elevation)."
}

# Hidden from login screen
$ualPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$hidden = (Get-ItemProperty -Path $ualPath -Name $UserName -ErrorAction SilentlyContinue).$UserName
if ($hidden -eq 0) { Pass "Hidden from the login screen." }
else { Warn "Not hidden from the login screen (cosmetic)." }

# --- 3. Outbound firewall -----------------------------------------------------
Section "Outbound firewall"
Test-LocalFirewallPolicyApplies
foreach ($ruleSpec in $FirewallRules) {
    Test-SandboxFirewallRule -RuleSpec $ruleSpec -SandboxSid $u.SID.Value
}
Write-Host "  [INFO] Firewall mode preserves normal web/HTTPS egress; it is not full egress isolation." -ForegroundColor DarkGray

# --- 4. Workspace ACLs --------------------------------------------------------
Section "Workspace permissions"
if (-not (Test-Path $SandboxPath)) {
    Fail "Sandbox path does not exist: $SandboxPath"
}
else {
    $acl = Get-Acl $SandboxPath
    $userAce = $acl.Access | Where-Object { (Get-IdentitySidValue -Identity $_.IdentityReference) -eq $u.SID.Value }
    if ($userAce | Where-Object { $_.FileSystemRights -match 'Modify|FullControl|Write' }) {
        Pass "'$UserName' has write access to the workspace (and sub-repos, via inheritance)."
    }
    else {
        Fail "'$UserName' lacks write access to the workspace - Claude can't edit code."
    }
}

# --- 5. Caller profile not world-readable ------------------------------------
Section "Your profile is not exposed"
$callingProfile = $env:USERPROFILE
$acl = Get-Acl $callingProfile
$risky = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.FileSystemRights -match 'Read|FullControl|Modify' -and
    (Test-IdentitySidIn -Identity $_.IdentityReference -SidValues $BroadReadSidValues)
}
if ($risky) {
    Fail "Your profile grants broad read access: $(($risky.IdentityReference | Sort-Object -Unique) -join ', '). Fix the profile ACL."
}
else {
    Pass "Profile not readable by Users/Everyone - '$UserName' is denied by default."
}

# --- 6. Installed scripts + tooling ------------------------------------------
Section "Installed scripts & toolchain"
$programDataRoot = Split-Path $ConfigFile -Parent
Test-AdminWriteOnlyPath -Path $programDataRoot -Description 'ProgramData sandbox directory' -UserName $UserName

if (Test-Path $LauncherScript) {
    Pass "Launcher present: $LauncherScript"
    Test-AdminWriteOnlyPath -Path $LauncherScript -Description 'Launcher script' -UserName $UserName
}
else {
    Fail "Launcher missing: $LauncherScript - run setup."
}

if (Test-Path $LaunchAsExe) {
    Pass "launch-as present: $LaunchAsExe"
    Test-AdminWriteOnlyPath -Path $LaunchAsExe -Description 'launch-as executable' -UserName $UserName
}
else {
    Fail "launch-as missing: $LaunchAsExe - run setup."
}

if (Test-Path $InstalledCheckScript) {
    Pass "Installed checker present: $InstalledCheckScript"
    Test-AdminWriteOnlyPath -Path $InstalledCheckScript -Description 'Installed checker script' -UserName $UserName
}
else {
    Fail "Installed checker missing: $InstalledCheckScript - run setup."
}

$bootstrapDir = Split-Path $ShellInitScript -Parent
Test-AdminWriteOnlyPath -Path $bootstrapDir -Description 'Bootstrap directory' -UserName $UserName
foreach ($scriptArtifact in @(
        [pscustomobject]@{ Description = 'Shell initializer'; Path = $ShellInitScript },
        [pscustomobject]@{ Description = 'Developer Shell command'; Path = $DevShellScript },
        [pscustomobject]@{ Description = 'Claude command wrapper'; Path = $ClaudeWrapperScript },
        [pscustomobject]@{ Description = 'Copilot command wrapper'; Path = $CopilotWrapperScript }
    )) {
    if (Test-Path $scriptArtifact.Path) {
        Pass "$($scriptArtifact.Description) present: $($scriptArtifact.Path)"
        Test-AdminWriteOnlyPath -Path $scriptArtifact.Path -Description $scriptArtifact.Description -UserName $UserName
    }
    else {
        Fail "$($scriptArtifact.Description) missing: $($scriptArtifact.Path) - run setup."
    }
}

$pwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
if (Test-Path $pwshExe -PathType Leaf) { Pass "PowerShell 7 found: $pwshExe" }
else { Fail "PowerShell 7 not found at $pwshExe." }

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath 2>$null
    if ($vsPath -and (Test-Path (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'))) {
        Pass "VS Developer Shell found: $vsPath"
    }
    else { Warn "VS found but DevShell module missing." }
}
else { Warn "vswhere not found - is Visual Studio installed machine-wide?" }

if (Get-Command git.exe -ErrorAction SilentlyContinue) { Pass "git on machine PATH." }
else { Warn "git not on machine PATH." }

# --- 7. Claude Code install location -----------------------------------------
# The boundary depends on AgentSandbox running ITS OWN per-user copy, not one
# from your profile or a machine-wide install: either of those could be picked
# up off the machine PATH, pulling binary/config from outside the sandbox.
Section "Claude Code install"
$expected = "C:\Users\$UserName\.local\bin\claude.exe"
$expectedCheckFailed = $false
try {
    $expectedExists = Test-Path -LiteralPath $expected -ErrorAction Stop
}
catch {
    $expectedExists = $false
    $expectedCheckFailed = $true
    Warn "Could not verify per-user Claude for ${UserName}: $expected ($($_.Exception.Message))"
}
if ($expectedExists) { Pass "Claude Code installed for ${UserName}: $expected" }
elseif (-not $expectedCheckFailed) { Warn "No per-user Claude for $UserName at $expected - run 'claude' inside Agent Sandbox." }

# Flag installs OUTSIDE the sandbox user that could leak in via machine PATH.
$leaks = @()

# Other user profiles (needs elevation to traverse other users' dirs).
if ($isAdmin) {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne $UserName } |
    ForEach-Object {
        $p = Join-Path $_.FullName '.local\bin\claude.exe'
        if (Test-Path $p) { $leaks += $p }
    }
}
else {
    Warn "Skipped other-profile scan (need elevation) - may under-report leaks."
}

# Machine-wide / common locations.
foreach ($m in @(
        "$env:ProgramFiles\Claude\claude.exe",
        "${env:ProgramFiles(x86)}\Claude\claude.exe",
        "$env:ProgramData\Claude\claude.exe"
    )) {
    if (Test-Path $m) { $leaks += $m }
}

# Anything resolvable on the check process's PATH that isn't the sandbox copy.
# (Resolves against you/admin, not AgentSandbox - catches machine/your-PATH leaks.)
$onPath = (Get-Command claude.exe -All -ErrorAction SilentlyContinue).Source |
Where-Object { $_ -and $_ -ne $expected }
if ($onPath) { $leaks += $onPath }

$leaks = $leaks | Sort-Object -Unique
if ($leaks) {
    Warn "Claude installed outside $UserName (could leak in via machine PATH):"
    $leaks | ForEach-Object { Warn "    $_" }
}
else {
    Pass "No Claude installs outside $UserName."
}

# --- 8. GitHub Copilot CLI install location ---------------------------------
Section "GitHub Copilot CLI install"
$expectedCopilot = "C:\Users\$UserName\.local\bin\copilot.exe"
try {
    if (Test-Path -LiteralPath $expectedCopilot -ErrorAction Stop) {
        Pass "GitHub Copilot CLI installed for ${UserName}: $expectedCopilot"
    }
    else {
        Warn "No per-user GitHub Copilot CLI for $UserName at $expectedCopilot - run 'copilot' inside Agent Sandbox."
    }
}
catch {
    Warn "Could not verify per-user GitHub Copilot CLI for ${UserName}: $expectedCopilot ($($_.Exception.Message))"
}

# --- 9. Claude Code managed policy -------------------------------------------
Section "Claude Code managed policy"
if (-not (Test-Path $ManagedSettings)) {
    Warn "File-based managed settings not found: $ManagedSettings - run setup and choose managed settings deployment."
}
else {
    Pass "File-based policy present: $ManagedSettings"
    Test-ManagedPolicyContent -Description 'File-based policy' -JsonText (Get-Content $ManagedSettings -Raw)

    # Policy location should be admin-write-only.
    $policyDir = Split-Path $ManagedSettings -Parent
    Test-AdminWriteOnlyPath -Path $policyDir -Description 'ClaudeCode policy directory' -UserName $UserName
    Test-AdminWriteOnlyPath -Path $ManagedSettings -Description 'Policy file' -UserName $UserName
}

$registryPolicy = $null
try {
    $registryPolicy = (Get-ItemProperty -Path $ManagedSettingsRegistryPath -Name $ManagedSettingsRegistryValue -ErrorAction SilentlyContinue).$ManagedSettingsRegistryValue
}
catch {
    Warn "Could not read HKLM managed settings registry policy: $($_.Exception.Message)"
}

if ([string]::IsNullOrWhiteSpace($registryPolicy)) {
    Info "No HKLM registry policy found at $ManagedSettingsRegistryPath\$ManagedSettingsRegistryValue."
}
else {
    Pass "HKLM registry policy present: $ManagedSettingsRegistryPath\$ManagedSettingsRegistryValue"
    Info "HKLM policy has higher precedence than the file-based managed settings."
    Test-ManagedPolicyContent -Description 'HKLM registry policy' -JsonText $registryPolicy
}

# --- Summary ------------------------------------------------------------------
Section "Summary"
if ($script:fails -eq 0 -and $script:warns -eq 0) {
    Write-Host "  All checks passed." -ForegroundColor Green
}
else {
    Write-Host "  $script:fails FAIL, $script:warns WARN." -ForegroundColor $(if ($script:fails) { 'Red' }else { 'Yellow' })
}
exit ([int]($script:fails -gt 0))
