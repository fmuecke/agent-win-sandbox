#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Provisions a low-privilege local 'ClaudeSandbox' for running Claude Code with
    scoped access to a fixed workspace directory, while denying access to the calling
    user's secrets.

.NOTES
    - Run from an ELEVATED PowerShell session.
    - Model: ClaudeSandbox is a STANDARD user. Windows default ACLs already deny it
      access to other users' profiles and admin areas. We GRANT the few extra
      paths it needs (sandbox workspace, its own profile) and add EXPLICIT DENY only on the
      current user's sensitive dirs as belt-and-suspenders.
    - VS + Git are assumed installed machine-wide (default). A Standard user can
      run them already; no extra grants needed for Program Files.
    - DENY ACEs override ALLOW. Review every Deny path before running.
    - The workspace config, launcher/check scripts, and Dev Shell bootstrap are
      written into ProgramData (Users-traversable by default) and locked
      admin-write/Users-RX, so ClaudeSandbox can read/run them but not modify
      them.
    - The sandbox username and workspace directory name are baked in
      (ClaudeSandbox); they are not configurable.
    - The workspace base directory is prompted for interactively if not passed.
#>

[CmdletBinding()]
param(
    [string]$BasePath, # if omitted, you will be prompted
    [securestring]$Password # if omitted, you will be prompted
)

$ErrorActionPreference = 'Stop'

$UserName = 'ClaudeSandbox'   # baked in; not configurable
$SandboxDirectoryName = 'ClaudeSandbox'   # baked in; not configurable
$SetupVersion = 3
$ProgramDataRoot = Join-Path $env:ProgramData 'claude-win-sandbox'    # baked in; not configurable
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$LegacySetupMarkerFile = Join-Path $ProgramDataRoot 'setup-marker.json'
$LauncherSource = Join-Path $PSScriptRoot 'Start-ClaudeSandbox.ps1'
$CheckerSource = Join-Path $PSScriptRoot 'Check-ClaudeSandbox.ps1'
$BootstrapSource = Join-Path $PSScriptRoot 'bootstrap\Enter-ClaudeDevShell.ps1'
$ManagedSettingsSource = Join-Path $PSScriptRoot 'managed-settings.json'
$LauncherScript = Join-Path $ProgramDataRoot 'Start-ClaudeSandbox.ps1'
$CheckerScript = Join-Path $ProgramDataRoot 'Check-ClaudeSandbox.ps1'
$BootstrapScript = Join-Path (Join-Path $ProgramDataRoot 'bootstrap') 'Enter-ClaudeDevShell.ps1'    # baked in; not configurable
$ClaudeCodePolicyDir = Join-Path $env:ProgramFiles 'ClaudeCode'
$ManagedSettings = Join-Path $ClaudeCodePolicyDir 'managed-settings.json'
$ShortcutPath = Join-Path (Join-Path $env:PUBLIC 'Desktop') 'Claude (sandboxed).lnk'
$FirewallMode = 'BlockWindowsLanProtocols'
$FirewallRuleGroup = 'claude-win-sandbox'
$BuiltinAdministratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$BuiltinUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$LocalSystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$EveryoneSid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$AuthenticatedUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
$BroadReadSidValues = @($BuiltinUsersSid.Value, $EveryoneSid.Value, $AuthenticatedUsersSid.Value)
$FirewallRules = @(
    [pscustomobject]@{
        Name        = 'claude_win_sandbox_block_smb_netbios_tcp'
        DisplayName = 'Claude Sandbox - Block SMB and NetBIOS TCP'
        Description = 'Blocks ClaudeSandbox outbound SMB and NetBIOS session traffic while leaving web traffic available.'
        Protocol    = 'TCP'
        RemotePort  = @('139', '445')
    },
    [pscustomobject]@{
        Name        = 'claude_win_sandbox_block_netbios_udp'
        DisplayName = 'Claude Sandbox - Block NetBIOS UDP'
        Description = 'Blocks ClaudeSandbox outbound NetBIOS name and datagram traffic while leaving web traffic available.'
        Protocol    = 'UDP'
        RemotePort  = @('137', '138')
    },
    [pscustomobject]@{
        Name        = 'claude_win_sandbox_block_remote_admin_tcp'
        DisplayName = 'Claude Sandbox - Block remote admin TCP'
        Description = 'Blocks ClaudeSandbox outbound RPC endpoint mapper, RDP, and WinRM traffic while leaving web traffic available.'
        Protocol    = 'TCP'
        RemotePort  = @('135', '3389', '5985', '5986')
    }
)


function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Get-IcaclsSidAce {
    param(
        [Security.Principal.SecurityIdentifier]$Sid,
        [string]$Rights
    )

    return "*$($Sid.Value):$Rights"
}
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
function Get-LocalUserFirewallSddl {
    param([string]$Sid)
    return "D:(A;;CC;;;$Sid)"
}
function Read-SandboxPassword {
    param([string]$AccountName)

    while ($true) {
        $first = Read-Host "Set password for '$AccountName' (must satisfy Windows password policy)" -AsSecureString
        $second = Read-Host "Confirm password for '$AccountName'" -AsSecureString
        $firstText = [pscredential]::new('user', $first).GetNetworkCredential().Password
        $secondText = [pscredential]::new('user', $second).GetNetworkCredential().Password

        if ([string]::IsNullOrEmpty($firstText)) {
            Write-Warning 'Password cannot be empty. Try again.'
            continue
        }
        if ($firstText -ceq $secondText) {
            return $first
        }

        Write-Warning 'Passwords did not match. Try again.'
    }
}
function Test-LocalFirewallPolicyApplies {
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        if ($policy.LocalPolicyModifyState -ne 0) {
            Write-Warning "Local firewall rules may not take effect: LocalPolicyModifyState=$($policy.LocalPolicyModifyState). Continuing setup."
            return $false
        }
        return $true
    }
    catch {
        Write-Warning "Cannot verify that local firewall rules apply: $($_.Exception.Message). Continuing setup."
        return $false
    }
}
function Set-SandboxFirewallRule {
    param(
        [pscustomobject]$RuleSpec,
        [string]$LocalUserSddl,
        [string]$Group
    )

    $rule = Get-NetFirewallRule -Name $RuleSpec.Name -ErrorAction SilentlyContinue
    if ($rule) {
        $rule | Remove-NetFirewallRule
        Write-Host "  removed existing firewall rule: $($RuleSpec.DisplayName)" -ForegroundColor Yellow
    }

    New-NetFirewallRule `
        -Name $RuleSpec.Name `
        -DisplayName $RuleSpec.DisplayName `
        -Description $RuleSpec.Description `
        -Group $Group `
        -Enabled True `
        -Profile Any `
        -Direction Outbound `
        -Action Block `
        -Protocol $RuleSpec.Protocol `
        -RemotePort $RuleSpec.RemotePort `
        -LocalUser $LocalUserSddl | Out-Null

    Write-Host "  created firewall rule: $($RuleSpec.DisplayName)" -ForegroundColor Green
}
function ConvertTo-ClaudePermissionPath {
    param([string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ($root -match '^[A-Za-z]:\\$') {
        $drive = $root.Substring(0, 1).ToLowerInvariant()
        $relative = $resolved.Substring($root.Length).TrimEnd('\') -replace '\\', '/'
        if ([string]::IsNullOrWhiteSpace($relative)) {
            return "//$drive"
        }
        return "//$drive/$relative"
    }

    return ($resolved.TrimEnd('\') -replace '\\', '/')
}
function Install-ClaudeManagedSettings {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$SandboxPath
    )

    if (-not (Test-Path $Source)) {
        Write-Warning "  managed settings source not found: $Source"
        return
    }

    $shouldInstall = $false
    if (Test-Path $Destination) {
        $answer = Read-Host "Claude Code managed settings already exist at '$Destination'. Overwrite? [y/N]"
        $shouldInstall = ($answer -match '^(y|yes)$')
    }
    else {
        $answer = Read-Host "Install Claude Code managed settings to '$Destination'? [Y/n]"
        $shouldInstall = ($answer -notmatch '^(n|no)$')
    }

    if (-not $shouldInstall) {
        Write-Host '  skipped managed settings deployment.' -ForegroundColor Yellow
        return
    }

    $claudeSandboxPath = ConvertTo-ClaudePermissionPath -Path $SandboxPath
    $settingsText = (Get-Content $Source -Raw).Replace('$SANDBOXDIR', $claudeSandboxPath)
    try {
        $settingsText | ConvertFrom-Json | Out-Null
    }
    catch {
        throw "Generated managed settings JSON is invalid: $($_.Exception.Message)"
    }

    $destinationDir = Split-Path $Destination -Parent
    if (-not (Test-Path $destinationDir)) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Set-Content -Path $Destination -Value $settingsText -Encoding UTF8
    icacls $Destination /inheritance:r /grant `
    (Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights 'F') `
    (Get-IcaclsSidAce -Sid $LocalSystemSid -Rights 'F') `
    (Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights 'R') | Out-Null
    Write-Host "  wrote $Destination" -ForegroundColor Green
    Write-Host "  substituted `$SANDBOXDIR with $claudeSandboxPath" -ForegroundColor Green
    Write-Host '  locked policy file: Administrators/SYSTEM full, Users read' -ForegroundColor Green
}
# --- 0. Sanity ----------------------------------------------------------------
$callingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name  # DOMAIN\user
$callingProfile = $env:USERPROFILE
Write-Step "Calling user: $callingUser"
Write-Step "Protecting profile: $callingProfile"

# --- 0b. Resolve sandbox workspace directory interactively -------------------
if (-not $BasePath) {
    $baseInput = Read-Host "Base directory where the '$SandboxDirectoryName' workspace folder will be created [C:\dev]"
    $BasePath = if ([string]::IsNullOrWhiteSpace($baseInput)) { 'C:\dev' } else { $baseInput.Trim() }
}
$SandboxPath = Join-Path $BasePath $SandboxDirectoryName
Write-Step "Sandbox workspace: $SandboxPath"
if (Test-Path $SandboxPath) {
    $answer = Read-Host "Sandbox workspace already exists. Use this existing shared folder? [y/N]"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host 'Cancelled. Choose another base directory or review the existing workspace first.' -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  using existing shared workspace: $SandboxPath" -ForegroundColor Yellow
}

# --- 1. Create the low-priv user ---------------------------------------------
Write-Step "Ensuring local user '$UserName' exists"
$existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $existing) {
    while ($true) {
        if (-not $Password) {
            $Password = Read-SandboxPassword -AccountName $UserName
        }
        try {
            New-LocalUser -Name $UserName -Password $Password `
                -FullName 'Claude Code Sandbox User' `
                -Description 'Low-privilege user for running Claude Code' `
                -PasswordNeverExpires:$true | Out-Null
            break
        }
        catch {
            $errorId = $_.FullyQualifiedErrorId
            $exceptionType = $_.Exception.GetType().FullName
            if (($errorId -like 'InvalidPassword*') -or
                ($exceptionType -eq 'Microsoft.PowerShell.Commands.InvalidPasswordException')) {
                Write-Warning 'Windows rejected that password. It may not satisfy local/domain length, complexity, or history policy. Try another password.'
                $Password = $null
                continue
            }
            throw
        }
    }

    # Ensure it is ONLY a standard user (member of Users, not Administrators)
    Add-LocalGroupMember -SID $BuiltinUsersSid -Member $UserName -ErrorAction SilentlyContinue
    Write-Host "  created." -ForegroundColor Green
}
else {
    Write-Host "  already exists - leaving membership as-is." -ForegroundColor Yellow
}

# Hard guard: make sure it is NOT an administrator
$sandboxUser = Get-LocalUser -Name $UserName
$sandboxSid = $sandboxUser.SID.Value
$adminMembers = Get-LocalGroupMember -SID $BuiltinAdministratorsSid -ErrorAction SilentlyContinue
if ($adminMembers | Where-Object { $_.SID -and ($_.SID.Value -eq $sandboxSid) }) {
    Write-Warning "'$UserName' is in Administrators. Removing for safety."
    Remove-LocalGroupMember -SID $BuiltinAdministratorsSid -Member $sandboxUser
}

# --- 1b. Harden the account ---------------------------------------------------
# This account is only ever used via the launcher (Start-Process -Credential /
# runas), which uses the INTERACTIVE logon type. So we deliberately do NOT deny
# interactive logon - doing so breaks the launcher (verified behavior). We deny
# the logon types the account never needs (network, RDP), set sane password
# flags, and hide it from the welcome screen.
Write-Step "Hardening '$UserName'"

# Password flags: never expires (avoid surprise launcher breakage), user can't
# change it (no self-service needed).
$u = Get-LocalUser -Name $UserName
Set-LocalUser -Name $UserName -PasswordNeverExpires $true -UserMayChangePassword $false
Write-Host "  password: never-expires, user-cannot-change" -ForegroundColor Green

# Deny NETWORK and REMOTE INTERACTIVE (RDP) logon rights via secedit.
# (Interactive + the runas path are intentionally left allowed.)
$sid = $u.SID.Value
$tmp = Join-Path $env:TEMP "claude_sandbox_secpol"
$inf = "$tmp.inf"; $sdb = "$tmp.sdb"
secedit /export /cfg $inf /quiet

# Read existing deny lists (if any) and append our SID, avoiding duplicates.
$content = Get-Content $inf
function Add-SidToRight {
    param([string[]]$Lines, [string]$Right, [string]$Sid, [string]$AccountName)
    $marker = "*$Sid"
    # Find the line index of an existing right entry, if any.
    $rightIdx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match "^\s*$Right\s*=") { $rightIdx = $i; break }
    }
    if ($rightIdx -ge 0) {
        # Already present in EITHER form (secedit may store *SID or bare name)?
        $val = ($Lines[$rightIdx] -split '=', 2)[1]
        $hasSid = $val -like "*$marker*"
        $hasName = $val -match "(^|[=,\s])$([regex]::Escape($AccountName))([,\s]|$)"
        if (-not ($hasSid -or $hasName)) {
            $Lines[$rightIdx] = "$($Lines[$rightIdx]),$marker"
        }
        return $Lines
    }
    # No existing entry: insert right after the [Privilege Rights] header.
    $hdrIdx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq '[Privilege Rights]') { $hdrIdx = $i; break }
    }
    $newLine = "$Right = $marker"
    if ($hdrIdx -ge 0) {
        $before = if ($hdrIdx -ge 0) { $Lines[0..$hdrIdx] } else { @() }
        $after = if ($hdrIdx + 1 -le $Lines.Count - 1) { $Lines[($hdrIdx + 1)..($Lines.Count - 1)] } else { @() }
        return @($before + $newLine + $after)
    }
    # Header missing (unexpected): append a fresh section.
    return @($Lines + '[Privilege Rights]' + $newLine)
}
$content = Add-SidToRight -Lines $content -Right 'SeDenyNetworkLogonRight'           -Sid $sid -AccountName $UserName
$content = Add-SidToRight -Lines $content -Right 'SeDenyRemoteInteractiveLogonRight' -Sid $sid -AccountName $UserName
Set-Content -Path $inf -Value $content -Encoding Unicode

secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet
Remove-Item $inf, $sdb -ErrorAction SilentlyContinue
Write-Host "  denied network + RDP logon (interactive left intact for launcher)" -ForegroundColor Green

# Hide from the Welcome / login screen (cosmetic + discourages manual login).
$ualPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if (-not (Test-Path $ualPath)) { New-Item -Path $ualPath -Force | Out-Null }
New-ItemProperty -Path $ualPath -Name $UserName -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "  hidden from the login screen" -ForegroundColor Green

# --- 1c. Account-scoped outbound firewall hardening --------------------------
# Keep Claude operational by allowing normal web/HTTPS egress, but block common
# Windows file-sharing and remote-admin ports for the sandbox identity.
Write-Step "Configuring outbound firewall protection for '$UserName'"
try {
    $localUserSddl = Get-LocalUserFirewallSddl -Sid $sid
    $localFirewallPolicyApplies = Test-LocalFirewallPolicyApplies
    foreach ($ruleSpec in $FirewallRules) {
        Set-SandboxFirewallRule -RuleSpec $ruleSpec -LocalUserSddl $localUserSddl -Group $FirewallRuleGroup
    }
    if ($localFirewallPolicyApplies) {
        Write-Host "  firewall mode: $FirewallMode (web/HTTPS remains allowed)" -ForegroundColor Green
    }
    else {
        Write-Warning "  firewall rules were created/updated, but local policy may prevent them from taking effect."
    }
}
catch {
    Write-Warning "Could not configure outbound firewall protection: $($_.Exception.Message)"
    Write-Warning "Continuing setup. Run & '$CheckerScript' later to verify firewall state."
}

# --- 2. Shared workspace permissions -----------------------------------------
Write-Step "Configuring shared workspace at $SandboxPath"
if (-not (Test-Path $SandboxPath)) {
    New-Item -ItemType Directory -Path $SandboxPath -Force | Out-Null
    Write-Host "  created $SandboxPath" -ForegroundColor Green
}
# Grant calling user + ClaudeSandbox Modify on the workspace tree (inherited).
# Repos beneath this dir are covered by inheritance.
# Using icacls; (OI)(CI) = object + container inherit, M = Modify.
icacls $SandboxPath /grant "${callingUser}:(OI)(CI)M" | Out-Null
icacls $SandboxPath /grant "${UserName}:(OI)(CI)M"     | Out-Null
Write-Host "  granted Modify to $callingUser and $UserName" -ForegroundColor Green

# --- 3. Write ProgramData configuration --------------------------------------
# ProgramData config is the single source of truth for the sandbox path.
# ClaudeSandbox can read it at launch but cannot alter where the bootstrap lands.
Write-Step "Writing sandbox configuration to ProgramData"
if (-not (Test-Path $ProgramDataRoot)) { New-Item -ItemType Directory -Path $ProgramDataRoot -Force | Out-Null }
$config = [ordered]@{
    sandboxPath = $SandboxPath
    setup       = [ordered]@{
        setupVersion      = $SetupVersion
        createdAtUtc      = (Get-Date).ToUniversalTime().ToString('o')
        userName          = $UserName
        installedByUser   = $callingUser
        firewallMode      = $FirewallMode
        firewallRuleNames = @($FirewallRules | ForEach-Object { $_.Name })
    }
}
$config | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigFile -Encoding UTF8
Write-Host "  wrote $ConfigFile" -ForegroundColor Green
if (Test-Path $LegacySetupMarkerFile) {
    Remove-Item -LiteralPath $LegacySetupMarkerFile -Force
    Write-Host "  removed legacy $LegacySetupMarkerFile" -ForegroundColor Green
}

# --- 3b. Optional Claude Code managed settings deployment --------------------
Write-Step "Optional Claude Code managed settings"
Install-ClaudeManagedSettings -Source $ManagedSettingsSource -Destination $ManagedSettings -SandboxPath $SandboxPath

# --- 4. Verify the calling user's profile is not world/Users-readable --------
# On a standard Windows config, C:\Users\<you> is accessible only to that user,
# SYSTEM, and Administrators. A Standard user (ClaudeSandbox) is denied by default,
# so NO explicit deny ACEs are needed - and explicit denies are brittle
# (they override everything and are a classic source of lockouts). Instead we
# VERIFY the assumption and warn loudly if the profile ACL is too permissive.
Write-Step "Verifying your profile is not readable by Users/Everyone"

$acl = Get-Acl -Path $callingProfile
$risky = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.FileSystemRights -match 'Read|FullControl|Modify' -and
    (Test-IdentitySidIn -Identity $_.IdentityReference -SidValues $BroadReadSidValues)
}

if ($risky) {
    Write-Warning "Your profile '$callingProfile' grants read access to a broad group:"
    $risky | ForEach-Object {
        Write-Warning "    $($_.IdentityReference) : $($_.FileSystemRights)"
    }
    Write-Warning "This means '$UserName' may be able to read your secrets. This is a"
    Write-Warning "MISCONFIGURED system. Fix the profile ACL (remove the broad grant)"
    Write-Warning "rather than relying on per-path denies. The boundary depends on this."
}
else {
    Write-Host "  OK - profile is not exposed to Users/Everyone." -ForegroundColor Green
    Write-Host "  '$UserName' is denied your profile by default Windows ACLs." -ForegroundColor Green
}

Write-Warning "Optional hardening note: if you keep secrets OUTSIDE your profile (e.g. a KeePass vault under C:\, a shared drive), verify those paths separately - the profile-default protection does not extend to them."

# --- 5. Verify VS Developer Shell + Git availability for the user ------------
Write-Step "Locating Visual Studio Developer Shell + Git (machine-wide)"

# vswhere is the supported way to find the VS install + dev shell module.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath
    $devShell = Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (Test-Path $devShell) {
        Write-Host "  VS DevShell module: $devShell" -ForegroundColor Green
    }
    else {
        Write-Warning "  DevShell module not found under $vsPath - check VS install."
    }
}
else {
    Write-Warning "  vswhere.exe not found. Is Visual Studio installed machine-wide?"
}

$gitCmd = Get-Command git.exe -ErrorAction SilentlyContinue
$git = if ($gitCmd) { $gitCmd.Source } else { $null }
if ($git) {
    Write-Host "  git: $git" -ForegroundColor Green
}
else {
    Write-Warning "  git not on machine PATH. Install Git for Windows machine-wide."
}

# A standard user can execute both already. No grants needed because they live
# in Program Files (readable+executable by Users by default).

# --- 6. Copy trusted launch artifacts into ProgramData -----------------------
# ProgramData is traversable by Users by default, so ClaudeSandbox can reach the
# launcher/check/bootstrap regardless of where this repo was cloned (no
# profile-traversal trap). We copy them here and LOCK them admin-write / Users-RX,
# so the sandbox user can run them but cannot rewrite what executes at launch.
Write-Step "Copying trusted launch artifacts to ProgramData"

$bootstrapDir = Split-Path $BootstrapScript -Parent
if (-not (Test-Path $bootstrapDir)) { New-Item -ItemType Directory -Path $bootstrapDir -Force | Out-Null }
$launchArtifacts = @(
    [pscustomobject]@{ Name = 'launcher'; Source = $LauncherSource; Destination = $LauncherScript },
    [pscustomobject]@{ Name = 'checker'; Source = $CheckerSource; Destination = $CheckerScript },
    [pscustomobject]@{ Name = 'bootstrap'; Source = $BootstrapSource; Destination = $BootstrapScript }
)
foreach ($artifact in $launchArtifacts) {
    if (-not (Test-Path $artifact.Source)) {
        throw "$($artifact.Name) source not found: $($artifact.Source)"
    }
    Copy-Item -Path $artifact.Source -Destination $artifact.Destination -Force
    Write-Host "  wrote $($artifact.Destination)" -ForegroundColor Green
}

# Lock ProgramData artifacts down: admin-write only, Users get read+execute
# (read/run but not modify). Mirrors the managed-settings.json lock so the
# sandbox user can't tamper with config or what runs at launch.
$adminFullInheritAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights '(OI)(CI)F'
$systemFullInheritAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights '(OI)(CI)F'
$usersReadExecuteInheritAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights '(OI)(CI)RX'
icacls $ProgramDataRoot /inheritance:r /grant $adminFullInheritAce $systemFullInheritAce $usersReadExecuteInheritAce | Out-Null
icacls $bootstrapDir /inheritance:r /grant $adminFullInheritAce $systemFullInheritAce $usersReadExecuteInheritAce | Out-Null
Write-Host "  locked ProgramData artifacts: Administrators/SYSTEM full, Users read+execute" -ForegroundColor Green

# --- 6b. Desktop shortcut for double-click launch ----------------------------
Write-Step "Creating desktop shortcut"

if (-not (Test-Path $LauncherScript)) {
    throw "Installed launcher not found at $LauncherScript."
}
try {
    $powershellExe = (Get-Command powershell.exe).Source
    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($ShortcutPath)
    $sc.TargetPath = $powershellExe
    $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$LauncherScript`""
    $sc.WorkingDirectory = $SandboxPath
    $sc.IconLocation = "$powershellExe,0"
    $sc.Description = 'Launch Claude Code as the low-privilege sandbox user'
    $sc.Save()

    Write-Host "  created $ShortcutPath" -ForegroundColor Green
}
catch {
    throw "Could not create desktop shortcut at ${ShortcutPath}: $($_.Exception.Message)"
}

# --- 7. Done ------------------------------------------------------------------
Write-Step "Setup complete"
Write-Host @"
To start a Claude Code session, use the desktop shortcut:

  $ShortcutPath

Or run the launcher directly:

  & '$LauncherScript'

  NOTE:
  - Keep secrets in your own Windows profile or another location ClaudeSandbox
    cannot read. Shared folders, drives, and vaults outside your profile need
    separate review.
  - ClaudeSandbox has its own Windows Credential Manager and profile. Set up its
    ADO PAT/git credential separately, scoped minimally.

"@ -ForegroundColor Cyan
