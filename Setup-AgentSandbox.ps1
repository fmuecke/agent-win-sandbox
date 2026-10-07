# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -RunAsAdministrator
#Requires -Version 7.0
<#
.SYNOPSIS
    Provisions a low-privilege local 'AgentSandbox' for running AI coding
    agents with scoped access to a fixed workspace directory, while denying
    access to the calling user's secrets.

.NOTES
    - Run from an ELEVATED PowerShell session.
    - Model: AgentSandbox is a STANDARD user. Windows default ACLs already deny it
      access to other users' profiles and admin areas. We GRANT the few extra
      paths it needs (sandbox workspace, its own profile) and add EXPLICIT DENY only on the
      current user's sensitive dirs as belt-and-suspenders.
    - PowerShell 7 is required. standard users need no extra Program Files grants.
    - DENY ACEs override ALLOW. Review every Deny path before running.
    - The workspace config, launcher/check scripts, and shell commands are
      written into ProgramData (Users-traversable by default) and locked
      admin-write/Users-RX, so AgentSandbox can read/run them but not modify
      them.
    - The sandbox username and workspace directory name are baked in
      (AgentSandbox); they are not configurable.
    - The complete workspace directory is prompted for interactively if not passed.
#>

[CmdletBinding()]
param(
    [string]$SandboxPath, # if omitted, you will be prompted
    [ValidateRange(1, 65535)][int]$ProxyPort = 8080
)

$ErrorActionPreference = 'Stop'

$UserName = 'AgentSandbox'   # baked in; not configurable
$Version = '0.9.0'
$ProgramDataRoot = Join-Path $env:ProgramData 'agent-win-sandbox'    # baked in; not configurable
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$LegacySetupMarkerFile = Join-Path $ProgramDataRoot 'setup-marker.json'
$LauncherSource = Join-Path $PSScriptRoot 'Start-AgentSandbox.ps1'
$CheckerSource = Join-Path $PSScriptRoot 'Check-AgentSandbox.ps1'
$ExposureCheckSource = Join-Path $PSScriptRoot 'Test-AgentSandboxExposure.ps1'
$ShellInitSource = Join-Path $PSScriptRoot 'bootstrap\Initialize-AgentSandboxShell.ps1'
$DevShellSource = Join-Path $PSScriptRoot 'bootstrap\Enter-DevShell.ps1'
$ClaudeWrapperSource = Join-Path $PSScriptRoot 'scripts\claude-wrapper.ps1'
$CopilotWrapperSource = Join-Path $PSScriptRoot 'scripts\copilot-wrapper.ps1'
$ManagedSettingsSource = Join-Path $PSScriptRoot 'config\managed-settings.json'
$LauncherScript = Join-Path $ProgramDataRoot 'Start-AgentSandbox.ps1'
$CheckerScript = Join-Path $ProgramDataRoot 'Check-AgentSandbox.ps1'
$ExposureCheckScript = Join-Path $ProgramDataRoot 'Test-AgentSandboxExposure.ps1'
$BootstrapRoot = Join-Path $ProgramDataRoot 'bootstrap'
$ShellInitScript = Join-Path $BootstrapRoot 'Initialize-AgentSandboxShell.ps1'
$DevShellScript = Join-Path $BootstrapRoot 'Enter-DevShell.ps1'
$ClaudeWrapperScript = Join-Path $BootstrapRoot 'claude-wrapper.ps1'
$CopilotWrapperScript = Join-Path $BootstrapRoot 'copilot-wrapper.ps1'
$LaunchAsInstallRoot = Join-Path $env:ProgramFiles 'launch-as'
$LaunchAsExe = Join-Path $LaunchAsInstallRoot 'launch-as.exe'
$LaunchAsAdminExe = Join-Path $LaunchAsInstallRoot 'launch-as-admin.exe'
$LegacyLaunchAsExe = Join-Path $ProgramDataRoot 'launch-as.exe'
$LegacyLaunchAsAdminExe = Join-Path $ProgramDataRoot 'launch-as-admin.exe'
$LaunchAsVersion = 'v1.3.0'
$LaunchAsDownloadUri = 'https://github.com/fmuecke/launch-as/releases/download/v1.3.0/launch-as-v1.3.0-win64.zip'
$LaunchAsSha256 = '1CCDA8A7736C24846102D94A9C12A6D3F0C29733EB282504CCCCED69E0543A8F'
$SupportedLaunchAsVersions = @('v1.0.0-preview', 'v1.1.0-preview', 'v1.1.0', 'v1.2.0-preview', 'v1.3.0')
$UserNetLockVersion = 'v0.8.1'
$UserNetLockUri = 'https://github.com/fmuecke/user-net-lock/releases/download/v0.8.1/user-net-lock-v0.8.1-win64.zip'
$UserNetLockSha256 = '4DB67DB57106CA8EFECF041B809FFC0FC18CD459C414BE7C232FD3DFC9E09672'
$ToolsRoot = $ProgramDataRoot
$UserNetLockExe = Join-Path $ToolsRoot 'user-net-lock.exe'
$NetworkSandboxVersion = 'v0.2.1'
$NetworkSandboxUri = 'https://github.com/fmuecke/network-sandbox/releases/download/v0.2.1/network-sandbox-v0.2.1.zip'
$NetworkSandboxSha256 = 'A4355750492273225A96C08DEE25810A862622C621BCA2854F2D88608CF95473'
$NetworkSandboxExe = Join-Path $ToolsRoot 'network-sandbox.exe'
$LegacyNetworkSandboxExe = Join-Path (Join-Path $env:ProgramFiles 'network-sandbox') 'network-sandbox.exe'
$NetworkSandboxConfigSource = Join-Path $PSScriptRoot 'config\network-sandbox.ini'
$NetworkSandboxStateRoot = Join-Path $ProgramDataRoot 'network-sandbox'
$NetworkSandboxConfig = Join-Path $NetworkSandboxStateRoot 'network-sandbox.ini'
$ClaudeCodePolicyDir = Join-Path $env:ProgramFiles 'ClaudeCode'
$ManagedSettings = Join-Path $ClaudeCodePolicyDir 'managed-settings.json'
$ShortcutPath = Join-Path (Join-Path $env:PUBLIC 'Desktop') 'Agent Sandbox.lnk'
$PwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
$BuiltinAdministratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$BuiltinUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$LocalSystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$EveryoneSid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$AuthenticatedUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
$BroadReadSidValues = @($BuiltinUsersSid.Value, $EveryoneSid.Value, $AuthenticatedUsersSid.Value)


function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Set-AdminOwner {
    param([string]$Path)
    icacls $Path /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set Administrators as owner of $Path." }
}
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
        Write-Warning 'Claude Code managed settings are machine-wide and shared by all Windows users.'
        $answer = Read-Host "Managed settings already exist at '$Destination'. Overwrite? [y/N]"
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

    $agentSandboxPath = ConvertTo-ClaudePermissionPath -Path $SandboxPath
    $settingsText = (Get-Content $Source -Raw).Replace('$SANDBOXDIR', $agentSandboxPath)
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
    Write-Host "  substituted `$SANDBOXDIR with $agentSandboxPath" -ForegroundColor Green
    Write-Host '  locked policy file: Administrators/SYSTEM full, Users read' -ForegroundColor Green
}
function Install-LaunchAs {
    param(
        [string]$InstallRoot,
        [string]$DownloadUri,
        [string]$ExpectedSha256
    )

    $tempRoot = Join-Path $env:TEMP ("agent-win-sandbox-launch-as-" + [guid]::NewGuid().ToString('N'))
    $archivePath = Join-Path $tempRoot 'launch-as.zip'
    $extractPath = Join-Path $tempRoot 'extracted'

    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        Invoke-WebRequest -Uri $DownloadUri -OutFile $archivePath

        $actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        if ($actualSha256 -ine $ExpectedSha256) {
            throw "launch-as download hash mismatch. Expected $ExpectedSha256, got $actualSha256."
        }

        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force
        $releaseFiles = @{}
        foreach ($name in 'launch-as.exe', 'launch-as-admin.exe', 'launch-as-broker.exe', 'launch-as-conhost.exe') {
            $matches = @(Get-ChildItem -LiteralPath $extractPath -Filter $name -File -Recurse)
            if ($matches.Count -ne 1) {
                throw "Expected exactly one $name in the release archive; found $($matches.Count)."
            }
            $releaseFiles[$name] = $matches[0]
        }

        & $releaseFiles['launch-as-admin.exe'].FullName install
        if ($LASTEXITCODE -ne 0) {
            throw "launch-as broker installation failed with exit code $LASTEXITCODE."
        }

        foreach ($name in $releaseFiles.Keys) {
            $installedPath = Join-Path $InstallRoot $name
            if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf)) {
                throw "launch-as installation did not create the expected file: $installedPath"
            }
        }

        $enrolledAccounts = @(& $releaseFiles['launch-as-admin.exe'].FullName list)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not list launch-as broker accounts (exit code $LASTEXITCODE)."
        }
        if ($UserName -notin $enrolledAccounts) {
            & $releaseFiles['launch-as-admin.exe'].FullName create --takeover $UserName --force
            if ($LASTEXITCODE -ne 0) {
                throw "Could not enroll '$UserName' with launch-as (exit code $LASTEXITCODE)."
            }
        }

        Write-Host "  downloaded and verified launch-as package" -ForegroundColor Green
        Write-Host "  installed launch-as service and command-line tools: $InstallRoot" -ForegroundColor Green
        Write-Host "  configured '$UserName' as a launch-as-managed account" -ForegroundColor Green
    }
    finally {
        if (Test-Path $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
function Install-PinnedExecutable {
    param(
        [string]$Name,
        [string]$DownloadUri,
        [string]$ExpectedSha256,
        [string]$InstallRoot
    )

    $tempRoot = Join-Path $env:TEMP ("agent-win-sandbox-$Name-" + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        $archive = Join-Path $tempRoot 'release.zip'
        $extracted = Join-Path $tempRoot 'extracted'
        Invoke-WebRequest -Uri $DownloadUri -OutFile $archive
        $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        if ($actualHash -ine $ExpectedSha256) {
            throw "$Name download hash mismatch. Expected $ExpectedSha256, got $actualHash."
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $extracted
        $matches = @(Get-ChildItem -LiteralPath $extracted -Filter "$Name.exe" -File -Recurse)
        if ($matches.Count -ne 1) {
            throw "Expected exactly one $Name.exe in the release archive; found $($matches.Count)."
        }
        New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
        if ((Get-Item -LiteralPath $InstallRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing to install into linked tools directory: $InstallRoot"
        }
        icacls $InstallRoot /reset | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions on $InstallRoot." }
        $adminAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights '(OI)(CI)F'
        $systemAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights '(OI)(CI)F'
        $usersAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights '(OI)(CI)RX'
        icacls $InstallRoot /inheritance:r /grant:r $adminAce $systemAce $usersAce | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not protect $InstallRoot." }
        Set-AdminOwner -Path $InstallRoot
        $executablePath = Join-Path $InstallRoot "$Name.exe"
        if ((Test-Path -LiteralPath $executablePath) -and
            ((Get-Item -LiteralPath $executablePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing to replace linked executable: $executablePath"
        }
        Copy-Item -LiteralPath $matches[0].FullName -Destination $executablePath -Force
        icacls (Join-Path $InstallRoot "$Name.exe") /reset | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not protect $Name.exe." }
        Set-AdminOwner -Path (Join-Path $InstallRoot "$Name.exe")
        Write-Host "  installed hash-verified $Name at $InstallRoot" -ForegroundColor Green
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
function Install-NetworkSandboxPolicy {
    if ((Test-Path -LiteralPath $NetworkSandboxConfig) -and
        ((Get-Item -LiteralPath $NetworkSandboxConfig -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to update linked proxy policy: $NetworkSandboxConfig"
    }
    if (-not (Test-Path -LiteralPath $NetworkSandboxConfig -PathType Leaf)) {
        $policy = Get-Content -LiteralPath $NetworkSandboxConfigSource -Raw
    }
    else {
        $policy = Get-Content -LiteralPath $NetworkSandboxConfig -Raw
        Write-Warning "Preserving the existing proxy allowlist at $NetworkSandboxConfig. Review it before starting agents."
    }
    if ($policy -notmatch '(?m)^port=\d+[^\r\n]*$') {
        throw "Network proxy policy has no port setting: $NetworkSandboxConfig"
    }
    if ($policy -notmatch "(?m)^port=$ProxyPort(?:\s|$)") {
        Write-Warning "Setting the proxy policy port to $ProxyPort to match the network lock."
    }
    $policy = $policy -replace '(?m)^port=\d+[^\r\n]*$', "port=$ProxyPort"
    $logPath = Join-Path $NetworkSandboxStateRoot 'network-sandbox.log'
    if ($policy -match '(?m)^logfile=[^\r\n]*$') {
        $policy = $policy -replace '(?m)^logfile=[^\r\n]*$', "logfile=$logPath"
    }
    else {
        $policy = $policy -replace '(?m)^(port=\d+)$', "`$1`nlogfile=$logPath"
    }
    Set-Content -LiteralPath $NetworkSandboxConfig -Value $policy -Encoding utf8NoBOM -NoNewline
}
function Test-NetworkSandboxRunning {
    $output = @(& $NetworkSandboxExe status -config $NetworkSandboxConfig 2>&1)
    return ($LASTEXITCODE -eq 0 -and ($output -join ' ') -match "127\.0\.0\.1:$ProxyPort(?!\d)")
}
function Start-NetworkSandbox {
    if (-not (Test-NetworkSandboxRunning)) {
        & $NetworkSandboxExe start -config $NetworkSandboxConfig
    }
    if (-not (Test-NetworkSandboxRunning)) {
        throw "Network proxy did not start on 127.0.0.1:$ProxyPort; inspect its log."
    }
}
function Test-ExistingSandboxProxyListener {
    param([object]$Listener)

    if (-not (Test-Path -LiteralPath $NetworkSandboxConfig -PathType Leaf)) { return $false }
    $process = Get-Process -Id $Listener.OwningProcess -ErrorAction SilentlyContinue
    if (-not $process -or $process.Path -notin @($NetworkSandboxExe, $LegacyNetworkSandboxExe)) {
        return $false
    }
    $output = @(& $process.Path status -config $NetworkSandboxConfig 2>&1)
    return ($LASTEXITCODE -eq 0 -and ($output -join ' ') -match
        "running \(pid $($Listener.OwningProcess)\) on 127\.0\.0\.1:$($Listener.LocalPort)(?!\d)")
}
function Resolve-ProxyPort {
    param([int]$Port)

    while ($true) {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalPort -eq $Port })
        $conflicts = @($listeners | Where-Object { -not (Test-ExistingSandboxProxyListener -Listener $_) })
        if ($conflicts.Count -eq 0) { return $Port }

        Write-Warning "TCP port $Port is already in use by another process (PID: $(($conflicts.OwningProcess | Sort-Object -Unique) -join ', '))."
        do {
            $answer = Read-Host 'Choose a different proxy port (1-65535), or press Enter to cancel setup'
            if ([string]::IsNullOrWhiteSpace($answer)) {
                throw 'Setup cancelled because the proxy port is already in use.'
            }
            $replacementPort = 0
            $validPort = [int]::TryParse($answer.Trim(), [ref]$replacementPort) -and
            $replacementPort -ge 1 -and $replacementPort -le 65535
            if (-not $validPort) { Write-Warning 'Enter a port number from 1 to 65535.' }
        } while (-not $validPort)
        $Port = $replacementPort
    }
}
function Remove-LegacyLaunchAsCopies {
    param(
        [string]$LegacyClientPath,
        [string]$LegacyAdminPath
    )

    foreach ($legacyPath in $LegacyClientPath, $LegacyAdminPath) {
        if (Test-Path -LiteralPath $legacyPath -PathType Leaf) {
            Remove-Item -LiteralPath $legacyPath -Force
            Write-Host "  removed obsolete launch-as copy: $legacyPath" -ForegroundColor Green
        }
    }
}
function Stop-IfLegacyInstallationPresent {
    $hasConfig = Test-Path -LiteralPath $ConfigFile -PathType Leaf
    $hasInstalledClient = Test-Path -LiteralPath $LaunchAsExe -PathType Leaf
    $hasLegacyClient = Test-Path -LiteralPath $LegacyLaunchAsExe -PathType Leaf

    if (-not $hasConfig) {
        if ($hasLegacyClient) {
            throw "A legacy launch-as copy was found under $ProgramDataRoot without Agent Sandbox configuration. Uninstall the matching earlier Agent Sandbox version first."
        }
        if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
            throw "The '$UserName' account exists without a launch-as $LaunchAsVersion installation. Treat it as a legacy or incomplete installation and uninstall it before running setup."
        }
        return
    }
    if (-not $hasInstalledClient -and -not $hasLegacyClient) {
        throw "An incomplete or legacy Agent Sandbox installation was found under $ProgramDataRoot. Uninstall it before installing launch-as $LaunchAsVersion."
    }

    try {
        $installedConfig = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
        $installedVersion = [string]$installedConfig.setup.launchAsVersion
    }
    catch {
        throw "An unreadable Agent Sandbox installation was found under $ProgramDataRoot. Uninstall it before installing launch-as $LaunchAsVersion."
    }

    if ($installedVersion -notin $SupportedLaunchAsVersions) {
        throw "Agent Sandbox uses launch-as '$installedVersion'. launch-as $LaunchAsVersion cannot share the AgentSandbox account with earlier versions. Uninstall the earlier Agent Sandbox version first, then run setup again."
    }
}
# --- 0. Sanity ----------------------------------------------------------------
if (-not (Test-Path $PwshExe -PathType Leaf)) {
    throw "PowerShell 7 is required but was not found at $PwshExe. Install it machine-wide before setup."
}
$pwshVersion = & $PwshExe -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
if ($LASTEXITCODE -ne 0) {
    throw "PowerShell 7 at $PwshExe could not be started."
}
Stop-IfLegacyInstallationPresent
$existingSandboxUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($existingSandboxUser) {
    $existingProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($existingSandboxUser.SID.Value)'" -ErrorAction Stop
    if ($existingProfile -and $existingProfile.Loaded) {
        throw "Close all '$UserName' sessions before updating the broker or network policy."
    }
}

$callingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name  # DOMAIN\user
$callingUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$callingProfile = $env:USERPROFILE
Write-Step "PowerShell 7: $pwshVersion"
Write-Step "Calling user: $callingUser"
Write-Step "Protecting profile: $callingProfile"

# Resolve port conflicts before changing accounts, files, or network policy.
$ProxyPort = Resolve-ProxyPort -Port $ProxyPort
Write-Step "Proxy port: $ProxyPort"

# --- 0b. Resolve sandbox workspace directory interactively -------------------
if (-not $SandboxPath) {
    $workspaceInput = Read-Host 'Sandbox workspace folder [C:\AgentSandbox]'
    $SandboxPath = if ([string]::IsNullOrWhiteSpace($workspaceInput)) { 'C:\AgentSandbox' } else { $workspaceInput.Trim() }
}
if ((Split-Path -Path $SandboxPath -Leaf) -ne 'AgentSandbox') {
    throw "Sandbox workspace must be named 'AgentSandbox': $SandboxPath"
}
Write-Step "Sandbox workspace: $SandboxPath"
if (Test-Path $SandboxPath) {
    $answer = Read-Host "Sandbox workspace already exists. Use this existing shared folder? [y/N]"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host 'Cancelled. Choose another workspace folder or review the existing workspace first.' -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  using existing shared workspace: $SandboxPath" -ForegroundColor Yellow
}

# --- 1. Install and enroll the broker-managed user ---------------------------
Write-Step "Installing launch-as $LaunchAsVersion and creating '$UserName'"
if (-not (Test-Path $ProgramDataRoot)) {
    New-Item -ItemType Directory -Path $ProgramDataRoot -Force | Out-Null
}
Install-LaunchAs -InstallRoot $LaunchAsInstallRoot `
    -DownloadUri $LaunchAsDownloadUri -ExpectedSha256 $LaunchAsSha256

# Hard guard: make sure it is NOT an administrator
$sandboxUser = Get-LocalUser -Name $UserName
$sandboxSid = $sandboxUser.SID.Value
$adminMembers = Get-LocalGroupMember -SID $BuiltinAdministratorsSid -ErrorAction SilentlyContinue
if ($adminMembers | Where-Object { $_.SID -and ($_.SID.Value -eq $sandboxSid) }) {
    Write-Warning "'$UserName' is in Administrators. Removing for safety."
    Remove-LocalGroupMember -SID $BuiltinAdministratorsSid -Member $sandboxUser
}

# --- 1b. Harden the account ---------------------------------------------------
# The broker uses the INTERACTIVE logon type to create the account's independent
# console session. Do not deny interactive logon; deny only the logon types the
# account never needs (network, RDP), set sane password flags, and hide it from
# the welcome screen.
Write-Step "Hardening '$UserName'"

# Password flags: never expires (avoid surprise launcher breakage), user can't
# change it (no self-service needed).
$u = Get-LocalUser -Name $UserName
Set-LocalUser -Name $UserName -PasswordNeverExpires $true -UserMayChangePassword $false
Write-Host "  password: never-expires, user-cannot-change" -ForegroundColor Green

# Deny NETWORK and REMOTE INTERACTIVE (RDP) logon rights via secedit.
# (Interactive + the launch-as path are intentionally left allowed.)
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

# --- 1c. Protected proxy and account-scoped network lock --------------------
Write-Step "Installing network proxy $NetworkSandboxVersion and user-net-lock $UserNetLockVersion"
New-Item -ItemType Directory -Path $ProgramDataRoot -Force | Out-Null
if ((Get-Item -LiteralPath $ProgramDataRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing to install into linked ProgramData directory: $ProgramDataRoot"
}
icacls $ProgramDataRoot /reset | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions on $ProgramDataRoot." }
$adminRootAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights '(OI)(CI)F'
$systemRootAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights '(OI)(CI)F'
$usersRootAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights '(OI)(CI)RX'
icacls $ProgramDataRoot /inheritance:r /grant:r $adminRootAce $systemRootAce $usersRootAce | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect $ProgramDataRoot." }
Set-AdminOwner -Path $ProgramDataRoot
New-Item -ItemType Directory -Path $NetworkSandboxStateRoot -Force | Out-Null
if ((Get-Item -LiteralPath $NetworkSandboxStateRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing to use linked proxy state directory: $NetworkSandboxStateRoot"
}
icacls $NetworkSandboxStateRoot /reset | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions on $NetworkSandboxStateRoot." }
$adminStateAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights '(OI)(CI)F'
$systemStateAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights '(OI)(CI)F'
$usersStateAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights '(OI)(CI)RX'
$launcherCreateAce = "*${callingUserSid}:(WD)"
$launcherFileAce = "*${callingUserSid}:(OI)(CI)(IO)M"
icacls $NetworkSandboxStateRoot /inheritance:r /grant:r $adminStateAce $systemStateAce $usersStateAce $launcherCreateAce $launcherFileAce | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect $NetworkSandboxStateRoot." }
Set-AdminOwner -Path $NetworkSandboxStateRoot
Install-PinnedExecutable -Name 'user-net-lock' -DownloadUri $UserNetLockUri `
    -ExpectedSha256 $UserNetLockSha256 -InstallRoot $ToolsRoot
$previousProxyExe = if (Test-Path -LiteralPath $NetworkSandboxExe -PathType Leaf) {
    $NetworkSandboxExe
}
else { $LegacyNetworkSandboxExe }
if ((Test-Path -LiteralPath $previousProxyExe -PathType Leaf) -and
    (Test-Path -LiteralPath $NetworkSandboxConfig -PathType Leaf)) {
    & $previousProxyExe stop -config $NetworkSandboxConfig
    if ($LASTEXITCODE -ne 0) { throw 'Could not stop the previous network proxy.' }
}
foreach ($runtimeName in 'network-sandbox.ini.pid', 'network-sandbox.ini.pid.lock',
    'network-sandbox.log', 'network-sandbox.log.1', 'network-sandbox.log.2', 'network-sandbox.log.3') {
    $runtimePath = Join-Path $NetworkSandboxStateRoot $runtimeName
    if (-not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) { continue }
    if ((Get-Item -LiteralPath $runtimePath -Force).LinkType) {
        throw "Refusing to update linked proxy runtime file: $runtimePath"
    }
    icacls $runtimePath /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not protect $runtimePath." }
    Set-AdminOwner -Path $runtimePath
}
Install-PinnedExecutable -Name 'network-sandbox' -DownloadUri $NetworkSandboxUri `
    -ExpectedSha256 $NetworkSandboxSha256 -InstallRoot $ToolsRoot
Install-NetworkSandboxPolicy
icacls $NetworkSandboxConfig /reset | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions on $NetworkSandboxConfig." }
$adminConfigAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights 'F'
$systemConfigAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights 'F'
$usersConfigAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights 'RX'
icacls $NetworkSandboxConfig /inheritance:r /grant:r $adminConfigAce $systemConfigAce $usersConfigAce | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect $NetworkSandboxConfig." }
Set-AdminOwner -Path $NetworkSandboxConfig
Start-NetworkSandbox
& $UserNetLockExe apply --user $UserName --port $ProxyPort
if ($LASTEXITCODE -ne 0) { throw "Could not apply user-net-lock for '$UserName'." }
& $UserNetLockExe verify --user $UserName --port $ProxyPort
if ($LASTEXITCODE -ne 0) { throw "Could not verify user-net-lock for '$UserName'." }

# --- 2. Shared workspace permissions -----------------------------------------
Write-Step "Configuring shared workspace at $SandboxPath"
if (-not (Test-Path $SandboxPath)) {
    New-Item -ItemType Directory -Path $SandboxPath -Force | Out-Null
    Write-Host "  created $SandboxPath" -ForegroundColor Green
}
# Grant calling user + AgentSandbox Modify on the workspace tree (inherited).
# Repos beneath this dir are covered by inheritance.
# Using icacls; (OI)(CI) = object + container inherit, M = Modify.
icacls $SandboxPath /grant "${callingUser}:(OI)(CI)M" | Out-Null
icacls $SandboxPath /grant "${UserName}:(OI)(CI)M"     | Out-Null
Write-Host "  granted Modify to $callingUser and $UserName" -ForegroundColor Green

# --- 3. Write ProgramData configuration --------------------------------------
# ProgramData config is the single source of truth for the sandbox path.
# AgentSandbox can read it at launch but cannot alter where the bootstrap lands.
Write-Step "Writing sandbox configuration to ProgramData"
if (-not (Test-Path $ProgramDataRoot)) { New-Item -ItemType Directory -Path $ProgramDataRoot -Force | Out-Null }
$config = [ordered]@{
    sandboxPath = $SandboxPath
    setup       = [ordered]@{
        version               = $Version
        createdAtUtc          = (Get-Date).ToUniversalTime().ToString('o')
        userName              = $UserName
        installedByUser       = $callingUser
        launchAsVersion       = $LaunchAsVersion
        userNetLockVersion    = $UserNetLockVersion
        networkSandboxVersion = $NetworkSandboxVersion
        proxyPort             = $ProxyPort
        proxyOwnerSid         = $callingUserSid
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
# SYSTEM, and Administrators. A Standard user (AgentSandbox) is denied by default,
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

# --- 5. Report machine-wide PowerShell and Git -------------------------------
Write-Step "PowerShell 7 and Git (machine-wide)"

Write-Host "  pwsh: $PwshExe ($pwshVersion)" -ForegroundColor Green

$gitCmd = Get-Command git.exe -ErrorAction SilentlyContinue
$git = if ($gitCmd) { $gitCmd.Source } else { $null }
if ($git) {
    Write-Host "  git: $git" -ForegroundColor Green
}
else {
    Write-Warning "  git not on machine PATH. Install Git for Windows machine-wide."
}

# Standard users can run machine-wide tools without extra Program Files grants.

# --- 6. Copy trusted launch artifacts into ProgramData -----------------------
# ProgramData is traversable by Users by default, so AgentSandbox can reach the
# launcher/check/bootstrap regardless of where this repo was cloned (no
# profile-traversal trap). We copy them here and LOCK them admin-write / Users-RX,
# so the sandbox user can run them but cannot rewrite what executes at launch.
Write-Step "Copying trusted launch artifacts to ProgramData"

$bootstrapDir = $BootstrapRoot
if (-not (Test-Path $bootstrapDir)) { New-Item -ItemType Directory -Path $bootstrapDir -Force | Out-Null }
$launchArtifacts = @(
    [pscustomobject]@{ Name = 'launcher'; Source = $LauncherSource; Destination = $LauncherScript },
    [pscustomobject]@{ Name = 'checker'; Source = $CheckerSource; Destination = $CheckerScript },
    [pscustomobject]@{ Name = 'exposure diagnostic'; Source = $ExposureCheckSource; Destination = $ExposureCheckScript },
    [pscustomobject]@{ Name = 'shell initializer'; Source = $ShellInitSource; Destination = $ShellInitScript },
    [pscustomobject]@{ Name = 'Developer Shell command'; Source = $DevShellSource; Destination = $DevShellScript },
    [pscustomobject]@{ Name = 'Claude command'; Source = $ClaudeWrapperSource; Destination = $ClaudeWrapperScript },
    [pscustomobject]@{ Name = 'Copilot command'; Source = $CopilotWrapperSource; Destination = $CopilotWrapperScript }
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
$adminFullAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights 'F'
$systemFullAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights 'F'
$usersReadExecuteAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights 'RX'
foreach ($protectedFile in @(
        $ConfigFile,
        $LauncherScript,
        $CheckerScript,
        $ExposureCheckScript,
        $ShellInitScript,
        $DevShellScript,
        $ClaudeWrapperScript,
        $CopilotWrapperScript
    )) {
    icacls $protectedFile /inheritance:r /grant $adminFullAce $systemFullAce $usersReadExecuteAce | Out-Null
}
Write-Host "  locked ProgramData artifacts: Administrators/SYSTEM full, Users read+execute" -ForegroundColor Green
Remove-LegacyLaunchAsCopies -LegacyClientPath $LegacyLaunchAsExe -LegacyAdminPath $LegacyLaunchAsAdminExe
$obsoleteSurfaceCheck = Join-Path $ProgramDataRoot 'Test-AgentSandboxAttackSurfaces.ps1'
if (Test-Path -LiteralPath $obsoleteSurfaceCheck -PathType Leaf) {
    Remove-Item -LiteralPath $obsoleteSurfaceCheck -Force
}

# --- 6b. Desktop shortcut for double-click launch ----------------------------
Write-Step "Creating desktop shortcut"

if (-not (Test-Path $LauncherScript)) {
    throw "Installed launcher not found at $LauncherScript."
}
try {
    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($ShortcutPath)
    $sc.TargetPath = $PwshExe
    $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$LauncherScript`""
    $sc.WorkingDirectory = $SandboxPath
    $sc.IconLocation = "$PwshExe,0"
    $sc.Description = 'Launch a PowerShell terminal for low-privilege coding agents'
    $sc.Save()

    Write-Host "  created $ShortcutPath" -ForegroundColor Green
}
catch {
    throw "Could not create desktop shortcut at ${ShortcutPath}: $($_.Exception.Message)"
}

# --- 7. Done ------------------------------------------------------------------
Write-Step "Setup complete" -ForegroundColor Cyan
Write-Host @"
To start an Agent Sandbox terminal, use the desktop shortcut:

  $ShortcutPath

Inside the sandbox, run 'sandbox-help' to list the available commands.

NOTE:
  - Keep secrets in your own Windows profile or another location AgentSandbox
    cannot read. Shared folders, drives, and vaults outside your profile need
    separate review.
  - AgentSandbox has its own Windows Credential Manager and profile. Set up its
    ADO PAT/git credential separately, scoped minimally.
  - COPILOT_GITHUB_TOKEN is stored for AgentSandbox when the Copilot wrapper
    first prompts for its fine-grained PAT. Every process running as that user
    can read it.

"@
