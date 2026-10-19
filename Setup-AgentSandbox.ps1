# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0
<#
.SYNOPSIS
    Provisions a low-privilege local 'AgentSandbox' for running AI coding
    agents with scoped access to a fixed workspace directory, while denying
    access to the calling user's secrets.

.NOTES
    - Requests administrator elevation when needed.
    - Model: AgentSandbox is a STANDARD user. Windows default ACLs already deny it
      access to other users' profiles and admin areas. We GRANT the few extra
      paths it needs (sandbox workspace, its own profile) and add EXPLICIT DENY only on the
      current user's sensitive dirs as belt-and-suspenders.
    - PowerShell 7 is required. standard users need no extra Program Files grants.
    - DENY ACEs override ALLOW. Review every Deny path before running.
    - The workspace config, launcher/check scripts, and shell commands are
      written into Program Files (Users-traversable by default) and locked
      admin-write/Users-RX, so AgentSandbox can read/run them but not modify
      them.
    - The sandbox username and workspace directory name are baked in
      (AgentSandbox); they are not configurable.
    - Settings (workspace, proxy port and allowed hosts, direct endpoints) are
      merged in this order, later wins: config\agent-sandbox.json defaults,
      the installed config.json, -ConfigFile, then -SandboxPath/-ProxyPort.
      Objects merge by key; lists replace. Setup applies them with
      Apply-Config.ps1.
    - Existing installations must be removed with their matching
      Remove-AgentSandbox.ps1 first. There is no automatic migration.
    - On a new installation without -SandboxPath or a workspace in
      -ConfigFile, the workspace directory is prompted for interactively.
#>

[CmdletBinding()]
param(
    [string]$ConfigFile, # settings to merge over the installed configuration
    [string]$SandboxPath,
    [ValidateRange(1, 65535)][int]$ProxyPort
)

$ErrorActionPreference = 'Stop'

# --- Elevation ---------------------------------------------------------------
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    foreach ($name in 'ConfigFile', 'SandboxPath') {
        if (-not $PSBoundParameters.ContainsKey($name)) { continue }
        $value = [string]$PSBoundParameters[$name]
        # A quote could end the argument and inject options into the elevated process.
        if ($value.Contains('"') -or $value.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) {
            throw "-$name contains invalid path characters."
        }
        if ($name -eq 'ConfigFile' -and $value) {
            $value = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($value)
        }
        # Windows command-line parsing consumes backslashes before a closing quote.
        $value = $value -replace '(\\+)$', '$1$1'
        $arguments += " -$name `"$value`""
    }
    if ($PSBoundParameters.ContainsKey('ProxyPort')) {
        $arguments += " -ProxyPort $ProxyPort"
    }
    $powerShell = Join-Path $PSHOME 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
        throw "PowerShell 7 executable not found at $powerShell."
    }
    $process = Start-Process -FilePath $powerShell `
        -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    $exitCode = $process.ExitCode
    if ($exitCode -eq 0) {
        Write-Host 'Elevated setup completed successfully (exit code 0).' -ForegroundColor Green
    }
    elseif ($exitCode -eq 1223) {
        Write-Host 'Elevated setup was cancelled (exit code 1223).' -ForegroundColor Yellow
    }
    else {
        Write-Host "Elevated setup failed (exit code $exitCode)." -ForegroundColor Red
    }
    exit $exitCode
}

$UserName = 'AgentSandbox'   # baked in; not configurable
$Version = '0.10.0'
$InstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'agent-win-sandbox'    # baked in; not configurable
$InstalledConfigFile = Join-Path $InstallRoot 'config.json'
$SettingsDefaultsSource = Join-Path $PSScriptRoot 'config\agent-sandbox.json'
$ConfigFunctionsSource = Join-Path $PSScriptRoot 'bootstrap\AgentSandboxConfig.ps1'
$ApplyConfigSource = Join-Path $PSScriptRoot 'Apply-Config.ps1'
$LauncherSource = Join-Path $PSScriptRoot 'Start-AgentSandbox.ps1'
$CheckerSource = Join-Path $PSScriptRoot 'Check-AgentSandbox.ps1'
$ExposureCheckSource = Join-Path $PSScriptRoot 'Test-AgentSandboxExposure.ps1'
$ShellInitSource = Join-Path $PSScriptRoot 'bootstrap\Initialize-AgentSandboxShell.ps1'
$DevShellSource = Join-Path $PSScriptRoot 'bootstrap\Enter-DevShell.ps1'
$ClaudeWrapperSource = Join-Path $PSScriptRoot 'scripts\claude-wrapper.ps1'
$CopilotWrapperSource = Join-Path $PSScriptRoot 'scripts\copilot-wrapper.ps1'
$ManagedSettingsSource = Join-Path $PSScriptRoot 'config\managed-settings.json'
$LauncherScript = Join-Path $InstallRoot 'Start-AgentSandbox.ps1'
$CheckerScript = Join-Path $InstallRoot 'Check-AgentSandbox.ps1'
$ExposureCheckScript = Join-Path $InstallRoot 'Test-AgentSandboxExposure.ps1'
$BootstrapRoot = Join-Path $InstallRoot 'bootstrap'
$ShellInitScript = Join-Path $BootstrapRoot 'Initialize-AgentSandboxShell.ps1'
$DevShellScript = Join-Path $BootstrapRoot 'Enter-DevShell.ps1'
$ClaudeWrapperScript = Join-Path $BootstrapRoot 'claude-wrapper.ps1'
$CopilotWrapperScript = Join-Path $BootstrapRoot 'copilot-wrapper.ps1'
$ConfigFunctionsScript = Join-Path $BootstrapRoot 'AgentSandboxConfig.ps1'
$ApplyConfigScript = Join-Path $InstallRoot 'Apply-Config.ps1'
$LaunchAsInstallRoot = Join-Path $env:ProgramFiles 'launch-as'
$LaunchAsExe = Join-Path $LaunchAsInstallRoot 'launch-as.exe'
$LaunchAsAdminExe = Join-Path $LaunchAsInstallRoot 'launch-as-admin.exe'
$LaunchAsVersion = 'v1.3.0'
$LaunchAsDownloadUri = "https://github.com/fmuecke/launch-as/releases/download/$LaunchAsVersion/launch-as-$LaunchAsVersion-win64.zip"
$LaunchAsSha256 = '1CCDA8A7736C24846102D94A9C12A6D3F0C29733EB282504CCCCED69E0543A8F'
$SupportedLaunchAsVersions = @('v1.0.0-preview', 'v1.1.0-preview', 'v1.1.0', 'v1.2.0-preview', 'v1.3.0')
$WfpLockVersion = 'v0.10.0'
$WfpLockUri = "https://github.com/fmuecke/wfp-lock/releases/download/$WfpLockVersion/wfp-lock-$WfpLockVersion-win64.zip"
$WfpLockSha256 = 'B4A4E52FB92DDF6CE4E1AA97F713438388DCA0BA213C6077BE4DEB273BB207E8'
$ToolsRoot = $InstallRoot
$WfpLockExe = Join-Path $ToolsRoot 'wfp-lock.exe'
$AllowProxyVersion = 'v0.4.0'
$AllowProxyUri = "https://github.com/fmuecke/allowproxy/releases/download/$AllowProxyVersion/allowproxy-$AllowProxyVersion.zip"
$AllowProxySha256 = 'CA812875647E73912D8EB0DFC72DCC718BC373D6C2CB72911C487AC668CE529C'
$AllowProxyStateRoot = Join-Path $InstallRoot 'allowproxy'
$AllowProxyExe = Join-Path $AllowProxyStateRoot 'allowproxy.exe'
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

. $ConfigFunctionsSource


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
function Test-ExistingSandboxProxyListener {
    param([object]$Listener)

    $process = Get-Process -Id $Listener.OwningProcess -ErrorAction SilentlyContinue
    if (-not $process -or $process.Path -ne $AllowProxyExe) {
        return $false
    }
    $runtimeConfig = Join-Path $AllowProxyStateRoot "allowproxy.inline-$($Listener.LocalPort).json"
    if (-not (Test-Path -LiteralPath $runtimeConfig -PathType Leaf)) { return $false }
    $output = @(& $process.Path status -config $runtimeConfig 2>&1)
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
# Returns the installed settings, or $null on a new installation.
function Get-InstalledSettings {
    if (-not (Test-Path -LiteralPath $InstalledConfigFile -PathType Leaf)) {
        return $null
    }

    try {
        $installedConfig = Read-AgentSandboxConfig -Path $InstalledConfigFile
    }
    catch {
        throw "An unreadable Agent Sandbox installation was found under $InstallRoot. Uninstall it with Remove-AgentSandbox.ps1, then run setup again."
    }
    if (-not $installedConfig.Contains('proxy') -or $installedConfig['setup'] -isnot [Collections.IDictionary]) {
        throw "The installed Agent Sandbox predates the shared configuration. Uninstall it with Remove-AgentSandbox.ps1, then run setup again."
    }
    $installedVersion = [string]$installedConfig['setup']['launchAsVersion']
    if ($installedVersion -notin $SupportedLaunchAsVersions) {
        throw "Agent Sandbox uses launch-as '$installedVersion'. launch-as $LaunchAsVersion cannot share the AgentSandbox account with earlier versions. Uninstall the earlier Agent Sandbox version first, then run setup again."
    }
    return Get-AgentSandboxSettings -Config $installedConfig
}

function Resolve-Settings {
    param([Collections.IDictionary]$InstalledSettings)

    $settings = Read-AgentSandboxConfig -Path $SettingsDefaultsSource
    if ($InstalledSettings) {
        $settings = Merge-AgentSandboxSettings -Base $settings -Override $InstalledSettings
    }
    $workspaceGiven = [bool]$InstalledSettings
    if ($ConfigFile) {
        $override = Read-AgentSandboxConfig -Path $ConfigFile
        if ($override.Contains('setup')) {
            throw "-ConfigFile must not contain the generated 'setup' section: $ConfigFile"
        }
        $settings = Merge-AgentSandboxSettings -Base $settings -Override $override
        $workspaceGiven = $workspaceGiven -or $override.Contains('workspace')
    }
    if ($SandboxPath) {
        $settings.workspace = $SandboxPath
    }
    elseif (-not $workspaceGiven) {
        $workspaceInput = Read-Host "Sandbox workspace folder [$($settings.workspace)]"
        if (-not [string]::IsNullOrWhiteSpace($workspaceInput)) { $settings.workspace = $workspaceInput.Trim() }
    }
    if ($ProxyPort) {
        $settings.proxy.port = $ProxyPort
    }
    return $settings
}

function Show-SettingsWarnings {
    param([Collections.IDictionary]$Settings)

    foreach ($warning in (Test-AgentSandboxSettings -Settings $Settings)) {
        Write-Warning $warning
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
$installedSettings = Get-InstalledSettings
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

# --- 0b. Resolve and validate settings ----------------------------------------
# Validate settings and resolve port conflicts before changing accounts, files,
# or network policy.
$settings = Resolve-Settings -InstalledSettings $installedSettings
Show-SettingsWarnings -Settings $settings
$settings.proxy.port = Resolve-ProxyPort -Port $settings.proxy.port
$null = Test-AgentSandboxSettings -Settings $settings
$SandboxPath = $settings.workspace
$ProxyPort = $settings.proxy.port
Write-Step "Proxy port: $ProxyPort"
Write-Step "Sandbox workspace: $SandboxPath"
$isInstalledWorkspace = $installedSettings -and $installedSettings.workspace -eq $SandboxPath
if ((Test-Path $SandboxPath) -and -not $isInstalledWorkspace) {
    $answer = Read-Host "Sandbox workspace already exists. Use this existing shared folder? [Y/n]"
    if ($answer -match '^(n|no)$') {
        Write-Host 'Cancelled. Choose another workspace folder or review the existing workspace first.' -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  using existing shared workspace: $SandboxPath" -ForegroundColor Yellow
}

# --- 1. Install and enroll the broker-managed user ---------------------------
Write-Step "Installing launch-as $LaunchAsVersion and creating '$UserName'"
if (-not (Test-Path $InstallRoot)) {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
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
Write-Step "Installing network proxy $AllowProxyVersion and wfp-lock $WfpLockVersion"
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
if ((Get-Item -LiteralPath $InstallRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing to install into linked Program Files directory: $InstallRoot"
}
icacls $InstallRoot /reset | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions on $InstallRoot." }
$adminRootAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights '(OI)(CI)F'
$systemRootAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights '(OI)(CI)F'
$usersRootAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights '(OI)(CI)RX'
icacls $InstallRoot /inheritance:r /grant:r $adminRootAce $systemRootAce $usersRootAce | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect $InstallRoot." }
Set-AdminOwner -Path $InstallRoot
if (Test-Path -LiteralPath $AllowProxyExe -PathType Leaf) {
    Stop-AgentSandboxProxy -Exe $AllowProxyExe
}
Install-PinnedExecutable -Name 'wfp-lock' -DownloadUri $WfpLockUri `
    -ExpectedSha256 $WfpLockSha256 -InstallRoot $ToolsRoot
Install-PinnedExecutable -Name 'allowproxy' -DownloadUri $AllowProxyUri `
    -ExpectedSha256 $AllowProxySha256 -InstallRoot $AllowProxyStateRoot
# Inline mode writes runtime files beside its executable. Keep the executable
# admin-write-only before granting the launcher file creation in this directory.
icacls $AllowProxyExe /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' '*S-1-5-32-545:RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect $AllowProxyExe." }
$launcherCreateAce = "*${callingUserSid}:(WD)"
$launcherFileAce = "*${callingUserSid}:(OI)(CI)(IO)M"
icacls $AllowProxyStateRoot /grant:r $launcherCreateAce $launcherFileAce | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect $AllowProxyStateRoot." }
foreach ($runtimeName in 'allowproxy.log', 'allowproxy.log.1', 'allowproxy.log.2', 'allowproxy.log.3') {
    $runtimePath = Join-Path $AllowProxyStateRoot $runtimeName
    if (-not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) { continue }
    if ((Get-Item -LiteralPath $runtimePath -Force).LinkType) {
        throw "Refusing to update linked proxy runtime file: $runtimePath"
    }
    icacls $runtimePath /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not protect $runtimePath." }
    Set-AdminOwner -Path $runtimePath
}

# --- 1d. Write configuration and apply network settings ----------------------
# config.json is the single source of truth for settings. It inherits the
# admin-write / Users-RX Program Files ACL; Apply-Config re-locks it.
Write-Step "Writing sandbox configuration to Program Files"
if ((Test-Path -LiteralPath $InstalledConfigFile) -and (Get-Item -LiteralPath $InstalledConfigFile -Force).LinkType) {
    throw "Refusing to write linked config: $InstalledConfigFile"
}
$config = Merge-AgentSandboxSettings -Base $settings -Override @{
    setup = [ordered]@{
        version              = $Version
        createdAtUtc         = (Get-Date).ToUniversalTime().ToString('o')
        userName             = $UserName
        installedByUser      = $callingUser
        launchAsVersion      = $LaunchAsVersion
        wfpLockVersion       = $WfpLockVersion
        allowProxyVersion    = $AllowProxyVersion
        proxyOwnerSid        = $callingUserSid
        provisionedWorkspace = $SandboxPath
    }
}
Set-Content -LiteralPath $InstalledConfigFile -Value ($config | ConvertTo-Json -Depth 10) -Encoding utf8NoBOM
Write-Host "  wrote $InstalledConfigFile" -ForegroundColor Green
& $ApplyConfigSource

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

# --- 3. Optional Claude Code managed settings deployment --------------------
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

# --- 6. Copy trusted launch artifacts into Program Files ---------------------
# Keep launch files outside the writable workspace and readable by AgentSandbox.
# Lock them admin-write / Users-RX so the agent cannot rewrite launch code.
Write-Step "Copying trusted launch artifacts to Program Files"

$bootstrapDir = $BootstrapRoot
if (-not (Test-Path $bootstrapDir)) { New-Item -ItemType Directory -Path $bootstrapDir -Force | Out-Null }
$launchArtifacts = @(
    [pscustomobject]@{ Name = 'launcher'; Source = $LauncherSource; Destination = $LauncherScript },
    [pscustomobject]@{ Name = 'configuration apply command'; Source = $ApplyConfigSource; Destination = $ApplyConfigScript },
    [pscustomobject]@{ Name = 'configuration functions'; Source = $ConfigFunctionsSource; Destination = $ConfigFunctionsScript },
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

# Lock Program Files artifacts down: admin-write only, Users get read+execute
# (read/run but not modify). Mirrors the managed-settings.json lock so the
# sandbox user can't tamper with config or what runs at launch.
$adminFullInheritAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights '(OI)(CI)F'
$systemFullInheritAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights '(OI)(CI)F'
$usersReadExecuteInheritAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights '(OI)(CI)RX'
icacls $InstallRoot /inheritance:r /grant $adminFullInheritAce $systemFullInheritAce $usersReadExecuteInheritAce | Out-Null
icacls $bootstrapDir /inheritance:r /grant $adminFullInheritAce $systemFullInheritAce $usersReadExecuteInheritAce | Out-Null
$adminFullAce = Get-IcaclsSidAce -Sid $BuiltinAdministratorsSid -Rights 'F'
$systemFullAce = Get-IcaclsSidAce -Sid $LocalSystemSid -Rights 'F'
$usersReadExecuteAce = Get-IcaclsSidAce -Sid $BuiltinUsersSid -Rights 'RX'
foreach ($protectedFile in @(
        $InstalledConfigFile,
        $LauncherScript,
        $ApplyConfigScript,
        $ConfigFunctionsScript,
        $CheckerScript,
        $ExposureCheckScript,
        $ShellInitScript,
        $DevShellScript,
        $ClaudeWrapperScript,
        $CopilotWrapperScript
    )) {
    icacls $protectedFile /inheritance:r /grant $adminFullAce $systemFullAce $usersReadExecuteAce | Out-Null
}
Write-Host "  locked Program Files artifacts: Administrators/SYSTEM full, Users read+execute" -ForegroundColor Green

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
