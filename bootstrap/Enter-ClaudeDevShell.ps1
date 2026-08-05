# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

# claude-win-sandbox Dev Shell bootstrap.
# Opens a VS Developer Shell in the configured sandbox workspace. Run AS ClaudeSandbox.
# Uses -VsInstanceId (more reliable than -VsInstallPath discovery under a
# different user profile). Errors loudly if VS isn't found.
$Version = '0.5.2'
$ProgramDataRoot = Join-Path $env:ProgramData 'claude-win-sandbox'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$CheckScript = Join-Path $ProgramDataRoot 'Check-ClaudeSandbox.ps1'
if (-not (Test-Path $ConfigFile)) {
    Write-Host "Sandbox config missing: $ConfigFile" -ForegroundColor Red
    Write-Host 'Run Setup-ClaudeSandbox.ps1 again.' -ForegroundColor Yellow
    exit 1
}
try {
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $SandboxPath = $config.sandboxPath
}
catch {
    Write-Host "Sandbox config is invalid: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
if ([string]::IsNullOrWhiteSpace($SandboxPath)) {
    Write-Host 'Sandbox config does not define sandboxPath.' -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $SandboxPath)) {
    Write-Host "Sandbox path does not exist: $SandboxPath" -ForegroundColor Red
    exit 1
}

# Guard: this must run as the sandbox user, not whoever launched it. If the
# bootstrap is invoked directly (without launch-as), refuse - running as the wrong user
# silently defeats the boundary.
$me = $env:USERNAME
if ($me -ne 'ClaudeSandbox') {
    Write-Host "Refusing to run: expected user 'ClaudeSandbox' but running as '$me'." -ForegroundColor Red
    Write-Host 'Launch via Start-ClaudeSandbox.ps1 (which uses launch-as), not directly.' -ForegroundColor Yellow
    exit 1
}
Write-Host "claude-win-sandbox $Version" -ForegroundColor Cyan
Write-Host "Running as: $me" -ForegroundColor Green
Write-Host 'Check for newer versions: https://github.com/fmuecke/claude-win-sandbox' -ForegroundColor DarkGray
Write-Host ""

function Set-ClaudeSandboxWindowTitle {
    try {
        $Host.UI.RawUI.WindowTitle = 'Claude Sandbox'
    }
    catch {
        # Some non-console hosts do not expose a mutable window title.
    }
}

function Set-CheckClaudeSandboxAlias {
    if (Test-Path $CheckScript) {
        Set-Alias -Name Check-ClaudeSandbox -Value $CheckScript -Scope Global
        Write-Host "Run 'Check-ClaudeSandbox' anytime to verify the sandbox setup." -ForegroundColor DarkGray
    }
    else {
        Write-Host "Sandbox checker missing: $CheckScript" -ForegroundColor Yellow
        Write-Host 'Run Setup-ClaudeSandbox.ps1 again to deploy it.' -ForegroundColor Yellow
    }
}

function Set-ClaudeCodeSettings {
    $claudeConfigDir = Join-Path $env:USERPROFILE '.claude'
    $settingsFile = Join-Path $claudeConfigDir 'settings.json'

    if (-not (Test-Path $claudeConfigDir)) {
        New-Item -Path $claudeConfigDir -ItemType Directory -Force | Out-Null
    }

    $settings = [pscustomobject]@{}
    if (Test-Path $settingsFile) {
        try {
            $settings = Get-Content $settingsFile -Raw | ConvertFrom-Json
            if ($null -eq $settings -or $settings -isnot [pscustomobject]) {
                $settings = [pscustomobject]@{}
            }
        }
        catch {
            Write-Host "Claude settings file is invalid JSON; rewriting managed values in $settingsFile." -ForegroundColor Yellow
            $settings = [pscustomobject]@{}
        }
    }

    # These per-user settings are managed by this dev shell and rewritten on every launch.
    if (-not ($settings.PSObject.Properties.Name -contains 'env') -or
        $null -eq $settings.env -or
        $settings.env -isnot [pscustomobject]) {
        $settings | Add-Member -MemberType NoteProperty -Name 'env' -Value ([pscustomobject]@{}) -Force
    }

    $settings.env | Add-Member -MemberType NoteProperty -Name 'CLAUDE_CODE_USE_POWERSHELL_TOOL' -Value '1' -Force
    $settings.env | Add-Member -MemberType NoteProperty -Name 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC' -Value '1' -Force
    $settings | Add-Member -MemberType NoteProperty -Name 'defaultShell' -Value 'powershell' -Force
    $settings | Add-Member -MemberType NoteProperty -Name 'autoUpdatesChannel' -Value 'stable' -Force

    $settings | ConvertTo-Json -Depth 8 | Set-Content -Path $settingsFile -Encoding utf8
    Write-Host "Managed Claude settings written to $settingsFile." -ForegroundColor DarkGray
    Write-Host ""
}

function Write-SandboxNetworkExposureWarning {
    $mappedDrives = @()
    try {
        $mappedDrives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop |
            Where-Object { $_.DisplayRoot -like '\\*' })
    }
    catch {
        $mappedDrives = @()
    }

    $persistentMappings = @()
    try {
        if (Test-Path 'HKCU:\Network') {
            $persistentMappings = @(Get-ChildItem -Path 'HKCU:\Network' -ErrorAction Stop | ForEach-Object {
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                    [pscustomobject]@{
                        Drive      = "$($_.PSChildName):"
                        RemotePath = [string]$props.RemotePath
                        UserName   = [string]$props.UserName
                    }
                })
        }
    }
    catch {
        $persistentMappings = @()
    }

    $networkShortcuts = @()
    $shortcutDir = Join-Path $env:APPDATA 'Microsoft\Windows\Network Shortcuts'
    try {
        if (Test-Path $shortcutDir) {
            $networkShortcuts = @(Get-ChildItem -Path $shortcutDir -Force -ErrorAction Stop)
        }
    }
    catch {
        $networkShortcuts = @()
    }

    if ((-not $mappedDrives) -and (-not $persistentMappings) -and (-not $networkShortcuts)) {
        return
    }

    Write-Host 'Warning: this sandbox profile has network access hints.' -ForegroundColor Yellow
    Write-Host 'Review these before starting Claude if this machine is domain joined.' -ForegroundColor Yellow

    foreach ($drive in $mappedDrives) {
        Write-Host "  mapped drive $($drive.Name): -> $($drive.DisplayRoot)" -ForegroundColor Yellow
    }
    foreach ($mapping in $persistentMappings) {
        $asUser = if ([string]::IsNullOrWhiteSpace($mapping.UserName)) { 'default credentials' } else { $mapping.UserName }
        Write-Host "  persistent drive $($mapping.Drive) -> $($mapping.RemotePath) ($asUser)" -ForegroundColor Yellow
    }
    foreach ($shortcut in $networkShortcuts) {
        Write-Host "  network shortcut $($shortcut.Name)" -ForegroundColor Yellow
    }
}

Set-ClaudeSandboxWindowTitle
Write-SandboxNetworkExposureWarning
Set-ClaudeCodeSettings
Set-CheckClaudeSandboxAlias

$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -format json | ConvertFrom-Json
Import-Module (Join-Path $vs.installationPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstanceId $vs.instanceId -SkipAutomaticLocation -DevCmdArguments '-arch=x64'
Set-ClaudeSandboxWindowTitle
Set-Location $SandboxPath

# Ensure THIS user's per-user Claude install is on PATH. Self-contained: no
# dependency on the persisted User PATH. Prepend so the sandbox user's own copy
# wins over any machine-wide / other-profile install that may be on PATH - the
# install must live inside this profile to stay within the boundary.
$claudeBin = Join-Path $env:USERPROFILE '.local\bin'
$claudeBinFull = [System.IO.Path]::GetFullPath($claudeBin).TrimEnd('\')
$claudeBinOnPath = @($env:PATH -split ';') | Where-Object {
    if ([string]::IsNullOrWhiteSpace($_)) {
        $false
    }
    else {
        try {
            [System.IO.Path]::GetFullPath($_).TrimEnd('\') -ieq $claudeBinFull
        }
        catch {
            $_.TrimEnd('\') -ieq $claudeBinFull
        }
    }
}
if (-not $claudeBinOnPath) {
    $env:PATH = if ([string]::IsNullOrWhiteSpace($env:PATH)) { $claudeBin } else { "$claudeBin;$env:PATH" }
}

# Verify claude resolves; if not, tell the user how to install it (as THIS user).
if (Get-Command claude.exe -ErrorAction SilentlyContinue) {
    Write-Host "Ready for claude'ing in $SandboxPath." -ForegroundColor Cyan
    Write-Host "Update version with 'claude update'." -ForegroundColor Gray
    Write-Host ""
}
else {
    Write-Host "Ready in $SandboxPath, but 'claude' was not found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host 'Install it AS THIS USER (do not use a machine-wide install):' -ForegroundColor Yellow
    Write-Host '  irm https://claude.ai/install.ps1 | iex' -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Then simply run 'claude' in this shell." -ForegroundColor DarkGray
    Write-Host ""
}
