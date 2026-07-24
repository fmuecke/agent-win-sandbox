<#
.SYNOPSIS
    Launches Claude Code as a low-privilege user inside a Visual Studio Developer
    Shell, scoped to the ClaudeSandbox workspace stored in ProgramData config.
    Prompts for the password each launch.

.DESCRIPTION
    Part of claude-win-sandbox. Assumes Setup-ClaudeSandbox.ps1 has provisioned
    the low-priv user, sandbox ACLs, config, and the Dev Shell bootstrap.

    Launch uses runas.exe, which attaches the new process to an interactive
    desktop for the target user so the console accepts keyboard input.
    (Start-Process -Credential can produce a window that renders but won't accept
    typing - the "hung shell".) runas prompts for the password natively.

.EXAMPLE
    & "$env:ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1"
    Prompts for the password, launches a sandboxed Dev Shell in the workspace
    stored in the ProgramData config by setup.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$UserName = 'ClaudeSandbox'
$ProgramDataRoot = Join-Path $env:ProgramData 'claude-win-sandbox'
$BootstrapScript = Join-Path (Join-Path $ProgramDataRoot 'bootstrap') 'Enter-ClaudeDevShell.ps1'
$CheckerScript = Join-Path $ProgramDataRoot 'Check-ClaudeSandbox.ps1'
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'

function Stop-LauncherError {
    param([string]$Message)

    Write-Host $Message -ForegroundColor Red
    if (Test-Path $CheckerScript) {
        Write-Host "Verify setup with: & '$CheckerScript'" -ForegroundColor Yellow
    }
    Write-Host ""
    Read-Host 'Press Enter to close'
    exit 1
}

trap {
    Stop-LauncherError "Unexpected launcher error: $($_.Exception.Message)"
}

# --- Pre-flight checks --------------------------------------------------------
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    Stop-LauncherError "User '$UserName' does not exist. Run Setup-ClaudeSandbox.ps1 first."
}
if (-not (Test-Path $BootstrapScript)) {
    Stop-LauncherError "Bootstrap not found at $BootstrapScript. Run Setup-ClaudeSandbox.ps1 first."
}
if (-not (Test-Path $ConfigFile)) {
    Stop-LauncherError "Config not found at $ConfigFile. Run Setup-ClaudeSandbox.ps1 first."
}
try {
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $sandboxPath = $config.sandboxPath
}
catch {
    Stop-LauncherError "Config at $ConfigFile is invalid: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($sandboxPath)) {
    Stop-LauncherError "Config at $ConfigFile does not define sandboxPath. Run Setup-ClaudeSandbox.ps1 again."
}
if (-not (Test-Path $sandboxPath)) {
    Stop-LauncherError "Sandbox path $sandboxPath does not exist. Run Setup-ClaudeSandbox.ps1 again."
}
Write-Host "Configured sandbox path: $sandboxPath" -ForegroundColor Cyan

# --- Launch -------------------------------------------------------------------
$inner = "powershell.exe -NoExit -ExecutionPolicy Bypass -File `"$BootstrapScript`""

Write-Host "Launching as '$UserName' in $sandboxPath ..." -ForegroundColor Green
Write-Host "(runas will prompt for the '$UserName' password.)" -ForegroundColor DarkGray

runas /user:$UserName $inner

if ($LASTEXITCODE -ne 0) {
    Write-Warning "runas returned exit code $LASTEXITCODE (wrong password, cancelled prompt, or the account lacks interactive logon)."
    if (Test-Path $CheckerScript) {
        Write-Host "Verify setup with: & '$CheckerScript'" -ForegroundColor Yellow
    }
    Write-Host ""
    Read-Host 'Press Enter to close'
    exit 1
}
else {
    Write-Host "Launched. In the new window, run: claude" -ForegroundColor Cyan
}
