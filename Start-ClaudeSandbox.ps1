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

# --- Pre-flight checks --------------------------------------------------------
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    Write-Error "User '$UserName' does not exist. Run Setup-ClaudeSandbox.ps1 first."
    exit 1
}
if (-not (Test-Path $BootstrapScript)) {
    Write-Error "Bootstrap not found at $BootstrapScript. Run Setup-ClaudeSandbox.ps1 first."
    exit 1
}
if (-not (Test-Path $ConfigFile)) {
    Write-Error "Config not found at $ConfigFile. Run Setup-ClaudeSandbox.ps1 first."
    exit 1
}
try {
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $sandboxPath = $config.sandboxPath
}
catch {
    Write-Error "Config at $ConfigFile is invalid: $($_.Exception.Message)"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($sandboxPath)) {
    Write-Error "Config at $ConfigFile does not define sandboxPath. Run Setup-ClaudeSandbox.ps1 again."
    exit 1
}
if (-not (Test-Path $sandboxPath)) {
    Write-Error "Sandbox path $sandboxPath does not exist. Run Setup-ClaudeSandbox.ps1 again."
    exit 1
}
Write-Host "Configured sandbox path: $sandboxPath" -ForegroundColor Cyan

# --- Launch -------------------------------------------------------------------
$inner = "powershell.exe -NoExit -ExecutionPolicy Bypass -File `"$BootstrapScript`""

Write-Host "Launching as '$UserName' in $sandboxPath ..." -ForegroundColor Green
Write-Host "(runas will prompt for the '$UserName' password.)" -ForegroundColor DarkGray

runas /user:$UserName $inner

if ($LASTEXITCODE -ne 0) {
    Write-Warning "runas returned exit code $LASTEXITCODE (wrong password, or the account lacks interactive logon)."
    Write-Host "Verify setup with: & '$CheckerScript'" -ForegroundColor Yellow
}
else {
    Write-Host "Launched. In the new window, run: claude" -ForegroundColor Cyan
}
