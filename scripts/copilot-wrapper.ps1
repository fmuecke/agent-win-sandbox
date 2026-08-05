<#
.SYNOPSIS
    Installs, updates, authenticates, and launches GitHub Copilot CLI on Windows.

.DESCRIPTION
    Installs the official Windows x64 release in the current user's
    ~/.local/bin directory and verifies it against GitHub's published
    SHA256SUMS.txt. A fine-grained PAT is stored in the current user's
    persistent COPILOT_GITHUB_TOKEN environment variable.

.EXAMPLE
    .\copilot-wrapper.ps1
    .\copilot-wrapper.ps1 --help
    .\copilot-wrapper.ps1 -SetToken
    .\copilot-wrapper.ps1 -ClearToken
#>
[CmdletBinding()]
param(
    [switch]$SkipUpdate,
    [switch]$SetToken,
    [switch]$ClearToken,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CopilotArguments
)

$ErrorActionPreference = 'Stop'

$CopilotBin = Join-Path $env:USERPROFILE '.local\bin'
$CopilotExe = Join-Path $CopilotBin 'copilot.exe'
$ArchiveName = 'copilot-win32-x64.zip'
$ArchiveUri = "https://github.com/github/copilot-cli/releases/latest/download/$ArchiveName"
$ChecksumsUri = 'https://github.com/github/copilot-cli/releases/latest/download/SHA256SUMS.txt'

function Install-Copilot {
    $tempRoot = Join-Path $env:TEMP ("agent-sandbox-copilot-" + [guid]::NewGuid().ToString('N'))
    $archivePath = Join-Path $tempRoot $ArchiveName
    $checksumsPath = Join-Path $tempRoot 'SHA256SUMS.txt'
    $extractPath = Join-Path $tempRoot 'extracted'

    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        Invoke-WebRequest -Uri $ArchiveUri -OutFile $archivePath
        Invoke-WebRequest -Uri $ChecksumsUri -OutFile $checksumsPath

        $checksumLine = Get-Content $checksumsPath |
        Where-Object { $_ -match "^[0-9a-fA-F]{64}\s+$([regex]::Escape($ArchiveName))$" } |
        Select-Object -First 1
        if (-not $checksumLine) {
            throw "No checksum for $ArchiveName was found in SHA256SUMS.txt."
        }

        $expectedSha256 = ($checksumLine -split '\s+', 2)[0]
        $actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        if ($actualSha256 -ine $expectedSha256) {
            throw "Copilot download hash mismatch. Expected $expectedSha256, got $actualSha256."
        }

        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force
        $executables = @(Get-ChildItem -LiteralPath $extractPath -Filter 'copilot.exe' -File -Recurse)
        if ($executables.Count -ne 1) {
            throw "Expected exactly one copilot.exe in the release archive; found $($executables.Count)."
        }

        New-Item -ItemType Directory -Path $CopilotBin -Force | Out-Null
        Copy-Item -LiteralPath $executables[0].FullName -Destination $CopilotExe -Force
        Write-Host "Installed and verified GitHub Copilot CLI: $CopilotExe" -ForegroundColor Green
    }
    finally {
        if (Test-Path $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Save-CopilotToken {
    Write-Host 'Create a user-owned fine-grained PAT with Copilot Requests as its only added permission and minimal repository access.' -ForegroundColor Yellow
    Write-Host 'The token will be stored in this sandbox user''s environment and is readable by all processes running as this user.' -ForegroundColor Yellow
    $secureToken = Read-Host 'Fine-grained GitHub PAT' -AsSecureString
    $plainToken = [pscredential]::new('token', $secureToken).GetNetworkCredential().Password
    if ($plainToken -notmatch '^github_pat_') {
        throw 'Copilot CLI requires a user-owned fine-grained PAT beginning with github_pat_.'
    }

    [Environment]::SetEnvironmentVariable('COPILOT_GITHUB_TOKEN', $plainToken, 'User')
    $env:COPILOT_GITHUB_TOKEN = $plainToken
    Write-Host 'Stored COPILOT_GITHUB_TOKEN for the sandbox user.' -ForegroundColor Green
}

function Get-CopilotToken {
    $token = [Environment]::GetEnvironmentVariable('COPILOT_GITHUB_TOKEN', 'Process')
    if ([string]::IsNullOrWhiteSpace($token)) {
        $token = [Environment]::GetEnvironmentVariable('COPILOT_GITHUB_TOKEN', 'User')
    }
    if ([string]::IsNullOrWhiteSpace($token)) {
        Save-CopilotToken
        $token = [Environment]::GetEnvironmentVariable('COPILOT_GITHUB_TOKEN', 'Process')
    }
    if ($token -notmatch '^github_pat_') {
        throw "COPILOT_GITHUB_TOKEN is not a fine-grained PAT. Run 'copilot -SetToken' to replace it."
    }
    return $token
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'GitHub Copilot CLI requires PowerShell 7 or later on Windows.'
}
if ($env:USERNAME -ne 'AgentSandbox') {
    throw "Refusing to run: expected user 'AgentSandbox' but running as '$env:USERNAME'."
}
if ($SetToken -and $ClearToken) {
    throw 'Use either -SetToken or -ClearToken, not both.'
}

if ($ClearToken) {
    $storedToken = [Environment]::GetEnvironmentVariable('COPILOT_GITHUB_TOKEN', 'User')
    $processToken = [Environment]::GetEnvironmentVariable('COPILOT_GITHUB_TOKEN', 'Process')
    if ([string]::IsNullOrWhiteSpace($storedToken) -and [string]::IsNullOrWhiteSpace($processToken)) {
        Write-Host 'No locally stored Copilot token was found.' -ForegroundColor Yellow
    }
    else {
        [Environment]::SetEnvironmentVariable('COPILOT_GITHUB_TOKEN', $null, 'User')
        Remove-Item Env:COPILOT_GITHUB_TOKEN -ErrorAction SilentlyContinue
        Write-Host 'Removed COPILOT_GITHUB_TOKEN for the sandbox user.' -ForegroundColor Green
    }
    return
}
if ($SetToken) {
    Save-CopilotToken
    if ($CopilotArguments.Count -eq 0) {
        return
    }
}

$installedNow = $false
if (-not (Test-Path $CopilotExe -PathType Leaf)) {
    $answer = Read-Host 'GitHub Copilot CLI is not installed. Download and install it now? [y/N]'
    if ($answer -notmatch '^[Yy](es)?$') {
        Write-Host 'Aborted.'
        return
    }

    Install-Copilot
    $installedNow = $true
}

if (-not $SkipUpdate -and -not $installedNow) {
    Write-Host 'Checking GitHub Copilot CLI for updates...'
    try {
        & $CopilotExe update
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Copilot update failed (exit code $LASTEXITCODE). Launching the installed version."
        }
    }
    catch {
        Write-Warning "Copilot update failed: $($_.Exception.Message). Launching the installed version."
    }
}

Get-CopilotToken | Out-Null
& $CopilotExe @CopilotArguments
$copilotExitCode = $LASTEXITCODE

exit $copilotExitCode
