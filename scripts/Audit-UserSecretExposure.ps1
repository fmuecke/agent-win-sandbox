# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

# Audit-UserSecretExposure.ps1
# Demonstrates which secret-bearing resources are accessible to the current user.
# It does not decrypt or print secret values.

$ErrorActionPreference = "Continue"

function Write-Section([string]$Title) {
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

function Test-ReadableFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $stream.Dispose()
        return $true
    }
    catch {
        return $false
    }
}

Write-Host "Running as: $env:USERDOMAIN\$env:USERNAME"
Write-Host "Profile:    $env:USERPROFILE"

Write-Section "Windows Credential Manager entries"

# Lists target names and types, but not passwords.
$cmdkeyOutput = cmdkey.exe /list 2>&1
$cmdkeyOutput

$credentialTargets = @(
    $cmdkeyOutput |
    Select-String '^\s*Target:' |
    ForEach-Object { $_.Line.Trim() }
)

Write-Host "`nVisible credential targets: $($credentialTargets.Count)"

Write-Section "SSH material"

$sshDirectory = Join-Path $env:USERPROFILE ".ssh"

if (Test-Path -LiteralPath $sshDirectory) {
    Get-ChildItem -LiteralPath $sshDirectory -Force -File |
    Select-Object Name,
    Length,
    LastWriteTime,
    @{Name = "Readable"; Expression = {
            Test-ReadableFile $_.FullName
        }
    },
    @{Name = "LikelySensitive"; Expression = {
            $_.Name -notmatch '\.pub$|known_hosts|config'
        }
    } |
    Format-Table -AutoSize
}
else {
    Write-Host "No .ssh directory found."
}

Write-Section "Common secret-bearing files"

$paths = @(
    "$env:USERPROFILE\.git-credentials"
    "$env:USERPROFILE\.gitconfig"
    "$env:USERPROFILE\.npmrc"
    "$env:USERPROFILE\.pypirc"
    "$env:USERPROFILE\.docker\config.json"
    "$env:USERPROFILE\.azure\accessTokens.json"
    "$env:USERPROFILE\.azure\azureProfile.json"
    "$env:USERPROFILE\.aws\credentials"
    "$env:USERPROFILE\.config\gh\hosts.yml"
    "$env:APPDATA\GitHub CLI\hosts.yml"
    "$env:APPDATA\NuGet\NuGet.Config"
    "$env:APPDATA\Microsoft\UserSecrets"
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
    "$env:APPDATA\Mozilla\Firefox\Profiles"
)

$paths |
ForEach-Object {
    $expanded = [Environment]::ExpandEnvironmentVariables($_)

    [pscustomobject]@{
        Path     = $expanded
        Exists   = Test-Path -LiteralPath $expanded
        Readable = if (Test-Path -LiteralPath $expanded -PathType Leaf) {
            Test-ReadableFile $expanded
        }
        else {
            $null
        }
    }
} |
Where-Object Exists |
Format-Table -Wrap

Write-Section "Environment variables with secret-like names"

$secretNamePattern =
'TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CONNECTION[_-]?STRING|PAT'

Get-ChildItem Env: |
Where-Object Name -Match $secretNamePattern |
Select-Object Name,
@{Name = "ValuePresent"; Expression = {
        -not [string]::IsNullOrEmpty($_.Value)
    }
},
@{Name = "Length"; Expression = {
        if ($null -eq $_.Value) { 0 } else { $_.Value.Length }
    }
} |
Format-Table -AutoSize

Write-Section "Browser profile data"

$browserFiles = @(
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
)

$browserFiles |
ForEach-Object {
    $path = [Environment]::ExpandEnvironmentVariables($_)

    if (Test-Path -LiteralPath $path) {
        [pscustomobject]@{
            Path     = $path
            Size     = (Get-Item -LiteralPath $path).Length
            Readable = Test-ReadableFile $path
        }
    }
} |
Format-Table -Wrap

Write-Section "PowerShell history"

$historyPath =
(Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath

if ($historyPath) {
    [pscustomobject]@{
        Path     = $historyPath
        Exists   = Test-Path -LiteralPath $historyPath
        Readable = Test-ReadableFile $historyPath
    } | Format-List
}

Write-Section "Summary"

Write-Host @"
This user context can potentially access:

- Credential Manager entry metadata
- SSH private-key files
- CLI authentication configuration
- cloud and package-manager credentials
- browser cookie and login databases
- secret-like environment variables
- PowerShell command history

Being 'encrypted at rest' does not necessarily protect a secret from a process
running interactively as the same user.
"@