# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

<#
.SYNOPSIS
    Creates the distributable Agent Sandbox release archive.

.DESCRIPTION
    Packages the setup, removal, runtime, and user documentation files required
    to install and use Agent Sandbox. The archive version is read from
    Setup-AgentSandbox.ps1 so a release cannot be accidentally labeled with a
    different version.

.EXAMPLE
    .\Package-Release.ps1

.EXAMPLE
    .\Package-Release.ps1 -OutputDirectory C:\releases -Force
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "dist"),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ReleaseVersion {
    param(
        [string]$SetupScript
    )

    $setupContent = Get-Content -LiteralPath $SetupScript -Raw
    $matches = [regex]::Matches($setupContent, '(?m)^\$Version\s*=\s*''(?<version>\d+\.\d+\.\d+)''\s*$')
    if ($matches.Count -ne 1) {
        throw "Could not determine exactly one release version from $SetupScript."
    }

    return $matches[0].Groups['version'].Value
}

function Copy-ReleaseFile {
    param(
        [string]$RelativePath,
        [string]$SourceRoot,
        [string]$DestinationRoot
    )

    $sourcePath = Join-Path $SourceRoot $RelativePath
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Required release file is missing: $sourcePath"
    }

    $destinationPath = Join-Path $DestinationRoot $RelativePath
    $destinationDirectory = Split-Path -Path $destinationPath -Parent
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
}

# --- Release manifest ---------------------------------------------------------

$releaseFiles = @(
    'Setup-AgentSandbox.ps1',
    'Remove-AgentSandbox.ps1',
    'Start-AgentSandbox.ps1',
    'Check-AgentSandbox.ps1',
    'Test-AgentSandboxExposure.ps1',
    'Run-Demo.ps1',
    'Package-Release.ps1',
    'Apply-Config.ps1',
    'config\agent-sandbox.json',
    'config\managed-settings.json',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'bootstrap\AgentSandboxConfig.ps1',
    'bootstrap\Initialize-AgentSandboxShell.ps1',
    'bootstrap\Enter-DevShell.ps1',
    'bootstrap\Initialize-AgentSandboxDemo.ps1',
    'scripts\claude-wrapper.ps1',
    'scripts\copilot-wrapper.ps1',
    'docs\FULL-GUIDE.md',
    'docs\the-security-guide.md',
    'docs\threat-model.md',
    'docs\todo-and-decisions.md'
)

$setupScript = Join-Path $PSScriptRoot 'Setup-AgentSandbox.ps1'
$version = Get-ReleaseVersion -SetupScript $setupScript
$archiveName = "agent-win-sandbox-v$version.zip"
$archivePath = Join-Path $OutputDirectory $archiveName

if (Test-Path -LiteralPath $archivePath) {
    if (-not $Force) {
        throw "Release archive already exists: $archivePath. Use -Force to replace it."
    }

    Remove-Item -LiteralPath $archivePath -Force
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$stagingDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("agent-win-sandbox-release-" + [guid]::NewGuid().ToString('N'))

try {
    New-Item -ItemType Directory -Path $stagingDirectory | Out-Null
    foreach ($relativePath in $releaseFiles) {
        Copy-ReleaseFile -RelativePath $relativePath -SourceRoot $PSScriptRoot -DestinationRoot $stagingDirectory
    }

    Compress-Archive -Path (Join-Path $stagingDirectory '*') -DestinationPath $archivePath
    Write-Host "Created release archive: $archivePath" -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $stagingDirectory) {
        Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
    }
}
