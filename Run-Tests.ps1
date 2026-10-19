# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0
<#
.SYNOPSIS
    Runs all PowerShell regression suites in separate processes.
.PARAMETER ProxyExecutable
    Optional allowproxy executable for the proxy suite's binary integration test.
.EXAMPLE
    .\Run-Tests.ps1
.EXAMPLE
    .\Run-Tests.ps1 -ProxyExecutable C:\tools\allowproxy.exe
#>

[CmdletBinding()]
param(
    [string]$ProxyExecutable
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

# --- Discover test suites -----------------------------------------------------
$powerShell = Join-Path $PSHOME 'pwsh.exe'
$testFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'tests') `
        -Filter '*.Tests.ps1' -File -Recurse | Sort-Object FullName)
if ($testFiles.Count -eq 0) {
    throw 'No test suites found.'
}
if ($ProxyExecutable) {
    $ProxyExecutable = (Resolve-Path -LiteralPath $ProxyExecutable).Path
}

# --- Run every suite ----------------------------------------------------------
$failures = [Collections.Generic.List[string]]::new()
foreach ($test in $testFiles) {
    Write-Host "Running $($test.Name)" -ForegroundColor Cyan
    $testArguments = @()
    if ($ProxyExecutable -and $test.Name -eq 'Test-AgentSandboxProxy.Tests.ps1') {
        $testArguments = @('-ProxyExecutable', $ProxyExecutable)
    }

    & $powerShell -NoLogo -NoProfile -NonInteractive -File $test.FullName @testArguments
    if ($LASTEXITCODE -ne 0) {
        $failures.Add($test.Name)
        Write-Host "FAIL: $($test.Name) (exit code $LASTEXITCODE)" -ForegroundColor Red
    }
    else {
        Write-Host "PASS: $($test.Name)" -ForegroundColor Green
    }
}

Write-Host "Results: $($testFiles.Count - $failures.Count) passed, $($failures.Count) failed."
if ($failures.Count -gt 0) {
    exit 1
}
exit 0
