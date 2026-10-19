# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0

# Execute only the elevation prefix. UAC and all provisioning are replaced with
# a harmless child that records its parameters and returns a chosen exit code.
$ErrorActionPreference = 'Stop'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('agent-sandbox-elevation-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

function Invoke-TestProcess {
    param([Diagnostics.ProcessStartInfo]$StartInfo)

    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($StartInfo)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) {
        $process.Kill($true)
        throw 'Elevation fixture timed out.'
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    }
}

$mocks = @'
$plan = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'plan.json') -Raw | ConvertFrom-Json
function Test-Administrator {
    return $env:AGENT_SANDBOX_ELEVATION_TEST_CHILD -eq '1' -or $plan.AlreadyElevated
}
function Test-Path {
    param($LiteralPath, $PathType)
    return -not $plan.MissingPowerShell
}
function Start-Process {
    param($FilePath, [string]$ArgumentList, $Verb, [switch]$Wait, [switch]$PassThru)
    if ($FilePath -cne (Join-Path $PSHOME 'pwsh.exe') -or $Verb -ne 'RunAs' -or -not $Wait -or -not $PassThru) {
        throw 'Wrong elevation host or launch options.'
    }
    Set-Content -LiteralPath (Join-Path $PSScriptRoot 'started.txt') -Value $ArgumentList
    # Start-Process wraps ShellExecute errors, including UAC cancellation.
    if ($plan.StartError) { throw [InvalidOperationException]::new('Simulated process start failure.') }
    $info = [Diagnostics.ProcessStartInfo]::new($FilePath, $ArgumentList)
    $info.Environment['AGENT_SANDBOX_ELEVATION_TEST_CHILD'] = '1'
    $info.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($info)
    $process.WaitForExit()
    return $process
}
'@

try {
    foreach ($scriptName in 'Apply-Config.ps1', 'Setup-AgentSandbox.ps1') {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\$scriptName") -Raw
        if ($source -match '(?im)^#Requires -RunAsAdministrator') { throw "$scriptName blocks self-elevation." }
        $prefix = $source.Substring(0, $source.IndexOf('$UserName ='))
        $ast = [Management.Automation.Language.Parser]::ParseInput($prefix, [ref]$null, [ref]$null)
        $adminFunction = $ast.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-Administrator'
            }, $true)
        if (-not $adminFunction) { throw "$scriptName has no administrator check." }
        $prefix = $prefix.Remove($adminFunction.Extent.StartOffset, $adminFunction.Extent.Text.Length).
            Insert($adminFunction.Extent.StartOffset, $mocks)
        $fixture = Join-Path $fixtureRoot "setup space & ü ' $scriptName"
        $record = @'
$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'received.json')
exit ([int]$plan.ChildExitCode)
'@
        Set-Content -LiteralPath $fixture -Value ($prefix + $record) -Encoding utf8NoBOM

        $cases = @('success', 'failure', 'child-cancel', 'start-error', 'already-elevated', 'missing-pwsh')
        if ($scriptName -eq 'Setup-AgentSandbox.ps1') { $cases += 'parameters', 'quoted-path', 'invalid-port' }
        foreach ($case in $cases) {
            foreach ($name in 'started.txt', 'received.json') {
                Remove-Item -LiteralPath (Join-Path $fixtureRoot $name) -Force -ErrorAction SilentlyContinue
            }
            $childExit = switch ($case) { 'failure' { 37 } 'child-cancel' { 1223 } default { 0 } }
            @{
                AlreadyElevated = $case -eq 'already-elevated'
                MissingPowerShell = $case -eq 'missing-pwsh'
                StartError = $case -eq 'start-error'
                ChildExitCode = $childExit
            } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $fixtureRoot 'plan.json')
            $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
            foreach ($argument in '-NoProfile', '-File', $fixture) { $info.ArgumentList.Add($argument) }
            $info.WorkingDirectory = $fixtureRoot
            if ($case -eq 'parameters') {
                foreach ($argument in '-ConfigFile', ".\config space & ü ' [test].json", '-SandboxPath', "C:\space & ü ' \AgentSandbox\", '-ProxyPort', '18080') {
                    $info.ArgumentList.Add($argument)
                }
            }
            elseif ($case -eq 'quoted-path') {
                # Bind as an interactive PowerShell caller would; pwsh -File can
                # strip embedded quotes before the fixture sees the argument.
                $command = "& '$($fixture.Replace("'", "''"))' -SandboxPath 'C:\bad`" -ProxyPort 1234'; exit `$LASTEXITCODE"
                $info.ArgumentList.Clear()
                foreach ($argument in '-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))) {
                    $info.ArgumentList.Add($argument)
                }
            }
            elseif ($case -eq 'invalid-port') {
                foreach ($argument in '-ProxyPort', '65536') { $info.ArgumentList.Add($argument) }
            }
            $result = Invoke-TestProcess -StartInfo $info
            $expectedExit = switch ($case) {
                { $_ -in 'start-error', 'missing-pwsh', 'quoted-path', 'invalid-port' } { 1 }
                default { $childExit }
            }
            if ($result.ExitCode -ne $expectedExit) { throw "$scriptName $case : exit $($result.ExitCode), expected $expectedExit. $($result.Output)" }
            $shouldStart = $case -notin 'already-elevated', 'missing-pwsh', 'quoted-path', 'invalid-port'
            if ((Test-Path -LiteralPath (Join-Path $fixtureRoot 'started.txt')) -ne $shouldStart) {
                throw "$scriptName $case : wrong relaunch behavior."
            }
            $shouldContinue = $case -in 'success', 'failure', 'child-cancel', 'already-elevated', 'parameters'
            $receivedPath = Join-Path $fixtureRoot 'received.json'
            if ((Test-Path -LiteralPath $receivedPath) -ne $shouldContinue) { throw "$scriptName $case : wrong continuation behavior." }
            if ($shouldContinue) {
                $received = Get-Content -LiteralPath $receivedPath -Raw | ConvertFrom-Json -AsHashtable
                if ($case -eq 'parameters') {
                    if ($received.Count -ne 3 -or $received.ConfigFile -cne (Join-Path $fixtureRoot "config space & ü ' [test].json") -or
                        $received.SandboxPath -cne "C:\space & ü ' \AgentSandbox\" -or $received.ProxyPort -ne 18080) {
                        throw "Setup parameters changed during relaunch: $($received | ConvertTo-Json -Compress)"
                    }
                }
                elseif ($received.Count -ne 0) { throw 'Omitted parameters were added during relaunch.' }
            }
            if ($case -in 'success', 'failure', 'child-cancel', 'parameters') {
                $status = switch ($case) { 'failure' { 'failed' } 'child-cancel' { 'cancelled' } default { 'successfully' } }
                if ($result.Output -notmatch $status) { throw "$scriptName $case : missing result message. $($result.Output)" }
            }
            Write-Output "PASS: $scriptName elevation $case"
        }
    }
}
finally {
    if ([IO.Path]::GetDirectoryName($fixtureRoot) -ne [IO.Path]::GetTempPath().TrimEnd('\')) {
        throw "Unexpected fixture path: $fixtureRoot"
    }
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
