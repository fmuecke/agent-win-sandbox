# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0

# Exercise the shared configuration functions. No host changes.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\bootstrap\AgentSandboxConfig.ps1')

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ("agent-sandbox-config-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

function Read-Fixture {
    param([string]$Json)

    $path = Join-Path $fixtureRoot 'config.json'
    Set-Content -LiteralPath $path -Value $Json -Encoding utf8NoBOM
    return Read-AgentSandboxConfig -Path $path
}

function Get-ValidSettings {
    return Read-AgentSandboxConfig -Path (Join-Path $PSScriptRoot '..\config\agent-sandbox.json')
}

function Assert-Rejected {
    param([string]$Name, [scriptblock]$Action, [string]$Pattern)

    try { & $Action }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "$Name : wrong error: $($_.Exception.Message)"
        }
        Write-Output "PASS: rejects $Name"
        return
    }
    throw "$Name : was accepted."
}

try {
    # The shipped defaults are valid and lock only the proxy endpoint.
    $defaults = Get-ValidSettings
    $warnings = Test-AgentSandboxSettings -Settings $defaults
    if ($warnings.Count -ne 0) { throw 'Defaults produce warnings.' }
    if ((Get-AgentSandboxLockEndpoints -Settings $defaults) -ne '127.0.0.1:8080') { throw 'Default lock endpoints are wrong.' }
    Write-Output 'PASS: defaults'

    # Duplicate keys would otherwise resolve last-wins and hide an entry.
    Assert-Rejected 'duplicate key' { Read-Fixture '{"proxy":{"port":1,"port":2}}' } 'Duplicate config key: proxy\.port'
    Assert-Rejected 'case-variant key' { Read-Fixture '{"workspace":"a","Workspace":"b"}' } 'Duplicate config key'

    # Merge: objects merge by key; lists replace; omitted keys keep their value.
    $override = Read-Fixture '{"proxy":{"allowedHosts":["example.com:443"]},"directEndpoints":[{"endpoint":"10.0.0.5:1433","label":"Database server"}]}'
    $merged = Merge-AgentSandboxSettings -Base $defaults -Override $override
    if ($merged.proxy.port -ne 8080 -or ($merged.proxy.allowedHosts -join ',') -ne 'example.com:443' -or
        $merged.workspace -ne 'C:\AgentSandbox') {
        throw 'Merge did not replace lists and keep omitted keys.'
    }
    if ($defaults.proxy.allowedHosts.Count -ne 6) { throw 'Merge modified its base.' }
    $null = Test-AgentSandboxSettings -Settings $merged
    if ((Get-AgentSandboxLockEndpoints -Settings $merged) -ne '127.0.0.1:8080,10.0.0.5:1433') { throw 'Merged lock endpoints are wrong.' }
    Write-Output 'PASS: merge'

    # Endpoint normalization.
    foreach ($case in @(
            @('10.0.0.5:1433', '10.0.0.5:1433'),
            @('[2001:DB8:0:0::5]:443', '[2001:db8::5]:443'),
            @('[::ffff:10.0.0.5]:22', '10.0.0.5:22')
        )) {
        $actual = ConvertTo-AgentSandboxEndpoint -Endpoint $case[0]
        if ($actual -cne $case[1]) { throw "Endpoint $($case[0]) normalized to $actual." }
    }
    Write-Output 'PASS: endpoint normalization'

    $endpointCases = [ordered]@{
        'host name'        = @('db.example.com:1433', 'host names are not allowed')
        'IPv4 shorthand'   = @('10.5:1433', 'host names are not allowed')
        'missing port'     = @('10.0.0.5', 'host names are not allowed')
        'port zero'        = @('10.0.0.5:0', 'invalid port')
        'port too large'   = @('10.0.0.5:65536', 'invalid port')
        'bad octet'        = @('10.0.0.256:22', 'invalid IP')
        'IPv6 zone id'     = @('[fe80::1%3]:22', 'host names are not allowed')
        'IPv4 wildcard'    = @('0.0.0.0:22', 'wildcard')
        'IPv6 wildcard'    = @('[::]:22', 'wildcard')
    }
    foreach ($name in $endpointCases.Keys) {
        $endpoint, $pattern = $endpointCases[$name]
        Assert-Rejected $name { ConvertTo-AgentSandboxEndpoint -Endpoint $endpoint } $pattern
    }

    # Settings validation.
    $settingCases = [ordered]@{
        'unknown top-level key'  = @({ param($s) $s.directEndpoint = @() }, "Unknown top-level setting 'directEndpoint'")
        'missing key'            = @({ param($s) $s.Remove('directEndpoints') }, "Missing top-level setting 'directEndpoints'")
        'setup in settings'      = @({ param($s) $s.setup = @{} }, "Unknown top-level setting 'setup'")
        'relative workspace'     = @({ param($s) $s.workspace = 'AgentSandbox' }, 'absolute local path')
        'UNC workspace'          = @({ param($s) $s.workspace = '\\server\share\AgentSandbox' }, 'absolute local path')
        'workspace name'         = @({ param($s) $s.workspace = 'C:\Work' }, "directory name 'AgentSandbox'")
        'unknown proxy key'      = @({ param($s) $s.proxy.privateAddresses = 'allow' }, "Unknown proxy setting 'privateAddresses'")
        'string port'            = @({ param($s) $s.proxy.port = '8080' }, 'proxy.port')
        'port out of range'      = @({ param($s) $s.proxy.port = 70000 }, 'proxy.port')
        'host list not a list'   = @({ param($s) $s.proxy.allowedHosts = 'example.com:443' }, 'must be a list')
        'host without port'      = @({ param($s) $s.proxy.allowedHosts = @('example.com') }, '<host>:<port>')
        'endpoint without label' = @({ param($s) $s.directEndpoints = @(@{ endpoint = '10.0.0.5:22' }) }, "Missing directEndpoints setting 'label'")
        'blank label'            = @({ param($s) $s.directEndpoints = @(@{ endpoint = '10.0.0.5:22'; label = ' ' }) }, 'one-line label')
        'multi-line label'       = @({ param($s) $s.directEndpoints = @(@{ endpoint = '10.0.0.5:22'; label = "a`nb" }) }, 'one-line label')
        'proxy as endpoint'      = @({ param($s) $s.directEndpoints = @(@{ endpoint = '127.0.0.1:8080'; label = 'proxy' }) }, 'proxy endpoint')
        'duplicate endpoint'     = @({ param($s) $s.directEndpoints = @(@{ endpoint = '10.0.0.5:22'; label = 'a' }, @{ endpoint = '[::ffff:10.0.0.5]:22'; label = 'b' }) }, 'more than once')
        'too many endpoints'     = @({ param($s) $s.directEndpoints = @(1..32 | ForEach-Object { @{ endpoint = "10.0.0.$($_):22"; label = 'host' } }) }, 'at most 32')
    }
    foreach ($name in $settingCases.Keys) {
        $mutate, $pattern = $settingCases[$name]
        $settings = Get-ValidSettings
        & $mutate $settings
        Assert-Rejected $name { Test-AgentSandboxSettings -Settings $settings } $pattern
    }

    # 31 direct endpoints plus the proxy fill the lock exactly.
    $settings = Get-ValidSettings
    $settings.directEndpoints = @(1..31 | ForEach-Object { @{ endpoint = "10.0.0.$($_):22"; label = 'host' } })
    $null = Test-AgentSandboxSettings -Settings $settings
    Write-Output 'PASS: endpoint limit'

    # Loopback endpoints are allowed but widen access, so they warn.
    $settings = Get-ValidSettings
    $settings.directEndpoints = @(@{ endpoint = '127.0.0.1:5432'; label = 'Local database' }, @{ endpoint = '[::1]:6379'; label = 'Local cache' })
    $warnings = Test-AgentSandboxSettings -Settings $settings
    if ($warnings.Count -ne 2 -or $warnings[0] -notmatch 'Local database') { throw 'Loopback endpoints did not warn.' }
    Write-Output 'PASS: loopback warning'

    # The hash ignores the generated setup section and formatting, but sees setting changes.
    $config = Read-Fixture '{"workspace":"C:\\AgentSandbox","proxy":{"port":8080,"allowedHosts":[]},"directEndpoints":[],"setup":{"version":"1"}}'
    $reformatted = Read-Fixture "{`n  `"directEndpoints`": [],`n  `"workspace`": `"C:\\AgentSandbox`",`n  `"proxy`": { `"port`": 8080, `"allowedHosts`": [] },`n  `"setup`": { `"version`": `"2`" }`n}"
    $changed = Read-Fixture '{"workspace":"C:\\AgentSandbox","proxy":{"port":8081,"allowedHosts":[]},"directEndpoints":[],"setup":{"version":"1"}}'
    if ((Get-AgentSandboxSettingsHash -Config $config) -ne (Get-AgentSandboxSettingsHash -Config $reformatted)) {
        throw 'Hash depends on formatting, top-level order, or setup metadata.'
    }
    if ((Get-AgentSandboxSettingsHash -Config $config) -eq (Get-AgentSandboxSettingsHash -Config $changed)) {
        throw 'Hash missed a settings change.'
    }
    Write-Output 'PASS: settings hash'

    # Setup precedence: defaults < installed < -ConfigFile < -SandboxPath/-ProxyPort.
    $setupSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Setup-AgentSandbox.ps1') -Raw
    $ast = [Management.Automation.Language.Parser]::ParseInput($setupSource, [ref]$null, [ref]$null)
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-Settings'
        }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
    $SettingsDefaultsSource = Join-Path $PSScriptRoot '..\config\agent-sandbox.json'
    $installed = Read-Fixture '{"workspace":"D:\\AgentSandbox","proxy":{"port":9000,"allowedHosts":["installed.test:443"]},"directEndpoints":[{"endpoint":"10.0.0.1:22","label":"Build host"}]}'
    $overridePath = Join-Path $fixtureRoot 'override.json'
    Set-Content -LiteralPath $overridePath -Encoding utf8NoBOM -Value '{"proxy":{"allowedHosts":["override.test:443"]},"directEndpoints":[]}'
    $script:prompts = 0
    function Read-Host { param($Prompt) $script:prompts++; '' }

    $ConfigFile = $null; $SandboxPath = $null; $ProxyPort = 0
    $resolved = Resolve-Settings -InstalledSettings $null
    if ($resolved.workspace -ne 'C:\AgentSandbox' -or $resolved.proxy.port -ne 8080 -or $script:prompts -ne 1) {
        throw 'New installation must prompt for the workspace and use defaults.'
    }

    $script:prompts = 0
    $resolved = Resolve-Settings -InstalledSettings $installed
    if ($resolved.workspace -ne 'D:\AgentSandbox' -or $resolved.proxy.port -ne 9000 -or
        ($resolved.proxy.allowedHosts -join ',') -ne 'installed.test:443' -or $resolved.directEndpoints.Count -ne 1 -or $script:prompts -ne 0) {
        throw 'Update must keep installed settings without prompting.'
    }

    $ConfigFile = $overridePath
    $resolved = Resolve-Settings -InstalledSettings $installed
    if ($resolved.workspace -ne 'D:\AgentSandbox' -or $resolved.proxy.port -ne 9000 -or
        ($resolved.proxy.allowedHosts -join ',') -ne 'override.test:443' -or $resolved.directEndpoints.Count -ne 0) {
        throw '-ConfigFile must replace the lists it names and keep other settings.'
    }

    $SandboxPath = 'E:\AgentSandbox'; $ProxyPort = 9100
    $resolved = Resolve-Settings -InstalledSettings $installed
    if ($resolved.workspace -ne 'E:\AgentSandbox' -or $resolved.proxy.port -ne 9100 -or $script:prompts -ne 0) {
        throw 'Parameters must override -ConfigFile and installed settings.'
    }

    Set-Content -LiteralPath $overridePath -Encoding utf8NoBOM -Value '{"setup":{"proxyOwnerSid":"S-1-1-0"}}'
    Assert-Rejected '-ConfigFile with setup section' { Resolve-Settings -InstalledSettings $installed } "must not contain the generated 'setup'"
    Write-Output 'PASS: setup settings precedence'
}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
