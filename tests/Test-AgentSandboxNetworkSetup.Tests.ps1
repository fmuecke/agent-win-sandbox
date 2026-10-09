# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0

# Execute only the network-lock section with mocked commands.
# Never provision accounts or change the host firewall.
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Setup-AgentSandbox.ps1') -Raw
$start = $source.IndexOf("`nStart-NetworkSandbox`r`n")
if ($start -lt 0) { $start = $source.IndexOf("`nStart-NetworkSandbox`n") }
if ($start -lt 0) { throw 'Network setup section not found.' }
$end = $source.IndexOf('# --- 2. Shared workspace permissions', $start)
if ($end -lt $start) { throw 'Network setup section end not found.' }
$networkSetup = [scriptblock]::Create($source.Substring($start, $end - $start))

foreach ($case in 'fresh', 'upgrade', 'apply-failure', 'verify-failure') {
    & {
        $UserName = 'AgentSandbox'
        $ProxyPort = 18080
        $WfpLockExe = 'Invoke-TestNetworkLock'
        $events = [Collections.Generic.List[string]]::new()
        $warnings = [Collections.Generic.List[string]]::new()

        function Start-NetworkSandbox { $events.Add('proxy') }
        function Invoke-TestNetworkLock {
            param($Operation, $UserOption, $User, $AllowOption, $Endpoint)
            if ($UserOption -ne '--user' -or $User -ne 'AgentSandbox' -or
                $AllowOption -ne '--allow' -or $Endpoint -ne '127.0.0.1:18080') {
                throw 'Wrong network-lock target.'
            }
            $events.Add($Operation)
            $global:LASTEXITCODE = if ($case -eq "$Operation-failure") { 1 } else { 0 }
        }
        function Get-NetFirewallRule { throw 'Setup must not query legacy firewall rules.' }
        function Remove-NetFirewallRule { throw 'Setup must not remove legacy firewall rules.' }
        function Write-Warning { param($Message) $warnings.Add($Message) }
        function Write-Host { }

        $failure = $null
        try { & $networkSetup }
        catch { $failure = $_ }
        $expected = switch ($case) {
            'apply-failure' { 'proxy,apply' }
            'verify-failure' { 'proxy,apply,verify' }
            default { 'proxy,apply,verify' }
        }
        if (($events -join ',') -ne $expected) { throw "$case : unexpected order: $events; setup failure: $failure" }
        $expectFailure = $case -in 'apply-failure', 'verify-failure'
        if ([bool]$failure -ne $expectFailure) { throw "$case : unexpected setup failure: $failure" }
        if ($warnings.Count -ne 0) { throw "$case : unexpected warning." }
        Write-Output "PASS: $case"
    }
}

# The installed-state checker must not require superseded firewall metadata or rules.
$checker = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Check-AgentSandbox.ps1') -Raw
if ($checker -match 'firewallMode|firewallRuleNames|Get-NetFirewall|HNetCfg\.FwPolicy2') {
    throw 'Checker still depends on legacy firewall policy.'
}
Write-Output 'PASS: checker has no legacy firewall requirements'

# Existing proxy state must have a JSON policy before setup can change it.
$start = $source.IndexOf('# Validate the policy and resolve port conflicts')
$end = $source.IndexOf('$ProxyPort = Resolve-ProxyPort', $start)
if ($start -lt 0 -or $end -lt $start) { throw 'Policy preflight section not found.' }
$policyPreflight = [scriptblock]::Create($source.Substring($start, $end - $start))
foreach ($case in 'fresh', 'existing-json', 'missing-json') {
    & {
        $NetworkSandboxStateRoot = 'C:\fixture'
        $NetworkSandboxConfig = 'C:\fixture\network-sandbox.json'
        $reads = [Collections.Generic.List[string]]::new()
        function Test-Path {
            param($LiteralPath, $PathType)
            if ($LiteralPath -eq $NetworkSandboxStateRoot) { return $case -ne 'fresh' }
            return $case -eq 'existing-json'
        }
        function Get-NetworkSandboxPolicy { $reads.Add('policy') }
        $failure = $null
        try { & $policyPreflight }
        catch { $failure = $_ }
        if ($case -eq 'missing-json') {
            if (-not $failure -or $failure.Exception.Message -notmatch 'no JSON policy' -or $reads.Count -ne 0) {
                throw 'Existing proxy state must not fall back to the default policy.'
            }
        }
        elseif ($failure -or $reads.Count -ne 1) { throw "$case : unexpected policy preflight result: $failure" }
        Write-Output "PASS: policy preflight $case"
    }
}

# Load only policy and port-selection functions, with external operations mocked.
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
foreach ($name in 'Get-NetworkSandboxPolicy', 'Install-NetworkSandboxPolicy', 'Test-ExistingSandboxProxyListener', 'Resolve-ProxyPort') {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if (-not $definition) { throw "Function not found: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

foreach ($lineEnding in "`n", "`r`n") {
    foreach ($case in 'fresh-logfile', 'fresh-no-logfile', 'existing-logfile', 'existing-no-logfile',
        'missing-port', 'invalid-json', 'duplicate-key', 'linked-policy') {
        & {
            $ProxyPort = 18080
            $NetworkSandboxStateRoot = 'C:\fixture'
            $NetworkSandboxConfig = Join-Path $NetworkSandboxStateRoot 'network-sandbox.json'
            $NetworkSandboxConfigSource = 'C:\source\network-sandbox.json'
            $existing = $case.StartsWith('existing-') -or $case -eq 'linked-policy'
            $lines = @('{', '  "port": 8080,', '  "loglevel": "debug",', '  "privateaddresses": "allow",')
            if ($case.EndsWith('-logfile')) { $lines += '  "logfile": "old.log",' }
            $lines += '  "allowed": ["example.com:443", "[2001:db8::1]:443"]', '}'
            $fixture = switch ($case) {
                'missing-port' { '{"allowed":["example.com:443"]}' }
                'invalid-json' { '{' }
                'duplicate-key' { '{"port":8080,"allowed":["first.test:443"],"allowed":["second.test:443"]}' }
                default { $lines -join $lineEnding }
            }
            $writes = [Collections.Generic.List[string]]::new()

            function Test-Path {
                param($LiteralPath, $PathType)
                $existing
            }
            function Get-Item {
                param($LiteralPath, [switch]$Force)
                $attributes = if ($case -eq 'linked-policy') { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Normal }
                [pscustomobject]@{ Attributes = $attributes }
            }
            function Get-Content {
                param($LiteralPath, [switch]$Raw)
                $expectedPath = if ($existing) { $NetworkSandboxConfig } else { $NetworkSandboxConfigSource }
                if ($LiteralPath -ne $expectedPath -or -not $Raw) { throw 'Wrong policy read.' }
                $fixture
            }
            function Set-Content {
                param($LiteralPath, $Value, $Encoding, [switch]$NoNewline)
                if ($LiteralPath -ne $NetworkSandboxConfig -or $Encoding -ne 'utf8NoBOM' -or -not $NoNewline) {
                    throw 'Wrong policy write.'
                }
                $writes.Add($Value)
            }
            function Write-Warning { }

            $failure = $null
            try { Install-NetworkSandboxPolicy }
            catch { $failure = $_ }
            if ($case -in 'missing-port', 'invalid-json', 'duplicate-key', 'linked-policy') {
                $expectedMessage = switch ($case) {
                    'missing-port' { 'no port setting' }
                    'invalid-json' { 'JSON|depth' }
                    'duplicate-key' { 'Duplicate proxy policy key' }
                    'linked-policy' { 'linked proxy policy' }
                }
                if (-not $failure -or $failure.Exception.Message -notmatch $expectedMessage -or $writes.Count -ne 0) {
                    throw "$case : expected rejection without writing: $failure"
                }
            }
            else {
                if ($failure -or $writes.Count -ne 1) {
                    throw "$case : policy was not updated correctly: $failure"
                }
                $actual = $writes[0] | ConvertFrom-Json
                if ($actual.port -ne 18080 -or $actual.logfile -cne 'C:\fixture\network-sandbox.log' -or
                    $actual.loglevel -cne 'debug' -or $actual.privateaddresses -cne 'allow' -or
                    ($actual.allowed -join ',') -cne 'example.com:443,[2001:db8::1]:443') {
                    throw "$case : policy settings or custom allowlist were lost."
                }
            }
            $endingName = if ($lineEnding -eq "`n") { 'LF' } else { 'CRLF' }
            Write-Output "PASS: proxy policy $case $endingName"
        }
    }
}

foreach ($case in 'free-default', 'free-custom', 'conflict', 'custom-conflict', 'invalid-and-occupied',
    'existing-proxy', 'legacy-proxy', 'other-executable', 'wrong-pid', 'wrong-port',
    'missing-config', 'second-listener', 'cancel', 'query-failure') {
    & {
        $NetworkSandboxExe = 'Invoke-TestProxyStatus'
        $LegacyNetworkSandboxExe = 'Invoke-LegacyProxyStatus'
        $NetworkSandboxConfig = 'fixture.json'
        $requestedPort = if ($case -in 'free-custom', 'custom-conflict') { 19090 } else { 8080 }
        $answers = [Collections.Generic.Queue[string]]::new()
        if ($case -eq 'invalid-and-occupied') {
            foreach ($answer in 'text', '0', '65536', '8080', '18080') { $answers.Enqueue($answer) }
        }
        elseif ($case -eq 'cancel') { $answers.Enqueue('') }
        else { $answers.Enqueue('18080') }
        $prompts = [Collections.Generic.List[string]]::new()
        $warnings = [Collections.Generic.List[string]]::new()

        function Get-NetTCPConnection {
            param($State, $ErrorAction)
            if ($State -ne 'Listen' -or $ErrorAction -ne 'Stop') { throw 'Unexpected listener query.' }
            if ($case -eq 'query-failure') { throw 'Simulated listener query failure.' }
            if ($case -notin 'free-default', 'free-custom') {
                [pscustomobject]@{ LocalPort = $requestedPort; OwningProcess = 42 }
                if ($case -eq 'second-listener') {
                    [pscustomobject]@{ LocalPort = $requestedPort; OwningProcess = 43 }
                }
            }
        }
        function Get-Process {
            param($Id, $ErrorAction)
            $path = switch ($case) {
                'legacy-proxy' { $LegacyNetworkSandboxExe }
                'other-executable' { 'C:\unrelated\network-sandbox.exe' }
                'conflict' { 'C:\unrelated\service.exe' }
                'custom-conflict' { 'C:\unrelated\service.exe' }
                'invalid-and-occupied' { 'C:\unrelated\service.exe' }
                'cancel' { 'C:\unrelated\service.exe' }
                default { $NetworkSandboxExe }
            }
            [pscustomobject]@{ Path = $path }
        }
        function Test-Path {
            param($LiteralPath, $PathType)
            if ($case -eq 'missing-config') { return $false }
            return $LiteralPath -eq $NetworkSandboxConfig
        }
        function Invoke-TestProxyStatus {
            param($Operation, $Config)
            if ($Operation -ne 'status' -or $Config -ne 'fixture.json') { throw 'Wrong proxy status query.' }
            $global:LASTEXITCODE = 0
            $statusPid = if ($case -eq 'wrong-pid') { 99 } else { 42 }
            $statusPort = if ($case -eq 'wrong-port') { 8081 } else { $requestedPort }
            "network-sandbox: running (pid $statusPid) on 127.0.0.1:$statusPort -config $Config"
        }
        function Invoke-LegacyProxyStatus {
            param($Operation, $Config)
            Invoke-TestProxyStatus -Operation $Operation -Config $Config
        }
        function Read-Host {
            param($Prompt)
            $prompts.Add($Prompt)
            if ($answers.Count -eq 0) { throw 'Unexpected additional prompt.' }
            $answers.Dequeue()
        }
        function Write-Warning { param($Message) $warnings.Add($Message) }

        $failure = $null
        try { $selectedPort = Resolve-ProxyPort -Port $requestedPort }
        catch { $failure = $_ }
        if ($case -in 'cancel', 'query-failure') {
            $expectedMessage = if ($case -eq 'cancel') { 'Setup cancelled' } else { 'listener query failure' }
            if (-not $failure -or $failure.Exception.Message -notmatch $expectedMessage) {
                throw "$case : expected failure was not reported: $failure"
            }
        }
        else {
            $noPrompt = $case -in 'free-default', 'free-custom', 'existing-proxy', 'legacy-proxy'
            $expectedPort = if ($noPrompt) { $requestedPort } else { 18080 }
            $expectedPrompts = if ($noPrompt) { 0 } elseif ($case -eq 'invalid-and-occupied') { 5 } else { 1 }
            if ($failure -or $selectedPort -ne $expectedPort -or $prompts.Count -ne $expectedPrompts) {
                throw "$case : wrong port or prompt count: port=$selectedPort, prompts=$($prompts.Count), failure=$failure"
            }
        }
        Write-Output "PASS: proxy port $case"
    }
}
