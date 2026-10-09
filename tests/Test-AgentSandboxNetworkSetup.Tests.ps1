# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0

# Execute only the network sections of Apply-Config and setup with mocked
# commands. Never provision accounts or change the host firewall.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\bootstrap\AgentSandboxConfig.ps1')

function Get-ScriptSection {
    param([string]$Source, [string]$StartMarker, [string]$EndMarker)

    $start = $Source.IndexOf($StartMarker)
    $end = $Source.IndexOf($EndMarker, [Math]::Max($start, 0))
    if ($start -lt 0 -or $end -lt $start) { throw "Section not found: $StartMarker" }
    return [scriptblock]::Create($Source.Substring($start, $end - $start))
}

# --- Apply-Config network flow ----------------------------------------------
$applySource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Apply-Config.ps1') -Raw
$applyNetwork = Get-ScriptSection -Source $applySource -StartMarker '# --- Proxy policy' -EndMarker '# --- Record the applied settings'

foreach ($case in 'apply', 'port-in-use', 'stop-failure', 'apply-failure', 'verify-failure') {
    & {
        $UserName = 'AgentSandbox'
        $NetworkSandboxStateRoot = 'C:\fixture'
        $NetworkSandboxConfig = 'C:\fixture\network-sandbox.json'
        $ConfigFile = 'C:\fixture\config.json'
        $NetworkSandboxExe = 'Invoke-TestProxy'
        $WfpLockExe = 'Invoke-TestNetworkLock'
        $settings = Read-AgentSandboxConfig -Path (Join-Path $PSScriptRoot '..\config\agent-sandbox.json')
        $settings.proxy.port = 18080
        $settings.proxy.allowedHosts = @('example.com:443')
        $settings.directEndpoints = @(@{ endpoint = '10.0.0.5:1433'; label = 'Database server' })
        $proxyPort = 18080
        $lockEndpoints = Get-AgentSandboxLockEndpoints -Settings $settings
        $events = [Collections.Generic.List[string]]::new()
        $policies = [Collections.Generic.List[string]]::new()

        function Test-Path { param($LiteralPath, $PathType) $true }
        function Invoke-TestProxy {
            param($Operation, $ConfigOption, $Config)
            if ($Operation -ne 'stop' -or $Config -ne $NetworkSandboxConfig) { throw 'Wrong proxy operation.' }
            $events.Add('stop')
            $global:LASTEXITCODE = if ($case -eq 'stop-failure') { 1 } else { 0 }
        }
        function Get-NetTCPConnection {
            param($State, $LocalPort, $ErrorAction)
            if ($LocalPort -ne 18080) { throw 'Wrong port query.' }
            if ($case -eq 'port-in-use') { [pscustomobject]@{ OwningProcess = 42 } }
        }
        function Assert-NotLinked { param($Path) }
        function Set-Content {
            param($LiteralPath, $Value, $Encoding, [switch]$NoNewline)
            if ($LiteralPath -ne $NetworkSandboxConfig) { throw 'Wrong policy write.' }
            $events.Add('policy')
            $policies.Add($Value)
        }
        function Protect-AdminFile { param($Path) $events.Add('protect') }
        function Invoke-TestNetworkLock {
            param($Operation, $UserOption, $User, $AllowOption, $Endpoints)
            if ($User -ne 'AgentSandbox' -or $AllowOption -ne '--allow' -or
                $Endpoints -ne '127.0.0.1:18080,10.0.0.5:1433') {
                throw "Wrong network-lock target: $User $Endpoints"
            }
            $events.Add($Operation)
            $global:LASTEXITCODE = if ($case -eq "$Operation-failure") { 1 } else { 0 }
        }
        function Write-Step { }
        function Write-Host { }

        $failure = $null
        try { & $applyNetwork }
        catch { $failure = $_ }
        $expected = switch ($case) {
            'stop-failure' { 'stop' }
            'port-in-use' { 'stop' }
            'apply-failure' { 'stop,policy,protect,apply' }
            default { 'stop,policy,protect,apply,verify' }
        }
        if (($events -join ',') -ne $expected) { throw "$case : unexpected order: $events; failure: $failure" }
        if ([bool]$failure -ne ($case -ne 'apply')) { throw "$case : unexpected result: $failure" }
        if ($case -eq 'apply') {
            $policy = $policies[0] | ConvertFrom-Json
            if ($policy.port -ne 18080 -or $policy.privateaddresses -cne 'deny' -or
                $policy.logfile -cne 'C:\fixture\network-sandbox.log' -or ($policy.allowed -join ',') -cne 'example.com:443') {
                throw 'Generated proxy policy is wrong.'
            }
        }
        Write-Output "PASS: apply network $case"
    }
}

# Setup applies the network settings through Apply-Config only.
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Setup-AgentSandbox.ps1') -Raw
if ($source -match 'wfp-lock\S*\s+(apply|verify)|\$WfpLockExe\s+(apply|verify)|network-sandbox\.json.*Set-Content') {
    throw 'Setup must not apply the network lock or proxy policy itself.'
}
if ($source -notmatch '& \$ApplyConfigSource') { throw 'Setup does not run Apply-Config.' }
Write-Output 'PASS: setup delegates to Apply-Config'

# The installed-state checker must not require superseded firewall metadata or rules.
$checker = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Check-AgentSandbox.ps1') -Raw
if ($checker -match 'firewallMode|firewallRuleNames|Get-NetFirewall|HNetCfg\.FwPolicy2') {
    throw 'Checker still depends on legacy firewall policy.'
}
Write-Output 'PASS: checker has no legacy firewall requirements'

# Load only the port-selection functions, with external operations mocked.
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
foreach ($name in 'Test-ExistingSandboxProxyListener', 'Resolve-ProxyPort') {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if (-not $definition) { throw "Function not found: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
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
