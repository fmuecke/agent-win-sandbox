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
        $UserNetLockExe = 'Invoke-TestNetworkLock'
        $events = [Collections.Generic.List[string]]::new()
        $warnings = [Collections.Generic.List[string]]::new()

        function Start-NetworkSandbox { $events.Add('proxy') }
        function Invoke-TestNetworkLock {
            param($Operation, $UserOption, $User, $PortOption, $Port)
            if ($User -ne 'AgentSandbox' -or $Port -ne 18080) { throw 'Wrong network-lock target.' }
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
        if (($events -join ',') -ne $expected) { throw "$case : unexpected order: $events" }
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

# Load only the port-selection functions, with process/listener/input seams mocked.
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
        $NetworkSandboxConfig = 'fixture.ini'
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
        function Test-Path { param($LiteralPath, $PathType) $case -ne 'missing-config' }
        function Invoke-TestProxyStatus {
            param($Operation, $Config)
            if ($Operation -ne 'status' -or $Config -ne 'fixture.ini') { throw 'Wrong proxy status query.' }
            $global:LASTEXITCODE = 0
            $statusPid = if ($case -eq 'wrong-pid') { 99 } else { 42 }
            $statusPort = if ($case -eq 'wrong-port') { 8081 } else { $requestedPort }
            "network-sandbox: running (pid $statusPid) on 127.0.0.1:$statusPort -config fixture.ini"
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
