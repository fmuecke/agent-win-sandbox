#requires -Version 7.0

# Load definitions and state only. Never run the host assessment entry point.
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Test-AgentSandboxExposure.ps1') -Raw
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
$start = $ast.ParamBlock.Extent.EndOffset
$end = $source.IndexOf('# --- Main ')
Invoke-Expression $source.Substring($start, $end - $start)

Add-Type -TypeDefinition @'
using System.Collections.Generic;
public sealed class TestAccessResult { public uint Granted; public int Error; }
public sealed class TestPrivilege { public string Name; }
public sealed class TestToken {
    public string UserSid = "S-1-5-21-101-102-103-1001";
    public string IntegritySid = "S-1-16-8192";
    public TestPrivilege[] Privileges = new TestPrivilege[0];
}
public sealed class TestJob { public bool InJob; public uint LimitFlags; public uint UiRestrictions; public int Error; }
public static class AgentSandboxAssessmentNative {
    public static int NamedError;
    public static uint NamedGranted;
    public static int FileError;
    public static uint ServiceGranted;
    public static uint ParentGranted;
    public static string NamedPath;
    public static string ConsoleSid;
    public static TestToken ForeignToken;
    public static uint ProcessGranted;
    public static int ProcessError = 5;
    public static readonly List<uint> ProcessRequests = new List<uint>();
    public static readonly List<uint> ServiceRequests = new List<uint>();
    public static TestAccessResult CheckNamedObject(string path, int type) {
        return new TestAccessResult { Granted = !string.IsNullOrEmpty(NamedPath) && path != NamedPath ? ParentGranted : NamedGranted, Error = NamedError };
    }
    public static readonly Dictionary<uint, int> FileErrors = new Dictionary<uint, int>();
    public static int ProbeFile(string path, uint right) { int error; return FileErrors.TryGetValue(right, out error) ? error : FileError; }
    public static int ProbeService(string name, uint right) {
        ServiceRequests.Add(right);
        return (right & ServiceGranted) == right ? 0 : 5;
    }
    public static int ProbeRegistryKey(int hive, string path, uint right) { return 5; }
    public static TestToken GetCurrentToken() { return new TestToken(); }
    public static TestToken GetProcessToken(int pid) { return ForeignToken; }
    public static int ProbeProcess(int pid, uint right) {
        ProcessRequests.Add(right);
        return (right & ProcessGranted) == right ? 0 : ProcessError;
    }
    public static TestJob GetJobInfo() { return new TestJob(); }
    public static string GetConsoleSessionSid() { return ConsoleSid; }
    public static int GetSessionId(int pid) { return 0; }
    public static string GetConsoleSessionUser() { return null; }
    public static string GetSessionUser() { return "TestAgent"; }
}
'@

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('exposure-regression-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$savedProfile = $env:USERPROFILE
$savedProxies = @{ HTTP_PROXY = $env:HTTP_PROXY; HTTPS_PROXY = $env:HTTPS_PROXY }
$failures = [Collections.Generic.List[string]]::new()

function Assert-Equal {
    param($Actual, $Expected)
    if ($Actual -ne $Expected) { throw "Expected '$Expected', got '$Actual'." }
}

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    $script:WorkspacePath = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkspacePath | Out-Null
    $env:USERPROFILE = Join-Path $testRoot 'empty-profile'
    $env:HTTP_PROXY = $null
    $env:HTTPS_PROXY = $null
    $script:Findings.Clear()
    $script:Errors.Clear()
    $script:Inventory.Clear()
    foreach ($criterion in $script:Criteria.Values) {
        $criterion.Outcome = 'unknown'
        $criterion.Reason = 'not evaluated'
        $criterion.Critical = $false
    }
    [AgentSandboxAssessmentNative]::NamedError = 0
    [AgentSandboxAssessmentNative]::NamedGranted = 0
    [AgentSandboxAssessmentNative]::FileError = 5
    [AgentSandboxAssessmentNative]::FileErrors.Clear()
    [AgentSandboxAssessmentNative]::ServiceGranted = 0
    [AgentSandboxAssessmentNative]::ServiceRequests.Clear()
    [AgentSandboxAssessmentNative]::NamedPath = $null
    [AgentSandboxAssessmentNative]::ParentGranted = 0
    [AgentSandboxAssessmentNative]::ConsoleSid = $null
    [AgentSandboxAssessmentNative]::ForeignToken = $null
    [AgentSandboxAssessmentNative]::ProcessGranted = 0
    [AgentSandboxAssessmentNative]::ProcessError = 5
    [AgentSandboxAssessmentNative]::ProcessRequests.Clear()
    try {
        & $Body
        Write-Host "PASS $Name"
    }
    catch {
        # 'SKIP: <reason>' marks an environment precondition, not a failure.
        if ($_.Exception.Message -like 'SKIP:*') {
            Write-Host "SKIP $Name ($($_.Exception.Message.Substring(5).Trim()))"
            return
        }
        $failures.Add("${Name}: $($_.Exception.Message)")
        Write-Host "FAIL $Name"
    }
}

try {
    Test-Case 'Unknown write permissions do not earn protection credit' {
        [AgentSandboxAssessmentNative]::NamedError = 5
        [AgentSandboxAssessmentNative]::FileError = 32
        Resolve-AccessTargets -Check CONTAINMENT -Criterion C-POLICY-INTEGRITY -Right Write `
            -Path $script:WorkspacePath -Capability test -Scope test -Impact test `
            -NoneReason absent -MetReason protected -UnmetReasonFormat '{0} writable' | Out-Null
        Assert-Equal $script:Criteria['C-POLICY-INTEGRITY'].Outcome 'unknown'
    }
    Test-Case 'Denied write requests resolve an unreadable security descriptor' {
        [AgentSandboxAssessmentNative]::NamedError = 5
        Resolve-AccessTargets -Check CONTAINMENT -Criterion C-POLICY-INTEGRITY -Right Write `
            -Path $script:WorkspacePath -Capability test -Scope test -Impact test `
            -NoneReason absent -MetReason protected -UnmetReasonFormat '{0} writable' | Out-Null
        Assert-Equal $script:Criteria['C-POLICY-INTEGRITY'].Outcome 'met'
    }
    Test-Case 'A granted write request on an unreadable security descriptor is reported' {
        [AgentSandboxAssessmentNative]::NamedError = 5
        [AgentSandboxAssessmentNative]::FileErrors[0x40000] = 0
        Assert-Equal (Get-PathAccess $script:WorkspacePath).ChangeAcl 'granted'
    }
    Test-Case 'A data-write denial on a file whose attributes are writable stays unknown' {
        $path = Join-Path $script:WorkspacePath 'maybe-read-only.json'
        [IO.File]::WriteAllText($path, '{}')
        [AgentSandboxAssessmentNative]::NamedError = 5
        [AgentSandboxAssessmentNative]::FileErrors[0x100] = 0
        $access = Get-PathAccess $path
        Assert-Equal $access.Write 'unknown'
        Assert-Equal $access.Create 'unknown'
    }
    Test-Case 'A hidden path is resolved by direct requests instead of treated as absent' {
        function Test-Path { $false }
        [AgentSandboxAssessmentNative]::NamedError = 5
        $access = Get-PathAccess 'C:\synthetic\hidden'
        Assert-Equal $access.Exists $true
        Assert-Equal $access.Write 'denied'
        Assert-Equal $access.Delete 'denied'
    }
    Test-Case 'Sharing violations stay unknown for read access' {
        [AgentSandboxAssessmentNative]::NamedError = 5
        [AgentSandboxAssessmentNative]::FileError = 32
        Assert-Equal (Get-PathAccess $script:WorkspacePath).Read 'unknown'
    }
    Test-Case 'Resolved denials still earn protection credit' {
        Resolve-AccessTargets -Check CONTAINMENT -Criterion C-POLICY-INTEGRITY -Right Write `
            -Path $script:WorkspacePath -Capability test -Scope test -Impact test `
            -NoneReason absent -MetReason protected -UnmetReasonFormat '{0} writable' | Out-Null
        Assert-Equal $script:Criteria['C-POLICY-INTEGRITY'].Outcome 'met'
    }
    Test-Case 'An observed grant takes precedence over unknown targets' {
        [AgentSandboxAssessmentNative]::NamedGranted = 2
        Resolve-AccessTargets -Check CONTAINMENT -Criterion C-POLICY-INTEGRITY -Right Write `
            -Path $script:WorkspacePath -Capability test -Scope test -Impact test `
            -NoneReason absent -MetReason protected -UnmetReasonFormat '{0} writable' | Out-Null
        Assert-Equal $script:Criteria['C-POLICY-INTEGRITY'].Outcome 'unmet'
    }
    Test-Case 'A failed file read leaves the secret scan incomplete' {
        $path = Join-Path $script:WorkspacePath 'locked.json'
        [IO.File]::WriteAllText($path, '{}')
        $lock = [IO.File]::Open($path, 'Open', 'ReadWrite', 'None')
        try {
            Invoke-SecretContentScan
            Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unknown'
            Assert-Equal $script:Inventory['secretScan'].readErrors 1
        }
        finally { $lock.Dispose() }
    }
    Test-Case 'A per-file partial read leaves the secret scan incomplete' {
        [IO.File]::WriteAllText((Join-Path $script:WorkspacePath 'large.txt'), ('a' * (1MB + 1)))
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unknown'
        Assert-Equal $script:Inventory['secretScan'].partialFiles 1
    }
    Test-Case 'A fully scanned benign file remains met' {
        [IO.File]::WriteAllText((Join-Path $script:WorkspacePath 'plain.json'), '{"name":"example"}')
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'met'
    }
    Test-Case 'A detected synthetic secret remains unmet' {
        [IO.File]::WriteAllText((Join-Path $script:WorkspacePath 'sample.txt'), ('ghp_' + ('A' * 36)))
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unmet'
        Assert-Equal ($script:Findings | ConvertTo-Json -Depth 8).Contains('A' * 36) $false
    }
    Test-Case 'Junctions are excluded before scanning their contents' {
        $outside = Join-Path $testRoot ('outside-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $outside | Out-Null
        [IO.File]::WriteAllText((Join-Path $outside 'secret.txt'), ('ghp_' + ('B' * 36)))
        New-Item -ItemType Junction -Path (Join-Path $script:WorkspacePath 'linked') -Target $outside | Out-Null
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unknown'
        Assert-Equal $script:Inventory['secretScan'].filesScanned 0
    }
    Test-Case 'A file reparse point is excluded without a content read' {
        $linkedFile = Join-Path $script:WorkspacePath 'linked.json'
        function Get-ChildItem { [pscustomobject]@{ FullName = $linkedFile; Name = 'linked.json'; Extension = '.json'; PSIsContainer = $false } }
        function Get-Item { param($LiteralPath) [pscustomobject]@{ Attributes = $(if ($LiteralPath -eq $linkedFile) { 0x400 } else { 0 }) } }
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unknown'
        Assert-Equal $script:Inventory['secretScan'].filesScanned 0
        Assert-Equal $script:Inventory['secretScan'].readErrors 0
    }
    Test-Case 'An unsafe ancestor is rejected before inspecting a child' {
        $visited = [Collections.Generic.List[string]]::new()
        function Get-Item {
            param($LiteralPath)
            $visited.Add($LiteralPath)
            [pscustomobject]@{ Attributes = $(if ($LiteralPath -eq 'C:\synthetic') { 0x400 } else { 0 }) }
        }
        Assert-Equal (Get-ScanPathExclusion 'C:\synthetic\remote-child\secret.txt') 'reparse-point'
        Assert-Equal $visited.Contains('C:\synthetic\remote-child\secret.txt') $false
        Assert-Equal $visited.Contains('C:\synthetic\remote-child') $false
    }
    Test-Case 'Enumeration errors leave the scan incomplete' {
        function Get-ChildItem {
            [CmdletBinding()]
            param([string]$LiteralPath, [switch]$Force)
            Write-Error 'Synthetic enumeration failure'
        }
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unknown'
        Assert-Equal $script:Inventory['secretScan'].enumerationErrors 1
    }
    Test-Case 'Remote paths are excluded before metadata access' {
        Assert-Equal (Get-ScanPathExclusion '\\unselected.invalid\share\secret.txt') 'network-path'
    }
    Test-Case 'Detectable recall attributes are excluded' {
        function Get-Item { [pscustomobject]@{ Attributes = 0x400000 } }
        Assert-Equal (Get-ScanPathExclusion 'C:\synthetic\placeholder.txt') 'offline-placeholder'
    }
    Test-Case 'Metadata redaction removes labeled and recognizable credentials' {
        $token = 'ghp_' + ('C' * 36)
        $text = Protect-Text ("https://proxy.example/?token=$token&sig=synthetic-signature /keys/$token")
        Assert-Equal $text.Contains($token) $false
        Assert-Equal $text.Contains('synthetic-signature') $false
        Assert-Equal (Protect-Text 'https://user:synthetic-password@example.com').Contains('synthetic-password') $false
        Assert-Equal (Protect-Text '{"password":"synthetic-secret"}').Contains('synthetic-secret') $false
        Assert-Equal (Protect-Text '{"password":"synthetic secret with spaces"}').Contains('with spaces') $false
        Assert-Equal (Protect-Text 'password="synthetic\"quoted secret"').Contains('quoted secret') $false
        $opaque = 'opaque12345' * 4
        Assert-Equal (Protect-Text "C:\keys\$opaque.json").Contains($opaque) $false
        Assert-Equal (Protect-Text 'S-1-5-21-101-102-103-1001') 'S-1-5-21-101-102-103-1001'
    }
    Test-Case 'Nested report fields are redacted before serialization' {
        $report = [ordered]@{ scope = @{ networkTargets = @('tcp:example.test:443?token=synthetic-token') }; inventory = @{ url = 'https://example.test/?sig=synthetic-signature' } }
        $json = Protect-Report $report | ConvertTo-Json -Depth 8
        Assert-Equal $json.Contains('synthetic-token') $false
        Assert-Equal $json.Contains('synthetic-signature') $false
        Assert-Equal ($json | ConvertFrom-Json).scope.networkTargets.Count 1
    }
    Test-Case 'Report redaction preserves numbers, booleans and empty arrays' {
        $report = Protect-Report ([ordered]@{ enabled = $false; count = 2; items = @(); optional = $null })
        $roundTrip = $report | ConvertTo-Json | ConvertFrom-Json
        Assert-Equal $roundTrip.enabled $false
        Assert-Equal $roundTrip.count 2
        Assert-Equal $roundTrip.items.Count 0
        Assert-Equal $roundTrip.optional $null
    }
    Test-Case 'Diagnostics redact token-bearing text' {
        $savedError = [Console]::Error
        $captured = [IO.StringWriter]::new()
        try {
            [Console]::SetError($captured)
            Write-Diag 'Invalid target: https://example.test/?token=synthetic-diagnostic-token'
        }
        finally { [Console]::SetError($savedError) }
        Assert-Equal $captured.ToString().Contains('synthetic-diagnostic-token') $false
        $captured.Dispose()
    }
    Test-Case 'JSON entry point emits one object without running host checks' {
        $scriptPath = (Join-Path $PSScriptRoot '..\Test-AgentSandboxExposure.ps1').Replace("'", "''")
        $workspace = $script:WorkspacePath.Replace("'", "''")
        $areas = ($AllCheckAreas | ForEach-Object { "'$_'" }) -join ','
        $command = "& '$scriptPath' -Json -Workspace '$workspace' -SkipCheck @($areas)"
        $startInfo = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in '-NoProfile', '-Command', $command) { $startInfo.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::Start($startInfo)
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'JSON smoke check timed out.' }
            Assert-Equal $process.ExitCode 0
            $report = $stdout.GetAwaiter().GetResult() | ConvertFrom-Json
            $null = $stderr.GetAwaiter().GetResult()
            Assert-Equal $report.schemaVersion $SchemaVersion
            Assert-Equal $report.scope.checksEvaluated.Count 0
            Assert-Equal $report.scope.checksSkipped.Count $AllCheckAreas.Count
            Assert-Equal $report.verdict 'Incomplete'
        }
        finally { $process.Dispose() }
    }
    Test-Case 'Change-config alone is detected on a service object' {
        function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = '"C:\synthetic\service.exe"'; StartName = 'LocalSystem' } }
        function Get-ScheduledTask { @() }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'denied'; Create = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        [AgentSandboxAssessmentNative]::ServiceGranted = 2
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $true
        Assert-Equal (@([AgentSandboxAssessmentNative]::ServiceRequests | Where-Object { $_ -notin 2, 0x40000, 0x80000 }).Count) 0
    }
    foreach ($targetKind in @('service', 'task')) {
        Test-Case "Replacement of a SYSTEM $targetKind target requires file creation" {
            $exe = Join-Path $script:WorkspacePath 'synthetic.exe'
            [IO.File]::WriteAllText($exe, '')
            [AgentSandboxAssessmentNative]::NamedPath = $exe
            [AgentSandboxAssessmentNative]::NamedGranted = 0x10000
            [AgentSandboxAssessmentNative]::ParentGranted = 0x4
            function Get-CimInstance {
                if ($targetKind -eq 'service') {
                    [pscustomobject]@{ Name = 'synthetic'; PathName = "`"$exe`""; StartName = 'LocalSystem' }
                }
            }
            function Get-ScheduledTask {
                if ($targetKind -eq 'task') {
                    [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = 'S-1-5-18' }
                        Actions = @([pscustomobject]@{ Execute = $exe; Arguments = ''; WorkingDirectory = '' }) }
                }
            }
            Invoke-IndirectCheck
            Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
            Assert-Equal $script:Criteria['A-SVC'].Critical $false
            Assert-Equal (Measure-Assessment).CriticalCapApplied $false
            Assert-Equal (@($script:Findings | Where-Object { $_.Capability -match 'replacement' }).Count) 0

            [AgentSandboxAssessmentNative]::ParentGranted = 0x2
            $script:Findings.Clear()
            Invoke-IndirectCheck
            Assert-Equal $script:Criteria['A-SVC'].Critical $true
            Assert-Equal (Measure-Assessment).CriticalCapApplied $true
            Assert-Equal (@($script:Findings | Where-Object { $_.Capability -match 'replacement' }).Count) 1
        }
    }
    Test-Case 'Unresolved service binary permissions do not earn credit' {
        function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = '"C:\synthetic\service.exe"'; StartName = 'LocalSystem' } }
        function Get-ScheduledTask { @() }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'unknown'; Create = 'unknown'; ChangeAcl = 'unknown'; TakeOwnership = 'unknown' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unknown'
    }
    Test-Case 'Stop alone is detected on a monitoring service' {
        function Get-Service { param($Name) if ($Name -eq 'Sense') { [pscustomobject]@{ Name = $Name } } }
        function Get-ItemProperty { throw 'No synthetic logging policy' }
        function Test-Path { $false }
        [AgentSandboxAssessmentNative]::ServiceGranted = 0x20
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-TAMPER'].Outcome 'unmet'
        Assert-Equal (@([AgentSandboxAssessmentNative]::ServiceRequests | Where-Object { $_ -notin 2, 0x20 }).Count) 0
    }
    Test-Case 'Failed TCP probes leave both route criteria unknown' {
        $script:ProbeNetwork = $false
        $script:NetworkTarget = @('tcp:1.1.1.1:443', 'tcp:8.8.8.8:443', 'tcp:127.0.0.1:1')
        function Invoke-TcpProbe { $false }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
        Assert-Equal $script:Criteria['R-NET-LATERAL'].Outcome 'unknown'
    }
    Test-Case 'An Internet request answered through the environment proxy is unmet' {
        $script:ProbeNetwork = $true
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://localhost:8080'
        function Invoke-TcpProbe { $false }
        function Invoke-ProxyProbe { 200 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unmet'
        Assert-Equal (@($script:Findings | Where-Object { $_.Criterion -eq 'R-NET-INTERNET' }).Count) 1
    }
    Test-Case 'An explicit proxy refusal with failed direct routes is met' {
        $script:ProbeNetwork = $true
        $script:NetworkTarget = @()
        $env:HTTPS_PROXY = 'localhost:8080'
        function Invoke-TcpProbe { $false }
        function Invoke-ProxyProbe { 403 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'met'
        Assert-Equal ($script:Criteria['R-NET-INTERNET'].Reason -match 'HTTPS_PROXY returned 403') $true
    }
    foreach ($status in @(407, 502, 0)) {
        Test-Case "A proxy status $status is not an enforced refusal" {
            $script:ProbeNetwork = $true
            $script:NetworkTarget = @()
            $env:HTTP_PROXY = 'http://localhost:8080'
            function Invoke-TcpProbe { $false }
            function Invoke-ProxyProbe { $status }
            function Get-CimInstance { @() }
            function Get-ItemProperty { throw 'No synthetic proxy' }
            Invoke-NetworkCheck
            Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
        }
    }
    Test-Case 'A refusal does not cover an untested proxy route' {
        $script:ProbeNetwork = $true
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://user:pass@localhost:8081'
        $env:HTTPS_PROXY = 'http://localhost:8080'
        function Invoke-TcpProbe { $false }
        function Invoke-ProxyProbe { 403 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
    }
    Test-Case 'A proxy URL with credentials is never used' {
        $script:ProbeNetwork = $true
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://user:pass@localhost:8080'
        $script:proxyCalls = 0
        function Invoke-TcpProbe { $false }
        function Invoke-ProxyProbe { $script:proxyCalls++; 200 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:proxyCalls 0
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
        Assert-Equal ($script:Criteria['R-NET-INTERNET'].Reason -match 'pass') $false
    }
    Test-Case 'Proxies are not contacted without -ProbeNetwork' {
        $script:ProbeNetwork = $false
        $script:NetworkTarget = @('tcp:1.1.1.1:443')
        $env:HTTP_PROXY = 'http://localhost:8080'
        $script:proxyCalls = 0
        function Invoke-TcpProbe { $false }
        function Invoke-ProxyProbe { $script:proxyCalls++; 200 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:proxyCalls 0
    }
    foreach ($variable in @('HTTP_PROXY', 'HTTPS_PROXY')) {
        Test-Case "The $variable probe sends one request and reads the proxy status" {
            $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $precheck = [Net.Sockets.TcpClient]::new()
            try { $precheck.Connect([Net.IPAddress]::Loopback, $listener.LocalEndpoint.Port) }
            catch {
                $listener.Stop()
                # A sandbox identity may have loopback blocked by its firewall.
                if ($_.Exception.InnerException.SocketErrorCode -eq 'AccessDenied') { throw 'SKIP: loopback connections are blocked for this identity' }
                throw
            }
            finally { $precheck.Close() }
            $listener.AcceptTcpClient().Close()
            $server = [powershell]::Create().AddScript({
                    param($Listener)
                    $accept = $Listener.AcceptTcpClientAsync()
                    if (-not $accept.Wait(10000)) { return 'no connection' }
                    $client = $accept.Result
                    $reader = [IO.StreamReader]::new($client.GetStream(), [Text.Encoding]::ASCII)
                    $line = $reader.ReadLine()
                    $bytes = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection established`r`n`r`n")
                    $client.GetStream().Write($bytes, 0, $bytes.Length)
                    $client.Close()
                    $line
                }).AddArgument($listener)
            $handle = $server.BeginInvoke()
            try {
                $proxy = [Uri]"http://127.0.0.1:$($listener.LocalEndpoint.Port)"
                Assert-Equal (Invoke-ProxyProbe -Proxy $proxy -Variable $variable) 200
                $expected = if ($variable -eq 'HTTPS_PROXY') { 'CONNECT example.com:443 HTTP/1.1' } else { 'HEAD http://example.com/ HTTP/1.1' }
                Assert-Equal @($server.EndInvoke($handle))[0] $expected
            }
            finally {
                $listener.Stop()
                $server.Dispose()
            }
        }
    }
    Test-Case 'Higher-integrity processes of the same account are probed' {
        [AgentSandboxAssessmentNative]::ForeignToken = [TestToken]::new()
        [AgentSandboxAssessmentNative]::ForeignToken.IntegritySid = 'S-1-16-12288'
        [AgentSandboxAssessmentNative]::ProcessGranted = 0x10
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        Assert-Equal $script:Criteria['R-PROC-READ'].Outcome 'unmet'
        Assert-Equal $script:Criteria['R-PROC-READ'].Critical $true
    }
    Test-Case 'Independent process rights are reported without claiming injection' {
        [AgentSandboxAssessmentNative]::ForeignToken = [TestToken]::new()
        [AgentSandboxAssessmentNative]::ForeignToken.UserSid = 'S-1-5-21-101-102-103-1002'
        [AgentSandboxAssessmentNative]::ProcessGranted = 0x20
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        Assert-Equal $script:Criteria['A-PROC-INJECT'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-PROC-INJECT'].Critical $false
        foreach ($right in @(0x8, 0x800, 0x80000)) {
            Assert-Equal ([AgentSandboxAssessmentNative]::ProcessRequests.Contains([uint32]$right)) $true
        }
        Assert-Equal (@($script:Findings | Where-Object { $_.Severity -eq 'critical' }).Count) 0
    }
    Test-Case 'Process probe errors stay unknown' {
        [AgentSandboxAssessmentNative]::ProcessError = 87
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        foreach ($id in @('R-PROC-READ', 'A-PROC-INJECT', 'A-PROC-CONTROL')) {
            Assert-Equal $script:Criteria[$id].Outcome 'unknown'
        }
    }
    Test-Case 'Session zero without console identity does not prove attribution' {
        function Get-Service { @() }
        function Get-ItemProperty { throw 'No synthetic policy' }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-ATTRIBUTION'].Outcome 'unknown'
    }
    Test-Case 'Installed monitoring service does not establish active logging' {
        function Get-Service { [pscustomobject]@{ Name = 'Sense'; Status = 'Stopped' } }
        function Get-ItemProperty { throw 'No synthetic policy' }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-OS-LOGGING'].Outcome 'unknown'
    }
    Test-Case 'A proxy policy key alone does not prove enforced routing' {
        function Test-Path { $true }
        function Get-ChildItem { @() }
        function Get-ItemProperty { [pscustomobject]@{} }
        function Get-Content { '{"allowManagedHooksOnly":true}' }
        function Get-PathAccess { [pscustomobject]@{ Exists = $true; IsDirectory = $false; Method = 'permission-analysis'; ErrorCategory = $null; Read = 'denied'; Write = 'denied'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-ContainmentCheck
        Assert-Equal $script:Criteria['C-PROXY-INTEGRITY'].Outcome 'unknown'
        Assert-Equal $script:Criteria['C-TOOL-POLICY'].Outcome 'unknown'
    }
    Test-Case 'A file can be deleted through its parent directory rights' {
        $path = Join-Path $script:WorkspacePath 'protected.json'
        [IO.File]::WriteAllText($path, '{}')
        [AgentSandboxAssessmentNative]::NamedPath = $path
        [AgentSandboxAssessmentNative]::ParentGranted = 0x40
        Assert-Equal (Get-PathAccess $path).Delete 'granted'
    }
    Test-Case 'Directory listing is not described as file-content access' {
        [AgentSandboxAssessmentNative]::NamedGranted = 1
        Get-MatchingTargets -Check FILES -Criterion R-FILES-PROFILES -Right Read -Path $script:WorkspacePath `
            -Capability 'readable profile' -Scope test -Impact 'documents readable' | Out-Null
        Assert-Equal $script:Findings[0].Capability 'directory listing'
        Assert-Equal $script:Findings[0].Impact 'Directory names are visible; child file readability is evaluated separately.'
    }
    Test-Case 'Workspace siblings are discovered without prefix collisions' {
        $script:WorkspacePath = Join-Path $testRoot 'workspace'
        $sibling = Join-Path $testRoot 'workspace-other'
        New-Item -ItemType Directory -Path $script:WorkspacePath, $sibling -Force | Out-Null
        $result = Get-AdjacentDirectories -DriveRoot @()
        Assert-Equal (@($result.Paths) -contains $sibling) $true
        Assert-Equal (@($result.Paths) -contains $script:WorkspacePath) $false
    }
    Test-Case 'Nested control files are checked independently' {
        $nested = Join-Path $script:WorkspacePath 'bootstrap'
        New-Item -ItemType Directory -Path $nested | Out-Null
        $file = Join-Path $nested 'Initialize-AgentSandboxShell.ps1'
        [IO.File]::WriteAllText($file, '# synthetic')
        $result = Get-ControlTargets -Root $script:WorkspacePath
        Assert-Equal (@($result.Paths) -contains $file) $true
    }
    Test-Case 'Task script arguments resolve against the working directory' {
        $action = [pscustomobject]@{ Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Arguments = '-NoProfile -File "scripts\job.ps1"'; WorkingDirectory = $script:WorkspacePath }
        $result = Get-TaskActionTargets $action
        Assert-Equal (@($result.Paths) -contains (Join-Path $script:WorkspacePath 'scripts\job.ps1')) $true
        Assert-Equal $result.Incomplete $false
        $action.Arguments = '-EncodedCommand abcdef'
        Assert-Equal (Get-TaskActionTargets $action).Incomplete $true
        $action.Arguments = '-Command "Write-Output -File scripts\job.ps1"'
        $result = Get-TaskActionTargets $action
        Assert-Equal $result.Incomplete $true
        Assert-Equal $result.Paths.Count 1
    }
    Test-Case 'Writable targets for unresolved service identities are not critical' {
        function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = '"C:\synthetic\service.exe"'; StartName = 'unresolvable-test-identity' } }
        function Get-ScheduledTask { @() }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'granted'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $false
    }
    Test-Case 'Coverage gives each dimension an equal weight' {
        foreach ($criterion in $script:Criteria.Values) {
            if ($criterion.Dimension -eq 'Monitoring') { $criterion.Outcome = 'met' }
        }
        Assert-Equal (Measure-Assessment).Coverage 0.25
    }
    Test-Case 'Unavailable dimensions contribute zero evidence coverage' {
        foreach ($criterion in $script:Criteria.Values) {
            $criterion.Outcome = if ($criterion.Dimension -eq 'Monitoring') { 'na' } else { 'met' }
        }
        Assert-Equal (Measure-Assessment).Coverage 0.75
    }
    Test-Case 'Resolved process denials still earn protection credit' {
        [AgentSandboxAssessmentNative]::ForeignToken = [TestToken]::new()
        [AgentSandboxAssessmentNative]::ForeignToken.UserSid = 'S-1-5-21-101-102-103-1002'
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        foreach ($id in @('R-PROC-READ', 'A-PROC-INJECT', 'A-PROC-CONTROL')) {
            Assert-Equal $script:Criteria[$id].Outcome 'met'
        }
    }
    Test-Case 'Denials on unattributed owners still earn protection credit' {
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        foreach ($id in @('R-PROC-READ', 'A-PROC-INJECT', 'A-PROC-CONTROL')) {
            Assert-Equal $script:Criteria[$id].Outcome 'met'
        }
    }
    Test-Case 'Suspension alone is recorded as process control' {
        [AgentSandboxAssessmentNative]::ForeignToken = [TestToken]::new()
        [AgentSandboxAssessmentNative]::ForeignToken.UserSid = 'S-1-5-21-101-102-103-1002'
        [AgentSandboxAssessmentNative]::ProcessGranted = 0x800
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        Assert-Equal $script:Criteria['A-PROC-CONTROL'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-PROC-INJECT'].Outcome 'met'
    }
    Test-Case 'A nonzero session alone does not make a memory grant critical' {
        [AgentSandboxAssessmentNative]::ForeignToken = [TestToken]::new()
        [AgentSandboxAssessmentNative]::ForeignToken.UserSid = 'S-1-5-21-101-102-103-1002'
        [AgentSandboxAssessmentNative]::ProcessGranted = 0x10
        function Get-Process { [pscustomobject]@{ Id = 987654; ProcessName = 'synthetic'; SessionId = 1 } }
        Invoke-ProcessesCheck
        Assert-Equal $script:Criteria['R-PROC-READ'].Outcome 'unmet'
        Assert-Equal $script:Criteria['R-PROC-READ'].Critical $false
    }
    Test-Case 'Distinct console account SIDs establish account attribution' {
        [AgentSandboxAssessmentNative]::ConsoleSid = 'S-1-5-21-101-102-103-1002'
        function Get-Service { @() }
        function Get-ItemProperty { throw 'No synthetic policy' }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-ATTRIBUTION'].Outcome 'met'
    }
    Test-Case 'The same console account SID remains unattributed in session zero' {
        [AgentSandboxAssessmentNative]::ConsoleSid = [AgentSandboxAssessmentNative]::GetCurrentToken().UserSid
        function Get-Service { @() }
        function Get-ItemProperty { throw 'No synthetic policy' }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-ATTRIBUTION'].Outcome 'unmet'
    }
    Test-Case 'Command-line inclusion alone does not establish auditing' {
        function Get-Service { @() }
        function Get-ItemProperty { [pscustomobject]@{ ProcessCreationIncludeCmdLine_Enabled = 1 } }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-OS-LOGGING'].Outcome 'unknown'
    }
    Test-Case 'Enabled script-block logging counts as configured logging' {
        function Get-Service { @() }
        function Get-ItemProperty { [pscustomobject]@{ EnableScriptBlockLogging = 1 } }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-OS-LOGGING'].Outcome 'met'
    }
    Test-Case 'A task script is assessed independently of its interpreter executable' {
        $taskScript = Join-Path $script:WorkspacePath 'job.ps1'
        function Get-CimInstance { @() }
        function Get-ScheduledTask {
            [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = 'S-1-5-21-101-102-103-1002' }
                Actions = @([pscustomobject]@{ Execute = 'C:\synthetic\pwsh.exe'; Arguments = "-File `"$taskScript`""; WorkingDirectory = '' }) }
        }
        function Test-Path { $true }
        function Get-PathAccess {
            param($Path)
            [pscustomobject]@{ Write = $(if ($Path -eq $taskScript) { 'granted' } else { 'denied' }); Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' }
        }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $false
        Assert-Equal (@($script:Findings | Where-Object { $_.Capability.Contains('job.ps1') }).Count) 1
    }
    Test-Case 'A resolved different standard service account is not automatically privileged' {
        function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = '"C:\synthetic\service.exe"'; StartName = 'S-1-5-21-101-102-103-1002' } }
        function Get-ScheduledTask { @() }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'granted'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Critical $false
    }
    Test-Case 'A task script with an unresolved interpreter does not establish privileged execution' {
        function Get-CimInstance { @() }
        function Get-ScheduledTask {
            [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = 'S-1-5-18' }
                Actions = @([pscustomobject]@{ Execute = 'pwsh.exe'; Arguments = '-File "C:\synthetic\job.ps1"'; WorkingDirectory = '' }) }
        }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'granted'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $false
    }
    Test-Case 'Discovery limits survive into control and read sampling results' {
        foreach ($name in @('one.json', 'two.json', 'three.json')) {
            [IO.File]::WriteAllText((Join-Path $script:WorkspacePath $name), '{}')
        }
        Assert-Equal (Get-ControlTargets -Root $script:WorkspacePath -MaxTargets 2).Incomplete $true
        $samples = Get-ReadSamples -Directory $script:WorkspacePath -MaxFilesPerDirectory 1
        Assert-Equal $samples.Incomplete $true
        Assert-Equal $samples.Paths.Count 2
    }
    Test-Case 'Discovery is bounded even when files are not scan candidates' {
        function Get-ScanPathExclusion { $null }
        function Get-ChildItem {
            foreach ($i in 1..50001) {
                [pscustomobject]@{ Name = "file$i.exe"; FullName = "C:\synthetic\file$i.exe"; Extension = '.exe'; PSIsContainer = $false }
            }
        }
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unknown'
        Assert-Equal $script:Inventory['secretScan'].limitReached 'max-discovery-entries'
        Assert-Equal $script:Inventory['secretScan'].discoveryEntries 50000
        Assert-Equal $script:Inventory['secretScan'].filesScanned 0
    }
    Test-Case 'A denied directory listing is a resolved sample, not an incomplete one' {
        function Get-ScanPathExclusion { $null }
        function Get-ChildItem {
            [CmdletBinding()] param($LiteralPath, [switch]$File, [switch]$Force)
            Write-Error -Exception ([UnauthorizedAccessException]::new('denied'))
        }
        $samples = Get-ReadSamples -Directory 'C:\synthetic\other-profile'
        Assert-Equal $samples.Incomplete $false
        Assert-Equal (@($samples.Paths) -contains 'C:\synthetic\other-profile') $true
    }
    Test-Case 'Other directory enumeration errors leave the sample incomplete' {
        function Get-ScanPathExclusion { $null }
        function Get-ChildItem {
            [CmdletBinding()] param($LiteralPath, [switch]$File, [switch]$Force)
            Write-Error -Exception ([IO.IOException]::new('device not ready'))
        }
        Assert-Equal (Get-ReadSamples -Directory 'C:\synthetic\other-profile').Incomplete $true
    }
    Test-Case 'A root hidden by a denied ancestor is probed directly' {
        function Get-ScanPathExclusion { 'metadata-denied' }
        $samples = Get-ReadSamples -Directory 'C:\synthetic\other-profile\Documents'
        Assert-Equal $samples.Incomplete $false
        Assert-Equal (@($samples.Paths) -contains 'C:\synthetic\other-profile\Documents') $true
    }
    Test-Case 'An absent sample root is skipped, not incomplete' {
        function Get-ScanPathExclusion { 'not-found' }
        $samples = Get-ReadSamples -Directory 'C:\synthetic\other-profile\Desktop'
        Assert-Equal $samples.Incomplete $false
        Assert-Equal $samples.Paths.Count 0
    }
    foreach ($case in @(@{ Error = 3; Expected = 'not-found' }, @{ Error = 5; Expected = 'metadata-denied' }, @{ Error = 32; Expected = 'metadata-error' })) {
        Test-Case "A missing-item report is confirmed natively (error $($case.Error))" {
            function Get-Item { throw [Management.Automation.ItemNotFoundException]::new('synthetic') }
            [AgentSandboxAssessmentNative]::FileError = $case.Error
            Assert-Equal (Get-ScanPathExclusion 'C:\synthetic\absent') $case.Expected
        }
    }
    Test-Case 'Unresolved consumer identities do not block a protected verdict' {
        function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = '"C:\synthetic\service.exe"'; StartName = '' } }
        function Get-ScheduledTask {
            [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = '' }
                Actions = @([pscustomobject]@{ Execute = 'C:\synthetic\task.exe'; Arguments = ''; WorkingDirectory = '' }) }
        }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'denied'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'met'
    }
    foreach ($create in @('granted', 'denied', 'unknown')) {
        Test-Case "A missing service binary is assessed by ancestor create rights ($create)" {
            function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = '"C:\synthetic\missing\service.exe"'; StartName = 'LocalSystem' } }
            function Get-ScheduledTask { @() }
            function Test-Path { $false }
            function Get-PathAccess {
                param($Path)
                if ($Path -like 'C:\synthetic\missing*') { [pscustomobject]@{ Exists = $false; ErrorCategory = 'not-found'; Create = 'unknown' } }
                else { [pscustomobject]@{ Exists = $true; ErrorCategory = $null; Create = $create } }
            }
            Invoke-IndirectCheck
            $expected = @{ granted = 'unmet'; denied = 'met'; unknown = 'unknown' }[$create]
            Assert-Equal $script:Criteria['A-SVC'].Outcome $expected
            Assert-Equal $script:Criteria['A-SVC'].Critical ($create -eq 'granted')
        }
    }
    Test-Case 'Machine-wide variables in task paths are expanded; per-user ones are not' {
        $action = [pscustomobject]@{ Execute = '%windir%\system32\synthetic.exe'; Arguments = ''; WorkingDirectory = '' }
        $result = Get-TaskActionTargets $action
        Assert-Equal $result.Incomplete $false
        Assert-Equal (@($result.Paths) -contains (Join-Path $env:windir 'system32\synthetic.exe')) $true
        $action.Execute = '%LOCALAPPDATA%\synthetic.exe'
        Assert-Equal (Get-TaskActionTargets $action).Incomplete $true
    }
    Test-Case 'Native file analysis distinguishes child read rights and parent deletion rights' {
        $fixture = Join-Path $script:WorkspacePath 'native-fixture.json'
        [IO.File]::WriteAllText($fixture, '{}')
        $childScript = Join-Path $script:WorkspacePath 'native-check.ps1'
        [IO.File]::WriteAllText($childScript, @'
param([string]$SourcePath, [string]$Fixture)
$source = Get-Content -LiteralPath $SourcePath -Raw
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
Invoke-Expression $source.Substring($ast.ParamBlock.Extent.EndOffset, $source.IndexOf('# --- Main ') - $ast.ParamBlock.Extent.EndOffset)
Initialize-NativeProbe
$original = Get-Acl -LiteralPath $Fixture
$parent = Split-Path -Parent $Fixture
$originalParent = Get-Acl -LiteralPath $parent
try {
    $acl = Get-Acl -LiteralPath $Fixture
    $sid = [Security.Principal.SecurityIdentifier]::new([AgentSandboxAssessmentNative]::GetCurrentToken().UserSid)
    $rights = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ReadData
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, 'Deny'))
    Set-Acl -LiteralPath $Fixture -AclObject $acl
    $parentAcl = Get-Acl -LiteralPath $parent
    $parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles, 'Allow'))
    Set-Acl -LiteralPath $parent -AclObject $parentAcl
    $check = [AgentSandboxAssessmentNative]::CheckNamedObject($Fixture, 1)
    if ($check.Error -ne 0 -or ($check.Granted -band 0x10001)) { throw 'Fixture did not deny object read/delete rights.' }
    $access = Get-PathAccess $Fixture
    if ($access.Read -ne 'denied' -or $access.Delete -ne 'granted') { throw "Native rights: read=$($access.Read), delete=$($access.Delete), method=$($access.Method), error=$($access.ErrorCategory)." }
}
finally {
    Set-Acl -LiteralPath $Fixture -AclObject $original
    Set-Acl -LiteralPath $parent -AclObject $originalParent
}
'@)
        $startInfo = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @('-NoProfile', '-File', $childScript, '-SourcePath', (Join-Path $PSScriptRoot '..\Test-AgentSandboxExposure.ps1'), '-Fixture', $fixture)) {
            $startInfo.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::Start($startInfo)
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'Native fixture check timed out.' }
            $null = $stdout.GetAwaiter().GetResult()
            $diagnostics = $stderr.GetAwaiter().GetResult()
            if ($process.ExitCode -ne 0) { throw "Native fixture check failed: $diagnostics" }
        }
        finally { $process.Dispose() }
    }
}
finally {
    $env:USERPROFILE = $savedProfile
    $env:HTTP_PROXY = $savedProxies.HTTP_PROXY
    $env:HTTPS_PROXY = $savedProxies.HTTPS_PROXY
    # Verify the recursive cleanup stays within this test's unique temp root.
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'exposure-regression-*') {
        throw 'Refusing cleanup outside the test temp root.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
Write-Host 'All exposure regression checks passed.'
