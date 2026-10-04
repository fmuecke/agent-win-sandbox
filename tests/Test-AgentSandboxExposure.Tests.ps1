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
    public bool IsElevated;
}
public sealed class TestHeldHandle {
    public string Type; public uint Access; public bool Inheritable; public int ProcessId;
    public string Path; public string TokenSid; public bool TokenElevated;
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
    public static string RegistryGrantedPath;
    public static readonly Dictionary<string, int> RegistryErrors = new Dictionary<string, int>();
    public static int ProbeRegistryKey(int hive, string path, uint right) {
        int error;
        if (path == RegistryGrantedPath) { return 0; }
        return RegistryErrors.TryGetValue(path, out error) ? error : 5;
    }
    public static TestToken GetCurrentToken() { return new TestToken(); }
    public static TestToken GetProcessToken(int pid) { return ForeignToken; }
    public static int ProbeProcess(int pid, uint right) {
        ProcessRequests.Add(right);
        return (right & ProcessGranted) == right ? 0 : ProcessError;
    }
    public static TestJob GetJobInfo() { return new TestJob(); }
    public static int HandleStatus;
    public static readonly List<TestHeldHandle> Handles = new List<TestHeldHandle>();
    public static TestHeldHandle[] GetHeldHandles(out int status) { status = HandleStatus; return Handles.ToArray(); }
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
$savedClaudeCode = $env:CLAUDECODE
$failures = [Collections.Generic.List[string]]::new()

function Assert-Equal {
    param($Actual, $Expected)
    if ($Actual -ne $Expected) { throw "Expected '$Expected', got '$Actual'." }
}

function New-PathAccessFixture {
    param([string]$Path, [string]$Read = 'denied', [string]$Write = 'denied')
    [pscustomobject]@{
        Path = $Path; Exists = $true; IsDirectory = $false; Method = 'permission-analysis'; ErrorCategory = $null
        Read = $Read; Create = 'denied'; Write = $Write; Delete = 'denied'
        ChangeAcl = 'denied'; TakeOwnership = 'denied'; DeleteChild = 'denied'
    }
}

function Test-Case {
    # -Pending marks a known checker gap (docs/exposure-checker-gaps.md): its
    # failure is reported, not counted. A pending case that passes fails the
    # run so the marker is removed when the gap is closed.
    param([string]$Name, [scriptblock]$Body, [switch]$Pending)
    $script:WorkspacePath = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkspacePath | Out-Null
    $env:USERPROFILE = Join-Path $testRoot 'empty-profile'
    $env:HTTP_PROXY = $null
    $env:HTTPS_PROXY = $null
    $env:CLAUDECODE = $null
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
    [AgentSandboxAssessmentNative]::RegistryGrantedPath = $null
    [AgentSandboxAssessmentNative]::RegistryErrors.Clear()
    [AgentSandboxAssessmentNative]::ServiceGranted = 0
    [AgentSandboxAssessmentNative]::ServiceRequests.Clear()
    [AgentSandboxAssessmentNative]::NamedPath = $null
    [AgentSandboxAssessmentNative]::ParentGranted = 0
    [AgentSandboxAssessmentNative]::ConsoleSid = $null
    [AgentSandboxAssessmentNative]::ForeignToken = $null
    [AgentSandboxAssessmentNative]::ProcessGranted = 0
    [AgentSandboxAssessmentNative]::ProcessError = 5
    [AgentSandboxAssessmentNative]::ProcessRequests.Clear()
    [AgentSandboxAssessmentNative]::HandleStatus = 0
    [AgentSandboxAssessmentNative]::Handles.Clear()
    try {
        & $Body
        if ($Pending) {
            $failures.Add("${Name}: passes now; remove -Pending.")
            Write-Host "FAIL $Name (pending case passed)"
            return
        }
        Write-Host "PASS $Name"
    }
    catch {
        # 'SKIP: <reason>' marks an environment precondition, not a failure.
        if ($_.Exception.Message -like 'SKIP:*') {
            Write-Host "SKIP $Name ($($_.Exception.Message.Substring(5).Trim()))"
            return
        }
        if ($Pending) {
            Write-Host "PENDING $Name ($($_.Exception.Message))"
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
    foreach ($case in @(
            @{ Name = 'a quoted JSON key'; File = 'settings.json'; Text = ('{"api_key": "' + ('q7Rt2kLm' * 3) + '"}'); Encoding = [Text.UTF8Encoding]::new($false) },
            @{ Name = 'a fine-grained GitHub token'; File = 'notes.txt'; Text = ('github' + '_pat_' + ('A' * 22) + '_' + ('B' * 59)); Encoding = [Text.UTF8Encoding]::new($false) },
            @{ Name = 'a UTF-16LE file with a byte-order mark'; File = 'out.txt'; Text = ('ghp_' + ('C' * 36)); Encoding = [Text.Encoding]::Unicode },
            @{ Name = 'a UTF-16BE file with a byte-order mark'; File = 'out.txt'; Text = ('ghp_' + ('D' * 36)); Encoding = [Text.Encoding]::BigEndianUnicode })) {
        Test-Case "The secret scan detects $($case.Name)" {
            [IO.File]::WriteAllText((Join-Path $script:WorkspacePath $case.File), $case.Text, $case.Encoding)
            Invoke-SecretContentScan
            Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unmet'
        }
    }
    Test-Case 'A placeholder value in a generic assignment is not a suspected secret' {
        [IO.File]::WriteAllText((Join-Path $script:WorkspacePath 'fixture.json'), ('{"password":"' + 'synthetic-' + 'secret-value"}'))
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'met'
        Assert-Equal $script:Inventory['secretScan'].placeholderMatches 1
    }
    Test-Case 'A placeholder word does not hide a known token format' {
        [IO.File]::WriteAllText((Join-Path $script:WorkspacePath 'fixture.txt'), ('example token: ghp_' + ('E' * 36)))
        Invoke-SecretContentScan
        Assert-Equal $script:Criteria['R-SECRETS-SCAN'].Outcome 'unmet'
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
        $script:NetworkTarget = @('tcp:1.1.1.1:443', 'tcp:8.8.8.8:443', 'tcp:127.0.0.1:1')
        function Invoke-TcpProbe { 'timeout' }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
        Assert-Equal $script:Criteria['R-NET-LATERAL'].Outcome 'unknown'
    }
    Test-Case 'An Internet request answered through the environment proxy is unmet' {
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://localhost:8080'
        function Invoke-TcpProbe { 'timeout' }
        function Invoke-ProxyProbe { 200 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unmet'
        Assert-Equal (@($script:Findings | Where-Object { $_.Criterion -eq 'R-NET-INTERNET' }).Count) 1
    }
    Test-Case 'An explicit proxy refusal with failed direct routes is met' {
        $script:NetworkTarget = @()
        $env:HTTPS_PROXY = 'localhost:8080'
        function Invoke-TcpProbe { 'timeout' }
        function Invoke-ProxyProbe { 403 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'met'
        Assert-Equal ($script:Criteria['R-NET-INTERNET'].Reason -match 'HTTPS_PROXY returned 403') $true
    }
    foreach ($status in @(407, 502, 0)) {
        Test-Case "A proxy status $status is not an enforced refusal" {
            $script:NetworkTarget = @()
            $env:HTTP_PROXY = 'http://localhost:8080'
            function Invoke-TcpProbe { 'timeout' }
            function Invoke-ProxyProbe { $status }
            function Get-CimInstance { @() }
            function Get-ItemProperty { throw 'No synthetic proxy' }
            Invoke-NetworkCheck
            Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
        }
    }
    Test-Case 'A refusal does not cover an untested proxy route' {
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://user:pass@localhost:8081'
        $env:HTTPS_PROXY = 'http://localhost:8080'
        function Invoke-TcpProbe { 'timeout' }
        function Invoke-ProxyProbe { 403 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
    }
    Test-Case 'A proxy URL with credentials is never used' {
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://user:pass@localhost:8080'
        $script:proxyCalls = 0
        function Invoke-TcpProbe { 'timeout' }
        function Invoke-ProxyProbe { $script:proxyCalls++; 200 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:proxyCalls 0
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unknown'
        Assert-Equal ($script:Criteria['R-NET-INTERNET'].Reason -match 'pass') $false
    }
    Test-Case 'Default Internet targets and proxies are probed on every run' {
        $script:NetworkTarget = @()
        $env:HTTP_PROXY = 'http://localhost:8080'
        $script:proxyCalls = 0
        $script:tcpHosts = @()
        function Invoke-TcpProbe { param($HostName, $Port) $script:tcpHosts += $HostName; 'timeout' }
        function Invoke-ProxyProbe { $script:proxyCalls++; 403 }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal ($script:tcpHosts -contains 'example.com') $true
        Assert-Equal $script:proxyCalls 1
    }
    Test-Case 'Socket errors map to connect outcomes' {
        Assert-Equal (ConvertTo-ConnectOutcome 10013) 'blocked'
        Assert-Equal (ConvertTo-ConnectOutcome 10061) 'refused'
        Assert-Equal (ConvertTo-ConnectOutcome 10060) 'timeout'
        Assert-Equal (ConvertTo-ConnectOutcome 10051) 'error'
    }
    Test-Case 'Lateral targets come from gateways, private DNS servers and loopback' {
        $specs = @(Get-LateralTargets -Gateway '192.168.2.1', 'fe80::1', '0.0.0.0' -DnsServer '192.168.2.1', '8.8.8.8', 'fec0:0:0:ffff::1' -ExcludeLoopbackPort 49151)
        foreach ($expected in @('tcp:192.168.2.1:80', 'tcp:192.168.2.1:443', 'tcp:192.168.2.1:53', 'tcp:127.0.0.1:49150')) {
            Assert-Equal ($specs -contains $expected) $true
        }
        Assert-Equal (@($specs | Where-Object { $_ -match '8\.8\.8\.8|fe80|fec0|0\.0\.0\.0|:49151$' }).Count) 0
        Assert-Equal $specs.Count (@($specs | Select-Object -Unique).Count)
    }
    foreach ($case in @(
            @{ Name = 'all blocked'; Outcome = { 'blocked' }; Expected = 'met' },
            @{ Name = 'a refused gateway port'; Outcome = { param($HostName) if ($HostName -eq '192.168.2.1') { 'refused' } else { 'blocked' } }; Expected = 'unmet' },
            @{ Name = 'a timeout'; Outcome = { param($HostName) if ($HostName -eq '192.168.2.1') { 'timeout' } else { 'blocked' } }; Expected = 'unknown' })) {
        Test-Case "Lateral reach with $($case.Name) is $($case.Expected)" {
            $script:NetworkTarget = @()
            function Get-LateralTargets { 'tcp:192.168.2.1:80', 'tcp:127.0.0.1:49151' }
            Set-Item -Path Function:\Invoke-TcpProbe -Value $case.Outcome
            function Get-CimInstance { @() }
            function Get-ItemProperty { throw 'No synthetic proxy' }
            Invoke-NetworkCheck
            Assert-Equal $script:Criteria['R-NET-LATERAL'].Outcome $case.Expected
        }
    }
    Test-Case 'Explicitly blocked direct Internet probes are met without a proxy' {
        $script:NetworkTarget = @()
        function Get-LateralTargets { @() }
        function Invoke-TcpProbe { 'blocked' }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'met'
    }
    Test-Case 'A refused Internet connection reached its host and is unmet' {
        $script:NetworkTarget = @()
        function Get-LateralTargets { @() }
        function Invoke-TcpProbe { param($HostName) if ($HostName -eq '1.1.1.1') { 'refused' } else { 'blocked' } }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'unmet'
    }
    Test-Case 'The verdict line shows the whole scale with the current verdict raised' {
        $context = @{ userName = 'synthetic'; userSid = 'S-1-5-21-0'; integrityLevel = 'medium'; isElevated = $false; sessionId = 0; timestampUtc = 'now' }
        # Rebuild host lines: each Write-Host -NoNewline segment is its own record.
        $report = -join (& { Write-HumanReport -Measure ([pscustomobject]@{ Verdict = 'Partial'; ScoreLower = 50; ScoreUpper = 60; CriticalCapApplied = $false; Coverage = 0.9; Dimensions = @() }) -Context $context } 6>&1 |
            ForEach-Object { $_.MessageData.Message + $(if ($_.MessageData.NoNewLine) { '' } else { "`n" }) })
        $line = @($report -split "`r?`n" | Where-Object { $_ -like 'Verdict:*' })[0]
        Assert-Equal $line 'Verdict: Critical | Incomplete | Weak | PARTIAL | Strong'
        Assert-Equal ($report -split "`r?`n" -contains "Verdict scope: $VerdictScope") $true
    }
    Test-Case 'Absent local tool declarations do not earn tool-scope credit' {
        function Get-CimInstance { [pscustomobject]@{ PartOfDomain = $false; Workgroup = 'WORKGROUP'; Domain = 'WORKGROUP' } }
        function Get-GitConfigPaths { @() }
        Invoke-RemoteCheck
        Assert-Equal $script:Criteria['A-TOOL-SCOPE'].Outcome 'unknown'
    }
    Test-Case 'The verdict block follows the findings and precedes remediation' {
        $script:Criteria['A-ID-ADMIN'].Outcome = 'unmet'
        $context = @{ userName = 'synthetic'; userSid = 'S-1-5-21-0'; integrityLevel = 'medium'; isElevated = $false; sessionId = 0; timestampUtc = 'now' }
        $report = (& { Write-HumanReport -Measure (Measure-Assessment) -Context $context } 6>&1 | Out-String)
        $verdict = $report.IndexOf('Verdict:')
        Assert-Equal ($verdict -gt $report.IndexOf('Not evaluated / unknown')) $true
        Assert-Equal ($verdict -lt $report.IndexOf('Remediation:')) $true
        Assert-Equal ($report.IndexOf('Evidence coverage:') -lt $report.IndexOf('Remediation:')) $true
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
    Test-Case 'A proxy policy key without proxy values is not a proxy policy' {
        function Test-Path { $true }
        function Get-ChildItem { @() }
        function Get-ItemProperty { [pscustomobject]@{ CallLegacyWCMPolicies = 0 } }
        function Get-Content { '{"allowManagedHooksOnly":true}' }
        function Get-PathAccess { [pscustomobject]@{ Exists = $true; IsDirectory = $false; Method = 'permission-analysis'; ErrorCategory = $null; Read = 'denied'; Write = 'denied'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-ContainmentCheck
        Assert-Equal $script:Criteria['C-PROXY-INTEGRITY'].Outcome 'na'
    }
    # Containment fixtures: a protected managed-settings file and an
    # environment proxy; each case varies the network evidence or policy.
    function Set-ContainmentFixture {
        param([string]$Settings = '{"allowManagedPermissionRulesOnly":true}', [string]$Owner = 'S-1-5-32-544', [string]$Write = 'denied')
        $script:fixtureSettings = $Settings
        $script:fixtureOwner = $Owner
        $script:fixtureWrite = $Write
    }
    function Invoke-ContainmentFixture {
        function Test-Path { $true }
        function Get-ChildItem { @() }
        function Get-ItemProperty { throw 'No synthetic registry value' }
        function Get-Content { $script:fixtureSettings }
        function Get-OwnerSid { $script:fixtureOwner }
        function Get-PathAccess { [pscustomobject]@{ Exists = $true; IsDirectory = $false; Method = 'permission-analysis'; ErrorCategory = $null; Read = 'denied'; Write = $script:fixtureWrite; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-ContainmentCheck
    }
    foreach ($case in @(
            @{ Name = 'met Internet restriction'; Internet = 'met'; Probe = 'blocked'; Expected = 'met' },
            @{ Name = 'a direct route that reached its host'; Internet = 'unmet'; Probe = 'connected'; Expected = 'unmet' },
            @{ Name = 'unresolved direct routes'; Internet = 'unknown'; Probe = 'timeout'; Expected = 'unknown' })) {
        Test-Case "An agent-changeable proxy with $($case.Name) is $($case.Expected)" {
            $env:HTTP_PROXY = 'http://127.0.0.1:8080'
            $script:Criteria['R-NET-INTERNET'].Outcome = $case.Internet
            $script:Inventory['networkProbes'] = @([pscustomobject]@{ Spec = 'tcp:1.1.1.1:443'; Kind = 'tcp'; Class = 'internet'; Outcome = $case.Probe })
            Set-ContainmentFixture
            Invoke-ContainmentFixture
            Assert-Equal $script:Criteria['C-PROXY-INTEGRITY'].Outcome $case.Expected
        }
    }
    foreach ($case in @(
            @{ Name = 'is not assessed outside Claude Code'; ClaudeCode = $null; Settings = '{"allowManagedPermissionRulesOnly":true}'; Owner = 'S-1-5-32-544'; Write = 'denied'; Expected = 'unknown' },
            @{ Name = 'allowing only managed permission rules is met'; ClaudeCode = '1'; Settings = '{"allowManagedPermissionRulesOnly":true}'; Owner = 'S-1-5-32-544'; Write = 'denied'; Expected = 'met' },
            @{ Name = 'merging user permission rules is unmet'; ClaudeCode = '1'; Settings = '{"permissions":{"deny":["WebFetch"]}}'; Owner = 'S-1-5-32-544'; Write = 'denied'; Expected = 'unmet' },
            @{ Name = 'writable by the agent is unmet'; ClaudeCode = '1'; Settings = '{"allowManagedPermissionRulesOnly":true}'; Owner = 'S-1-5-32-544'; Write = 'granted'; Expected = 'unmet' },
            @{ Name = 'owned by an untrusted account is unknown'; ClaudeCode = '1'; Settings = '{"allowManagedPermissionRulesOnly":true}'; Owner = 'S-1-5-21-101-102-103-1002'; Write = 'denied'; Expected = 'unknown' },
            @{ Name = 'that cannot be parsed is unknown'; ClaudeCode = '1'; Settings = '{ not json'; Owner = 'S-1-5-32-544'; Write = 'denied'; Expected = 'unknown' })) {
        Test-Case "Claude Code managed settings $($case.Name)" {
            $env:CLAUDECODE = $case.ClaudeCode
            Set-ContainmentFixture -Settings $case.Settings -Owner $case.Owner -Write $case.Write
            Invoke-ContainmentFixture
            Assert-Equal $script:Criteria['C-TOOL-POLICY'].Outcome $case.Expected
        }
    }
    # Git credential fixtures: synthetic config files in Git's read order and
    # synthetic Credential Manager target names.
    function Invoke-GitCredentialFixture {
        param([string[]]$Configs, [string[]]$StoredTargets = @())
        $paths = @()
        for ($i = 0; $i -lt $Configs.Count; $i++) {
            $path = Join-Path $script:WorkspacePath "gitconfig-$i"
            [IO.File]::WriteAllText($path, $Configs[$i])
            $paths += $path
        }
        $script:fixtureGitPaths = $paths
        $script:fixtureTargets = $StoredTargets
        function Get-GitConfigPaths { $script:fixtureGitPaths }
        function Get-StoredCredentialTargets { $script:fixtureTargets }
        function Get-CimInstance { [pscustomobject]@{ PartOfDomain = $false; Workgroup = 'WORKGROUP'; Domain = 'WORKGROUP' } }
        Invoke-RemoteCheck
        return $script:Criteria['A-REMOTE-DELEGATED'].Outcome
    }
    Test-Case 'A Credential Manager helper with nothing stored is not a usable credential' {
        Assert-Equal (Invoke-GitCredentialFixture -Configs "[credential]`n`thelper = manager`n") 'met'
    }
    Test-Case 'A Credential Manager helper with a stored git credential is usable' {
        Assert-Equal (Invoke-GitCredentialFixture -Configs "[credential]`n`thelper = manager`n" -StoredTargets 'git:https://github.com') 'unmet'
    }
    Test-Case 'An empty helper value in a later config clears earlier helpers' {
        Assert-Equal (Invoke-GitCredentialFixture -Configs "[credential]`n`thelper = store`n", "[credential]`n`thelper =`n") 'met'
    }
    Test-Case 'A store helper with an existing credential file is usable' {
        $file = Join-Path $script:WorkspacePath 'creds'
        [IO.File]::WriteAllText($file, '')
        $config = "[credential]`n`thelper = store --file `"$($file -replace '\\', '/')`"`n"
        Assert-Equal (Invoke-GitCredentialFixture -Configs $config) 'unmet'
    }
    foreach ($case in @(
            @{ Name = 'a custom helper'; Config = "[credential `"https://example.com`"]`n`thelper = !synthetic-helper`n" },
            @{ Name = 'a non-default credential store'; Config = "[credential]`n`thelper = manager`n`tcredentialStore = dpapi`n" },
            @{ Name = 'an unresolved include'; Config = "[include]`n`tpath = other.gitconfig`n" })) {
        Test-Case "Git credentials behind $($case.Name) stay unknown" {
            Assert-Equal (Invoke-GitCredentialFixture -Configs $case.Config) 'unknown'
        }
    }
    # Discovery failures: a failed enumeration or a non-denial probe error is
    # not evidence of absence or protection.
    $otherHive = 'S-1-5-21-101-102-103-1002'
    Test-Case 'Denied other-user and sensitive hives earn registry credit' {
        function Get-LoadedUserHives { @('.DEFAULT', $otherHive, "${otherHive}_Classes", 'S-1-5-21-101-102-103-1001', 'S-1-5-18') }
        Invoke-RegistryOthersCheck
        Assert-Equal $script:Criteria['R-REG-OTHERS'].Outcome 'met'
        Assert-Equal $script:Criteria['R-REG-OTHERS'].Reason 'Every probed other-user or sensitive registry location denied read (3 probed).'
    }
    Test-Case 'A readable other-user hive is unmet' {
        function Get-LoadedUserHives { @($otherHive) }
        [AgentSandboxAssessmentNative]::RegistryGrantedPath = "$otherHive\Software"
        Invoke-RegistryOthersCheck
        Assert-Equal $script:Criteria['R-REG-OTHERS'].Outcome 'unmet'
    }
    Test-Case 'A registry probe error is not a denial' {
        function Get-LoadedUserHives { @($otherHive) }
        [AgentSandboxAssessmentNative]::RegistryErrors['SECURITY'] = 1450
        Invoke-RegistryOthersCheck
        Assert-Equal $script:Criteria['R-REG-OTHERS'].Outcome 'unknown'
    }
    Test-Case 'A failed hive enumeration leaves registry reach unknown' {
        function Get-LoadedUserHives { throw 'synthetic enumeration failure' }
        Invoke-RegistryOthersCheck
        Assert-Equal $script:Criteria['R-REG-OTHERS'].Outcome 'unknown'
    }
    Test-Case 'A failed share enumeration leaves mapped shares unknown' {
        $script:NetworkTarget = @()
        function Invoke-TcpProbe { 'blocked' }
        function Get-CimInstance { param($ClassName) if ($ClassName -eq 'Win32_NetworkConnection') { throw 'synthetic CIM failure' } }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-SHARES'].Outcome 'unknown'
    }
    Test-Case 'A failed membership query leaves domain reach unknown' {
        function Get-CimInstance { throw 'synthetic CIM failure' }
        function Get-GitConfigPaths { @() }
        Invoke-RemoteCheck
        Assert-Equal $script:Criteria['A-REMOTE-DOMAIN'].Outcome 'unknown'
    }
    Test-Case 'PowerShell 7 script-block logging counts as configured logging' {
        function Get-Service { @() }
        function Get-ItemProperty { param($Path) if ($Path -like '*PowerShellCore*') { [pscustomobject]@{ EnableScriptBlockLogging = 1 } } else { throw 'No synthetic policy' } }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-OS-LOGGING'].Outcome 'met'
    }
    Test-Case 'A running process-monitoring service counts as configured logging' {
        function Get-Service { param($Name) if ($Name -eq 'Sysmon64') { [pscustomobject]@{ Name = $Name; Status = 'Running' } } }
        function Get-ItemProperty { throw 'No synthetic policy' }
        function Test-Path { $false }
        Invoke-MonitoringCheck
        Assert-Equal $script:Criteria['M-OS-LOGGING'].Outcome 'met'
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
        function Resolve-BareExecutable { $null }
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
    # Held handles: a right the token is denied on the same object is excess.
    function Invoke-HandleFixture {
        param([hashtable[]]$Handle)
        foreach ($entry in $Handle) {
            $held = [TestHeldHandle]::new()
            foreach ($key in $entry.Keys) { $held.$key = $entry[$key] }
            [AgentSandboxAssessmentNative]::Handles.Add($held)
        }
        Invoke-HeldHandleCheck -OwnSid 'S-1-5-21-101-102-103-1001' -OwnElevated $false
        return $script:Criteria['A-PROC-HANDLES'].Outcome
    }
    Test-Case 'A process handle with rights the token is denied is excess authority' {
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Process'; Access = 0x20; ProcessId = 4242 }) 'unmet'
    }
    Test-Case 'A process handle within the token''s rights is not excess' {
        [AgentSandboxAssessmentNative]::ProcessGranted = 0x20
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Process'; Access = 0x20; ProcessId = 4242 }) 'met'
    }
    Test-Case 'A held token of another identity is excess authority' {
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Token'; Access = 0xF; TokenSid = 'S-1-5-18' }) 'unmet'
    }
    Test-Case 'An elevated token of the same account is excess for an unelevated agent' {
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Token'; Access = 0xF; TokenSid = 'S-1-5-21-101-102-103-1001'; TokenElevated = $true }) 'unmet'
    }
    Test-Case 'A writable key handle the token cannot open for write is excess' {
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Key'; Access = 0x2; Path = '\REGISTRY\MACHINE\SOFTWARE\Synthetic' }) 'unmet'
    }
    Test-Case 'A key comparison that fails without a denial stays unknown' {
        [AgentSandboxAssessmentNative]::RegistryErrors['SOFTWARE\Synthetic'] = 1450
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Key'; Access = 0x2; Path = '\REGISTRY\MACHINE\SOFTWARE\Synthetic' }) 'unknown'
    }
    Test-Case 'A file handle is compared by path analysis, not a second open' {
        function Get-PathAccess { [pscustomobject]@{ Read = 'granted'; Write = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Assert-Equal (Invoke-HandleFixture @{ Type = 'File'; Access = 0x2; Path = '\\?\C:\synthetic\log.txt' }) 'unmet'
    }
    Test-Case 'A foreign thread handle with control rights cannot be compared and stays unknown' {
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Thread'; Access = 0x10; ProcessId = 4242 }) 'unknown'
    }
    Test-Case 'An unreadable handle table leaves held handles unknown' {
        [AgentSandboxAssessmentNative]::HandleStatus = -1073741790
        Assert-Equal (Invoke-HandleFixture @()) 'unknown'
    }
    Test-Case 'Handles within the token''s own rights earn held-handle credit' {
        Assert-Equal (Invoke-HandleFixture @{ Type = 'Process'; Access = 0x100000; ProcessId = 4242 }, @{ Type = 'Thread'; Access = 0x1FFFFF; ProcessId = $PID }) 'met'
    }
    # Service execution files beyond the image: unquoted-path candidates and
    # svchost ServiceDlls. $script:grants maps a path to its granted rights.
    function New-SyntheticAccess {
        param([string[]]$Granted = @(), [switch]$Missing)
        if ($Missing) { return [pscustomobject]@{ Exists = $false; ErrorCategory = 'not-found'; Write = 'unknown'; Create = 'unknown' } }
        $access = [ordered]@{ Exists = $true; ErrorCategory = $null }
        foreach ($right in 'Write', 'Create', 'Delete', 'ChangeAcl', 'TakeOwnership', 'DeleteChild') { $access[$right] = $(if ($Granted -contains $right) { 'granted' } else { 'denied' }) }
        return [pscustomobject]$access
    }
    function Invoke-ServiceFixture {
        param([string]$PathName, [hashtable]$Grants = @{}, [string[]]$MissingPaths = @())
        $script:fixturePathName = $PathName
        $script:fixtureGrants = $Grants
        $script:fixtureMissing = $MissingPaths
        function Get-CimInstance { [pscustomobject]@{ Name = 'synthetic'; PathName = $script:fixturePathName; StartName = 'LocalSystem' } }
        function Get-ScheduledTask { @() }
        function Test-Path { param($LiteralPath) $LiteralPath -notin $script:fixtureMissing }
        function Get-PathAccess {
            param($Path)
            if ($Path -in $script:fixtureMissing) { return New-SyntheticAccess -Missing }
            New-SyntheticAccess -Granted @($script:fixtureGrants[$Path])
        }
        Invoke-IndirectCheck
    }
    Test-Case 'An unquoted service path tries each space-delimited prefix first' {
        $candidates = Get-UnquotedPathCandidates -PathName 'C:\Program Files\A B\x.exe -k' -Image 'C:\Program Files\A B\x.exe'
        Assert-Equal ($candidates -join '|') 'C:\Program.exe|C:\Program Files\A.exe'
        Assert-Equal @(Get-UnquotedPathCandidates -PathName '"C:\Program Files\A B\x.exe"' -Image 'C:\Program Files\A B\x.exe').Count 0
    }
    Test-Case 'A creatable unquoted-path candidate for SYSTEM is critical' {
        Invoke-ServiceFixture -PathName 'C:\synthetic dir\svc.exe' -MissingPaths 'C:\synthetic.exe' -Grants @{ 'C:\' = 'Write' }
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $true
    }
    Test-Case 'Creating folders but not files beside an unquoted-path candidate is not a plant' {
        Invoke-ServiceFixture -PathName 'C:\synthetic dir\svc.exe' -MissingPaths 'C:\synthetic.exe' -Grants @{ 'C:\' = 'Create' }
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'met'
    }
    Test-Case 'A writable svchost ServiceDll for SYSTEM is critical' {
        function Get-ServiceDll { [pscustomobject]@{ Path = 'C:\synthetic\svc.dll'; Key = 'SYSTEM\CurrentControlSet\Services\synthetic\Parameters'; Inferred = $false; Unresolved = $null } }
        Invoke-ServiceFixture -PathName 'C:\Windows\system32\svchost.exe -k netsvcs' -Grants @{ 'C:\synthetic\svc.dll' = 'Write' }
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $true
    }
    Test-Case 'A writable ServiceDll Parameters key for SYSTEM is critical' {
        function Get-ServiceDll { [pscustomobject]@{ Path = 'C:\synthetic\svc.dll'; Key = 'SYSTEM\CurrentControlSet\Services\synthetic\Parameters'; Inferred = $false; Unresolved = $null } }
        [AgentSandboxAssessmentNative]::RegistryGrantedPath = 'SYSTEM\CurrentControlSet\Services\synthetic\Parameters'
        Invoke-ServiceFixture -PathName 'C:\Windows\system32\svchost.exe -k netsvcs'
        Assert-Equal $script:Criteria['A-SVC'].Critical $true
    }
    Test-Case 'An unreadable ServiceDll leaves services unknown and is named' {
        function Get-ServiceDll { [pscustomobject]@{ Path = $null; Key = 'SYSTEM\CurrentControlSet\Services\synthetic\Parameters'; Inferred = $false; Unresolved = 'ServiceDll key unreadable' } }
        Invoke-ServiceFixture -PathName 'C:\Windows\system32\svchost.exe -k netsvcs'
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unknown'
        Assert-Equal $script:Criteria['A-SVC'].Reason.Contains('synthetic (ServiceDll key unreadable)') $true
    }
    Test-Case 'A host merely named like svchost is not resolved as svchost' {
        function Get-ServiceDll { throw 'must not be called' }
        Invoke-ServiceFixture -PathName 'C:\Windows\Microsoft.NET\SMSvcHost.exe'
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'met'
    }
    Test-Case 'A hidden ServiceDll is inferred from the service name resource' {
        function Read-RegistryValue {
            param($Path, $Name)
            if ($Path -like '*\Parameters') { return [pscustomobject]@{ State = 'denied'; Value = $null } }
            if ($Name -eq 'DisplayName') { return [pscustomobject]@{ State = 'present'; Value = '@%SystemRoot%\system32\lmhsvc.dll,-101' } }
            [pscustomobject]@{ State = 'present'; Value = $null }
        }
        $dll = Get-ServiceDll -Name 'lmhosts'
        Assert-Equal $dll.Path (Join-Path $env:SystemRoot 'system32\lmhsvc.dll')
        Assert-Equal $dll.Inferred $true
        Assert-Equal $dll.Key 'SYSTEM\CurrentControlSet\Services\lmhosts\Parameters'
    }
    Test-Case 'A hidden ServiceDll without a name resource stays unresolved' {
        function Read-RegistryValue {
            param($Path, $Name)
            if ($Path -like '*\Parameters') { return [pscustomobject]@{ State = 'denied'; Value = $null } }
            [pscustomobject]@{ State = 'present'; Value = $(if ($Name -eq 'DisplayName') { 'Plain name' }) }
        }
        Assert-Equal (Get-ServiceDll -Name 'lmhosts').Unresolved 'ServiceDll key unreadable'
    }
    Test-Case 'A protected inferred ServiceDll earns credit and is named in the reason' {
        function Get-ServiceDll { [pscustomobject]@{ Path = 'C:\synthetic\lmhsvc.dll'; Key = 'SYSTEM\CurrentControlSet\Services\synthetic\Parameters'; Inferred = $true; Unresolved = $null } }
        Invoke-ServiceFixture -PathName 'C:\Windows\system32\svchost.exe -k LocalService'
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'met'
        Assert-Equal $script:Criteria['A-SVC'].Reason.Contains('inferred from the service''s name resource: synthetic') $true
    }
    Test-Case 'A writable inferred ServiceDll is still a finding' {
        function Get-ServiceDll { [pscustomobject]@{ Path = 'C:\synthetic\lmhsvc.dll'; Key = 'SYSTEM\CurrentControlSet\Services\synthetic\Parameters'; Inferred = $true; Unresolved = $null } }
        Invoke-ServiceFixture -PathName 'C:\Windows\system32\svchost.exe -k LocalService' -Grants @{ 'C:\synthetic\lmhsvc.dll' = 'Write' }
        Assert-Equal $script:Criteria['A-SVC'].Critical $true
    }
    Test-Case 'A per-user service instance resolves its ServiceDll through the template' {
        function Read-RegistryValue {
            param($Path, $Name)
            if ($Path -like '*\Services\CDPUserSvc\Parameters') { return [pscustomobject]@{ State = 'present'; Value = '%SystemRoot%\System32\CDPUserSvc.dll' } }
            if ($Path -like '*\Services\CDPUserSvc_1ca413*') { return [pscustomobject]@{ State = 'present'; Value = $null } }
            [pscustomobject]@{ State = 'absent'; Value = $null }
        }
        $dll = Get-ServiceDll -Name 'CDPUserSvc_1ca413'
        Assert-Equal $dll.Path (Join-Path $env:SystemRoot 'System32\CDPUserSvc.dll')
        Assert-Equal $dll.Key 'SYSTEM\CurrentControlSet\Services\CDPUserSvc\Parameters'
    }
    Test-Case 'Machine-wide variables in task paths are expanded; per-user ones are not' {
        $action = [pscustomobject]@{ Execute = '%windir%\system32\synthetic.exe'; Arguments = ''; WorkingDirectory = '' }
        $result = Get-TaskActionTargets $action
        Assert-Equal $result.Incomplete $false
        Assert-Equal (@($result.Paths) -contains (Join-Path $env:windir 'system32\synthetic.exe')) $true
        $action.Execute = '%LOCALAPPDATA%\synthetic.exe'
        Assert-Equal (Get-TaskActionTargets $action).Incomplete $true
    }
    # COM handler fixtures: Read-RegistryValue reads a synthetic registry whose
    # keys are paths (default value) or 'path::name' (named value).
    $comId = '{11111111-2222-3333-4444-555555555555}'
    $machineCom = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$comId"
    $userCom = "Registry::HKEY_USERS\S-1-5-21-101-102-103-1002_Classes\CLSID\$comId"
    function New-SyntheticRegistry {
        param([hashtable]$Values, [string[]]$Denied = @())
        $script:syntheticRegistry = $Values
        $script:syntheticDenied = $Denied
    }
    function Read-RegistryValue {
        param($Path, $Name = '')
        if ($script:syntheticDenied | Where-Object { $Path.StartsWith($_) }) { return [pscustomobject]@{ State = 'denied'; Value = $null } }
        if (-not $script:syntheticRegistry.ContainsKey($Path)) { return [pscustomobject]@{ State = 'absent'; Value = $null } }
        $value = if ($Name) { $script:syntheticRegistry["${Path}::$Name"] } else { $script:syntheticRegistry[$Path] }
        return [pscustomobject]@{ State = 'present'; Value = $value }
    }
    Test-Case 'A service-hosted COM handler is assessed through its service' {
        $appId = '{66666666-7777-8888-9999-000000000000}'
        $appKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\$appId"
        New-SyntheticRegistry @{ $machineCom = ''; "${machineCom}::AppID" = $appId; $appKey = ''; "${appKey}::LocalService" = 'SyntheticSvc' }
        $result = Get-TaskActionTargets ([pscustomobject]@{ ClassId = $comId; Data = '' })
        Assert-Equal $result.Incomplete $false
        Assert-Equal $result.Paths.Count 0
        Assert-Equal (@($result.Keys | Where-Object { $_.Sub -eq "SOFTWARE\Classes\AppID\$appId" }).Count) 1
    }
    Test-Case 'An unregistered COM handler is resolved by whether it can be registered' {
        New-SyntheticRegistry @{}
        $result = Get-TaskActionTargets ([pscustomobject]@{ ClassId = $comId; Data = '' })
        Assert-Equal $result.Incomplete $false
        Assert-Equal (@($result.Keys | Where-Object { $_.Sub -eq 'SOFTWARE\Classes\CLSID' -and $_.Access -eq 0x4 }).Count) 1
    }
    Test-Case 'A rundll32 entry point is not part of the DLL path' {
        $result = Get-ArgumentPathTokens 'C:\WINDOWS\system32\synthetic.dll,EntryPoint'
        Assert-Equal @($result.Paths)[0] 'C:\WINDOWS\system32\synthetic.dll'
    }
    Test-Case 'A bare program name resolves through the system directories' {
        $result = Get-TaskActionTargets ([pscustomobject]@{ Execute = 'sc.exe'; Arguments = ''; WorkingDirectory = '' })
        Assert-Equal $result.Incomplete $false
        Assert-Equal @($result.Paths)[0] (Join-Path ([Environment]::SystemDirectory) 'sc.exe')
    }
    Test-Case 'A bare DLL argument resolves in the program directory only when present' {
        $tool = Join-Path $script:WorkspacePath 'tool.exe'
        [IO.File]::WriteAllText($tool, '')
        [IO.File]::WriteAllText((Join-Path $script:WorkspacePath 'plugin.dll'), '')
        $result = Get-TaskActionTargets ([pscustomobject]@{ Execute = $tool; Arguments = '-m:plugin.dll -f:Run'; WorkingDirectory = '' })
        Assert-Equal $result.Incomplete $false
        Assert-Equal @($result.ArgumentPaths)[0] (Join-Path $script:WorkspacePath 'plugin.dll')
        $result = Get-TaskActionTargets ([pscustomobject]@{ Execute = $tool; Arguments = '-m:absent.dll'; WorkingDirectory = '' })
        Assert-Equal $result.Incomplete $true
    }
    Test-Case 'A headless conhost wrapper is assessed through the command it hosts' {
        $action = [pscustomobject]@{ Execute = 'conhost.exe'; Arguments = '--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File job.ps1'; WorkingDirectory = $script:WorkspacePath }
        $result = Get-TaskActionTargets $action
        Assert-Equal $result.Incomplete $false
        Assert-Equal (@($result.Paths) -contains (Join-Path ([Environment]::SystemDirectory) 'conhost.exe')) $true
        Assert-Equal (@($result.Paths) -contains (Join-Path $script:WorkspacePath 'job.ps1')) $true
    }
    Test-Case 'A service hidden from CIM is read from its registry ImagePath' {
        $serviceKey = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\test-service'
        New-SyntheticRegistry @{ $serviceKey = ''; "${serviceKey}::ImagePath" = 'C:\synthetic\svc.exe -k test'; "${serviceKey}::ObjectName" = 'LocalSystem' }
        function Get-CimInstance { [pscustomobject]@{ Name = 'test-service'; PathName = $null; StartName = $null } }
        function Get-ScheduledTask { @() }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'denied'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'met'
    }
    Test-Case 'A COM handler resolves to its machine-registered server file' {
        New-SyntheticRegistry @{ $machineCom = ''; "$machineCom\InprocServer32" = '%SystemRoot%\system32\synthetic.dll' }
        $result = Get-TaskActionTargets ([pscustomobject]@{ ClassId = $comId; Data = '' })
        Assert-Equal $result.Incomplete $false
        Assert-Equal @($result.Paths)[0] (Join-Path $env:SystemRoot 'system32\synthetic.dll')
    }
    Test-Case 'A principal''s per-user COM registration overrides the machine one' {
        New-SyntheticRegistry @{ $machineCom = ''; "$machineCom\InprocServer32" = 'C:\machine\server.dll'; $userCom = ''; "$userCom\InprocServer32" = 'C:\user\server.dll' }
        $result = Get-TaskActionTargets ([pscustomobject]@{ ClassId = $comId; Data = '' }) -PrincipalSid 'S-1-5-21-101-102-103-1002'
        Assert-Equal @($result.Paths)[0] 'C:\user\server.dll'
    }
    Test-Case 'An unreadable per-user COM hive falls back to the machine registration' {
        New-SyntheticRegistry @{ $machineCom = ''; "$machineCom\InprocServer32" = 'C:\machine\server.dll' } -Denied @('Registry::HKEY_USERS\S-1-5-21-101-102-103-1002')
        $result = Get-TaskActionTargets ([pscustomobject]@{ ClassId = $comId; Data = '' }) -PrincipalSid 'S-1-5-21-101-102-103-1002'
        Assert-Equal $result.Incomplete $false
        Assert-Equal @($result.Paths)[0] 'C:\machine\server.dll'
    }
    foreach ($case in @(
            @{ Name = 'a TreatAs redirection'; Values = @{ $machineCom = ''; "$machineCom\TreatAs" = '{x}'; "$machineCom\InprocServer32" = 'C:\machine\server.dll' } },
            @{ Name = 'a bare server name'; Values = @{ $machineCom = ''; "$machineCom\InprocServer32" = 'server.dll' } })) {
        Test-Case "A COM handler with $($case.Name) stays unresolved" {
            New-SyntheticRegistry $case.Values
            Assert-Equal (Get-TaskActionTargets ([pscustomobject]@{ ClassId = $comId; Data = '' })).Incomplete $true
        }
    }
    Test-Case 'An agent-writable COM registration for a SYSTEM task is critical' {
        New-SyntheticRegistry @{ $machineCom = ''; "$machineCom\InprocServer32" = 'C:\machine\server.dll' }
        [AgentSandboxAssessmentNative]::RegistryGrantedPath = "SOFTWARE\Classes\CLSID\$comId\InprocServer32"
        function Get-CimInstance { @() }
        function Get-ScheduledTask {
            [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = 'S-1-5-18' }
                Actions = @([pscustomobject]@{ ClassId = $comId; Data = '' }) }
        }
        function Test-Path { $true }
        function Get-PathAccess { [pscustomobject]@{ Write = 'denied'; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied' } }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $true
    }
    Test-Case 'Absolute argument paths of a program are extracted; flags are data' {
        $action = [pscustomobject]@{ Execute = 'C:\synthetic\tool.exe'; Arguments = '/reporting --config "C:\Program Files\synthetic\a.json" /out:%ProgramData%\x.log'; WorkingDirectory = '' }
        $result = Get-TaskActionTargets $action
        Assert-Equal $result.Incomplete $false
        Assert-Equal (@($result.ArgumentPaths) -contains 'C:\Program Files\synthetic\a.json') $true
        Assert-Equal (@($result.ArgumentPaths) -contains (Join-Path $env:ProgramData 'x.log')) $true
    }
    foreach ($arguments in @('-f %LOCALAPPDATA%\x.json', '-f sub\x.json', '-f \\server\share\x.json', '-f settings.xml')) {
        Test-Case "An unresolvable argument path stays unknown ($arguments)" {
            $action = [pscustomobject]@{ Execute = 'C:\synthetic\tool.exe'; Arguments = $arguments; WorkingDirectory = '' }
            Assert-Equal (Get-TaskActionTargets $action).Incomplete $true
        }
    }
    Test-Case 'A writable argument path is high but not critical' {
        function Get-CimInstance { @() }
        function Get-ScheduledTask {
            [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = 'S-1-5-18' }
                Actions = @([pscustomobject]@{ Execute = 'C:\synthetic\tool.exe'; Arguments = '--config C:\synthetic\a.json'; WorkingDirectory = '' }) }
        }
        function Test-Path { $true }
        function Get-PathAccess {
            param($Path)
            $write = if ($Path -eq 'C:\synthetic\a.json') { 'granted' } else { 'denied' }
            [pscustomobject]@{ Write = $write; Create = 'denied'; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied'; DeleteChild = 'denied' }
        }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unmet'
        Assert-Equal $script:Criteria['A-SVC'].Critical $false
    }
    Test-Case 'A missing argument path stays unknown instead of plantable' {
        function Get-CimInstance { @() }
        function Get-ScheduledTask {
            [pscustomobject]@{ TaskName = 'synthetic'; Principal = [pscustomobject]@{ UserId = 'S-1-5-18' }
                Actions = @([pscustomobject]@{ Execute = 'C:\synthetic\tool.exe'; Arguments = '--log C:\logs\missing.log'; WorkingDirectory = '' }) }
        }
        function Test-Path { param($LiteralPath) $LiteralPath -ne 'C:\logs\missing.log' }
        function Get-PathAccess {
            param($Path)
            if ($Path -eq 'C:\logs\missing.log') { return [pscustomobject]@{ ErrorCategory = 'not-found'; Exists = $false } }
            # The missing argument's folder would accept a new file.
            $create = if ($Path -eq 'C:\logs') { 'granted' } else { 'denied' }
            [pscustomobject]@{ Write = 'denied'; Create = $create; Delete = 'denied'; ChangeAcl = 'denied'; TakeOwnership = 'denied'; DeleteChild = 'denied'; ErrorCategory = $null; Exists = $true }
        }
        Invoke-IndirectCheck
        Assert-Equal $script:Criteria['A-SVC'].Outcome 'unknown'
        Assert-Equal (@($script:Findings | Where-Object { $_.Result -eq 'granted' }).Count) 0
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

    # --- Known checker gaps (docs/exposure-checker-gaps.md) -------------------
    # New criterion IDs and probe seams below are proposals; rename them here
    # when the implementation chooses differently.

    function New-AdjacentFixture {
        param([string[]]$File = @())
        $root = Join-Path $testRoot ('adjacent-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root | Out-Null
        foreach ($relative in $File) {
            $path = Join-Path $root $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            [IO.File]::WriteAllText($path, 'synthetic')
        }
        return $root
    }

    # High: write reach outside the workspace.
    foreach ($case in @(@{ Write = 'granted'; Expected = 'unmet' }, @{ Write = 'denied'; Expected = 'met' })) {
        Test-Case "Write reach to an adjacent directory ($($case.Write)) is $($case.Expected)" {
            $script:adjacent = New-AdjacentFixture -File 'data.txt'
            function Get-AdjacentDirectories { [pscustomobject]@{ Paths = @($script:adjacent); Incomplete = $false; MaxTargets = 200 } }
            function Get-PathAccess {
                param($Path)
                New-PathAccessFixture -Path $Path -Write $(if ($Path -like "$script:adjacent*") { $case.Write } else { 'denied' })
            }
            Invoke-FilesCheck
            Assert-Equal $script:Criteria['R-FILES-WRITE'].Outcome $case.Expected
        }
    }

    # High: handoff through binaries and repos the human runs.
    Test-Case 'An agent-writable program in an adjacent tree is a shared execution location' {
        $script:adjacent = New-AdjacentFixture -File 'tool.exe', 'lib\helper.dll', 'readme.txt'
        $script:OtherProfiles = @()
        function Get-AdjacentDirectories { [pscustomobject]@{ Paths = @($script:adjacent); Incomplete = $false; MaxTargets = 200 } }
        function Get-PathAccess {
            param($Path)
            New-PathAccessFixture -Path $Path -Write $(if ($Path -like "$script:adjacent\*") { 'granted' } else { 'denied' })
        }
        Invoke-HandoffCheck
        Assert-Equal $script:Criteria['A-HANDOFF-SHARED'].Outcome 'unmet'
        $targets = @($script:Findings | Where-Object { $_.Criterion -eq 'A-HANDOFF-SHARED' } | ForEach-Object { $_.Target })
        Assert-Equal (@($targets | Where-Object { $_ -like '*tool.exe' }).Count) 1
        Assert-Equal (@($targets | Where-Object { $_ -like '*helper.dll' }).Count) 1
        Assert-Equal (@($targets | Where-Object { $_ -like '*readme.txt' }).Count) 0
    }
    Test-Case 'The adjacent program search is bounded per root and reports its limit' {
        $large = New-AdjacentFixture -File 'a.exe', 'b.exe', 'sub\c.dll', 'notes.txt'
        $small = New-AdjacentFixture -File 'tool.exe'
        $result = Get-HandoffArtifacts -Root $large, $small -MaxPerRoot 2
        Assert-Equal $result.Paths.Count 3
        Assert-Equal (@($result.Paths) -contains (Join-Path $small 'tool.exe')) $true
        Assert-Equal $result.Incomplete $true
        $all = Get-HandoffArtifacts -Root $large
        Assert-Equal $all.Paths.Count 3
        Assert-Equal $all.Incomplete $false
    }
    Test-Case 'Writable build entry points of an adjacent repository are shared execution locations' {
        $script:adjacent = New-AdjacentFixture -File 'build.ps1', 'CMakeLists.txt', '.git\hooks\pre-commit.sample'
        $script:OtherProfiles = @()
        function Get-AdjacentDirectories { [pscustomobject]@{ Paths = @($script:adjacent); Incomplete = $false; MaxTargets = 200 } }
        function Get-PathAccess {
            param($Path)
            New-PathAccessFixture -Path $Path -Write $(if ($Path -like "$script:adjacent\*") { 'granted' } else { 'denied' })
        }
        Invoke-HandoffCheck
        $targets = @($script:Findings | Where-Object { $_.Criterion -eq 'A-HANDOFF-SHARED' } | ForEach-Object { $_.Target })
        foreach ($name in @('*build.ps1', '*CMakeLists.txt', '*.git\hooks')) {
            if (-not @($targets | Where-Object { $_ -like $name }).Count) { throw "No A-HANDOFF-SHARED finding for $name." }
        }
    }

    # High: workspace control scripts.
    Test-Case 'The control-integrity remediation names running elevated scripts from an agent-writable checkout' {
        Assert-Equal ($script:Criteria['C-POLICY-INTEGRITY'].Remediation -match 'elevated') $true
    }

    # Medium: egress outside TCP 443. DNS through the system resolver is sent by
    # the DNS Client service, so a per-user firewall rule cannot block it.
    # Dot-source so the mocks stay local to the calling case.
    function Set-BlockedEgressMocks {
        $script:NetworkTarget = @()
        $script:probes = [Collections.Generic.List[string]]::new()
        function Get-LateralTargets { @() }
        function Get-CimInstance { @() }
        function Get-ItemProperty { throw 'No synthetic proxy' }
        function Get-NetTCPConnection { @() }
        function Invoke-TcpProbe { param($HostName, $Port) $script:probes.Add("tcp:${HostName}:$Port"); 'blocked' }
        function Invoke-DnsProbe { param($HostName) $script:probes.Add("dns:$HostName"); 'error' }
        function Invoke-UdpProbe { param($HostName, $Port) $script:probes.Add("udp:${HostName}:$Port"); 'blocked' }
        function Invoke-IcmpProbe { param($HostName) $script:probes.Add("icmp:$HostName"); 'blocked' }
    }
    Test-Case 'Unique DNS names, direct UDP, ICMP and a non-443 TCP port are probed on every run' -Pending {
        . Set-BlockedEgressMocks
        Invoke-NetworkCheck
        $dnsNames = @($script:probes | Where-Object { $_ -like 'dns:*' -and $_ -ne 'dns:example.com' })
        if (-not $dnsNames.Count) { throw 'No unique DNS name was probed.' }
        if (-not @($script:probes | Where-Object { $_ -like 'udp:*:53' }).Count) { throw 'No direct UDP 53 probe.' }
        if (-not @($script:probes | Where-Object { $_ -like 'icmp:*' }).Count) { throw 'No ICMP probe.' }
        if (-not @($script:probes | Where-Object { $_ -match '^tcp:(?!127\.).*:(?!443$)\d+$' }).Count) { throw 'No non-443 Internet TCP probe.' }
        Assert-Equal $script:Criteria['R-NET-COVERT'].Outcome 'met'
    }
    foreach ($case in @(
            @{ Name = 'a resolved unique DNS name'; Mock = 'Invoke-DnsProbe'; Result = 'resolved' },
            @{ Name = 'a direct UDP reply'; Mock = 'Invoke-UdpProbe'; Result = 'reply' },
            @{ Name = 'an ICMP echo reply'; Mock = 'Invoke-IcmpProbe'; Result = 'reply' })) {
        Test-Case "Covert egress through $($case.Name) is unmet while TCP is blocked" -Pending {
            . Set-BlockedEgressMocks
            Set-Item -Path "Function:\$($case.Mock)" -Value ([scriptblock]::Create("'$($case.Result)'"))
            Invoke-NetworkCheck
            Assert-Equal $script:Criteria['R-NET-INTERNET'].Outcome 'met'
            Assert-Equal $script:Criteria['R-NET-COVERT'].Outcome 'unmet'
        }
    }
    Test-Case 'Timed-out UDP and ICMP probes leave covert egress unknown' -Pending {
        . Set-BlockedEgressMocks
        function Invoke-UdpProbe { 'timeout' }
        function Invoke-IcmpProbe { 'timeout' }
        Invoke-NetworkCheck
        Assert-Equal $script:Criteria['R-NET-COVERT'].Outcome 'unknown'
    }
    Test-Case 'The verdict scope no longer excludes DNS and UDP egress' -Pending {
        Assert-Equal ($VerdictScope -match 'DNS/UDP') $false
    }

    # Medium: loopback services.
    Test-Case 'Every loopback and wildcard TCP listener is probed through loopback' {
        . Set-BlockedEgressMocks
        function Get-NetTCPConnection {
            [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 2179; OwningProcess = 101; State = 'Listen' }
            [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 3240; OwningProcess = 102; State = 'Listen' }
            [pscustomobject]@{ LocalAddress = '::'; LocalPort = 3389; OwningProcess = 103; State = 'Listen' }
            [pscustomobject]@{ LocalAddress = '192.168.2.10'; LocalPort = 5000; OwningProcess = 104; State = 'Listen' }
        }
        Invoke-NetworkCheck
        foreach ($expected in @('tcp:127.0.0.1:2179', 'tcp:127.0.0.1:3240', 'tcp:::1:3389')) {
            if ($script:probes -notcontains $expected) { throw "Listener not probed: $expected." }
        }
        Assert-Equal (@($script:probes | Where-Object { $_ -like '*:5000' }).Count) 0
        Assert-Equal $script:Criteria['R-NET-LATERAL'].Outcome 'met'
    }
    Test-Case 'A loopback proxy listener is not probed as lateral reach' {
        . Set-BlockedEgressMocks
        $env:HTTP_PROXY = 'http://127.0.0.1:8080'
        function Invoke-ProxyProbe { 403 }
        function Get-NetTCPConnection { [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 8080; OwningProcess = 101; State = 'Listen' } }
        Invoke-NetworkCheck
        Assert-Equal ($script:probes -contains 'tcp:127.0.0.1:8080') $false
    }
    Test-Case 'An unreadable listener table is recorded without failing the network check' {
        . Set-BlockedEgressMocks
        function Get-NetTCPConnection { throw 'synthetic CIM failure' }
        Invoke-NetworkCheck
        Assert-Equal (@($script:Errors | Where-Object { $_.Message -like '*TCP listeners*' }).Count) 1
    }

    # Medium: high-value files outside the scan scope.
    Test-Case 'Adjacent trees without credential container names meet the name search' {
        $script:adjacent = New-AdjacentFixture -File 'notes.txt', 'keys\id_ed25519.pub'
        function Get-AdjacentDirectories { [pscustomobject]@{ Paths = @($script:adjacent); Incomplete = $false; MaxTargets = 200 } }
        function Get-PathAccess { param($Path) New-PathAccessFixture -Path $Path -Read granted }
        Invoke-FilesCheck
        Assert-Equal $script:Criteria['R-FILES-SECRETS'].Outcome 'met'
    }
    Test-Case 'Credential containers in adjacent trees are found by name without reading them' {
        $script:adjacent = New-AdjacentFixture -File 'signing.pfx', 'keys\id_ed25519', 'vault\db.kdbx', 'notes.txt'
        # Exclusive handles make any content read fail; a name-only search succeeds.
        $locks = @('signing.pfx', 'keys\id_ed25519', 'vault\db.kdbx') |
            ForEach-Object { [IO.File]::Open((Join-Path $script:adjacent $_), 'Open', 'Read', 'None') }
        try {
            function Get-AdjacentDirectories { [pscustomobject]@{ Paths = @($script:adjacent); Incomplete = $false; MaxTargets = 200 } }
            function Get-PathAccess { param($Path) New-PathAccessFixture -Path $Path -Read granted }
            Invoke-FilesCheck
            Assert-Equal $script:Criteria['R-FILES-SECRETS'].Outcome 'unmet'
            $targets = @($script:Findings | Where-Object { $_.Criterion -eq 'R-FILES-SECRETS' } | ForEach-Object { $_.Target })
            foreach ($name in @('*signing.pfx', '*id_ed25519', '*db.kdbx')) {
                if (-not @($targets | Where-Object { $_ -like $name }).Count) { throw "No R-FILES-SECRETS finding for $name." }
            }
            Assert-Equal (@($targets | Where-Object { $_ -like '*notes.txt' }).Count) 0
        }
        finally { $locks | ForEach-Object { $_.Dispose() } }
    }

    # Medium: code execution policy.
    foreach ($case in @(
            @{ Name = 'UMCI off without AppLocker'; Umci = 0; Mode = 'NotConfigured'; Service = 'Stopped'; Expected = 'unmet' },
            @{ Name = 'UMCI in audit mode'; Umci = 1; Mode = 'NotConfigured'; Service = 'Stopped'; Expected = 'unmet' },
            @{ Name = 'enforced UMCI'; Umci = 2; Mode = 'NotConfigured'; Service = 'Stopped'; Expected = 'met' },
            @{ Name = 'enforced AppLocker exe rules'; Umci = 0; Mode = 'Enabled'; Service = 'Running'; Expected = 'met' },
            @{ Name = 'AppLocker rules without AppIDSvc'; Umci = 0; Mode = 'Enabled'; Service = 'Stopped'; Expected = 'unmet' },
            @{ Name = 'audit-only AppLocker rules'; Umci = 0; Mode = 'AuditOnly'; Service = 'Running'; Expected = 'unmet' })) {
        Test-Case "Execution policy with $($case.Name) is $($case.Expected)" {
            function Get-CimInstance { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = $case.Umci } }
            function Get-AppLockerPolicy {
                [pscustomobject]@{ RuleCollections = @([pscustomobject]@{ RuleCollectionType = 'Exe'; EnforcementMode = $case.Mode; Count = 3 }) }
            }
            function Get-Service { [pscustomobject]@{ Status = $case.Service } }
            Invoke-ExecutionPolicyCheck
            Assert-Equal $script:Criteria['C-EXEC-POLICY'].Outcome $case.Expected
        }
    }
    Test-Case 'An unreadable WDAC status without enforced AppLocker leaves execution policy unknown' {
        function Get-CimInstance { throw 'synthetic access denied' }
        function Get-AppLockerPolicy { [pscustomobject]@{ RuleCollections = @() } }
        Invoke-ExecutionPolicyCheck
        Assert-Equal $script:Criteria['C-EXEC-POLICY'].Outcome 'unknown'
    }
    Test-Case 'Missing AppLocker cmdlets count as no AppLocker policy' {
        function Get-CimInstance { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = 0 } }
        function Get-Command { $null }
        Invoke-ExecutionPolicyCheck
        Assert-Equal $script:Criteria['C-EXEC-POLICY'].Outcome 'unmet'
    }
    Test-Case 'An AppLocker cmdlet that fails to load leaves execution policy unknown' {
        function Get-CimInstance { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = 0 } }
        function Get-AppLockerPolicy { throw [System.Management.Automation.CommandNotFoundException]::new('module could not be loaded') }
        Invoke-ExecutionPolicyCheck
        Assert-Equal $script:Criteria['C-EXEC-POLICY'].Outcome 'unknown'
    }

    # Low: named pipe ACLs. Scheduled-task persistence needs a registration and
    # belongs in Test-AgentSandboxAttackSurfaces.ps1, not this read-only checker.
    Test-Case 'A named pipe that grants the agent write access is reported' -Pending {
        function Get-Process { @() }
        function Get-NamedPipes { 'codex-ipc', 'other-pipe' }
        [AgentSandboxAssessmentNative]::NamedPath = '\\.\pipe\codex-ipc'
        [AgentSandboxAssessmentNative]::NamedGranted = 0x2
        Invoke-ProcessesCheck
        Assert-Equal $script:Criteria['A-IPC-PIPES'].Outcome 'unmet'
        $targets = @($script:Findings | Where-Object { $_.Criterion -eq 'A-IPC-PIPES' } | ForEach-Object { $_.Target })
        Assert-Equal ($targets -join ',') '\\.\pipe\codex-ipc'
    }

    # Low: git trust. Git refuses repositories owned by another account unless
    # safe.directory allows them, so the dangerous case is a repository owned
    # by another identity whose hooks the agent can write.
    foreach ($case in @(
            @{ Owner = 'S-1-5-21-101-102-103-1002'; Expected = 1 },
            @{ Owner = 'S-1-5-21-101-102-103-1001'; Expected = 0 })) {
        $ownerLabel = if ($case.Expected) { 'another identity' } else { 'the agent' }
        Test-Case "Writable hooks in a workspace repository owned by $ownerLabel are reported ($($case.Expected))" {
            New-Item -ItemType Directory -Path (Join-Path $script:WorkspacePath '.git\hooks') | Out-Null
            $script:OtherProfiles = @()
            function Get-OwnerSid { $case.Owner }
            function Get-PathAccess { param($Path) New-PathAccessFixture -Path $Path -Write granted }
            Invoke-HandoffCheck
            $hookFindings = @($script:Findings | Where-Object { $_.Criterion -eq 'A-HANDOFF-WORKSPACE' -and $_.Target -like '*.git\hooks' })
            Assert-Equal $hookFindings.Count $case.Expected
        }
    }
}
finally {
    $env:USERPROFILE = $savedProfile
    $env:HTTP_PROXY = $savedProxies.HTTP_PROXY
    $env:HTTPS_PROXY = $savedProxies.HTTPS_PROXY
    $env:CLAUDECODE = $savedClaudeCode
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
