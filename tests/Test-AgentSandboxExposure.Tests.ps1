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
public sealed class TestToken { public string UserSid = "S-1-5-21-101-102-103-1001"; }
public static class AgentSandboxAssessmentNative {
    public static int NamedError;
    public static uint NamedGranted;
    public static int FileError;
    public static uint ServiceGranted;
    public static readonly List<uint> ServiceRequests = new List<uint>();
    public static TestAccessResult CheckNamedObject(string path, int type) {
        return new TestAccessResult { Granted = NamedGranted, Error = NamedError };
    }
    public static int ProbeFile(string path, uint right) { return FileError; }
    public static int ProbeService(string name, uint right) {
        ServiceRequests.Add(right);
        return (right & ServiceGranted) == right ? 0 : 5;
    }
    public static int ProbeRegistryKey(int hive, string path, uint right) { return 5; }
    public static TestToken GetCurrentToken() { return new TestToken(); }
    public static int GetSessionId(int pid) { return 0; }
    public static string GetConsoleSessionUser() { return null; }
    public static string GetSessionUser() { return "TestAgent"; }
}
'@

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('exposure-regression-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$savedProfile = $env:USERPROFILE
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
    [AgentSandboxAssessmentNative]::ServiceGranted = 0
    [AgentSandboxAssessmentNative]::ServiceRequests.Clear()
    try {
        & $Body
        Write-Host "PASS $Name"
    }
    catch {
        $failures.Add("${Name}: $($_.Exception.Message)")
        Write-Host "FAIL $Name"
    }
}

try {
    Test-Case 'Unknown write permissions do not earn protection credit' {
        [AgentSandboxAssessmentNative]::NamedError = 5
        Resolve-AccessTargets -Check CONTAINMENT -Criterion C-POLICY-INTEGRITY -Right Write `
            -Path $script:WorkspacePath -Capability test -Scope test -Impact test `
            -NoneReason absent -MetReason protected -UnmetReasonFormat '{0} writable' | Out-Null
        Assert-Equal $script:Criteria['C-POLICY-INTEGRITY'].Outcome 'unknown'
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
        Assert-Equal (@([AgentSandboxAssessmentNative]::ServiceRequests | Where-Object { $_ -notin 2, 0x40000, 0x80000 }).Count) 0
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
}
finally {
    $env:USERPROFILE = $savedProfile
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
