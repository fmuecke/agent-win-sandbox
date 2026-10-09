# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

# Shared configuration functions. Dot-sourced by setup, Apply-Config, the
# launcher, the shell initializer, and the checker.
#
# config.json holds the user settings (workspace, proxy, directEndpoints) and a
# generated 'setup' section. Settings are validated strictly: unknown or
# duplicate keys are rejected so a typo cannot silently drop a restriction.

$AgentSandboxSettingKeys = @('workspace', 'proxy', 'directEndpoints')
$AgentSandboxProxyKeys = @('port', 'allowedHosts')
$AgentSandboxEndpointKeys = @('endpoint', 'label')
$AgentSandboxMaxLockEndpoints = 32    # wfp-lock policy limit

# --- Reading ------------------------------------------------------------------
function Assert-AgentSandboxUniqueJsonKeys {
    param([System.Text.Json.JsonElement]$Element, [string]$Path)

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $keys.Add($property.Name)) {
                throw "Duplicate config key: $Path$($property.Name)"
            }
            Assert-AgentSandboxUniqueJsonKeys -Element $property.Value -Path "$Path$($property.Name)."
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-AgentSandboxUniqueJsonKeys -Element $item -Path $Path
        }
    }
}

function Read-AgentSandboxConfig {
    param([string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to read linked config: $Path"
    }
    $text = Get-Content -LiteralPath $Path -Raw
    $document = [System.Text.Json.JsonDocument]::Parse($text)
    try { Assert-AgentSandboxUniqueJsonKeys -Element $document.RootElement -Path '' }
    finally { $document.Dispose() }
    $config = $text | ConvertFrom-Json -AsHashtable
    if ($config -isnot [Collections.IDictionary]) {
        throw "Config must be a JSON object: $Path"
    }
    return $config
}

# --- Merging ------------------------------------------------------------------
# Objects merge key by key; lists and values in Override replace those in Base.
function Merge-AgentSandboxSettings {
    param([Collections.IDictionary]$Base, [Collections.IDictionary]$Override)

    $result = [ordered]@{}
    foreach ($key in $Base.Keys) { $result[$key] = $Base[$key] }
    foreach ($key in $Override.Keys) {
        if ($result[$key] -is [Collections.IDictionary] -and $Override[$key] -is [Collections.IDictionary]) {
            $result[$key] = Merge-AgentSandboxSettings -Base $result[$key] -Override $Override[$key]
        }
        else {
            $result[$key] = $Override[$key]
        }
    }
    return $result
}

function Get-AgentSandboxSettings {
    param([Collections.IDictionary]$Config)

    $settings = [ordered]@{}
    foreach ($key in $Config.Keys) {
        if ($key -cne 'setup') { $settings[$key] = $Config[$key] }
    }
    return $settings
}

# --- Validation ---------------------------------------------------------------
function Test-AgentSandboxInteger {
    param($Value, [int]$Minimum, [int]$Maximum)

    return ($Value -is [int] -or $Value -is [long]) -and $Value -ge $Minimum -and $Value -le $Maximum
}

function Assert-AgentSandboxKeys {
    param([Collections.IDictionary]$Object, [string[]]$Allowed, [string]$Name)

    foreach ($key in $Object.Keys) {
        if ($key -cnotin $Allowed) {
            throw "Unknown $Name setting '$key'. Allowed: $($Allowed -join ', ')."
        }
    }
    foreach ($key in $Allowed) {
        if (-not $Object.Contains($key)) {
            throw "Missing $Name setting '$key'."
        }
    }
}

# Returns the normalized endpoint, e.g. '10.0.0.5:1433' or '[2001:db8::5]:443'.
function ConvertTo-AgentSandboxEndpoint {
    param([string]$Endpoint)

    if ($Endpoint -match '^\[(?<ip>[0-9A-Fa-f:.]+)\]:(?<port>\d{1,5})$') {
        $family = [Net.Sockets.AddressFamily]::InterNetworkV6
    }
    elseif ($Endpoint -match '^(?<ip>\d{1,3}(\.\d{1,3}){3}):(?<port>\d{1,5})$') {
        $family = [Net.Sockets.AddressFamily]::InterNetwork
    }
    else {
        throw "Endpoint '$Endpoint' must be <ipv4>:<port> or [<ipv6>]:<port>; host names are not allowed."
    }
    $port = [int]$Matches.port
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Matches.ip, [ref]$address) -or $address.AddressFamily -ne $family) {
        throw "Endpoint '$Endpoint' has an invalid IP address."
    }
    if ($port -lt 1 -or $port -gt 65535) {
        throw "Endpoint '$Endpoint' has an invalid port."
    }
    if ($address.IsIPv4MappedToIPv6) {
        $address = $address.MapToIPv4()
    }
    if ($address.Equals([Net.IPAddress]::Any) -or $address.Equals([Net.IPAddress]::IPv6Any)) {
        throw "Endpoint '$Endpoint' is a wildcard address."
    }
    if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        return "[$address]:$port"
    }
    return "${address}:$port"
}

# Throws on invalid settings. Returns warnings that setup and Apply-Config show.
function Test-AgentSandboxSettings {
    param([Collections.IDictionary]$Settings)

    $warnings = [Collections.Generic.List[string]]::new()
    Assert-AgentSandboxKeys -Object $Settings -Allowed $AgentSandboxSettingKeys -Name 'top-level'

    $workspace = $Settings['workspace']
    if ($workspace -isnot [string] -or $workspace -notmatch '^[A-Za-z]:\\') {
        throw "workspace must be an absolute local path such as C:\AgentSandbox."
    }
    if ((Split-Path -Path $workspace -Leaf) -cne 'AgentSandbox') {
        throw "workspace must end in the directory name 'AgentSandbox': $workspace"
    }

    $proxy = $Settings['proxy']
    if ($proxy -isnot [Collections.IDictionary]) { throw 'proxy must be an object.' }
    Assert-AgentSandboxKeys -Object $proxy -Allowed $AgentSandboxProxyKeys -Name 'proxy'
    if (-not (Test-AgentSandboxInteger -Value $proxy['port'] -Minimum 1 -Maximum 65535)) {
        throw 'proxy.port must be an integer from 1 to 65535.'
    }
    if ($proxy['allowedHosts'] -isnot [array]) { throw 'proxy.allowedHosts must be a list.' }
    foreach ($hostEntry in $proxy['allowedHosts']) {
        if ($hostEntry -isnot [string] -or $hostEntry -notmatch '^\S+:(\d{1,5})$' -or
            [int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535) {
            throw "proxy.allowedHosts entry '$hostEntry' must be <host>:<port>."
        }
    }

    $proxyEndpoint = "127.0.0.1:$($proxy['port'])"
    if ($Settings['directEndpoints'] -isnot [array]) { throw 'directEndpoints must be a list.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Settings['directEndpoints']) {
        if ($entry -isnot [Collections.IDictionary]) {
            throw 'Each directEndpoints entry must be an object with endpoint and label.'
        }
        Assert-AgentSandboxKeys -Object $entry -Allowed $AgentSandboxEndpointKeys -Name 'directEndpoints'
        $label = $entry['label']
        if ($label -isnot [string] -or [string]::IsNullOrWhiteSpace($label) -or $label -match '[\r\n]') {
            throw "directEndpoints entry '$($entry['endpoint'])' needs a one-line label."
        }
        $endpoint = ConvertTo-AgentSandboxEndpoint -Endpoint ([string]$entry['endpoint'])
        if ($endpoint -eq $proxyEndpoint) {
            throw "directEndpoints entry '$endpoint' is the proxy endpoint, which is always allowed."
        }
        if (-not $seen.Add($endpoint)) {
            throw "directEndpoints lists '$endpoint' more than once."
        }
        $ip = [Net.IPAddress]::Parse(($endpoint -replace ':\d+$', '').Trim('[', ']'))
        if ([Net.IPAddress]::IsLoopback($ip)) {
            $warnings.Add("Direct endpoint $endpoint ($label) exposes a local service on this machine to the agent.")
        }
    }
    if ($seen.Count + 1 -gt $AgentSandboxMaxLockEndpoints) {
        throw "Too many directEndpoints: the network lock holds at most $AgentSandboxMaxLockEndpoints endpoints including the proxy."
    }

    return , $warnings.ToArray()
}

# --- Derived values -----------------------------------------------------------
# The network lock allows the local proxy plus the configured direct endpoints.
function Get-AgentSandboxLockEndpoints {
    param([Collections.IDictionary]$Settings)

    $endpoints = @("127.0.0.1:$($Settings['proxy']['port'])")
    foreach ($entry in $Settings['directEndpoints']) {
        $endpoints += ConvertTo-AgentSandboxEndpoint -Endpoint ([string]$entry['endpoint'])
    }
    return $endpoints -join ','
}

# Detects settings edited after Apply-Config. Top-level keys are sorted; nested
# order follows the file, so reordering nested keys also requires Apply-Config.
function Get-AgentSandboxSettingsHash {
    param([Collections.IDictionary]$Config)

    $settings = [ordered]@{}
    foreach ($key in ($Config.Keys | Where-Object { $_ -cne 'setup' } | Sort-Object -CaseSensitive)) {
        $settings[$key] = $Config[$key]
    }
    $json = ConvertTo-Json -InputObject $settings -Depth 10 -Compress
    $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($json))
    return [Convert]::ToHexString($hash)
}
