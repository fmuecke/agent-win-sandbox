# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0
param([string]$ProxyExecutable)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\bootstrap\AgentSandboxConfig.ps1')
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('agent proxy test ' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    $settings = @{ proxy = @{ port = 18080; allowedHosts = @('example.com:443', '*.example.org:443') } }
    $json = Get-AgentSandboxProxyJson -Settings $settings -StateRoot $fixtureRoot
    $policy = $json | ConvertFrom-Json
    if ($policy.port -ne 18080 -or $policy.privateaddresses -cne 'deny' -or
        $policy.loglevel -cne 'info' -or $policy.logfile -cne (Join-Path $fixtureRoot 'allowproxy.log') -or
        ($policy.allowed -join ',') -cne 'example.com:443,*.example.org:443') {
        throw 'Inline proxy policy does not preserve the configured restrictions.'
    }
    if (@(Get-ChildItem -LiteralPath $fixtureRoot).Count) { throw 'Generating JSON must not write a file.' }
    Write-Output 'PASS: inline JSON policy and no separate config file'

    & {
        $calls = [Collections.Generic.List[int]]::new()
        function Invoke-AgentSandboxProxy {
            param($Exe, $Operation, $ConfigJson)
            if ($Operation -ne 'stop') { throw 'Expected stop.' }
            $calls.Add(($ConfigJson | ConvertFrom-Json).port)
            $global:LASTEXITCODE = 0
        }
        $runtimeConfig = Join-Path $fixtureRoot 'allowproxy.inline-18080.json'
        Set-Content -LiteralPath $runtimeConfig -Value $json
        Set-Content -LiteralPath "$runtimeConfig.pid" -Value '123 456 inline'
        $settings.proxy.port = 19090
        Stop-AgentSandboxProxy -Exe (Join-Path $fixtureRoot 'allowproxy.exe')
        if (($calls -join ',') -ne '18080') { throw 'Stop must target the running port after settings change.' }
        Remove-Item -LiteralPath $runtimeConfig, "$runtimeConfig.pid"
        Write-Output 'PASS: stop finds the previous port independently of edited settings'
    }

    if ($ProxyExecutable) {
        $exe = Join-Path $fixtureRoot 'allowproxy.exe'
        Copy-Item -LiteralPath $ProxyExecutable -Destination $exe
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $settings.proxy.port = $listener.LocalEndpoint.Port
        $listener.Stop()
        $json = Get-AgentSandboxProxyJson -Settings $settings -StateRoot $fixtureRoot
        $runtimeConfig = Join-Path $fixtureRoot "allowproxy.inline-$($settings.proxy.port).json"
        # The helper must preserve quotes regardless of the shell's native mode.
        $PSNativeCommandArgumentPassing = 'Legacy'
        try {
            Invoke-AgentSandboxProxy -Exe $exe -Operation start -ConfigJson $json
            if ($LASTEXITCODE -ne 0) { throw 'Inline start failed.' }
            $status = Invoke-AgentSandboxProxy -Exe $exe -Operation status -ConfigJson $json
            if ($LASTEXITCODE -ne 0 -or $status -notmatch "127\.0\.0\.1:$($settings.proxy.port)(?!\d)") {
                throw 'Inline status failed.'
            }
            $actual = Read-AgentSandboxConfig -Path $runtimeConfig
            if (($actual | ConvertTo-Json -Depth 4 -Compress) -cne $json) { throw 'Native JSON argument was changed.' }
            $client = [Net.Sockets.TcpClient]::new('127.0.0.1', $settings.proxy.port)
            try {
                $client.ReceiveTimeout = 5000
                $stream = $client.GetStream()
                $request = [Text.Encoding]::ASCII.GetBytes("CONNECT denied.invalid:443 HTTP/1.1`r`nHost: denied.invalid:443`r`n`r`n")
                $stream.Write($request, 0, $request.Length)
                $reader = [IO.StreamReader]::new($stream)
                if ($reader.ReadLine() -notmatch '^HTTP/1\.1 403 ') { throw 'Unlisted destination was not denied.' }
            }
            finally { $client.Dispose() }
        }
        finally { Stop-AgentSandboxProxy -Exe $exe }
        if ((Test-Path -LiteralPath $runtimeConfig) -or (Test-Path -LiteralPath "$runtimeConfig.pid")) {
            throw 'Stop left inline runtime configuration behind.'
        }
        $null = Invoke-AgentSandboxProxy -Exe $exe -Operation status -ConfigJson $json
        if ($LASTEXITCODE -ne 3) { throw 'Stopped proxy still reports running.' }
        Write-Output 'PASS: release binary start/status/deny/stop, JSON quoting, and runtime cleanup'
    }
}
finally {
    # fixtureRoot is an absolute, uniquely created child of the temporary directory.
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
