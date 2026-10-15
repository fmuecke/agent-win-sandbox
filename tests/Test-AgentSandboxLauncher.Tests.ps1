# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of agent-win-sandbox: https://github.com/fmuecke/agent-win-sandbox

#Requires -Version 7.0

# Load only the ACL check. Never launch a session or change filesystem ACLs.
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '..\Start-AgentSandbox.ps1'), [ref]$null, [ref]$null)
$definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-WriteAccessIssue'
    }, $true)
. ([scriptblock]::Create($definition.Extent.Text))

function Get-Item {
    param($LiteralPath, [switch]$Force)
    [pscustomobject]@{ LinkType = $null; Attributes = [IO.FileAttributes]::Directory }
}
function Get-Acl {
    param($LiteralPath)
    $script:fixtureAcl
}

foreach ($case in @(
        @{ Name = 'inherit-only CREATOR OWNER'; Owner = 'S-1-5-32-544'; Writer = 'S-1-3-0'; Propagation = 'InheritOnly'; Issue = '' },
        @{ Name = 'inherit-only combined flags'; Owner = 'S-1-5-32-544'; Writer = 'S-1-3-0'; Propagation = 'InheritOnly, NoPropagateInherit'; Issue = '' },
        @{ Name = 'effective Users write'; Owner = 'S-1-5-32-544'; Writer = 'S-1-5-32-545'; Propagation = 'None'; Issue = 'writable by S-1-5-32-545' },
        @{ Name = 'effective CREATOR OWNER is not blanket-trusted'; Owner = 'S-1-5-32-544'; Writer = 'S-1-3-0'; Propagation = 'None'; Issue = 'writable by S-1-3-0' },
        @{ Name = 'untrusted owner with inherit-only ACE'; Owner = 'S-1-5-32-545'; Writer = 'S-1-3-0'; Propagation = 'InheritOnly'; Issue = 'owned by S-1-5-32-545' }
    )) {
    $script:fixtureAcl = [Security.AccessControl.DirectorySecurity]::new()
    $script:fixtureAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($case.Owner))
    $script:fixtureAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($case.Writer),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]$case.Propagation,
            [Security.AccessControl.AccessControlType]::Allow))
    $issue = Get-WriteAccessIssue -Path 'C:\Program Files\fixture'
    if (($case.Issue -and $issue -notlike "*$($case.Issue)*") -or (-not $case.Issue -and $issue)) {
        throw "$($case.Name): unexpected ACL result: $issue"
    }
    Write-Output "PASS: $($case.Name)"
}
