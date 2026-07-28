# Repository Guidelines

## Project Structure & Module Organization

This repository contains a small Windows PowerShell toolset for running Claude Code as a low-privilege local user.

- `Setup-ClaudeSandbox.ps1`: one-time elevated provisioning for the `ClaudeSandbox` user, ACLs, hardening, and bootstrap installation.
- `Remove-ClaudeSandbox.ps1`: elevated teardown for the `ClaudeSandbox` user, firewall rules, login-screen registry value, and generated ProgramData state.
- `Start-ClaudeSandbox.ps1`: normal day-to-day launcher using the bundled `launch-as` helper.
- `Check-ClaudeSandbox.ps1`: read-only verifier for account state, ACLs, bootstrap, policy, and toolchain assumptions.
- `bootstrap/`: source bootstrap scripts copied into locked ProgramData by setup.
- `managed-settings.json`: Claude Code enterprise policy template intended for deployment to `C:\Program Files\ClaudeCode\managed-settings.json`.
- `README.md`: user-facing setup and threat-model documentation.
- `discovery/`: research notes and design background. Do not treat these as executable source.

## Build, Test, and Development Commands

There is no build step. Validate script changes with parser checks before committing:

```powershell
$errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Setup-ClaudeSandbox.ps1), [ref]$null, [ref]$errors); $errors
$errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Remove-ClaudeSandbox.ps1), [ref]$null, [ref]$errors); $errors
$errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Start-ClaudeSandbox.ps1), [ref]$null, [ref]$errors); $errors
$errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Check-ClaudeSandbox.ps1), [ref]$null, [ref]$errors); $errors
$errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\bootstrap\Enter-ClaudeDevShell.ps1), [ref]$null, [ref]$errors); $errors
git diff --check
```

Use the repo-local `.\Check-ClaudeSandbox.ps1` only when explicitly verifying an installed sandbox. Do not run it elevated or use the ProgramData-installed copy unless the user explicitly asks for installed-state verification.

## Coding Style & Naming Conventions

Use PowerShell with 4-space indentation. Keep functions small and named with approved verb-style names where practical, such as `Write-Step`. Prefer explicit paths and clear parameter names over implicit global state. Preserve the existing section-banner comment style for major script phases.

Use single quotes for literal strings and double quotes only when interpolation is needed. In expandable here-strings that generate scripts, escape runtime variables with a backtick, for example `` `$RepoPath ``.

Keep implementations simple and maintainable. Aim for working, easy-to-review code that is good enough for the threat model rather than clever or highly generalized machinery. This matters especially for security-sensitive setup, ACL, firewall, and teardown code: less complexity means fewer threat vectors and fewer mistakes.

## Testing Guidelines

Avoid executing provisioning or teardown paths casually: `Setup-ClaudeSandbox.ps1` changes local users, ACLs, registry values, and security policy; `Remove-ClaudeSandbox.ps1` removes the sandbox user and generated ProgramData state. For review, prefer parser checks, `git diff --check`, and close inspection of script contents. Test real setup/removal changes on a disposable Windows VM or dedicated dev machine.

## Commit & Pull Request Guidelines

Recent commit messages are short, imperative summaries, for example `Harden sandbox bootstrap and require per-user Claude installs`. Keep commits focused on one intent.

Pull requests should include the intent, affected scripts, manual validation performed, and any security-boundary implications. Mention whether elevated commands were run and whether behavior was tested on a clean or existing `ClaudeSandbox` account.

## Security & Configuration Tips

Do not add credential caching or broaden the sandbox user’s access without documenting the threat-model tradeoff. Keep `ClaudeSandbox` as a standard user, keep the bootstrap admin-write/Users-read-execute, and keep Claude installed per-user under `C:\Users\ClaudeSandbox`.
