# claude-win-sandbox

Windows PowerShell tooling that runs Claude Code as the standard local user
`ClaudeSandbox`.

## Repository map

- `Setup-ClaudeSandbox.ps1`: elevated provisioning, ACLs, hardening, bootstrap.
- `Remove-ClaudeSandbox.ps1`: elevated removal of the account, firewall rules,
  login-screen registry value, and generated ProgramData state.
- `Start-ClaudeSandbox.ps1`: normal daily launcher using `launch-as`.
- `Check-ClaudeSandbox.ps1`: read-only verifier.
- `bootstrap/`: source copied to locked ProgramData; `managed-settings.json`:
  policy template for `C:\Program Files\ClaudeCode\managed-settings.json`.
- `README.md`: user guide and threat model; `discovery/`: non-executable
  research.

## Change and validation rules

- There is no build. Before committing script changes, parse every shipped
  script and run `git diff --check`:

  ```powershell
  $files = 'Setup-ClaudeSandbox.ps1','Remove-ClaudeSandbox.ps1','Start-ClaudeSandbox.ps1','Check-ClaudeSandbox.ps1','bootstrap\Enter-ClaudeDevShell.ps1'
  foreach ($file in $files) { $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $file), [ref]$null, [ref]$errors); $errors }
  git diff --check
  ```

- Do not run setup or removal casually: they change local users, ACLs, registry,
  policy, and ProgramData. Prefer parser checks and review; test real changes on
  a disposable VM or dedicated development machine.
- Use the repository `Check-ClaudeSandbox.ps1` only for explicit installed-state
  verification. Do not elevate it or use the ProgramData copy unless explicitly
  requested.

## PowerShell and security

- Use 4-space indentation, small verb-named functions, explicit paths, and
  section-banner comments. Use single-quoted literals; interpolate only with
  double quotes. Escape runtime variables in expandable here-strings (for
  example, `` `$RepoPath ``).
- Prefer the smallest clear implementation, especially in setup, ACL, firewall,
  and teardown paths.
- Keep `ClaudeSandbox` a standard user; keep bootstrap files admin-write /
  Users-read-execute; install Claude per-user in
  `C:\Users\ClaudeSandbox`. Document any credential caching or access widening
  with its threat-model tradeoff.

## Commits and PRs

- Use short, imperative, single-purpose commits.
- State intent, affected scripts, manual validation, security-boundary impact,
  elevated commands, and whether testing used a clean or existing sandbox.
