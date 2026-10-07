# Agent Working Agreement

Optimize for the intended outcome, not merely the requested implementation.

- Clarify consequential assumptions early.
- Treat requirements and inherited constraints as hypotheses.
- Remove unnecessary scope before adding or optimizing anything.
- Prefer eliminating causes over compensating for symptoms.
- Complexity must justify itself.
- First make the change easy, then make the easy change.
- Tidy first when a small structural change makes the intended change simpler or safer.
- For changed functional behavior, prefer the simplest meaningful test first when practical.
- Keep structural and behavioral changes separate when practical.
- Prefer small, reversible steps and fast feedback.

Use `first-principles-analysis` for significant design, architecture, requirements, or optimization decisions.
Use `security-review` for security-sensitive work.
Use `redpen` for human-facing prose where signal/noise matters.

## Completion

Use the `definition-of-done` skill to establish required verification early and before any claim that coding work is complete, fixed, ready, or done.

# agent-win-sandbox

Windows PowerShell tooling that runs AI coding agents as the standard local
user `AgentSandbox`.

## Repository map

- `Setup-AgentSandbox.ps1`: elevated provisioning, ACLs, hardening, bootstrap.
- `Remove-AgentSandbox.ps1`: elevated removal of the account, login-screen registry value, and generated ProgramData state.
- `Start-AgentSandbox.ps1`: normal daily PowerShell 7 launcher using
  `launch-as`.
- `Check-AgentSandbox.ps1`: read-only verifier.
- `bootstrap/`: shell initialization and Developer Shell command copied to
  locked ProgramData.
- `scripts/*-wrapper.ps1`: protected per-agent install/update/launch commands.
- `config/managed-settings.json`: policy template for
  `C:\Program Files\ClaudeCode\managed-settings.json`.
- `README.md`: user guide and threat model; `discovery/`: non-executable
  research.

## Change and validation rules

- There is no build. Before committing script changes, parse every shipped
  script and run `git diff --check`:

  ```powershell
  $files = 'Setup-AgentSandbox.ps1','Remove-AgentSandbox.ps1','Start-AgentSandbox.ps1','Check-AgentSandbox.ps1','bootstrap\Initialize-AgentSandboxShell.ps1','bootstrap\Enter-DevShell.ps1','scripts\claude-wrapper.ps1','scripts\copilot-wrapper.ps1'
  foreach ($file in $files) { $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $file), [ref]$null, [ref]$errors); $errors }
  git diff --check
  ```

- Do not run setup or removal casually: they change local users, ACLs, registry,
  policy, and ProgramData. Prefer parser checks and review; test real changes on
  a disposable VM or dedicated development machine.
- Use the repository `Check-AgentSandbox.ps1` only for explicit installed-state
  verification. Do not elevate it or use the ProgramData copy unless explicitly
  requested.

## PowerShell and security

- Use 4-space indentation, small verb-named functions, explicit paths, and
  section-banner comments. Use single-quoted literals; interpolate only with
  double quotes. Escape runtime variables in expandable here-strings (for
  example, `` `$RepoPath ``).
- Prefer the smallest clear implementation, especially in setup, ACL, and teardown paths.
- Keep `AgentSandbox` a standard user; keep bootstrap files admin-write /
  Users-read-execute; install Claude per-user in
  `C:\Users\AgentSandbox`. Document any credential caching or access widening
  with its threat-model tradeoff.

## Commits and PRs

- Use short, imperative, single-purpose commits.
- State intent, affected scripts, manual validation, security-boundary impact,
  elevated commands, and whether testing used a clean or existing sandbox.
