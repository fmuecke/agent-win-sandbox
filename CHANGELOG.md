# Changelog

All notable user-facing changes are documented here. Earlier history is in the
Git log.

## 0.5.2 — 2026-08-01

- Changed: Applied Redpen to documentation for better readability.
- Changed: Updated the bundled `launch-as.exe` to v0.3.2.
- Fixed: Ctrl+Break no longer opens `DBG>` or leaves the terminal in raw mode.

## 0.5.1 — 2026-07-29

- Added: Optional passwordless starts using Windows Credential Manager.
- Changed: Replaced `runas.exe` with bundled `launch-as`, which keeps the
  sandbox shell in the initiating terminal, including VS Code's integrated
  terminal.
- Changed: Setup downloads pinned `launch-as` v0.3.1, verifies its SHA-256
  archive hash, and installs it in protected ProgramData.
- Security: Setup restricts `launch-as.exe` and existing ProgramData control
  files to Administrators/SYSTEM full control and Users read/execute; the
  checker verifies the executable, ACLs, and setup metadata.

## 0.4.0 — 2026-07-26

- Added: Displayed the installed sandbox version and project URL in the Dev
  Shell, and configured sandbox-specific Claude Code shell and stable
  auto-update settings at bootstrap.
- Changed: Added the sandbox user's Claude binary directory to `PATH` without a
  new session, kept launch failures visible, required the desktop shortcut, and
  made `Check-ClaudeSandbox` available inside the sandbox.
- Changed: Reduced hard-coded runtime paths.

## Earlier development

- Added: The standard-user `ClaudeSandbox` model, protected ProgramData control
  plane, workspace ACLs, account-scoped firewall blocks, teardown script, and
  optional Claude Code managed-policy deployment.
