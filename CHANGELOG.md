# Changelog

All notable user-facing changes are documented here. Versions before 0.4.0 were
developed without explicit release versions; their history remains available in
the Git log.

## 0.5.1 — 2026-07-29

### User-facing features

- Supports passwordless sandbox starts after user chooses to save it in Windows
  Credential Manager.
- Runs the sandbox shell in the initiating terminal, with no extra console
  window. This also allows launching it from an integrated terminal such as
  Visual Studio Code's terminal.

### Changed

- Replaced `runas.exe` with the bundled `launch-as` helper for daily sandbox
  sessions.
- The launcher uses launch-as terminal mode, so the sandbox shell runs in the
  initiating terminal instead of opening a separate console window.
- Setup downloads the pinned launch-as v0.3.1 Windows x64 release, verifies its
  SHA-256 archive hash, and installs `launch-as.exe` under the protected
  ProgramData directory.

### Security

- Setup locks `launch-as.exe` and the existing ProgramData control-plane files
  to Administrators/SYSTEM full control and Users read/execute.
- The checker verifies that launch-as is present, locked, and recorded in setup
  metadata.

## 0.4.0 — 2026-07-26

### Added

- Displayed the installed sandbox version and project URL in the Dev Shell.
- Configured sandbox-specific Claude Code shell and stable auto-update settings
  at bootstrap.

### Changed

- Added the sandbox user's per-user Claude binary directory to `PATH` without
  requiring a new session.
- Kept the launcher window open when startup fails and made the desktop shortcut
  mandatory.
- Made `Check-ClaudeSandbox` callable from a sandbox session and reduced
  hard-coded runtime paths.

## Earlier development

- Established the dedicated `ClaudeSandbox` standard-user model, ProgramData
  control plane, workspace ACLs, account-scoped firewall blocks, teardown
  script, and optional Claude Code managed policy deployment.
