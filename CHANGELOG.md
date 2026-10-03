# Changelog

All notable user-facing changes are documented here. Earlier history is in the
Git log.

## 0.8.0 - 2026-09-15

- Changed: Updated the pinned `launch-as` release to `v1.2.0-preview`. Setup now verifies the package and lets `launch-as-admin` install the whole component under `C:\Program Files\launch-as`; it no longer copies individual launch-as executables into ProgramData.
- Changed: Supported brokered installations from `v1.0.0-preview`, `v1.1.0-preview`, and `v1.1.0` update in place. Unknown or incomplete installations still require removal with their matching Agent Sandbox version.
- Changed: Setup now proposes `C:\AgentSandbox` as the complete workspace path. It no longer treats `C:\dev` as a base directory and appends an `AgentSandbox` child folder.

## 0.7.1 — 2026-09-13

- Changed: Updated the pinned `launch-as` release to `v1.1.0-preview`. Remove existing v0.6. installs before running setup. Update from 0.7.0 will work.

## 0.7.0 — 2026-08-31

- Added: `sandbox-surfaces`, a read-only diagnostic for interactive desktop and cross-user process-handle exposure, plus a controlled surface canary for evidence-bounded reproduction.
- Changed: Replaced credential-based `launch-as` launches with the `v1.0.0-preview` broker. Setup enrolls `AgentSandbox`; daily console launches are passwordless, use an independent logon session, and permit one active session per account. Legacy installations must be removed before setup. This effectively reduces attack surfaces.

## 0.6.0 — 2026-08-06

- Changed: This is now called `agent-win-sandbox` respective `AgentSandbox` as
  it is no longer limited to claude only.
- Changed: The launcher now opens a plain PowerShell 7 Agent Sandbox terminal;
  `devshell` activates the Visual Studio Developer Shell only when requested.
- Added: Support for GitHub Copilot CLI: The Copilot wrapper downloads and
  verifies the official latest Windows x64 release in `~\.local\bin`, updates
  it through `copilot update`, and manages a Copilot-Requests-scoped fine-
  grained PAT.
- Added: Wrapper commands for `claude`, `copilot`, `sandbox-check`, and `sandbox-help`
  in every sandbox session.
- Fixed: Removal scripts stops if user profile is still active.

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
  made `Check-AgentSandbox` available inside the sandbox.
- Changed: Reduced hard-coded runtime paths.

## Earlier development

- Added: The standard-user `AgentSandbox` model, protected ProgramData control
  plane, workspace ACLs, account-scoped firewall blocks, teardown script, and
  optional Claude Code managed-policy deployment.
