# Changelog

All notable user-facing changes are documented here. Earlier history is in the
Git log.

## 0.10.0 - 2026-10-09

- Added: One admin-write `config.json` holds the workspace, proxy port, proxy
  allowed hosts, and labeled `directEndpoints` (IP:port the sandbox may reach
  directly, e.g. a database server; uses `wfp-lock v0.10.0`). It replaces
  `config\network-sandbox.json`; the proxy policy is generated from it.
- Added: `Setup-AgentSandbox.ps1 -ConfigFile` merges settings over the installed
  configuration; lists replace, omitted keys are kept.
- Added: `Apply-Config.ps1` applies edited settings without setup. The launcher
  refuses to start while settings are unapplied or when a non-admin can modify
  the config or bootstrap scripts.
- Changed: The proxy is started by the launcher only, not by setup's elevated
  session.
- Fixed: A failed shell startup check left an interactive AgentSandbox prompt
  open. The session now closes, and the network lock is verified first.
- Fixed: Scripts running as `AgentSandbox` located ProgramData and Program
  Files through environment variables that the account can set for its own
  later sessions. That let the agent point the network-lock check and the
  checker at its own files. They now ask Windows for these paths.
- Breaking: Installations from before this configuration format must be removed
  with `Remove-AgentSandbox.ps1` before setup.
- Changed: Default now is to accept and use existing agent workspace (switched options).
- Removed: Handling for legacy installations

## 0.9.1 - 2026-10-07

- Updated the network lock to the renamed `wfp-lock v0.9.0` release.
- Updated the proxy to `network-sandbox v0.3.0` and JSON configuration which prevents line-ending errors.
- Changed License to GPLv3 or later

## 0.9.0 - 2026-10-07

- Added network egress control for `AgentSandbox`: direct outbound TCP is limited
  to a shared local proxy, outbound UDP is blocked, and the proxy forwards only
  to allowlisted destinations. Setup installs and verifies the controls, asks
  for another port if the selected one is occupied, and preserves the allowlist
  on updates. The port is configurable; updates recognize the existing proxy.
  These controls replace the custom NetBIOS and RDP firewall rules.
- Added `Run-Demo.ps1` for a disposable Windows Sandbox demo with a configured
  visible AgentSandbox console on the guest desktop and read-only host inputs.
- Added `sandbox-exposure` in place of the installed `sandbox-surfaces` command
  and checker. It scores current evidence and reports network reachability,
  file and credential access and writable paths outside the workspace,
  cross-process permissions, and policy, service, and task gaps. Incomplete
  checks remain unknown rather than earning protection credit. Suspected
  secrets are reported by location without contents; token-bearing metadata is
  redacted. Interactive runs show progress. The installed command uses its
  configured workspace; standalone runs accept `-SandboxPath` for other
  agent-owned folders. Its new scoring profile is not comparable with earlier
  releases.
- Network checks now run by default and cover local listeners, proxy bypass,
  DNS, UDP, and ICMP. Use `-SkipCheck NETWORK` to omit them; `-ProbeNetwork` was
  removed. Results describe the tested process, not other agent tools.
- Added separate WSL containment diagnostics with human-readable and JSON
  reports. Their scores are not comparable with the Windows assessment.
- Setup, removal, the launcher, and the installed checker now require PowerShell
  7; the desktop shortcut opens it directly. Removal stops the proxy, removes
  network controls, and uninstalls `launch-as` when no other broker accounts
  remain. The pinned `launch-as` release is now `v1.3.0`.
- The README warns against running setup or removal from a checkout the agent
  can modify.

**Limitations.** Windows DNS Client may send data encoded in query names under
another identity. The egress controls do not cover ICMP or traffic relayed by
local services, containers, or VMs; allowlisted HTTPS destinations can still
receive data. Anything running as `AgentSandbox` can use its credentials and
access its readable or writable files. `sandbox-exposure` reports findings but
enforces nothing. This setup does not prevent prompt injection or provide hard
isolation.

## 0.8.0 - 2026-09-15

- Changed: Updated the pinned `launch-as` release to `v1.2.0-preview`. Setup now verifies the package and lets `launch-as-admin` install the whole component under `C:\Program Files\launch-as`; it no longer copies individual launch-as executables into ProgramData.
- Changed: Supported brokered installations from `v1.0.0-preview`, `v1.1.0-preview`, and `v1.1.0` update in place. Unknown or incomplete installations still require removal with their matching Agent Sandbox version.
- Changed: Setup replaces `-BasePath` with `-SandboxPath` and proposes `C:\AgentSandbox` as the complete workspace path. It no longer appends an `AgentSandbox` child folder to a base directory.
- Changed: Removal supports the known broker versions and leaves the shared `launch-as` component installed for other managed accounts. The installed-state checker verifies its Program Files directory and executable permissions.

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
