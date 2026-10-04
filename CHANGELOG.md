# Changelog

All notable user-facing changes are documented here. Earlier history is in the
Git log.

## Unreleased

- Changed: `Test-AgentSandboxExposure.ps1` advances to checker `0.2.0`, profile `default/5`, with evidence coverage weighted equally across dimensions. Scores from earlier profiles are not comparable.
- Added: Bounded secret-content scanning and Credential Manager metadata inventory. The scanner handles quoted JSON keys and UTF-16, excludes links and detectable cloud placeholders, and reports suspected secret locations without values.
- Added: Individual cross-process permission probes, including higher-integrity processes of the same account, and comparisons of held handles against the current token's authority. Granted permissions are reported without claiming successful injection.
- Added: Checks for write access and credential files outside the workspace, agent-writable programs and build scripts in adjacent trees, and writable git hooks or config in a workspace repository owned by another user. Credential discovery in adjacent trees uses file names only.
- Changed: Network probes run by default; `-ProbeNetwork` is removed. Use `-SkipCheck NETWORK` to disable them. Targets include configured proxies, gateways, private DNS servers and loopback TCP listeners; connection refusals count as reach, explicit local denials as blocks, and timeouts as unknown.
- Added: Egress checks beyond TCP: unique-name DNS, one direct UDP 53 query and one ICMP echo, plus TCP 80 as an extra Internet target. Every verdict states its OS-process scope, excludes external agent-tool authority, and identifies named pipes as unassessed by design.
- Changed: Policy checks now require enforced WDAC or AppLocker for application control, validate Claude Code managed-policy ownership and permission rules, and assess proxy bypass using route evidence. Logging detection recognizes PowerShell 7 policy and running process-monitoring sensors.
- Changed: Service and scheduled-task checks cover unquoted executable paths, service DLLs, script arguments, COM handlers and creation rights for missing executables. Service permissions are requested individually.
- Fixed: Unresolved access, failed enumeration and incomplete secret scans remain unknown instead of earning protection credit. Reports and diagnostics redact token-bearing metadata; Git credential helpers without stored credentials and obvious placeholder secrets no longer produce exposure findings.
- Fixed: A loaded native probe from an older checker now stops the run with instructions to start a fresh PowerShell session.
- Added: A progress indicator during initialization and checks, suppressed in JSON mode and when stderr is redirected.
- Added: `-SandboxPath` declares agent-owned folders, such as `C:\AgentSandbox`, that the exposure checker treats like the workspace. Reports list them; drive roots and system folders are ignored.
- Added: Native Python WSL diagnostics in `tools/check-wsl-containment.py` and `tools/test_wsl_sandbox_exposure.py`, with human and JSON reports for Windows bridges, Linux authority and containment. The broader checker also provides bounded secret scanning, optional TCP probes and policy comparison; its scores are separate from the Windows profile.
- Changed: The README warns against running setup or removal from a checkout the agent can write.

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
