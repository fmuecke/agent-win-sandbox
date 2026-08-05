# agent-win-sandbox — Todo & Decisions

Current decisions and open work. Personal and career discussions are excluded.

_Last updated: 2026-08-05_

## Decisions

### Boundary and account

- **`AgentSandbox` is the boundary.** Windows ACLs enforce access; Docker/WSL2
  do not suit this native Windows, MSVC, and on-prem toolchain.
- **Threat model:** blast-radius reduction on a trusted machine, not hard
  containment against an attacker with your privileges. Managed settings are
  defense in depth; ACLs are the enforcement layer.
- **Use `launch-as.exe`, not `runas.exe` or `Start-Process -Credential`.** It
  launches an interactive target-user console and verifies the target token
  before resuming the child.
- **Credential storage is optional.** Credential UI may store the generic
  credential only for the regular user who launches the sandbox, never for
  `AgentSandbox`.
- **Use a stable, policy-compliant password.** Per-launch random resets require
  elevation, make daily launch a privileged broker, add failure points, and may
  disrupt password-tied user state. Setup is elevated; daily launch is not.
- **Keep interactive logon enabled** because the launcher needs it; deny network
  and RDP logon, hide the account from the sign-in screen, and set
  password-never-expires and user-cannot-change-password.
- **Firewall rules are account-scoped and operational.** Block sandbox outbound
  SMB, NetBIOS, RDP, and WinRM ports; leave web and internal services available.
  Proxy variables are bypassable routing hints, not an isolation boundary.
  Strict allowlisting needs protected proxy plus firewall/WFP enforcement—or a
  controlled VM/network route—and host-specific auditing of localhost, BITS,
  WebClient, DNS, Docker, and WSL/Hyper-V brokers.

### Filesystem and setup state

- **Control plane:** keep config, launcher, `launch-as`, checker, and bootstrap
  in `C:\ProgramData\agent-win-sandbox`; keep managed settings in
  `C:\Program Files\ClaudeCode\managed-settings.json`. These files are
  admin-write and Users-RX/read, preventing sandbox-user poisoning. Program
  Files is required because current Claude Code no longer supports the legacy
  ProgramData managed-settings location on Windows.
- **Workspace:** default to `C:\dev\AgentSandbox`; ask only for its base
  directory. `AgentSandbox` remains the fixed child name for awareness, not
  security. The `repos\` subdirectory was unnecessary; the workspace README
  explains its purpose.
- **Generated state:** setup copies ProgramData artifacts from the repository,
  writes the resolved sandbox path and nested setup metadata to one
  `config.json`, and deploys trusted daily entrypoints there. The source repo
  remains canonical; a separate setup-marker file is unnecessary.
- **Managed policy deployment is optional.** Setup substitutes `$SANDBOXDIR`,
  asks before installation and overwrite, writes the resolved policy to Program
  Files, and locks it admin-write / Users-read.
- **Removal leaves the workspace and its ACLs.** Cleaning stale ACLs after the
  user/profile is gone adds little value; the workspace is left for review or
  manual deletion.

### Shell and agent commands

- **Lock shell initialization and command wrappers admin-write / Users-RX** and
  refuse to run them unless
  `$env:USERNAME` is the sandbox user.
- Launch a plain PowerShell 7 terminal. Enter the Developer Shell only through
  `devshell`, using
  `Enter-VsDevShell -VsInstanceId` from `vswhere -format json`; install-path
  discovery can hang under a different profile.
- **Install agent CLIs per-user under `AgentSandbox`.** Shell initialization
  adds `~\.local\bin` to `PATH` every launch.
- Use the protected Claude wrapper for its native installer and the protected
  Copilot wrapper for the official latest ZIP plus published checksum. npm and
  WinGet are out of scope.

### Launch UX

- Full Visual Studio embedding is not worth the cross-user terminal-input
  problem; it has no terminal-profile equivalent.
- Setup always creates the Public Desktop shortcut. The launcher pauses on
  errors so shortcut launches show wrong-password, cancelled-prompt, and
  pre-flight failures.
- Do not pursue VS Code now. Prefer a dedicated Windows Terminal tab once its
  profile is finalized and terminal-mode behavior has been verified.

### Distribution and compatibility

- Use PSGallery rather than winget: the goal is easy setup and updates, not
  silent provisioning; keep this personal, public MIT hobby project
  (© Florian Mücke 2026).
- Keep elevated setup/removal compatible with PowerShell 5.1, but require
  machine-wide PowerShell 7 for Agent Sandbox sessions. PowerShell 5.1 lacks
  `?.`; parse `secedit` by index instead of fragile `Select-String .LineNumber`;
  never use `$input` as a variable; and match both `*SID` and bare account-name
  forms because `secedit` can normalize names.

## Todo / open items

### Completed filesystem migration

- [x] Moved the bootstrap to `C:\ProgramData\agent-win-sandbox\bootstrap\`.
- [x] Changed the workspace default from `C:\dev\repo` to
  `C:\dev\AgentSandbox\`; setup now prompts for its base and grants Modify on
  the fixed child tree.
- [x] Added the required Public Desktop shortcut and updated checker and README
  paths.
- [x] Deployed the launcher and checker with `launch-as` to trusted ProgramData
  rather than launching from the mutable repository.
- [ ] Update the Windows Terminal profile snippet after finalizing the launcher
  location.

### Launch UX

- [ ] Finalize the Windows Terminal profile after testing `launch-as`
  terminal-mode behavior.
- [ ] Decide whether to launch VS Code as `AgentSandbox` for tighter IDE
  integration or keep the Windows Terminal-tab approach.

### Git collaboration hardening

- [ ] Address shared-repository git-hook, `.git/config`, and filter-driver
  injection. Short term: redirect `core.hooksPath` and add explicit deny ACEs
  on `.git/config` and `.git/hooks/`.
- [ ] Long term: use separate clones and fetch-based collaboration.

### Higher-risk workflows

- [ ] Explore Hyper-V VM or Dev Box isolation for YOLO-mode agent workflows.

### Tool-agnostic generalization

- [x] Exposed Claude Code and Copilot CLI from the same plain PowerShell
  sandbox; Claude managed settings remain Claude-only.
- [ ] Remove script needs to check if a sandbox is currently running and ask the user to close it first (or terminate running processes)
- [ ] does the setup script really need to check for the VS dev environment? This should be the wrappers responsibility only.
- [ ] Encrypt/protect the Copilot PAT at rest with DPAPI or Windows Credential
  Manager instead of storing `COPILOT_GITHUB_TOKEN` in the sandbox user's
  plaintext environment. Any replacement must still acknowledge that Copilot
  and processes it starts can read the token while it is in use.
- [ ] Verify whether Copilot CLI needs the same operational firewall profile or
  stricter proxy/network egress control.

## Parking lot

- [x] Added operational sandbox-account firewall rules for SMB, NetBIOS, RDP,
  and WinRM; web remains available.
- [ ] Add strict process egress allowlisting (for example,
  `api.anthropic.com` and `dev.azure.com`) through a protected proxy and
  non-bypassable firewall/WFP policy, or use a VM with a controlled route. Do
  not treat proxy variables alone as enforcement.
- [ ] Audit local network brokers: localhost listeners, BITS, WebClient/WebDAV,
  DNS Client, Docker permissions, accessible WSL distributions, Hyper-V firewall
  policy, and Security events 5156/5157.
- [ ] Add active pre-commit secret scanning with `gitleaks` or
  `detect-secrets`.
