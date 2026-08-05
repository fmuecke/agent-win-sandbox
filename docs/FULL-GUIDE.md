# claude-win-sandbox full guide

Run AI coding agents as a dedicated standard Windows user in a fixed workspace
without Docker or WSL. The launcher opens a plain PowerShell 7 terminal;
activate the Visual Studio Developer Shell only when a task needs it.

> **Threat model:** This reduces blast radius for a generally trusted machine;
> it is not hard containment against a determined attacker with your
> privileges. It helps contain agent mistakes and prompt-injection overreach.
> Use a VM when strong isolation is required.

## Components

1. **`Setup-ClaudeSandbox.ps1`** (elevated, once) creates and hardens the
   `ClaudeSandbox` local user, creates its workspace, applies ACLs and
   account-scoped firewall blocks, installs and locks ProgramData control files,
   locates the toolchain, and creates the Public Desktop shortcut.
2. **`managed-settings.json`** (optional, elevated) deploys Claude Code policy
   that disables bypass/auto modes, restricts web, hooks, MCP, plugin-sideload,
   and agent-control-file surfaces, and pre-approves routine read-only Git and
   build verbs.
3. **`Start-ClaudeSandbox.ps1`** (normal privilege, per session) uses
   `launch-as` to start a plain PowerShell 7 terminal as the sandbox user and
   keeps launch errors visible.
4. **`Check-ClaudeSandbox.ps1`** (read-only) verifies account, ACL, firewall,
   shell commands, policy, workspace, and toolchain state. It prints
   PASS/WARN/FAIL and exits non-zero on FAIL.
5. **`Remove-ClaudeSandbox.ps1`** (elevated) removes generated sandbox state.
   It never removes the shared workspace or changes its ACLs.

### Setup details

Setup creates `ClaudeSandbox` when absent and:

- Denies network and RDP logon; sets password-never-expires and
  user-cannot-change-password; hides the user from the sign-in screen; leaves
  interactive logon enabled because the launcher needs it.
- Prompts for a workspace base directory (default `C:\dev`), creates
  `C:\dev\ClaudeSandbox`, and grants that user Modify access to the tree.
- Warns if your profile is readable by Users or Everyone.
- Blocks sandbox-account outbound ports `137-139`, `445`, `135`, `3389`, and
  `5985-5986`, while leaving web/HTTPS available for agents, Git, and internal
  services.
- Records configuration in `C:\ProgramData\claude-win-sandbox\config.json`;
  installs the launcher, checker, shell commands, and verified `launch-as.exe`
  under `C:\ProgramData\claude-win-sandbox`; and makes them admin-write /
  Users-RX.

Optional policy deployment writes
`C:\Program Files\ClaudeCode\managed-settings.json`, makes it admin-write /
Users-read, and asks whether to overwrite an existing file.

## Why a separate user

Claude Code normally has your OS access, including to environment variables,
SSH keys, PATs, and credential stores. On native Windows, the practical OS
boundary is a separate low-privilege user: Windows ACLs prevent access to paths
that user cannot read or write. This complements Claude Code permission prompts
and managed-settings rules.

| Layer | Protects against | Enforced by |
|---|---|---|
| NTFS ACLs | Access to your secrets and system directories | Windows kernel |
| Managed settings | High-risk modes and agent-control-file edits | Claude Code |
| Permission prompts | Unreviewed command execution | Claude Code |
| Logon hardening | Network/RDP logon as the sandbox user | Windows user rights |
| Firewall rules | Outbound SMB, NetBIOS, RDP, and WinRM | Windows Firewall |

## Prerequisites

- Windows 10 or 11 on a dedicated or trusted development machine
- Machine-wide PowerShell 7
- Machine-wide Visual Studio Pro or later and Git for Windows
- Administrator rights for setup, removal, and policy installation

## Agent commands

Every Agent Sandbox terminal provides:

```powershell
devshell       # Activate the Visual Studio Developer Shell in this terminal
claude         # Install, update, or launch Claude Code
copilot        # Install, update, or launch GitHub Copilot CLI
sandbox-check  # Run the read-only checker
sandbox-help   # Show this list
```

The `claude` wrapper uses Anthropic's native Windows installer and prefers
`C:\Users\ClaudeSandbox\.local\bin\claude.exe`. Its PowerShell and
nonessential-traffic environment settings apply only to Claude and its child
processes.

The `copilot` wrapper downloads
`https://github.com/github/copilot-cli/releases/latest/download/copilot-win32-x64.zip`,
verifies it against the same release's `SHA256SUMS.txt`, and installs
`C:\Users\ClaudeSandbox\.local\bin\copilot.exe`. No npm or WinGet is used.
Installed Copilot versions use `copilot update`.

On first launch, the wrapper asks for a user-owned fine-grained GitHub PAT
beginning with `github_pat_`, `Copilot Requests` as its only added permission,
and minimal repository access. It stores the PAT as the sandbox user's
persistent `COPILOT_GITHUB_TOKEN`; every process running as `ClaudeSandbox` can
read it. Use `copilot -SetToken` to replace it and `copilot -ClearToken` to
remove it.

## Setup

Run from an elevated PowerShell:

```powershell
.\Setup-ClaudeSandbox.ps1
```

Setup prompts for the workspace base (Enter accepts `C:\dev`), confirmation to
reuse an existing workspace, a password twice when creating the user, and
optional managed-settings deployment. The password must meet the local or
domain Windows password policy.

Start the sandbox:

```powershell
& 'C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1'
```

The `Agent Sandbox` desktop shortcut does the same. Verify inside it with:

```powershell
sandbox-check
```

Run the checker elevated for full user-rights, HKLM, and other-profile checks.
On first use, configure each agent and source-control credential separately
with minimal scopes and expiry.

For daily use, start the shortcut or the launcher above from a normal PowerShell
session. Windows Credential UI requests the `ClaudeSandbox` password when no
usable stored credential exists; then run the agent or `devshell` command you
need.

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-ClaudeSandbox.ps1
```

This removes the sandbox account and profile, including its per-user agent
installs, settings, and Copilot PAT environment variable. It also removes
generated ProgramData state, account-scoped firewall rules, hidden-login
registry value, and desktop shortcuts. It keeps the workspace—for example,
`C:\dev\ClaudeSandbox`—and its ACLs.

## Credential handling

`launch-as` starts an interactive console as `ClaudeSandbox` and opens Windows
Credential UI for its password. If the initiating user chooses **Remember**,
Windows Credential Manager stores it for that initiating user; the sandbox user
cannot read it. Failed or cancelled launches print an error and wait for Enter.

Use a stable password that meets local or domain policy. The launcher does not
randomize it on each start: that would require elevation for daily use, turn the
launcher into a privileged broker, and create more failure modes. Keeping setup
elevated and launches non-elevated is intentional.

The Copilot PAT is currently stored as plaintext in the sandbox user's
environment. This separates it from the developer's identity but does not hide
it from agents or build processes running as `ClaudeSandbox`. Use only the
user-owned fine-grained `Copilot Requests` permission and set a short expiry.

## Limitations

- The boundary is the default Windows profile ACL. A correctly configured
  standard user cannot read your profile; setup verifies this rather than adding
  brittle deny ACEs. Protect secrets outside your profile with separate ACLs.
- Install agent CLIs only under `ClaudeSandbox`; the checker verifies the
  expected per-user locations.
- Native Windows has no bubblewrap sandbox. Prefer or layer native sandboxing
  when Anthropic provides it.
- Managed settings add defense in depth, not a guarantee; keep Claude Code
  updated against permission-bypass vulnerabilities.
- `ClaudeSandbox` has a writable profile for agent configuration and its own
  scoped credentials; treat everything in that profile as agent-accessible.
- Claude Code managed settings do not apply to GitHub Copilot CLI.
- Debugging system processes requires elevation. Keep it separate from this
  low-privilege agent session—for example, use elevated Visual Studio with
  agent mode off.
- Firewall rules block common Windows sharing and remote-admin ports, not web
  exfiltration. Proxy environment variables are routing hints, not enforcement.
  Strict egress needs firewall/WFP enforcement and host-specific auditing of
  brokers such as localhost proxies, BITS, WebClient, Docker, and WSL/Hyper-V.
  Use a controlled VM or network route where bypass must be impossible; see the
  [threat model](threat-model.md#proxy-settings-and-strict-egress).
- Mapped-drive checks are hints, not access proofs. The bootstrap warns about
  mapped drives and Network Shortcuts visible in the sandbox session; it does
  not inspect another user's Credential Manager or prove server authorization.

## Why not Docker or WSL?

Use them when the workload fits. This project instead supports native Windows
toolchains that cannot move to Linux containers without losing their toolchain.

## License

[MIT](../LICENSE)

## Status

Personal, opinionated, and not affiliated with Anthropic.
