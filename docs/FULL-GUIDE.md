# agent-win-sandbox full guide

Run AI coding agents as a dedicated standard Windows user in a fixed workspace
without Docker or WSL. The launcher opens a plain PowerShell 7 terminal;
start your coding agent as needed.

> **Threat model:** This reduces blast radius for a generally trusted machine;
> it is not hard containment against a determined attacker with your
> privileges. It helps contain agent mistakes and prompt-injection overreach.
> Use a VM when strong isolation is required.

## Components

1. **`Setup-AgentSandbox.ps1`** (elevated, once) creates and hardens the
   `AgentSandbox` local user, creates its workspace, applies ACLs and
   account-scoped WFP policy, installs the proxy and locked
   ProgramData control files, checks PowerShell 7, and creates the shortcut.
2. **`managed-settings.json`** (optional, elevated) deploys Claude Code policy
   that disables bypass/auto modes, restricts web, hooks, MCP, plugin-sideload,
   and agent-control-file surfaces, and pre-approves routine read-only Git and
   build verbs.
3. **`Start-AgentSandbox.ps1`** (normal privilege, per session) uses the
   launcher-owned proxy and installed [`launch-as`](https://github.com/fmuecke/launch-as) broker to start a plain
   PowerShell 7 terminal as the sandbox user in an independent logon session.
4. **`Check-AgentSandbox.ps1`** (read-only) verifies account, ACL, network lock,
   shell commands, policy, workspace, and toolchain state. It prints
   PASS/WARN/FAIL and exits non-zero on FAIL.
5. **`Remove-AgentSandbox.ps1`** (elevated) removes generated sandbox state and
   installed components when unused. It leaves the shared workspace and ACLs.

### Setup details

Setup creates `AgentSandbox` when absent and:

- Enrolls the account with `launch-as-broker`, which owns a temporary per-launch
  password; the launcher and its caller never receive that password.
- Denies network and RDP logon; sets password-never-expires and
  user-cannot-change-password; hides the user from the sign-in screen; leaves
  interactive logon enabled because the broker needs it.
- Proposes `C:\AgentSandbox` as the complete workspace directory and grants
  that user Modify access to the tree.
- Warns if your profile is readable by Users or Everyone.
- Blocks sandbox-account outbound TCP/UDP except the configured loopback proxy
  port and labeled `directEndpoints` with
  [`wfp-lock`](https://github.com/fmuecke/wfp-lock).
- Installs [`network-sandbox`](https://github.com/fmuecke/network-sandbox) with
  a policy generated from `proxy.allowedHosts`. The launcher starts one proxy
  shared by all sessions.
- Merges settings over the installed `config.json` on update; `Apply-Config.ps1`
  applies edited settings without rerunning setup.
- Installs both network executables in the private, admin-write
  `C:\ProgramData\agent-win-sandbox` folder. Removal deletes that folder
  with the rest of the generated state; older shared Program Files copies remain.
- Records configuration in `C:\ProgramData\agent-win-sandbox\config.json` and
  installs the launcher, checker, and shell commands there with admin-write /
  Users-RX permissions. After hash verification, `launch-as-admin` installs the
  broker and all four launch-as executables together under
  `C:\Program Files\launch-as` with component-owned protected permissions.

Optional policy deployment writes
`C:\Program Files\ClaudeCode\managed-settings.json`, makes it admin-write /
Users-read, and asks whether to overwrite an existing file. This Claude Code
policy is machine-wide, so multiple sandbox accounts share it.

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
| Network lock and proxy | Direct outbound TCP/UDP and unlisted destinations | WFP and `network-sandbox` |

## Prerequisites

- Windows 10 or 11 on a dedicated or trusted development machine
- Machine-wide PowerShell 7
- Visual Studio Pro or later and Git for Windows when needed
- Administrator rights for setup, removal, and policy installation

## Agent commands

Every Agent Sandbox terminal provides:

```powershell
devshell       # Activate the Visual Studio Developer Shell in this terminal
claude         # Install, update, or launch Claude Code
copilot        # Install, update, or launch GitHub Copilot CLI
sandbox-check  # Run the read-only checker
sandbox-exposure # Run the standalone exposure checker with -SandboxPath
sandbox-help   # Show this list
```

Other native Windows agents, such as OpenCode, can be installed for
`AgentSandbox` from inside the sandbox and run normally; they have no dedicated
wrapper.

The `claude` wrapper uses Anthropic's native Windows installer and prefers
`C:\Users\AgentSandbox\.local\bin\claude.exe`. Its PowerShell and
nonessential-traffic environment settings apply only to Claude and its child
processes.

The `copilot` wrapper downloads
`https://github.com/github/copilot-cli/releases/latest/download/copilot-win32-x64.zip`,
verifies it against the same release's `SHA256SUMS.txt`, and installs
`C:\Users\AgentSandbox\.local\bin\copilot.exe`. No npm or WinGet is used.
Installed Copilot versions use `copilot update`.

On first launch, the wrapper asks for a user-owned fine-grained GitHub PAT
beginning with `github_pat_`, `Copilot Requests` as its only added permission,
and minimal repository access. It stores the PAT as the sandbox user's
persistent `COPILOT_GITHUB_TOKEN`; every process running as `AgentSandbox` can
read it. Use `copilot -SetToken` to replace it and `copilot -ClearToken` to
remove it.

## Setup

Run from an elevated PowerShell:

```powershell
.\Setup-AgentSandbox.ps1
```

Setup prompts for the workspace base (Enter accepts `C:\dev`), confirmation to
reuse an existing workspace, and optional managed-settings deployment. It
installs and enrolls the broker-managed account without displaying its password.
It upgrades supported brokered installations from `v1.0.0-preview`,
`v1.1.0-preview`, and `v1.1.0`; unknown or incomplete installations require
removal with their matching Agent Sandbox version first.

Start the sandbox:

```powershell
& 'C:\ProgramData\agent-win-sandbox\Start-AgentSandbox.ps1'
```

The `Agent Sandbox` desktop shortcut does the same. Verify inside it with:

```powershell
sandbox-check
```

Run the checker elevated for full user-rights, HKLM, and other-profile checks.
On first use, configure each agent and source-control credential separately
with minimal scopes and expiry.

For daily use, start the shortcut or launcher from the same account that ran
setup. The broker starts the enrolled console in the same pane without a
password prompt. The shell verifies the WFP lock before accepting agent work;
multiple sessions share the proxy.

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-AgentSandbox.ps1
```

This removes the sandbox account and profile, including its per-user agent
installs, settings, and Copilot PAT environment variable. It also removes
the broker enrollment, generated ProgramData state, network lock, proxy process,
hidden-login registry value, and desktop shortcuts. It keeps the workspace—for example,
`C:\AgentSandbox`—and its ACLs. Close all Agent Sandbox terminals first;
removal stops before changing state when the `AgentSandbox` profile is still
loaded. It removes the installed network executables and uninstalls `launch-as`
when no other broker accounts remain.

## Broker-managed account

`launch-as-broker` owns the `AgentSandbox` password. For each console launch it
generates a temporary password, uses it only to create an independent logon
session, then discards it. The launcher never prompts for, reads, stores, or
sends that password. The console remains in the caller's terminal pane through
the broker's terminal bridge, but the child is not placed on the caller's
interactive desktop.

The broker uses a separate console logon session for each agent terminal.

The Copilot PAT is currently stored as plaintext in the sandbox user's
environment. This separates it from the developer's identity but does not hide
it from agents or build processes running as `AgentSandbox`. Use only the
user-owned fine-grained `Copilot Requests` permission and set a short expiry.

## Limitations

- The boundary is the default Windows profile ACL. A correctly configured
  standard user cannot read your profile; setup verifies this rather than adding
  brittle deny ACEs. Protect secrets outside your profile with separate ACLs.
- Install agent CLIs only under `AgentSandbox`; the checker verifies the
  expected per-user locations.
- Native Windows has no bubblewrap sandbox. Prefer or layer native sandboxing
  when Anthropic provides it.
- Managed settings add defense in depth, not a guarantee; keep Claude Code
  updated against permission-bypass vulnerabilities.
- `AgentSandbox` has a writable profile for agent configuration and its own
  scoped credentials; treat everything in that profile as agent-accessible.
- Claude Code managed settings do not apply to GitHub Copilot CLI.
- Debugging system processes requires elevation. Keep it separate from this
  low-privilege agent session—for example, use elevated Visual Studio with
  agent mode off.
- The WFP lock restricts outbound TCP/UDP attributed to `AgentSandbox` but
  does not cover ICMP or DNS and other traffic brokered under another identity.
  Proxy variables are routing hints; the WFP lock is the per-user enforcement.
  Audit local brokers such as BITS, WebClient, Docker, and WSL/Hyper-V.
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
