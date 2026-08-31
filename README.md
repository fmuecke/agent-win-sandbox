# agent-win-sandbox

Run AI coding agents on Windows as a dedicated standard user in a fixed
workspace. Start with a plain PowerShell terminal and start your coding agent.

This reduces the blast radius of Windows-native development; it is not hard
containment. Use a VM for adversarial code or strong isolation.

> Give the agent delegated access, not your full Windows identity.
> The CEO's assistant is not the CEO.

Currently supported with built-in commands:

- Claude Code
- GitHub Copilot CLI
- Visual Studio Dev Shell - to have the tools available for the agent

Of course any other agent like OpenCode can be installed within the Agent Sandbox and run normally.

## What it does

- Separates agent credentials, configuration, and installation into
  `C:\Users\AgentSandbox`.
- Runs console agents through a passwordless broker in an independent logon
  session and noninteractive desktop.
- Limits expected agent writes to the sandbox workspace.
- Protects the launcher, `launch-as`, bootstrap, checker, and managed-settings
  files in admin-write locations.
- Blocks common Windows lateral-movement protocols for the sandbox account.

## What it does not protect against

- Malicious code, prompt injection, or hard isolation failures.
- Exfiltration through allowed HTTPS, git, package feeds, or internal services.
- Data readable by `AgentSandbox`, including its workspace, credentials, and
  broadly readable local files.
- Snapshots, resource limits, centralized audit logs, or automatic kill
  switches.

## Requirements

- Windows 10 or 11 with machine-wide PowerShell 7
- Administrator rights for setup, removal, and policy installation
- Highly recommended: machine-wide Visual Studio and Git for Windows

## Setup

Run once from an elevated PowerShell:

```powershell
.\Setup-AgentSandbox.ps1
```

Setup optionally deploys the Claude Code managed settings to
`C:\Program Files\ClaudeCode\managed-settings.json`; it asks before replacing an
existing file because this policy is machine-wide and shared by every Claude
Code user. It installs and enrolls the `launch-as` broker, then creates the
`Agent Sandbox` Public Desktop shortcut.

The broker preview cannot reuse an account from an earlier Agent Sandbox
installation. Setup detects that state and stops; uninstall the earlier Agent
Sandbox version first, then run setup again. This version's removal script also
refuses legacy state. The shared workspace remains untouched by removal.

Start the sandbox with that shortcut, or run:

```powershell
& 'C:\ProgramData\agent-win-sandbox\Start-AgentSandbox.ps1'
```

The terminal provides:

```powershell
devshell       # Enter the Visual Studio Developer Shell
claude         # Install, update, or launch Claude Code
copilot        # Install, update, or launch GitHub Copilot CLI
sandbox-check  # Check the sandbox configuration
sandbox-surfaces # Check interactive process and desktop exposure
sandbox-help   # Show these commands
```

`claude` installs Claude Code per-user through Anthropic's native installer.
`copilot` downloads GitHub's latest Windows x64 release into `~\.local\bin` and
verifies it against the release's `SHA256SUMS.txt`. No npm or WinGet is used.
`sandbox-surfaces` is a non-destructive diagnostic, not a mitigation: it only
reports process-handle and desktop access currently granted to the session.

On first Copilot launch, enter a user-owned fine-grained PAT with
`Copilot Requests` as its only added permission and minimal repository access.
The wrapper stores it as the sandbox user's persistent
`COPILOT_GITHUB_TOKEN`. Every process running as `AgentSandbox` can read it;
scope and expire it accordingly.

Rotate or remove that token with:

```powershell
copilot -SetToken
copilot -ClearToken
```

## Daily use

Open `Agent Sandbox`. The installed `launch-as-broker` starts an enrolled
`AgentSandbox` console in the current terminal pane without a password prompt.
One account supports one active sandbox session at a time. Run `sandbox-help`,
then start the agent or Developer Shell you need.

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-AgentSandbox.ps1
```

This removes the sandbox user and profile, generated ProgramData state,
firewall rules, broker enrollment, and shortcut. It keeps the workspace, such as
`C:\dev\AgentSandbox`. 

## Important notes

- Install agent CLIs per-user under `C:\Users\AgentSandbox`, not machine-wide
  or in your main profile.
- The sandbox user can access anything in its workspace and anything readable
  by ordinary Windows users.
- Claude managed settings do not govern Copilot CLI. Configure each agent's
  permissions independently.
- A legacy `ClaudeSandbox` installation can coexist with this project because
  its user, workspace, ProgramData, firewall, and shortcut names are separate.
  Its optional machine-wide Claude managed settings are shared; decline the
  overwrite prompt unless one policy is intentionally used for both.
- HTTPS/web egress remains available to agents, git, package managers, and
  internal services.
- Proxy environment variables do not enforce egress. Local services and
  VM/container networking can relay traffic under another identity; read the
  [threat model](docs/threat-model.md#proxy-settings-and-strict-egress) before
  designing a strict destination allowlist.

## More detail

- [Changelog](CHANGELOG.md)
- [Full guide](docs/FULL-GUIDE.md)
- [Threat model](docs/threat-model.md)
- [Todo and decisions](docs/todo-and-decisions.md)
- [Codex Windows sandbox concepts and notes](docs/codex-sandbox.md)
- [The Shorthand Guide to Everything Agentic Security](docs/the-security-guide.md)
- [Claude Code sandbox environments](https://code.claude.com/docs/en/sandbox-environments)

## FAQ

### Can I use other agents?

Yes. Install any native Windows agent under `AgentSandbox` and run it there.
Only Claude Code and Copilot CLI have built-in wrappers.

### Should I run Codex agent inside Agent Sandbox?

Usually no. Run Codex directly with its native Windows `elevated` sandbox. It
already uses dedicated lower-privilege users, filesystem boundaries, firewall rules,
local policy, and a private desktop. See [Windows
sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox),
[permissions and sandboxing](https://learn.chatgpt.com/docs/sandboxing).

Use Agent Sandbox as an outer layer only when Codex needs broad access, cannot
use `elevated`, or needs a separate credential/profile boundary. Verify the
active sandbox mode before relying on it.

### What else is it for?

Use it as a low-trust automation identity, not a second desktop. It separates
credentials, token caches, shell history, browser state, and per-user installs.

## License

[MIT](LICENSE)
