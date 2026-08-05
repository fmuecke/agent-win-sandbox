# claude-win-sandbox

Run AI coding agents on Windows as a dedicated standard user in a fixed
workspace. Start with a plain PowerShell terminal and enter the Visual Studio
Developer Shell only when needed.

This reduces the blast radius of Windows-native development; it is not hard
containment. Use a VM for adversarial code or strong isolation.

> The CEO's assistant is not the CEO.
> Give the agent delegated access, not your full Windows identity.

## What it does

- Separates agent credentials, configuration, and installation into
  `C:\Users\ClaudeSandbox`.
- Limits expected agent writes to the sandbox workspace.
- Protects the launcher, `launch-as`, bootstrap, checker, and managed-settings
  files in admin-write locations.
- Blocks common Windows lateral-movement protocols for the sandbox account.

## What it does not protect against

- Malicious code, prompt injection, or hard isolation failures.
- Exfiltration through allowed HTTPS, git, package feeds, or internal services.
- Data readable by `ClaudeSandbox`, including its workspace, credentials, and
  broadly readable local files.
- Snapshots, resource limits, centralized audit logs, or automatic kill
  switches.

## Requirements

- Windows 10 or 11 with machine-wide PowerShell 7
- Machine-wide Visual Studio and Git for Windows
- Administrator rights for setup, removal, and policy installation

## Setup

Run once from an elevated PowerShell:

```powershell
.\Setup-ClaudeSandbox.ps1
```

Setup optionally deploys the Claude Code managed settings to
`C:\Program Files\ClaudeCode\managed-settings.json`; it asks before replacing an
existing file. It also creates the `Agent Sandbox` Public Desktop shortcut.

Start the sandbox with that shortcut, or run:

```powershell
& 'C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1'
```

The terminal provides:

```powershell
devshell       # Enter the Visual Studio Developer Shell
claude         # Install, update, or launch Claude Code
copilot        # Install, update, or launch GitHub Copilot CLI
sandbox-check  # Check the sandbox configuration
sandbox-help   # Show these commands
```

`claude` installs Claude Code per-user through Anthropic's native installer.
`copilot` downloads GitHub's latest Windows x64 release into `~\.local\bin` and
verifies it against the release's `SHA256SUMS.txt`. No npm or WinGet is used.

On first Copilot launch, enter a user-owned fine-grained PAT with
`Copilot Requests` as its only added permission and minimal repository access.
The wrapper stores it as the sandbox user's persistent
`COPILOT_GITHUB_TOKEN`. Every process running as `ClaudeSandbox` can read it;
scope and expire it accordingly.

Rotate or remove that token with:

```powershell
copilot -SetToken
copilot -ClearToken
```

## Daily use

Open `Agent Sandbox`. On first launch, Windows Credential UI asks for the
`ClaudeSandbox` password and can save it for later starts. Run `sandbox-help`,
then start the agent or Developer Shell you need.

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-ClaudeSandbox.ps1
```

This removes the sandbox user and profile, generated ProgramData state,
firewall rules, and shortcut. It keeps the workspace, such as
`C:\dev\ClaudeSandbox`.

## Important notes

- Install agent CLIs per-user under `C:\Users\ClaudeSandbox`, not machine-wide
  or in your main profile.
- The sandbox user can access anything in its workspace and anything readable
  by ordinary Windows users.
- Claude managed settings do not govern Copilot CLI. Configure each agent's
  permissions independently.
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

## License

[MIT](LICENSE)
