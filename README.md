# claude-win-sandbox

Run Claude Code on Windows as a dedicated standard user in a fixed workspace
from a Visual Studio Developer Shell.

This reduces the blast radius of Windows-native development; it is not hard
containment. Use a VM for adversarial code or strong isolation.

> The CEO's assistant is not the CEO.
> Give the agent delegated access, not your full Windows identity.

## What it does

- Separates Claude Code, its credentials, configuration, and installation into
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

- Windows 10 or 11
- Machine-wide Visual Studio and Git for Windows
- Administrator rights for setup, removal, and policy installation

## Setup

Run once from an elevated PowerShell:

```powershell
.\Setup-ClaudeSandbox.ps1
```

Setup optionally deploys the Claude Code managed settings to
`C:\Program Files\ClaudeCode\managed-settings.json`; it asks before replacing an
existing file. It also creates the `Claude (sandboxed)` Public Desktop shortcut.

Start the sandbox with that shortcut, or run:

```powershell
& 'C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1'
```

Install Claude Code in the sandbox shell:

```powershell
irm https://claude.ai/install.ps1 | iex
```

Then verify the installation:

```powershell
Check-ClaudeSandbox
```

## Daily use

Open `Claude (sandboxed)`. On first launch, Windows Credential UI asks for the
`ClaudeSandbox` password and can save it for later starts. Run:

```powershell
claude
```

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-ClaudeSandbox.ps1
```

This removes the sandbox user and profile, generated ProgramData state,
firewall rules, and shortcut. It keeps the workspace, such as
`C:\dev\ClaudeSandbox`.

## Important notes

- Install Claude Code per-user under `C:\Users\ClaudeSandbox`, not machine-wide
  or in your main profile.
- The sandbox user can access anything in its workspace and anything readable
  by ordinary Windows users.
- HTTPS/web egress remains available to Claude Code, git, package managers, and
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
