# claude-win-sandbox

Run Claude Code on Windows as a dedicated low-privilege local user, inside a
Visual Studio Developer Shell, scoped to a fixed workspace directory.

This is blast-radius reduction for Windows-native development. It is not hard
containment. Use a VM for adversarial code or strong isolation.

> The CEO's assistant is not the CEO.
> Give the agent delegated access, not your full Windows identity.

## What It Offers

This project helps you:

- Run Claude Code as a dedicated standard Windows user instead of your main account.
- Keep Claude Code configuration, credentials, and installation under `C:\Users\ClaudeSandbox`.
- Limit expected agent writes to a fixed sandbox workspace.
- Protect launcher, launch-as, bootstrap, check, and managed-settings files under admin-write locations.
- Block common Windows lateral-movement protocols from the sandbox account.

## Limitations

This project currently does not solve:

- Hard isolation for malicious code, malware, or highly sensitive third-party repos.
- Prompt injection from repos, issues, docs, web pages, attachments, tool output, or MCP servers.
- Exfiltration over allowed channels such as HTTPS, git remotes, package feeds, or internal web apps.
- Protection for anything readable by `ClaudeSandbox`, including the sandbox workspace, its own credentials, broadly readable local paths, and secrets stored outside protected profile areas.
- Rollback, snapshots, resource limits, centralized audit logs, or automatic kill switches.

## Requirements

- Windows 10/11
- Visual Studio installed machine-wide
- Git for Windows installed machine-wide
- Admin rights for setup, removal, and policy installation

## Setup

Run once from an elevated PowerShell:

```powershell
.\Setup-ClaudeSandbox.ps1
```

During setup, choose whether to deploy the Claude Code managed settings to:

```text
C:\Program Files\ClaudeCode\managed-settings.json
```

If a policy file already exists there, setup asks whether to overwrite or skip it.

Setup creates a Public Desktop shortcut named `Claude (sandboxed)`. Start the
sandbox shell with that shortcut, or use:

```powershell
& 'C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1'
```

In the new window, install Claude Code as the `ClaudeSandbox` user:

```powershell
irm https://claude.ai/install.ps1 | iex
```

After installation, verify using:

```powershell
Check-ClaudeSandbox
```

## Daily Use

Use the `Claude (sandboxed)` desktop shortcut.

On the first launch, Windows Credential UI asks for the `ClaudeSandbox` password.
Choose whether Windows should remember it for later launches. In the new window:

```powershell
claude
```

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-ClaudeSandbox.ps1
```

Removal deletes the sandbox user, profile, generated ProgramData state, firewall
rules, and the Public Desktop shortcut if present. It does not delete the workspace directory,
for example `C:\dev\ClaudeSandbox`.

## Notes

- Claude Code must be installed per-user under `C:\Users\ClaudeSandbox`, not
  machine-wide and not from your main profile.
- Trusted launcher/launch-as/check/bootstrap/config files live under ProgramData and are
  locked admin-write / Users-read-execute.
- The sandbox user can still access anything explicitly placed in the sandbox
  workspace and anything otherwise readable by normal Windows users.
- HTTPS/web egress remains available for Claude Code, git, package managers, and
  internal services.

## More Detail

- [Changelog](CHANGELOG.md)
- [Full guide](docs/FULL-GUIDE.md)
- [Threat model](docs/threat-model.md)
- [Todo and decisions](docs/todo-and-decisions.md)
- [Codex Windows sandbox concepts and notes](docs/codex-sandbox.md)
- [The Shorthand Guide to Everything Agentic Security](docs/the-security-guide.md)

## License

[MIT](LICENSE)
