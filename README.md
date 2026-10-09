# agent-win-sandbox

Give coding agents their own Windows identity, workspace, and controlled path
to the internet. Keep your familiar PowerShell terminal and development tools.

- **Protect your account:** the agent runs as a separate standard user, away
  from your personal credentials and interactive desktop.
- **Control network egress:** outbound TCP/UDP is limited to a local proxy that
  forwards only to destinations in your allowlist.
- **See what is exposed:** run `sandbox-exposure` to check the agent's actual
  reach, authority, containment, and monitoring controls.
- **Stay in your tools:** the console runs in Windows Terminal or the integrated
  terminal of VS Code or Visual Studio.

**Measured on one Windows host (October 2026):** the exposure checker scored
an AgentSandbox session **51–67/100**, versus **17–31/100** for a regular
developer session. Both used checker profile `default/5`; evidence coverage
was 85% and 87%, respectively; the sandbox assessment was marked incomplete.
These are control-assessment ranges, not a multiplier for security or breach
risk. Results depend on the machine and session. This setup reduces blast
radius, but does not provide VM-grade isolation; use a VM for adversarial code
or strong isolation.

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
- Protects the launcher, [`launch-as`](https://github.com/fmuecke/launch-as), network tools, bootstrap, checker, and managed-settings
  files in admin-write locations.
- Restricts the sandbox account's outbound TCP/UDP to the local proxy port with
  [`wfp-lock`](https://github.com/fmuecke/wfp-lock); [`network-sandbox`](https://github.com/fmuecke/network-sandbox) forwards only allowlisted destinations.

## What it does not protect against

- Malicious code, prompt injection, or hard isolation failures.
- Exfiltration through services included in the proxy allowlist.
- Data readable by `AgentSandbox`, including its workspace, credentials, and
  broadly readable local files.
- Snapshots, resource limits, centralized audit logs, or automatic kill
  switches.

## Requirements

- Windows 10 or 11 with machine-wide PowerShell 7
- Administrator rights for setup, removal, and policy installation
- Highly recommended: machine-wide Visual Studio and Git for Windows

## Try it in Windows Sandbox

With [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
enabled, run this from PowerShell 7:

```powershell
.\Run-Demo.ps1
```

The demo packages the checkout or release beside the script, maps that package
and PowerShell 7 read-only, and installs AgentSandbox inside a fresh guest.
It opens a visible AgentSandbox console for exploration; try `sandbox-exposure`
or `sandbox-help`. That console uses one of the pinned broker's two session
slots; you can open one more with the desktop shortcut. Git, Visual Studio,
and agent sign-ins are not preconfigured.
Close Windows Sandbox to discard the guest. Host accounts and policies are
untouched; the generated package and `.wsb` file remain under `dist\demo-runs`.

Use `-ProxyPort 18080` to try another port, or `-PrepareOnly` to create and
inspect the `.wsb` configuration before opening it.

## Setup

Run once from an elevated PowerShell 7 session, using the account that will
normally launch the sandbox:

```powershell
.\Setup-AgentSandbox.ps1 -ProxyPort 8080
```

Run setup and removal only from a reviewed release or a clone the agent
cannot write. An elevated script in an agent-writable checkout runs whatever
the agent changed in it, with administrator rights.

Setup optionally deploys the Claude Code managed settings to
`C:\Program Files\ClaudeCode\managed-settings.json`; it asks before replacing an
existing file because this policy is machine-wide and shared by every Claude
Code user. It downloads and hash-verifies the `launch-as` package, then lets
`launch-as-admin` install the broker and all command-line tools together under
`C:\Program Files\launch-as`. It also installs pinned `wfp-lock` and
`network-sandbox` binaries together under protected
`C:\ProgramData\agent-win-sandbox`, copies
`config\network-sandbox.json` to protected ProgramData on first setup, starts the proxy
under the setup account, and applies the per-user WFP lock after the proxy is
running. An existing proxy allowlist is preserved with a warning; setup updates
its port to match `-ProxyPort`. Review the installed allowlist before using
agents. Setup enrolls `AgentSandbox` and creates the `Agent Sandbox` Public
Desktop shortcut. Component directories are not added to `PATH`.

Setup upgrades supported brokered installations from `v1.0.0-preview`,
`v1.1.0-preview`, `v1.1.0`, and `v1.2.0-preview`; after a successful component installation, it
deploys the new ProgramData launcher and then removes the obsolete ProgramData
client/admin copies. Unknown or incomplete
installations still require removal with their matching Agent Sandbox version.
The shared workspace remains untouched by removal.

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
sandbox-exposure # Assess this session using the configured -SandboxPath
sandbox-help   # Show these commands
```

`claude` installs Claude Code per-user through Anthropic's native installer.
`copilot` downloads GitHub's latest Windows x64 release into `~\.local\bin` and
verifies it against the release's `SHA256SUMS.txt`. No npm or WinGet is used.
`sandbox-exposure` reports the access currently available to the session;
the checker itself does not enforce isolation.

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

Open `Agent Sandbox` as the same Windows account that ran setup. The launcher
starts the proxy if needed, then the installed `launch-as-broker` starts an
enrolled `AgentSandbox` console in the current terminal pane without a password
prompt. The shell verifies the WFP lock and sets `HTTP_PROXY` and `HTTPS_PROXY`
to `http://127.0.0.1:8080` (or the configured port). Multiple sessions share
one proxy. Run `sandbox-help`, then start the agent or Developer Shell you need.

## Use in your terminal or IDE

Open a PowerShell 7 terminal in your preferred host:

- **Windows Terminal:** open a PowerShell 7 tab.
- **VS Code:** select **View > Terminal**, then choose PowerShell 7.
- **Visual Studio:** select **View > Terminal**. If it opens Developer PowerShell
  instead of PowerShell 7, run `& 'C:\Program Files\PowerShell\7\pwsh.exe'` first.

Then run this command in that terminal pane:

```powershell
& 'C:\ProgramData\agent-win-sandbox\Start-AgentSandbox.ps1'
```

The pane becomes the `AgentSandbox` console; run `claude`, `copilot`, or
`devshell` there. The IDE itself and its other terminals still run as your
normal Windows user.

## Removal

Run from an elevated PowerShell 7 session:

```powershell
.\Remove-AgentSandbox.ps1
```

This stops the proxy and removes the account's WFP lock, user and profile,
generated ProgramData state, broker enrollment, shortcut, and
installed `wfp-lock` and `network-sandbox` executables. It uninstalls the
`launch-as` broker and executables when no other broker accounts remain. It
keeps the workspace, such as `C:\AgentSandbox`, and any older network-tool
copies in Program Files that other tools may use.

## Important notes

- Install agent CLIs per-user under `C:\Users\AgentSandbox`, not machine-wide
  or in your main profile.
- The sandbox user can access anything in its workspace and anything readable
  by ordinary Windows users.
- Claude managed settings do not govern Copilot CLI. Configure each agent's
  permissions independently.
- The initial `network-sandbox.json` allowlist is intentionally small. Agent
  sign-in, updates, and package feeds may need additional reviewed destinations.
- WFP covers outbound TCP/UDP attributed to `AgentSandbox`; ICMP and brokered
  DNS or traffic under another identity remain outside that per-user lock. The
  proxy controls destination hosts and ports, not HTTPS content. See the
  [threat model](docs/threat-model.md#proxy-settings-and-strict-egress).

## More detail

- [Changelog](CHANGELOG.md)
- [Full guide](docs/FULL-GUIDE.md)
- [Threat model](docs/threat-model.md)
- [Todo and decisions](docs/todo-and-decisions.md)
- [Codex Windows sandbox concepts and notes](docs/codex-sandbox.md)
- [The Shorthand Guide to Everything Agentic Security](docs/the-security-guide.md)
- [Claude Code sandbox environments](https://code.claude.com/docs/en/sandbox-environments)

## FAQ

### Why doesn't Microsoft build something like this?

They do — but it is not a general solution yet.

Microsoft is actively developing [MXC (Microsoft eXecution Containers)](https://github.com/microsoft/mxc), and GitHub already uses it to provide local sandboxing for **GitHub Copilot CLI** and the **GitHub Copilot app**. It provides OS-level restrictions for filesystem, network, credentials, and process capabilities.

However, GitHub's Windows sandboxing is still experimental/public preview and currently requires a **Windows Insider build**. It is also integrated specifically into GitHub Copilot; tools such as **Claude Code do not currently gain MXC sandboxing automatically**.

So MXC is a very promising direction and may eventually become the preferred Windows primitive for agent containment. Today, `agent-win-sandbox` fills a different gap: it provides a harness-independent security boundary that can be used with different coding agents on normally deployed Windows systems.

Further reading:

- [GitHub: Cloud and local sandboxes for Copilot](https://github.blog/changelog/2026-06-02-cloud-and-local-sandboxes-for-github-copilot-now-in-public-preview/)
- [GitHub Docs: Using local sandboxing](https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/using-local-sandboxing)
- [Microsoft MXC](https://github.com/microsoft/mxc)

### Can I use other agents?

Yes. Install any native Windows agent under `AgentSandbox` and run it there.
Only Claude Code and Copilot CLI have built-in wrappers.

### Should I run Codex agent inside Agent Sandbox?

Usually no. Run Codex directly with its native Windows `elevated` sandbox. It
already uses dedicated lower-privilege users, filesystem boundaries, network egress,
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

[GPL-3.0-or-later](LICENSE) © 2026 Florian Mücke
