# claude-win-sandbox full guide

Run **Claude Code** on Windows under a dedicated low-privilege user, inside a
Visual Studio Developer Shell, scoped to a fixed workspace directory — **without
Docker and without WSL.**

This fills a gap: existing Claude Code sandboxing projects are all Docker- or
WSL/bubblewrap-based. None of them work for the **Windows-native + MSVC + on-prem
toolchain** stack common in embedded, automotive, industrial, and enterprise C++
shops. This project is for that case.

> **Threat model:** This is **blast-radius reduction**, not hard containment.
> It defends against agent mistakes and prompt-injection overreach on a machine
> you basically trust. It is **not** a security boundary against a determined
> attacker who already has your privileges. For hard isolation, use a VM. See
> [Limitations](#limitations).


## What it does

1. **`Setup-ClaudeSandbox.ps1`** (run once, elevated)
   - Creates a low-privilege local user (`ClaudeSandbox`) if absent
   - Hardens it: denies network + RDP logon, password never-expires /
     user-cannot-change, hidden from the login screen. **Interactive logon is
     left enabled on purpose** — the launcher uses it; denying it breaks launch.
   - Prompts for the workspace base directory, defaulting to `C:\dev`, then
     creates `C:\dev\ClaudeSandbox` and grants `ClaudeSandbox` Modify on that tree
   - Verifies your profile isn't readable by Users/Everyone (a Standard user is
     denied your profile by default — the script warns if yours is misconfigured)
   - Adds account-scoped outbound firewall blocks for common Windows
     file-sharing and remote-admin ports (`137-139`, `445`, `135`, `3389`,
     `5985-5986`) while leaving web/HTTPS access available for Claude, git, and
     internal services
   - Writes `C:\ProgramData\claude-win-sandbox\config.json` with the sandbox
     path and setup metadata, locates VS Developer Shell + git, copies the Dev
     Shell bootstrap and the verified `launch-as.exe` helper into
     `C:\ProgramData\claude-win-sandbox\bootstrap\`, installs the launcher and
     checker into `C:\ProgramData\claude-win-sandbox\`, and locks those
     ProgramData artifacts admin-write / Users-RX
   - Creates a Public Desktop shortcut that launches the sandbox

2. **`managed-settings.json`** (optional setup deployment, elevated)
   - Enterprise Claude Code policy: disables bypass/auto modes, blocks web
     fetch/search, locks down hooks/MCP/plugin sideload surfaces, protects
     Claude control files such as `.claude`, `.mcp.json`, and `.git`, and
     pre-approves routine read-only git + build verbs
   - Setup can deploy it to `C:\Program Files\ClaudeCode\managed-settings.json`
     and lock it admin-write / Users-read. If the file already exists, setup
     asks whether to overwrite or skip it.

3. **`Remove-ClaudeSandbox.ps1`** (run for teardown, elevated)
   - Removes the `ClaudeSandbox` local user and profile, account-scoped firewall
     rules, hidden-login-screen registry value, generated
     `C:\ProgramData\claude-win-sandbox\` files, and the Public Desktop
     shortcut if present
   - Does **not** delete or modify the shared workspace directory or its ACLs.
     Delete it manually only after reviewing that it contains nothing you still
     need.

4. **`Start-ClaudeSandbox.ps1`** (run per session, normal priv)
   - Uses `launch-as` to start the target user's interactive console. Windows
     Credential UI requests the `ClaudeSandbox` password when no usable stored
     credential is available.
   - Launches a new console as `ClaudeSandbox`, in the Dev Shell, `cd`'d to the
     sandbox path stored in `C:\ProgramData\claude-win-sandbox\config.json`
   - Creates/updates `C:\Users\ClaudeSandbox\.claude\settings.json`, preserving
     other valid settings while overwriting the sandbox-managed Claude Code
     shell/update settings documented below
   - Keeps the launcher window open on pre-flight or launch errors so shortcut
     launches do not hide the failure
   - The bootstrap warns at launch if the sandbox profile has current
     mapped drives, persistent mapped-drive entries, or saved Network Shortcuts
   - You type `claude` and go

5. **`Check-ClaudeSandbox.ps1`** (run anytime, read-only)
   - Verifies the whole setup: config valid and locked, user exists & is
     non-admin, hardening applied, outbound firewall rules are present and
     scoped to `ClaudeSandbox`, workspace ACLs, your profile isn't exposed,
     bootstrap present + locked, toolchain present, Claude installed per-user
     (and *not* leaking in from elsewhere), policy file valid and admin-locked
   - Prints PASS/WARN/FAIL; exits non-zero on any FAIL. Run elevated for full
     coverage (user-rights + HKLM + other-profile checks). Doubles as a
     post-launch diagnostic.


## Why a separate user (and not just sandbox flags)

Claude Code runs with **your** OS privileges by default — it can read anything
you can: env vars, SSH keys, PATs, credential stores. On Windows, Anthropic's
native bubblewrap sandbox **isn't available yet** (WSL2/Linux/macOS only). So on
native Windows the most practical OS-level boundary is a **separate low-priv
user**: the NTFS ACLs do the enforcing, and Claude Code physically can't reach
what that user can't reach.

The CEO's assistant is not the CEO. Treat the agent the same way: give it
delegated access, not your full Windows identity.

This pairs with — doesn't replace — Claude Code's own permission system and the
managed-settings deny rules. Defense in depth:

| Layer | What it stops | Enforced by |
|-------|---------------|-------------|
| NTFS ACLs (low-priv user) | Reading/writing your secrets & system dirs | Windows kernel |
| `managed-settings.json` deny rules | High-risk Claude modes and agent-control file edits | Claude Code |
| Permission prompts (no bypass mode) | Unreviewed command execution | Claude Code |
| Account logon hardening | Network/RDP logon as the sandbox user | Windows user rights |
| Account-scoped firewall rules | Outbound SMB/NetBIOS/RDP/WinRM from the sandbox user | Windows Firewall |


## Prerequisites

- Windows 10/11, dedicated/trusted dev machine
- Visual Studio (Pro or higher) installed machine-wide
- Git for Windows installed machine-wide
- **Claude Code installed *as the `ClaudeSandbox` user* (per-user, not
  machine-wide).** See [Installing Claude Code](#installing-claude-code).
- Admin rights for setup, removal, and policy installation


## Installing Claude Code

Claude Code **must be installed inside the `ClaudeSandbox` profile**, not
machine-wide and not in your own profile. The binary and its `~/.claude` config
live with the sandbox user so they stay inside the boundary; a machine-wide or
your-profile install can be picked up off the machine PATH, pulling binary/config
from **outside** the sandbox — exactly what the boundary is meant to prevent.

After running setup, start the sandboxed shell via desktop shortcut and install as `ClaudeSandbox`:

```powershell
irm https://claude.ai/install.ps1 | iex
```

This installs to `C:\Users\ClaudeSandbox\.local\bin\claude.exe`. The bootstrap
prepends that directory to PATH on every launch, so no manual PATH edit or
restart is needed. `Check-ClaudeSandbox.ps1` verifies the per-user install is
present and warns if a copy exists elsewhere.

On every sandbox shell launch, the bootstrap also creates or updates
`C:\Users\ClaudeSandbox\.claude\settings.json`. If the file already exists and
contains valid JSON, unrelated settings are preserved, but these values are
managed by the dev shell and overwritten each time:

```json
{
  "env": {
    "CLAUDE_CODE_USE_POWERSHELL_TOOL": "1"
  },
  "defaultShell": "powershell",
  "autoUpdatesChannel": "stable"
}
```

## Setup

```powershell
# 1. Provision the user, ACLs, bootstrap, and optional Claude policy  (ELEVATED)
.\Setup-ClaudeSandbox.ps1
#   prompts for the base directory where the ClaudeSandbox workspace folder
#   will be created; Enter accepts C:\dev
#   if the workspace folder already exists, setup asks before reusing it
#   when creating ClaudeSandbox, setup asks for the password twice
#   the password must satisfy the machine's Windows password policy
#   setup asks whether to deploy managed-settings.json to:
#     C:\Program Files\ClaudeCode\managed-settings.json
#   if that file already exists, setup asks whether to overwrite or skip it

# 2. Install Claude Code AS ClaudeSandbox (see "Installing Claude Code" above)
& 'C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1'
# or use the Claude (sandboxed) desktop shortcut created by setup
#   in the new window:  irm https://claude.ai/install.ps1 | iex

# 3. Verify everything took  (ELEVATED for full coverage)
& 'C:\ProgramData\claude-win-sandbox\Check-ClaudeSandbox.ps1'

# 4. First-time: log in as ClaudeSandbox once to set up its git/ADO credential
#    (scoped, minimal PAT — kept separate from yours)
```

Then, day to day (normal PowerShell, no elevation):

```powershell
& 'C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1'
# or use the Claude (sandboxed) desktop shortcut created by setup
# Windows Credential UI may request the ClaudeSandbox password -> new window opens -> type: claude
```

## Removal

Run the removal script from an elevated PowerShell session:

```powershell
.\Remove-ClaudeSandbox.ps1
```

The script removes the local sandbox account, its Windows profile including the
per-user Claude install/settings, generated `C:\ProgramData\claude-win-sandbox\`
state, account-scoped firewall rules, and the Public Desktop shortcut if present.

It does **not** delete or modify the workspace directory or its ACLs, for example
`C:\dev\ClaudeSandbox`. That folder is a shared working area and may contain
repositories or files you still need. Delete it manually after review if it is no
longer needed.


## Credential handling

The launcher uses the bundled **`launch-as`** helper to start a separate
interactive console as `ClaudeSandbox`. It uses Windows Credential UI when it
needs the sandbox password. The default credential mode may store the credential
in the launching user's Windows Credential Manager if the user selects Remember;
the sandbox account cannot read that credential.

If launch-as fails, for example because of a wrong password or cancelled prompt,
the launcher prints the error and waits for Enter before closing.

Use a stable password that satisfies the local or domain Windows password policy.

The launcher also deliberately does not reset `ClaudeSandbox` to a random
password on every start. That would hide the password from the user, but it
would require elevation for every daily launch, make the starter script a
privileged broker, and add more failure modes than it removes. Keep provisioning
elevated and keep normal launches non-elevated. Credential Manager storage is
optional and scoped to the regular Windows user who starts the launcher.


## Limitations

- **The boundary is Windows' default profile ACL**, not explicit deny rules.
  A Standard user can't read your profile on a correctly configured system; the
  setup script verifies this rather than patching over it with brittle deny ACEs.
  Secrets kept *outside* your profile (e.g. a vault under `C:\` or a share) aren't
  covered by that default — protect those paths' ACLs separately.
- **Claude must be installed per-user under `ClaudeSandbox`.** A machine-wide or
  your-profile install can be resolved off the machine PATH, which would pull the
  binary and `~/.claude` config from outside the boundary. The check script warns
  if it finds Claude installed anywhere other than the sandbox user.
- **No native bubblewrap on Windows.** When Anthropic ships native Windows
  sandboxing, prefer it (or stack it on top of this).
- **Managed-settings deny rules are defense-in-depth, not airtight.** Claude
  Code has had permission-bypass CVEs (symlink tricks, path resolution). Keep it
  updated.
- **`ClaudeSandbox` needs its own writable profile** for `~/.claude` config — that's
  fine; it contains none of your secrets.
- **Debugging system processes still needs elevation.** Don't run *this* elevated
  to get there. Keep agent autonomy and elevation in separate processes — run
  elevated VS for debugging (agent mode off), agentic AI here (low-priv).
- **Outbound firewall protection is operational, not strict egress isolation.**
  The setup blocks common Windows sharing and remote-admin outbound ports for
  `ClaudeSandbox`, but still allows normal web/HTTPS traffic so Claude Code,
  git, installers, package managers, and internal web services keep working. It
  does not stop exfiltration over allowed protocols such as HTTPS. Proxy
  environment variables are routing hints and can be bypassed; strict egress
  also requires firewall/WFP enforcement and an audit of local brokers such as
  localhost proxies, BITS, WebClient, Docker, and WSL/Hyper-V networking. Use a
  controlled VM/network route when "cannot bypass" is a requirement. See the
  [threat model](threat-model.md#proxy-settings-and-strict-egress) for the
  detailed findings.
- **Mapped-drive checks are hints, not complete access proofs.** The bootstrap
  warns at launch about mapped-drive and Network Shortcut hints visible to the
  `ClaudeSandbox` session. It does not enumerate another user's Credential
  Manager entries or prove what a server will allow at connection time.

## Why not Docker / WSL?

Both are great and already well-served by other projects — use them if your
workload runs there. This project exists specifically for **native Windows
toolchains** (MSVC, classic .vcxproj, on-prem build) that can't move into a
Linux container without losing the toolchain.

## License

[MIT](../LICENSE)

## Status

Personal project. Opinionated, minimal, not affiliated with Anthropic.
