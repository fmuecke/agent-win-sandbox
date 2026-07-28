# claude-win-sandbox Threat Model

Date: 2026-06-28

## Scope

This threat model covers the current `claude-win-sandbox` implementation:

- `Setup-ClaudeSandbox.ps1`
- `Start-ClaudeSandbox.ps1`
- `Check-ClaudeSandbox.ps1`
- `Remove-ClaudeSandbox.ps1`
- `bootstrap/Enter-ClaudeDevShell.ps1`
- `managed-settings.json`
- generated state under `C:\ProgramData\claude-win-sandbox`
- Claude Code installed per-user under `C:\Users\ClaudeSandbox`
- the shared sandbox workspace, normally `C:\dev\ClaudeSandbox`

The target scenario is a trusted Windows developer workstation on a dedicated
developer VLAN, joined to or able to reach a separate Windows domain used for
development. This is not intended for hostile endpoints, unmanaged networks, or
production domain administration.

## Security Objective

The objective is blast-radius reduction for agentic coding on a trusted Windows
machine.

The sandbox should make a compromised or confused Claude Code session unable to
read the developer's primary Windows profile, personal credentials, private SSH
keys, browser state, unrelated source trees, and most local machine state. It
should also reduce accidental lateral movement through common Windows sharing
and remote-admin protocols.

This is not a hard isolation boundary. A VM, disposable host, or remote sandbox
is still required for adversarial code, malware analysis, production secrets, or
workloads where full host compromise must be assumed.

## Deployment Assumptions

- The physical or virtual developer machine is trusted and administered by the
  developer or a trusted IT function.
- The machine is on a dedicated developer VLAN, not a general office, guest, or
  production network.
- The Windows domain reachable from that VLAN is separate from production and
  contains only development identities and resources.
- The primary developer account is not used for production administration from
  the same agent session.
- `ClaudeSandbox` is a local standard user and is not a domain administrator,
  local administrator, Backup Operator, Remote Desktop user, or member of other
  privileged groups.
- Claude Code is installed per-user as `ClaudeSandbox`, not machine-wide and not
  from the developer's own profile.
- The developer's own profile ACL follows the Windows default model where other
  standard users cannot read it.
- Repositories placed in the sandbox workspace are considered shareable with the
  agent. Anything placed there may be read, modified, built, or deleted by the
  agent.
- Normal HTTPS/web egress remains available because Claude Code, git, package
  managers, installers, and internal web services need it.

## Assets

Primary assets to protect:

- Developer profile data under `C:\Users\<developer>`, including SSH keys,
  cloud credentials, browser state, token caches, shell history, and private
  configuration.
- Domain credentials and Kerberos/NTLM material belonging to the developer.
- Development-domain services, repositories, package feeds, shares, and build
  systems reachable from the developer VLAN.
- Source trees outside `C:\dev\ClaudeSandbox`.
- Trusted launcher files under ProgramData and Claude Code policy under
  Program Files.
- Claude Code configuration and credentials scoped to `ClaudeSandbox`.

Assets intentionally exposed to the agent:

- Files under the configured sandbox workspace.
- The `ClaudeSandbox` Windows profile and Credential Manager.
- Machine-wide developer tools readable/executable by normal Users, such as
  Visual Studio and Git for Windows.
- Network destinations reachable over allowed protocols from the developer VLAN.

## Trust Boundaries

### Developer account to sandbox account

The primary boundary is the Windows user boundary between the developer account
and `ClaudeSandbox`. NTFS profile ACLs enforce that `ClaudeSandbox` cannot read
the developer's profile on a correctly configured system.

### Trusted control plane to writable workspace

Trusted launch/configuration artifacts live under ProgramData and should be
admin-write / Users-read-execute:

- `C:\ProgramData\claude-win-sandbox\config.json`
- `C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1`
- `C:\ProgramData\claude-win-sandbox\launch-as.exe`
- `C:\ProgramData\claude-win-sandbox\Check-ClaudeSandbox.ps1`
- `C:\ProgramData\claude-win-sandbox\bootstrap\Enter-ClaudeDevShell.ps1`

File-based Claude Code managed policy lives under Program Files and should be
admin-write / Users-read:

- `C:\Program Files\ClaudeCode\managed-settings.json`

The writable workspace must not be the source of trusted launcher code.

### Local machine to developer network

The workstation is allowed onto a developer VLAN. Account-scoped Windows
Firewall rules block common Windows lateral-movement protocols from
`ClaudeSandbox`, but ordinary web/HTTPS traffic remains available.

### Human approval to agent action

Claude Code permission prompts and managed settings are a policy boundary around
tool use. They are defense in depth and should not be treated as equivalent to
OS isolation.

## Threat Actors

| Actor | Capability | In scope |
|-------|------------|----------|
| Malicious repository author | Controls repo files, scripts, hooks, build files, prompts, docs, and test data | Yes |
| Indirect prompt injector | Controls issue text, PR text, web content, generated docs, test fixtures, or package metadata read by the agent | Yes |
| Compromised dependency or build tool | Executes as `ClaudeSandbox` during build/test/install | Yes |
| Curious or mistaken agent | Runs incorrect commands, edits wrong files, follows malicious text, or overreaches | Yes |
| Network attacker on developer VLAN | Can scan or attack exposed services from the same VLAN | Partially |
| Compromised developer-domain service | Serves malicious content or captures credentials presented by `ClaudeSandbox` | Partially |
| Local administrator or malware already on the host | Can change ACLs, read memory, tamper with ProgramData, or elevate | No |
| Production-domain attacker | Attempts cross-domain movement from development to production | Out of scope except as a design concern |

## Main Controls

### Separate Windows identity

`ClaudeSandbox` runs as a local standard user. It has its own profile, Credential
Manager, Claude Code install, Claude configuration, and git credentials. The
agent is not running with the developer's OS identity.

Security effect:

- Prevents direct reads of the developer profile when default profile ACLs are
  intact.
- Separates credential stores.
- Limits accidental writes to unrelated user-owned files.

Limitations:

- Does not stop access to anything readable by all Users.
- Does not protect secrets stored in broadly readable paths outside the
  developer profile.
- Does not stop a malicious build process from abusing any credential available
  to `ClaudeSandbox`.

### Fixed writable workspace

Setup grants `ClaudeSandbox` Modify access to the configured workspace, normally
`C:\dev\ClaudeSandbox`.

Security effect:

- Keeps expected agent writes in one directory tree.
- Makes it clear which repos and files are intentionally exposed.

Limitations:

- The agent can modify or delete anything in that workspace.
- There is no per-repo, per-command, or read-only mode in the current
  PowerShell implementation.

### Protected control plane

Setup downloads and verifies launch-as, copies the launcher, checker, and bootstrap, and writes configuration
under `C:\ProgramData\claude-win-sandbox`, then locks the directory admin-write /
Users-read-execute. The managed Claude Code policy is also intended to live under
`C:\Program Files\ClaudeCode\managed-settings.json` with admin-write
permissions.

Security effect:

- Prevents `ClaudeSandbox` from rewriting launch-as, the launcher/checker/bootstrap, or
  changing the configured sandbox path.
- Keeps trusted launch scripts out of the agent-writable workspace.

Limitations:

- Local administrators can still change these files.
- Misconfigured ACLs weaken the boundary, so `Check-ClaudeSandbox.ps1` should be
  run after setup and after local policy changes.

### Account hardening

Setup denies network logon and remote interactive logon for `ClaudeSandbox`,
hides the account from the login screen, and leaves normal interactive logon
enabled because launch-as needs it.

Security effect:

- Reduces use of `ClaudeSandbox` as a network or RDP login identity.
- Keeps the launcher path usable.

Limitations:

- Deny network logon is not outbound network isolation.
- Interactive local logon remains possible for anyone who knows the sandbox
  password and can log on to the workstation.

### Account-scoped firewall rules

Setup creates outbound Windows Firewall block rules scoped to the
`ClaudeSandbox` SID for:

- SMB and NetBIOS: TCP 139, TCP 445, UDP 137, UDP 138
- RPC endpoint mapper: TCP 135
- RDP: TCP 3389
- WinRM: TCP 5985, TCP 5986

Security effect:

- Reduces accidental or prompt-injected access to common Windows file-sharing
  and remote-admin paths from the sandbox identity.
- Helps in a domain environment where nearby developer services may otherwise
  be reachable.

Limitations:

- HTTPS and other allowed protocols can still exfiltrate data.
- Rules may be overridden or disabled by higher-priority firewall policy.
- They do not block all domain protocols, all RPC dynamic ports, package feeds,
  source-control remotes, or arbitrary internal web services.

### Claude Code managed settings

`managed-settings.json` disables bypass-permissions and auto mode, locks down
hooks/MCP/plugin sideload surfaces, denies WebFetch/WebSearch, and blocks edits
to agent-control paths such as `.git`, `.claude`, and `.mcp.json`.

Security effect:

- Reduces policy/config poisoning through Claude-controlled files.
- Prevents local policy bypass mode when installed correctly.
- Avoids broad secret-read promises that would duplicate or weaken the Windows
  user/ACL boundary story.

Limitations:

- This is defense in depth, not a kernel boundary.
- Path and command policies are intentionally narrow and incomplete.
- Agent bugs or future Claude Code behavior changes can affect enforcement.

## STRIDE Summary

| Category | Relevant threats | Current controls | Residual risk |
|----------|------------------|------------------|---------------|
| Spoofing | Agent uses developer identity or domain credentials | Separate local user, separate Credential Manager, per-user Claude install | `ClaudeSandbox` may still receive its own git/PAT credentials |
| Tampering | Agent rewrites launcher, policy, or config | ProgramData admin-write locks, checker coverage | Admin compromise or ACL drift defeats this |
| Repudiation | Hard to know what the agent did | Claude Code transcript/history, git history, manual review | No centralized audit trail in this repo |
| Information disclosure | Agent reads secrets, profile data, repo secrets, network shares | Separate user, profile ACL check, managed deny rules, firewall blocks | Secrets in workspace or broad ACL locations remain exposed |
| Denial of service | Agent deletes workspace, consumes CPU/disk, breaks repos | Low-priv user limits system impact | Workspace is fully writable; no job-object or resource limit |
| Elevation of privilege | Malicious code escapes to developer/admin | Standard user, no elevation path in launcher | Local privilege escalation vulnerabilities remain out of scope |

## Key Attack Scenarios

### 1. Poisoned repository reads developer SSH keys

Attack:

1. Developer clones a malicious repo into the sandbox workspace.
2. Claude reads project instructions or runs a build script.
3. Malicious content tries to read `C:\Users\<developer>\.ssh`.

Expected result:

- OS ACLs should block direct reads from the developer profile.
- Claude Code deny rules should also block obvious `.ssh` read attempts.

Residual risk:

- If the developer profile ACL is misconfigured, this can fail.
- SSH keys copied into the workspace or another broad-read path are exposed.

### 2. Poisoned build steals sandbox git credentials

Attack:

1. Repo build script runs under `ClaudeSandbox`.
2. Script reads `ClaudeSandbox` git credential material or uses an existing
   authenticated remote.
3. Script pushes, fetches private repos, or exfiltrates over HTTPS.

Expected result:

- Developer credentials are separated from sandbox credentials.
- `git push` should require Claude Code approval when invoked through Claude's
  tool policy.

Residual risk:

- A build tool or child process can use credentials available to
  `ClaudeSandbox`.
- HTTPS egress is allowed.
- Tokens assigned to `ClaudeSandbox` must be scoped as if compromised.

### 3. Agent attempts lateral movement over Windows protocols

Attack:

1. Prompt injection tells Claude to enumerate or mount domain file shares.
2. The agent tries SMB, NetBIOS, WinRM, RDP, or RPC endpoint mapper traffic.

Expected result:

- Account-scoped firewall rules should block the listed outbound ports for
  `ClaudeSandbox`.
- Deny network logon reduces the usefulness of the account as a network logon
  identity.

Residual risk:

- HTTPS, package feeds, source hosting, and internal web apps remain reachable.
- Not all domain or RPC traffic is covered.
- Firewall policy may drift or be overridden.

### 4. Agent rewrites its next-session bootstrap

Attack:

1. Agent tries to edit the bootstrap script so future launches run attacker
   commands.
2. Agent tries to change config so the launcher starts somewhere else.

Expected result:

- ProgramData files should be readable but not writable by `ClaudeSandbox`.
- `Check-ClaudeSandbox.ps1` should report failures if broad write ACLs appear.

Residual risk:

- If setup was not run elevated, ACLs were later changed, or an admin account is
  compromised, this control can fail.

### 5. Prompt injection causes destructive workspace changes

Attack:

1. Malicious text instructs the agent to delete files or rewrite source.
2. Claude executes commands inside the sandbox workspace.

Expected result:

- Damage is contained to the workspace and resources available to
  `ClaudeSandbox`.

Residual risk:

- Repos in the workspace can be damaged.
- Generated artifacts, local branches, and uncommitted work can be lost.
- This repo does not provide snapshots, copy-on-write isolation, or automatic
  rollback.

### 6. Domain SSO or mapped drive exposure

Attack:

1. `ClaudeSandbox` has mapped drives, saved network shortcuts, or default domain
   access that reaches developer resources.
2. Agent follows prompt-injected instructions to access those resources.

Expected result:

- Bootstrap warns about mapped drives, persistent mappings, and network
  shortcuts visible in the sandbox profile.
- Firewall blocks common Windows sharing ports.

Residual risk:

- Web-based SSO and internal HTTPS applications are still reachable.
- The warning is not a complete proof of domain access.
- Saved credentials in `ClaudeSandbox` remain usable by processes running as
  that user.

## Domain and VLAN Considerations

The separate developer VLAN and separate Windows domain are useful containment
layers, but they do not replace local least privilege.

Recommended operating model:

- Keep the developer domain separate from production identity and production
  resources.
- Do not grant `ClaudeSandbox` broad domain group membership.
- Use dedicated development credentials for `ClaudeSandbox`.
- Prefer short-lived, scoped PATs or bot identities for source hosting.
- Keep domain file shares off-limits unless the agent workflow explicitly needs
  them.
- Treat developer-domain HTTPS services as reachable by the sandbox unless a
  network firewall or proxy says otherwise.
- Monitor or log outbound connections from the developer VLAN when possible.
- Do not use this setup from a workstation that also performs production
  administration.

## Residual Risks

Accepted residual risks in the current implementation:

- A malicious process running as `ClaudeSandbox` can fully control the sandbox
  workspace.
- Any credential stored in the `ClaudeSandbox` profile can be abused by code
  running as `ClaudeSandbox`.
- Allowed HTTPS egress can be used for exfiltration.
- Machine-wide tools, extensions, and build systems are trusted to the extent
  that normal Users can execute them.
- There is no restricted token, capability SID, per-command ACL refresh, network
  allowlist, process supervisor, job-object cleanup, memory limit, or automatic
  rollback.
- A local administrator, kernel exploit, endpoint security bypass, or host
  compromise defeats the model.
- Supply-chain attacks in compilers, package managers, build scripts, or test
  runners execute inside the sandbox user's authority.

## Misuse Cases

Do not rely on this implementation for:

- Running malware or intentionally adversarial binaries.
- Opening untrusted attachments that may exploit local applications.
- Handling production secrets.
- Production-domain administration.
- Reviewing highly sensitive third-party code without stronger isolation.
- Multi-tenant workstations where other local users are not trusted.
- Regulatory isolation requirements that call for a formal security boundary.

Use a disposable VM, isolated build host, devcontainer, or remote sandbox for
those cases.

## Validation Checklist

Run after setup and after material local policy changes:

```powershell
& 'C:\ProgramData\claude-win-sandbox\Check-ClaudeSandbox.ps1'
```

For full coverage, run it elevated. Review every WARN and FAIL, especially:

- `ClaudeSandbox` is not an administrator and has no risky group memberships.
- Network and RDP logon deny rights are present.
- Interactive logon is still allowed.
- ProgramData config, launcher/launch-as/checker, bootstrap, and the Program Files Claude
  policy file are admin-write-only.
- The sandbox workspace exists and grants `ClaudeSandbox` write access.
- The developer profile is not readable by Users, Everyone, or Authenticated
  Users.
- Claude Code is installed only under `C:\Users\ClaudeSandbox\.local\bin`.
- Account-scoped firewall rules exist and apply.

Manual checks to perform periodically:

- Review what credentials are stored under the `ClaudeSandbox` profile.
- Review PAT scopes and expiry for source hosting.
- Check for mapped drives and saved network shortcuts in the sandbox profile.
- Confirm no secrets have been copied into the sandbox workspace.
- Confirm local or domain firewall policy has not disabled the account-scoped
  block rules.

## Security Posture Summary

This implementation is appropriate for a trusted developer machine on a
segmented developer network when the goal is to keep an agent's mistakes or
prompt-injection failures away from the developer's primary identity and local
secrets.

The strongest controls are Windows identity separation, default profile ACLs,
protected ProgramData launch files, per-user Claude installation, and scoped
blocking of common Windows lateral-movement protocols.

The main remaining risk is that the sandbox is still an online development user
with a writable workspace, build tools, package managers, and HTTPS egress. Keep
the sandbox's credentials narrow and assume that anything reachable by
`ClaudeSandbox` can eventually be reached by a compromised agent session.
