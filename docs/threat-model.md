# claude-win-sandbox Threat Model

Date: 2026-07-30

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

Reduce the blast radius of agentic coding on a trusted Windows machine. The
sandbox should keep a compromised or confused Claude Code session from the
developer's profile, credentials, private keys, browser state, unrelated source
trees, and most local machine state, while reducing common Windows
lateral-movement traffic.

It is not hard isolation. Use a VM, disposable host, or remote sandbox for
adversarial code, malware analysis, production secrets, or assumed host
compromise.

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

- **Developer to sandbox account:** Default NTFS profile ACLs prevent
  `ClaudeSandbox` from reading the developer profile on a correctly configured
  system.
- **Trusted control plane to workspace:** ProgramData launcher/configuration
  files are admin-write / Users-read-execute; managed policy in Program Files is
  admin-write / Users-read. The writable workspace is never trusted launcher
  code.
- **Workstation to developer network:** Account-scoped firewall rules block
  common lateral-movement protocols but allow ordinary web/HTTPS traffic.
- **Human approval to agent action:** Claude Code prompts and managed settings
  constrain tool use but are defense in depth, not OS isolation.

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

### Proxy settings and strict egress

`HTTP_PROXY` and `HTTPS_PROXY` are cooperative application configuration, not a
security boundary. A process running as `ClaudeSandbox` can unset them, configure
a proxy bypass, invoke a client that ignores them, or open a socket directly.
Putting proxy variables in protected managed settings keeps that file from being
edited, but it does not constrain other programs or child processes running as
the sandbox user.

A meaningful same-host proxy design would require all of the following:

- Run the proxy as a service outside the `ClaudeSandbox` identity.
- Keep the proxy binary and configuration admin-write-only.
- Bind only to the intended local address and port.
- Allow exact destination hostnames and ports and deny everything else. A small
  native Windows proxy such as
  [3proxy](https://3proxy.org/doc/man5/3proxy.cfg.5.html) can enforce HTTP
  `CONNECT` hostname/port ACLs; Squid in a small VM is a heavier alternative.
- Force `ClaudeSandbox` traffic to that proxy with firewall/WFP policy, covering
  IPv4, IPv6, UDP/QUIC, and direct DNS. Proxy variables alone are insufficient.
- Resolve destination names at the trusted proxy rather than through a resolver
  controlled by the sandbox session.

Windows Firewall explicit block rules override conflicting allow rules. A broad
explicit "block everything" rule cannot be paired with an overlapping allow rule
and expected to restore proxy access. The policy must structurally exclude the
proxy path from the block, or use a separate network/VM boundary. See
[Microsoft's firewall rule precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

The smallest Claude allowlist depends on authentication and enabled features.
Current core candidates are `api.anthropic.com`, `claude.ai`, `claude.com`, and
`platform.claude.com`. Updates, connectors, documentation, release notes, and
older installers can require additional destinations such as
`downloads.claude.ai`, `mcp-proxy.anthropic.com`, `code.claude.com`,
`storage.googleapis.com`, or `raw.githubusercontent.com`. Prefer disabling
unneeded features over broadly allowing shared hosting domains, and revalidate
the list against the
[Claude Code network requirements](https://code.claude.com/docs/en/network-config)
before deployment.

Even an enforced hostname allowlist still permits communication with the allowed
service. It limits destinations; it cannot prevent misuse of an allowed Claude
credential or distinguish legitimate prompts from data intentionally sent to an
allowed endpoint without deeper application-aware controls.

### Brokered and local-service egress

Blocking sockets attributed directly to `ClaudeSandbox` may not cover a local
broker that accepts a request from the sandbox user and creates the external
connection under another process, service, or VM identity.

The clearest practical case is an unauthenticated localhost proxy or tunnel, such
as a debugging proxy, corporate proxy agent, or SSH dynamic-forward listener.
Other installed privileged agents may expose localhost ports or named pipes that
can fetch arbitrary URLs.

The following built-in or commonly installed components are audit candidates:

- [BITS](https://learn.microsoft.com/en-us/windows/win32/bits/about-bits) can
  perform HTTP/HTTPS downloads and uploads through the Background Intelligent
  Transfer Service.
- [WebClient](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/credentials-prompt-access-webdav-fqdn-sites)
  performs WebDAV network I/O through WinHTTP.
- [DNS Client](https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups)
  can issue externally visible queries and therefore provides at least a
  possible low-bandwidth DNS exfiltration channel.
- [Docker daemon access](https://docs.docker.com/desktop/setup/install/windows-permission-requirements/)
  can move networking into Docker's backend or VM and is highly privileged.
  `ClaudeSandbox` must not be a member of `docker-users`.
- [WSL2 and Hyper-V](https://learn.microsoft.com/en-us/windows/wsl/networking)
  use a separate filtering plane. Check Hyper-V firewall policy and accessible
  WSL distributions instead of assuming an ordinary host `LocalUser` rule
  covers guest traffic.

BITS, WebClient, and DNS are not asserted here as universal bypasses. Windows
Filtering Platform attribution can depend on service impersonation, the broker,
and the Windows version. Validate the actual process and user associated with
connections on the target host, using Windows Filtering Platform/Security events
5156 and 5157 where available. See Microsoft's
[Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
overview for the application/user filtering boundary.

For a hard "cannot bypass" requirement, prefer a VM or isolated host whose only
network route is a controlled proxy or firewall. The same-host standard-user
design remains a pragmatic blast-radius control rather than a formal egress
boundary.

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

| Scenario | Current control | Residual risk |
|---|---|---|
| Poisoned repo reads `C:\Users\<developer>\.ssh` | Default profile ACLs block direct reads; Claude deny rules block obvious `.ssh` reads. | Misconfigured profile ACLs or keys copied to the workspace/broad-read paths expose them. |
| Poisoned build uses sandbox Git credentials or authenticated remotes | Developer and sandbox credentials are separate; `git push` should require Claude approval. | Build tools can use sandbox credentials and HTTPS. Scope sandbox tokens as compromised. |
| Prompt injection attempts SMB, NetBIOS, WinRM, RDP, or RPC traffic | SID-scoped firewall blocks and deny-network-logon reduce access. | HTTPS, package feeds, source hosting, and internal web apps remain; RPC/domain coverage is incomplete and policy can drift. |
| Agent rewrites bootstrap or launch configuration | ProgramData files are readable but not writable by `ClaudeSandbox`; checker detects broad write ACLs. | Fails if setup was not elevated, ACLs drift, or an administrator is compromised. |
| Prompt injection changes or deletes workspace files | Damage stays within the workspace and sandbox-accessible resources. | Repositories, artifacts, local branches, and uncommitted work can be lost; no snapshots, copy-on-write isolation, or rollback. |
| Domain SSO, mapped drives, or network shortcuts expose resources | Bootstrap warns about visible mappings and shortcuts; firewall blocks common sharing ports. | Web SSO and internal HTTPS remain, warnings are not access proofs, and sandbox credentials remain usable by its processes. |

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

## Not Protected: Use Stronger Isolation

The sandbox user can fully control its workspace and use every credential in its
profile. Allowed HTTPS can exfiltrate data, and proxy variables remain bypassable
until firewall/WFP or a VM makes the proxy the only route. A reachable local
proxy, broker, container daemon, or VM network path may connect under another
identity.

Machine-wide tools, extensions, compilers, package managers, build scripts, and
test runners are trusted to the extent normal Users can run them. This project
does not provide a restricted token, capability SID, per-command ACL refresh,
network allowlist, process supervisor, job-object cleanup, memory limit, or
automatic rollback. Local administrators, kernel exploits, endpoint-security
bypasses, and host compromise defeat the model.

Use a disposable VM, isolated build host, devcontainer, or remote sandbox for
malware or adversarial binaries, untrusted attachments, production secrets or
administration, highly sensitive third-party code, multi-tenant workstations,
or formal regulatory isolation requirements.

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
- Inventory localhost listeners and confirm no unintended proxy or tunnel is
  reachable by `ClaudeSandbox`.
- Confirm `ClaudeSandbox` is not in `docker-users`, `Hyper-V Administrators`, or
  another group that grants access to a privileged broker.
- Review accessible WSL distributions and Hyper-V firewall policy.
- If strict proxy enforcement is being evaluated, test BITS, WebClient/WebDAV,
  DNS, and other brokers while recording Security events 5156/5157; do not infer
  their effective firewall identity from the service name alone.
