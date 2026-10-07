# agent-win-sandbox Threat Model

Date: 2026-08-05

## Scope

This threat model covers the current `agent-win-sandbox` implementation:

- `Setup-AgentSandbox.ps1`
- `Start-AgentSandbox.ps1`
- `Check-AgentSandbox.ps1`
- `Remove-AgentSandbox.ps1`
- `bootstrap/Initialize-AgentSandboxShell.ps1`
- `bootstrap/Enter-DevShell.ps1`
- `scripts/claude-wrapper.ps1`
- `scripts/copilot-wrapper.ps1`
- `managed-settings.json`
- generated state under `C:\ProgramData\agent-win-sandbox`
- agent CLIs installed per-user under `C:\Users\AgentSandbox`
- the shared sandbox workspace, normally `C:\AgentSandbox`

The target scenario is a trusted Windows developer workstation on a dedicated
developer VLAN, joined to or able to reach a separate Windows domain used for
development. This is not intended for hostile endpoints, unmanaged networks, or
production domain administration.

## Security Objective

Reduce the blast radius of agentic coding on a trusted Windows machine. The
sandbox should keep a compromised or confused agent session from the
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
- `AgentSandbox` is a local standard user and is not a domain administrator,
  local administrator, Backup Operator, Remote Desktop user, or member of other
  privileged groups.
- Agent CLIs are installed per-user as `AgentSandbox`, not machine-wide and not
  from the developer's own profile.
- The developer's own profile ACL follows the Windows default model where other
  standard users cannot read it.
- Repositories placed in the sandbox workspace are considered shareable with the
  agent. Anything placed there may be read, modified, built, or deleted by the
  agent.
- Normal HTTPS/web egress remains available because agents, git, package
  managers, installers, and internal web services need it.

## Assets

Primary assets to protect:

- Developer profile data under `C:\Users\<developer>`, including SSH keys,
  cloud credentials, browser state, token caches, shell history, and private
  configuration.
- Domain credentials and Kerberos/NTLM material belonging to the developer.
- Development-domain services, repositories, package feeds, shares, and build
  systems reachable from the developer VLAN.
- Source trees outside `C:\AgentSandbox`.
- Trusted launcher files under ProgramData and Claude Code policy under
  Program Files.
- Agent configuration and credentials scoped to `AgentSandbox`.

Assets intentionally exposed to the agent:

- Files under the configured sandbox workspace.
- The `AgentSandbox` Windows profile and Credential Manager.
- Machine-wide developer tools readable/executable by normal Users, such as
  Visual Studio and Git for Windows.
- Network destinations reachable over allowed protocols from the developer VLAN.

## Trust Boundaries

- **Developer to sandbox account:** Default NTFS profile ACLs prevent
  `AgentSandbox` from reading the developer profile on a correctly configured
  system.
- **Trusted control plane to workspace:** ProgramData launcher/configuration
  files are admin-write / Users-read-execute; managed policy in Program Files is
  admin-write / Users-read. The writable workspace is never trusted launcher
  code.
- **Workstation to developer network:** The WFP lock routes the sandbox user's
  outbound TCP/UDP to the allowlisted proxy; other identity paths need separate
  validation.
- **Human approval to agent action:** Agent prompts and product-specific policy
  constrain tool use but are defense in depth, not OS isolation.

## Threat Actors

| Actor | Capability | In scope |
|-------|------------|----------|
| Malicious repository author | Controls repo files, scripts, hooks, build files, prompts, docs, and test data | Yes |
| Indirect prompt injector | Controls issue text, PR text, web content, generated docs, test fixtures, or package metadata read by the agent | Yes |
| Compromised dependency or build tool | Executes as `AgentSandbox` during build/test/install | Yes |
| Curious or mistaken agent | Runs incorrect commands, edits wrong files, follows malicious text, or overreaches | Yes |
| Network attacker on developer VLAN | Can scan or attack exposed services from the same VLAN | Partially |
| Compromised developer-domain service | Serves malicious content or captures credentials presented by `AgentSandbox` | Partially |
| Local administrator or malware already on the host | Can change ACLs, read memory, tamper with ProgramData, or elevate | No |
| Production-domain attacker | Attempts cross-domain movement from development to production | Out of scope except as a design concern |

## Main Controls

### Separate Windows identity

`AgentSandbox` runs as a local standard user. It has its own profile,
Credential Manager, agent installs, agent configuration, and git credentials.
The agent is not running with the developer's OS identity.

Security effect:

- Prevents direct reads of the developer profile when default profile ACLs are
  intact.
- Separates credential stores.
- Limits accidental writes to unrelated user-owned files.
- Verified broker boundary: the console-only `launch-as-broker` path creates an
  independent logon session, so the child lacks the developer's shared logon
  SID and cannot use that default-DACL grant for process-memory reads or
  termination.
- Verified desktop boundary: console I/O uses only ConPTY and named pipes; the
  child never enters the developer's interactive window station or desktop, so
  the former interactive-desktop attack surface is removed.

Limitations:

- Does not stop access to anything readable by all Users.
- Does not protect secrets stored in broadly readable paths outside the
  developer profile.
- Does not stop a malicious build process from abusing any credential available
  to `AgentSandbox`.
- This remains blast-radius reduction, not hard containment. Use a VM for
  adversarial code, a local administrator, kernel malware, or a boundary that
  must be independently enforced.

### Fixed writable workspace

Setup grants `AgentSandbox` Modify access to the configured workspace, normally
`C:\AgentSandbox`.

Security effect:

- Keeps expected agent writes in one directory tree.
- Makes it clear which repos and files are intentionally exposed.

Limitations:

- The agent can modify or delete anything in that workspace.
- There is no per-repo, per-command, or read-only mode in the current
  PowerShell implementation.

### Protected control plane

Setup downloads and verifies launch-as, then lets its administrator tool install
the broker and command-line tools together under `C:\Program Files\launch-as`.
It copies the launcher, checker, shell initializer, and agent command wrappers,
and writes configuration under `C:\ProgramData\agent-win-sandbox`, then locks
that directory admin-write / Users-read-execute. The managed Claude Code policy
is also intended to live under `C:\Program Files\ClaudeCode\managed-settings.json`
with admin-write permissions.

Security effect:

- Prevents `AgentSandbox` from rewriting launch-as, the launcher, checker,
  shell initializer, command wrappers, or configured sandbox path.
- Keeps trusted launch scripts out of the agent-writable workspace.

Limitations:

- Local administrators can still change these files.
- Misconfigured ACLs weaken the boundary, so `Check-AgentSandbox.ps1` should be
  run after setup and after local policy changes.

### Account hardening

Setup denies network logon and remote interactive logon for `AgentSandbox`,
hides the account from the login screen, and leaves normal interactive logon
enabled because launch-as needs it.

Security effect:

- Reduces use of `AgentSandbox` as a network or RDP login identity.
- Keeps the launcher path usable.

Limitations:

- Deny network logon is not outbound network isolation.
- Interactive local logon remains possible for anyone who knows the sandbox
  password and can log on to the workstation.

### Proxy settings and strict egress

`HTTP_PROXY` and `HTTPS_PROXY` are cooperative application configuration, not a
security boundary. A process running as `AgentSandbox` can unset them, configure
a proxy bypass, or invoke a client that ignores them. Setup installs
both network executables under protected `C:\ProgramData\agent-win-sandbox`
and the allowlist in a separate protected ProgramData folder. The trusted
launcher account starts one proxy on `127.0.0.1` and
the shell sets proxy variables for clients that honor them. `wfp-lock`
applies a per-account WFP policy that allows TCP only to the configured proxy
port on loopback and blocks other outbound TCP/UDP attributed to `AgentSandbox`.
Startup verifies the proxy and the WFP lock before opening an agent shell.
The WFP lock supersedes the older sandbox-specific Windows Firewall port
blocks.

The proxy enforces destination host and port entries, including HTTP `CONNECT`;
it does not inspect HTTPS requests inside a tunnel. The launcher account can
write proxy runtime files but cannot change the protected allowlist without
elevation. Other accounts running the public shortcut cannot start a session
until setup is run from the intended launcher account.

This WFP policy does not cover ICMP, DNS queries issued by the Windows DNS Client
service under another identity, or network requests relayed through other local
services, containers, or VMs. Validate these paths on the target host before
relying on destination confinement. The sandbox user may also communicate with
allowed services, including sending data through them.

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

Blocking sockets attributed directly to `AgentSandbox` may not cover a local
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
  `AgentSandbox` must not be a member of `docker-users`.
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

`config\managed-settings.json` disables bypass-permissions and auto mode, locks down
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
- These settings do not govern GitHub Copilot CLI. Its permissions and
  organization policy must be configured independently.

### GitHub Copilot CLI token

The Copilot wrapper accepts only a user-owned fine-grained PAT whose value
begins with `github_pat_`; the documented scope uses `Copilot Requests` as its
only added permission and minimizes repository access. It stores that PAT as
the sandbox user's persistent `COPILOT_GITHUB_TOKEN`.

Security effect:

- Keeps the Copilot credential separate from the developer's Windows identity.
- Avoids reusing a broader `GH_TOKEN` or classic PAT.

Limitations:

- Windows user environment variables are plaintext. Every process running as
  `AgentSandbox` can read and exfiltrate the PAT.
- The PAT must be treated as compromised if an agent, build, or dependency
  running under that identity is compromised.
- Protected token storage remains an open item; even protected-at-rest storage
  cannot hide a token from Copilot while it is in use.

## STRIDE Summary

| Category | Relevant threats | Current controls | Residual risk |
|----------|------------------|------------------|---------------|
| Spoofing | Agent uses developer identity or domain credentials | Separate local user, separate Credential Manager, per-user agent installs | `AgentSandbox` may still receive its own git/PAT credentials |
| Tampering | Agent rewrites launcher, policy, or config | ProgramData admin-write locks, checker coverage | Admin compromise or ACL drift defeats this |
| Repudiation | Hard to know what the agent did | Claude Code transcript/history, git history, manual review | No centralized audit trail in this repo |
| Information disclosure | Agent reads secrets, profile data, repo secrets, network shares | Separate user, profile ACL check, managed deny rules, WFP lock and allowlist proxy | Secrets in workspace or broad ACL locations remain exposed |
| Denial of service | Agent deletes workspace, consumes CPU/disk, breaks repos | Low-priv user limits system impact | Workspace is fully writable; no job-object or resource limit |
| Elevation of privilege | Malicious code escapes to developer/admin | Standard user, no elevation path in launcher | Local privilege escalation vulnerabilities remain out of scope |

## Key Attack Scenarios

| Scenario | Current control | Residual risk |
|---|---|---|
| Poisoned repo reads `C:\Users\<developer>\.ssh` | Default profile ACLs block direct reads; Claude deny rules block obvious `.ssh` reads. | Misconfigured profile ACLs or keys copied to the workspace/broad-read paths expose them. |
| Poisoned build uses sandbox Git credentials or authenticated remotes | Developer and sandbox credentials are separate; `git push` should require agent approval. | Build tools can use sandbox credentials and HTTPS. Scope sandbox tokens as compromised. |
| Poisoned build reads the Copilot PAT | The PAT is scoped to the sandbox identity and Copilot Requests. | The persistent environment value is readable by every sandbox process; use minimal scope and expiry. |
| Prompt injection attempts SMB, NetBIOS, WinRM, RDP, or RPC traffic | WFP blocks direct TCP/UDP outside the proxy; deny-network-logon limits inbound authentication. | Allowed proxy destinations and requests relayed under another identity remain possible. |
| Agent rewrites bootstrap or launch configuration | ProgramData files are readable but not writable by `AgentSandbox`; checker detects broad write ACLs. | Fails if setup was not elevated, ACLs drift, or an administrator is compromised. |
| Prompt injection changes or deletes workspace files | Damage stays within the workspace and sandbox-accessible resources. | Repositories, artifacts, local branches, and uncommitted work can be lost; no snapshots, copy-on-write isolation, or rollback. |
| Domain SSO, mapped drives, or network shortcuts expose resources | Bootstrap warns about visible mappings and shortcuts; WFP blocks direct TCP/UDP outside the proxy. | Allowed web destinations and local brokers may expose resources; sandbox credentials remain usable by its processes. |

## Domain and VLAN Considerations

The separate developer VLAN and separate Windows domain are useful containment
layers, but they do not replace local least privilege.

Recommended operating model:

- Keep the developer domain separate from production identity and production
  resources.
- Do not grant `AgentSandbox` broad domain group membership.
- Use dedicated development credentials for `AgentSandbox`.
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
profile. Allowed HTTPS can exfiltrate data; the WFP lock restricts direct
TCP/UDP attributed to the sandbox account. A reachable local
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
& 'C:\ProgramData\agent-win-sandbox\Check-AgentSandbox.ps1'
```

For full coverage, run it elevated. Review every WARN and FAIL, especially:

- `AgentSandbox` is not an administrator and has no risky group memberships.
- Network and RDP logon deny rights are present.
- Interactive logon is still allowed.
- ProgramData config, launcher/checker, shell initializer, command wrappers,
  the Program Files launch-as component, and the Program Files Claude policy
  file are admin-write-only.
- The sandbox workspace exists and grants `AgentSandbox` write access.
- The developer profile is not readable by Users, Everyone, or Authenticated
  Users.
- Agent CLIs are installed only under `C:\Users\AgentSandbox\.local\bin`.
- The configured proxy is running and the account-scoped WFP lock verifies.

Manual checks to perform periodically:

- Review what credentials are stored under the `AgentSandbox` profile.
- Review PAT scopes and expiry for source hosting.
- Check for mapped drives and saved network shortcuts in the sandbox profile.
- Confirm no secrets have been copied into the sandbox workspace.
- Review the proxy allowlist and test that direct connections cannot bypass it.
- Inventory localhost listeners and confirm no unintended proxy or tunnel is
  reachable by `AgentSandbox`.
- Confirm `AgentSandbox` is not in `docker-users`, `Hyper-V Administrators`, or
  another group that grants access to a privileged broker.
- Review accessible WSL distributions and Hyper-V firewall policy.
- If strict proxy enforcement is being evaluated, test BITS, WebClient/WebDAV,
  DNS, and other brokers while recording Security events 5156/5157; do not infer
  their effective firewall identity from the service name alone.
