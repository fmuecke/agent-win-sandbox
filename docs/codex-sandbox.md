# Codex Elevated Windows Sandbox Concepts

source: https://github.com/openai/codex/tree/main/codex-rs/windows-sandbox-rs

This note summarizes only the Codex Windows sandbox "elevated" mode. The legacy
path that creates a restricted token from the current user is intentionally
ignored here because it does not match our target model. The relevant Codex path
uses dedicated local users, an elevated setup helper, per-run ACL refresh, and a
command runner launched under the sandbox user.

## Executive Summary

The elevated Codex sandbox is a two-stage system:

1. An elevated setup helper provisions durable Windows state: sandbox users,
   a sandbox users group, protected helper/state directories, firewall/WFP
   policy, ACLs, setup markers, and DPAPI-protected sandbox credentials.
2. Normal runtime code selects the right sandbox user, refreshes ACLs for the
   current command's permission profile, launches a command-runner helper as
   that sandbox user, and asks the runner to start the real child process with a
   further restricted token.

For `claude-win-sandbox`, the closest useful concept is: keep Claude Code under
a dedicated Windows account, move trusted launch/control files outside the
writable workspace, and let Windows enforce filesystem and network boundaries.
Codex goes further by automating per-command ACL refresh and using a helper
binary instead of `runas`.

## Relevant Files

- `codex-windows-sandbox/src/elevated_impl.rs`: capture-mode elevated sandbox
  entry point. Resolves permissions, obtains sandbox credentials, refreshes ACLs,
  prepares capability SIDs, launches the runner, and captures output.
- `codex-windows-sandbox/src/unified_exec/backends/elevated.rs`: interactive
  elevated backend. It prepares the same sandbox context, launches the runner,
  and bridges stdin/stdout/stderr/resize/terminate.
- `codex-windows-sandbox/src/spawn_prep.rs`: common elevated spawn preparation:
  environment normalization, setup refresh, effective write-root calculation,
  capability SID selection, and sandbox credential retrieval.
- `codex-windows-sandbox/src/setup.rs`: orchestrates elevated setup and
  non-elevated setup refreshes; builds read/write/deny root payloads.
- `codex-windows-sandbox/src/bin/setup_main/win.rs`: elevated setup helper
  implementation.
- `codex-windows-sandbox/src/bin/setup_main/win/sandbox_users.rs`: provisions
  local users and stores DPAPI-protected passwords.
- `codex-windows-sandbox/src/bin/setup_main/win/firewall.rs`: configures
  Windows Firewall rules scoped to the offline sandbox account.
- `codex-windows-sandbox/src/wfp.rs` and `src/wfp/filter_specs.rs`: configures
  persistent WFP filters for account-scoped DNS/ICMP/SMB blocking.
- `codex-windows-sandbox/src/bin/command_runner/win.rs`: the process launched
  as the sandbox user. It creates the final restricted token and starts the real
  child process.
- `codex-windows-sandbox/src/token.rs`: `CreateRestrictedToken` helpers used by
  the runner.
- `codex-windows-sandbox/src/cap.rs`: creates persistent synthetic capability
  SIDs used in ACLs and restricted tokens.
- `codex-windows-sandbox/src/helper_materialization.rs`: copies helper binaries
  into a protected sandbox bin directory.

## Elevated Mode Flow

### 1. Provisioning

The elevated setup helper provisions:

- `CodexSandboxOffline`
- `CodexSandboxOnline`
- `CodexSandboxUsers`
- `.sandbox`
- `.sandbox-bin`
- `.sandbox-secrets`
- `setup_marker.json`
- `sandbox_users.json`
- firewall and WFP rules for the offline account

The two-user split lets Codex choose a network identity per run:

- Offline/restricted network: run as `CodexSandboxOffline`.
- Online/network-enabled: run as `CodexSandboxOnline`.

The shared `CodexSandboxUsers` group is used as a stable ACL principal for
common read/write grants.

### 2. Credential Storage

The setup helper creates random passwords for the sandbox users and stores them
under `.sandbox-secrets` in `sandbox_users.json`. Passwords are DPAPI-protected
before writing.

At runtime, Codex decrypts the selected user's password and uses it to launch the
command-runner helper under that account. If the login fails, it deletes the
stored user file and reruns setup/refresh.

Claude implication:

- Our current `runas` model avoids password storage, but requires manual entry.
- A Codex-style launcher would need stored or otherwise retrievable sandbox
  credentials, plus careful ACL protection around that state.

### 3. Setup Markers and Refresh

Codex records setup version and network proxy settings in a protected setup
marker. Runtime checks compare the marker with the current code's setup version
and desired offline proxy settings.

Even after provisioning is complete, Codex refreshes ACLs before each run:

- Calculate current read roots.
- Calculate current write roots.
- Calculate deny-read paths.
- Calculate deny-write paths.
- Apply missing grants.
- Apply/reconcile deny ACEs.

This matters because elevated mode is not just "create user once." It keeps
filesystem policy synchronized with the current command's permission profile.

Claude implication:

- A setup marker under `C:\ProgramData\claude-win-sandbox` would be useful even
  without porting the full runtime refresh system.
- If we keep one fixed workspace grant, refresh can remain simple.
- If we add per-repo/per-run permissions, we need Codex-like ACL reconciliation.

### 4. Read and Write Roots

Codex translates its permission profile into Windows paths:

- Read roots: helper directory, platform defaults, workspace roots, selected
  user-profile children, and other configured readable paths.
- Write roots: active workspace roots, extra writable roots, and optionally
  Windows temp roots from `TEMP`/`TMP`.
- Deny-write paths: protected children inside writable roots, such as `.git`,
  `.codex`, `.agents`, and explicit read-only subpaths.
- Deny-read paths: explicit sensitive paths that must remain unreadable.

The elevated setup helper grants read and write access to the sandbox users
group and to the active capability SIDs. It applies deny ACEs where required.

Claude implication:

- Today we permanently grant `ClaudeSandbox` Modify on `C:\dev\ClaudeSandbox`.
- Codex's model is stricter: write access is computed and refreshed.
- We can adapt this gradually by protecting launcher/config/control paths first,
  then later considering per-root grants.

### 5. Capability SIDs

Codex generates random SID strings that are not local users. They function as
capability SIDs and are stored under the Codex home:

- A read-only capability SID.
- A per-CWD workspace capability SID.
- A per-extra-write-root capability SID.

Writable roots are ACLed for both the sandbox group and the relevant capability
SID. The command runner includes only the active capability SIDs in the final
restricted token. Stale ACLs from previous roots do not grant access unless the
current token also has the matching capability SID.

This is the main reason elevated mode can keep durable ACLs without allowing
every future sandbox run to use every previously allowed path.

Claude implication:

- Pure `runas` cannot attach custom restricting capability SIDs.
- To port this concept, we need a native helper or equivalent Windows API layer.
- Without capability SIDs, our practical boundary is the sandbox account's
  normal ACL access.

### 6. The Command Runner

The parent launches `codex-command-runner.exe` under the selected sandbox user.
The parent and runner communicate through named pipes using framed messages.

The parent sends a `SpawnRequest` containing:

- command
- cwd
- environment
- permission profile
- workspace roots
- Codex home paths
- active capability SIDs
- timeout
- TTY/stdin/private-desktop options

The runner:

- Hides the real user profile path from the sandbox process where possible.
- Determines whether the command needs a read-only or writable-roots token.
- Converts active capability SID strings to SID pointers.
- Opens the current sandbox user's token.
- Calls `CreateRestrictedToken`.
- Starts the real command via pipes or ConPTY.
- Streams stdout/stderr and lifecycle events back to the parent.
- Accepts stdin, resize, and terminate messages.
- Uses a kill-on-close job object for process cleanup.

Claude implication:

- `runas` gives us a real interactive terminal with much less machinery.
- A Codex-style helper would replace `runas` if we want automatic launch,
  restricted tokens, process tree cleanup, or parent-controlled sessions.

### 7. Restricted Token Inside the Dedicated User

The elevated path first switches identity to the sandbox user, then the runner
creates a further restricted token from that sandbox user's token. This is the
important distinction from the legacy path.

The token helpers use:

- `DISABLE_MAX_PRIVILEGE`
- `LUA_TOKEN`
- `WRITE_RESTRICTED`
- active capability SIDs
- the sandbox user's SID
- the logon SID
- Everyone

The result is narrower than a normal standard-user token. Access checks must
satisfy both the sandbox user's normal ACLs and the restricting SID set.

Claude implication:

- Our current process runs as a normal `ClaudeSandbox` standard user.
- That is still useful blast-radius reduction, but it is weaker than Codex
  elevated mode.
- Porting this exactly means building a launcher/runner helper.

### 8. Network Isolation

Codex uses the offline sandbox account for restricted network runs.

Windows Firewall COM rules:

- Scope rules to the offline user's SID.
- Block non-loopback outbound traffic.
- Block loopback UDP.
- Block loopback TCP except configured local proxy ports, unless local binding is
  explicitly allowed.
- Verify local firewall policy changes are effective.

WFP rules:

- Install persistent user-scoped WFP filters.
- Block ICMP.
- Block DNS on ports 53 and 853.
- Block SMB on ports 445 and 139.
- Treat WFP setup as best-effort and log failures.

Claude implication:

- Our current `SeDenyNetworkLogonRight` blocks network logon, not outbound
  sockets.
- The most direct Codex elevated-mode feature to adapt is account-scoped
  outbound firewall blocking for `ClaudeSandbox`.
- If we later split online/offline users, firewall policy should attach only to
  the offline user.

### 9. Protected Control Plane

Codex separates trusted control-plane files from writable workspaces:

- Helper binaries are copied into `.sandbox-bin`.
- Setup state lives under `.sandbox`.
- Secrets live under `.sandbox-secrets`.
- Sandbox users can read/execute what they need, but cannot rewrite trusted
  launch artifacts.

Claude implication:

- Keep `C:\ProgramData\claude-win-sandbox\config.json`, launcher/checker, and
  bootstrap scripts admin-write / Users-RX.
- Keep `C:\Program Files\ClaudeCode\managed-settings.json` admin-write.
- Do not put trusted launch scripts under the writable workspace.
- If we add a helper binary, install/copy it to an admin-controlled location,
  not to `C:\dev\ClaudeSandbox`.

## What We Can Adapt Soon

1. Keep setup metadata in the ProgramData config.
2. Keep checker coverage for ProgramData locks and setup metadata compatibility.
3. Keep optional outbound firewall blocking scoped to `ClaudeSandbox`.
4. Document clearly that deny-network-logon is not outbound network isolation.
5. Keep trusted launcher/check/bootstrap/config/policy files out of the writable
   workspace.
6. Add checks or optional protection for workspace control paths such as `.git`,
   `.claude`, `.codex`, and `.agents`.

## What Requires a Helper Binary

These Codex elevated-mode features do not map cleanly to the current
PowerShell-plus-`runas` implementation:

1. Launching without manual password entry while preserving an interactive
   session.
2. Creating a restricted token from the sandbox user's token.
3. Adding synthetic capability SIDs to the final process token.
4. Per-run write-root capabilities.
5. Framed IPC and ConPTY mediation.
6. Kill-on-close job-object cleanup.
7. DPAPI-protected sandbox user password lifecycle.
8. WFP provider/sublayer/filter installation.

If we want exact Codex elevated-mode behavior, the right shape is a small native
launcher/runner helper plus a PowerShell setup/check layer around it.

## Recommended Claude Adaptation

For this repository, the practical path is:

1. Keep the current single `ClaudeSandbox` user for now.
2. Add Codex-style setup state/versioning under ProgramData.
3. Add optional account-scoped outbound firewall blocking.
4. Keep using `runas` until we have a clear need for automatic launch,
   restricted tokens, or per-run writable roots.
5. Treat a native helper as a later redesign, not as a prerequisite for the
   current PowerShell toolset.

If we later want to mirror Codex elevated mode closely, split the design into:

- `ClaudeSandboxOffline` and `ClaudeSandboxOnline`.
- `ClaudeSandboxUsers` group.
- Protected ProgramData helper/state/secrets directories.
- DPAPI-protected credentials.
- Native command runner launched under the selected sandbox user.
- Restricted-token child process with active capability SIDs.
