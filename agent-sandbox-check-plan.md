# Agent sandbox assessment v1: implementation plan

Implements `agent-sandbox-check-spec.md` in reduced scope. Read the spec first; this plan records the decisions made so far and the remaining work.

## Current state

`Test-AgentSandboxExposure.ps1` (repo root, untracked) — **steps 1–5 are done and validated** on a non-elevated split-token admin account. All 11 check areas are implemented. It runs end to end in both human and JSON modes with 0 internal errors and reports `Incomplete` (expected: R-SECRETS-SCAN and A-PROC-INJECT are out of v1 scope, so those essential criteria stay unknown; R-NET-INTERNET needs `-ProbeNetwork`). Validated both as a normal admin account (coverage ~77%) and **inside AgentSandbox itself** (session 0, standard user: score 43-77, coverage 63%, and the sandbox correctly shows more criteria met). **The script stays a standalone asset — it is not copied into Setup/ProgramData or deployed via the launcher.** It contains:

- Comment-based help and parameters: `-Json`, `-Workspace`, `-ProbeNetwork`, `-NetworkTarget`, `-PolicyPath`, `-OutputDirectory`, `-SkipCheck`.
- Constants: `$SchemaVersion = 'agent-sandbox-assessment/1'`, `$CheckerVersion = '0.1.0'`, profile `default/2`, `$MinimumCoverageForVerdict = 0.6`.
- `$CriterionRegistry`: 32 criteria (Id, Dimension, Check, Essential, Severity, Title, Remediation). Profile `default/2` added `A-REMOTE-DOMAIN` (Authority/REMOTE: AD or Entra/Azure AD join, via `Win32_ComputerSystem.PartOfDomain` and the `CloudDomainJoin\JoinInfo` key; notes whether the agent runs as a local vs domain account) and `R-NET-SHARES` (Reach/NETWORK: mapped SMB shares present, from `Win32_NetworkConnection`, inventory of presence only — shares are never contacted). Both nonessential. Comparisons are only valid within the same profile version, so a `default/1` report cannot be compared to a `default/2` one.
- `Initialize-NativeProbe`: `Add-Type` C# class `AgentSandboxAssessmentNative` — token snapshot, foreign process owner/session, single-right process probe, `CheckNamedObject` (AccessCheck against a file/registry security descriptor without opening the object), single-right file/registry/service open probes, window station/desktop names, input desktop probe, visible-window owner PIDs, WTS session user, job limits.
- **Framework (step 1):** assessment state, `Set-CriterionOutcome`, `Add-Finding`, `Add-AssessmentError`, `Protect-Text` (URL-userinfo redaction), `Format-SafePath`, `Get-ErrorCategory`, `Invoke-Check` (honors `-SkipCheck`, catches exceptions, enforces the completeness invariant), `Get-PathAccess` / `Test-AnyWrite` / `Resolve-AccessTargets`, `Measure-Assessment` (score interval, coverage, verdict, critical cap), `Test-Policy`, human report, markdown report, JSON assembly, output-file writing, exit codes.
- **Checks (steps 2–4):** `Invoke-IdentityCheck`, `Invoke-FilesCheck`, `Invoke-DesktopCheck`, `Invoke-NetworkCheck`, `Invoke-HandoffCheck`, `Invoke-IndirectCheck`, `Invoke-RemoteCheck`, `Invoke-ContainmentCheck`, `Invoke-MonitoringCheck`. Helpers: `Get-MatchingTargets` (probe a path list, emit findings, return `{Existing; Matched}`), `Resolve-AccessTargets` (single-source path-set criterion), `Get-WritableRegistryKeys` (KEY_SET_VALUE probe), network helpers (`ConvertTo-NetworkTarget`, `Get-AddressClass`, `Invoke-TcpProbe`), `Get-ServiceImagePath`. The check list and run order live in `$CheckPlan`; `checksNotImplemented` is derived from `$AllCheckAreas` minus the plan. Remaining areas (SECRETS, PROCESSES) are `unknown` / `not implemented in v1`.

Validated on the dev box: verdict `Incomplete`, coverage 70% without network probing, 0 internal errors. A-SVC correctly flags a real LocalSystem service with a writable binary *parent directory* as high (not critical, since the binary itself is not writable), and the critical cap stays off. HANDOFF flags the all-users Startup folder and a machine-PATH dir as agent-writable. CONTAINMENT stayed byte-identical through the `Get-MatchingTargets` extraction.

Two more PowerShell gotchas fixed in step 4 (watch for these in step 5):
- A function that `return @()` (empty array) yields `$null` at the call site, so `$x = Get-Thing; $x.Count` throws under StrictMode. Wrap such calls: `$x = @(Get-Thing ...)`. Property values on a returned object (e.g. `$obj.Matched`) are preserved as arrays and are safe.
- Real `.claude.json` can contain keys differing only in case; `ConvertFrom-Json` throws. Use `ConvertFrom-Json -AsHashtable` and hashtable access (`.ContainsKey` / `.Keys` / `-is [System.Collections.IDictionary]`), and treat a parse failure as `unknown`, not `met`.

**Step 5 (done):** `Invoke-ProcessesCheck` (R-PROC-READ, A-PROC-CONTROL). The exposure is the *possibility*: a granted `PROCESS_VM_READ` / `PROCESS_TERMINATE` handle is proof of the capability — the handle is closed, memory is never read. The right is probed on **every non-own process whether or not its owner can be attributed** (own processes are skipped; since we can always open our own, an unattributable process is by definition not ours — so attribution failure must not downgrade the result to `unknown`). VM_READ on a session≠0 target is the critical case. A denied handle only proves denial *for the token as configured*, so `met` is withheld when the token merely **holds** a DACL-bypass privilege it could enable: `SeDebugPrivilege` (bypasses process DACLs outright → unmet + critical, reaches human-session memory) or `SeTakeOwnership`/`SeRestore` (seize the object, rewrite its DACL → unmet). These are reported via `permission-analysis` even with zero direct handles, and cross-reference `A-ID-PRIVS`. Broader escalation (e.g. `SeImpersonate` → SYSTEM) is left to the Authority dimension, not re-derived here. A-PROC-INJECT left unknown and `Invoke-SecretsCheck` (R-SECRETS-ENV reports secret-bearing env **names only**; R-SECRETS-KNOWN tests existence + readability of known credential files, excludes the agent's own `~/.claude/.credentials.json` as expected, and skips public `.pub`/`.cer`/`.crt`; R-SECRETS-SCAN and R-SECRETS-CREDMAN left unknown). Both checks explicitly resolve their out-of-scope criteria to `unknown` so the completeness invariant passes. `Invoke-FilesCheck` caches other-user profiles in `$script:OtherProfiles` for `Invoke-HandoffCheck`.

Step 5 also hardened the probe paths for the real sandbox run: under `$ErrorActionPreference = 'Stop'`, a bare `Test-Path` (or other probe cmdlet) on a path whose parent denies the agent — e.g. a machine-PATH directory inside the interactive user's profile — raises `UnauthorizedAccessException`, which `Stop` escalates to a check-aborting throw. Every probe-path filesystem cmdlet that may hit a denied target uses `-ErrorAction SilentlyContinue` (a denied path is then treated as unreachable), and `Invoke-Check`'s catch now marks a thrown check's unresolved criteria `unknown` / `check error` instead of letting the sweep mislabel them "not implemented in v1".

Remaining: nothing required for v1 — the former deferred capabilities (secret content scan, Credential Manager inventory, process injection-right probes) are now implemented, lifting coverage to ~94% on the dev box with only the operator-gated network criteria left unknown.

### Two bugs found and fixed in step 1/2 — avoid repeating in steps 3–5

- `ConvertTo-Json` throws `Argument types do not match` when the object graph contains `@($someGenericList)` (a `List[object]` wrapped by `@()`). Serialize generic lists with `.ToArray()` instead. `$script:Findings` and `$script:Errors` use `.ToArray()` in the report for this reason.
- A file-rights test must check the **specific** data bits (`FILE_READ_DATA 0x1`, `FILE_WRITE_DATA 0x2`, `FILE_APPEND_DATA 0x4`, `DELETE 0x10000`, `WRITE_DAC 0x40000`, `WRITE_OWNER 0x80000`), **not** the generic masks. `FILE_GENERIC_WRITE` (0x120116) shares `SYNCHRONIZE`/`READ_CONTROL` with `FILE_GENERIC_READ`, so a whole-mask `-band` reports write on read-only objects. Verified against `icacls` and an open-for-write probe on `hosts`.

## v1 scope decisions

All 32 criteria are now implemented. The following were added after the initial cut, so the earlier "not implemented in v1" wording below is historical:

- **R-SECRETS-SCAN** — `Invoke-SecretContentScan`: bounded content scan (5000 files / 1 MiB per file / 32 MiB / 30 s) over the workspace tree plus a short profile config-file list, with token/key regex detection. Reports only sanitized location + category + count — never a value, snippet or surrounding line. Records coverage and any limit reached; a truncated scan with no hit stays `unknown`.
- **R-SECRETS-CREDMAN** — `GetCredentialEntries` (native `CredEnumerateW`) copies only type + target name, never the blob; the finding reports provider prefixes + a per-type count with e-mail/user tails redacted.
- **A-PROC-INJECT** — probes `VM_WRITE` / `CREATE_THREAD` / `DUP_HANDLE` / `WRITE_DAC` per process (handle closed, never used), with the same `SeDebug` / `SeTakeOwnership` self-grant conditioning as read/terminate.

Still not implemented (deliberately): UDP / proxy-path network probes, inherited-handle enumeration, COM/automation inventory. The only criteria that remain `unknown` on a normal run are `R-NET-INTERNET` / `R-NET-LATERAL`, which require the operator to opt into probing (`-ProbeNetwork` / `-NetworkTarget`); without that the verdict stays **Incomplete** by design, since no destination was tested.

`Protect-Text` now also redacts e-mail local-parts (keeping the domain) so resolved account names, credential targets and git remotes cannot leak PII.

### Sandbox-run semantics fixed (session 0, job confinement)

Two corrections from running as `AgentSandbox` (non-interactive **session 0**):
- **M-ATTRIBUTION** must not treat "can't read the interactive session" as `unknown` — that is the *strongest* separation. It now resolves `met` when the agent is in session 0, or when its account differs from the **active console** user (`WTSGetActiveConsoleSessionId` + `WTSQuerySessionInformation`); `unmet` only when it runs as the console user.
- **C-JOB** returned `win32-24` (`ERROR_BAD_LENGTH`) because `QueryInformationJobObject` rejects an oversized buffer. It now queries `JobObjectBasicLimitInformation` (class 2) with an exact `Marshal.SizeOf` buffer, so an agent confined to a job (as the launcher does) resolves met/unmet instead of unknown. Not-in-job and session-0 paths are exercised only in the sandbox, not on a dev host.

### Requires PowerShell 7

The script declares `#requires -Version 7.0`. The sandbox launcher (`Start-AgentSandbox.ps1`) already runs `pwsh` 7, so that is the tool's real runtime; requiring it fails fast with a clear message when someone runs it under Windows PowerShell 5.1 (`powershell.exe`) instead of hitting subtle 7-only-feature errors. This lets the code use `ConvertFrom-Json -AsHashtable` (which tolerates a `.claude.json` whose project keys differ only by case) without a 5.1 fallback. One session caveat remains and is version-independent: `Add-Type` caches the compiled `AgentSandboxAssessmentNative` for the life of a session, so re-running after the C# changes needs a fresh shell — the `GetCredentialEntries` call is wrapped so a stale cached class degrades `R-SECRETS-CREDMAN` to unknown instead of aborting the whole SECRETS check.

Hard rules (from the spec): no elevation, no memory reads, no file-content reads, no use of discovered credentials, no execution of discovered scripts or binaries, no modification of anything. Probes request one right at a time and close the handle. Collected configuration is data only.

## Internal architecture (follow for steps 3–5)

The script is one shipped file by deliberate choice: the spec requires a single trusted entry point, no installed modules, and the ProgramData copy is ACL-locked and enumerated per-file. Modularity lives *inside* the file, via a uniform check contract — not via extra files, a module, a bundler, or disk-loaded plugins.

- **A check is `Invoke-<Area>Check`** registered as one line in the `$CheckPlan` array in `Main`. `Invoke-Check` dispatches it, honors `-SkipCheck`, catches exceptions, and enforces a completeness invariant: after the check runs, every criterion whose `Check` equals its area must be resolved (not left `not evaluated`), or an `incomplete-check` error is recorded. So the work of adding a check is: add its criteria to `$CriterionRegistry`, write one `Invoke-<Area>Check`, add one `$CheckPlan` line.
- **A check must not re-implement discover → probe → decide → emit.** For a path-set criterion (writable files/dirs), build the candidate path list and call `Resolve-WritableTargets` (sets the criterion to unknown/unmet/met and emits one finding per writable target). FILES, HANDOFF, INDIRECT and SECRETS are mostly "assemble a path list + one helper call". Add sibling helpers in the same spirit when a new repeated shape appears (e.g. a registry-set-value helper, a network-probe helper) rather than inlining the loop in each check.
- **Never call P/Invoke from a check.** All native access goes through `AgentSandboxAssessmentNative` and the `Get-PathAccess` / probe helpers. The C# stays inline behind `Initialize-NativeProbe`; group new members by concern.
- **PowerShell variables are case-insensitive:** never name a local the same word as a parameter (e.g. `$capability` vs param `$Capability`) — it mutates the parameter across loop iterations.
- Scoring, policy and reporting are generic; new checks need no changes there beyond registering criteria.

## Steps

Do these in order; each step should leave a runnable script. After each step run the validation below.

### 1. Framework

- State: ordered map of criterion results (`Outcome` = met/unmet/unknown/na, `Method`, `Evidence`, `Critical`, `CriticalReason`), all initialized `unknown` / `not evaluated`; lists for findings and errors.
- Helpers: `Set-CriterionOutcome`, `Add-Finding` (check, criterion, target, capability, result granted/denied/unknown/observed, method inventory/permission-analysis/access-request, scope, error category, impact, severity), `Add-AssessmentError`, `Format-SafePath` (replace profile and workspace prefixes with `%USERPROFILE%` / `%WORKSPACE%`), `Protect-Text` (redact URL userinfo and long token-like runs; apply to every emitted string as a final pass).
- `Get-PathAccess`: uses `CheckNamedObject` first; if the descriptor is unreadable (error 5), fall back to `ProbeFile` for read/create/delete. Returns read, create, write, delete, changeAcl, takeOwnership as granted/denied/unknown plus the method and the error category. File rights: 0x1 read/list, 0x2 write/add-file, 0x4 append/add-subdirectory, 0x40 delete-child, 0x10000 DELETE, 0x40000 WRITE_DAC, 0x80000 WRITE_OWNER.
- `Invoke-Check -Name -ScriptBlock`: honors `-SkipCheck` (criteria stay unknown, reason `skipped`) and catches exceptions (the check's still-unknown criteria get the error category; the run continues).
- Scoring per the spec: per dimension, lower = met/applicable, upper = (met+unknown)/applicable, times 25, floor lower and ceil upper. If a dimension has no applicable criteria, it contributes 0–25. Coverage = (met+unmet)/applicable over all criteria. A critical finding caps both bounds at 39.
- Verdict: Critical exposure > Incomplete (any essential unknown or coverage < 0.6) > Weak (<40) / Partial (40–69) / Bounded within tested scope (≥70), using the lower bound.
- Policy (`-PolicyPath`): JSON `{ "name": "...", "requireMet": ["<criterion id>", ...] }`. Per id: met/na → compliant, unmet → violation, unknown → unknown; an unknown id is an argument error (exit 1). Policy compliance never changes the score.
- Output:
  - **JSON mode:** exactly one object on stdout, with schema/checker/profile versions, status, timestamp, duration, execution context, scope (workspace, checks run/skipped, network targets), verdict, score, coverage, dimensions, criteria, findings, essential unknowns, `notEvaluated` (every unknown criterion with title/dimension/essential/reason), policy, inventory, limitations and errors. Never use `Write-Host` in JSON mode; diagnostics go to `[Console]::Error`.
  - **Human mode:** verdict, score interval, coverage, the four dimension rows, top findings (one per category), a **Not evaluated / unknown** section listing *every* unknown criterion with an essential/non-essential tag and the reason it was not resolved, remediation for unmet criteria, limitations.
  - **`-OutputDirectory`:** must already exist; writes `assessment-<timestamp>.json` and `.md`.
- Exit codes: 0 when completed, regardless of risk; 1 for invalid arguments or a fatal error.

### 2. IDENTITY, CONTAINMENT, MONITORING

- **IDENTITY:** user/groups/privileges/integrity/elevation/session/auth ID/restricted SIDs/AppContainer/thread token into inventory.
  - `A-ID-ADMIN`: elevated, high/system integrity or an enabled Administrators group → unmet + critical. Deny-only Administrators (UAC split token) → unmet, not critical.
  - `A-ID-PRIVS`: SeDebug, SeTcb, SeCreateToken, SeLoadDriver, SeRestore, SeBackup, SeTakeOwnership, SeAssignPrimaryToken or SeImpersonate present (enabled or not) → unmet + critical.
  - `A-ID-GROUPS`: membership (not deny-only) in Backup/Server/Account Operators, Hyper-V Administrators, Remote Management Users, Network Configuration Operators or `docker-users` → unmet.
- **CONTAINMENT:**
  - `C-POLICY-INTEGRITY`: the `%ProgramData%\agent-win-sandbox` tree (bounded), `C:\Program Files\ClaudeCode\managed-settings.json` and its directory, and the running script and its directory. Any write/create/delete/ACL/owner right → unmet; all denied → met; none present → unknown.
  - `C-TOOL-POLICY`: managed settings present → met; else `~/.claude` exists → unmet; else unknown.
  - `C-JOB`: in a job with kill-on-close (0x2000) and no breakaway (0x800/0x1000) → met; otherwise unmet; query error → unknown. Record UI restriction flags.
  - `C-PERSIST-SELF`: user PATH directories (including `~/.local/bin`), PowerShell profile directories, and `~/.claude/settings.json` when managed `allowManagedHooksOnly` is not true. Any writable → unmet.
  - `C-PROXY-INTEGRITY`: no proxy configured → na. Proxy only in env/HKCU → unmet. Machine policy with a non-writable key → met.
- **MONITORING:**
  - `M-ATTRIBUTION`: WTS session user differs from the current user → met; same → unmet.
  - `M-OS-LOGGING`: Sysmon/Sense service, ScriptBlockLogging policy or ProcessCreationIncludeCmdLine → met; otherwise unknown, never unmet.
  - `M-TAMPER`: write probes on discovered logging policy keys and service change-config/stop probes on discovered monitoring services. Any granted → unmet; none granted → met; nothing discovered → unknown.
  - `M-AGENT-LOG`: `~/.claude/projects` or `~/.copilot` exists and is writable → unmet; none found → unknown.

Milestone: the script runs end to end and prints a report with honest unknowns.

### 3. FILES, DESKTOP, NETWORK

- **FILES:**
  - `R-FILES-PROFILES`: other `C:\Users\*` profiles (excluding own, Public, Default, All Users) readable → unmet. Keep write results for HANDOFF.
  - `R-FILES-ADJACENT`: non-system top-level directories on fixed drives, plus siblings of the workspace and its ancestors, excluding the workspace and its ancestors. Cap at 200 directories; readable → unmet.
  - `R-REG-OTHERS`: other user SIDs under HKU (`<sid>\Software`, read) and `HKLM\SAM\SAM` / `HKLM\SECURITY`. Readable → unmet.
- **DESKTOP:**
  - `R-DESKTOP`: on `WinSta0\Default` with an openable input desktop or visible windows owned by another identity → unmet; not on WinSta0 and input desktop denied → met; otherwise unknown.
  - Named pipes: inventory known broker names only (docker_engine, openssh-ssh-agent); do not connect.
- **NETWORK:** inventory interfaces, gateways, DNS servers and proxy settings (sanitized). Probes only with `-ProbeNetwork` (defaults: `dns:example.com`, `tcp:example.com:443`, `tcp:1.1.1.1:443`, `tcp:[2606:4700:4700::1111]:443`) or `-NetworkTarget` (`dns:`, `tcp:`, `smb:`). 3-second timeout; connect and close, send nothing. Classify targets by resolved address: loopback, private/link-local or internet.
  - `R-NET-INTERNET`: any internet connect succeeds → unmet (note a proxy bypass if a proxy is configured). At least two internet targets probed, all failed → met, with the note that failure does not prove a firewall denial. Not probed → unknown. DNS success alone never decides it.
  - `R-NET-LATERAL`: same logic for supplied LAN/loopback targets; none supplied → unknown.

### 4. HANDOFF, INDIRECT, REMOTE

- **HANDOFF:**
  - `A-HANDOFF-SHARED`: machine PATH directories, the all-users Startup folder, HKLM Run/RunOnce (64- and 32-bit views, set-value probe), first-level subdirectories of Program Files and Program Files (x86), and other profiles (from FILES). Any create/write → unmet.
  - `A-HANDOFF-WORKSPACE`: workspace writable and its ACL grants read to principals other than self, SYSTEM, CREATOR OWNER and TrustedInstaller → unmet ("consumer privileges unknown"). Not writable, or no other principals → met. Inventory counts of non-sample git hooks, `.vscode/tasks.json`, `.github/workflows/*` and build files; never execute them.
- **INDIRECT:** `Win32_Service` (CIM) for each service with a resolvable binary, plus `Get-ScheduledTask` exec actions whose principal is not the current user (expand environment variables). Unmet when any of these hold:
  - the binary is writable, or its ACL/owner can be changed;
  - the parent directory accepts new files;
  - an `OpenService` probe grants change-config, WRITE_DAC or WRITE_OWNER;
  - the service registry key grants set-value.

  Critical only when a writable binary or config belongs to a service or task running as another identity (LocalSystem, LocalService, NetworkService or another account). A writable parent directory alone → high, not critical. This goes into `A-SVC`.
- **REMOTE:**
  - `A-REMOTE-DELEGATED`: git `credential.helper` in the user/system gitconfig, or tool login files present (gh `hosts.yml`, `.azure`, `.aws`, `.kube/config`, `.docker/config.json`) → unmet; none → met. Workspace `.git/config` remote hosts go into inventory with userinfo stripped. Effective scopes are always recorded as unknown.
  - `A-TOOL-SCOPE`: MCP servers declared in `~/.claude.json` (`mcpServers`, `projects.*.mcpServers`) or workspace `.mcp.json` → unknown, with a count; none → met. JSON `toolScope` is always `partial (local declarations only)`.

### 5. PROCESSES and reduced SECRETS

- **PROCESSES:** for each process, owner via `GetProcessToken` (null = owner unknown); skip own SID. Request PROCESS_VM_READ (0x10) and PROCESS_TERMINATE (0x1) separately; never use the handle.
  - `R-PROC-READ`: any VM_READ granted → unmet; critical when the target is in an interactive session (session ≠ 0). All denied → met, with counts.
  - `A-PROC-CONTROL`: same rule for terminate.
  - `A-PROC-INJECT` stays unknown.
  - Cache PID → owner for DESKTOP.
- **SECRETS:**
  - `R-SECRETS-ENV`: environment variable names matching token/secret/password/key/PAT/credential with a non-empty value; report names only, never values.
  - `R-SECRETS-KNOWN`: existence and readability (open probe, no content read) of known credential locations: `.git-credentials`, `.netrc`/`_netrc`, `.npmrc`, `.pypirc`, `.aws/credentials`, `.azure/`, `.kube/config`, `.docker/config.json`, `.config/gcloud/`, gh `hosts.yml`, `.ssh/*` (not `.pub`, `known_hosts`, `config`), and browser profile directories. `~/.claude/.credentials.json` is the agent's own operating credential: report it with `expected: true` and do not fail the criterion on it.

## Validation (every step)

```powershell
$files = 'Test-AgentSandboxExposure.ps1'   # plus the AGENTS.md list if other scripts change
foreach ($file in $files) { $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $file), [ref]$null, [ref]$errors); $errors }
git diff --check
pwsh -NoProfile -File .\Test-AgentSandboxExposure.ps1
pwsh -NoProfile -File .\Test-AgentSandboxExposure.ps1 -Json 2>$null | ConvertFrom-Json   # must parse as one object
```

- Run non-elevated only. Never run setup or removal.
- Check that JSON stdout contains nothing but the object, and that no file contents or environment values appear in either output.
- The test machine's user is a UAC split-token admin. Expect `A-ID-ADMIN` unmet (not critical) and `C-POLICY-INTEGRITY` unmet (the checker runs from a writable repo copy).
- Real sandbox validation (run as `AgentSandbox` via the launcher) needs an installed sandbox; report whether it was done.

## Deployment: standalone asset (decided)

The script stays a **standalone asset**: a single self-contained `.ps1` the operator drops into the sandbox and runs directly through the agent's normal shell. It is deliberately **not** deployed like `Test-AgentSandboxAttackSurfaces.ps1` — no copy into `Setup-AgentSandbox.ps1`, no protected ProgramData ACLs, no `sandbox-assess` alias, no `Package-Release.ps1` entry. This matches the spec's "single trusted PowerShell entry point, no installed modules" and keeps the assessor independent of the installed sandbox state it inspects (and self-evidently writable, which the report honestly flags under `C-POLICY-INTEGRITY` when run from a writable copy).

Confirmed working when run as `AgentSandbox` via the normal shell (session 0, standard user). Because it is not an installed, ACL-locked artifact, treat its own integrity as unattested — the inside-only caveat in the report already states a compromised agent can falsify it.
