# claude-win-sandbox — Todo & Decisions

Running log to update the project step by step. Captures decisions already made
(with rationale) and open items still to action. Personal/career discussions are
deliberately excluded.

_Last updated: 2026-07-09_

---

## Decisions made (rationale captured)

### Architecture & isolation
- **Separate low-priv user (`ClaudeSandbox`) is the boundary.** NTFS ACLs do the
  enforcing; the agent physically can't reach what the user can't reach. Chosen
  over Docker/WSL2 because the native Windows + MSVC + on-prem toolchain can't
  move into a Linux container.
- **`managed-settings.json` deny rules are defense-in-depth (belt), not the
  enforcement layer.** The ACL boundary is the real control.
- **Threat model = blast-radius reduction, not hard containment.** Defends against
  agent mistakes and prompt-injection overreach on a trusted machine; not against
  a determined attacker who already has your privileges.
- **`runas.exe` over `Start-Process -Credential`.** The latter produces a hung
  shell (renders but won't accept keyboard input) — confirmed on this machine.
- **No credential caching.** The per-launch `runas` password prompt is the only
  credential path; acts as a deliberate speed-bump / cross-user boundary enforcer.
  Infrequent use doesn't justify the security tradeoff of caching.
- **Stable policy-compliant password (Option A) over per-launch random reset
  (Option B).** The sandbox password must satisfy the local/domain Windows
  password policy; a short simple password may not be accepted on managed
  machines. A random password reset on every launch would avoid the user knowing
  the `ClaudeSandbox` password, but it would require elevation every time and
  turn the daily launcher into a privileged broker. It also does not fit cleanly
  with `runas`, adds failure points for marginal value, and may interfere with
  per-user protected state if Windows secrets become tied to the previous logon
  password. Keep setup elevated once; keep daily launch non-elevated.

### Account hardening
- **Interactive logon stays ENABLED on purpose** — the launcher needs it; denying
  it breaks launch. Deny only network + RDP logon.
- **Password never-expires + user-cannot-change**, account hidden from login screen.
- **Outbound firewall protection is account-scoped and operational.** Setup
  blocks `ClaudeSandbox` outbound SMB/NetBIOS/RDP/WinRM-style ports while
  leaving HTTP/HTTPS and internal web services usable. Strict destination
  allowlisting is deferred because it needs a managed proxy or network policy.

### Filesystem layout
- **Config/launcher/checker/bootstrap → ProgramData; Claude managed settings
  → Program Files.**
  (`C:\ProgramData\claude-win-sandbox\config.json` for the sandbox path,
  `C:\ProgramData\claude-win-sandbox\Start-ClaudeSandbox.ps1` for launch,
  `C:\ProgramData\claude-win-sandbox\Check-ClaudeSandbox.ps1` for verification,
  `C:\ProgramData\claude-win-sandbox\bootstrap\` for the bootstrap, and
  `C:\Program Files\ClaudeCode\managed-settings.json` for file-based Claude Code
  policy), admin-write and Users-RX/read only — not writable by sandbox user,
  prevents launch/check/config/policy poisoning. Program Files is used because
  current Claude Code no longer supports the legacy ProgramData managed-settings
  location on Windows.
- **Workspace default → `C:\dev\ClaudeSandbox\`** with setup asking only for the
  base directory. Chosen over `C:\Users\Public\` as the most developer-intuitive
  tradeoff; awareness carried by naming + in-shell prompt marker, not ownership
  semantics.
- **`ClaudeSandbox` is a fixed, well-known workspace name** (base path
  configurable, name always `ClaudeSandbox`) — for user awareness, not security.
- **Dropped the `repos\` subdirectory** as unnecessary ceremony; README in the
  workspace root carries the explanatory load.
- **Setup regenerates ProgramData artifacts** from the repo source and writes the
  resolved sandbox path to ProgramData config; the project repo remains the
  source of truth for scripts.
- **Setup deploys the daily launcher and checker into ProgramData** alongside
  the bootstrap. These entrypoints are admin-write / Users-RX so desktop
  shortcuts, Windows Terminal profiles, and elevated verification can target a
  stable trusted path instead of a mutable repo checkout. `Setup` and `Remove`
  remain repo/package maintenance scripts for now.
- **Single ProgramData state file.** `config.json` carries the runtime
  `sandboxPath` plus nested setup metadata (version, timestamp, sandbox
  user, installing user, and firewall intent). A separate `setup-marker.json` is
  unnecessary duplication.
- **Setup optionally deploys Claude Code managed settings.** The repo template
  keeps `$SANDBOXDIR` as a placeholder; setup asks before installing the policy,
  asks overwrite/skip when one already exists, substitutes the resolved
  `ClaudeSandbox` workspace path, writes to Program Files, and locks the policy
  file admin-write / Users-read.
- **Removal does not clean workspace ACLs.** After the sandbox user and profile
  are deleted, stale workspace ACL cleanup is low-value complexity. The shared
  workspace is deliberately left untouched for manual review or deletion.

### Bootstrap hardening
- **Bootstrap locked admin-write / Users-RX** so the sandbox user can't modify its
  own launch script.
- **User-identity guard** in the bootstrap: exits if `$env:USERNAME` doesn't match
  the sandbox account (prevents direct invocation as the wrong user).
- **"Running as &lt;user&gt;" greeting** printed before VS Dev Shell output.
- **`Enter-VsDevShell -VsInstanceId`** (from `vswhere -format json`) rather than
  `-VsInstallPath` discovery, which can hang under a different user profile.

### Claude Code install
- **Installed per-user under `ClaudeSandbox`**, not machine-wide — prevents
  binary/config leakage via machine PATH.
- **Bootstrap always adds `~\.local\bin` to PATH.**
  This lets the user install Claude Code and run `claude` in the same shell
  without reopening the session. This also supports other CLI agents.

### IDE / launch UX
- **Full Visual Studio embedding ruled out** — no terminal-profile equivalent;
  a VSIX tool window would still fight the cross-user input problem. Not worth it.
- **Setup always creates the Public Desktop shortcut.** It is part of the normal
  launch path, not an optional prompt. This keeps setup more straightforward and
  reduces branching/complexity.
- **Launcher pauses on launch errors.** Desktop-shortcut launches should not
  disappear before the user can read a wrong-password, cancelled-prompt, or
  pre-flight failure.
- **VS Code NOT being pursued right now** (despite being the cleanest integration
  path if VS Code itself were launched as `ClaudeSandbox`).
- **Preferred mitigation: dedicated Windows Terminal tab** to reduce alt-tab
  friction. Profile snippet drafted; not yet finalized/committed.

### Distribution & IP
- **PSGallery chosen as distribution channel** (over winget) — real need is easy
  setup/updates, not silent provisioning; and public credit is wanted.
- **Stays a personal, public, open-source hobby project** (MIT, © Florian Mücke
  2026), maintained at own pace.

### PowerShell 5.1 quirks (learnings to respect)
- `?.` null-conditional operator unavailable.
- `Select-String .LineNumber` fragile for `secedit` parsing → use index-based
  parsing.
- Avoid `$input` as a variable name (automatic pipeline variable).
- `secedit` normalizes to account name on this machine → checker must match both
  `*SID` and bare account-name forms.

---

## Todo / open items

### Implementation — filesystem layout migration
- [x] Move bootstrap default to `C:\ProgramData\claude-win-sandbox\bootstrap\`.
- [x] Move workspace default from `C:\dev\repo` → `C:\dev\ClaudeSandbox\` in
      setup/start paths.
- [x] Update `Setup-ClaudeSandbox.ps1` to prompt for the workspace base
      directory and apply Modify grants to the fixed `ClaudeSandbox` child tree.
- [x] Add required Public Desktop shortcut for the fixed bootstrap workspace.
- [x] Update `Check-ClaudeSandbox.ps1` paths + ProgramData lock verification.
- [x] Update README default paths and setup flow.
- [x] Decide whether `Setup` should deploy launcher/check scripts themselves to
      `C:\ProgramData\claude-win-sandbox\`, or keep launching from the repo plus
      locked ProgramData bootstrap.
- [ ] Update the Windows Terminal profile snippet once the final launcher location
      is decided.

### Launch UX
- [ ] Finalize the Windows Terminal profile (test `runas` desktop-attachment
      behaviour first — does it dock or detach?).
- [ ] **Decide:** pursue "VS Code launched as `ClaudeSandbox`" for tighter IDE
      integration, or leave as WT-tab only?

### Git collaboration hardening (deferred to a hardening pass)
- [ ] Address git-hook / `.git/config` / filter-driver injection vector on the
      shared repo. Short-term "belt and buckles": `core.hooksPath` redirect +
      explicit NTFS deny ACEs on `.git/config` and `.git/hooks/`.
- [ ] Long-term: Path A — separate clones, fetch-based collaboration (the
      architecturally sound answer).

### Higher-risk workflows
- [ ] Explore Hyper-V VM / Dev Box isolation for YOLO-mode agent workflows.

### Tool-agnostic generalization (from Copilot CLI discussion)
- [ ] Consider generalizing the harness to `-Agent Claude|Copilot`. One isolation
      pattern, two policy models — NTFS boundary generalizes; defense-in-depth
      layer differs (Copilot CLI: server-side org policy, no local
      `managed-settings.json` equivalent; needs PAT with Copilot Requests scope +
      a seat).
- [ ] Verify whether Copilot CLI needs the same operational firewall profile or
      stricter proxy/network-layer egress control.

---

## Parking lot / nice-to-have
- [x] Operational outbound firewall rules for the sandbox account
      (SMB/NetBIOS/RDP/WinRM blocked; web remains available).
- [ ] Strict egress allowlist for the sandbox process (e.g. `api.anthropic.com`,
      `dev.azure.com`) via managed local proxy, network firewall, or VM.
- [ ] Pre-commit secrets scanning (`gitleaks` / `detect-secrets`) as an active
      layer beyond content exclusions.
