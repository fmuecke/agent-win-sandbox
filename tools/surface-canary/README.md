# Controlled surface canary

This pair of PowerShell tools produces a safe, evidence-bounded reproduction
for reporting cross-user process and shared-desktop isolation failures. It uses
only data and UI you create for the test; it is intentionally not a general
memory-inspection tool.

`Start-InteractiveSurfaceCanary.ps1` starts a separate PowerShell process as the
interactive user. It creates a visible, random-title window and stores a random
32-byte buffer in that process. Its public state file contains the process ID,
the buffer address and length, the buffer's SHA-256 hash, and the exact window
title—not the canary plaintext and never a real secret.

`Test-SurfaceCanary.ps1` runs from the candidate sandbox session—for example,
`AgentSandbox` or a Codex sandbox session. It accepts no PID, address, length,
window-title, or output-file parameter. It verifies the worker command line
with a direct native process query, then reads exactly the fixed 32-byte buffer,
hashes it, and reports only a match/mismatch. For the UI proof, it looks only for
the known canary title on the active input desktop. It does not print unrelated
window titles, capture pixels, send input, or change UI objects.

## Procedure

1. Close personal applications you do not need for the test, especially browsers,
   editors, password managers, and terminals with sensitive output.
2. From the normal interactive-user terminal, run:

   ```powershell
   & .\tools\surface-canary\Start-InteractiveSurfaceCanary.ps1
   ```

3. Leave the resulting **AgentSandbox UI Canary** window open.
4. From the separately launched candidate sandbox terminal, run the command
   printed by the starter. It normally is:

   ```powershell
   & 'C:\dev\AI-workbench\agent-win-sandbox\tools\surface-canary\Test-SurfaceCanary.ps1'
   ```

5. A positive process proof requires all of: different `TokenUser` SIDs, a shared
   logon SID, and the exact canary hash. A positive UI proof requires locating the
   canary title on the active input desktop.
6. Close the canary window. This deletes the public state file and releases the
   canary buffer.

## What a positive result proves

A positive cross-user process proof requires all of these observations:

- `CrossUserTest = True`: the verifier and canary have different `TokenUser` SIDs.
- `SharedLogonSid` is not `<none>`: both tokens contain the same logon SID.
- `CanaryMemoryRead = True`: the verifier read and SHA-256-verified the exact
  32-byte canary allocated by the other user's process.

Together, these are direct, controlled evidence that the candidate sandbox read
data from a process owned by a different user because their tokens share a logon
SID. A positive desktop proof requires `CanaryWindowFound = True` on the active
input desktop. `DesktopWriteObjects = True` means the requested
`DESKTOP_WRITEOBJECTS` access was granted; this tool does not exercise it.

The test does **not** claim code injection, privilege escalation, browser-cookie
extraction, screen capture, input injection, or recovery of any real secret.
Those are potential impact paths that require separate analysis and must not be
represented as actions performed by this tool.

## Reporting template

Report a positive cross-user result as an isolation-boundary issue. Suggested
summary:

> A process under the candidate sandbox identity read a SHA-256-verified
> 32-byte controlled secret from a process owned by a different interactive
> user. Both process tokens contained the same logon SID. The sandbox also
> located the controlled window on the active input desktop and opened that
> desktop with `DESKTOP_WRITEOBJECTS`.

Attach the complete verifier output and record the Windows edition/build,
candidate-sandbox identity and launcher configuration, interactive-user identity,
and tool revision. State explicitly that the canary is synthetic and that no
browser, editor, password manager, real secret, screen pixels, or input was
accessed. Include the procedure above so the report can be reproduced without
touching personal data.

## Negative and baseline results

A same-user run may report `[BASELINE]`: it confirms the canary and verifier work
end-to-end, but it is not evidence of cross-user exposure. A failed or
inconclusive run does not prove the boundary secure; retain the exact error and
environment details in the report.

For a remediation regression test, repeat the procedure after switching the
launcher to a genuinely independent sandbox logon session and denying access to
the interactive window station/default desktop. The expected secure result is no
shared logon SID, no canary memory read, and no canary window found.

## Validation

The starter supports a non-UI compile check:

```powershell
& .\tools\surface-canary\Start-InteractiveSurfaceCanary.ps1 -ValidateOnly
```
