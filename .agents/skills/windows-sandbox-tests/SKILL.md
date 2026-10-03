---
name: windows-sandbox-tests
description: Integrate, run, or diagnose Windows project tests through the public WindowsSandboxTest PowerShell gist framework. Use when privileged or interactive tests need a fresh Windows Sandbox guest, retained logs, and verified teardown; not for host-only unit tests or unrelated VM frameworks.
---

# Windows Sandbox tests

Use the public [WindowsSandboxTest framework](https://gist.github.com/fmuecke/2a53528dba05cd208c2cfbef2c547e2a)
for execution. This skill guides integration and evidence collection; project-owned
PowerShell runners remain directly usable by developers and CI without the skill.

## 1. Establish the project contract

Read the target repository's agent instructions, test documentation, and existing
Sandbox runner. Identify these inputs before running a test:

| Input | Required detail |
| --- | --- |
| Build and entry point | Build command, configuration, host runner, and required artifacts |
| Guest context | SYSTEM, existing interactive login, or a project-created test identity; required provisioning and desktop access |
| Storage | Host run root, staged files, guest mount path, and retained result/log files |
| Success | Expected command exit status plus explicit file markers or structured assertions |
| Coverage | What the selected tests establish and what remains outside their scope |

Take these from the actual project, not another project's conventions. Do not invent
account names, executable names, build flags, or success markers. If a consequential
input cannot be established from the repository, ask for it before dependent execution.

For an existing integration, reuse its runner. For a request to adopt the framework,
read [Framework integration](references/framework.md), implement a small project-owned
runner, and document the contract above in the project's normal test documentation.
Link that guide from its agent instructions. Do not introduce a required manifest or
copy the framework into the skill. A run-only request does not authorize redesigning
an unrelated test harness.

## 2. Check readiness

- Confirm the target checkout and use its documented build command; skip a separate
  build when the test entry point already builds. Check whether it formats sources.
- Require Windows Sandbox and `wsb.exe` on the host. Interactive tests need a visible
  guest desktop and the correct login; SYSTEM execution alone does not provide it.
- The framework refuses an occupied Sandbox. If a guest exists, stop this attempt; do
  not attach to or terminate it. Run these workflows serially.
- The runner verifies the framework's pinned SHA-256 before import, including cached
  copies. Downloading a missing copy requires its pinned URL. Never bypass a mismatch.

## 3. Execute in a fresh guest

Invoke the project host runner and retain its output and exit status. Let the framework
own GUID staging, guest startup, writable sharing, bounded readiness retries, command
dispatch, timing, and teardown. The default guest mount is `C:\SandboxTest`; use the
callback's actual paths rather than assuming the default.

Keep test installation, account creation, service changes, and elevation inside the
guest. Share only the staged artifacts/results directory writable. Do not run guest
drivers directly on the host or make privileged host setup a substitute for a failed
guest run.

The framework bounds share readiness; project drivers must bound their own process
waits and preserve diagnostics when a phase fails.

## 4. Validate evidence and teardown

Identify this invocation's GUID directory below the project run root. Require both
successful command status and the project's expected shared-file results. Never reuse
an earlier pass or treat `InvokeCommand.Output` as guest stdout/stderr: it is control
output. Read and replay relevant output from the files written by the guest.

Preserve full phase logs separately from concise result markers. If logs originate
outside the share, copy them after each phase and again during failure cleanup. A phase
that never started may have no log; explain that instead of silently omitting it.
Keep the run directory after success and failure.

After the framework's teardown, check `wsb.exe --raw list` and confirm the test guest is
gone. Report cleanup failures separately from test failures. Identify the guest owned
by this attempt before any recovery action.

## 5. Diagnose and report

| Failure | Next action |
| --- | --- |
| Missing artifact | Rebuild the selected configuration and check the runner's artifact list |
| Download/hash failure | Inspect the pinned URL, expected hash, and cached bytes; do not accept a replacement silently |
| Startup/share failure | Inspect host prerequisites and transport diagnostics; preserve available artifacts |
| Interactive login failure | Check guest desktop/login readiness and the runner's bounded retry policy |
| Missing result, failed assertion, or nonzero exit | Read current-run phase logs; do not infer success from transport output |
| Teardown failure | Report the remaining guest and cleanup error separately |

Retry in a fresh guest after an identified correction. Stop and report the blocker if
another attempt would merely repeat the same failure.

Report the project workflow, configuration, pass/fail result, failing phase if any,
retained run directory, and teardown status. Separate source/contract checks, host
tests, live guest integration, and interactive acceptance. Claim only the coverage
established by the selected tests.
