# Framework integration

Read this when adopting the framework in a project or changing its runner. The public
gist owns the executable lifecycle; keep project provisioning and assertions in a
small host runner and, where needed, a guest driver.

## Pin and import the dependency

Preserve an existing project's verified pin unless changing it is part of the task.
For a new integration, this known revision provides the API described below:

- [Immutable module source](https://gist.githubusercontent.com/fmuecke/2a53528dba05cd208c2cfbef2c547e2a/raw/7b4d862ab00465b06028b11ee4981c48c398602a/WindowsSandboxTest.psm1)
- SHA-256: `B23495DFF238F65FDD69869BFD58481032BD3F9BA0A7E9D001EDF4444FB4C78C`
- Module version: `1.0.0`. A version label alone does not identify the bytes; retain
  the immutable revision and hash together.

Download to a temporary file under a project-owned output/cache directory, verify
SHA-256, then move it to the cache path and import it. Verify cached bytes on reuse.
Remove temporary downloads in `finally`; a mismatch must stop import. Updating the
dependency means reviewing the new source and updating its URL and hash together,
including affected project contracts. Do not fetch a mutable latest revision at runtime.

## Implement the host runner

1. Resolve project paths, select configuration, and validate required artifacts.
   Stage only what the tests need; top-level artifact names must be unique.
2. Import the verified module and call `Invoke-WindowsSandboxTest` with `-RunRoot`,
   `-ArtifactPath`, `-TestScript`, and `-PassThru`.
3. In the callback, provision the guest, execute the tests, inspect current-run files,
   and throw on any failed command or assertion. Print the retained host directory
   early in the callback so failure diagnostics identify it too.
4. On success, report the returned output and `HostDirectory`. Propagate failures to
   the caller/CI; do not turn them into a successful process exit.

The framework refuses an occupied Sandbox and creates `RunRoot\<guid>` on the host.
It stages artifacts there, starts a guest, shares that directory writable, executes
the callback, and attempts to stop its guest in `finally`. Project code must not add
a competing lifecycle or assume cleanup cannot fail.

### API contract

| API | Contract |
| --- | --- |
| `Invoke-WindowsSandboxTest` | Required `RunRoot` and `TestScript`; optional `ArtifactPath`, `GuestMountPath` (default `C:\SandboxTest`), `StartupTimeoutSeconds` (120), `ShareRetryIntervalSeconds` (2), `WsbExecutable`, and `PassThru` |
| Callback | `param($sandbox)` receives `HostDirectory`, `GuestMountPath`, and `InvokeCommand` |
| Command delegate | `& $sandbox.InvokeCommand -Command $command -Phase $phase -CaptureFailure`; optional `WorkingDirectory` and `RunAs` (default `system`) |
| Command result | `Output` is control output; `ExitCode` must be checked when using `CaptureFailure` |
| Runner result | With `PassThru`, returns `HostDirectory` and callback `Output`; otherwise emits callback output |

Do not detach the command delegate with `.GetNewClosure()`; it relies on the module's
scope. Keep host paths distinct from guest aliases.

## Capture output and assert success

For native commands, use `cmd.exe /d /s /c` with correct Windows quoting to redirect
stdout/stderr (`> "result-path" 2>&1`) into a unique file below `GuestMountPath`.
Read its matching file below `HostDirectory`. Require file existence, successful
`ExitCode`, and the project's exact success marker or structured assertions. Do not
create an unconditional `PASS` to compensate for a test with no explicit results.

The callback owns result validation; the framework does not interpret project markers.
Preserve full logs independently of markers. Guest drivers that create logs outside
the share must copy them back after each phase and in `finally`, before guest teardown.

## Interactive tests

Connect the guest desktop when required and run its bootstrap using
`-RunAs ExistingLogin`. Determine the guest ID from this invocation, checking the
`wsb.exe --raw list` response rather than selecting an arbitrary running instance.
Add bounded login-readiness handling if needed by the project.

An existing login is not proof of a standard-user test context. The project driver
must establish and verify the identity, token, session, and desktop required by its
test. Keep account provisioning and temporary permission changes inside the guest,
restore them on failure, and bound process waits.

## Verify integration changes

- Parse changed PowerShell and run the project's focused host tests/contracts.
- Run the affected real guest workflow. Check exit status, current-run assertions,
  complete retained logs, and teardown; source checks alone do not prove integration.
- For a new integration or changed lifecycle/log retention, exercise a controlled
  callback failure and verify diagnostics survive and the guest is stopped.
- Test interactive behavior in the required visible session. If unavailable, report
  it unverified rather than substituting noninteractive execution.

For documentation-only edits, validate metadata, links, and API/command accuracy;
state that live guest execution was not performed.
