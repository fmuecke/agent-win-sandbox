# Native WSL agent sandbox checker

`test_wsl_sandbox_exposure.py` is a Python 3.9+ standard-library-only checker for the **current Linux/WSL agent process context**. No PowerShell, Windows executable, sudo, installed module or privileged helper is required. Run through the agent's normal shell, with the same identity, mounts, environment and launcher.

```bash
# Human summary
python3 -I -B test_wsl_sandbox_exposure.py

# Machine-readable evidence: exactly one JSON object on stdout
python3 -I -B test_wsl_sandbox_exposure.py --json

# Explicit workspace and operator-approved endpoints; numeric IPs only
python3 -I -B test_wsl_sandbox_exposure.py --json \
  --workspace /home/agent/project \
  --tcp-target 127.0.0.1:8080 --tcp-target '[::1]:8080'

# Skip content scanning (environment and permission inventory still run)
python3 -I -B test_wsl_sandbox_exposure.py --json --no-content-scan
```

Use a trusted local copy of the checker. `-I -B` prevents workspace/PYTHONPATH import injection and bytecode-cache writes; it does not make an already compromised Python installation trustworthy. Default mode makes **no external connection**. TCP probes are opt-in, at most 16 endpoints, with a 3-second connect deadline per target. They send no application payload, use no credentials, do no DNS resolution and close immediately. They can still create connection logs. Use only destinations you control or are authorized to assess.

## What it checks

| Area | Evidence collected |
| --- | --- |
| WSL detection | Microsoft kernel markers and WSL environment signals; a nested container can hide the outer environment |
| Windows/shared filesystem bridges | Actual mount table, custom drive mount locations, DrvFS/9p, shared `/mnt/wsl`, remote filesystems, read/write permission analysis |
| Windows execution interop | `WSLInterop` binfmt entry and global status, `/run/WSL` sockets, inherited `WSL_INTEROP`, Windows PATH indicators; no Windows launch |
| Declared WSL configuration | Selected safe boolean settings in `/etc/wsl.conf`, boot-command presence without the command; declaration is not effective enforcement |
| GUI/audio bridges | WSLg, Wayland, X11 and PulseAudio path/environment inventory; no screen, clipboard, audio or input interaction |
| Linux authority | Effective UID/groups, effective/permitted/ambient/bounding capabilities, UID/GID maps, NoNewPrivs, seccomp, namespace comparison with visible PID 1, LSM label, ptrace setting, cgroup membership and resource limits |
| Files/processes | Bounded other-Linux-profile permission inventory; read-only `/proc/PID/mem` open requests for visible foreign UIDs, immediately closed without reading; inherited FD counts/types |
| Brokers and devices | Docker/Desktop, Podman, containerd, libvirt and SSH-agent socket permissions; relevant device nodes; no broker connections or API requests |
| Secrets/remote authority signals | Environment candidates, known credential locations, bounded text/config scanning, credential-helper/config environment signals; no credential use, decryption or scope validation |
| Network | IPv4 route inventory, resolver inventory where safely readable, current-namespace socket-table counts, proxy presence, optional numeric TCP connect probes |
| Control integrity/monitoring | Boot/restriction-control file and parent permissions, local logging-directory permissions; no configuration or log changes |

Access probes never request write/truncate/create opens. File, directory and socket write results are **permission analysis**, not proof of a successful damaging operation. Remote mounts are not actively probed; symlink paths are conservatively excluded. Windows mount metadata may still involve the host provider; remapped network drives and provider behavior cannot be fully identified inside WSL. General inventory is best-effort, not race-proof or a hard-deadline security scanner.

## Secret scan boundaries

Defaults: 5,000 candidate files, 1 MiB/file, 32 MiB total content, and a 30-second cooperative content-scan budget. Default roots are the workspace and selected current-user SSH/cloud/cluster configuration directories, plus known credential files. `--scan-root PATH` is repeatable and replaces directory roots; known credential-file checks remain. `--max-files`, `--max-file-bytes`, `--max-total-bytes` and `--scan-seconds` adjust limits.

No whole-disk scan, link traversal, binary/archive decoding or content reads on recognized Windows/shared/remote mounts. A Windows-mounted workspace is therefore inventoried but **not content-scanned**; use a Linux-local workspace to scan its contents. Files are opened read-only/nonblocking/no-follow, checked as regular files and checked against their actual `/proc/self/fd` path before reading. This is defensive race mitigation, not an adversarial filesystem proof. Reads may update access times or generate audit events. Local filesystem calls may block beyond the cooperative budget.

Patterns cover quoted JSON and key/value assignments, GitHub PATs, selected provider tokens, AWS access-key identifiers and private-key headers; UTF-16 BOM and UTF-8 text are supported. Matches are suspected exposure, not evidence that credentials work. Outputs contain only sanitized locations/categories and coverage metadata: **no matched values, lines, hashes, environment dumps or raw exception/configuration content**. Known detected values and token-like metadata are redacted. Metadata can still be sensitive; protect the report. Absence of matches never establishes absence of secrets.

## Scoring and interpretation

Profile `wsl-inside-exposure-1` defines 17 fixed protection criteria in four equally weighted dimensions: Reach, Authority, Containment and Monitoring, each worth 25 points. Criteria remain visible in JSON with their scope/reason and `met`, `unmet`, `unknown` or justified `not_applicable` outcome.

- Lower score: points supported by met criteria.
- Upper score: lower score plus points that unknown criteria could potentially earn.
- Coverage: equally weighted proportion of resolved criteria in each dimension.
- Essential unknowns force **Incomplete**, irrespective of a high upper score.
- Otherwise: Weak below 40, Partial 40–69, Bounded within tested scope at 70+ (lower bound).

This is a conservative **exposure checklist index, not a safety probability**, and is not numerically interchangeable with a different Windows scoring profile. Permissions on shared mounts and successful selected TCP connections are exposure under this default strict profile even if a permissive policy allows them.

Inside-only evidence cannot verify Windows account privilege, effective host firewall rules, host isolation, independent log delivery, complete sudo/broker/remote permissions, higher-privilege code consumers, child cleanup, hidden namespaces or other agent tool channels. These remain unknown, so v1 will ordinarily end **Incomplete**. That is intentional: use the observed exposures, dimension results and recommendations to improve the environment; do not treat the upper score as earned protection.

The scorer supports a critical-exposure override, but this version does not automatically assert a critical host compromise: Linux root, a broker socket or a suspected token alone does not establish Windows administrator authority, privileged broker authorization or a proven protected-host takeover. They are high-impact exposure findings with explicit uncertainty.

## Optional policy comparison

Policy is data only; example `wsl-policy.example.json`:

```json
{
  "profile_version": "wsl-inside-exposure-1",
  "require_met": ["privileges", "interop", "control_integrity"],
  "minimum_lower_score": 70
}
```

```bash
python3 -I -B test_wsl_sandbox_exposure.py --json --policy wsl-policy.example.json
```

Policy compliance is separate from exposure. Unknown is not compliant. This strict example will not pass simply because `/etc/wsl.conf` says interop is disabled. Use criterion names listed in JSON; unsupported policy fields are rejected.

Exit codes: **0** completed assessment, including exposure and collection gaps; **1** unsupported platform/invalid policy; **2** invalid CLI arguments; **3** violation or unknown when `--fail-on-policy` is explicitly requested with a policy. Collection errors and their categories remain in JSON. No report files are automatically written. If you redirect stdout, your shell creates the selected output file; protect it appropriately.

## Validation and limitations

```bash
python3 -B -m unittest -v test_wsl_checker.py
```

Tests cover mount parsing/custom locations, interval scoring, unknown handling, JSON/PAT/UTF-16 secret detection and redaction, budgets, link/FIFO exclusions, read-only opens, remote-mount exclusions, network timeout handling, a loopback TCP connection with zero payload, policy comparison, collection failures, and interop sockets surviving a disabled binfmt entry.

Validated using Linux execution and offline WSL fixtures. **Not yet tested in a real WSL1/WSL2 instance.** Validate in your actual agent context before relying on it. Do not run as a different/elevated identity just to make checks succeed: that assesses the wrong blast radius. An inside-only report is not independent attestation and can be falsified by a compromised agent.

Technical references used for WSL bridge interpretation:

- https://wsl.dev/technical-documentation/interop/
- https://wsl.dev/technical-documentation/security/
- https://learn.microsoft.com/en-us/windows/wsl/wsl-config
