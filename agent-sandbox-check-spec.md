# Agent coding sandbox: assessment specification

Date: 2026-10-03. Scope agreed through interview; implementation defaults below are proposals.

## Purpose and scope

Assume prompt injection has succeeded and the agent can execute arbitrary code. Assess the reachable damage and the controls that limit it: reach, authority, containment and monitoring. This is an exposure assessment, not a test of model obedience or a proof that the system has no vulnerabilities.

- Windows-native first; keep check definitions portable for a later WSL implementation.
- Run inside the actual agent context, through its usual launcher. No elevation, host-side inspector or privileged helper.
- Automatic discovery; optional comparison against an expected policy.
- Inventory plus non-destructive access probes. No canary setup in v1.
- Bounded content scans for likely secrets; never report secret values.
- Agent-invokable, noninteractive self-assessment, with both a scored human report and structured JSON.

An inside-only run cannot establish complete host policy, external monitoring coverage, remote authorization or resistance to an already compromised agent falsifying the report. Record these limits explicitly.

## Checks

| ID | Area | Required checks |
| --- | --- | --- |
| IDENTITY | Effective identity | User and group SIDs and attributes; logon SID/authentication ID; process and thread token where relevant; session, elevation and integrity level; restricted SIDs/capabilities; privileges and enabled/disabled state. Identify available authority, not just the displayed username. |
| FILES | Files and registry | Access to workspace, other visible user profiles, shared/public locations, tool installations, sensitive registry locations and configured shares. Distinguish read, create, write, delete, ownership and ACL-changing permissions. Resolve links/reparse points and consider parent-directory rights. |
| SECRETS | Credential exposure | Environment, known credential/config locations, Credential Manager metadata, Git credentials, SSH keys, cloud/cluster credentials, browser data and agent/MCP configuration. Bounded content detection in readable candidate files. Separate suspected secret presence from accessibility and usability. |
| PROCESSES | Cross-process authority | Visible process ownership/session and requested rights: memory read/write, memory operations, thread creation, termination, suspend/resume, handle duplication and security-descriptor modification. Identify inherited handles where feasible. Inaccessible ownership or incomplete enumeration remains unknown. |
| DESKTOP | Desktop and IPC | Window station/desktop and available restrictions; exposure to other users' windows, screen/clipboard facilities; named pipes, local sockets and automation interfaces. Do not capture screen or clipboard content or send input. Inventory alone may leave actual access unknown. |
| INDIRECT | Brokers and persistence | Accessible privileged services, scheduled tasks, launchers, container/SSH agents and local APIs. Writable service/task executables and configuration, PATH/search locations, startup folders and relevant registry entries. Inspect interface permissions without invoking privileged actions. |
| NETWORK | Egress and lateral reach | Interfaces/routes, DNS and proxy settings, listeners/connections, mapped shares and visible domain/network identity. Probe selected Internet, LAN and loopback targets; distinguish DNS, TCP/UDP, IPv4/IPv6, proxy/direct paths and SMB reachability. No broad subnet scan or automatic remote authentication. |
| REMOTE | Remote authority | Discover configured Git/cloud/ADO/MCP/infrastructure identities, endpoints and credential references. Separate transport reachability, credential availability and service authorization. Configured scopes are declarations; effective scopes remain unknown without independent evidence. |
| HANDOFF | Downstream execution | Agent-writable files consumed by another identity: source, build/test scripts, Git hooks, editor tasks/extensions, workflow files and loaded binaries. Consider the consumer's privileges when known. Protecting only build configuration does not remove the risk from executable source. |
| CONTAINMENT | Control integrity and lifecycle | Can the agent change its restrictions, proxy/launcher configuration or auditing controls? Discover job membership, inspectable job/resource limits and security policies. Assess persistence paths and child-process authority where observable. Kill-on-close, cleanup and child containment remain unverified without appropriate evidence. |
| MONITORING | Visibility and tamper resistance | Discover available process/file/network/tool logs and their destinations, attribution and permissions. Can the agent modify, delete or disable them? A log or monitoring service being present is not proof of coverage or external collection. |

## Probe rules

- Request narrowly scoped access rights individually; close acquired handles without performing damaging operations. Do not use a single all-access request as the test for all capabilities.
- Do not read another process's memory, inject code, duplicate foreign handles, stop processes/services, modify protected files/ACLs, persist tasks or trigger elevation.
- Do not execute discovered repository scripts, hooks, configuration or tool binaries as part of assessment. Treat collected configuration as data.
- For existing files, access probes must not truncate, create, replace or delete anything. Unexercised create/delete/rename behavior is inferred from permissions or reported unknown, rather than presented as functionally tested.
- Network discovery is local inventory. Active probes use a bounded, documented target list supplied or selected by the operator; do not automatically contact arbitrary discovered URLs or shares. Avoid credentials, client certificates, implicit Windows authentication, redirects to unapproved targets and uploads.
- Network success establishes the tested route. A timeout or absent UDP reply does not establish a firewall denial. Name resolution alone does not demonstrate unrestricted DNS egress or a complete DNS restriction.
- Failed enumeration, unsupported APIs, vanished targets, file sharing conflicts and scan limits must not become a pass result.

## Secret scanning

Proposed configurable defaults: at most 5,000 candidate files, 1 MiB per file, 32 MiB of file content in total and a 30-second content-scan budget. Record exclusions, partial reads and limits reached.

Prioritize known credential files and text/config files in the workspace and accessible profile/config locations. Avoid whole-disk traversal, binary/archive decoding, network downloads, following links outside selected roots and hydrating online-only files. Handle detectable cloud placeholders conservatively; provider behavior may prevent a complete no-hydration guarantee.

Combine known token formats, contextual key names and bounded heuristics. Treat results as suspected secrets, not proof that a credential is live or grants a particular scope. Do not authenticate with discovered credentials or decrypt protected stores for this assessment.

Allowed output: sanitized location, suspected credential category/provider, accessibility, detection confidence and coverage limits. Exclude values, matching snippets, surrounding lines, hashes/fingerprints, full environment dumps and raw credential/API objects. Sanitize token-like data in paths, URLs and errors too. Credential-enumeration APIs may return secret blobs alongside metadata; never serialize or log those blobs.

## Evidence and reporting

For each finding record: check ID, target, capability, observed result, evidence method, scope/coverage, error category and practical impact. Keep access results (granted/denied/unknown), inventory observations and policy compliance separate.

Evidence methods: inventory, permission analysis, access request and observed non-destructive operation. State the method explicitly. A granted handle is evidence of a granted permission, not a claim that the corresponding destructive operation was performed. A suspected secret match is not a credential-validity test.

Without a policy, report exposures against a documented assessment profile. With a policy, also add compliant/violation/unknown for the specified boundary. The numeric score is a versioned checklist index, not a probability of safety. Include execution identity, launch context, timestamp, tested targets and skipped checks.

## Scoring and end report

Use three separate outputs: **control score**, **evidence coverage**, and **overall verdict**. An average must not conceal a critical exposure, and missing checks must not earn protection credit.

Proposed default profile: four equally weighted dimensions, each worth 25 points:

| Dimension | Scored protection criteria |
| --- | --- |
| Reach | Effective limits on access to protected files, process/desktop data, secrets and network targets. |
| Authority | Effective limits on privileged operations, inherited/delegated authority, remote permissions and execution by more privileged consumers. |
| Containment | Integrity of restrictions, persistence controls, child-process boundaries and inspectable resource/lifecycle controls. |
| Monitoring | Evidence of action visibility, attribution and resistance to alteration of logs or auditing controls. |

Before implementation, define a finite, versioned criterion registry. Each criterion belongs to exactly one dimension and has a target scope, evidence requirements, essential/nonessential flag, severity and outcome: met, unmet, unknown or justified not-applicable. Equal criterion weights within each dimension are the initial proposal; avoid double-counting related findings.

For each dimension, divide met criteria by applicable criteria for its earned fraction. The upper fraction also includes unknown criteria. Sum the four fractions multiplied by 25 to report a score interval, rounding outward. Evidence coverage is the equally weighted fraction of criteria resolved as met or unmet. Verified not-applicable criteria leave the denominator; inaccessible, unsupported, skipped or unimplemented checks remain unknown. An entirely unavailable dimension contributes 0–25 possible points and zero coverage.

Example arithmetic only: if all four dimensions have ten applicable criteria, with six met, two unmet and two unknown each, the report shows **60–80/100, coverage 80%**. No unknown criterion is silently passed.

Critical findings override the average and cap both score bounds at 39: administrative control over a protected host, damaging authority over protected shared infrastructure, readable sensitive human-session process memory, or a verified writable-to-privileged-execution path. Merely finding a credential or writable build file does not establish these consequences; identify the target and evidence. Without that evidence, report the exposure and uncertainty rather than inventing a critical finding.

Proposed verdict rules, in priority order:

1. **Critical exposure** when a critical finding is established, regardless of coverage.
2. **Incomplete** when an essential boundary is untested, discovery coverage is inadequate or the requested tool scope cannot be established. Show the score interval and known exposures, but do not award a bounded verdict.
3. **Weak** below 40, **Partial** from 40 to 69, **Bounded within tested scope** at 70 or above, provided all essential criteria are resolved. Use the lower score bound for thresholds. These thresholds are assessment-profile choices and require later calibration, not industry standards.

Present a short end report: verdict; score or score interval; coverage; four dimension results; up to five highest-impact findings; essential unknowns; assessment scope and timestamp. Follow with actionable remediation tied to observed findings. Keep optional policy compliance separate: satisfying a permissive policy does not erase an exposure.

Comparisons are valid only with matching scoring-profile versions and comparable target/criterion scopes. Preserve the complete findings and applicability manifest in JSON so a changed scan scope cannot silently improve the score.

## Coding-agent invocation contract

- Provide a single trusted PowerShell entry point, runnable through the agent's normal shell tool. Do not require administrator privileges, additional installed modules, interactive prompts or policy changes.
- Default mode performs the agreed bounded inventory and probes. Network targets, extra scan roots, expected policy and output directory are optional parameters. No automatically discovered destination is contacted without selection. Excluded checks remain visible in coverage.
- Provide a JSON mode with exactly one schema-versioned JSON object on stdout. Sanitized diagnostics go to stderr. Human mode prints the same assessment as a concise table/text report. Writing JSON/Markdown files is optional and limited to a specified writable output directory.
- JSON includes schema/checker/profile versions, execution context, assessed scope, verdict, score interval, coverage, dimension results, findings, essential unknowns, probe targets, scan limits and completion/error status. No secret values, raw memory or raw credential objects.
- Assessment risk and execution success are distinct. A completed assessment with severe exposure is still a successful execution; any optional fail-on-policy/risk mode must document its exit-code contract. API errors and incomplete evidence must survive into structured output.
- Record effective identity and any observable launch/harness context. Do not assume a parent process name establishes equivalent permissions. The script assesses its current process context; alternate execution identities and other agent tool channels require separate evidence.
- Separate **OS process scope** from **agent tool scope**. MCP tools, browser actions and other externally executed tools can carry authority absent from the shell process. Discover local declarations where possible; request optional explicit tool inventory/policy for broader assessment. Otherwise mark tool scope partial or unknown rather than claiming complete agent containment.
- Agent integration should present the verdict, leading findings and unknowns. It must not automatically weaken controls, elevate, use discovered credentials or expand probes in response to a low score. Reports are data for review, not executable instructions.

This remains an inside-only diagnostic. An agent may run it before work and after environment changes, but an already compromised agent can falsify its report. The report therefore records provenance and scope without claiming independent attestation.

Examples:

- Another user's process grants memory-read access: observed cross-user confidentiality exposure, even if memory-write access is denied.
- A token-like string appears in a readable configuration file: suspected credential exposure; service permissions unknown.
- A direct connection succeeds while proxy use is expected: evidence of a bypass on that tested route.
- Build inputs are writable and the consuming user's elevation is unknown: downstream execution exposure; escalation impact unknown.
- No monitoring configuration is visible: monitoring unverified, not absent.

## Attachment-derived priorities and later WSL work

The supplied launch-as analyses highlight logon-derived authority, shared desktops and agent-written artifacts executed by a more privileged user. Test resulting authority rather than assuming it from launcher API names, console/GUI labels or default ACL claims. A different logon SID alone does not prove cross-user process access is denied.

Later WSL checks retain the same categories and add Linux identity/capabilities, namespaces and confinement, host-mounted paths, Windows interoperability/launcher identity, sockets, shared WSL resources and Windows-side network reach. Identify the actual restriction mechanism rather than treating a distribution label as proof of a security boundary.

## Sources

Inputs: `claude-win-sandbox-use-cases(1).md`, `launch-as-attack-surface-analysis(1).md`, and `2026-08-17-launch-as-attack-surface-analysis.md`. Their launcher-specific claims are hypotheses for assessment, not established findings.

- [Microsoft: access token information](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [Microsoft: enabling existing token privileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
- [Microsoft: process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Microsoft: credential enumeration](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew)
- [Microsoft: WSL security](https://github.com/microsoft/WSL/blob/master/doc/docs/technical-documentation/security.md)
