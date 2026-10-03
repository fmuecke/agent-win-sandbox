---
name: definition-of-done
description: Mandatory completion gate for coding work. Use before any claim that an implementation, bug fix, refactoring, or other code change is complete, fixed, ready, or done.
---

# Definition of Done

A change is **Done** only when there is sufficient evidence that it is valuable, correct, safe, and maintainable in its intended context.

## Scope

- Apply this gate to any completion claim, regardless of wording.
- Establish the intended outcome, relevant execution context, and required verification early.
- Keep verification proportional to the change and its risks. Expand it only when changed scope, failures, or new evidence justify additional checks.
- Distinguish implementation progress from verified completion. If required evidence is missing, report what is complete and what remains unverified.

## Intent

- The intended outcome is achieved.
- Relevant assumptions and requirements are satisfied.
- No unnecessary scope or complexity was introduced.

## Correctness

- Changed behavior has appropriate evidence, normally the simplest meaningful tests.
- Relevant existing tests pass.
- The change builds and works in the relevant integration context.

## Quality

- The solution is as simple as reasonably possible.
- No unnecessary code, abstractions, dependencies, configuration, duplication, temporary artifacts, or dead code remain.
- Another developer can understand and safely change it.

## Safety

- Relevant security, privacy, data-loss, compatibility, failure, and operational risks were considered.
- Appropriate checks were performed for identified risks.
- No known critical issue remains unresolved.

## Evidence

Before making a completion claim, report concisely:

- what changed
- what was verified and how
- relevant checks not performed and why
- remaining assumptions, limitations, or risks

**Unverified is not verified.** If required verification is missing, state that explicitly and do not present the task as complete.
